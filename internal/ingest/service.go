// Package ingest implements the alert ingestion service that forms the
// high-throughput write path for the SOC Dashboard. It is transport-agnostic:
// the same Service is wired to both the REST handler (port 8001) and the gRPC
// server (port 9001).
//
// Field encryption: title, source_ip, and description are Fernet-encrypted
// when DB_ENCRYPTION_KEY is configured, using the same key and the same
// fernet-go implementation that is cross-validated against Python's
// cryptography.fernet in fernet_roundtrip_test.go.
//
// Embedding: fastembed vector storage is a Python-only capability; it is not
// replicated here. Alerts ingested via this service will not have rows in
// alert_embeddings and therefore do not appear in similarity search results.
// Route PII-heavy alerts through the Flask endpoint if embedding is required.
package ingest

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

var validSeverities = map[string]bool{
	"CRITICAL": true,
	"HIGH":     true,
	"MEDIUM":   true,
	"LOW":      true,
}

// AlertRequest carries the fields for a single alert, shared between the REST
// and gRPC transports.
type AlertRequest struct {
	Title         string
	Category      string
	Severity      string
	Source        string
	SourceIP      string
	Description   string
	WorkflowRunID string
	RunMetadata   string
}

// AlertResponse carries the database-assigned fields returned to callers.
type AlertResponse struct {
	ID        int64
	Severity  string
	Status    string
	CreatedAt time.Time
}

// Config holds all runtime parameters needed to construct a Service.
type Config struct {
	DatabaseURL      string
	RedisURL         string // empty → SSE disabled
	EncryptionKey    string // empty → field encryption disabled
	APIKey           string
	RESTAddr         string
	GRPCAddr         string
}

// Servicer is the interface consumed by the REST and gRPC transports. It is
// satisfied by *Service and enables unit testing without a live database.
type Servicer interface {
	ValidateAPIKey(key string) bool
	Ingest(ctx context.Context, req AlertRequest) (AlertResponse, error)
}

// Service is the transport-agnostic ingest core.
type Service struct {
	db     *pgxpool.Pool
	rdb    *redis.Client // nil when Redis is not configured
	fk     *fernetKeys   // nil when encryption is disabled
	apiKey string
}

// NewService connects to PostgreSQL (and optionally Redis), decodes the
// Fernet key, and returns a ready-to-use Service.
func NewService(ctx context.Context, cfg Config) (*Service, error) {
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	fk, err := newFernetKeys(cfg.EncryptionKey)
	if err != nil {
		pool.Close()
		return nil, err
	}
	if fk != nil {
		slog.Info("field encryption active (DB_ENCRYPTION_KEY set)")
	} else {
		slog.Info("field encryption disabled — set DB_ENCRYPTION_KEY to encrypt PII at rest")
	}

	var rdb *redis.Client
	if cfg.RedisURL != "" {
		opt, err := redis.ParseURL(cfg.RedisURL)
		if err != nil {
			pool.Close()
			return nil, fmt.Errorf("parse redis URL: %w", err)
		}
		rdb = redis.NewClient(opt)
		if err := rdb.Ping(ctx).Err(); err != nil {
			slog.Warn("redis unavailable — SSE broadcast disabled", "err", err)
			rdb = nil
		} else {
			slog.Info("redis SSE pub/sub enabled")
		}
	}

	return &Service{
		db:     pool,
		rdb:    rdb,
		fk:     fk,
		apiKey: cfg.APIKey,
	}, nil
}

// Close releases the database connection pool and Redis client.
func (s *Service) Close() {
	s.db.Close()
	if s.rdb != nil {
		_ = s.rdb.Close()
	}
}

// ValidateAPIKey returns true if key matches the configured API key using a
// constant-time comparison to prevent timing attacks.
func (s *Service) ValidateAPIKey(key string) bool {
	if s.apiKey == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(key), []byte(s.apiKey)) == 1
}

// Ingest validates, optionally encrypts, and persists one alert, then
// broadcasts an SSE event to Redis. It is safe to call concurrently.
func (s *Service) Ingest(ctx context.Context, req AlertRequest) (AlertResponse, error) {
	if err := validate(req); err != nil {
		return AlertResponse{}, err
	}

	title, err := s.fk.encryptField(req.Title)
	if err != nil {
		return AlertResponse{}, fmt.Errorf("encrypt title: %w", err)
	}
	sourceIP, err := s.fk.encryptField(req.SourceIP)
	if err != nil {
		return AlertResponse{}, fmt.Errorf("encrypt source_ip: %w", err)
	}
	description, err := s.fk.encryptField(req.Description)
	if err != nil {
		return AlertResponse{}, fmt.Errorf("encrypt description: %w", err)
	}

	var resp AlertResponse
	err = s.db.QueryRow(ctx, `
		INSERT INTO alerts
		    (title, category, severity, source, source_ip, description,
		     workflow_run_id, run_metadata, status)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'open')
		RETURNING id, severity, status, created_at`,
		title,
		req.Category,
		strings.ToUpper(strings.TrimSpace(req.Severity)),
		nullableStr(req.Source),
		nullableStr(sourceIP),
		nullableStr(description),
		nullableStr(req.WorkflowRunID),
		nullableStr(req.RunMetadata),
	).Scan(&resp.ID, &resp.Severity, &resp.Status, &resp.CreatedAt)
	if err != nil {
		return AlertResponse{}, fmt.Errorf("insert alert: %w", err)
	}

	s.publishSSE(ctx, resp)
	return resp, nil
}

// publishSSE broadcasts a new-alert event to the soc:alerts Redis channel so
// the Flask SSE stream notifies connected browsers. Best-effort: a Redis
// failure is logged but does not fail the ingest call.
func (s *Service) publishSSE(ctx context.Context, resp AlertResponse) {
	if s.rdb == nil {
		return
	}
	event, _ := json.Marshal(map[string]any{
		"type":     "new_alert",
		"alert_id": resp.ID,
		"severity": resp.Severity,
		"status":   resp.Status,
	})
	if err := s.rdb.Publish(ctx, "soc:alerts", event).Err(); err != nil {
		slog.Warn("SSE publish failed", "err", err)
	}
}

func validate(req AlertRequest) error {
	req.Title = strings.TrimSpace(req.Title)
	req.Category = strings.TrimSpace(req.Category)
	req.Severity = strings.ToUpper(strings.TrimSpace(req.Severity))
	if req.Title == "" || req.Category == "" {
		return fmt.Errorf("title and category are required")
	}
	if !validSeverities[req.Severity] {
		return fmt.Errorf("severity must be CRITICAL, HIGH, MEDIUM or LOW; got %q", req.Severity)
	}
	return nil
}

// nullableStr returns nil for the empty string so optional alert fields are
// stored as SQL NULL rather than empty text.
func nullableStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
