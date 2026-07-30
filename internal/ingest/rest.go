package ingest

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
)

// NewRESTHandler returns an http.Handler that exposes POST /api/alerts on the
// Go ingest service. All other paths return 404. The handler is intentionally
// minimal: routing, TLS, and keep-alive tuning belong at the infrastructure
// layer (nginx, cloud load balancer), not here.
//
// Method-prefix patterns in http.ServeMux require Go 1.22+; we target Go 1.21
// so the method check is done explicitly inside the handler.
func NewRESTHandler(svc *Service) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/alerts", makeIngestHandler(svc))
	return mux
}

func makeIngestHandler(svc *Service) http.HandlerFunc {
	tracer := otel.Tracer("soc-ingest")
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := extractRemoteSpanContext(r.Context(), r.Header.Get("Traceparent"))
		ctx, span := tracer.Start(ctx, "soc_ingest.rest_ingest")
		defer span.End()
		r = r.WithContext(ctx)

		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		if !svc.ValidateAPIKey(r.Header.Get("X-Api-Key")) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid X-API-Key"})
			return
		}

		var body struct {
			Title         string `json:"title"`
			Category      string `json:"category"`
			Severity      string `json:"severity"`
			Source        string `json:"source"`
			SourceIP      string `json:"source_ip"`
			Description   string `json:"description"`
			WorkflowRunID string `json:"workflow_run_id"`
			RunMetadata   string `json:"run_metadata"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}

		resp, err := svc.Ingest(r.Context(), AlertRequest{
			Title:         body.Title,
			Category:      body.Category,
			Severity:      body.Severity,
			Source:        body.Source,
			SourceIP:      body.SourceIP,
			Description:   body.Description,
			WorkflowRunID: body.WorkflowRunID,
			RunMetadata:   body.RunMetadata,
		})
		if err != nil {
			slog.Warn("ingest failed", "err", err)
			status := http.StatusInternalServerError
			if isValidationError(err) {
				status = http.StatusBadRequest
			}
			writeJSON(w, status, map[string]string{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusCreated, map[string]any{
			"id":         resp.ID,
			"severity":   resp.Severity,
			"status":     resp.Status,
			"created_at": resp.CreatedAt.Format(time.RFC3339),
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// isValidationError returns true for errors that originate from validate(),
// i.e., bad caller input rather than infrastructure failures.
func isValidationError(err error) bool {
	msg := err.Error()
	return msg == "title and category are required" ||
		len(msg) > 8 && msg[:8] == "severity"
}
