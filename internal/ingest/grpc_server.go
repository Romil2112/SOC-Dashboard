package ingest

import (
	"context"
	"crypto/subtle"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/Romil2112/SOC-Dashboard/internal/ingestpb"
)

// grpcMetadataCarrier adapts gRPC metadata to the OTel TextMapCarrier interface.
// Kept for potential future use (e.g. tracestate propagation). Active trace context
// extraction uses extractRemoteSpanContext directly to bypass Go OTel v1.28.0's
// strict flags validation (rejects SAMPLED|RANDOM_TRACE_ID = 0x03 from Python ≥1.44).

// grpcMetadataCarrier adapts gRPC metadata to the OTel TextMapCarrier interface
// so W3C TraceContext headers injected by the Python client propagate correctly.
type grpcMetadataCarrier metadata.MD

func (c grpcMetadataCarrier) Get(key string) string {
	vals := metadata.MD(c).Get(key)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func (c grpcMetadataCarrier) Set(key, value string) {
	metadata.MD(c).Set(key, value)
}

func (c grpcMetadataCarrier) Keys() []string {
	out := make([]string, 0, len(c))
	for k := range c {
		out = append(out, k)
	}
	return out
}

// GRPCServer implements ingestpb.AlertIngestServiceServer.
type GRPCServer struct {
	ingestpb.UnimplementedAlertIngestServiceServer
	svc *Service
}

// NewGRPCServer returns a configured gRPC server with the API-key interceptor
// and the AlertIngestService registered.
func NewGRPCServer(svc *Service) *grpc.Server {
	srv := grpc.NewServer(grpc.UnaryInterceptor(apiKeyInterceptor(svc.apiKey)))
	ingestpb.RegisterAlertIngestServiceServer(srv, &GRPCServer{svc: svc})
	return srv
}

// IngestAlert implements the gRPC unary RPC.
func (g *GRPCServer) IngestAlert(ctx context.Context, req *ingestpb.IngestAlertRequest) (*ingestpb.IngestAlertResponse, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get("traceparent"); len(vals) > 0 {
			ctx = extractRemoteSpanContext(ctx, vals[0])
		}
	}
	tracer := otel.Tracer("soc-ingest")
	ctx, span := tracer.Start(ctx, "soc_ingest.grpc_ingest")
	defer span.End()

	resp, err := g.svc.Ingest(ctx, AlertRequest{
		Title:         req.Title,
		Category:      req.Category,
		Severity:      req.Severity,
		Source:        req.Source,
		SourceIP:      req.SourceIp,
		Description:   req.Description,
		WorkflowRunID: req.WorkflowRunId,
		RunMetadata:   req.RunMetadata,
	})
	if err != nil {
		if isValidationError(err) {
			return nil, status.Errorf(codes.InvalidArgument, "%s", err)
		}
		return nil, status.Errorf(codes.Internal, "ingest failed: %s", err)
	}
	return &ingestpb.IngestAlertResponse{
		Id:        resp.ID,
		Severity:  resp.Severity,
		Status:    resp.Status,
		CreatedAt: resp.CreatedAt.Format(time.RFC3339),
	}, nil
}

// apiKeyInterceptor is a unary server interceptor that enforces the X-API-Key
// using constant-time comparison to prevent timing attacks.
func apiKeyInterceptor(apiKey string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if apiKey == "" {
			return nil, status.Error(codes.Unauthenticated, "server has no API key configured")
		}
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}
		vals := md.Get("x-api-key")
		if len(vals) == 0 || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(vals[0])), []byte(apiKey)) != 1 {
			return nil, status.Error(codes.Unauthenticated, "missing or invalid x-api-key")
		}
		return handler(ctx, req)
	}
}
