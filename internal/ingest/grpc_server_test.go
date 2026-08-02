package ingest

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/Romil2112/SOC-Dashboard/internal/ingestpb"
)

// validIngestReq returns a minimal valid gRPC ingest request.
func validIngestReq() *ingestpb.IngestAlertRequest {
	return &ingestpb.IngestAlertRequest{
		Title:    "Port Scan Detected",
		Category: "port_scan",
		Severity: "MEDIUM",
	}
}

// grpcServer returns a GRPCServer wired to the given stub.
func grpcServer(stub *stubSvc) *GRPCServer {
	return &GRPCServer{svc: stub}
}

// grpcCode extracts the gRPC status code from an error, failing the test if
// err is not a gRPC status error.
func grpcCode(t *testing.T, err error) codes.Code {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected a gRPC status error, got %T: %v", err, err)
	}
	return st.Code()
}

// ── apiKeyInterceptor ───────────────────────────────────────────────────────

func TestAPIKeyInterceptorEmptyServerKeyRejectsAll(t *testing.T) {
	interceptor := apiKeyInterceptor("")
	handler := func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	}
	md := metadata.New(map[string]string{"x-api-key": "anything"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	_, err := interceptor(ctx, nil, nil, handler)
	if grpcCode(t, err) != codes.Unauthenticated {
		t.Errorf("empty server key: want Unauthenticated, got %s", grpcCode(t, err))
	}
}

func TestAPIKeyInterceptorNoMetadataRejects(t *testing.T) {
	interceptor := apiKeyInterceptor("mykey")
	handler := func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	}
	// context with no gRPC metadata attached
	_, err := interceptor(context.Background(), nil, nil, handler)
	if grpcCode(t, err) != codes.Unauthenticated {
		t.Errorf("no metadata: want Unauthenticated, got %s", grpcCode(t, err))
	}
}

func TestAPIKeyInterceptorMissingKeyInMetadataRejects(t *testing.T) {
	interceptor := apiKeyInterceptor("mykey")
	handler := func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	}
	// metadata present but x-api-key field absent
	md := metadata.New(map[string]string{"other-header": "value"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	_, err := interceptor(ctx, nil, nil, handler)
	if grpcCode(t, err) != codes.Unauthenticated {
		t.Errorf("missing x-api-key: want Unauthenticated, got %s", grpcCode(t, err))
	}
}

func TestAPIKeyInterceptorEmptyKeyValueRejects(t *testing.T) {
	interceptor := apiKeyInterceptor("mykey")
	handler := func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	}
	md := metadata.New(map[string]string{"x-api-key": ""})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	_, err := interceptor(ctx, nil, nil, handler)
	if grpcCode(t, err) != codes.Unauthenticated {
		t.Errorf("empty key value: want Unauthenticated, got %s", grpcCode(t, err))
	}
}

func TestAPIKeyInterceptorWrongKeyRejects(t *testing.T) {
	interceptor := apiKeyInterceptor("mykey")
	handler := func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	}
	md := metadata.New(map[string]string{"x-api-key": "wrongkey"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	_, err := interceptor(ctx, nil, nil, handler)
	if grpcCode(t, err) != codes.Unauthenticated {
		t.Errorf("wrong key: want Unauthenticated, got %s", grpcCode(t, err))
	}
}

func TestAPIKeyInterceptorCorrectKeyCallsHandler(t *testing.T) {
	interceptor := apiKeyInterceptor("mykey")
	called := false
	handler := func(ctx context.Context, req any) (any, error) {
		called = true
		return "ok", nil
	}
	md := metadata.New(map[string]string{"x-api-key": "mykey"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	if _, err := interceptor(ctx, nil, nil, handler); err != nil {
		t.Fatalf("correct key: unexpected error %v", err)
	}
	if !called {
		t.Error("correct key: handler must be invoked")
	}
}

// The interceptor trims leading/trailing whitespace from the incoming key value
// to handle HTTP header quirks — "  mykey  " must match "mykey".
func TestAPIKeyInterceptorLeadingTrailingWhitespaceStripped(t *testing.T) {
	interceptor := apiKeyInterceptor("mykey")
	called := false
	handler := func(ctx context.Context, req any) (any, error) {
		called = true
		return "ok", nil
	}
	md := metadata.New(map[string]string{"x-api-key": "  mykey  "})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	if _, err := interceptor(ctx, nil, nil, handler); err != nil {
		t.Fatalf("whitespace-padded key: unexpected error %v", err)
	}
	if !called {
		t.Error("whitespace-padded key matching real key: handler must be invoked")
	}
}

// Whitespace embedded inside the key is NOT stripped — "my key" must not match "mykey".
func TestAPIKeyInterceptorEmbeddedWhitespaceDoesNotMatch(t *testing.T) {
	interceptor := apiKeyInterceptor("mykey")
	handler := func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	}
	md := metadata.New(map[string]string{"x-api-key": "my key"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	_, err := interceptor(ctx, nil, nil, handler)
	if grpcCode(t, err) != codes.Unauthenticated {
		t.Error("embedded whitespace must not match a key without whitespace")
	}
}

// Rejection uses codes.Unauthenticated, not codes.PermissionDenied or codes.Internal.
func TestAPIKeyInterceptorRejectCodeIsUnauthenticated(t *testing.T) {
	interceptor := apiKeyInterceptor("mykey")
	handler := func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	}
	_, err := interceptor(context.Background(), nil, nil, handler)
	code := grpcCode(t, err)
	if code != codes.Unauthenticated {
		t.Errorf("rejection code: want Unauthenticated, got %s", code)
	}
}

// ── GRPCServer.IngestAlert ──────────────────────────────────────────────────

func TestGRPCServerIngestValidRequestSucceeds(t *testing.T) {
	stub := &stubSvc{
		apiKey: "k",
		resp: AlertResponse{ID: 7, Severity: "MEDIUM", Status: "open",
			CreatedAt: time.Now()},
	}
	g := grpcServer(stub)
	resp, err := g.IngestAlert(context.Background(), validIngestReq())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("response must not be nil")
	}
}

func TestGRPCServerIngestMissingTitleMapsToInvalidArgument(t *testing.T) {
	stub := &stubSvc{
		ingestErr: errors.New("title and category are required"),
	}
	g := grpcServer(stub)
	req := validIngestReq()
	req.Title = ""
	_, err := g.IngestAlert(context.Background(), req)
	if grpcCode(t, err) != codes.InvalidArgument {
		t.Errorf("missing title: want InvalidArgument, got %s", grpcCode(t, err))
	}
}

func TestGRPCServerIngestMissingCategoryMapsToInvalidArgument(t *testing.T) {
	stub := &stubSvc{
		ingestErr: errors.New("title and category are required"),
	}
	g := grpcServer(stub)
	req := validIngestReq()
	req.Category = ""
	_, err := g.IngestAlert(context.Background(), req)
	if grpcCode(t, err) != codes.InvalidArgument {
		t.Errorf("missing category: want InvalidArgument, got %s", grpcCode(t, err))
	}
}

func TestGRPCServerIngestBadSeverityMapsToInvalidArgument(t *testing.T) {
	stub := &stubSvc{
		ingestErr: errors.New(`severity must be CRITICAL, HIGH, MEDIUM or LOW; got "URGENT"`),
	}
	g := grpcServer(stub)
	req := validIngestReq()
	req.Severity = "URGENT"
	_, err := g.IngestAlert(context.Background(), req)
	if grpcCode(t, err) != codes.InvalidArgument {
		t.Errorf("bad severity: want InvalidArgument, got %s", grpcCode(t, err))
	}
}

func TestGRPCServerIngestInternalErrorMapsToInternal(t *testing.T) {
	stub := &stubSvc{
		ingestErr: errors.New("insert alert: pq: connection refused"),
	}
	g := grpcServer(stub)
	_, err := g.IngestAlert(context.Background(), validIngestReq())
	if grpcCode(t, err) != codes.Internal {
		t.Errorf("internal error: want Internal, got %s", grpcCode(t, err))
	}
}

func TestGRPCServerIngestResponseIDIsPositive(t *testing.T) {
	stub := &stubSvc{resp: AlertResponse{ID: 99, Severity: "HIGH", Status: "open", CreatedAt: time.Now()}}
	g := grpcServer(stub)
	resp, _ := g.IngestAlert(context.Background(), validIngestReq())
	if resp.Id != 99 {
		t.Errorf("want ID=99, got %d", resp.Id)
	}
}

func TestGRPCServerIngestResponseSeverityPreserved(t *testing.T) {
	stub := &stubSvc{resp: AlertResponse{ID: 1, Severity: "CRITICAL", Status: "open", CreatedAt: time.Now()}}
	g := grpcServer(stub)
	resp, _ := g.IngestAlert(context.Background(), validIngestReq())
	if resp.Severity != "CRITICAL" {
		t.Errorf("want CRITICAL, got %q", resp.Severity)
	}
}

func TestGRPCServerIngestResponseStatusIsOpen(t *testing.T) {
	stub := &stubSvc{resp: AlertResponse{ID: 1, Severity: "LOW", Status: "open", CreatedAt: time.Now()}}
	g := grpcServer(stub)
	resp, _ := g.IngestAlert(context.Background(), validIngestReq())
	if resp.Status != "open" {
		t.Errorf("want status=open, got %q", resp.Status)
	}
}

func TestGRPCServerIngestResponseCreatedAtIsRFC3339(t *testing.T) {
	stub := &stubSvc{resp: AlertResponse{ID: 1, Severity: "LOW", Status: "open",
		CreatedAt: time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)}}
	g := grpcServer(stub)
	resp, _ := g.IngestAlert(context.Background(), validIngestReq())
	if _, err := time.Parse(time.RFC3339, resp.CreatedAt); err != nil {
		t.Errorf("created_at %q is not RFC3339: %v", resp.CreatedAt, err)
	}
}

// The proto field is SourceIp (snake_case) but AlertRequest uses SourceIP.
func TestGRPCServerIngestSourceIPMappedCorrectly(t *testing.T) {
	stub := &stubSvc{resp: AlertResponse{ID: 1, Severity: "HIGH", Status: "open", CreatedAt: time.Now()}}
	g := grpcServer(stub)
	req := validIngestReq()
	req.SourceIp = "192.168.1.100"
	g.IngestAlert(context.Background(), req) //nolint:errcheck
	if stub.lastReq.SourceIP != "192.168.1.100" {
		t.Errorf("SourceIp→SourceIP: want 192.168.1.100, got %q", stub.lastReq.SourceIP)
	}
}

// Proto WorkflowRunId must map to AlertRequest.WorkflowRunID.
func TestGRPCServerIngestWorkflowRunIDMappedCorrectly(t *testing.T) {
	stub := &stubSvc{resp: AlertResponse{ID: 1, Severity: "HIGH", Status: "open", CreatedAt: time.Now()}}
	g := grpcServer(stub)
	req := validIngestReq()
	req.WorkflowRunId = "wf-abc123"
	g.IngestAlert(context.Background(), req) //nolint:errcheck
	if stub.lastReq.WorkflowRunID != "wf-abc123" {
		t.Errorf("WorkflowRunId→WorkflowRunID: want wf-abc123, got %q", stub.lastReq.WorkflowRunID)
	}
}

// A traceparent carried in gRPC metadata must be extracted without panicking.
func TestGRPCServerIngestTraceparentInMetadataDoesNotPanic(t *testing.T) {
	stub := &stubSvc{resp: AlertResponse{ID: 1, Severity: "HIGH", Status: "open", CreatedAt: time.Now()}}
	g := grpcServer(stub)
	md := metadata.New(map[string]string{
		"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	if _, err := g.IngestAlert(ctx, validIngestReq()); err != nil {
		t.Fatalf("unexpected error with traceparent: %v", err)
	}
}

// Python OTel ≥1.44 flags=03 must not cause IngestAlert to fail.
func TestGRPCServerIngestPythonTraceparentFlagsAccepted(t *testing.T) {
	stub := &stubSvc{resp: AlertResponse{ID: 1, Severity: "HIGH", Status: "open", CreatedAt: time.Now()}}
	g := grpcServer(stub)
	md := metadata.New(map[string]string{
		"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-03",
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	if _, err := g.IngestAlert(ctx, validIngestReq()); err != nil {
		t.Fatalf("flags=03 must not cause an error: %v", err)
	}
}

// No traceparent in metadata — must succeed without any tracing context.
func TestGRPCServerIngestNoTraceparentIsOK(t *testing.T) {
	stub := &stubSvc{resp: AlertResponse{ID: 1, Severity: "HIGH", Status: "open", CreatedAt: time.Now()}}
	g := grpcServer(stub)
	// metadata present but no traceparent key
	md := metadata.New(map[string]string{"x-api-key": "key"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	if _, err := g.IngestAlert(ctx, validIngestReq()); err != nil {
		t.Fatalf("missing traceparent must not cause error: %v", err)
	}
}
