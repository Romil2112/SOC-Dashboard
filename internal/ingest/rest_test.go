package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// stubSvc satisfies Servicer without a database. lastReq captures the most
// recent AlertRequest passed to Ingest so callers can assert field mapping.
type stubSvc struct {
	apiKey     string
	resp       AlertResponse
	ingestErr  error
	lastReq    AlertRequest
}

func (s *stubSvc) ValidateAPIKey(key string) bool {
	return s.apiKey != "" && key == s.apiKey
}

func (s *stubSvc) Ingest(_ context.Context, req AlertRequest) (AlertResponse, error) {
	s.lastReq = req
	return s.resp, s.ingestErr
}

// defaultStub returns a stub pre-configured with a key and a successful response.
func defaultStub() *stubSvc {
	return &stubSvc{
		apiKey: "test-api-key",
		resp: AlertResponse{
			ID:        42,
			Severity:  "HIGH",
			Status:    "open",
			CreatedAt: time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC),
		},
	}
}

// validBody returns a minimal valid JSON request body.
func validBody() *bytes.Buffer {
	return bytes.NewBufferString(`{"title":"SSH Brute Force","category":"brute_force","severity":"HIGH"}`)
}

// post builds a POST request to /api/alerts with the given body and API key.
func post(body *bytes.Buffer, apiKey string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/alerts", body)
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-Api-Key", apiKey)
	}
	return req
}

// --- HTTP method enforcement ---

func TestRESTHandlerGetReturns405(t *testing.T) {
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/alerts", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: want 405, got %d", rr.Code)
	}
}

func TestRESTHandlerPutReturns405(t *testing.T) {
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/api/alerts", validBody()))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT: want 405, got %d", rr.Code)
	}
}

func TestRESTHandlerDeleteReturns405(t *testing.T) {
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/api/alerts", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE: want 405, got %d", rr.Code)
	}
}

func TestRESTHandlerPatchReturns405(t *testing.T) {
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPatch, "/api/alerts", validBody()))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PATCH: want 405, got %d", rr.Code)
	}
}

func TestRESTHandlerHeadReturns405(t *testing.T) {
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodHead, "/api/alerts", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("HEAD: want 405, got %d", rr.Code)
	}
}

func TestRESTHandlerUnknownPathReturns404(t *testing.T) {
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, post(validBody(), "test-api-key"))
	// Reuse the same handler but with a different path.
	rr2 := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/other", validBody())
	req.Header.Set("X-Api-Key", "test-api-key")
	h.ServeHTTP(rr2, req)
	if rr2.Code != http.StatusNotFound {
		t.Fatalf("POST /api/other: want 404, got %d", rr2.Code)
	}
}

// --- API key enforcement ---

func TestRESTHandlerMissingAPIKeyReturns401(t *testing.T) {
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	// post() with empty apiKey omits the header entirely.
	h.ServeHTTP(rr, post(validBody(), ""))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("missing key: want 401, got %d", rr.Code)
	}
}

func TestRESTHandlerEmptyAPIKeyReturns401(t *testing.T) {
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	req := post(validBody(), "")
	req.Header.Set("X-Api-Key", "") // header present but empty
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("empty key: want 401, got %d", rr.Code)
	}
}

func TestRESTHandlerWrongAPIKeyReturns401(t *testing.T) {
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, post(validBody(), "wrong-key"))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key: want 401, got %d", rr.Code)
	}
}

func TestRESTHandlerCorrectAPIKeyPasses(t *testing.T) {
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, post(validBody(), "test-api-key"))
	if rr.Code == http.StatusUnauthorized {
		t.Fatal("correct key must not return 401")
	}
}

// --- JSON body decoding ---

func TestRESTHandlerMalformedJSONReturns400(t *testing.T) {
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	req := post(bytes.NewBufferString(`{not valid json`), "test-api-key")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("malformed JSON: want 400, got %d", rr.Code)
	}
}

func TestRESTHandlerEmptyBodyReturns400(t *testing.T) {
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	req := post(bytes.NewBufferString(""), "test-api-key")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty body: want 400, got %d", rr.Code)
	}
}

func TestRESTHandlerJSONArrayBodyReturns400(t *testing.T) {
	// A JSON array cannot be decoded into the request struct.
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	req := post(bytes.NewBufferString(`[{"title":"t"}]`), "test-api-key")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("JSON array body: want 400, got %d", rr.Code)
	}
}

// --- Validation error → 400 ---

func TestRESTHandlerValidationErrorMapsTo400(t *testing.T) {
	stub := defaultStub()
	stub.ingestErr = errors.New("title and category are required")
	h := NewRESTHandler(stub)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, post(validBody(), "test-api-key"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("validation error: want 400, got %d", rr.Code)
	}
}

func TestRESTHandlerSeverityValidationErrorMapsTo400(t *testing.T) {
	stub := defaultStub()
	stub.ingestErr = fmt.Errorf("severity must be CRITICAL, HIGH, MEDIUM or LOW; got %q", "URGENT")
	h := NewRESTHandler(stub)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, post(validBody(), "test-api-key"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("severity validation error: want 400, got %d", rr.Code)
	}
}

// --- Infrastructure error → 500 ---

func TestRESTHandlerInternalErrorMapsTo500(t *testing.T) {
	stub := defaultStub()
	stub.ingestErr = errors.New("insert alert: connection refused")
	h := NewRESTHandler(stub)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, post(validBody(), "test-api-key"))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("internal error: want 500, got %d", rr.Code)
	}
}

// --- Success response shape ---

func TestRESTHandlerValidRequestReturns201(t *testing.T) {
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, post(validBody(), "test-api-key"))
	if rr.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d", rr.Code)
	}
}

func TestRESTHandlerResponseBodyHasID(t *testing.T) {
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, post(validBody(), "test-api-key"))
	var body map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, ok := body["id"]; !ok {
		t.Error("response must contain 'id'")
	}
}

func TestRESTHandlerResponseBodyHasSeverity(t *testing.T) {
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, post(validBody(), "test-api-key"))
	var body map[string]any
	json.NewDecoder(rr.Body).Decode(&body) //nolint:errcheck
	if _, ok := body["severity"]; !ok {
		t.Error("response must contain 'severity'")
	}
}

func TestRESTHandlerResponseBodyHasStatus(t *testing.T) {
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, post(validBody(), "test-api-key"))
	var body map[string]any
	json.NewDecoder(rr.Body).Decode(&body) //nolint:errcheck
	if body["status"] != "open" {
		t.Errorf("want status=open, got %v", body["status"])
	}
}

func TestRESTHandlerResponseBodyHasCreatedAt(t *testing.T) {
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, post(validBody(), "test-api-key"))
	var body map[string]any
	json.NewDecoder(rr.Body).Decode(&body) //nolint:errcheck
	if _, ok := body["created_at"]; !ok {
		t.Error("response must contain 'created_at'")
	}
}

func TestRESTHandlerCreatedAtIsRFC3339(t *testing.T) {
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, post(validBody(), "test-api-key"))
	var body map[string]any
	json.NewDecoder(rr.Body).Decode(&body) //nolint:errcheck
	ts, _ := body["created_at"].(string)
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		t.Errorf("created_at %q is not RFC3339: %v", ts, err)
	}
}

// --- Content-Type header ---

func TestRESTHandlerContentTypeIsJSONOnSuccess(t *testing.T) {
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, post(validBody(), "test-api-key"))
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type on success: want application/json, got %q", ct)
	}
}

func TestRESTHandlerContentTypeIsJSONOnError(t *testing.T) {
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, post(validBody(), "wrong-key"))
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type on error: want application/json, got %q", ct)
	}
}

func TestRESTHandlerErrorBodyHasErrorKey(t *testing.T) {
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, post(validBody(), "wrong-key"))
	var body map[string]any
	json.NewDecoder(rr.Body).Decode(&body) //nolint:errcheck
	if _, ok := body["error"]; !ok {
		t.Error("error response must contain 'error' key")
	}
}

// --- Field forwarding to service ---

func TestRESTHandlerAllOptionalFieldsForwardedToService(t *testing.T) {
	stub := defaultStub()
	h := NewRESTHandler(stub)
	rr := httptest.NewRecorder()
	body := bytes.NewBufferString(`{
		"title":"t","category":"c","severity":"LOW",
		"source":"EDR","source_ip":"10.0.0.1","description":"desc"
	}`)
	req := post(body, "test-api-key")
	h.ServeHTTP(rr, req)
	if stub.lastReq.Source != "EDR" {
		t.Errorf("source: want EDR, got %q", stub.lastReq.Source)
	}
	if stub.lastReq.SourceIP != "10.0.0.1" {
		t.Errorf("source_ip: want 10.0.0.1, got %q", stub.lastReq.SourceIP)
	}
	if stub.lastReq.Description != "desc" {
		t.Errorf("description: want desc, got %q", stub.lastReq.Description)
	}
}

func TestRESTHandlerWorkflowFieldsForwardedToService(t *testing.T) {
	stub := defaultStub()
	h := NewRESTHandler(stub)
	rr := httptest.NewRecorder()
	body := bytes.NewBufferString(`{
		"title":"t","category":"c","severity":"LOW",
		"workflow_run_id":"run-abc","run_metadata":"{\"k\":\"v\"}"
	}`)
	h.ServeHTTP(rr, post(body, "test-api-key"))
	if stub.lastReq.WorkflowRunID != "run-abc" {
		t.Errorf("workflow_run_id: want run-abc, got %q", stub.lastReq.WorkflowRunID)
	}
	if stub.lastReq.RunMetadata != `{"k":"v"}` {
		t.Errorf("run_metadata: want {\"k\":\"v\"}, got %q", stub.lastReq.RunMetadata)
	}
}

// --- OTel Traceparent header ---

func TestRESTHandlerTraceparentHeaderDoesNotPanic(t *testing.T) {
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	req := post(validBody(), "test-api-key")
	req.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	h.ServeHTTP(rr, req)
	// Any 2xx or 4xx is fine; we only care that it doesn't panic.
}

func TestRESTHandlerMalformedTraceparentHandledGracefully(t *testing.T) {
	h := NewRESTHandler(defaultStub())
	rr := httptest.NewRecorder()
	req := post(validBody(), "test-api-key")
	req.Header.Set("Traceparent", "not-a-valid-traceparent")
	h.ServeHTTP(rr, req)
	// Should succeed normally despite the bad traceparent.
	if rr.Code != http.StatusCreated {
		t.Fatalf("malformed Traceparent must not break ingest: got %d", rr.Code)
	}
}

// --- isValidationError edge cases (function lives in rest.go) ---

func TestIsValidationErrorExactlySeverityPrefixEightChars(t *testing.T) {
	// "severity" is exactly 8 chars. len(msg) > 8 is false, so the prefix
	// branch does not fire and this is NOT classified as a validation error.
	// validate() can never produce this exact string, but the guard must hold.
	err := fakeError("severity")
	if isValidationError(err) {
		t.Error("8-char 'severity' must not match (len > 8 guard)")
	}
}

func TestIsValidationErrorSeverityPrefixNineChars(t *testing.T) {
	// One char longer than the prefix check — crosses the len > 8 threshold.
	err := fakeError("severity!")
	if !isValidationError(err) {
		t.Error("nine-char 'severity!' must match the severity prefix branch")
	}
}
