package ingest

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

// well-formed W3C traceparent produces a valid remote span context
func TestExtractRemoteSpanContextValidTraceparent(t *testing.T) {
	tp := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	ctx := extractRemoteSpanContext(context.Background(), tp)
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		t.Error("expected valid span context")
	}
	if !sc.IsRemote() {
		t.Error("expected remote=true on the injected span context")
	}
}

// Python OTel ≥1.44 sets flags=03 (SAMPLED|RANDOM_TRACE_ID). The standard Go
// propagator rejects this; our custom parser must accept it.
func TestExtractRemoteSpanContextPythonFlags03Accepted(t *testing.T) {
	tp := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-03"
	ctx := extractRemoteSpanContext(context.Background(), tp)
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		t.Error("flags=03 (Python OTel ≥1.44) should produce a valid span context")
	}
}

// empty string — context must be returned unchanged
func TestExtractRemoteSpanContextEmptyString(t *testing.T) {
	ctx := extractRemoteSpanContext(context.Background(), "")
	sc := trace.SpanContextFromContext(ctx)
	if sc.IsValid() {
		t.Error("empty traceparent must not inject a span context")
	}
}

// fewer than 4 dash-separated parts — context unchanged
func TestExtractRemoteSpanContextTooFewParts(t *testing.T) {
	for _, bad := range []string{"00", "00-abc", "00-abc-def"} {
		ctx := extractRemoteSpanContext(context.Background(), bad)
		sc := trace.SpanContextFromContext(ctx)
		if sc.IsValid() {
			t.Errorf("malformed traceparent %q must not inject a span context", bad)
		}
	}
}

// invalid trace ID hex — context unchanged
func TestExtractRemoteSpanContextBadTraceID(t *testing.T) {
	tp := "00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-00f067aa0ba902b7-01"
	ctx := extractRemoteSpanContext(context.Background(), tp)
	sc := trace.SpanContextFromContext(ctx)
	if sc.IsValid() {
		t.Error("invalid trace ID hex must not inject a span context")
	}
}

// invalid span ID hex — context unchanged
func TestExtractRemoteSpanContextBadSpanID(t *testing.T) {
	tp := "00-4bf92f3577b34da6a3ce929d0e0e4736-zzzzzzzzzzzzzzzz-01"
	ctx := extractRemoteSpanContext(context.Background(), tp)
	sc := trace.SpanContextFromContext(ctx)
	if sc.IsValid() {
		t.Error("invalid span ID hex must not inject a span context")
	}
}

// non-hex flags field — context unchanged
func TestExtractRemoteSpanContextBadFlags(t *testing.T) {
	tp := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-zz"
	ctx := extractRemoteSpanContext(context.Background(), tp)
	sc := trace.SpanContextFromContext(ctx)
	if sc.IsValid() {
		t.Error("non-hex flags must not inject a span context")
	}
}

// all-zero trace ID is structurally invalid per the W3C spec — context unchanged
func TestExtractRemoteSpanContextZeroTraceID(t *testing.T) {
	tp := "00-00000000000000000000000000000000-00f067aa0ba902b7-01"
	ctx := extractRemoteSpanContext(context.Background(), tp)
	sc := trace.SpanContextFromContext(ctx)
	if sc.IsValid() {
		t.Error("all-zero trace ID must not produce a valid span context")
	}
}

// all-zero span ID is structurally invalid per the W3C spec — context unchanged
func TestExtractRemoteSpanContextZeroSpanID(t *testing.T) {
	tp := "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"
	ctx := extractRemoteSpanContext(context.Background(), tp)
	sc := trace.SpanContextFromContext(ctx)
	if sc.IsValid() {
		t.Error("all-zero span ID must not produce a valid span context")
	}
}

// flags=01 must set the SAMPLED bit
func TestExtractRemoteSpanContextSampledFlagSet(t *testing.T) {
	tp := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	ctx := extractRemoteSpanContext(context.Background(), tp)
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsSampled() {
		t.Error("expected SAMPLED flag to be set for flags=01")
	}
}

// flags=00 must leave the SAMPLED bit clear
func TestExtractRemoteSpanContextUnsampledFlagClear(t *testing.T) {
	tp := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"
	ctx := extractRemoteSpanContext(context.Background(), tp)
	sc := trace.SpanContextFromContext(ctx)
	if sc.IsSampled() {
		t.Error("expected SAMPLED flag to be clear for flags=00")
	}
}

// SplitN(..., 4) puts everything after the third dash into parts[3]; a fifth
// segment like "-extra" makes parts[3]="01-extra" which is not a valid uint,
// so the function must return ctx unchanged rather than panicking.
func TestExtractRemoteSpanContextExtraSegmentsReturnCtxUnchanged(t *testing.T) {
	tp := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra"
	ctx := extractRemoteSpanContext(context.Background(), tp)
	sc := trace.SpanContextFromContext(ctx)
	if sc.IsValid() {
		t.Error("traceparent with a fifth segment must not inject a span context")
	}
}

// trace ID and span ID fields must round-trip through the context correctly
func TestExtractRemoteSpanContextIDsRoundTrip(t *testing.T) {
	const (
		wantTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
		wantSpanID  = "00f067aa0ba902b7"
	)
	tp := "00-" + wantTraceID + "-" + wantSpanID + "-01"
	ctx := extractRemoteSpanContext(context.Background(), tp)
	sc := trace.SpanContextFromContext(ctx)
	if sc.TraceID().String() != wantTraceID {
		t.Errorf("trace ID: want %s, got %s", wantTraceID, sc.TraceID())
	}
	if sc.SpanID().String() != wantSpanID {
		t.Errorf("span ID: want %s, got %s", wantSpanID, sc.SpanID())
	}
}
