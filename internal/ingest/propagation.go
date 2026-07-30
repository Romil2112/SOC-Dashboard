package ingest

import (
	"context"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel/trace"
)

// extractRemoteSpanContext sets a remote span context in ctx from a raw W3C
// traceparent string. It bypasses go.opentelemetry.io/otel/propagation.TraceContext
// which rejects trace flags > 2 — Python OTel ≥1.44 sets SAMPLED|RANDOM_TRACE_ID
// (0x03) which triggers that guard in Go OTel v1.28.0. Returns ctx unchanged on
// parse failure or invalid span context.
func extractRemoteSpanContext(ctx context.Context, traceparent string) context.Context {
	parts := strings.SplitN(traceparent, "-", 4)
	if len(parts) != 4 {
		return ctx
	}
	traceID, err := trace.TraceIDFromHex(parts[1])
	if err != nil {
		return ctx
	}
	spanID, err := trace.SpanIDFromHex(parts[2])
	if err != nil {
		return ctx
	}
	flagVal, err := strconv.ParseUint(parts[3], 16, 8)
	if err != nil {
		return ctx
	}
	rsc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.TraceFlags(flagVal),
		Remote:     true,
	})
	if !rsc.IsValid() {
		return ctx
	}
	return trace.ContextWithRemoteSpanContext(ctx, rsc)
}
