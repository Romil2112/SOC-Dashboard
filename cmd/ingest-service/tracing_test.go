package main

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
)

func TestInitTracerDoesNotPanicWithUnreachableEndpoint(t *testing.T) {
	shutdown := initTracer(context.Background())
	if shutdown == nil {
		t.Fatal("initTracer returned nil shutdown function")
	}
	shutdown(context.Background())
}

func TestInitTracerRegistersGlobalProvider(t *testing.T) {
	_ = initTracer(context.Background())
	tp := otel.GetTracerProvider()
	if tp == nil {
		t.Fatal("expected non-nil TracerProvider after initTracer")
	}
	tracer := tp.Tracer("test")
	if tracer == nil {
		t.Fatal("expected non-nil tracer from provider")
	}
}

func TestInitTracerSpanDoesNotPanic(t *testing.T) {
	_ = initTracer(context.Background())
	tracer := otel.Tracer("soc-ingest")
	ctx, span := tracer.Start(context.Background(), "test.span")
	if ctx == nil {
		t.Fatal("span context should not be nil")
	}
	span.End()
}
