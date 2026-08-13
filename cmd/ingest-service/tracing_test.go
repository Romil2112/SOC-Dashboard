package main

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	oteltrace "go.opentelemetry.io/otel/trace"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
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

func TestInitTracerSkipsProviderWhenSDKDisabled(t *testing.T) {
	// Reset the global provider so we can detect whether initTracer sets a new one.
	otel.SetTracerProvider(oteltrace.NewNoopTracerProvider())
	t.Setenv("OTEL_SDK_DISABLED", "true")

	shutdown := initTracer(context.Background())
	if shutdown == nil {
		t.Fatal("initTracer returned nil shutdown function")
	}

	// Global must NOT have been upgraded to a real TracerProvider.
	if _, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
		t.Fatal("initTracer with OTEL_SDK_DISABLED=true must not register a TracerProvider")
	}

	// Shutdown must return promptly — it is a no-op, not a flush.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	shutdown(ctx)
}

func TestInitTracerSDKDisabledCaseInsensitive(t *testing.T) {
	for _, val := range []string{"TRUE", "True", " true ", "TRUE "} {
		val := val
		t.Run(val, func(t *testing.T) {
			otel.SetTracerProvider(oteltrace.NewNoopTracerProvider())
			t.Setenv("OTEL_SDK_DISABLED", val)
			_ = initTracer(context.Background())
			if _, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
				t.Fatalf("OTEL_SDK_DISABLED=%q should skip provider registration", val)
			}
		})
	}
}

func TestShutdownRespectsTimeout(t *testing.T) {
	// Verify the shutdown function exits when its context deadline fires,
	// not when the underlying flush gives up on its own schedule.
	t.Setenv("OTEL_SDK_DISABLED", "true")
	shutdown := initTracer(context.Background())

	// A 50ms deadline is far shorter than any real flush timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		shutdown(ctx)
		close(done)
	}()

	select {
	case <-done:
		// returned within deadline — correct
	case <-time.After(500 * time.Millisecond):
		t.Fatal("shutdown did not return within deadline — no-op guard may not be working")
	}
}
