package main

import (
	"context"
	"log/slog"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

const _serviceName = "soc-ingest"

// initTracer configures the global OTel TracerProvider and returns a shutdown
// function to flush pending spans on exit. Tracing failures are logged but do
// not prevent the service from starting — spans are simply dropped.
func initTracer(ctx context.Context) func(context.Context) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		endpoint = "localhost:4317"
	}

	exp, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		slog.Warn("OTel exporter init failed — tracing disabled", "err", err)
		return func(context.Context) {}
	}

	res, _ := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(_serviceName),
		),
	)

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
	))
	slog.Info("OTel tracer initialised", "endpoint", endpoint)

	return func(ctx context.Context) {
		if err := tp.Shutdown(ctx); err != nil {
			slog.Warn("OTel shutdown error", "err", err)
		}
	}
}
