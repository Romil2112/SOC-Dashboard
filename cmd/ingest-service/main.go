package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/Romil2112/SOC-Dashboard/internal/ingest"
)

func main() {
	restAddr := flag.String("rest-addr", ":8001", "address for the REST ingest endpoint")
	grpcAddr := flag.String("grpc-addr", ":9001", "address for the gRPC ingest endpoint")
	flag.Parse()

	cfg := ingest.Config{
		DatabaseURL:   requireEnv("DATABASE_URL"),
		RedisURL:      os.Getenv("REDIS_URL"),
		EncryptionKey: os.Getenv("DB_ENCRYPTION_KEY"),
		APIKey:        requireEnv("ALERTS_API_KEY"),
		RESTAddr:      *restAddr,
		GRPCAddr:      *grpcAddr,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	svc, err := ingest.NewService(ctx, cfg)
	if err != nil {
		slog.Error("failed to initialise ingest service", "err", err)
		os.Exit(1)
	}
	defer svc.Close()

	errc := make(chan error, 2)

	// REST server
	restSrv := &http.Server{
		Addr:    *restAddr,
		Handler: ingest.NewRESTHandler(svc),
	}
	go func() {
		slog.Info("REST ingest listening", "addr", *restAddr)
		if err := restSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errc <- err
		}
	}()

	// gRPC server
	grpcSrv := ingest.NewGRPCServer(svc)
	go func() {
		lis, err := net.Listen("tcp", *grpcAddr)
		if err != nil {
			errc <- err
			return
		}
		slog.Info("gRPC ingest listening", "addr", *grpcAddr)
		if err := grpcSrv.Serve(lis); err != nil {
			errc <- err
		}
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutting down ingest service")
		restSrv.Shutdown(context.Background()) //nolint:errcheck
		grpcSrv.GracefulStop()
	case err := <-errc:
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("required environment variable not set", "var", key)
		os.Exit(1)
	}
	return v
}
