package main

import (
	"context"
	"github.com/wardenv/service/internal/app"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg, e := app.LoadConfig()
	if e != nil {
		logger.Error("configuration failed", "error", e)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	a, e := app.New(ctx, cfg, logger)
	if e != nil {
		logger.Error("startup failed", "error", e)
		os.Exit(1)
	}
	defer a.Close()
	if e = a.Store.Migrate(ctx); e != nil {
		logger.Error("migration failed", "error", e)
		os.Exit(1)
	}
	a.StartWorker(ctx)
	if e = a.Auth.Discovery(ctx); e != nil {
		logger.Warn("oidc discovery deferred", "error", e)
	}
	srv := &http.Server{Addr: cfg.Addr, Handler: a.Router(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		logger.Info("server listening", "addr", cfg.Addr)
		if e := srv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
			logger.Error("server failed", "error", e)
			cancel()
		}
	}()
	<-ctx.Done()
	shutdown, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdown)
}
