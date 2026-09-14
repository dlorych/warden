package main

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
	"github.com/wardenv/service/internal/migrations"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	databaseURL := os.Getenv("MIGRATION_DATABASE_URL")
	if databaseURL == "" {
		logger.Error("MIGRATION_DATABASE_URL is required")
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		logger.Error("open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	if err = db.PingContext(ctx); err != nil {
		logger.Error("database unavailable", "error", err)
		os.Exit(1)
	}
	locker, err := lock.NewPostgresSessionLocker(lock.WithLockTimeout(1, 60), lock.WithUnlockTimeout(1, 10))
	if err != nil {
		logger.Error("create migration lock", "error", err)
		os.Exit(1)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.Files, goose.WithSessionLocker(locker), goose.WithSlog(logger))
	if err != nil {
		logger.Error("create migrator", "error", err)
		os.Exit(1)
	}
	defer provider.Close()
	results, err := provider.Up(ctx)
	if err != nil {
		logger.Error("migration failed", "error", err)
		os.Exit(1)
	}
	logger.Info("schema ready", "version", migrations.CurrentVersion, "applied", len(results))
}
