package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jmirfield/auth-service/internals/logging"
	"github.com/jmirfield/auth-service/internals/repository/postgres"
)

func main() {
	serviceName := os.Getenv("SERVICE_NAME")
	if serviceName == "" {
		serviceName = "auth-service"
	}
	logger := logging.New(serviceName).With("component", "prune")
	logger.Info("prune start")
	base := context.Background()
	ctx, stop := signal.NotifyContext(base, os.Interrupt, syscall.SIGTERM)
	defer stop()

	timeout := 1 * time.Minute
	if s := os.Getenv("PRUNE_TIMEOUT"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			timeout = d
		}
	}

	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, timeout)
	defer cancel()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		logger.Error("missing DATABASE_URL")
		return
	}

	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		logger.Error("parse DATABASE_URL", "error", err)
		return
	}

	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		logger.Error("connect", "error", err)
		return
	}
	defer conn.Close(context.Background())

	repo, err := postgres.NewUserRepoFromQuerier(conn)
	if err != nil {
		logger.Error("repo", "error", err)
		return
	}

	var gotLock bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", int64(42)).Scan(&gotLock); err != nil {
		logger.Error("lock", "error", err)
		return
	}
	if !gotLock {
		return
	}
	defer func() {
		if _, err := conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", int64(42)); err != nil {
			logger.Error("unlock error", "error", err)
		}
	}()

	var total int64
	for {
		select {
		case <-ctx.Done():
			logger.Warn("cancelled/timeout after deleting", "total", total)
			return
		default:
		}

		count, err := repo.PruneExpiredRefreshTokens(ctx, time.Now())
		if err != nil {
			logger.Error("prune", "error", err)
			return
		}
		total += count
		if count == 0 {
			break
		}
	}

	logger.Info("prune complete", "deleted", total)
}
