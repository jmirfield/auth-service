package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jmirfield/auth-service/internals/repository/postgres"
)

func main() {
	log.Printf("prune start")
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
		log.Println("DATABASE_URL is required")
		return
	}

	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		log.Printf("parse DATABASE_URL: %v", err)
		return
	}

	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		log.Printf("connect: %v", err)
		return
	}
	defer conn.Close(context.Background())

	repo, err := postgres.NewUserRepoFromQuerier(conn)
	if err != nil {
		log.Printf("repo: %v", err)
		return
	}

	var gotLock bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", int64(42)).Scan(&gotLock); err != nil {
		log.Printf("lock: %v", err)
		return
	}
	if !gotLock {
		return
	}
	defer func() {
		if _, err := conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", int64(42)); err != nil {
			log.Printf("unlock error: %v", err)
		}
	}()

	var total int64
	for {
		select {
		case <-ctx.Done():
			log.Printf("cancelled/timeout after deleting %d", total)
			return
		default:
		}

		count, err := repo.PruneExpiredRefreshTokens(ctx, time.Now())
		if err != nil {
			log.Printf("prune: %v", err)
			return
		}
		total += count
		if count == 0 {
			break
		}
	}

	log.Printf("prune complete: deleted=%d", total)
}
