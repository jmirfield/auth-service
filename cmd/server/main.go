package main

import (
	"context"
	"crypto/rsa"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jmirfield/auth-service/internals/apple"
	"github.com/jmirfield/auth-service/internals/cache"
	"github.com/jmirfield/auth-service/internals/handlers"
	"github.com/jmirfield/auth-service/internals/repository/postgres"
	sessionx "github.com/jmirfield/auth-service/internals/session"
	authhttp "github.com/jmirfield/auth-service/pkg/http"
	"github.com/jmirfield/auth-service/pkg/session"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}
	pgxCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		log.Fatalf("parse DATABASE_URL: %v", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, pgxCfg)
	if err != nil {
		log.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	{
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if err := pool.Ping(pingCtx); err != nil {
			cancel()
			log.Fatalf("postgres ping: %v", err)
		}
		cancel()
	}

	usrstore, err := postgres.NewUserRepo(pool)
	if err != nil {
		log.Fatalf("failed to create user repo: %v", err)
	}

	go func(ctx context.Context) {
		t := time.NewTicker(12 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if n, err := usrstore.PruneExpiredRefreshTokens(ctx, time.Now()); err == nil && n > 0 {
					log.Printf("pruned %d expired refresh tokens", n)
				}
			case <-ctx.Done():
				return
			}
		}
	}(ctx)

	appleCfg, err := apple.Load()
	if err != nil {
		log.Fatal(err)
	}

	sessionCfg, err := session.Load()
	if err != nil {
		log.Fatal(err)
	}

	sessionMgr, err := session.NewManager(sessionCfg)
	if err != nil {
		log.Fatal(err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	appleMgr, err := apple.NewManager(appleCfg, cache.NewMemory[rsa.PublicKey](ctx), client)
	if err != nil {
		log.Fatal(err)
	}

	sessionSvc, err := sessionx.NewService(usrstore, sessionMgr)
	if err != nil {
		log.Fatal(err)
	}
	sessionHandler, err := handlers.NewSessionHandler(sessionSvc)
	if err != nil {
		log.Fatal(err)
	}

	appleSvc, err := apple.NewService(appleMgr, sessionMgr, usrstore)
	if err != nil {
		log.Fatal(err)
	}
	appleHandler, err := handlers.NewAppleHandler(appleSvc)
	if err != nil {
		log.Fatal(err)
	}

	authMiddleware := authhttp.NewAuth(sessionMgr).Middleware

	mux := http.NewServeMux()
	mux.HandleFunc("POST /token/apple", appleHandler.Auth)
	mux.HandleFunc("POST /token/refresh", sessionHandler.Refresh)
	mux.Handle("POST /token/revoke", authMiddleware(http.HandlerFunc(sessionHandler.RevokeSingle)))
	mux.Handle("POST /token/revoke/all", authMiddleware(http.HandlerFunc(sessionHandler.RevokeAll)))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{Addr: ":" + port, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Println("Listening on :" + port)
		log.Fatal(srv.ListenAndServe())
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}
