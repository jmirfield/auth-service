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
		log.Println("DATABASE_URL is required")
		return
	}
	pgxCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		log.Printf("parse DATABASE_URL: %v", err)
		return
	}

	pgxCfg.ConnConfig.RuntimeParams = map[string]string{
		"application_name":  "auth-service",
		"statement_timeout": "30000",
	}

	pool, err := pgxpool.NewWithConfig(ctx, pgxCfg)
	if err != nil {
		log.Printf("pgxpool.New: %v", err)
		return
	}
	defer pool.Close()

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	if err := pool.Ping(pingCtx); err != nil {
		cancel()
		log.Printf("postgres ping: %v", err)
		return
	}
	cancel()

	userstore, err := postgres.NewUserRepo(pool)
	if err != nil {
		log.Printf("failed to create user repo: %v", err)
		return
	}

	appleCfg, err := apple.Load()
	if err != nil {
		log.Printf("failed to load apple config: %v", err)
		return
	}

	sessionCfg, err := session.Load()
	if err != nil {
		log.Printf("failed to load session config: %v", err)
		return
	}

	sessionMgr, err := session.NewManager(sessionCfg)
	if err != nil {
		log.Printf("failed to create session manager: %v", err)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	appleMgr, err := apple.NewManager(appleCfg, cache.NewMemory[rsa.PublicKey](ctx), client)
	if err != nil {
		log.Printf("failed to create apple manager: %v", err)
		return
	}

	sessionSvc, err := sessionx.NewService(userstore, sessionMgr)
	if err != nil {
		log.Printf("failed to create session service: %v", err)
		return
	}
	sessionHandler, err := handlers.NewSessionHandler(sessionSvc)
	if err != nil {
		log.Printf("failed to create session handler: %v", err)
		return
	}

	appleSvc, err := apple.NewService(appleMgr, sessionMgr, userstore)
	if err != nil {
		log.Printf("failed to create apple service: %v", err)
		return
	}
	appleHandler, err := handlers.NewAppleHandler(appleSvc)
	if err != nil {
		log.Printf("failed to create apple handler: %v", err)
		return
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

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	go func() {
		log.Println("listening on :" + port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("http server error: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown error: %v", err)
	}
}
