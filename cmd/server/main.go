package main

import (
	"context"
	"crypto/rsa"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jmirfield/auth-service/internals/apple"
	"github.com/jmirfield/auth-service/internals/cache"
	"github.com/jmirfield/auth-service/internals/handlers"
	"github.com/jmirfield/auth-service/internals/idp"
	"github.com/jmirfield/auth-service/internals/logging"
	"github.com/jmirfield/auth-service/internals/ratelimit"
	"github.com/jmirfield/auth-service/internals/repository/postgres"
	sessionx "github.com/jmirfield/auth-service/internals/session"
	authhttp "github.com/jmirfield/auth-service/pkg/http"
	"github.com/jmirfield/auth-service/pkg/session"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serviceName := os.Getenv("SERVICE_NAME")
	if serviceName == "" {
		serviceName = "auth-service"
	}
	logger := logging.New(serviceName).With("component", "server")

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		logger.Error("missing DATABASE_URL")
		return
	}
	pgxCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		logger.Error("parse DATABASE_URL", "error", err)
		return
	}

	pgxCfg.ConnConfig.RuntimeParams = map[string]string{
		"application_name":  "auth-service",
		"statement_timeout": "30000",
	}

	pool, err := pgxpool.NewWithConfig(ctx, pgxCfg)
	if err != nil {
		logger.Error("pgxpool.New", "error", err)
		return
	}
	defer pool.Close()

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	if err := pool.Ping(pingCtx); err != nil {
		cancel()
		logger.Error("postgres ping", "error", err)
		return
	}
	cancel()

	userstore, err := postgres.NewUserRepo(pool)
	if err != nil {
		logger.Error("failed to create user repo", "error", err)
		return
	}

	appleCfg, err := apple.Load()
	if err != nil {
		logger.Error("failed to load apple config", "error", err)
		return
	}

	sessionCfg, err := session.Load()
	if err != nil {
		logger.Error("failed to load session config", "error", err)
		return
	}

	sessionMgr, err := session.NewManager(sessionCfg)
	if err != nil {
		logger.Error("failed to create session manager", "error", err)
		return
	}
	if reloadInterval := os.Getenv("APP_JWT_KEY_RELOAD_INTERVAL"); reloadInterval != "" {
		interval, err := time.ParseDuration(reloadInterval)
		if err != nil {
			logger.Error("invalid APP_JWT_KEY_RELOAD_INTERVAL", "error", err)
		} else if interval > 0 {
			keyUpdater, ok := sessionMgr.(session.KeyUpdater)
			if !ok {
				logger.Error("session manager does not support key reload")
			} else {
				go func() {
					ticker := time.NewTicker(interval)
					defer ticker.Stop()
					for {
						select {
						case <-ctx.Done():
							return
						case <-ticker.C:
							keys, err := session.LoadKeysFromEnv()
							if err != nil {
								logger.Error("failed to reload session keys", "error", err)
								continue
							}
							changed, err := keyUpdater.UpdateKeys(keys.KeyID, keys.PrivateKey, keys.PublicKeys)
							if err != nil {
								logger.Error("failed to update session keys", "error", err)
								continue
							}
							if changed {
								logger.Info("reloaded session keys", "kid", keys.KeyID, "public_keys", len(keys.PublicKeys))
							} else {
								logger.Debug("session keys unchanged")
							}
						}
					}
				}()
			}
		}
	}
	jwksProvider, ok := sessionMgr.(session.JWKSProvider)
	if !ok {
		logger.Error("session manager does not support JWKS publishing")
		return
	}

	rlCfg := ratelimit.Load()
	globalLimiter := ratelimit.NewLimiter(rlCfg.Max, rlCfg.Window)

	client := &http.Client{Timeout: 10 * time.Second}
	appleMgr, err := apple.NewManager(appleCfg, cache.NewMemory[rsa.PublicKey](ctx), client)
	if err != nil {
		logger.Error("failed to create apple manager", "error", err)
		return
	}

	sessionSvc, err := sessionx.NewService(userstore, sessionMgr)
	if err != nil {
		logger.Error("failed to create session service", "error", err)
		return
	}
	sessionHandler, err := handlers.NewSessionHandler(sessionSvc)
	if err != nil {
		logger.Error("failed to create session handler", "error", err)
		return
	}

	registry := idp.NewRegistry()
	appleProvider, err := idp.NewAppleProvider(appleMgr)
	if err != nil {
		logger.Error("failed to create apple provider", "error", err)
		return
	}
	if err := registry.Register(appleProvider); err != nil {
		logger.Error("failed to register apple provider", "error", err)
		return
	}

	idpSvc, err := idp.NewService(registry, sessionMgr, userstore)
	if err != nil {
		logger.Error("failed to create idp service", "error", err)
		return
	}
	idpHandler, err := handlers.NewIdpHandler(idpSvc)
	if err != nil {
		logger.Error("failed to create idp handler", "error", err)
		return
	}
	wellKnownHandler, err := handlers.NewWellKnownHandler(sessionCfg.Issuer, jwksProvider)
	if err != nil {
		logger.Error("failed to create well-known handler", "error", err)
		return
	}

	authMiddleware := authhttp.NewAuth(sessionMgr).Middleware

	mux := http.NewServeMux()
	mux.HandleFunc("POST /token/{provider}", idpHandler.Auth)
	mux.HandleFunc("POST /token/refresh", sessionHandler.Refresh)
	mux.Handle("POST /token/revoke", authMiddleware(http.HandlerFunc(sessionHandler.RevokeSingle)))
	mux.Handle("POST /token/revoke/all", authMiddleware(http.HandlerFunc(sessionHandler.RevokeAll)))
	mux.HandleFunc("GET /.well-known/jwks.json", wellKnownHandler.JWKS)
	mux.HandleFunc("GET /.well-known/openid-configuration", wellKnownHandler.OpenIDConfig)

	handler := authhttp.RateLimit(globalLimiter)(mux)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	go func() {
		logger.Info("listening", "addr", ":"+port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("http server error", "error", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown error", "error", err)
	}
}
