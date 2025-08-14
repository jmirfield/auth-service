package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jmirfield/auth-service/internals/apple"
	"github.com/jmirfield/auth-service/internals/handlers"
	authhttp "github.com/jmirfield/auth-service/internals/http"
	"github.com/jmirfield/auth-service/internals/secret"
	"github.com/jmirfield/auth-service/internals/session"
	"github.com/jmirfield/auth-service/internals/storage"
)

func main() {
	appleCfg, err := apple.Load()
	if err != nil {
		log.Fatal(err)
	}

	sessionCfg, err := session.Load()
	if err != nil {
		log.Fatal(err)
	}

	secretCfg, err := secret.Load()
	if err != nil {
		log.Fatal(err)
	}

	sessionMgr, err := session.NewManager(sessionCfg)
	if err != nil {
		log.Fatal(err)
	}

	appleMgr, err := apple.NewManager(appleCfg)
	if err != nil {
		log.Fatal(err)
	}

	secretMgr, err := secret.NewManager(secretCfg)
	if err != nil {
		log.Fatal(err)
	}

	var store = storage.NewMemoryStore()
	var sessionHandler = handlers.NewSessionHandler(sessionMgr, store)
	var appleHandler = handlers.NewAppleHandler(appleCfg, store, sessionMgr, appleMgr, secretMgr)
	var authMiddleware = authhttp.NewAuth(sessionMgr).Middleware

	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/refresh", sessionHandler.Refresh)
	mux.HandleFunc("POST /auth/apple", appleHandler.Auth)
	mux.Handle("POST /auth/revoke", authMiddleware(http.HandlerFunc(sessionHandler.RevokeSingle)))
	mux.Handle("POST /auth/revoke/all", authMiddleware(http.HandlerFunc(sessionHandler.RevokeAll)))

	go func() {
		t := time.NewTicker(12 * time.Hour)
		defer t.Stop()
		for range t.C {
			if n, err := store.PruneAllExpired(context.Background(), time.Now()); err == nil && n > 0 {
				log.Printf("pruned %d expired refresh tokens", n)
			}
		}
	}()

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	log.Println("Listening on :" + port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
