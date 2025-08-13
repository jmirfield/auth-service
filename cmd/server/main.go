package main

import (
	"log"
	"net/http"
	"os"

	"github.com/jmirfield/auth-service/internals/apple"
	"github.com/jmirfield/auth-service/internals/handlers"
	authhttp "github.com/jmirfield/auth-service/internals/http"
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

	mgr, err := session.New(sessionCfg)
	if err != nil {
		log.Fatal(err)
	}

	var store = storage.NewMemoryStore()
	var sessionHandler = handlers.NewSessionHandler(mgr, store)
	var appleHandler = handlers.NewAppleHandler(appleCfg, store, mgr)
	var authMiddleware = authhttp.NewAuth(mgr).Middleware

	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/refresh", sessionHandler.Refresh)
	mux.HandleFunc("POST /auth/apple", appleHandler.Auth)
	mux.Handle("POST /auth/revoke", authMiddleware(http.HandlerFunc(sessionHandler.Revoke)))

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	log.Println("Listening on :" + port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
