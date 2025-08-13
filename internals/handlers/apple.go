package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/jmirfield/auth-service/internals/apple"
	httpx "github.com/jmirfield/auth-service/internals/http"
	"github.com/jmirfield/auth-service/internals/session"
	"github.com/jmirfield/auth-service/internals/storage"
)

type AppleHandler struct {
	c *apple.Config
	s storage.Store
	m *session.Manager
}

func NewAppleHandler(cfg *apple.Config, store storage.Store, mgr *session.Manager) *AppleHandler {
	return &AppleHandler{c: cfg, s: store, m: mgr}
}

type appleAuthReq struct {
	Code string `json:"code"`
}

type authResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (h *AppleHandler) Auth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var in appleAuthReq
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Code == "" {
		httpx.Error(w, http.StatusBadRequest, "missing code")
		return
	}

	// 1) Exchange authorization code with Apple
	tok, err := apple.ExchangeCode(h.c, in.Code)
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}

	// 2) Verify the ID token
	var claims *apple.AppleClaims
	claims, err = apple.VerifyIDToken(h.c, tok.IDToken)

	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid id_token")
		return
	}

	// 3) Derive stable user key
	userID := "apple:" + claims.Subject

	// 4) Issue YOUR session tokens (access + refresh)
	appAccess, appRefresh, err := h.m.IssuePair(userID, nil)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to issue session tokens")
		return
	}

	// 5) Persist minimal provider state + useful attributes
	if _, err := h.s.Update(ctx, userID, func(rec storage.Record) storage.Record {
		rec.UserID = userID
		if rec.TokensByProvider == nil {
			rec.TokensByProvider = make(map[string]storage.Tokens)
		}

		rec.TokensByProvider[storage.ProviderApple] = storage.Tokens{
			RefreshToken: tok.RefreshToken,
		}

		rec.RefreshToken = appRefresh

		return rec
	}); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to persist tokens")
		return
	}

	httpx.Json(w, http.StatusOK, authResponse{
		AccessToken:  appAccess,
		RefreshToken: appRefresh,
	})
}
