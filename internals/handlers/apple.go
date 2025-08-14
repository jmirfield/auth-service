package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/jmirfield/auth-service/internals/apple"
	httpx "github.com/jmirfield/auth-service/internals/http"
	"github.com/jmirfield/auth-service/internals/secret"
	"github.com/jmirfield/auth-service/internals/session"
	"github.com/jmirfield/auth-service/internals/storage"
)

type AppleHandler struct {
	c   *apple.Config
	s   storage.Store
	sm  *session.Manager
	am  *apple.Manager
	scm *secret.Manager
}

func NewAppleHandler(cfg *apple.Config, store storage.Store, mgr *session.Manager, am *apple.Manager, scm *secret.Manager) *AppleHandler {
	return &AppleHandler{c: cfg, s: store, sm: mgr, am: am, scm: scm}
}

type appleAuthReq struct {
	Code  string `json:"code"`
	Nonce string `json:"nonce,omitempty"`
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

	tok, err := h.am.ExchangeCode(in.Code)
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "bad code")
		return
	}

	var claims *apple.Claims
	claims, err = h.am.VerifyIDToken(tok.IDToken, in.Nonce)
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid id token")
		return
	}

	userID := claims.Subject
	appAccess, appRefresh, err := h.sm.IssuePair(userID, nil)
	if err != nil {
		httpx.InternalServerError(w)
		return
	}

	rClaims, err := h.sm.ParseRefresh(appRefresh)
	if err != nil {
		httpx.InternalServerError(w)
		return
	}

	enctok, err := h.scm.Encrypt(tok.RefreshToken)
	if err != nil {
		httpx.InternalServerError(w)
		return
	}

	if _, err := h.s.Update(ctx, userID, func(rec storage.Record) storage.Record {
		rec.UserID = userID
		rec.RefreshTokensByProvider[storage.ProviderApple] = enctok
		rec.RefreshTokens = append(rec.RefreshTokens, storage.RefreshTokenRecord{
			Hash:      secret.Hash(appRefresh),
			JTI:       rClaims.ID,
			ExpiresAt: rClaims.ExpiresAt.Time,
			CreatedAt: rClaims.IssuedAt.Time,
		})

		return rec
	}); err != nil {
		httpx.InternalServerError(w)
		return
	}

	httpx.Json(w, http.StatusOK, authResponse{
		AccessToken:  appAccess,
		RefreshToken: appRefresh,
	})
}
