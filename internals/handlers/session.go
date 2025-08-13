package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	httpx "github.com/jmirfield/auth-service/internals/http"
	"github.com/jmirfield/auth-service/internals/session"
	"github.com/jmirfield/auth-service/internals/storage"
)

type SessionHandler struct {
	m *session.Manager
	s storage.Store
}

func NewSessionHandler(mgr *session.Manager, store storage.Store) *SessionHandler {
	return &SessionHandler{m: mgr, s: store}
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token"`
}

type refreshRes struct {
	AccessToken  string `json:"app_access_token"`
	RefreshToken string `json:"app_refresh_token,omitempty"`
}

func (h *SessionHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var in refreshReq
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.RefreshToken == "" {
		httpx.Error(w, http.StatusBadRequest, "missing refresh_token")
		return
	}

	claims, err := h.m.ParseRefresh(in.RefreshToken)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			httpx.Error(w, http.StatusUnauthorized, "refresh token expired")
			return
		}
		httpx.Error(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	uid := claims.UserID
	if uid == "" {
		httpx.Error(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	rec, err := h.s.Get(ctx, uid)
	if err != nil {
		httpx.Error(w, http.StatusUnauthorized, "user not found or disabled")
		return
	}

	if rec.RefreshToken != "" && rec.RefreshToken != in.RefreshToken {
		httpx.Error(w, http.StatusUnauthorized, "invalid or rotated refresh token")
		return
	}

	newAccess, newRefresh, err := h.m.RefreshFrom(in.RefreshToken, nil, true)
	if err != nil {
		httpx.Error(w, http.StatusUnauthorized, "invalid or expired refresh token")
		return
	}

	httpx.Json(w, http.StatusOK, refreshRes{
		AccessToken:  newAccess,
		RefreshToken: newRefresh,
	})
}

func (h *SessionHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	uid, ok := httpx.UserIDFromContext(ctx)
	if !ok {
		httpx.Error(w, http.StatusUnauthorized, "missing or invalid session")
		return
	}

	_, err := h.s.Update(ctx, uid, func(rec storage.Record) storage.Record {
		rec.RefreshToken = ""
		return rec
	})
	if err != nil {
		httpx.InternalServerError(w)
		return
	}

	httpx.Json(w, http.StatusOK, "")
}
