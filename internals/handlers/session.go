package handlers

import (
	"encoding/json"
	"net/http"

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
		httpx.Error(w, http.StatusBadRequest, "missing refresh token")
		return
	}

	claims, err := h.m.ParseRefresh(in.RefreshToken)
	if err != nil {
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

	if len(rec.RefreshTokens) <= 0 {
		httpx.Error(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	_, found := rec.FindRefreshToken(in.RefreshToken)
	if !found {
		httpx.Error(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	newAccess, newRefresh, err := h.m.RefreshFrom(in.RefreshToken, nil, true)
	if err != nil {
		httpx.Error(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	httpx.Json(w, http.StatusOK, refreshRes{
		AccessToken:  newAccess,
		RefreshToken: newRefresh,
	})
}

type revokeReq struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *SessionHandler) RevokeSingle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	uid, ok := httpx.UserIDFromContext(ctx)
	if !ok {
		httpx.Error(w, http.StatusUnauthorized, "user not found or disabled")
		return
	}

	var in revokeReq
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		httpx.Error(w, http.StatusBadRequest, "missing refresh token")
		return
	}

	claims, err := h.m.ParseRefresh(in.RefreshToken)
	if err != nil {
		httpx.NoContent(w)
		return
	}

	if claims.UserID != uid {
		httpx.NoContent(w)
		return
	}

	_, err = h.s.Update(ctx, uid, func(rec storage.Record) storage.Record {
		out := rec.RefreshTokens[:0]
		for _, rt := range rec.RefreshTokens {
			if rt.JTI == claims.ID {
				continue
			}
			out = append(out, rt)
		}
		rec.RefreshTokens = out
		return rec
	})
	if err != nil {
		httpx.InternalServerError(w)
		return
	}

	httpx.NoContent(w)
}

func (h *SessionHandler) RevokeAll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	uid, ok := httpx.UserIDFromContext(ctx)
	if !ok {
		httpx.Error(w, http.StatusUnauthorized, "missing or invalid session")
		return
	}

	_, err := h.s.Update(ctx, uid, func(rec storage.Record) storage.Record {
		rec.RefreshTokens = nil
		return rec
	})
	if err != nil {
		httpx.InternalServerError(w)
		return
	}

	httpx.NoContent(w)
}
