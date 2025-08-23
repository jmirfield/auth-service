package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	httpx "github.com/jmirfield/auth-service/internals/http"
	"github.com/jmirfield/auth-service/internals/repository"
	"github.com/jmirfield/auth-service/internals/secret"
	"github.com/jmirfield/auth-service/internals/session"
)

type SessionHandler struct {
	m    *session.Manager
	repo repository.UserReadWriter
}

func NewSessionHandler(mgr *session.Manager, repo repository.UserReadWriter) (*SessionHandler, error) {
	if mgr == nil {
		return nil, errors.New("missing session manager")
	}

	if repo == nil {
		return nil, errors.New("missing user repository")
	}

	return &SessionHandler{m: mgr, repo: repo}, nil
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

	uid, err := uuid.Parse(claims.Subject)
	if err != nil {
		httpx.Error(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	_, err = h.repo.GetUser(ctx, uid)
	if err != nil {
		httpx.Error(w, http.StatusUnauthorized, "user not found or disabled")
		return
	}

	_, err = h.repo.FindRefreshTokenByHash(ctx, uid, secret.Hash(in.RefreshToken))
	if err != nil {
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

	if claims.Subject != uid.String() {
		httpx.NoContent(w)
		return
	}

	tokenID, err := uuid.Parse(claims.ID)
	if err != nil {
		httpx.InternalServerError(w)
		return
	}
	_, err = h.repo.DeleteRefreshToken(ctx, uid, tokenID)
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

	_, err := h.repo.DeleteAllRefreshTokens(ctx, uid)
	if err != nil {
		httpx.InternalServerError(w)
		return
	}

	httpx.NoContent(w)
}
