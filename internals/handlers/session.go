package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jmirfield/auth-service/internals/session"
	httpx "github.com/jmirfield/auth-service/pkg/http"
)

type SessionHandler struct {
	svc *session.Service
}

func NewSessionHandler(svc *session.Service) (*SessionHandler, error) {
	if svc == nil {
		return nil, errors.New("missing session service")
	}

	return &SessionHandler{svc: svc}, nil
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token"`
}

type refreshRes struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func (h *SessionHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var in refreshReq
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || in.RefreshToken == "" {
		httpx.Error(w, http.StatusBadRequest, "missing refresh token")
		return
	}

	newAccess, newRefresh, err := h.svc.Refresh(ctx, in.RefreshToken, true)
	if err != nil {
		switch err {
		case session.ErrInvalidToken:
		case session.ErrUserNotFound:
			httpx.Error(w, http.StatusBadRequest, err.Error())
		default:
			httpx.InternalServerError(w)
		}
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
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		httpx.Error(w, http.StatusBadRequest, "missing refresh token")
		return
	}

	err := h.svc.RevokeSingle(ctx, uid, in.RefreshToken)
	if err != nil {
		switch err {
		case session.ErrInvalidToken:
			httpx.NoContent(w)
		default:
			httpx.InternalServerError(w)
		}
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

	err := h.svc.RevokeAll(ctx, uid)
	if err != nil {
		httpx.InternalServerError(w)
		return
	}

	httpx.NoContent(w)
}
