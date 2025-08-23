package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jmirfield/auth-service/internals/apple"
	"github.com/jmirfield/auth-service/internals/domain/user"
	httpx "github.com/jmirfield/auth-service/internals/http"
	"github.com/jmirfield/auth-service/internals/repository"
	"github.com/jmirfield/auth-service/internals/secret"
	"github.com/jmirfield/auth-service/internals/session"
)

type AppleHandler struct {
	cfg  *apple.Config
	repo repository.UserReadWriter
	sm   *session.Manager
	am   *apple.Manager
	scm  *secret.Manager
}

func NewAppleHandler(cfg *apple.Config, ur repository.UserReadWriter, mgr *session.Manager, am *apple.Manager, scm *secret.Manager) (*AppleHandler, error) {
	if cfg == nil {
		return nil, errors.New("missing config")
	}

	if ur == nil {
		return nil, errors.New("missing user repository")
	}

	if mgr == nil {
		return nil, errors.New("missing session manager")
	}

	if am == nil {
		return nil, errors.New("missing apple manager")
	}

	if scm == nil {
		return nil, errors.New("missing secret manager")
	}

	return &AppleHandler{cfg: cfg, repo: ur, sm: mgr, am: am, scm: scm}, nil
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

	ident, err := h.repo.GetIdentityBySub(ctx, claims.Subject)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		httpx.InternalServerError(w)
		return
	}

	if ident == nil {
		usr := &user.User{
			ID: uuid.New(),
		}

		err := h.repo.UpsertUser(ctx, usr)
		if err != nil {
			httpx.InternalServerError(w)
			return
		}

		ident = &user.Identity{
			Uid:      usr.ID,
			Provider: claims.Issuer,
			Sub:      claims.Subject,
		}
		h.repo.UpsertIdentity(ctx, ident)
	}

	appAccess, appRefresh, err := h.sm.IssuePair(ident.Uid, nil)
	if err != nil {
		httpx.InternalServerError(w)
		return
	}

	rClaims, err := h.sm.ParseRefresh(appRefresh)
	if err != nil {
		httpx.InternalServerError(w)
		return
	}

	jtiUUID, err := uuid.Parse(rClaims.ID)
	if err != nil {
		httpx.InternalServerError(w)
		return
	}
	if err := h.repo.InsertRefreshToken(ctx, &user.RefreshToken{
		Uid:       ident.Uid,
		Hash:      secret.Hash(appRefresh),
		Jti:       jtiUUID,
		ExpiresAt: rClaims.ExpiresAt.Time,
	}); err != nil {
		httpx.InternalServerError(w)
		return
	}

	httpx.Json(w, http.StatusOK, authResponse{
		AccessToken:  appAccess,
		RefreshToken: appRefresh,
	})
}
