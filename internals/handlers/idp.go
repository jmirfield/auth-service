package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jmirfield/auth-service/internals/idp"
	httpx "github.com/jmirfield/auth-service/pkg/http"
)

type IdpHandler struct {
	svc *idp.Service
}

func NewIdpHandler(svc *idp.Service) (*IdpHandler, error) {
	if svc == nil {
		return nil, errors.New("missing idp service")
	}
	return &IdpHandler{svc: svc}, nil
}

type idpAuthReq struct {
	Code  string `json:"code"`
	Nonce string `json:"nonce,omitempty"`
}

type idpAuthRes struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (h *IdpHandler) Auth(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	h.authWithProvider(w, r, provider)
}

func (h *IdpHandler) AuthProvider(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.authWithProvider(w, r, provider)
	}
}

func (h *IdpHandler) authWithProvider(w http.ResponseWriter, r *http.Request, provider string) {
	ctx := r.Context()

	var in idpAuthReq
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || in.Code == "" {
		httpx.Error(w, http.StatusBadRequest, "missing code")
		return
	}

	appAccess, appRefresh, err := h.svc.Auth(ctx, provider, in.Code, in.Nonce)
	if err != nil {
		switch err {
		case idp.ErrUnknownProvider:
		case idp.ErrBadCode:
		case idp.ErrInvalidToken:
			httpx.Error(w, http.StatusBadRequest, err.Error())
		default:
			httpx.InternalServerError(w)
		}
		return
	}

	httpx.Json(w, http.StatusOK, idpAuthRes{
		AccessToken:  appAccess,
		RefreshToken: appRefresh,
	})
}
