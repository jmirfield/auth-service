package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jmirfield/auth-service/internals/apple"
	httpx "github.com/jmirfield/auth-service/pkg/http"
)

type AppleHandler struct {
	svc *apple.Service
}

func NewAppleHandler(svc *apple.Service) (*AppleHandler, error) {
	if svc == nil {
		return nil, errors.New("missing apple service")
	}

	return &AppleHandler{svc: svc}, nil
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
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || in.Code == "" {
		httpx.Error(w, http.StatusBadRequest, "missing code")
		return
	}

	appAccess, appRefresh, err := h.svc.Auth(ctx, in.Code, in.Nonce)
	if err != nil {
		switch err {
		case apple.ErrBadCode:
		case apple.ErrInvalidToken:
			httpx.Error(w, http.StatusBadRequest, err.Error())
		default:
			httpx.InternalServerError(w)
		}
		return
	}

	httpx.Json(w, http.StatusOK, authResponse{
		AccessToken:  appAccess,
		RefreshToken: appRefresh,
	})
}
