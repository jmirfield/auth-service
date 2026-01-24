package handlers

import (
	"errors"
	"net/http"
	"strings"

	httpx "github.com/jmirfield/auth-service/pkg/http"
	"github.com/jmirfield/auth-service/pkg/session"
)

type WellKnownHandler struct {
	issuer  string
	jwks    session.JWKSProvider
	baseURL string
}

func NewWellKnownHandler(issuer string, jwks session.JWKSProvider) (*WellKnownHandler, error) {
	if issuer == "" {
		return nil, errors.New("missing issuer")
	}
	if jwks == nil {
		return nil, errors.New("missing jwks provider")
	}

	base := strings.TrimRight(issuer, "/")
	return &WellKnownHandler{
		issuer:  issuer,
		jwks:    jwks,
		baseURL: base,
	}, nil
}

func (h *WellKnownHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	doc, err := h.jwks.PublicJWKS()
	if err != nil {
		httpx.InternalServerError(w)
		return
	}
	httpx.Json(w, http.StatusOK, doc)
}

type openIDConfig struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	TokenEndpoint                    string   `json:"token_endpoint,omitempty"`
	GrantTypesSupported              []string `json:"grant_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`
}

func (h *WellKnownHandler) OpenIDConfig(w http.ResponseWriter, r *http.Request) {
	httpx.Json(w, http.StatusOK, openIDConfig{
		Issuer:                           h.issuer,
		JWKSURI:                          h.baseURL + "/.well-known/jwks.json",
		TokenEndpoint:                    h.baseURL + "/token/refresh",
		GrantTypesSupported:              []string{"refresh_token"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	})
}
