package apple

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AppleClaims struct {
	jwt.RegisteredClaims
}

func VerifyIDToken(cfg *Config, idToken string) (*AppleClaims, error) {
	if idToken == "" {
		return nil, errors.New("empty id_token")
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithLeeway(60*time.Second),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	claims := &AppleClaims{}
	_, err := parser.ParseWithClaims(idToken, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid in header")
		}
		return fetchApplePublicKey(ctx, kid)
	})
	if err != nil {
		return nil, err
	}

	if claims.Issuer != "https://appleid.apple.com" {
		return nil, errors.New("invalid issuer")
	}

	if !slices.Contains(claims.Audience, cfg.ClientID) {
		return nil, errors.New("invalid audience")
	}

	// Ensure sub present & normalized between custom and registered fields.
	if claims.Subject == "" {
		return nil, errors.New("missing sub")
	}

	return claims, nil
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

func ExchangeCode(cfg *Config, code string) (*TokenResponse, error) {
	secret, err := generateClientSecret(cfg)
	if err != nil {
		return nil, err
	}

	data := url.Values{}
	data.Set("client_id", cfg.ClientID)
	data.Set("client_secret", secret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")

	return postToken(data)
}

func Refresh(cfg *Config, refreshToken string) (*TokenResponse, error) {
	if refreshToken == "" {
		return nil, errors.New("missing refresh token")
	}
	secret, err := generateClientSecret(cfg)
	if err != nil {
		return nil, err
	}

	data := url.Values{}
	data.Set("client_id", cfg.ClientID)
	data.Set("client_secret", secret)
	data.Set("refresh_token", refreshToken)
	data.Set("grant_type", "refresh_token")

	return postToken(data)
}

func generateClientSecret(cfg *Config) (string, error) {
	claims := jwt.MapClaims{
		"iss": cfg.TeamID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"aud": "https://appleid.apple.com",
		"sub": cfg.ClientID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = cfg.KeyID
	return token.SignedString(cfg.PrivateKey)
}

func postToken(values url.Values) (*TokenResponse, error) {
	resp, err := http.Post(
		"https://appleid.apple.com/auth/token",
		"application/x-www-form-urlencoded",
		bytes.NewBufferString(values.Encode()),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(string(body))
	}

	var out TokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
