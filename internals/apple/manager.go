package apple

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Manager struct {
	config *Config
}

func NewManager(cfg *Config) (*Manager, error) {
	return &Manager{
		config: cfg,
	}, nil
}

type Claims struct {
	Nonce string `json:"nonce,omitempty"`
	jwt.RegisteredClaims
}

func (m *Manager) VerifyIDToken(idToken string, nonce ...string) (*Claims, error) {
	if idToken == "" {
		return nil, errors.New("empty id_token")
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithLeeway(60*time.Second),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	claims := &Claims{}
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

	if !slices.Contains(claims.Audience, m.config.ClientID) {
		return nil, errors.New("invalid audience")
	}

	if claims.Subject == "" {
		return nil, errors.New("missing sub")
	}

	if len(nonce) > 0 && nonce[0] != "" {
		want := nonce[0]
		if claims.Nonce == "" {
			return nil, errors.New("nonce required but missing in id_token")
		}
		if claims.Nonce != want && claims.Nonce != sha256Hex(want) {
			return nil, errors.New("nonce mismatch")
		}
	}

	return claims, nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

func (m *Manager) ExchangeCode(code string) (*TokenResponse, error) {
	secret, err := generateClientSecret(m.config)
	if err != nil {
		return nil, err
	}

	data := url.Values{}
	data.Set("client_id", m.config.ClientID)
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
