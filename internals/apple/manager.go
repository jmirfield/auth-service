package apple

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jmirfield/auth-service/internals/cache"
	httpx "github.com/jmirfield/auth-service/internals/http"
	jwkx "github.com/jmirfield/auth-service/internals/jwk"
)

type Manager struct {
	cfg    *Config
	cache  cache.Provider[rsa.PublicKey]
	client httpx.HttpClient
}

type Claims struct {
	Nonce string `json:"nonce,omitempty"`
	jwt.RegisteredClaims
}

type jwk struct {
	Kty string `json:"kty"` // "RSA"
	Kid string `json:"kid"`
	Use string `json:"use"` // "sig"
	Alg string `json:"alg"` // "RS256"
	N   string `json:"n"`   // base64url modulus
	E   string `json:"e"`   // base64url exponent
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

func NewManager(cfg *Config, provider cache.Provider[rsa.PublicKey], client httpx.HttpClient) (*Manager, error) {
	if cfg == nil {
		return nil, errors.New("missing config")
	}

	if provider == nil {
		return nil, errors.New("missing cache provider")
	}

	var manager = &Manager{
		cfg:    cfg,
		cache:  provider,
		client: client,
	}

	return manager, nil
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
		key, err := m.fetchApplePublicKey(ctx, kid)
		if err != nil {
			return nil, err
		}
		return &key, nil
	})
	if err != nil {
		return nil, err
	}

	if claims.Issuer != "https://appleid.apple.com" {
		return nil, errors.New("invalid issuer")
	}

	if !slices.Contains(claims.Audience, m.cfg.ClientID) {
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
	secret, err := m.generateClientSecret()
	if err != nil {
		return nil, err
	}

	data := url.Values{}
	data.Set("client_id", m.cfg.ClientID)
	data.Set("client_secret", secret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")

	return m.postToken(data)
}

func (m *Manager) Refresh(refreshToken string) (*TokenResponse, error) {
	if refreshToken == "" {
		return nil, errors.New("missing refresh token")
	}

	secret, err := m.generateClientSecret()
	if err != nil {
		return nil, err
	}

	data := url.Values{}
	data.Set("client_id", m.cfg.ClientID)
	data.Set("client_secret", secret)
	data.Set("refresh_token", refreshToken)
	data.Set("grant_type", "refresh_token")

	return m.postToken(data)
}

func (m *Manager) generateClientSecret() (string, error) {
	claims := jwt.MapClaims{
		"iss": m.cfg.TeamID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"aud": "https://appleid.apple.com",
		"sub": m.cfg.ClientID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = m.cfg.KeyID
	return token.SignedString(m.cfg.PrivateKey)
}

func (m *Manager) postToken(values url.Values) (*TokenResponse, error) {
	resp, err := m.client.Post(
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

func (m *Manager) fetchApplePublicKey(ctx context.Context, kid string) (rsa.PublicKey, error) {
	var key rsa.PublicKey
	key, err := m.cache.Get(ctx, kid)
	if err == nil {
		return key, nil
	}

	if !errors.Is(err, cache.ErrNotFound) {
		return key, err
	}

	if err := m.refreshJWKS(ctx); err != nil {
		return key, err
	}

	key, err = m.cache.Get(ctx, kid)
	if err != nil {
		return key, fmt.Errorf("public key for kid %q not found after refresh: %w", kid, err)
	}

	return key, nil
}

func (m *Manager) refreshJWKS(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://appleid.apple.com/auth/keys", nil)
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return errors.New("jwks fetch failed: non-2xx")
	}

	var doc jwks
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return err
	}

	keys := make(map[string]rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.N == "" || k.E == "" {
			continue
		}
		pub, err := jwkx.JWKToRSA(k.N, k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = *pub
	}

	if len(keys) == 0 {
		return errors.New("empty JWKS")
	}

	for kid, key := range keys {
		m.cache.Set(ctx, kid, key, m.cfg.JwkCacheTTL)
	}
	return nil
}
