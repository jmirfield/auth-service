package apple

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jmirfield/auth-service/internals/cache"
)

type fakeHTTP struct {
	DoFunc   func(req *http.Request) (*http.Response, error)
	PostFunc func(url, contentType string, body io.Reader) (*http.Response, error)
}

func (f *fakeHTTP) Do(req *http.Request) (*http.Response, error) {
	if f.DoFunc != nil {
		return f.DoFunc(req)
	}
	return nil, errors.New("unexpected Do call")
}
func (f *fakeHTTP) Post(u, ct string, body io.Reader) (*http.Response, error) {
	if f.PostFunc != nil {
		return f.PostFunc(u, ct, body)
	}
	return nil, errors.New("unexpected Post call")
}

func mustRSAKey(tb testing.TB) *rsa.PrivateKey {
	tb.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatal(err)
	}
	return k
}

func mustECDSAKey(tb testing.TB) *ecdsa.PrivateKey {
	tb.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	return k
}

func b64u(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

func jwksJSON(kid string, pub *rsa.PublicKey) []byte {
	n := b64u(pub.N.Bytes())
	e := b64u(bigIntToBytes(pub.E))
	doc := map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"kid": kid,
			"use": "sig",
			"alg": "RS256",
			"n":   n,
			"e":   e,
		}},
	}
	buf, _ := json.Marshal(doc)
	return buf
}

func bigIntToBytes(e int) []byte {
	if e == 0 {
		return []byte{0}
	}
	var tmp []byte
	for x := e; x > 0; x >>= 8 {
		tmp = append([]byte{byte(x & 0xff)}, tmp...)
	}
	return tmp
}

func signRS256(tb testing.TB, kid string, priv *rsa.PrivateKey, claims *Claims) string {
	tb.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(priv)
	if err != nil {
		tb.Fatalf("signRS256: %v", err)
	}
	return s
}

func TestNewManager_Args(t *testing.T) {
	cfg := &Config{}
	c := cache.NewMemory[rsa.PublicKey](t.Context())
	h := &fakeHTTP{}

	if _, err := NewManager(nil, c, h); err == nil {
		t.Fatal("expected error for nil cfg")
	}
	if _, err := NewManager(cfg, nil, h); err == nil {
		t.Fatal("expected error for nil cache provider")
	}
	m, err := NewManager(cfg, c, h)
	if err != nil || m == nil {
		t.Fatalf("unexpected NewManager error: %v", err)
	}
}

func TestVerifyIDToken_Success(t *testing.T) {
	rsaPriv := mustRSAKey(t)
	rsaPub := rsaPriv.Public().(*rsa.PublicKey)
	kid := "kid-1"
	clientID := "com.example.app"

	cfg := &Config{
		ClientID:    clientID,
		JwkCacheTTL: time.Hour,
	}
	c := cache.NewMemory[rsa.PublicKey](t.Context())
	_ = c.Set(t.Context(), kid, *rsaPub, time.Hour)

	m, _ := NewManager(cfg, c, &fakeHTTP{})

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://appleid.apple.com",
			Audience:  jwt.ClaimStrings{clientID},
			Subject:   "user-123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	idToken := signRS256(t, kid, rsaPriv, claims)

	got, err := m.VerifyIDToken(t.Context(), idToken)
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if got.Subject != "user-123" {
		t.Fatalf("Subject = %q, want %q", got.Subject, "user-123")
	}
}

func TestVerifyIDToken_Nonce_Plain_And_SHA256(t *testing.T) {
	rsaPriv := mustRSAKey(t)
	rsaPub := rsaPriv.Public().(*rsa.PublicKey)
	kid := "kid-2"
	clientID := "app.id"

	cfg := &Config{ClientID: clientID}
	c := cache.NewMemory[rsa.PublicKey](t.Context())
	_ = c.Set(t.Context(), kid, *rsaPub, time.Hour)
	m, _ := NewManager(cfg, c, &fakeHTTP{})

	nonce := "abc123"
	sum := sha256.Sum256([]byte(nonce))
	for i, nonceInToken := range []string{nonce, hex.EncodeToString(sum[:])} {
		claims := &Claims{
			Nonce: nonceInToken,
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:   "https://appleid.apple.com",
				Audience: jwt.ClaimStrings{clientID},
				Subject:  "u",
			},
		}
		idToken := signRS256(t, kid, rsaPriv, claims)
		if _, err := m.VerifyIDToken(t.Context(), idToken, nonce); err != nil {
			t.Fatalf("case %d: VerifyIDToken with nonce failed: %v", i, err)
		}
	}
}

func TestVerifyIDToken_ErrorPaths(t *testing.T) {
	rsaPriv := mustRSAKey(t)
	rsaPub := rsaPriv.Public().(*rsa.PublicKey)
	kid := "kid-3"
	clientID := "cid"
	cfg := &Config{ClientID: clientID}
	c := cache.NewMemory[rsa.PublicKey](t.Context())
	_ = c.Set(t.Context(), kid, *rsaPub, time.Hour)
	m, _ := NewManager(cfg, c, &fakeHTTP{})

	makeClaims := func(mod func(*Claims)) *Claims {
		cl := &Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:   "https://appleid.apple.com",
				Audience: jwt.ClaimStrings{clientID},
				Subject:  "u",
			},
		}
		if mod != nil {
			mod(cl)
		}
		return cl
	}

	t.Run("empty token", func(t *testing.T) {
		if _, err := m.VerifyIDToken(t.Context(), ""); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("missing kid", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, makeClaims(nil))
		s, _ := tok.SignedString(rsaPriv)
		if _, err := m.VerifyIDToken(t.Context(), s); err == nil {
			t.Fatal("expected error due to missing kid")
		}
	})

	t.Run("invalid issuer", func(t *testing.T) {
		id := signRS256(t, kid, rsaPriv, makeClaims(func(c *Claims) { c.Issuer = "x" }))
		if _, err := m.VerifyIDToken(t.Context(), id); err == nil || !strings.Contains(err.Error(), "invalid issuer") {
			t.Fatalf("want invalid issuer error, got %v", err)
		}
	})

	t.Run("invalid audience", func(t *testing.T) {
		id := signRS256(t, kid, rsaPriv, makeClaims(func(c *Claims) { c.Audience = jwt.ClaimStrings{"other"} }))
		if _, err := m.VerifyIDToken(t.Context(), id); err == nil || !strings.Contains(err.Error(), "invalid audience") {
			t.Fatalf("want invalid audience error, got %v", err)
		}
	})

	t.Run("missing sub", func(t *testing.T) {
		id := signRS256(t, kid, rsaPriv, makeClaims(func(c *Claims) { c.Subject = "" }))
		if _, err := m.VerifyIDToken(t.Context(), id); err == nil || !strings.Contains(err.Error(), "missing sub") {
			t.Fatalf("want missing sub error, got %v", err)
		}
	})

	t.Run("nonce required but missing", func(t *testing.T) {
		id := signRS256(t, kid, rsaPriv, makeClaims(nil))
		if _, err := m.VerifyIDToken(t.Context(), id, "need-nonce"); err == nil || !strings.Contains(err.Error(), "nonce required") {
			t.Fatalf("want nonce required error, got %v", err)
		}
	})

	t.Run("nonce mismatch", func(t *testing.T) {
		id := signRS256(t, kid, rsaPriv, makeClaims(func(c *Claims) { c.Nonce = "foo" }))
		if _, err := m.VerifyIDToken(t.Context(), id, "bar"); err == nil || !strings.Contains(err.Error(), "nonce mismatch") {
			t.Fatalf("want nonce mismatch error, got %v", err)
		}
	})
}

func TestVerifyIDToken_KeyCacheMissTriggersJWKSRefresh(t *testing.T) {
	rsaPriv := mustRSAKey(t)
	rsaPub := rsaPriv.Public().(*rsa.PublicKey)
	kid := "kid-jwks"
	clientID := "cid"

	cfg := &Config{ClientID: clientID, JwkCacheTTL: time.Minute}

	c := cache.NewMemory[rsa.PublicKey](t.Context())
	httpCli := &fakeHTTP{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			if req.Method != http.MethodGet || !strings.Contains(req.URL.String(), "/auth/keys") {
				t.Fatalf("unexpected Do for %s %s", req.Method, req.URL)
			}
			body := io.NopCloser(bytes.NewReader(jwksJSON(kid, rsaPub)))
			return &http.Response{
				StatusCode: 200,
				Body:       body,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
			}, nil
		},
	}

	m, _ := NewManager(cfg, c, httpCli)

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   "https://appleid.apple.com",
			Audience: jwt.ClaimStrings{clientID},
			Subject:  "u",
		},
	}
	id := signRS256(t, kid, rsaPriv, claims)

	if _, err := m.VerifyIDToken(t.Context(), id); err != nil {
		t.Fatalf("VerifyIDToken after JWKS refresh failed: %v", err)
	}
}

func TestExchangeCode_Success(t *testing.T) {
	ecdsaPriv := mustECDSAKey(t)
	cfg := &Config{
		TeamID:     "T123",
		ClientID:   "com.example",
		KeyID:      "KID123",
		PrivateKey: ecdsaPriv,
	}
	var captured url.Values

	httpCli := &fakeHTTP{
		PostFunc: func(u, ct string, body io.Reader) (*http.Response, error) {
			if u != "https://appleid.apple.com/auth/token" {
				t.Fatalf("unexpected URL: %s", u)
			}
			if ct != "application/x-www-form-urlencoded" {
				t.Fatalf("unexpected content-type: %s", ct)
			}
			buf := new(bytes.Buffer)
			switch b := body.(type) {
			case *bytes.Buffer:
				io.Copy(buf, b)
			default:
				t.Fatalf("unexpected body type %T", body)
			}
			captured, _ = url.ParseQuery(buf.String())

			out := TokenResponse{
				AccessToken:  "at",
				RefreshToken: "rt",
				IDToken:      "id",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
			}
			js, _ := json.Marshal(out)
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewReader(js)),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
			}, nil
		},
	}

	m, _ := NewManager(cfg, cache.NewMemory[rsa.PublicKey](t.Context()), httpCli)

	resp, err := m.ExchangeCode(t.Context(), "the-code")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if resp.AccessToken != "at" || resp.RefreshToken != "rt" {
		t.Fatalf("unexpected token response: %+v", resp)
	}

	if captured.Get("client_id") != cfg.ClientID ||
		captured.Get("grant_type") != "authorization_code" ||
		captured.Get("code") != "the-code" ||
		captured.Get("client_secret") == "" {
		t.Fatalf("unexpected posted form: %v", captured)
	}
}

func TestExchangeCode_HTTPErrorBubbles(t *testing.T) {
	cfg := &Config{
		TeamID:     "T",
		ClientID:   "C",
		KeyID:      "K",
		PrivateKey: mustECDSAKey(t),
	}

	httpCli := &fakeHTTP{
		PostFunc: func(u, ct string, body io.Reader) (*http.Response, error) {
			return &http.Response{
				StatusCode: 400,
				Body:       io.NopCloser(strings.NewReader("nope")),
			}, nil
		},
	}

	m, _ := NewManager(cfg, cache.NewMemory[rsa.PublicKey](t.Context()), httpCli)
	_, err := m.ExchangeCode(t.Context(), "x")
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("want propagated error body, got %v", err)
	}
}

func TestRefresh_Success_And_MissingToken(t *testing.T) {
	cfg := &Config{
		TeamID:     "T1",
		ClientID:   "C1",
		KeyID:      "K1",
		PrivateKey: mustECDSAKey(t),
	}
	httpCli := &fakeHTTP{
		PostFunc: func(u, ct string, body io.Reader) (*http.Response, error) {
			out := TokenResponse{AccessToken: "new-at", RefreshToken: "new-rt"}
			js, _ := json.Marshal(out)
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewReader(js)),
			}, nil
		},
	}
	m, _ := NewManager(cfg, cache.NewMemory[rsa.PublicKey](t.Context()), httpCli)

	// Missing token
	if _, err := m.Refresh(t.Context(), ""); err == nil {
		t.Fatal("expected error for missing refresh token")
	}

	// Success path
	resp, err := m.Refresh(t.Context(), "rt")
	if err != nil {
		t.Fatalf("Refresh error: %v", err)
	}
	if resp.AccessToken != "new-at" {
		t.Fatalf("Resp.AccessToken = %q, want new-at", resp.AccessToken)
	}
}
