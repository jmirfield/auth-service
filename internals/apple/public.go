package apple

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"sync"
	"time"
)

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

var (
	jwksCache = struct {
		sync.RWMutex
		keys    map[string]*rsa.PublicKey // kid -> key
		fetched time.Time
		ttl     time.Duration
	}{ttl: 6 * time.Hour}

	// Reusable HTTP client with timeout for JWKS fetch.
	httpClient = &http.Client{Timeout: 5 * time.Second}
)

func fetchApplePublicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	// Fast path: cached and fresh.
	if key := getCachedKey(kid); key != nil {
		return key, nil
	}
	// Refresh cache.
	if err := refreshJWKS(ctx); err != nil {
		return nil, err
	}
	if key := getCachedKey(kid); key != nil {
		return key, nil
	}
	return nil, errors.New("public key not found for kid")
}

func getCachedKey(kid string) *rsa.PublicKey {
	jwksCache.RLock()
	defer jwksCache.RUnlock()
	if time.Since(jwksCache.fetched) < jwksCache.ttl && jwksCache.keys != nil {
		return jwksCache.keys[kid]
	}
	return nil
}

func refreshJWKS(ctx context.Context) error {
	jwksCache.Lock()
	defer jwksCache.Unlock()

	// If still fresh (maybe another goroutine refreshed), skip.
	if time.Since(jwksCache.fetched) < jwksCache.ttl && jwksCache.keys != nil {
		return nil
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://appleid.apple.com/auth/keys", nil)
	resp, err := httpClient.Do(req)
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

	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.N == "" || k.E == "" {
			continue
		}
		pub, err := jwkToRSA(k.N, k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return errors.New("empty JWKS")
	}

	jwksCache.keys = keys
	jwksCache.fetched = time.Now()
	return nil
}

func jwkToRSA(nB64url, eB64url string) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(nB64url)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(eB64url)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nb)

	// Exponent is small; convert bytes to int.
	var e int
	for _, b := range eb {
		e = e<<8 | int(b)
	}
	if e == 0 {
		return nil, errors.New("invalid exponent")
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}
