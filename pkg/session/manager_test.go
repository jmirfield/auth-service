package session

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// helper to build a test manager with sane defaults
func newTestMgr(t *testing.T, opts ...func(*Config)) SessionManager {
	t.Helper()
	key := testRSAKey(t)
	cfg := &Config{
		KeyID:           "test-kid",
		PrivateKey:      key,
		PublicKeys:      map[string]*rsa.PublicKey{"test-kid": &key.PublicKey},
		Issuer:          "issuer.test",
		Audience:        "aud.test",
		AccessLifetime:  15 * time.Minute,
		RefreshLifetime: 30 * 24 * time.Hour,
		ClockSkewLeeway: 30 * time.Second,
	}
	for _, o := range opts {
		o(cfg)
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("New manager: %v", err)
	}
	return mgr
}

func newTestManager(t *testing.T, opts ...func(*Config)) *Manager {
	t.Helper()
	key := testRSAKey(t)
	cfg := &Config{
		KeyID:           "test-kid",
		PrivateKey:      key,
		PublicKeys:      map[string]*rsa.PublicKey{"test-kid": &key.PublicKey},
		Issuer:          "issuer.test",
		Audience:        "aud.test",
		AccessLifetime:  15 * time.Minute,
		RefreshLifetime: 30 * 24 * time.Hour,
		ClockSkewLeeway: 30 * time.Second,
	}
	for _, o := range opts {
		o(cfg)
	}
	mgrAny, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("New manager: %v", err)
	}
	mgr, ok := mgrAny.(*Manager)
	if !ok {
		t.Fatalf("expected *Manager, got %T", mgrAny)
	}
	return mgr
}

var testKeyOnce sync.Once
var testKey *rsa.PrivateKey

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate RSA key: %v", err)
		}
		testKey = key
	})
	return testKey
}

func TestIssueAndParseAccess(t *testing.T) {
	mgr := newTestMgr(t)

	attrs := map[string]string{"email": "user@example.com"}
	var userID = uuid.MustParse("de2f8213-246d-4f95-8e02-1431b47e0a09")
	tok, err := mgr.IssueAccess(t.Context(), userID, attrs)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}

	claims, err := mgr.ParseAccess(t.Context(), tok)
	if err != nil {
		t.Fatalf("ParseAccess: %v", err)
	}

	if claims.Subject != userID.String() {
		t.Fatalf("got uid %q, want %q", claims.Subject, userID)
	}
	if claims.TokenType != tokenTypeAccess {
		t.Fatalf("got token_type %q, want %q", claims.TokenType, tokenTypeAccess)
	}
	// issuer/audience checks
	if claims.Issuer != "issuer.test" {
		t.Fatalf("got iss %q, want %q", claims.Issuer, "issuer.test")
	}
	if !slices.Contains(claims.Audience, "aud.test") {
		t.Fatalf("aud does not contain %q: %v", "aud.test", claims.Audience)
	}
	// iat <= exp
	if !claims.IssuedAt.Time.Before(claims.ExpiresAt.Time) {
		t.Fatalf("issuedAt not before expiresAt: %v >= %v", claims.IssuedAt, claims.ExpiresAt)
	}
	if claims.Attrs["email"] != "user@example.com" {
		t.Fatalf("attrs not propagated")
	}
}

func TestIssueAndParseRefresh(t *testing.T) {
	mgr := newTestMgr(t)

	var userId = uuid.MustParse("b572fbcc-f567-4032-8933-1a15b522ef60")
	tok, err := mgr.IssueRefresh(t.Context(), userId)
	if err != nil {
		t.Fatalf("IssueRefresh: %v", err)
	}

	claims, err := mgr.ParseRefresh(t.Context(), tok)
	if err != nil {
		t.Fatalf("ParseRefresh: %v", err)
	}
	if claims.Subject != userId.String() {
		t.Fatalf("got uid %q, want %q", claims.Subject, userId.String())
	}
	if claims.TokenType != tokenTypeRefresh {
		t.Fatalf("got token_type %q, want %q", claims.TokenType, tokenTypeRefresh)
	}
}

func TestInvalidIssuer(t *testing.T) {
	// Issue with issuer A
	issuerA := newTestMgr(t, func(c *Config) { c.Issuer = "issuerA" })
	var userId = uuid.MustParse("c2080dd1-c872-43a9-8848-e9d49dcd85d6")
	tok, err := issuerA.IssueAccess(t.Context(), userId, nil)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	// Parse with issuer B (same secret & aud) -> should fail issuer check
	issuerB := newTestMgr(t, func(c *Config) {
		c.Issuer = "issuerB"
		key := testRSAKey(t)
		c.PrivateKey = key
		c.PublicKeys = map[string]*rsa.PublicKey{"test-kid": &key.PublicKey}
	})
	_, err = issuerB.ParseAccess(t.Context(), tok)
	if err == nil || !strings.Contains(err.Error(), "invalid issuer") {
		t.Fatalf("expected invalid issuer error, got %v", err)
	}
}

func TestInvalidAudience(t *testing.T) {
	// Issue with audience A
	audA := newTestMgr(t, func(c *Config) { c.Audience = "audA" })
	userId := uuid.MustParse("02fd253f-5a74-475c-8b72-54336cec2392")
	tok, err := audA.IssueAccess(t.Context(), userId, nil)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	// Parse with audience B (same secret & issuer) -> should fail audience check
	audB := newTestMgr(t, func(c *Config) {
		c.Audience = "audB"
		key := testRSAKey(t)
		c.PrivateKey = key
		c.PublicKeys = map[string]*rsa.PublicKey{"test-kid": &key.PublicKey}
	})
	_, err = audB.ParseAccess(t.Context(), tok)
	if err == nil || !strings.Contains(err.Error(), "invalid audience") {
		t.Fatalf("expected invalid audience error, got %v", err)
	}
}

func TestInvalidTokenType(t *testing.T) {
	mgr := newTestMgr(t)
	userId := uuid.MustParse("a7f9271c-a0bf-48d9-a6e3-706df362fddd")
	access, err := mgr.IssueAccess(t.Context(), userId, nil)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	// Parsing ACCESS with ParseRefresh should fail
	_, err = mgr.ParseRefresh(t.Context(), access)
	if err == nil || !strings.Contains(err.Error(), "invalid token type") {
		t.Fatalf("expected invalid token type, got %v", err)
	}
}

func TestRefreshFrom_NoRotate(t *testing.T) {
	mgr := newTestMgr(t)

	userId := uuid.MustParse("ea014952-e613-4b38-9a17-1d766eb095c9")
	refTok, err := mgr.IssueRefresh(t.Context(), userId)
	if err != nil {
		t.Fatalf("IssueRefresh: %v", err)
	}
	newAccess, newRefresh, err := mgr.RefreshFrom(t.Context(), refTok, map[string]string{"k": "v"}, false)
	if err != nil {
		t.Fatalf("RefreshFrom: %v", err)
	}
	if newAccess == "" {
		t.Fatalf("expected new access token")
	}
	if newRefresh != "" {
		t.Fatalf("did not expect rotated refresh token")
	}
	claims, err := mgr.ParseAccess(t.Context(), newAccess)
	if err != nil {
		t.Fatalf("ParseAccess: %v", err)
	}
	if claims.Subject != userId.String() {
		t.Fatalf("got uid %q, want %q", claims.Subject, userId.String())
	}
	if claims.Attrs["k"] != "v" {
		t.Fatalf("attrs not embedded in new access token")
	}
}

func TestRefreshFrom_Rotate(t *testing.T) {
	mgr := newTestMgr(t)

	userId := uuid.MustParse("9c21b47e-85c1-480b-a588-b42b6f89cd7a")
	origRefresh, err := mgr.IssueRefresh(t.Context(), userId)
	if err != nil {
		t.Fatalf("IssueRefresh: %v", err)
	}
	newAccess, newRefresh, err := mgr.RefreshFrom(t.Context(), origRefresh, nil, true)
	if err != nil {
		t.Fatalf("RefreshFrom: %v", err)
	}
	if newAccess == "" || newRefresh == "" {
		t.Fatalf("expected both new access and rotated refresh tokens")
	}
	if newRefresh == origRefresh {
		t.Fatalf("expected refresh rotation (different token)")
	}
	// Validate both tokens parse
	if _, err := mgr.ParseAccess(t.Context(), newAccess); err != nil {
		t.Fatalf("ParseAccess(new): %v", err)
	}
	if _, err := mgr.ParseRefresh(t.Context(), newRefresh); err != nil {
		t.Fatalf("ParseRefresh(new): %v", err)
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	mgr := newTestMgr(t) // normal positive lifetimes

	// Build an already-expired ACCESS token
	now := time.Now().Add(-2 * time.Minute) // pretend token was issued 2m ago
	claims := Claims{
		Attrs:     nil,
		TokenType: tokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   uuid.MustParse("f7ca09e0-ab01-4ec3-89da-e038e4712535").String(),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(-1 * time.Minute)), // expired 1m ago
			Issuer:    "issuer.test",
			Audience:  jwt.ClaimStrings{"aud.test"},
		},
	}

	key := testRSAKey(t)
	tk := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tk.Header["kid"] = "test-kid"
	signed, err := tk.SignedString(key)
	if err != nil {
		t.Fatalf("sign expired token: %v", err)
	}

	_, err = mgr.ParseAccess(t.Context(), signed)
	if err == nil {
		t.Fatalf("expected parse error for expired token")
	}
	if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Fatalf("expected jwt.ErrTokenExpired, got %v", err)
	}
}

func TestUpdateKeysHotSwap(t *testing.T) {
	mgr := newTestManager(t)
	key1 := testRSAKey(t)

	userID := uuid.MustParse("b3b9a251-4825-444a-8d4e-5461c1d78b02")
	oldTok, err := mgr.IssueAccess(t.Context(), userID, nil)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}

	kid, err := tokenKid(oldTok)
	if err != nil {
		t.Fatalf("token kid: %v", err)
	}
	if kid != "test-kid" {
		t.Fatalf("got kid %q, want %q", kid, "test-kid")
	}

	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	newKeys := map[string]*rsa.PublicKey{
		"test-kid": &key1.PublicKey,
		"kid-2":    &key2.PublicKey,
	}

	changed, err := mgr.UpdateKeys("kid-2", key2, newKeys)
	if err != nil {
		t.Fatalf("UpdateKeys: %v", err)
	}
	if !changed {
		t.Fatalf("expected UpdateKeys to report changed")
	}

	newTok, err := mgr.IssueAccess(t.Context(), userID, nil)
	if err != nil {
		t.Fatalf("IssueAccess (new key): %v", err)
	}
	newKid, err := tokenKid(newTok)
	if err != nil {
		t.Fatalf("token kid (new): %v", err)
	}
	if newKid != "kid-2" {
		t.Fatalf("got kid %q, want %q", newKid, "kid-2")
	}

	if _, err := mgr.ParseAccess(t.Context(), oldTok); err != nil {
		t.Fatalf("ParseAccess(old): %v", err)
	}
	if _, err := mgr.ParseAccess(t.Context(), newTok); err != nil {
		t.Fatalf("ParseAccess(new): %v", err)
	}

	changed, err = mgr.UpdateKeys("kid-2", key2, newKeys)
	if err != nil {
		t.Fatalf("UpdateKeys (same): %v", err)
	}
	if changed {
		t.Fatalf("expected UpdateKeys to report unchanged")
	}
}

func tokenKid(tokenStr string) (string, error) {
	parser := jwt.NewParser()
	claims := &Claims{}
	tok, _, err := parser.ParseUnverified(tokenStr, claims)
	if err != nil {
		return "", err
	}
	kid, _ := tok.Header["kid"].(string)
	return kid, nil
}
