package session

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// helper to build a test manager with sane defaults
func newTestMgr(t *testing.T, opts ...func(*Config)) *Manager {
	t.Helper()
	cfg := &Config{
		Secret:          "test-secret-32-bytes-minimum-please",
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

func TestIssueAndParseAccess(t *testing.T) {
	mgr := newTestMgr(t)

	attrs := map[string]string{"email": "user@example.com"}
	tok, err := mgr.IssueAccess("user-123", attrs)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}

	claims, err := mgr.ParseAccess(tok)
	if err != nil {
		t.Fatalf("ParseAccess: %v", err)
	}

	if claims.UserID != "user-123" {
		t.Fatalf("got uid %q, want %q", claims.UserID, "user-123")
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

	tok, err := mgr.IssueRefresh("user-123")
	if err != nil {
		t.Fatalf("IssueRefresh: %v", err)
	}

	claims, err := mgr.ParseRefresh(tok)
	if err != nil {
		t.Fatalf("ParseRefresh: %v", err)
	}
	if claims.UserID != "user-123" {
		t.Fatalf("got uid %q, want %q", claims.UserID, "user-123")
	}
	if claims.TokenType != tokenTypeRefresh {
		t.Fatalf("got token_type %q, want %q", claims.TokenType, tokenTypeRefresh)
	}
}

func TestInvalidIssuer(t *testing.T) {
	// Issue with issuer A
	issuerA := newTestMgr(t, func(c *Config) { c.Issuer = "issuerA" })
	tok, err := issuerA.IssueAccess("uid1", nil)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	// Parse with issuer B (same secret & aud) -> should fail issuer check
	issuerB := newTestMgr(t, func(c *Config) {
		c.Issuer = "issuerB"
		c.Secret = string(issuerA.secret) // keep same secret to pass signature
	})
	_, err = issuerB.ParseAccess(tok)
	if err == nil || !strings.Contains(err.Error(), "invalid issuer") {
		t.Fatalf("expected invalid issuer error, got %v", err)
	}
}

func TestInvalidAudience(t *testing.T) {
	// Issue with audience A
	audA := newTestMgr(t, func(c *Config) { c.Audience = "audA" })
	tok, err := audA.IssueAccess("uid1", nil)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	// Parse with audience B (same secret & issuer) -> should fail audience check
	audB := newTestMgr(t, func(c *Config) {
		c.Audience = "audB"
		c.Secret = string(audA.secret)
		c.Issuer = audA.issuer
	})
	_, err = audB.ParseAccess(tok)
	if err == nil || !strings.Contains(err.Error(), "invalid audience") {
		t.Fatalf("expected invalid audience error, got %v", err)
	}
}

func TestInvalidTokenType(t *testing.T) {
	mgr := newTestMgr(t)
	access, err := mgr.IssueAccess("uid1", nil)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	// Parsing ACCESS with ParseRefresh should fail
	_, err = mgr.ParseRefresh(access)
	if err == nil || !strings.Contains(err.Error(), "invalid token type") {
		t.Fatalf("expected invalid token type, got %v", err)
	}
}

func TestEmptyTokenAndEmptyUserID(t *testing.T) {
	mgr := newTestMgr(t)

	if _, err := mgr.ParseAccess(""); err == nil || !strings.Contains(err.Error(), "empty token") {
		t.Fatalf("expected empty token error, got %v", err)
	}
	if _, err := mgr.IssueAccess("", nil); err == nil || !strings.Contains(err.Error(), "empty userID") {
		t.Fatalf("expected empty userID error, got %v", err)
	}
}

func TestRefreshFrom_NoRotate(t *testing.T) {
	mgr := newTestMgr(t)

	refTok, err := mgr.IssueRefresh("uid-xyz")
	if err != nil {
		t.Fatalf("IssueRefresh: %v", err)
	}
	newAccess, newRefresh, err := mgr.RefreshFrom(refTok, map[string]string{"k": "v"}, false)
	if err != nil {
		t.Fatalf("RefreshFrom: %v", err)
	}
	if newAccess == "" {
		t.Fatalf("expected new access token")
	}
	if newRefresh != "" {
		t.Fatalf("did not expect rotated refresh token")
	}
	claims, err := mgr.ParseAccess(newAccess)
	if err != nil {
		t.Fatalf("ParseAccess: %v", err)
	}
	if claims.UserID != "uid-xyz" {
		t.Fatalf("got uid %q, want %q", claims.UserID, "uid-xyz")
	}
	if claims.Attrs["k"] != "v" {
		t.Fatalf("attrs not embedded in new access token")
	}
}

func TestRefreshFrom_Rotate(t *testing.T) {
	mgr := newTestMgr(t)

	origRefresh, err := mgr.IssueRefresh("uid-xyz")
	if err != nil {
		t.Fatalf("IssueRefresh: %v", err)
	}
	newAccess, newRefresh, err := mgr.RefreshFrom(origRefresh, nil, true)
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
	if _, err := mgr.ParseAccess(newAccess); err != nil {
		t.Fatalf("ParseAccess(new): %v", err)
	}
	if _, err := mgr.ParseRefresh(newRefresh); err != nil {
		t.Fatalf("ParseRefresh(new): %v", err)
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	mgr := newTestMgr(t) // normal positive lifetimes

	// Build an already-expired ACCESS token
	now := time.Now().Add(-2 * time.Minute) // pretend token was issued 2m ago
	claims := Claims{
		UserID:    "uid-expired",
		Attrs:     nil,
		TokenType: tokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "uid-expired",
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(-1 * time.Minute)), // expired 1m ago
			Issuer:    mgr.issuer,
			Audience:  jwt.ClaimStrings{mgr.audience},
		},
	}

	tk := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tk.SignedString(mgr.secret)
	if err != nil {
		t.Fatalf("sign expired token: %v", err)
	}

	_, err = mgr.ParseAccess(signed)
	if err == nil {
		t.Fatalf("expected parse error for expired token")
	}
	if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Fatalf("expected jwt.ErrTokenExpired, got %v", err)
	}
}
