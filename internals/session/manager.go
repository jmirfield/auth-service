package session

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	tokenTypeAccess  = "access"
	tokenTypeRefresh = "refresh"
)

type Claims struct {
	UserID    string            `json:"uid"`
	Attrs     map[string]string `json:"attrs,omitempty"`
	TokenType string            `json:"token_type"`
	jwt.RegisteredClaims
}

type Manager struct {
	secret          []byte
	issuer          string
	audience        string
	accessTTL       time.Duration
	refreshTTL      time.Duration
	clockSkewLeeway time.Duration
}

func NewManager(cfg *Config) (*Manager, error) {
	return &Manager{
		secret:          []byte(cfg.Secret),
		issuer:          cfg.Issuer,
		audience:        cfg.Audience,
		accessTTL:       cfg.AccessLifetime,
		refreshTTL:      cfg.RefreshLifetime,
		clockSkewLeeway: cfg.ClockSkewLeeway,
	}, nil
}

func (m *Manager) IssueAccess(userID string, attrs map[string]string) (string, error) {
	return m.issue(userID, attrs, tokenTypeAccess, m.accessTTL)
}

func (m *Manager) IssueRefresh(userID string) (string, error) {
	return m.issue(userID, nil, tokenTypeRefresh, m.refreshTTL)
}

func (m *Manager) IssuePair(userID string, attrs map[string]string) (access string, refresh string, err error) {
	access, err = m.IssueAccess(userID, attrs)
	if err != nil {
		return "", "", err
	}

	refresh, err = m.IssueRefresh(userID)
	if err != nil {
		return "", "", err
	}

	return access, refresh, nil
}

func (m *Manager) issue(userID string, attrs map[string]string, typ string, ttl time.Duration) (string, error) {
	if userID == "" {
		return "", errors.New("empty userID")
	}

	now := time.Now()

	rc := jwt.RegisteredClaims{
		Subject:   userID,
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(-m.clockSkewLeeway)),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		Issuer:    m.issuer,
		Audience:  jwt.ClaimStrings{m.audience},
		ID:        newJTI(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		UserID:           userID,
		Attrs:            attrs,
		TokenType:        typ,
		RegisteredClaims: rc,
	})

	return token.SignedString(m.secret)
}

func newJTI() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// extremely unlikely; fall back to time-based
		return base64.RawURLEncoding.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
	}

	return base64.RawURLEncoding.EncodeToString(b[:])
}

func (m *Manager) ParseAccess(tokenString string) (*Claims, error) {
	return m.parseTyped(tokenString, tokenTypeAccess)
}

func (m *Manager) ParseRefresh(tokenString string) (*Claims, error) {
	return m.parseTyped(tokenString, tokenTypeRefresh)
}

func (m *Manager) RefreshFrom(refreshToken string, attrs map[string]string, rotate bool) (newAccess, newRefresh string, err error) {
	refreshClaims, err := m.ParseRefresh(refreshToken)
	if err != nil {
		return "", "", err
	}

	newAccess, err = m.IssueAccess(refreshClaims.UserID, attrs)
	if err != nil {
		return "", "", err
	}

	if rotate {
		newRefresh, err = m.IssueRefresh(refreshClaims.UserID)
		if err != nil {
			return "", "", err
		}
	}

	return newAccess, newRefresh, nil
}

func (m *Manager) parseTyped(tokenString, wantType string) (*Claims, error) {
	if tokenString == "" {
		return nil, errors.New("empty token")
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithLeeway(m.clockSkewLeeway),
	)

	claims := &Claims{}
	_, err := parser.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		return m.secret, nil
	})

	if err != nil {
		return nil, err
	}

	if m.issuer != "" && claims.Issuer != m.issuer {
		return nil, errors.New("invalid issuer")
	}

	if m.audience != "" && !slices.Contains(claims.Audience, m.audience) {
		return nil, errors.New("invalid audience")
	}

	if claims.TokenType != wantType {
		return nil, errors.New("invalid token type")
	}

	if claims.UserID == "" {
		return nil, errors.New("missing uid")
	}

	return claims, nil
}
