package session

import (
	"context"
	"crypto/rsa"
	"errors"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	tokenTypeAccess  = "access"
	tokenTypeRefresh = "refresh"
)

type Claims struct {
	Attrs     map[string]string `json:"attrs,omitempty"`
	TokenType string            `json:"token_type"`
	jwt.RegisteredClaims
}

type Manager struct {
	keyID           string
	privateKey      *rsa.PrivateKey
	publicKeys      map[string]*rsa.PublicKey
	issuer          string
	audience        string
	accessTTL       time.Duration
	refreshTTL      time.Duration
	clockSkewLeeway time.Duration
}

func NewManager(cfg *Config) (SessionManager, error) {
	if cfg == nil {
		return nil, errors.New("missing config")
	}
	return &Manager{
		keyID:           cfg.KeyID,
		privateKey:      cfg.PrivateKey,
		publicKeys:      cfg.PublicKeys,
		issuer:          cfg.Issuer,
		audience:        cfg.Audience,
		accessTTL:       cfg.AccessLifetime,
		refreshTTL:      cfg.RefreshLifetime,
		clockSkewLeeway: cfg.ClockSkewLeeway,
	}, nil
}

func (m *Manager) IssueAccess(_ context.Context, userID uuid.UUID, attrs map[string]string) (string, error) {
	return m.issue(userID, attrs, tokenTypeAccess, m.accessTTL)
}

func (m *Manager) IssueRefresh(_ context.Context, userID uuid.UUID) (string, error) {
	return m.issue(userID, nil, tokenTypeRefresh, m.refreshTTL)
}

func (m *Manager) IssuePair(ctx context.Context, userID uuid.UUID, attrs map[string]string) (access string, refresh string, err error) {
	access, err = m.IssueAccess(ctx, userID, attrs)
	if err != nil {
		return "", "", err
	}

	refresh, err = m.IssueRefresh(ctx, userID)
	if err != nil {
		return "", "", err
	}

	return access, refresh, nil
}

func (m *Manager) issue(userID uuid.UUID, attrs map[string]string, typ string, ttl time.Duration) (string, error) {
	if userID.String() == "" {
		return "", errors.New("empty userID")
	}

	now := time.Now()

	rc := jwt.RegisteredClaims{
		Subject:   userID.String(),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(-m.clockSkewLeeway)),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		Issuer:    m.issuer,
		Audience:  jwt.ClaimStrings{m.audience},
		ID:        uuid.NewString(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, Claims{
		Attrs:            attrs,
		TokenType:        typ,
		RegisteredClaims: rc,
	})
	token.Header["kid"] = m.keyID

	return token.SignedString(m.privateKey)
}

func (m *Manager) ParseAccess(_ context.Context, tokenString string) (*Claims, error) {
	return m.parseTyped(tokenString, tokenTypeAccess)
}

func (m *Manager) ParseRefresh(_ context.Context, tokenString string) (*Claims, error) {
	return m.parseTyped(tokenString, tokenTypeRefresh)
}

func (m *Manager) RefreshFrom(ctx context.Context, old string, attrs map[string]string, rotate bool) (newAccess, newRefresh string, err error) {
	refreshClaims, err := m.ParseRefresh(ctx, old)
	if err != nil {
		return "", "", err
	}

	newAccess, err = m.IssueAccess(ctx, uuid.MustParse(refreshClaims.Subject), attrs)
	if err != nil {
		return "", "", err
	}

	if rotate {
		newRefresh, err = m.IssueRefresh(ctx, uuid.MustParse(refreshClaims.Subject))
		if err != nil {
			return "", "", err
		}
	}

	return newAccess, newRefresh, nil
}

func (m *Manager) parseTyped(tokStr, wantType string) (*Claims, error) {
	if tokStr == "" {
		return nil, errors.New("empty token")
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithLeeway(m.clockSkewLeeway),
	)

	claims := &Claims{}
	_, err := parser.ParseWithClaims(tokStr, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			if len(m.publicKeys) == 1 {
				for _, key := range m.publicKeys {
					return key, nil
				}
			}
			return nil, errors.New("missing kid")
		}

		key, ok := m.publicKeys[kid]
		if !ok {
			return nil, errors.New("unknown kid")
		}
		return key, nil
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

	if claims.Subject == "" {
		return nil, errors.New("missing uid")
	}

	return claims, nil
}
