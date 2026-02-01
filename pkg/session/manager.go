package session

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"slices"
	"strconv"
	"sync"
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
	mu              sync.RWMutex
	keyID           string
	privateKey      *rsa.PrivateKey
	publicKeys      map[string]*rsa.PublicKey
	keyFingerprint  string
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
	mgr := &Manager{
		issuer:          cfg.Issuer,
		audience:        cfg.Audience,
		accessTTL:       cfg.AccessLifetime,
		refreshTTL:      cfg.RefreshLifetime,
		clockSkewLeeway: cfg.ClockSkewLeeway,
	}
	if _, err := mgr.UpdateKeys(cfg.KeyID, cfg.PrivateKey, cfg.PublicKeys); err != nil {
		return nil, err
	}
	return mgr, nil
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

func (m *Manager) UpdateKeys(keyID string, privateKey *rsa.PrivateKey, publicKeys map[string]*rsa.PublicKey) (bool, error) {
	if err := validateKeys(keyID, privateKey, publicKeys); err != nil {
		return false, err
	}

	normalized := clonePublicKeys(publicKeys)
	if _, ok := normalized[keyID]; !ok && privateKey != nil {
		normalized[keyID] = &privateKey.PublicKey
	}

	fingerprint := keyFingerprint(keyID, normalized)

	m.mu.Lock()
	defer m.mu.Unlock()
	if fingerprint == m.keyFingerprint {
		return false, nil
	}

	m.keyID = keyID
	m.privateKey = privateKey
	m.publicKeys = normalized
	m.keyFingerprint = fingerprint
	return true, nil
}

func (m *Manager) issue(userID uuid.UUID, attrs map[string]string, typ string, ttl time.Duration) (string, error) {
	if userID.String() == "" {
		return "", errors.New("empty userID")
	}

	m.mu.RLock()
	keyID := m.keyID
	privateKey := m.privateKey
	m.mu.RUnlock()

	if privateKey == nil {
		return "", errors.New("missing private key")
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
	token.Header["kid"] = keyID

	return token.SignedString(privateKey)
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

	m.mu.RLock()
	publicKeys := m.publicKeys
	m.mu.RUnlock()

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithLeeway(m.clockSkewLeeway),
	)

	claims := &Claims{}
	_, err := parser.ParseWithClaims(tokStr, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			if len(publicKeys) == 1 {
				for _, key := range publicKeys {
					return key, nil
				}
			}
			return nil, errors.New("missing kid")
		}

		key, ok := publicKeys[kid]
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

func clonePublicKeys(src map[string]*rsa.PublicKey) map[string]*rsa.PublicKey {
	dst := make(map[string]*rsa.PublicKey, len(src))
	for kid, key := range src {
		dst[kid] = key
	}
	return dst
}

func keyFingerprint(keyID string, publicKeys map[string]*rsa.PublicKey) string {
	h := sha256.New()
	h.Write([]byte(keyID))

	keys := make([]string, 0, len(publicKeys))
	for kid := range publicKeys {
		keys = append(keys, kid)
	}
	sort.Strings(keys)
	for _, kid := range keys {
		pub := publicKeys[kid]
		h.Write([]byte(kid))
		if pub != nil {
			h.Write(pub.N.Bytes())
			h.Write([]byte(strconv.Itoa(pub.E)))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}
