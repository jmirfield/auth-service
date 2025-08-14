package storage

import (
	"errors"
	"time"

	"github.com/jmirfield/auth-service/internals/secret"
)

const (
	ProviderApple  = "apple"
	ProviderGoogle = "google"
	// add more as needed
)

var ErrNotFound = errors.New("record not found")

type RefreshTokenRecord struct {
	Hash      string    `json:"hash"`
	JTI       string    `json:"jti"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type Record struct {
	UserID                  string               `json:"user_id"`
	RefreshTokensByProvider map[string]string    `json:"tokens_by_provider"`
	RefreshTokens           []RefreshTokenRecord `json:"refresh_token"`
	Attrs                   map[string]string    `json:"attributes"`
}

func (r *Record) EnsureInit() {
	if r.RefreshTokensByProvider == nil {
		r.RefreshTokensByProvider = make(map[string]string)
	}

	if r.Attrs == nil {
		r.Attrs = make(map[string]string)
	}
}

func (r *Record) GetRefreshToken(provider string) (string, bool) {
	r.EnsureInit()
	token, ok := r.RefreshTokensByProvider[provider]
	return token, ok
}

func (r *Record) FindRefreshToken(token string) (RefreshTokenRecord, bool) {
	for _, rt := range r.RefreshTokens {
		if rt.Hash == secret.Hash(token) {
			return rt, true
		}
	}

	return RefreshTokenRecord{}, false
}
