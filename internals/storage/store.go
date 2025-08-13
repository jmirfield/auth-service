package storage

import (
	"context"
	"errors"
)

const (
	ProviderApple  = "apple"
	ProviderGoogle = "google"
	// add more as needed
)

var ErrNotFound = errors.New("record not found")

type Tokens struct {
	RefreshToken string `json:"refresh_token,omitempty"`
}

type Record struct {
	UserID           string            `json:"user_id"`
	TokensByProvider map[string]Tokens `json:"tokens_by_provider,omitempty"`
	RefreshToken     string            `json:"refresh_token,omitempty"`
	Attrs            map[string]string `json:"attributes,omitempty"`
}

type Store interface {
	// Get returns the user's record or ErrNotFound.
	Get(ctx context.Context, userID string) (Record, error)

	// Put stores r as the user's record. If the record exists it is replaced; if not, it is created.
	Put(ctx context.Context, userID string, r Record) error

	// Update atomically reads, transforms, and writes the record.
	Update(ctx context.Context, userID string, fn func(Record) Record) (Record, error)

	Delete(ctx context.Context, userID string) error
	Exists(ctx context.Context, refreshToken string) (bool, error)
}
