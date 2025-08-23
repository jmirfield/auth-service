package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jmirfield/auth-service/internals/domain/user"
)

var ErrNotFound = errors.New("not found")

type UserReader interface {
	// GetUser returns a user by ID or ErrNotFound.
	GetUser(ctx context.Context, id uuid.UUID) (*user.User, error)
	// GetUserIDByIdentity maps (provider, sub) -> user_id or ErrNotFound.
	GetUserIDByIdentity(ctx context.Context, provider, sub string) (uuid.UUID, error)
	GetIdentityBySub(ctx context.Context, sub string) (*user.Identity, error)
	// FindRefreshTokenByHash returns a refresh token for a user by its hash or ErrNotFound.
	FindRefreshTokenByHash(ctx context.Context, userID uuid.UUID, hash string) (user.RefreshToken, error)
}

type UserWriter interface {
	// UpsertUser creates or updates a user row (attributes, etc).
	UpsertUser(ctx context.Context, u *user.User) error

	// UpsertIdentity ensures (provider, sub) -> user_id mapping exists (or is reassigned).
	// Enforces your UNIQUE (provider, sub) invariant.
	UpsertIdentity(ctx context.Context, ident *user.Identity) error

	// DeleteIdentity removes a single (provider, sub) mapping.
	DeleteIdentity(ctx context.Context, provider, sub string) error

	// InsertRefreshToken persists a new refresh token record (hashed).
	InsertRefreshToken(ctx context.Context, t *user.RefreshToken) error

	// DeleteRefreshToken deletes a single refresh token by JTI; returns rows affected.
	DeleteRefreshToken(ctx context.Context, userID uuid.UUID, jti uuid.UUID) (int64, error)

	// DeleteAllRefreshTokens deletes all refresh tokens for a user; returns rows affected.
	DeleteAllRefreshTokens(ctx context.Context, userID uuid.UUID) (int64, error)

	// PruneExpiredRefreshTokens deletes all expired tokens across users; returns rows affected.
	PruneExpiredRefreshTokens(ctx context.Context, now time.Time) (int64, error)
}

type UserReadWriter interface {
	UserReader
	UserWriter
}
