package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jmirfield/auth-service/internals/domain/user"
	"github.com/jmirfield/auth-service/internals/repository"
)

type UserRepo struct {
	pool *pgxpool.Pool
}

func NewUserRepo(pool *pgxpool.Pool) repository.UserReadWriter {
	return &UserRepo{pool: pool}
}

func (r *UserRepo) UpsertUser(ctx context.Context, u *user.User) error {
	const q = `
INSERT INTO users (id, attributes)
VALUES ($1, COALESCE($2, '{}'::jsonb))
ON CONFLICT (id)
DO UPDATE SET attributes = EXCLUDED.attributes`
	_, err := r.pool.Exec(ctx, q, u.ID, u.Attr)
	return err
}

func (r *UserRepo) GetUser(ctx context.Context, id uuid.UUID) (*user.User, error) {
	const q = `SELECT id, attributes FROM users WHERE id = $1`
	var out user.User
	var attrs map[string]any
	err := r.pool.QueryRow(ctx, q, id).Scan(&out.ID, &attrs)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &user.User{}, repository.ErrNotFound
		}
		return &user.User{}, err
	}
	out.Attr = attrs
	return &out, nil
}

func (r *UserRepo) UpsertIdentity(ctx context.Context, ident *user.Identity) error {
	const q = `
INSERT INTO user_identities (provider, sub, user_id)
VALUES ($1, $2, $3)
ON CONFLICT (provider, sub)
DO UPDATE SET user_id = EXCLUDED.user_id`
	_, err := r.pool.Exec(ctx, q, ident.Provider, ident.Sub, ident.Uid)
	return err
}

func (r *UserRepo) GetIdentityBySub(ctx context.Context, sub string) (*user.Identity, error) {
	const q = `SELECT provider, sub, user_id FROM user_identities WHERE sub = $1`
	var ident user.Identity
	err := r.pool.QueryRow(ctx, q, sub).Scan(&ident.Provider, &ident.Sub, &ident.Uid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, err
	}
	return &ident, nil
}

func (r *UserRepo) GetUserIDByIdentity(ctx context.Context, provider, sub string) (uuid.UUID, error) {
	const q = `SELECT user_id FROM user_identities WHERE provider = $1 AND sub = $2`
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, q, provider, sub).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, repository.ErrNotFound
		}
		return uuid.Nil, err
	}
	return id, nil
}

func (r *UserRepo) DeleteIdentity(ctx context.Context, provider, sub string) error {
	const q = `DELETE FROM user_identities WHERE provider = $1 AND sub = $2`
	_, err := r.pool.Exec(ctx, q, provider, sub)
	return err
}

func (r *UserRepo) InsertRefreshToken(ctx context.Context, t *user.RefreshToken) error {
	const q = `
INSERT INTO user_refresh_tokens (user_id, jti, hash, expires_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (user_id, jti) DO NOTHING`
	cmd, err := r.pool.Exec(ctx, q, t.Uid, t.Jti, t.Hash, t.ExpiresAt.UTC())
	if err != nil {
		return err
	}

	if cmd.RowsAffected() == 0 {
	}
	return nil
}

func (r *UserRepo) FindRefreshTokenByHash(ctx context.Context, userID uuid.UUID, hash string) (user.RefreshToken, error) {
	const q = `
SELECT user_id, jti, hash, expires_at
FROM user_refresh_tokens
WHERE user_id = $1 AND hash = $2
LIMIT 1`
	var t user.RefreshToken
	err := r.pool.QueryRow(ctx, q, userID, hash).Scan(
		&t.Uid, &t.Jti, &t.Hash, &t.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return user.RefreshToken{}, repository.ErrNotFound
		}
		return user.RefreshToken{}, err
	}
	return t, nil
}

func (r *UserRepo) DeleteRefreshToken(ctx context.Context, userID uuid.UUID, jti uuid.UUID) (int64, error) {
	const q = `DELETE FROM user_refresh_tokens WHERE user_id = $1 AND jti = $2`
	cmd, err := r.pool.Exec(ctx, q, userID, jti)
	if err != nil {
		return 0, err
	}
	return cmd.RowsAffected(), nil
}

func (r *UserRepo) DeleteAllRefreshTokens(ctx context.Context, userID uuid.UUID) (int64, error) {
	const q = `DELETE FROM user_refresh_tokens WHERE user_id = $1`
	cmd, err := r.pool.Exec(ctx, q, userID)
	if err != nil {
		return 0, err
	}
	return cmd.RowsAffected(), nil
}

func (r *UserRepo) PruneExpiredRefreshTokens(ctx context.Context, now time.Time) (int64, error) {
	const q = `DELETE FROM user_refresh_tokens WHERE expires_at <= $1`
	cmd, err := r.pool.Exec(ctx, q, now.UTC())
	if err != nil {
		return 0, err
	}
	return cmd.RowsAffected(), nil
}
