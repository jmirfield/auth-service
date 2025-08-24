package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jmirfield/auth-service/internals/domain/user"
	"github.com/jmirfield/auth-service/internals/repository"
)

type pgxQuerier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type UserRepo struct {
	pool *pgxpool.Pool
	q    pgxQuerier
}

func NewUserRepo(pool *pgxpool.Pool) (repository.UserReadWriter, error) {
	if pool == nil {
		return nil, errors.New("pgxpool.Pool is nil")
	}

	return &UserRepo{pool: pool, q: pool}, nil
}

func (r *UserRepo) UpsertUser(ctx context.Context, u *user.User) error {
	var b []byte
	if u.Attr != nil {
		var err error
		b, err = json.Marshal(u.Attr)
		if err != nil {
			return err
		}
	}
	const q = `
INSERT INTO users (id, attributes)
VALUES ($1, COALESCE($2, '{}'::jsonb))
ON CONFLICT (id)
DO UPDATE SET attributes = EXCLUDED.attributes`
	_, err := r.q.Exec(ctx, q, u.ID, b)
	return err
}

func (r *UserRepo) GetUser(ctx context.Context, id uuid.UUID) (*user.User, error) {
	const q = `SELECT id, attributes FROM users WHERE id = $1`
	var out user.User
	var raw []byte
	err := r.q.QueryRow(ctx, q, id).Scan(&out.ID, &raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, err
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out.Attr); err != nil {
			return nil, err
		}
	}
	return &out, nil
}

func (r *UserRepo) UpsertIdentity(ctx context.Context, ident *user.Identity) error {
	const q = `
INSERT INTO user_identities (provider, sub, user_id)
VALUES ($1, $2, $3)
ON CONFLICT (provider, sub)
DO UPDATE SET user_id = EXCLUDED.user_id`
	_, err := r.q.Exec(ctx, q, ident.Provider, ident.Sub, ident.Uid)
	return err
}

func (r *UserRepo) GetIdentity(ctx context.Context, provider, sub string) (*user.Identity, error) {
	const q = `SELECT provider, sub, user_id FROM user_identities WHERE provider = $1 AND sub = $2`
	var ident user.Identity
	err := r.q.QueryRow(ctx, q, provider, sub).Scan(&ident.Provider, &ident.Sub, &ident.Uid)
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
	err := r.q.QueryRow(ctx, q, provider, sub).Scan(&id)
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
	_, err := r.q.Exec(ctx, q, provider, sub)
	return err
}

func (r *UserRepo) InsertRefreshToken(ctx context.Context, t *user.RefreshToken) error {
	const q = `
INSERT INTO user_refresh_tokens (user_id, jti, hash, expires_at)
VALUES ($1, $2, $3, $4)`
	_, err := r.q.Exec(ctx, q, t.Uid, t.Jti, t.Hash, t.ExpiresAt.UTC())
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return repository.ErrDuplicate
		}
		return err
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
	err := r.q.QueryRow(ctx, q, userID, hash).Scan(
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
	cmd, err := r.q.Exec(ctx, q, userID, jti)
	if err != nil {
		return 0, err
	}
	return cmd.RowsAffected(), nil
}

func (r *UserRepo) DeleteAllRefreshTokens(ctx context.Context, userID uuid.UUID) (int64, error) {
	const q = `DELETE FROM user_refresh_tokens WHERE user_id = $1`
	cmd, err := r.q.Exec(ctx, q, userID)
	if err != nil {
		return 0, err
	}
	return cmd.RowsAffected(), nil
}

func (r *UserRepo) PruneExpiredRefreshTokens(ctx context.Context, now time.Time) (int64, error) {
	const q = `DELETE FROM user_refresh_tokens WHERE expires_at <= $1`
	cmd, err := r.q.Exec(ctx, q, now.UTC())
	if err != nil {
		return 0, err
	}
	return cmd.RowsAffected(), nil
}

func (r *UserRepo) WithTx(ctx context.Context, fn func(ctx context.Context, rw repository.UserTx) error) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:       pgx.ReadCommitted,
		AccessMode:     pgx.ReadWrite,
		DeferrableMode: pgx.NotDeferrable,
	})
	if err != nil {
		return err
	}

	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout = '3s'`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '1s'`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SET LOCAL idle_in_transaction_session_timeout = '5s'`); err != nil {
		return err
	}

	if err := fn(ctx, &UserRepo{pool: r.pool, q: tx}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *UserRepo) AdvisoryLockIdentity(ctx context.Context, provider, sub string) error {
	if _, ok := r.q.(pgx.Tx); !ok {
		return fmt.Errorf("AdvisoryLockIdentity must be called within a transaction")
	}
	_, err := r.q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`, provider, sub)
	return err
}
