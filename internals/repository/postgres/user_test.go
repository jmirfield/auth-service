package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"

	domain "github.com/jmirfield/auth-service/internals/domain/user"
	"github.com/jmirfield/auth-service/internals/repository"
	"github.com/jmirfield/auth-service/migrations"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func startEmbeddedPostgres(t *testing.T) (stop func(), connString string) {
	t.Helper()

	dataDir := t.TempDir()
	port := uint32(55433)

	cfg := embeddedpostgres.DefaultConfig().
		RuntimePath(filepath.Join(dataDir, "run")).
		DataPath(filepath.Join(dataDir, "data")).
		BinariesPath(filepath.Join(dataDir, "bin")).
		Database("testdb").
		Username("testuser").
		Password("testpass").
		Port(port).
		Locale("en_US.UTF-8").
		StartTimeout(30 * time.Second).
		Logger(os.Stdout)

	ep := embeddedpostgres.NewDatabase(cfg)

	if err := ep.Start(); err != nil {
		t.Fatalf("start embedded postgres: %v", err)
	}

	stop = func() { _ = ep.Stop() }

	connString = fmt.Sprintf("postgres://%s:%s@localhost:%d/%s?sslmode=disable",
		"testuser", "testpass", port, "testdb")
	return stop, connString
}

func mustPool(t *testing.T, connString string) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return pool
}

func runMigrations(t *testing.T, dsn string) {
	t.Helper()
	goose.SetBaseFS(migrations.Files)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	if err := goose.Up(db, "."); err != nil {
		t.Fatalf("goose up: %v", err)
	}
}

// --- tests ---

func TestUserRepo_UpsertAndGetUser(t *testing.T) {
	stop, dsn := startEmbeddedPostgres(t)
	defer stop()

	pool := mustPool(t, dsn)
	runMigrations(t, dsn)

	r := NewUserRepo(pool)

	id := uuid.New()
	u := &domain.User{ID: id, Attr: map[string]any{"role": "admin", "tier": float64(2)}}

	ctx := context.Background()

	// Insert
	if err := r.UpsertUser(ctx, u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}

	// Read back
	got, err := r.GetUser(ctx, id)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.ID != id {
		t.Fatalf("GetUser.ID = %s, want %s", got.ID, id)
	}
	if got.Attr["role"] != "admin" {
		t.Fatalf("GetUser.Attr[role] = %v, want admin", got.Attr["role"])
	}

	// Update attributes
	u2 := &domain.User{ID: id, Attr: map[string]any{"role": "member"}}
	if err := r.UpsertUser(ctx, u2); err != nil {
		t.Fatalf("UpsertUser (update): %v", err)
	}
	got2, _ := r.GetUser(ctx, id)
	if got2.Attr["role"] != "member" {
		t.Fatalf("updated role = %v, want member", got2.Attr["role"])
	}
}

func TestUserRepo_Identities_CRUD(t *testing.T) {
	stop, dsn := startEmbeddedPostgres(t)
	defer stop()

	pool := mustPool(t, dsn)
	runMigrations(t, dsn)

	r := NewUserRepo(pool)
	ctx := context.Background()

	uid := uuid.New()
	// user must exist for FK
	if err := r.UpsertUser(ctx, &domain.User{ID: uid, Attr: map[string]any{"x": "y"}}); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}

	// upsert identity
	ident := &domain.Identity{Provider: "apple", Sub: "sub-123", Uid: uid}
	if err := r.UpsertIdentity(ctx, ident); err != nil {
		t.Fatalf("UpsertIdentity: %v", err)
	}

	// get by sub
	gotIdent, err := r.GetIdentityBySub(ctx, "sub-123")
	if err != nil {
		t.Fatalf("GetIdentityBySub: %v", err)
	}
	if gotIdent.Provider != "apple" || gotIdent.Uid != uid {
		t.Fatalf("GetIdentityBySub = %+v, want provider=apple uid=%s", gotIdent, uid)
	}

	// get user id by provider+sub
	gotUID, err := r.GetUserIDByIdentity(ctx, "apple", "sub-123")
	if err != nil {
		t.Fatalf("GetUserIDByIdentity: %v", err)
	}
	if gotUID != uid {
		t.Fatalf("GetUserIDByIdentity uid=%s, want %s", gotUID, uid)
	}

	// delete
	if err := r.DeleteIdentity(ctx, "apple", "sub-123"); err != nil {
		t.Fatalf("DeleteIdentity: %v", err)
	}
	if _, err := r.GetIdentityBySub(ctx, "sub-123"); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("GetIdentityBySub after delete err=%v, want ErrNotFound", err)
	}
}

func TestUserRepo_RefreshTokens_CRUDAndPrune(t *testing.T) {
	stop, dsn := startEmbeddedPostgres(t)
	defer stop()

	pool := mustPool(t, dsn)
	runMigrations(t, dsn)

	r := NewUserRepo(pool)
	ctx := context.Background()

	uid := uuid.New()
	if err := r.UpsertUser(ctx, &domain.User{ID: uid, Attr: nil}); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}

	jti := uuid.New()

	// insert one
	tok := &domain.RefreshToken{
		Uid:       uid,
		Jti:       jti,
		Hash:      "hash-1",
		ExpiresAt: time.Now().Add(1 * time.Hour).UTC(),
	}
	if err := r.InsertRefreshToken(ctx, tok); err != nil {
		t.Fatalf("InsertRefreshToken: %v", err)
	}

	// find by hash
	found, err := r.FindRefreshTokenByHash(ctx, uid, "hash-1")
	if err != nil {
		t.Fatalf("FindRefreshTokenByHash: %v", err)
	}
	if found.Jti != jti {
		t.Fatalf("found.Jti=%s, want %s", found.Jti, jti)
	}

	// duplicate insert (ON CONFLICT DO NOTHING) -> no error
	if err := r.InsertRefreshToken(ctx, tok); err != nil {
		t.Fatalf("dup InsertRefreshToken: %v", err)
	}

	// prune: add an expired token and prune
	expTok := &domain.RefreshToken{
		Uid:       uid,
		Jti:       uuid.New(),
		Hash:      "hash-exp",
		ExpiresAt: time.Now().Add(-1 * time.Hour).UTC(),
	}
	if err := r.InsertRefreshToken(ctx, expTok); err != nil {
		t.Fatalf("InsertRefreshToken expired: %v", err)
	}

	pruned, err := r.PruneExpiredRefreshTokens(ctx, time.Now())
	if err != nil {
		t.Fatalf("PruneExpiredRefreshTokens: %v", err)
	}
	if pruned < 1 {
		t.Fatalf("pruned=%d, want at least 1", pruned)
	}

	// delete single
	affected, err := r.DeleteRefreshToken(ctx, uid, jti)
	if err != nil {
		t.Fatalf("DeleteRefreshToken: %v", err)
	}
	if affected != 1 {
		t.Fatalf("DeleteRefreshToken affected=%d, want 1", affected)
	}

	// delete all
	affectedAll, err := r.DeleteAllRefreshTokens(ctx, uid)
	if err != nil {
		t.Fatalf("DeleteAllRefreshTokens: %v", err)
	}
	if affectedAll < 0 {
		t.Fatalf("DeleteAll affected=%d, want >=0", affectedAll)
	}

	// not found path
	if _, err := r.FindRefreshTokenByHash(ctx, uid, "nope"); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindRefreshTokenByHash want ErrNotFound, got %v", err)
	}
}
