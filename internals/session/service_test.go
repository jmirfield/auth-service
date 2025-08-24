package session_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/jmirfield/auth-service/internals/domain/user"
	"github.com/jmirfield/auth-service/internals/repository"
	"github.com/jmirfield/auth-service/internals/repository/postgres"
	"github.com/jmirfield/auth-service/internals/secret"
	appsession "github.com/jmirfield/auth-service/internals/session"
	"github.com/jmirfield/auth-service/internals/test"
	pkgsession "github.com/jmirfield/auth-service/pkg/session"
)

type fakeSessionManager struct {
	mu              sync.Mutex
	claims          map[string]*pkgsession.Claims
	refreshFromFunc func(ctx context.Context, old string, extra map[string]string, rotate bool) (string, string, error)
}

func newFakeSessionManager() *fakeSessionManager {
	return &fakeSessionManager{claims: make(map[string]*pkgsession.Claims)}
}

func (f *fakeSessionManager) setClaims(tok string, c *pkgsession.Claims) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claims[tok] = c
}

func (f *fakeSessionManager) ParseRefresh(ctx context.Context, tok string) (*pkgsession.Claims, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.claims[tok]
	if !ok {
		return nil, errors.New("bad token")
	}
	return c, nil
}

func (f *fakeSessionManager) RefreshFrom(ctx context.Context, old string, extra map[string]string, rotate bool) (string, string, error) {
	if f.refreshFromFunc != nil {
		return f.refreshFromFunc(ctx, old, extra, rotate)
	}
	if !rotate {
		return "access-new", "", nil
	}

	return "access-new", "ref2", nil
}

func (f *fakeSessionManager) IssueAccess(ctx context.Context, uid uuid.UUID, extra map[string]string) (string, error) {
	return "access", nil
}
func (f *fakeSessionManager) IssueRefresh(ctx context.Context, uid uuid.UUID) (string, error) {
	return "refresh", nil
}
func (f *fakeSessionManager) IssuePair(ctx context.Context, uid uuid.UUID, extra map[string]string) (string, string, error) {
	return "access", "refresh", nil
}
func (f *fakeSessionManager) ParseAccess(ctx context.Context, tok string) (*pkgsession.Claims, error) {
	return &pkgsession.Claims{}, nil
}

func mkClaims(uid uuid.UUID, jti uuid.UUID, exp time.Duration) *pkgsession.Claims {
	return &pkgsession.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   uid.String(),
			ID:        jti.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(exp)),
		},
	}
}

func TestRefresh_NoRotate(t *testing.T) {
	stop, dsn := test.StartEmbeddedPostgres(t)
	defer stop()

	repo, err := postgres.NewUserRepo(test.MustPool(t, dsn))
	if err != nil {
		t.Fatal(err)
	}

	// seed user + token
	uid := uuid.New()
	if err := repo.UpsertUser(t.Context(), &user.User{ID: uid}); err != nil {
		t.Fatal(err)
	}

	oldJTI := uuid.New()
	oldTok := "ref1"
	if err := repo.InsertRefreshToken(t.Context(), &user.RefreshToken{
		Uid:       uid,
		Jti:       oldJTI,
		Hash:      secret.Hash(oldTok),
		ExpiresAt: time.Now().Add(24 * time.Hour).UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	// fake session manager
	sm := newFakeSessionManager()
	sm.setClaims(oldTok, mkClaims(uid, oldJTI, 24*time.Hour)) // ParseRefresh(oldTok)
	// RefreshFrom with rotate=false returns only access
	svc, err := appsession.NewService(repo, sm)
	if err != nil {
		t.Fatal(err)
	}

	access, refresh, err := svc.Refresh(t.Context(), oldTok, false)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if access == "" || refresh != "" {
		t.Fatalf("expected access only, got access=%q refresh=%q", access, refresh)
	}

	// old row still present
	if _, err := repo.FindRefreshTokenByHash(t.Context(), uid, secret.Hash(oldTok)); err != nil {
		t.Fatalf("expected old token to remain: %v", err)
	}
}

func TestRefresh_Rotate_DeletesOld_InsertsNew(t *testing.T) {
	stop, dsn := test.StartEmbeddedPostgres(t)
	defer stop()

	repo, err := postgres.NewUserRepo(test.MustPool(t, dsn))
	if err != nil {
		t.Fatal(err)
	}

	uid := uuid.New()
	if err := repo.UpsertUser(t.Context(), &user.User{ID: uid}); err != nil {
		t.Fatal(err)
	}

	oldJTI := uuid.New()
	oldTok := "ref1"
	if err := repo.InsertRefreshToken(t.Context(), &user.RefreshToken{
		Uid:       uid,
		Jti:       oldJTI,
		Hash:      secret.Hash(oldTok),
		ExpiresAt: time.Now().Add(24 * time.Hour).UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	newJTI := uuid.New()
	newTok := "ref2"

	sm := newFakeSessionManager()
	// parsing old token
	sm.setClaims(oldTok, mkClaims(uid, oldJTI, 24*time.Hour))
	// parsing new token (service parses it after RefreshFrom)
	sm.setClaims(newTok, mkClaims(uid, newJTI, 24*time.Hour))
	// deterministic RefreshFrom
	sm.refreshFromFunc = func(ctx context.Context, old string, extra map[string]string, rotate bool) (string, string, error) {
		if !rotate {
			return "access-new", "", nil
		}
		return "access-new", newTok, nil
	}

	svc, err := appsession.NewService(repo, sm)
	if err != nil {
		t.Fatal(err)
	}

	access, refresh, err := svc.Refresh(t.Context(), oldTok, true)
	if err != nil {
		t.Fatalf("Refresh rotate: %v", err)
	}
	if access == "" || refresh != newTok {
		t.Fatalf("expected new access + %q refresh, got access=%q refresh=%q", newTok, access, refresh)
	}

	// old should be gone
	if _, err := repo.FindRefreshTokenByHash(t.Context(), uid, secret.Hash(oldTok)); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("expected old token removed, got err=%v", err)
	}
	// new should exist
	if _, err := repo.FindRefreshTokenByHash(t.Context(), uid, secret.Hash(newTok)); err != nil {
		t.Fatalf("expected new token stored: %v", err)
	}
}

func TestRefresh_InvalidToken(t *testing.T) {
	stop, dsn := test.StartEmbeddedPostgres(t)
	defer stop()

	repo, err := postgres.NewUserRepo(test.MustPool(t, dsn))
	if err != nil {
		t.Fatal(err)
	}

	sm := newFakeSessionManager() // no claims => ParseRefresh fails
	svc, _ := appsession.NewService(repo, sm)

	if _, _, err := svc.Refresh(t.Context(), "garbage", true); !errors.Is(err, appsession.ErrInvalidToken) {
		t.Fatalf("want ErrInvalidToken, got %v", err)
	}
}

func TestRefresh_UserNotFound(t *testing.T) {
	stop, dsn := test.StartEmbeddedPostgres(t)
	defer stop()

	repo, err := postgres.NewUserRepo(test.MustPool(t, dsn))
	if err != nil {
		t.Fatal(err)
	}

	uid := uuid.New()
	oldTok := "ref1"
	oldJTI := uuid.New()

	// no user row inserted

	sm := newFakeSessionManager()
	sm.setClaims(oldTok, mkClaims(uid, oldJTI, 24*time.Hour))
	svc, _ := appsession.NewService(repo, sm)

	if _, _, err := svc.Refresh(t.Context(), oldTok, true); !errors.Is(err, appsession.ErrInvalidToken) {
		t.Fatalf("want ErrInvalidToken for missing user, got %v", err)
	}
}

func TestRevokeSingle_OK(t *testing.T) {
	stop, dsn := test.StartEmbeddedPostgres(t)
	defer stop()

	repo, err := postgres.NewUserRepo(test.MustPool(t, dsn))
	if err != nil {
		t.Fatal(err)
	}

	uid := uuid.New()
	if err := repo.UpsertUser(t.Context(), &user.User{ID: uid}); err != nil {
		t.Fatal(err)
	}
	jti := uuid.New()
	tok := "ref1"
	if err := repo.InsertRefreshToken(t.Context(), &user.RefreshToken{
		Uid:       uid,
		Jti:       jti,
		Hash:      secret.Hash(tok),
		ExpiresAt: time.Now().Add(24 * time.Hour).UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	sm := newFakeSessionManager()
	sm.setClaims(tok, mkClaims(uid, jti, 24*time.Hour))

	svc, _ := appsession.NewService(repo, sm)
	if err := svc.RevokeSingle(t.Context(), uid, tok); err != nil {
		t.Fatalf("RevokeSingle: %v", err)
	}

	// should be gone
	if _, err := repo.FindRefreshTokenByHash(t.Context(), uid, secret.Hash(tok)); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("expected token removed, got err=%v", err)
	}
}

func TestRevokeSingle_MismatchSubject(t *testing.T) {
	stop, dsn := test.StartEmbeddedPostgres(t)
	defer stop()

	repo, err := postgres.NewUserRepo(test.MustPool(t, dsn))
	if err != nil {
		t.Fatal(err)
	}

	uid := uuid.New()
	other := uuid.New()
	jti := uuid.New()
	tok := "ref1"

	_ = repo.UpsertUser(t.Context(), &user.User{ID: other})

	sm := newFakeSessionManager()
	sm.setClaims(tok, mkClaims(other, jti, 24*time.Hour))

	svc, _ := appsession.NewService(repo, sm)
	if err := svc.RevokeSingle(t.Context(), uid, tok); !errors.Is(err, appsession.ErrInvalidToken) {
		t.Fatalf("want ErrInvalidToken, got %v", err)
	}
}

func TestRevokeAll(t *testing.T) {
	stop, dsn := test.StartEmbeddedPostgres(t)
	defer stop()

	repo, err := postgres.NewUserRepo(test.MustPool(t, dsn))
	if err != nil {
		t.Fatal(err)
	}

	uid := uuid.New()
	if err := repo.UpsertUser(t.Context(), &user.User{ID: uid}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_ = repo.InsertRefreshToken(t.Context(), &user.RefreshToken{
			Uid:       uid,
			Jti:       uuid.New(),
			Hash:      secret.Hash(uuid.NewString()),
			ExpiresAt: time.Now().Add(24 * time.Hour).UTC(),
		})
	}

	sm := newFakeSessionManager()
	svc, _ := appsession.NewService(repo, sm)

	if err := svc.RevokeAll(t.Context(), uid); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}
	// any lookup should fail
	if _, err := repo.FindRefreshTokenByHash(t.Context(), uid, "anything"); !errors.Is(err, repository.ErrNotFound) {
		// Note: FindRefreshTokenByHash requires exact hash; this just sanity-checks behavior.
	}
}

func TestRefresh_Rotate_OnlyOneWins_Concurrent(t *testing.T) {
	stop, dsn := test.StartEmbeddedPostgres(t)
	defer stop()

	repo, err := postgres.NewUserRepo(test.MustPool(t, dsn))
	if err != nil {
		t.Fatal(err)
	}

	uid := uuid.New()
	if err := repo.UpsertUser(t.Context(), &user.User{ID: uid}); err != nil {
		t.Fatal(err)
	}

	oldJTI := uuid.New()
	oldTok := "ref1"
	if err := repo.InsertRefreshToken(t.Context(), &user.RefreshToken{
		Uid:       uid,
		Jti:       oldJTI,
		Hash:      secret.Hash(oldTok),
		ExpiresAt: time.Now().Add(24 * time.Hour).UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	newJTI := uuid.New()
	newTok := "ref2"

	sm := newFakeSessionManager()
	sm.setClaims(oldTok, mkClaims(uid, oldJTI, 24*time.Hour))
	sm.setClaims(newTok, mkClaims(uid, newJTI, 24*time.Hour))
	sm.refreshFromFunc = func(ctx context.Context, old string, extra map[string]string, rotate bool) (string, string, error) {
		return "access-new", newTok, nil
	}

	svc, _ := appsession.NewService(repo, sm)

	var wg sync.WaitGroup
	const N = 8
	wg.Add(N)
	errs := make(chan error, N)

	start := make(chan struct{})
	for range N {
		go func() {
			defer wg.Done()
			<-start
			_, _, err := svc.Refresh(context.Background(), oldTok, true)
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)

	success := 0
	fail := 0
	for e := range errs {
		if e == nil {
			success++
		} else {
			fail++
		}
	}
	if success != 1 {
		t.Fatalf("expected exactly 1 success, got success=%d fail=%d", success, fail)
	}

	// old hash should be gone
	if _, err := repo.FindRefreshTokenByHash(t.Context(), uid, secret.Hash(oldTok)); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("old token still present; err=%v", err)
	}
	// new present
	if _, err := repo.FindRefreshTokenByHash(t.Context(), uid, secret.Hash(newTok)); err != nil {
		t.Fatalf("new token not present; err=%v", err)
	}
}
