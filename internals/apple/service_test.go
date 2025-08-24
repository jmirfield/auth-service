package apple_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"

	apple "github.com/jmirfield/auth-service/internals/apple"
	"github.com/jmirfield/auth-service/internals/domain/user"
	"github.com/jmirfield/auth-service/internals/repository/postgres"
	"github.com/jmirfield/auth-service/internals/secret"
	"github.com/jmirfield/auth-service/internals/test"
	"github.com/jmirfield/auth-service/pkg/session"
)

func countIdentities(t *testing.T, pool *pgxpool.Pool, provider, sub string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM user_identities WHERE provider=$1 AND sub=$2`, provider, sub).Scan(&n); err != nil {
		t.Fatalf("countIdentities: %v", err)
	}
	return n
}

func getIdentityUID(t *testing.T, pool *pgxpool.Pool, provider, sub string) uuid.UUID {
	t.Helper()
	var uid uuid.UUID
	if err := pool.QueryRow(t.Context(),
		`SELECT user_id FROM user_identities WHERE provider=$1 AND sub=$2`, provider, sub).Scan(&uid); err != nil {
		t.Fatalf("getIdentityUID: %v", err)
	}
	return uid
}

func countUsers(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	return n
}

func countRefreshTokensFor(t *testing.T, pool *pgxpool.Pool, uid uuid.UUID) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM user_refresh_tokens WHERE user_id = $1`, uid).Scan(&n); err != nil {
		t.Fatalf("count refresh tokens: %v", err)
	}
	return n
}

func countAllRefreshTokens(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM user_refresh_tokens`).Scan(&n); err != nil {
		t.Fatalf("countAllRefreshTokens: %v", err)
	}
	return n
}

type fakeAppleManager struct {
	exchangeCodeFunc func(ctx context.Context, code string) (*apple.TokenResponse, error)
	refreshFunc      func(ctx context.Context, tok string) (*apple.TokenResponse, error)
	verifyFunc       func(ctx context.Context, tok string, nonce ...string) (*apple.Claims, error)
}

func (f *fakeAppleManager) ExchangeCode(ctx context.Context, code string) (*apple.TokenResponse, error) {
	return f.exchangeCodeFunc(ctx, code)
}
func (f *fakeAppleManager) Refresh(ctx context.Context, tok string) (*apple.TokenResponse, error) {
	return f.refreshFunc(ctx, tok)
}
func (f *fakeAppleManager) VerifyIDToken(ctx context.Context, tok string, nonce ...string) (*apple.Claims, error) {
	return f.verifyFunc(ctx, tok, nonce...)
}

var errBadTok = jwt.ErrTokenMalformed

type fakeSessionManager struct {
	mu            sync.Mutex
	claims        map[string]*sessionClaims // refresh-token -> claims
	issuePairFunc func(ctx context.Context, uid uuid.UUID, extra map[string]string) (string, string, error)
}

type sessionClaims struct {
	sub string
	jti string
	exp time.Time
}

func newFakeSessionManager() *fakeSessionManager {
	return &fakeSessionManager{claims: make(map[string]*sessionClaims)}
}

func (f *fakeSessionManager) IssuePair(ctx context.Context, uid uuid.UUID, extra map[string]string) (string, string, error) {
	if f.issuePairFunc != nil {
		return f.issuePairFunc(ctx, uid, extra)
	}
	// Default: make unique tokens + register claims
	ref := "refresh-" + uuid.NewString()
	acc := "access-" + uuid.NewString()
	f.mu.Lock()
	f.claims[ref] = &sessionClaims{
		sub: uid.String(),
		jti: uuid.NewString(),
		exp: time.Now().Add(24 * time.Hour),
	}
	f.mu.Unlock()
	return acc, ref, nil
}

func (f *fakeSessionManager) ParseRefresh(ctx context.Context, tok string) (*session.Claims, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.claims[tok]
	if !ok {
		return nil, errBadTok
	}
	return &session.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   c.sub,
			ID:        c.jti,
			ExpiresAt: jwt.NewNumericDate(c.exp),
		},
	}, nil
}

func (f *fakeSessionManager) RefreshFrom(ctx context.Context, old string, extra map[string]string, rotate bool) (string, string, error) {
	if !rotate {
		return "access-" + uuid.NewString(), "", nil
	}
	// Rotate to new refresh; inherit subject from old
	cOld, _ := f.ParseRefresh(ctx, old)
	ref := "refresh-" + uuid.NewString()
	acc := "access-" + uuid.NewString()

	f.mu.Lock()
	f.claims[ref] = &sessionClaims{
		sub: cOld.Subject,
		jti: uuid.NewString(),
		exp: time.Now().Add(24 * time.Hour),
	}
	f.mu.Unlock()
	return acc, ref, nil
}

func (f *fakeSessionManager) IssueAccess(ctx context.Context, uid uuid.UUID, extra map[string]string) (string, error) {
	return "access-" + uuid.NewString(), nil
}
func (f *fakeSessionManager) IssueRefresh(ctx context.Context, uid uuid.UUID) (string, error) {
	ref := "refresh-" + uuid.NewString()
	f.mu.Lock()
	f.claims[ref] = &sessionClaims{
		sub: uid.String(),
		jti: uuid.NewString(),
		exp: time.Now().Add(24 * time.Hour),
	}
	f.mu.Unlock()
	return ref, nil
}
func (f *fakeSessionManager) ParseAccess(ctx context.Context, tok string) (*session.Claims, error) {
	return &session.Claims{}, nil
}

func TestAuth_FirstLogin_CreatesIdentity_StoresRefresh(t *testing.T) {
	stop, dsn := test.StartEmbeddedPostgres(t)
	defer stop()

	repo, err := postgres.NewUserRepo(test.MustPool(t, dsn))
	if err != nil {
		t.Fatal(err)
	}

	am := &fakeAppleManager{
		exchangeCodeFunc: func(ctx context.Context, code string) (*apple.TokenResponse, error) {
			return &apple.TokenResponse{IDToken: "idtok"}, nil
		},
		verifyFunc: func(ctx context.Context, tok string, nonce ...string) (*apple.Claims, error) {
			return &apple.Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: "sub-123", Issuer: "iss"}}, nil
		},
		refreshFunc: func(ctx context.Context, tok string) (*apple.TokenResponse, error) { return nil, nil },
	}

	sm := newFakeSessionManager()

	svc, err := apple.NewService(am, sm, repo)
	if err != nil {
		t.Fatal(err)
	}

	access, refresh, err := svc.Auth(t.Context(), "code-ok", "nonce-ok")
	if err != nil {
		t.Fatalf("Auth: %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatalf("expected non-empty tokens")
	}

	ident, err := repo.GetIdentity(t.Context(), user.ProviderApple, "sub-123")
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}

	if _, err := repo.FindRefreshTokenByHash(t.Context(), ident.Uid, secret.Hash(refresh)); err != nil {
		t.Fatalf("refresh not stored: %v", err)
	}
}

func TestAuth_BadCode_NoSideEffects(t *testing.T) {
	stop, dsn := test.StartEmbeddedPostgres(t)
	defer stop()

	pool := test.MustPool(t, dsn)
	repo, err := postgres.NewUserRepo(pool)
	if err != nil {
		t.Fatal(err)
	}

	am := &fakeAppleManager{
		exchangeCodeFunc: func(ctx context.Context, code string) (*apple.TokenResponse, error) {
			return nil, apple.ErrBadCode
		},
		verifyFunc: func(ctx context.Context, tok string, nonce ...string) (*apple.Claims, error) {
			t.Fatal("VerifyIDToken should not be called on bad code")
			return nil, nil
		},
		refreshFunc: func(ctx context.Context, tok string) (*apple.TokenResponse, error) { return nil, nil },
	}

	sm := newFakeSessionManager()

	svc, _ := apple.NewService(am, sm, repo)

	_, _, err = svc.Auth(t.Context(), "bad-code", "nonce")
	if !errors.Is(err, apple.ErrBadCode) {
		t.Fatalf("want ErrBadCode, got %v", err)
	}

	if _, err := repo.GetIdentity(t.Context(), user.ProviderApple, "sub-123"); err == nil {
		t.Fatalf("identity unexpectedly persisted")
	}
}

func TestAuth_InvalidIDToken_NoSideEffects(t *testing.T) {
	stop, dsn := test.StartEmbeddedPostgres(t)
	defer stop()

	pool := test.MustPool(t, dsn)
	repo, err := postgres.NewUserRepo(pool)
	if err != nil {
		t.Fatal(err)
	}

	am := &fakeAppleManager{
		exchangeCodeFunc: func(ctx context.Context, code string) (*apple.TokenResponse, error) {
			return &apple.TokenResponse{IDToken: "idtok"}, nil
		},
		verifyFunc: func(ctx context.Context, tok string, nonce ...string) (*apple.Claims, error) {
			return nil, apple.ErrInvalidToken
		},
		refreshFunc: func(ctx context.Context, tok string) (*apple.TokenResponse, error) { return nil, nil },
	}
	sm := newFakeSessionManager()

	svc, _ := apple.NewService(am, sm, repo)

	_, _, err = svc.Auth(t.Context(), "code-ok", "nonce")
	if !errors.Is(err, apple.ErrInvalidToken) {
		t.Fatalf("want ErrInvalidToken, got %v", err)
	}

	if _, err := repo.GetIdentity(t.Context(), user.ProviderApple, "sub-123"); err == nil {
		t.Fatalf("identity unexpectedly persisted")
	}
}

func TestAuth_ExistingIdentity_NoNewUser_StoresRefresh(t *testing.T) {
	stop, dsn := test.StartEmbeddedPostgres(t)
	defer stop()

	pool := test.MustPool(t, dsn)
	repo, err := postgres.NewUserRepo(pool)
	if err != nil {
		t.Fatal(err)
	}

	uid := uuid.New()
	if err := repo.UpsertUser(t.Context(), &user.User{ID: uid, Attr: nil}); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	if err := repo.UpsertIdentity(t.Context(), &user.Identity{
		Uid: uid, Provider: user.ProviderApple, Sub: "sub-123",
	}); err != nil {
		t.Fatalf("UpsertIdentity: %v", err)
	}

	usersBefore := countUsers(t, pool)

	am := &fakeAppleManager{
		exchangeCodeFunc: func(ctx context.Context, code string) (*apple.TokenResponse, error) {
			return &apple.TokenResponse{IDToken: "idtok"}, nil
		},
		verifyFunc: func(ctx context.Context, tok string, nonce ...string) (*apple.Claims, error) {
			return &apple.Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: "sub-123", Issuer: "iss"}}, nil
		},
		refreshFunc: func(ctx context.Context, tok string) (*apple.TokenResponse, error) { return nil, nil },
	}

	sm := newFakeSessionManager()

	svc, _ := apple.NewService(am, sm, repo)

	access, refresh, err := svc.Auth(t.Context(), "code-ok", "nonce")
	if err != nil {
		t.Fatalf("Auth: %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatalf("expected tokens")
	}

	ident, err := repo.GetIdentity(t.Context(), user.ProviderApple, "sub-123")
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}
	if ident.Uid != uid {
		t.Fatalf("identity reassigned: got %s want %s", ident.Uid, uid)
	}

	usersAfter := countUsers(t, pool)
	if usersAfter != usersBefore {
		t.Fatalf("users count changed: before=%d after=%d", usersBefore, usersAfter)
	}

	if countRefreshTokensFor(t, pool, uid) < 1 {
		t.Fatalf("expected refresh token persisted")
	}
}

func TestAuth_ConcurrentFirstLogin_SerializesIdentity(t *testing.T) {
	stop, dsn := test.StartEmbeddedPostgres(t)
	defer stop()

	pool := test.MustPool(t, dsn)
	repo, err := postgres.NewUserRepo(pool)
	if err != nil {
		t.Fatal(err)
	}

	const (
		N        = 8
		provider = user.ProviderApple
		subject  = "concurrent-sub"
		issuer   = "iss"
	)

	am := &fakeAppleManager{
		exchangeCodeFunc: func(ctx context.Context, code string) (*apple.TokenResponse, error) {
			return &apple.TokenResponse{IDToken: "idtok"}, nil
		},
		verifyFunc: func(ctx context.Context, tok string, nonce ...string) (*apple.Claims, error) {
			return &apple.Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: subject, Issuer: issuer}}, nil
		},
		refreshFunc: func(ctx context.Context, tok string) (*apple.TokenResponse, error) { return nil, nil },
	}

	errs := make([]error, N)
	accesses := make([]string, N)
	refreshes := make([]string, N)

	var wg sync.WaitGroup
	wg.Add(N)
	start := make(chan struct{})

	for i := range N {
		go func(idx int) {
			defer wg.Done()
			sm := newFakeSessionManager()

			svc, serr := apple.NewService(am, sm, repo)
			if serr != nil {
				errs[idx] = serr
				return
			}

			<-start
			a, r, serr := svc.Auth(context.Background(), "code-ok", "nonce-ok")
			if serr != nil {
				errs[idx] = serr
				return
			}
			accesses[idx] = a
			refreshes[idx] = r
		}(i)
	}

	close(start)
	wg.Wait()

	// no goroutine should error
	for i, e := range errs {
		if e != nil {
			t.Fatalf("goroutine %d error: %v", i, e)
		}
	}
	// tokens non-empty
	for i := 0; i < N; i++ {
		if accesses[i] == "" || refreshes[i] == "" {
			t.Fatalf("goroutine %d returned empty tokens", i)
		}
	}

	// exactly one identity
	if got := countIdentities(t, pool, provider, subject); got != 1 {
		t.Fatalf("identities count = %d, want 1", got)
	}
	finalUID := getIdentityUID(t, pool, provider, subject)

	// exactly one user
	if users := countUsers(t, pool); users != 1 {
		t.Fatalf("users count = %d, want 1", users)
	}

	// N unique refresh tokens (no UNIQUE (user_id,hash) collisions)
	if got := countAllRefreshTokens(t, pool); got != N {
		t.Fatalf("refresh tokens total = %d, want %d", got, N)
	}

	if nForFinal := countRefreshTokensFor(t, pool, finalUID); nForFinal == 0 {
		t.Fatalf("expected at least one refresh token for final identity uid %s", finalUID)
	}
}
