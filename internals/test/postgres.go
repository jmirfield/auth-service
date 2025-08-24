package test

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"

	"github.com/jmirfield/auth-service/migrations"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func freeTCPPort(t *testing.T) uint32 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	return uint32(l.Addr().(*net.TCPAddr).Port)
}

func binariesCacheDir() string {
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "embedded-postgres-binaries")
	}
	return filepath.Join(os.TempDir(), "embedded-postgres-binaries")
}

func StartEmbeddedPostgres(t *testing.T) (stop func(), connString string) {
	t.Helper()

	dataDir := t.TempDir()
	port := freeTCPPort(t)
	cfg := embeddedpostgres.DefaultConfig().
		RuntimePath(filepath.Join(dataDir, "run")).
		DataPath(filepath.Join(dataDir, "data")).
		BinariesPath(binariesCacheDir()).
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

	runMigrations(t, connString)

	return stop, connString
}

func MustPool(t *testing.T, connString string) *pgxpool.Pool {
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
