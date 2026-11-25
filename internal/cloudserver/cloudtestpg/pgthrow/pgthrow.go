package pgthrow

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EnvVar is the environment variable naming the admin DSN of the test Postgres.
const EnvVar = "SBCI_TEST_PG_DSN"

// RequiredEnvVar, set to "1", turns a missing DSN from a skip into a failure.
// The ops gate's bootstrap sets it with the DSN for every live-PostgreSQL
// unit, so a suite whose DSN did not arrive fails loudly instead of passing
// by skipping (L-139: the cloud suites skipped on every gate until
// 2026-11-17, and only GitHub's org-postgres run executed them).
const RequiredEnvVar = "SBCI_TEST_PG_REQUIRED"

// RequireDSN returns the admin DSN or SKIPS the test with a loud, explicit
// message. Silent-pass is a known hazard (repo memory
// feedback_cached_test_results_vacuous_gate) — a skipped Postgres suite must be
// unmistakable in the output, never look like a pass.
func RequireDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv(EnvVar)
	if dsn == "" && os.Getenv(RequiredEnvVar) == "1" {
		t.Fatalf("%s=1 but %s is empty: this run provides PostgreSQL, so the suite must not skip", RequiredEnvVar, EnvVar)
	}
	if dsn == "" {
		t.Skipf("SKIP (no Postgres): set %s to run this suite, e.g. "+
			"%s=postgres://postgres:sbci@127.0.0.1:15544/postgres?sslmode=disable "+
			"(start one with: docker run -d --name sbci-test-pg -e POSTGRES_PASSWORD=sbci "+
			"-p 127.0.0.1:15544:5432 postgres:16-alpine). This test did NOT run.",
			EnvVar, EnvVar)
	}
	return dsn
}

// RandToken returns 16 random hex characters for a unique database name.
func RandToken() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// CreateDatabase creates the empty database name (TEMPLATE template0) on the
// admin DSN's cluster.
func CreateDatabase(ctx context.Context, adminDSN, name string) error {
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		return fmt.Errorf("connect admin: %w", err)
	}
	defer func() { _ = admin.Close(ctx) }()
	if _, err := admin.Exec(ctx, `CREATE DATABASE "`+name+`" TEMPLATE template0`); err != nil {
		return fmt.Errorf("create database %s: %w", name, err)
	}
	return nil
}

// DropDatabase drops name WITH (FORCE). A failure is logged, never fatal: it
// runs from test cleanup.
func DropDatabase(t *testing.T, adminDSN, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Logf("pgthrow: drop %s: connect admin: %v", name, err)
		return
	}
	defer func() { _ = admin.Close(ctx) }()
	if _, err := admin.Exec(ctx, `DROP DATABASE IF EXISTS "`+name+`" WITH (FORCE)`); err != nil {
		t.Logf("pgthrow: drop database %s: %v", name, err)
	}
}

// NewEmptyDB creates an EMPTY, un-migrated database named prefix plus a
// random token and returns a pool (at most 4 connections) bound to it. The
// database is dropped, and the pool closed, on test cleanup.
//
// It runs no migration and so takes no lock. A caller that migrates the
// database itself runs migration 0001's cluster-global role DDL without the
// admin-database advisory lock cloudtestpg.NewDB serializes it under.
func NewEmptyDB(t *testing.T, prefix string) *pgxpool.Pool {
	t.Helper()
	dsn := RequireDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	dbName := prefix + RandToken()
	if err := CreateDatabase(ctx, dsn, dbName); err != nil {
		t.Fatalf("pgthrow: %v", err)
	}
	t.Cleanup(func() { DropDatabase(t, dsn, dbName) })

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("pgthrow: parse DSN: %v", err)
	}
	cfg.ConnConfig.Database = dbName
	cfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("pgthrow: open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}
