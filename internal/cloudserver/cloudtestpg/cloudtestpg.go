// Package cloudtestpg is a Postgres test-support helper for the cloudserver
// suites. It reads SBCI_TEST_PG_DSN (the admin DSN of a throwaway Postgres,
// e.g. a local docker container) and hands each test its OWN freshly-migrated
// database, dropped on cleanup, so RLS/lease/reservation tests are fully
// isolated — including the global system rows (budget_pools, kill_switches).
//
// It is a normal package (not a _test.go file) so every cloudserver test
// package can import it, but it imports "testing" and is referenced only from
// tests, so it never enters a production binary.
package cloudtestpg

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/db"
)

// EnvVar is the environment variable naming the admin DSN of the test Postgres.
const EnvVar = "SBCI_TEST_PG_DSN"

// migrateSerial is a fast, process-local gate that serializes migrations run by
// this test binary's own parallel subtests before they reach the network lock —
// so same-process contention costs a mutex, not an admin round trip.
var migrateSerial sync.Mutex

// harnessMigrateLockKey is the advisory-lock key the harness holds on the
// SHARED admin database (the DSN's own database, typically "postgres") while it
// migrates a per-test database.
//
// WHY on the admin database and not the per-test one: 0001_roles.sql creates
// and alters the CLUSTER-GLOBAL roles sbci_app / sbci_defs (pg_authid is shared
// across every database in the cluster), but a PostgreSQL advisory lock only
// contends with lockers taken IN THE SAME DATABASE (verified against the test
// cluster: the same key acquired freely from a second database). So the
// production per-database lock in db.Migrate — correct for real replicas, which
// share one database — cannot serialize migrations of DIFFERENT test databases,
// and their concurrent role DDL races the transient "tuple concurrently
// updated" (SQLSTATE XX000). Taking this lock on the ONE admin database every
// test process shares gives a single advisory namespace, so concurrent NewDB
// calls — across goroutines AND across parallel `go test` package binaries —
// take turns through the role DDL. Distinct value from db.migrationsAdvisoryLock
// (a different database namespace anyway, so no cross-lock deadlock).
const harnessMigrateLockKey int64 = 0x5B_C1_03_11 // "sbci-0311", one past the prod migrate key.

// RequireDSN returns the admin DSN or SKIPS the test with a loud, explicit
// message. Silent-pass is a known hazard (repo memory
// feedback_cached_test_results_vacuous_gate) — a skipped Postgres suite must be
// unmistakable in the output, never look like a pass.
func RequireDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv(EnvVar)
	if dsn == "" {
		t.Skipf("SKIP (no Postgres): set %s to run this suite, e.g. "+
			"%s=postgres://postgres:sbci@127.0.0.1:15544/postgres?sslmode=disable "+
			"(start one with: docker run -d --name sbci-test-pg -e POSTGRES_PASSWORD=sbci "+
			"-p 127.0.0.1:15544:5432 postgres:16-alpine). This test did NOT run.",
			EnvVar, EnvVar)
	}
	return dsn
}

// NewDB creates a uniquely-named database on the admin DSN's cluster, migrates
// it to head, and returns a pool bound to it. The database is dropped on test
// cleanup. Roles (sbci_app/sbci_defs) are cluster-global and created
// idempotently by migration 0001, so parallel NewDB calls are safe.
func NewDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	adminDSN := RequireDSN(t)
	// Generous: migrations now serialize through the shared-admin advisory lock
	// (migrateSerialized), so a database queued behind many concurrent peers in
	// a heavily-parallel suite may wait for its turn at the role DDL.
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	dbName := "sbci_test_" + randToken()

	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("cloudtestpg: connect admin: %v", err)
	}
	if _, err := admin.Exec(ctx, `CREATE DATABASE "`+dbName+`" TEMPLATE template0`); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("cloudtestpg: create database %s: %v", dbName, err)
	}
	_ = admin.Close(ctx)

	cfg, err := pgxpool.ParseConfig(adminDSN)
	if err != nil {
		t.Fatalf("cloudtestpg: parse DSN: %v", err)
	}
	cfg.ConnConfig.Database = dbName
	cfg.MaxConns = 10

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		dropDatabase(t, adminDSN, dbName)
		t.Fatalf("cloudtestpg: open pool on %s: %v", dbName, err)
	}
	if err := migrateSerialized(ctx, adminDSN, pool); err != nil {
		pool.Close()
		dropDatabase(t, adminDSN, dbName)
		t.Fatalf("cloudtestpg: migrate %s: %v", dbName, err)
	}

	t.Cleanup(func() {
		pool.Close()
		dropDatabase(t, adminDSN, dbName)
	})
	return pool
}

// migrateSerialized runs db.Migrate on pool while serializing it against every
// other concurrent migration — same-process ones through migrateSerial, and
// cross-process ones through an advisory lock held on the SHARED admin database
// (see harnessMigrateLockKey). This closes the XX000 role race that db.Migrate's
// own per-database lock cannot, without touching the production migrate path.
func migrateSerialized(ctx context.Context, adminDSN string, pool *pgxpool.Pool) error {
	migrateSerial.Lock()
	defer migrateSerial.Unlock()

	lockConn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		return fmt.Errorf("cloudtestpg: open migrate-lock conn: %w", err)
	}
	// Release order is LIFO: unlock (frees the session lock the instant the
	// migration finishes, before a possibly-slow Close under load) then close.
	defer func() { _ = lockConn.Close(context.Background()) }()
	if _, err := lockConn.Exec(ctx, `SELECT pg_advisory_lock($1)`, harnessMigrateLockKey); err != nil {
		return fmt.Errorf("cloudtestpg: acquire migrate lock: %w", err)
	}
	defer func() {
		_, _ = lockConn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, harnessMigrateLockKey)
	}()

	return db.Migrate(ctx, pool)
}

func dropDatabase(t *testing.T, adminDSN, dbName string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Logf("cloudtestpg: drop %s: connect admin: %v", dbName, err)
		return
	}
	defer func() { _ = admin.Close(ctx) }()
	if _, err := admin.Exec(ctx, `DROP DATABASE IF EXISTS "`+dbName+`" WITH (FORCE)`); err != nil {
		t.Logf("cloudtestpg: drop database %s: %v", dbName, err)
	}
}

func randToken() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
