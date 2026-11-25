package cloudtestpg

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg/pgthrow"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/db"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// EnvVar is the environment variable naming the admin DSN of the test Postgres
// (pgthrow owns the name and the rule).
const EnvVar = pgthrow.EnvVar

// RequiredEnvVar, set to "1", turns a missing DSN from a skip into a failure
// (see pgthrow.RequiredEnvVar).
const RequiredEnvVar = pgthrow.RequiredEnvVar

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
// message (pgthrow.RequireDSN).
func RequireDSN(t *testing.T) string {
	t.Helper()
	return pgthrow.RequireDSN(t)
}

// NewDB creates a uniquely-named database on the admin DSN's cluster, migrates
// it to head, generates the plans rows from the entitlements catalog (what
// `observer-cloud migrate` does after the migrations, so a test reads the
// plans a deployment serves: the catalog's labels, cloud 0156), and returns a
// pool bound to it. The database is dropped on test
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

	dbName := "sbci_test_" + pgthrow.RandToken()

	if err := pgthrow.CreateDatabase(ctx, adminDSN, dbName); err != nil {
		t.Fatalf("cloudtestpg: %v", err)
	}

	cfg, err := pgxpool.ParseConfig(adminDSN)
	if err != nil {
		t.Fatalf("cloudtestpg: parse DSN: %v", err)
	}
	cfg.ConnConfig.Database = dbName
	cfg.MaxConns = 10

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		pgthrow.DropDatabase(t, adminDSN, dbName)
		t.Fatalf("cloudtestpg: open pool on %s: %v", dbName, err)
	}
	if err := migrateSerialized(ctx, adminDSN, pool); err != nil {
		pool.Close()
		pgthrow.DropDatabase(t, adminDSN, dbName)
		t.Fatalf("cloudtestpg: migrate %s: %v", dbName, err)
	}
	if _, err := store.GeneratePlans(ctx, pool); err != nil {
		pool.Close()
		pgthrow.DropDatabase(t, adminDSN, dbName)
		t.Fatalf("cloudtestpg: generate the plans rows on %s: %v", dbName, err)
	}

	t.Cleanup(func() {
		pool.Close()
		pgthrow.DropDatabase(t, adminDSN, dbName)
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
