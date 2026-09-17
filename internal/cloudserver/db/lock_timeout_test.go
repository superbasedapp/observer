package db

// lock_timeout_test.go covers the migration-transaction session timeouts
// added for the post-directives-followups tracker §6.2 residual: Migrate runs
// its whole pending batch in ONE transaction, and without a bound a GRANT or
// ALTER on a hot table can queue indefinitely behind an unrelated
// long-running (or lock-holding) session, blocking every other session
// behind it in turn.
//
// TestMigrateOptionsResolveDefaults is a pure unit test (no DSN needed).
// TestMigrateLockTimeoutSurfacesTypedErrorAndDoesNotAdvanceVersion is an
// INTERNAL (package db) live-Postgres test — it needs migratePrefix (defined
// in db_populated_migration_test.go) to leave the throwaway database sitting
// on a version where the very next embedded migration (0004_rls_grants.sql,
// `ALTER TABLE accounts ... ENABLE ROW LEVEL SECURITY`) is guaranteed to
// request a lock on "accounts" that conflicts with an ACCESS EXCLUSIVE lock
// held by another session — and newThrowawayDB (defined in
// db_plan_v2_migration_test.go) for the same throwaway-database dance every
// other live test in this package already follows.

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMigrateOptionsResolveDefaults(t *testing.T) {
	cases := []struct {
		name       string
		opts       MigrateOptions
		wantLock   time.Duration
		wantStmt   time.Duration
		wantLockOK bool // true when wantLock should equal the resolved value exactly
	}{
		{
			name:     "zero value applies both defaults",
			opts:     MigrateOptions{},
			wantLock: defaultMigrateLockTimeout,
			wantStmt: defaultMigrateStatementTimeout,
		},
		{
			name:     "negative values apply both defaults",
			opts:     MigrateOptions{LockTimeout: -1, StatementTimeout: -time.Minute},
			wantLock: defaultMigrateLockTimeout,
			wantStmt: defaultMigrateStatementTimeout,
		},
		{
			name:     "explicit positive values pass through unchanged",
			opts:     MigrateOptions{LockTimeout: 3 * time.Second, StatementTimeout: 90 * time.Second},
			wantLock: 3 * time.Second,
			wantStmt: 90 * time.Second,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotLock, gotStmt := tc.opts.resolve()
			if gotLock != tc.wantLock {
				t.Errorf("resolved LockTimeout = %v, want %v", gotLock, tc.wantLock)
			}
			if gotStmt != tc.wantStmt {
				t.Errorf("resolved StatementTimeout = %v, want %v", gotStmt, tc.wantStmt)
			}
		})
	}
	if defaultMigrateLockTimeout != 10*time.Second {
		t.Errorf("defaultMigrateLockTimeout = %v, want 10s", defaultMigrateLockTimeout)
	}
	if defaultMigrateStatementTimeout != 5*time.Minute {
		t.Errorf("defaultMigrateStatementTimeout = %v, want 5m", defaultMigrateStatementTimeout)
	}
}

// TestMigrateLockTimeoutSurfacesTypedErrorAndDoesNotAdvanceVersion is the
// live-rig proof: another session holds an ACCESS EXCLUSIVE lock on
// "accounts" while Migrate, given a 1s LockTimeout, tries to apply the
// pending 0004_rls_grants.sql (which ALTERs accounts to enable RLS). Migrate
// must fail with a *LockTimeoutError naming the migration it was applying,
// and — because the whole batch runs in one transaction that gets rolled
// back — the schema version must be exactly what it was before the attempt.
func TestMigrateLockTimeoutSurfacesTypedErrorAndDoesNotAdvanceVersion(t *testing.T) {
	pool := newThrowawayDB(t, "sbci_locktimeout_")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 1) Migrate to version 3: "accounts" exists (0002_core_schema.sql), and
	// the next pending migration (0004_rls_grants.sql) is the one that ALTERs
	// it. 0003_functions.sql only references accounts inside a function body
	// (no DDL against the table), so it applies cleanly at this prefix.
	if err := migratePrefix(ctx, pool, 3); err != nil {
		t.Fatalf("migrate to 3: %v", err)
	}
	before, err := Version(ctx, pool)
	if err != nil {
		t.Fatalf("Version before locked attempt: %v", err)
	}
	if before != 3 {
		t.Fatalf("Version after prefix = %d, want 3", before)
	}

	// 2) Hold an ACCESS EXCLUSIVE lock on accounts from a SEPARATE session
	// (a dedicated pool connection), left open across the Migrate call below.
	lockConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire lock-holder connection: %v", err)
	}
	defer lockConn.Release()
	lockTx, err := lockConn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin lock-holder transaction: %v", err)
	}
	defer func() { _ = lockTx.Rollback(ctx) }()
	if _, err := lockTx.Exec(ctx, `LOCK TABLE accounts IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatalf("take ACCESS EXCLUSIVE lock on accounts: %v", err)
	}

	// 3) Migrate, with a short LockTimeout, must give up waiting on the
	// blocked ALTER TABLE and surface a typed LockTimeoutError.
	migrateErr := Migrate(ctx, pool, MigrateOptions{LockTimeout: time.Second})
	if migrateErr == nil {
		t.Fatal("Migrate succeeded while accounts was ACCESS EXCLUSIVE-locked by another session; want a lock-timeout error")
	}
	var lockErr *LockTimeoutError
	if !errors.As(migrateErr, &lockErr) {
		t.Fatalf("Migrate error is not a *LockTimeoutError: %v", migrateErr)
	}
	if lockErr.Version <= before {
		t.Errorf("LockTimeoutError.Version = %d, want > %d (the migration blocked on the lock)", lockErr.Version, before)
	}
	if lockErr.Filename == "" {
		t.Error("LockTimeoutError.Filename is empty, want the blocked migration's filename")
	}
	if lockErr.Err == nil {
		t.Error("LockTimeoutError.Err is nil, want the underlying Postgres 55P03 error")
	}
	t.Logf("Migrate lock-timeout error (expected): %v", migrateErr)

	// 4) The batch transaction was rolled back in full: schema version is
	// unchanged, nothing from the blocked attempt was committed.
	after, err := Version(ctx, pool)
	if err != nil {
		t.Fatalf("Version after locked attempt: %v", err)
	}
	if after != before {
		t.Fatalf("Version after failed Migrate = %d, want unchanged %d — the migration batch should have rolled back entirely", after, before)
	}

	// 5) Release the lock and prove Migrate recovers cleanly on the next
	// attempt (the SET LOCAL timeouts are transaction-scoped, so the failed
	// attempt's session state cannot have leaked onto the pooled connection).
	// Rolling back lockTx releases the table lock immediately; the deferred
	// lockConn.Release()/lockTx.Rollback(ctx) above still run harmlessly at
	// test end (a second Rollback on an already-closed tx is a no-op error
	// we already discard).
	if err := lockTx.Rollback(ctx); err != nil {
		t.Fatalf("release lock-holder transaction: %v", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate after releasing the lock: %v", err)
	}
	head, err := MaxEmbeddedVersion()
	if err != nil {
		t.Fatalf("MaxEmbeddedVersion: %v", err)
	}
	if v, err := Version(ctx, pool); err != nil || v != head {
		t.Fatalf("Version after recovery migrate = %d err=%v, want head %d", v, err, head)
	}
}
