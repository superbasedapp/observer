// Package db owns the hosted cloud-intelligence service's Postgres connection
// pool and its OWN migration lineage (plan of record §6 CI-P3). It is separate
// in every dimension from the agent SQLite side (internal/db) and the
// org-server SQLite side (internal/orgserver/db): a different database, the pgx
// driver, and a version counter that begins at migration 0001.
package db

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/db/migrations"
)

// migrationsAdvisoryLock is an arbitrary but stable key for the
// transaction-scoped advisory lock that serializes concurrent migrators (two
// container replicas booting at once). It is unrelated to any other lock key
// in the estate.
const migrationsAdvisoryLock int64 = 0x5B_C1_03_10 // "sbci-0310" mnemonic.

// Open builds a bounded pgx pool from a DSN. It does NOT run migrations — call
// Migrate explicitly (the `observer-cloud migrate` verb, or a test harness).
func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("cloudserver/db.Open: DSN is required")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("cloudserver/db.Open: parse DSN: %w", err)
	}
	if cfg.MaxConns == 0 {
		cfg.MaxConns = 16
	}
	if cfg.MaxConnIdleTime == 0 {
		cfg.MaxConnIdleTime = 5 * time.Minute
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("cloudserver/db.Open: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("cloudserver/db.Open: ping: %w", err)
	}
	return pool, nil
}

// MigrateOptions configures the per-migration-transaction Postgres session
// timeouts SET LOCAL immediately applies after BEGIN (see Migrate). The zero
// value applies the documented defaults, so every existing call site (which
// passes no MigrateOptions at all) is unaffected.
type MigrateOptions struct {
	// LockTimeout bounds how long the migration transaction — including
	// every DDL statement in the embedded lineage — waits to acquire a lock
	// before giving up (the Postgres lock_timeout GUC). Without a bound, a
	// GRANT or ALTER on a hot table can queue behind an unrelated
	// long-running query and then block every other session waiting behind
	// it in turn, for as long as that query runs. Zero or negative (unset)
	// applies the default of 10s.
	LockTimeout time.Duration

	// StatementTimeout bounds how long any single statement inside the
	// migration transaction may run (the Postgres statement_timeout GUC).
	// Zero or negative (unset) applies the default of 5 minutes — generous
	// headroom for a legitimately large migration (e.g. a backfill), while
	// still bounding a runaway statement so a stuck migration can't hang a
	// deploy forever.
	StatementTimeout time.Duration
}

// Default MigrateOptions session timeouts, applied when the corresponding
// field is left at its zero (or negative) value. See the MigrateOptions doc
// comments above.
const (
	defaultMigrateLockTimeout      = 10 * time.Second
	defaultMigrateStatementTimeout = 5 * time.Minute
)

// resolve returns o's two session timeouts with defaults applied.
func (o MigrateOptions) resolve() (lock, statement time.Duration) {
	lock = o.LockTimeout
	if lock <= 0 {
		lock = defaultMigrateLockTimeout
	}
	statement = o.StatementTimeout
	if statement <= 0 {
		statement = defaultMigrateStatementTimeout
	}
	return lock, statement
}

// LockTimeoutError reports that the migration transaction's lock_timeout
// fired while applying a specific migration — most commonly a GRANT or ALTER
// queued behind a long-running (or long-holding) statement on the same
// table. The single migration transaction is rolled back in its entirety
// (see migrateOnce's deferred Rollback), so NOTHING from this batch —
// including any earlier migration applied earlier in the same attempt — was
// committed; Version still reports the schema's pre-attempt value.
type LockTimeoutError struct {
	// Version is the migration file version that was being applied when the
	// lock timeout fired.
	Version int
	// Filename is the embedded migration file that was being applied.
	Filename string
	// Err is the underlying Postgres error (SQLSTATE 55P03).
	Err error
}

func (e *LockTimeoutError) Error() string {
	return fmt.Sprintf(
		"cloudserver/db.Migrate: migration %d (%s) timed out waiting for a lock; the migration batch was rolled back and nothing was committed: %v",
		e.Version, e.Filename, e.Err,
	)
}

func (e *LockTimeoutError) Unwrap() error { return e.Err }

// isLockTimeoutDBError reports whether err is Postgres's lock_timeout
// cancellation (SQLSTATE 55P03, lock_not_available) — the error
// lock_timeout raises when a statement gives up waiting for a lock, distinct
// from statement_timeout's query_canceled (57014).
func isLockTimeoutDBError(err error) bool {
	var pgErr interface{ SQLState() string }
	return errors.As(err, &pgErr) && pgErr.SQLState() == "55P03"
}

// wrapMigrateExecErr wraps a failure applying entry e's migration inside the
// batch transaction. Every path here shares one fate: migrateOnce's deferred
// tx.Rollback(ctx) discards the WHOLE batch, so no earlier migration applied
// in this same attempt is left committed either — a lock-timeout failure gets
// its own typed error (LockTimeoutError) so a caller can distinguish "blocked
// by a lock" from any other migration failure.
func wrapMigrateExecErr(e entry, err error) error {
	if isLockTimeoutDBError(err) {
		return &LockTimeoutError{Version: e.version, Filename: e.filename, Err: err}
	}
	return fmt.Errorf(
		"cloudserver/db.Migrate: apply migration %d (%s): the migration batch was rolled back, nothing was committed: %w",
		e.version, e.filename, err,
	)
}

// Migrate applies every embedded migration whose version exceeds the recorded
// applied version, in one transaction guarded by a transaction-scoped advisory
// lock. All DDL in Postgres is transactional, so a mid-lineage failure rolls
// the whole batch back.
//
// opts is optional (zero or one MigrateOptions); passing none applies the
// documented defaults. Only the first element is used — the variadic shape
// exists solely so every pre-existing call site (which passes none) keeps
// compiling unchanged.
//
// migration 0001 creates the two CLUSTER-GLOBAL roles (pg_authid is shared
// across databases). When many databases migrate at once — the test harness
// creates a fresh database per test and `go test` runs package binaries in
// parallel — concurrent catalog DDL on the same role tuple can raise the
// transient "tuple concurrently updated" (SQLSTATE XX000). That is exactly the
// error Postgres tells you to retry; the advisory lock narrows the window and
// the retry closes it. Each attempt is a fresh, fully-rolled-back transaction,
// so retrying is safe.
func Migrate(ctx context.Context, pool *pgxpool.Pool, opts ...MigrateOptions) error {
	var opt MigrateOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	const maxAttempts = 8
	var err error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		err = migrateOnce(ctx, pool, opt)
		if err == nil || !isTransientDDLRace(err) {
			return err
		}
		// Small jittered backoff before retrying the whole batch.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(20*(attempt+1)) * time.Millisecond):
		}
	}
	return fmt.Errorf("cloudserver/db.Migrate: gave up after %d attempts: %w", maxAttempts, err)
}

// isTransientDDLRace reports whether err is a retryable concurrent-catalog-DDL
// error from parallel role creation in 0001.
func isTransientDDLRace(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "tuple concurrently updated") ||
		strings.Contains(msg, "tuple concurrently deleted") ||
		strings.Contains(msg, "concurrently updated") ||
		strings.Contains(msg, "duplicate key value") && strings.Contains(msg, "pg_authid")
}

func migrateOnce(ctx context.Context, pool *pgxpool.Pool, opt MigrateOptions) error {
	entries, err := readEntries()
	if err != nil {
		return err
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("cloudserver/db.Migrate: acquire: %w", err)
	}
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("cloudserver/db.Migrate: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Immediately after BEGIN, bound how long every statement in this batch —
	// including the advisory lock below and each migration's own DDL — may
	// wait for a lock or run, so a GRANT/ALTER on a hot table can't queue
	// unboundedly behind an unrelated long-running (or lock-holding) session.
	// SET LOCAL is transaction-scoped: it reverts automatically at COMMIT or
	// ROLLBACK and never leaks onto the pooled connection's next transaction.
	//
	// lock_timeout deliberately also bounds the pg_advisory_xact_lock wait
	// just below — the same choice internal/orgserver/db.Options.LockTimeout
	// makes for BeginSerialized's advisory lock, for the same reason: a
	// migrator that has hung (rather than merely being slow) while holding
	// the lock should not be able to block every other replica's migrate
	// attempt forever. A caller that legitimately expects a slower peer (a
	// bigger batch, a busy cluster) raises LockTimeout via MigrateOptions.
	lockTimeout, statementTimeout := opt.resolve()
	if _, err := tx.Exec(ctx, fmt.Sprintf(`SET LOCAL lock_timeout = %d`, lockTimeout.Milliseconds())); err != nil {
		return fmt.Errorf("cloudserver/db.Migrate: set lock_timeout: %w", err)
	}
	if _, err := tx.Exec(ctx, fmt.Sprintf(`SET LOCAL statement_timeout = %d`, statementTimeout.Milliseconds())); err != nil {
		return fmt.Errorf("cloudserver/db.Migrate: set statement_timeout: %w", err)
	}

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationsAdvisoryLock); err != nil {
		return fmt.Errorf("cloudserver/db.Migrate: advisory lock: the migration batch was rolled back, nothing was committed: %w", err)
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS sbci_migrations (
		version    int PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return fmt.Errorf("cloudserver/db.Migrate: bootstrap sbci_migrations: %w", err)
	}

	var applied int
	err = tx.QueryRow(ctx, `SELECT coalesce(max(version), 0) FROM sbci_migrations`).Scan(&applied)
	if err != nil {
		return fmt.Errorf("cloudserver/db.Migrate: read applied version: %w", err)
	}

	for _, e := range entries {
		if e.version <= applied {
			continue
		}
		body, readErr := fs.ReadFile(migrations.Files, e.filename)
		if readErr != nil {
			return fmt.Errorf("cloudserver/db.Migrate: read %s: %w", e.filename, readErr)
		}
		// No arguments ⇒ pgx uses the simple query protocol, which executes the
		// file's multiple semicolon-separated statements in one round trip.
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			return wrapMigrateExecErr(e, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO sbci_migrations (version) VALUES ($1)`, e.version); err != nil {
			return wrapMigrateExecErr(e, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("cloudserver/db.Migrate: commit: %w", err)
	}
	return nil
}

// Version reports the highest applied migration version (0 on a fresh DB).
func Version(ctx context.Context, q Querier) (int, error) {
	var v int
	err := q.QueryRow(ctx, `SELECT coalesce(max(version), 0) FROM sbci_migrations`).Scan(&v)
	if err != nil {
		// A brand-new DB has no sbci_migrations table yet.
		if strings.Contains(err.Error(), "does not exist") {
			return 0, nil
		}
		return 0, fmt.Errorf("cloudserver/db.Version: %w", err)
	}
	return v, nil
}

// MaxEmbeddedVersion returns the highest version present in the embedded
// lineage — the value the pin test asserts against a hardcoded constant so a
// new migration cannot land without deliberately bumping the pin.
func MaxEmbeddedVersion() (int, error) {
	entries, err := readEntries()
	if err != nil {
		return 0, err
	}
	if len(entries) == 0 {
		return 0, errors.New("cloudserver/db: no embedded migrations")
	}
	return entries[len(entries)-1].version, nil
}

// Querier is the read surface Version accepts (a pool or a tx).
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type entry struct {
	version  int
	filename string
}

func readEntries() ([]entry, error) {
	des, err := fs.ReadDir(migrations.Files, ".")
	if err != nil {
		return nil, fmt.Errorf("cloudserver/db: read migrations dir: %w", err)
	}
	var out []entry
	for _, de := range des {
		if de.IsDir() || filepath.Ext(de.Name()) != ".sql" {
			continue
		}
		prefix := strings.SplitN(de.Name(), "_", 2)[0]
		v, err := strconv.Atoi(prefix)
		if err != nil {
			return nil, fmt.Errorf("cloudserver/db: unparseable migration %q: %w", de.Name(), err)
		}
		out = append(out, entry{version: v, filename: de.Name()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}
