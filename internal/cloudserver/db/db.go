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
	"github.com/marmutapp/superbased-observer/internal/migcheck"
	"github.com/marmutapp/superbased-observer/internal/migplan"
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
// (see applyStep's deferred Rollback), so nothing from the blocked step was
// committed; steps below it stay applied and a rerun resumes at it.
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
		"cloudserver/db.Migrate: migration %d (%s) timed out waiting for a lock; the step was rolled back; steps below it stay applied and a rerun resumes here: %v",
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
// step transaction. Every path here shares one fate: applyStep's deferred
// tx.Rollback(ctx) discards that step while steps below it stay committed — a lock-timeout failure gets
// its own typed error (LockTimeoutError) so a caller can distinguish "blocked
// by a lock" from any other migration failure.
func wrapMigrateExecErr(e entry, err error) error {
	if isLockTimeoutDBError(err) {
		return &LockTimeoutError{Version: e.version, Filename: e.filename, Err: err}
	}
	return fmt.Errorf(
		"cloudserver/db.Migrate: apply migration %d (%s): the step was rolled back; steps below it stay applied and a rerun resumes here: %w",
		e.version, e.filename, err,
	)
}

// Migrate applies every embedded migration that has no row in the
// sbci_migrations ledger, in version order, including one numbered below the
// highest recorded version (a step that landed late from a parallel line).
// Each step runs in its own transaction, guarded by a transaction-scoped
// advisory lock, and commits with its ledger row before the next; a failure
// at step N leaves every earlier step applied and a rerun resumes at N.
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
// the retry closes it. Each failed attempt rolled back only its own step, and
// a retry resumes at the first unrecorded step, so retrying is safe.
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
	return migrateEntries(ctx, pool, opt, migrations.Files, entries)
}

// migrateEntries applies every entry of the lineage held in source that has
// no ledger row, in version order. It is the seam the resume-at-failed-step
// and late-step tests drive with a staged lineage.
//
// Which entries are pending is decided by internal/migplan (planPending), the
// planner every runner in the tree shares: an entry runs when sbci_migrations
// has no row for it, whatever the highest recorded version is (T-977/T-979
// semantics). Each step runs in its OWN transaction and commits with its
// ledger row before the next begins (plan 07 row E1.2), so a failure at step N
// leaves every earlier step applied and recorded, and a rerun resumes at N.
// Every step transaction re-takes the advisory lock and re-checks the step's
// own row, so two migrators racing never apply a step twice. The ledger row
// carries the step's migcheck label (expand, contract or data) next to its
// version. A step declared non-transactional is refused: the cloud lineage has
// no such step and this runner has no non-transactional path yet.
func migrateEntries(ctx context.Context, pool *pgxpool.Pool, opt MigrateOptions, source fs.FS, entries []entry) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("cloudserver/db.Migrate: acquire: %w", err)
	}
	defer conn.Release()

	lockTimeout, statementTimeout := opt.resolve()

	// begin opens one step transaction. Immediately after BEGIN it bounds how
	// long every statement in the step, including the advisory lock below and
	// the step's own DDL, may wait for a lock or run, so a GRANT/ALTER on a hot
	// table can't queue unboundedly behind an unrelated long-running session.
	// SET LOCAL reverts at COMMIT or ROLLBACK and never leaks onto the pooled
	// connection. lock_timeout also bounds the advisory-lock wait, the same
	// choice internal/orgserver/db.Options.LockTimeout makes: a migrator that
	// hung while holding the lock cannot block every other replica forever.
	begin := func() (pgx.Tx, error) {
		tx, err := conn.Begin(ctx)
		if err != nil {
			return nil, fmt.Errorf("cloudserver/db.Migrate: begin: %w", err)
		}
		if _, err := tx.Exec(ctx, fmt.Sprintf(`SET LOCAL lock_timeout = %d`, lockTimeout.Milliseconds())); err != nil {
			_ = tx.Rollback(ctx)
			return nil, fmt.Errorf("cloudserver/db.Migrate: set lock_timeout: %w", err)
		}
		if _, err := tx.Exec(ctx, fmt.Sprintf(`SET LOCAL statement_timeout = %d`, statementTimeout.Milliseconds())); err != nil {
			_ = tx.Rollback(ctx)
			return nil, fmt.Errorf("cloudserver/db.Migrate: set statement_timeout: %w", err)
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationsAdvisoryLock); err != nil {
			_ = tx.Rollback(ctx)
			return nil, fmt.Errorf("cloudserver/db.Migrate: advisory lock: %w", err)
		}
		return tx, nil
	}

	// Bootstrap the ledger in its own transaction. The label column is
	// additive and nullable: a database already at schema 44 or later gains it
	// here, and its existing rows keep a NULL label (they predate migcheck).
	tx, err := begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS sbci_migrations (
		version    int PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("cloudserver/db.Migrate: bootstrap sbci_migrations: %w", err)
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE sbci_migrations ADD COLUMN IF NOT EXISTS label text`); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("cloudserver/db.Migrate: add sbci_migrations.label: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("cloudserver/db.Migrate: commit bootstrap: %w", err)
	}

	recorded, err := recordedVersions(ctx, conn)
	if err != nil {
		return err
	}
	pending, err := planPending(entries, recorded)
	if err != nil {
		return err
	}
	for _, e := range pending {
		if err := applyStep(ctx, begin, source, e); err != nil {
			return err
		}
	}
	return nil
}

// recordedVersions reads every version the sbci_migrations ledger holds.
func recordedVersions(ctx context.Context, q interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
},
) (map[int]bool, error) {
	rows, err := q.Query(ctx, `SELECT version FROM sbci_migrations`)
	if err != nil {
		return nil, fmt.Errorf("cloudserver/db.Migrate: read ledger: %w", err)
	}
	versions, err := pgx.CollectRows(rows, pgx.RowTo[int])
	if err != nil {
		return nil, fmt.Errorf("cloudserver/db.Migrate: read ledger: %w", err)
	}
	out := make(map[int]bool, len(versions))
	for _, v := range versions {
		out[v] = true
	}
	return out, nil
}

// planPending returns the entries that still need to run, ascending, decided
// by migplan.Decide. It is the cloud runner's seam onto the shared planner:
// sbci_migrations has held one row per applied step since its first version,
// so every row maps to a migplan per-step record of RecordApplied, and the
// ledger is treated as initialised with a horizon of 0 (no step was ever
// handled without a row, so nothing is adopted and there is no late-step
// probe table). The cloud ledger has no adopted state and no separate version
// record, so a plan that asks to adopt a step, forget a record or move the
// horizon is refused rather than silently dropped.
func planPending(entries []entry, recorded map[int]bool) ([]entry, error) {
	ledger := migplan.Ledger{HasHorizon: true, Steps: make(map[int]string, len(recorded))}
	for v := range recorded {
		if v <= 0 {
			continue
		}
		ledger.Steps[v] = migplan.RecordApplied
		ledger.Version = max(ledger.Version, v)
	}
	embedded := make([]int, len(entries))
	byVersion := make(map[int]entry, len(entries))
	for i, e := range entries {
		embedded[i] = e.version
		byVersion[e.version] = e
	}
	plan, err := migplan.Decide(migplan.Input{Embedded: embedded, Ledger: ledger})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/db.Migrate: plan: %w", err)
	}
	if len(plan.Forget) > 0 || plan.WriteHorizon {
		return nil, fmt.Errorf("cloudserver/db.Migrate: plan asks to forget records %v or move the horizon to %d; the sbci_migrations ledger holds neither", plan.Forget, plan.Horizon)
	}
	out := make([]entry, 0, len(plan.Steps))
	for _, s := range plan.Steps {
		if s.Action != migplan.ActionRun {
			return nil, fmt.Errorf("cloudserver/db.Migrate: plan asks to %s step %d (%s); the sbci_migrations ledger records applied steps only", s.Action, s.Version, s.Rule)
		}
		out = append(out, byVersion[s.Version])
	}
	return out, nil
}

// applyStep applies one entry in its own transaction when it is still pending
// and records its version and label.
func applyStep(ctx context.Context, begin func() (pgx.Tx, error), source fs.FS, e entry) error {
	tx, err := begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Under the advisory lock: another migrator may have applied this step
	// since the plan was read.
	var done bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sbci_migrations WHERE version = $1)`, e.version).Scan(&done); err != nil {
		return fmt.Errorf("cloudserver/db.Migrate: read ledger row %d: %w", e.version, err)
	}
	if done {
		return nil
	}
	body, err := fs.ReadFile(source, e.filename)
	if err != nil {
		return fmt.Errorf("cloudserver/db.Migrate: read %s: %w", e.filename, err)
	}
	dir, err := migcheck.ReadDirectives(string(body))
	if err != nil {
		return fmt.Errorf("cloudserver/db.Migrate: read directives of %s: %w", e.filename, err)
	}
	if dir.NonTransactional {
		return fmt.Errorf("cloudserver/db.Migrate: migration %d (%s) is declared non-transactional; this runner applies every step in a transaction and has no non-transactional path, so it was refused (steps below %d stay applied)", e.version, e.filename, e.version)
	}
	// No arguments => pgx uses the simple query protocol, which executes the
	// file's multiple semicolon-separated statements in one round trip.
	if _, err := tx.Exec(ctx, string(body)); err != nil {
		return wrapMigrateExecErr(e, err)
	}
	var label *string
	if dir.Label != "" {
		label = &dir.Label
	}
	if _, err := tx.Exec(ctx, `INSERT INTO sbci_migrations (version, label) VALUES ($1, $2)`, e.version, label); err != nil {
		return wrapMigrateExecErr(e, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("cloudserver/db.Migrate: commit migration %d (%s): %w", e.version, e.filename, err)
	}
	return nil
}

// StepLabel reports the migcheck label recorded for an applied step, and
// whether the step is recorded at all. A step applied before the label column
// existed has an empty label.
func StepLabel(ctx context.Context, q Querier, version int) (label string, applied bool, err error) {
	var l *string
	err = q.QueryRow(ctx, `SELECT label FROM sbci_migrations WHERE version = $1`, version).Scan(&l)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("cloudserver/db.StepLabel: %w", err)
	}
	if l != nil {
		label = *l
	}
	return label, true, nil
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

func readEntries() ([]entry, error) { return readEntriesFrom(migrations.Files) }

func readEntriesFrom(source fs.FS) ([]entry, error) {
	des, err := fs.ReadDir(source, ".")
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
