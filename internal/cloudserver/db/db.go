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

// Migrate applies every embedded migration whose version exceeds the recorded
// applied version, in one transaction guarded by a transaction-scoped advisory
// lock. All DDL in Postgres is transactional, so a mid-lineage failure rolls
// the whole batch back.
//
// migration 0001 creates the two CLUSTER-GLOBAL roles (pg_authid is shared
// across databases). When many databases migrate at once — the test harness
// creates a fresh database per test and `go test` runs package binaries in
// parallel — concurrent catalog DDL on the same role tuple can raise the
// transient "tuple concurrently updated" (SQLSTATE XX000). That is exactly the
// error Postgres tells you to retry; the advisory lock narrows the window and
// the retry closes it. Each attempt is a fresh, fully-rolled-back transaction,
// so retrying is safe.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	const maxAttempts = 8
	var err error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		err = migrateOnce(ctx, pool)
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

func migrateOnce(ctx context.Context, pool *pgxpool.Pool) error {
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

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationsAdvisoryLock); err != nil {
		return fmt.Errorf("cloudserver/db.Migrate: advisory lock: %w", err)
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
			return fmt.Errorf("cloudserver/db.Migrate: exec %s: %w", e.filename, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO sbci_migrations (version) VALUES ($1)`, e.version); err != nil {
			return fmt.Errorf("cloudserver/db.Migrate: record version %d: %w", e.version, err)
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
