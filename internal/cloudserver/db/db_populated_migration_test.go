package db

// db_populated_migration_test.go is the Sol re-review N6 populated-table
// migration proof: it migrates a fresh database to version 26, inserts a
// populated community_grants row + a current-window leaderboard_contributions
// row, then migrates 26 → head and proves the device-scope migrations (0028 PK
// widen, 0029 device column) are safe on a NON-EMPTY table and that a legacy
// device_id='' current-window row is CLAIMABLE by the first authenticated device.
//
// It is an INTERNAL (package db) test so it can drive the embedded lineage
// directly (readEntries / migrations.Files / the advisory-lock + retry it shares
// with Migrate); the store package's cloudtestpg helper migrates only to head and
// importing it here would form an import cycle. It creates its OWN throwaway
// database from SBCI_TEST_PG_DSN and drops it on cleanup.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io/fs"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/db/migrations"
)

// migratePrefix applies every embedded migration up to and including target, in
// one transaction, with the same advisory lock + transient-DDL retry Migrate
// uses (0001's cluster-global role DDL can raise a transient XX000 under
// concurrency). It is the "migrate to an intermediate version" facility the
// public Migrate does not expose.
func migratePrefix(ctx context.Context, pool *pgxpool.Pool, target int) error {
	const maxAttempts = 8
	var err error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		err = migratePrefixOnce(ctx, pool, target)
		if err == nil || !isTransientDDLRace(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(20*(attempt+1)) * time.Millisecond):
		}
	}
	return err
}

func migratePrefixOnce(ctx context.Context, pool *pgxpool.Pool, target int) error {
	entries, err := readEntries()
	if err != nil {
		return err
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationsAdvisoryLock); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS sbci_migrations (
		version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	var applied int
	if err := tx.QueryRow(ctx, `SELECT coalesce(max(version), 0) FROM sbci_migrations`).Scan(&applied); err != nil {
		return err
	}
	for _, e := range entries {
		if e.version <= applied || e.version > target {
			continue
		}
		body, readErr := fs.ReadFile(migrations.Files, e.filename)
		if readErr != nil {
			return readErr
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO sbci_migrations (version) VALUES ($1)`, e.version); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func TestPopulatedMigration26ToHead(t *testing.T) {
	dsn := os.Getenv("SBCI_TEST_PG_DSN")
	if dsn == "" {
		t.Skipf("SKIP (no Postgres): set SBCI_TEST_PG_DSN to run this suite. This test did NOT run.")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Fresh throwaway database.
	rb := make([]byte, 8)
	_, _ = rand.Read(rb)
	dbName := "sbci_popmig_" + hex.EncodeToString(rb)
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	if _, err := admin.Exec(ctx, `CREATE DATABASE "`+dbName+`" TEMPLATE template0`); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create database: %v", err)
	}
	_ = admin.Close(ctx)
	t.Cleanup(func() {
		a, err := pgx.Connect(context.Background(), dsn)
		if err != nil {
			return
		}
		defer func() { _ = a.Close(context.Background()) }()
		_, _ = a.Exec(context.Background(), `DROP DATABASE IF EXISTS "`+dbName+`" WITH (FORCE)`)
	})

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse DSN: %v", err)
	}
	cfg.ConnConfig.Database = dbName
	cfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)

	// 1) Migrate to version 26 (community_grants + leaderboard_contributions
	// exist; both are still device-scope-less).
	if err := migratePrefix(ctx, pool, 26); err != nil {
		t.Fatalf("migrate to 26: %v", err)
	}
	if v, err := Version(ctx, pool); err != nil || v != 26 {
		t.Fatalf("version after prefix = %d err=%v, want 26", v, err)
	}

	// 2) Populate: one account, one community_grants row (pre-device-scope PK),
	// one leaderboard_contributions row for the CURRENT window (passes the 0025
	// freeze trigger). Superuser login ⇒ RLS bypassed.
	var acct string
	if err := pool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING account_id::text`).Scan(&acct); err != nil {
		t.Fatalf("insert account: %v", err)
	}
	const purpose = "community_cohort_benchmarking"
	if _, err := pool.Exec(ctx,
		`INSERT INTO community_grants
		   (account_id, purpose, data_dictionary_digest, schema_version, consent_generation, declared_timezone)
		 VALUES ($1::uuid, $2, 'sha256:dict', 'community_contribution.v1-candidate', 3, '')`,
		acct, purpose); err != nil {
		t.Fatalf("insert legacy community grant: %v", err)
	}
	window := time.Now().UTC().Format("2006-01")
	if _, err := pool.Exec(ctx,
		`INSERT INTO leaderboard_contributions
		   (account_id, cohort_key, metric_id, metric_version, window_id, value)
		 VALUES ($1::uuid, 'global', 'sessions_per_active_day', 1, $2, 2.0)`,
		acct, window); err != nil {
		t.Fatalf("insert legacy contribution: %v", err)
	}

	// 3) Migrate 26 → head over the populated table.
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate 26 -> head over populated tables: %v", err)
	}
	head, err := MaxEmbeddedVersion()
	if err != nil {
		t.Fatalf("MaxEmbeddedVersion: %v", err)
	}
	if v, err := Version(ctx, pool); err != nil || v != head {
		t.Fatalf("version after full migrate = %d err=%v, want head %d", v, err, head)
	}

	// PK is now (account_id, device_id, purpose).
	if got := primaryKeyColumns(t, ctx, pool, "community_grants"); !sameSet(got, []string{"account_id", "device_id", "purpose"}) {
		t.Fatalf("community_grants PK = %v, want {account_id, device_id, purpose}", got)
	}

	// Backfilled rows carry device_id=''.
	var grantDevice, contribDevice string
	if err := pool.QueryRow(ctx, `SELECT device_id FROM community_grants WHERE account_id=$1::uuid`, acct).Scan(&grantDevice); err != nil {
		t.Fatalf("read backfilled grant device: %v", err)
	}
	if grantDevice != "" {
		t.Fatalf("backfilled community_grants.device_id=%q, want '' (empty)", grantDevice)
	}
	if err := pool.QueryRow(ctx, `SELECT device_id FROM leaderboard_contributions WHERE account_id=$1::uuid`, acct).Scan(&contribDevice); err != nil {
		t.Fatalf("read backfilled contribution device: %v", err)
	}
	if contribDevice != "" {
		t.Fatalf("backfilled leaderboard_contributions.device_id=%q, want '' (empty)", contribDevice)
	}

	// 4) The legacy ''-owned current-window row is CLAIMABLE by the first
	// authenticated device (the Sol N6 product fix — this is the exact ON CONFLICT
	// guard upsertContributionTx uses: '' counts as unowned and is stamped).
	const realDevice = "cccccccc-cccc-cccc-cccc-cccccccccccc"
	var claimed string
	if err := pool.QueryRow(ctx,
		`INSERT INTO leaderboard_contributions
		     (account_id, cohort_key, metric_id, metric_version, window_id, device_id, value)
		 VALUES ($1::uuid, 'global', 'sessions_per_active_day', 1, $2, $3, 7.0)
		 ON CONFLICT (account_id, cohort_key, metric_id, metric_version, window_id)
		 DO UPDATE SET value = EXCLUDED.value, device_id = EXCLUDED.device_id, updated_at = now()
		 WHERE leaderboard_contributions.device_id IN ('', EXCLUDED.device_id)
		 RETURNING device_id`,
		acct, window, realDevice).Scan(&claimed); err != nil {
		t.Fatalf("claim legacy row: %v", err)
	}
	if claimed != realDevice {
		t.Fatalf("legacy '' row not claimed: device_id=%q, want %q", claimed, realDevice)
	}
	var val float64
	if err := pool.QueryRow(ctx,
		`SELECT value FROM leaderboard_contributions WHERE account_id=$1::uuid`, acct).Scan(&val); err != nil {
		t.Fatalf("read claimed value: %v", err)
	}
	if val != 7.0 {
		t.Fatalf("claimed row value=%v, want 7.0", val)
	}
}

func primaryKeyColumns(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table string) []string {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT a.attname
		   FROM pg_index i
		   JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
		  WHERE i.indrelid = $1::regclass AND i.indisprimary`, table)
	if err != nil {
		t.Fatalf("read pk columns: %v", err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatalf("scan pk column: %v", err)
		}
		cols = append(cols, c)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("pk rows: %v", err)
	}
	return cols
}

func sameSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	g := append([]string(nil), got...)
	w := append([]string(nil), want...)
	sort.Strings(g)
	sort.Strings(w)
	for i := range g {
		if g[i] != w[i] {
			return false
		}
	}
	return true
}
