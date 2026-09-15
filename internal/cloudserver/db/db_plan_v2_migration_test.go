package db

// db_plan_v2_migration_test.go proves migration 0039's subscriber move on a
// POPULATED database: an account sitting on the plus_beta v1 plan when the
// migration runs must come out on v2 (120/month + the Sol route pin) without
// anybody touching it, and an account carrying a SCHEDULED future assignment
// (a cancellation's cycle-boundary downgrade) must survive the move without
// tripping account_plans_no_overlap.
//
// It is an INTERNAL (package db) test for the same reason
// db_populated_migration_test.go is: only this package can drive the embedded
// lineage to an intermediate version (migratePrefix). It creates its OWN
// throwaway database from SBCI_TEST_PG_DSN and drops it on cleanup.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func newThrowawayDB(t *testing.T, prefix string) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("SBCI_TEST_PG_DSN")
	if dsn == "" {
		t.Skipf("SKIP (no Postgres): set SBCI_TEST_PG_DSN to run this suite. This test did NOT run.")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	rb := make([]byte, 8)
	_, _ = rand.Read(rb)
	dbName := prefix + hex.EncodeToString(rb)
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
	return pool
}

func TestPopulatedMigration38To39MovesPlusSubscribersToV2(t *testing.T) {
	pool := newThrowawayDB(t, "sbci_planv2_")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// 1) Migrate to 38 - plans v1 only, no route_id column.
	if err := migratePrefix(ctx, pool, 38); err != nil {
		t.Fatalf("migrate to 38: %v", err)
	}

	var plusV1 string
	if err := pool.QueryRow(ctx, `SELECT plan_id::text FROM plans WHERE name='plus_beta' AND version=1`).Scan(&plusV1); err != nil {
		t.Fatalf("read plus v1 plan_id: %v", err)
	}
	var freeV1 string
	if err := pool.QueryRow(ctx, `SELECT plan_id::text FROM plans WHERE name='free' AND version=1`).Scan(&freeV1); err != nil {
		t.Fatalf("read free v1 plan_id: %v", err)
	}

	// 2) Two paying subscribers on plus v1. Superuser login ⇒ RLS bypassed.
	//    - plain: one open assignment.
	//    - scheduled: an assignment that already ENDS at a future boundary,
	//      with the free downgrade scheduled there (the graceful-cancel shape).
	var plain, scheduled string
	for _, dst := range []*string{&plain, &scheduled} {
		if err := pool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING account_id::text`).Scan(dst); err != nil {
			t.Fatalf("insert account: %v", err)
		}
	}
	started := time.Now().UTC().Add(-48 * time.Hour)
	boundary := time.Now().UTC().Add(240 * time.Hour)
	if _, err := pool.Exec(ctx,
		`INSERT INTO account_plans (account_id, plan_id, effective_from, source)
		 VALUES ($1::uuid, $2::uuid, $3, 'paddle')`, plain, plusV1, started); err != nil {
		t.Fatalf("insert plain subscriber assignment: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO account_plans (account_id, plan_id, effective_from, effective_until, source)
		 VALUES ($1::uuid, $2::uuid, $3, $4, 'paddle')`, scheduled, plusV1, started, boundary); err != nil {
		t.Fatalf("insert scheduled subscriber assignment: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO account_plans (account_id, plan_id, effective_from, source)
		 VALUES ($1::uuid, $2::uuid, $3, 'paddle')`, scheduled, freeV1, boundary); err != nil {
		t.Fatalf("insert scheduled downgrade: %v", err)
	}

	// 3) Migrate 38 → head over the populated table.
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate 38 -> head over populated account_plans: %v", err)
	}

	// The v2 rows exist with the ruled caps and the route pin.
	var dailyCap, monthlyCap, concCap, retention int
	var routeID *string
	var digest bool
	if err := pool.QueryRow(ctx,
		`SELECT daily_cap, monthly_cap, concurrency_cap, results_retention_days, digest_weekly, route_id
		   FROM plans WHERE name='plus_beta' AND version=2`).
		Scan(&dailyCap, &monthlyCap, &concCap, &retention, &digest, &routeID); err != nil {
		t.Fatalf("read plus v2: %v", err)
	}
	if dailyCap != 25 || monthlyCap != 120 || concCap != 4 {
		t.Fatalf("plus v2 caps = %d/%d/%d, want 25/120/4", dailyCap, monthlyCap, concCap)
	}
	if routeID == nil || *routeID != "session_enrichment.sol.v1" {
		t.Fatalf("plus v2 route_id = %v, want session_enrichment.sol.v1", routeID)
	}
	if !digest || retention != 365 {
		t.Fatalf("plus v2 carried digest_weekly=%v retention=%d, want true/365 copied from v1", digest, retention)
	}
	var freeDaily, freeMonthly int
	var freeRoute *string
	if err := pool.QueryRow(ctx,
		`SELECT daily_cap, monthly_cap, route_id FROM plans WHERE name='free' AND version=2`).
		Scan(&freeDaily, &freeMonthly, &freeRoute); err != nil {
		t.Fatalf("read free v2: %v", err)
	}
	if freeDaily != 20 || freeMonthly != 100 || freeRoute != nil {
		t.Fatalf("free v2 = %d/%d route %v, want 20/100/NULL", freeDaily, freeMonthly, freeRoute)
	}

	// The Sol route ships INACTIVE, unbound, plan-pinned, with its kill switch.
	var active, pinned bool
	var endpoint, apiVersion, deployment string
	var maxOut int
	if err := pool.QueryRow(ctx,
		`SELECT active, plan_pinned, endpoint, api_version, deployment, max_output_tokens
		   FROM route_registry WHERE route_id='session_enrichment.sol.v1'`).
		Scan(&active, &pinned, &endpoint, &apiVersion, &deployment, &maxOut); err != nil {
		t.Fatalf("read sol route: %v", err)
	}
	if active || !pinned || endpoint != "" || apiVersion != "" {
		t.Fatalf("sol route = active:%v pinned:%v endpoint:%q api:%q, want inactive/pinned/unbound",
			active, pinned, endpoint, apiVersion)
	}
	if deployment != "gpt-5.6-sol" || maxOut != 4096 {
		t.Fatalf("sol route deployment=%q max_output=%d, want gpt-5.6-sol/4096", deployment, maxOut)
	}
	var switches int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM kill_switches WHERE scope='route' AND key='session_enrichment.sol.v1' AND active=false`).
		Scan(&switches); err != nil || switches != 1 {
		t.Fatalf("sol kill switch rows = %d err=%v, want exactly 1 (inactive)", switches, err)
	}

	// 4) Both subscribers are now IN FORCE on plus v2.
	for name, acct := range map[string]string{"plain": plain, "scheduled": scheduled} {
		var gotName string
		var gotVersion int
		if err := pool.QueryRow(ctx,
			`SELECT p.name, p.version FROM account_plans ap JOIN plans p ON p.plan_id = ap.plan_id
			  WHERE ap.account_id = $1::uuid AND ap.effective_from <= now()
			    AND (ap.effective_until IS NULL OR ap.effective_until > now())
			  ORDER BY ap.effective_from DESC LIMIT 1`, acct).Scan(&gotName, &gotVersion); err != nil {
			t.Fatalf("%s: resolve in-force plan: %v", name, err)
		}
		if gotName != "plus_beta" || gotVersion != 2 {
			t.Fatalf("%s subscriber is on %s v%d, want plus_beta v2", name, gotName, gotVersion)
		}
	}

	// 5) The scheduled account's new row ENDS where the old one was going to end,
	//    so the pending downgrade is still there and nothing overlaps.
	var until *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT ap.effective_until FROM account_plans ap JOIN plans p ON p.plan_id = ap.plan_id
		  WHERE ap.account_id = $1::uuid AND p.name='plus_beta' AND p.version=2`, scheduled).Scan(&until); err != nil {
		t.Fatalf("read migrated scheduled row: %v", err)
	}
	if until == nil || !until.UTC().Round(time.Millisecond).Equal(boundary.Round(time.Millisecond)) {
		t.Fatalf("migrated scheduled row ends at %v, want the preserved boundary %v", until, boundary)
	}
	var downgrades int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM account_plans ap JOIN plans p ON p.plan_id = ap.plan_id
		  WHERE ap.account_id = $1::uuid AND p.name='free'`, scheduled).Scan(&downgrades); err != nil || downgrades != 1 {
		t.Fatalf("scheduled downgrade rows = %d err=%v, want 1 (untouched)", downgrades, err)
	}
}
