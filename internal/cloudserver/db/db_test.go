package db_test

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/db"
)

// pinnedMaxVersion is the version pin (plan §6 CI-P3: "its own max-version pin
// test from 0001"). Bump it deliberately, in the same change that adds a
// migration, so a stray file cannot slip in.
const pinnedMaxVersion = 40

func TestMaxEmbeddedVersionPin(t *testing.T) {
	got, err := db.MaxEmbeddedVersion()
	if err != nil {
		t.Fatalf("MaxEmbeddedVersion: %v", err)
	}
	if got != pinnedMaxVersion {
		t.Fatalf("embedded lineage head = %d, pin = %d — bump pinnedMaxVersion in the same change that adds a migration", got, pinnedMaxVersion)
	}
}

func TestResultRetentionDoesNotUseCallerOwnedScratch(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Exercise the real execution role. A hostile temporary-table trigger
	// would inherit the SECURITY DEFINER function's current_user on TRUNCATE.
	_, err = tx.Exec(ctx, `SET LOCAL ROLE sbci_worker;
		CREATE TEMP TABLE sbci_due_results (id uuid);
		CREATE TEMP TABLE retention_probe (who text);
		GRANT ALL ON pg_temp.sbci_due_results, pg_temp.retention_probe TO sbci_defs;
		CREATE FUNCTION pg_temp.retention_probe_trigger() RETURNS trigger
		LANGUAGE plpgsql AS $fn$
		BEGIN
			INSERT INTO pg_temp.retention_probe VALUES (current_user);
			RETURN NULL;
		END $fn$;
		CREATE TRIGGER retention_probe_trigger AFTER TRUNCATE ON pg_temp.sbci_due_results
		FOR EACH STATEMENT EXECUTE FUNCTION pg_temp.retention_probe_trigger();`)
	if err != nil {
		t.Fatalf("hostile scratch fixture: %v", err)
	}
	var deleted int64
	if err := tx.QueryRow(ctx, `SELECT public.sbci_sweep_results_retention(now())`).Scan(&deleted); err != nil {
		t.Fatalf("retention with hostile scratch: %v", err)
	}
	var calls int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM pg_temp.retention_probe`).Scan(&calls); err != nil || calls != 0 {
		t.Fatalf("privileged function invoked caller trigger: calls=%d, err=%v", calls, err)
	}
}

func TestMigrateUpFromZero(t *testing.T) {
	pool := cloudtestpg.NewDB(t) // creates a fresh DB and migrates it to head
	ctx := context.Background()

	v, err := db.Version(ctx, pool)
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if v != pinnedMaxVersion {
		t.Fatalf("after migrate, Version = %d, want %d", v, pinnedMaxVersion)
	}

	// Re-running Migrate is idempotent (no pending versions ⇒ no-op).
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("re-Migrate: %v", err)
	}
	v2, err := db.Version(ctx, pool)
	if err != nil {
		t.Fatalf("Version after re-migrate: %v", err)
	}
	if v2 != pinnedMaxVersion {
		t.Fatalf("Version drifted after re-migrate: %d != %d", v2, pinnedMaxVersion)
	}

	// Spot-check that the schema, roles, and the lease function actually exist.
	for _, tbl := range []string{
		"accounts", "device_registrations", "analysis_jobs",
		"evidence_objects", "usage_cycles", "pop_replay",
	} {
		var exists bool
		if err := pool.QueryRow(ctx,
			`SELECT to_regclass($1) IS NOT NULL`, "public."+tbl).Scan(&exists); err != nil {
			t.Fatalf("check table %s: %v", tbl, err)
		}
		if !exists {
			t.Errorf("expected table %s to exist", tbl)
		}
	}
	var fnExists bool
	if err := pool.QueryRow(ctx,
		`SELECT count(*) > 0 FROM pg_proc WHERE proname = 'sbci_lease_next_job'`).Scan(&fnExists); err != nil {
		t.Fatalf("check lease fn: %v", err)
	}
	if !fnExists {
		t.Error("expected sbci_lease_next_job to exist")
	}
}

// TestAuthTransactionsDoNotBlockAccountDeletion pins migration 0011 (W1 review
// F13): a live step-up auth transaction must not make an account undeletable.
//
// Before 0011 the account_id foreign key carried the default NO ACTION, so a
// 10-minute-lived pre-auth row could fail an account purge with a foreign-key
// violation — on exactly the flow (start a deletion step-up, then be purged)
// where the row is most likely to exist. These rows are not account data (the
// 0009 header classifies them out of export and the deletion matrix), so they
// cascade away with the account.
func TestAuthTransactionsDoNotBlockAccountDeletion(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()

	var accountID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO accounts DEFAULT VALUES RETURNING account_id::text`).Scan(&accountID); err != nil {
		t.Fatalf("create account: %v", err)
	}
	var txnID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO auth_transactions
		   (state_hash, pkce_verifier_enc, nonce_hash, redirect_uri, purpose,
		    action, session_id, account_id, expires_at)
		 VALUES ('state-hash-f13', '\x00'::bytea, 'nonce-hash-f13',
		         'https://app.example/portal/auth/workos/callback', 'step_up',
		         'deletion', gen_random_uuid(), $1::uuid, now() + interval '10 minutes')
		 RETURNING txn_id::text`, accountID).Scan(&txnID); err != nil {
		t.Fatalf("create step-up auth transaction: %v", err)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM accounts WHERE account_id = $1::uuid`, accountID); err != nil {
		t.Fatalf("deleting an account with a live step-up transaction failed: %v", err)
	}

	var remaining int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM auth_transactions WHERE txn_id = $1::uuid`, txnID).Scan(&remaining); err != nil {
		t.Fatalf("count transactions after delete: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("the auth transaction survived its account (%d rows) — the cascade did not fire", remaining)
	}
}

// TestSweepRetentionPurgesStrayLeaderboardContribution pins migration 0027's
// Sol F5(b) backstop: a stray leaderboard_contributions row belonging to an
// account that is due for the 24-month purge must not block the whole sweep.
//
// Before 0027 added leaderboard_contributions to the 24-month CTE, this row's
// NO-ACTION FK to accounts made `DELETE FROM accounts` inside
// sbci_sweep_retention throw leaderboard_contributions_account_id_fkey
// (23503), rolling back the ENTIRE sweep — silently blocking every other due
// account too, not just this one. The row here is inserted directly (trigger
// bypassed via session_replication_role = replica, mirroring
// store/community_test.go's rawSeedContribution) to model a row that predates
// the write-time account-status guard, or that arrived via any other
// direct-SQL path.
func TestSweepRetentionPurgesStrayLeaderboardContribution(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()

	var accountID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO accounts (status, deleted_at, purge_after)
		 VALUES ('deleted', now() - interval '25 months', now() - interval '1 minute')
		 RETURNING account_id::text`).Scan(&accountID); err != nil {
		t.Fatalf("create due-for-purge account: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin seed: %v", err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatalf("bypass freeze trigger: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO leaderboard_contributions (account_id, cohort_key, metric_id, metric_version, window_id, value)
		 VALUES ($1::uuid, 'global', 'sessions_per_active_day', 1, '2025-01', 3.0)`, accountID); err != nil {
		t.Fatalf("seed stray contribution: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit seed: %v", err)
	}

	var consentPurged, auditPurged, accountsPurged int
	if err := pool.QueryRow(ctx, `SELECT * FROM sbci_sweep_retention(now())`).
		Scan(&consentPurged, &auditPurged, &accountsPurged); err != nil {
		t.Fatalf("sbci_sweep_retention with a stray leaderboard_contributions row: %v (F5(b) regression — the sweep must not roll back on this FK)", err)
	}
	if accountsPurged != 1 {
		t.Fatalf("accounts_purged=%d, want 1 — the sweep did not purge the due account", accountsPurged)
	}

	var accountsRemaining, contributionsRemaining int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM accounts WHERE account_id = $1::uuid`, accountID).Scan(&accountsRemaining); err != nil {
		t.Fatalf("count accounts after sweep: %v", err)
	}
	if accountsRemaining != 0 {
		t.Fatalf("account %s survived the sweep", accountID)
	}
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM leaderboard_contributions WHERE account_id = $1::uuid`, accountID).Scan(&contributionsRemaining); err != nil {
		t.Fatalf("count leaderboard_contributions after sweep: %v", err)
	}
	if contributionsRemaining != 0 {
		t.Fatalf("stray contribution for %s survived the sweep (%d rows)", accountID, contributionsRemaining)
	}
}

// TestSweepRetentionIgnoresTempTableShadow pins migration 0027's Sol F1 fix:
// sbci_sweep_retention is SECURITY DEFINER and executable by sbci_api, which
// holds default TEMP privilege. Before 0027 the function body used unqualified
// relation names under `SET search_path = public`; pg_temp is implicitly
// searched BEFORE public, so a caller's own `CREATE TEMP TABLE accounts (...)`
// on the SAME session would shadow the real table for the whole function
// body — a caller-controlled `due` CTE that could drive cross-tenant deletion.
//
// This test creates a pg_temp.accounts shadow (via a single pinned connection,
// since temp tables are session-scoped) seeded with a fabricated row that
// looks purge-due but does not correspond to any real account, then calls the
// sweep on that SAME connection and asserts: (a) no error, (b) accounts_purged
// reflects only the REAL due accounts (the shadow row contributes nothing),
// and (c) the real accounts table is untouched apart from genuinely due rows.
func TestSweepRetentionIgnoresTempTableShadow(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()

	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire pinned connection: %v", err)
	}
	defer conn.Release()

	// A real account that is NOT due (still active) — must survive untouched.
	var realAccountID string
	if err := conn.QueryRow(ctx,
		`INSERT INTO accounts (status) VALUES ('active') RETURNING account_id::text`).
		Scan(&realAccountID); err != nil {
		t.Fatalf("create real active account: %v", err)
	}

	// Shadow the real table on THIS connection's session. If the sweep function
	// resolved `accounts` through search_path instead of a schema-qualified
	// name, it would read this fabricated row instead of (or in addition to)
	// the real table.
	if _, err := conn.Exec(ctx,
		`CREATE TEMP TABLE accounts (
		    account_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
		    status text NOT NULL,
		    deleted_at timestamptz,
		    purge_after timestamptz
		 ) ON COMMIT PRESERVE ROWS`); err != nil {
		t.Fatalf("create pg_temp.accounts shadow: %v", err)
	}
	var shadowAccountID string
	if err := conn.QueryRow(ctx,
		`INSERT INTO pg_temp.accounts (status, deleted_at, purge_after)
		 VALUES ('deleted', now() - interval '25 months', now() - interval '1 minute')
		 RETURNING account_id::text`).Scan(&shadowAccountID); err != nil {
		t.Fatalf("seed shadow row: %v", err)
	}

	var consentPurged, auditPurged, accountsPurged int
	if err := conn.QueryRow(ctx, `SELECT * FROM sbci_sweep_retention(now())`).
		Scan(&consentPurged, &auditPurged, &accountsPurged); err != nil {
		t.Fatalf("sbci_sweep_retention on a session with a pg_temp.accounts shadow: %v", err)
	}
	if accountsPurged != 0 {
		t.Fatalf("accounts_purged=%d, want 0 — the sweep purged the shadow row or something it should not have (F1 regression: unqualified relation resolved via search_path)", accountsPurged)
	}

	// The real, still-active account must be completely untouched — proves the
	// function operated against public.accounts, not the shadow, for real.
	var status string
	if err := conn.QueryRow(ctx,
		`SELECT status FROM public.accounts WHERE account_id = $1::uuid`, realAccountID).Scan(&status); err != nil {
		t.Fatalf("real account vanished or errored after sweep: %v", err)
	}
	if status != "active" {
		t.Fatalf("real account status=%q after sweep, want active", status)
	}

	// The shadow row itself is untouched (this connection's own temp table was
	// never a DELETE target of the real function).
	var shadowRemaining int
	if err := conn.QueryRow(ctx,
		`SELECT count(*) FROM pg_temp.accounts WHERE account_id = $1::uuid`, shadowAccountID).Scan(&shadowRemaining); err != nil {
		t.Fatalf("count shadow rows: %v", err)
	}
	if shadowRemaining != 1 {
		t.Fatalf("shadow row count=%d, want 1 (untouched)", shadowRemaining)
	}
}
