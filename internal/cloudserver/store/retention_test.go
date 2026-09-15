package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// retention_test.go holds the W6d retention-TTL invariants: the two-clock sweep
// ages out the rows a completed deletion RETAINED — consent-proof + billing at
// 12 months, audit + the pseudonymized account row at 24 months, children before
// the account row (FK-safe). Ground truth for the counts + FK order was
// established by calling the sweep against live PG before these were written.

// seedTombstonedAccount deletes an account after populating its retained tables
// (consent receipt+events, a structural grant, an audit event), leaving the
// tombstone plus the retained rows.
func seedTombstonedAccount(t *testing.T, s *store.Store, pool *pgxpool.Pool, subject string, now time.Time) string {
	t.Helper()
	ctx := context.Background()
	acct := makeAccount(t, s)
	if _, _, err := s.RecordPreviewConfirmation(ctx, acct, store.PreviewConfirmationInput{
		Purposes: []string{"bounded_context_enrichment"}, FieldClasses: []string{"content_excerpts"},
		EvidenceSchema: "session-evidence.v1-candidate", ScrubberVersion: "v1", UploadDigest: "sha256:" + subject, Now: now,
	}); err != nil {
		t.Fatalf("consent: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO structural_grants (account_id, purpose, data_dictionary_digest, schema_version, consent_generation)
		 VALUES ($1::uuid, 'structural_activity_insights', 'sha256:dd', 'structural_insights.v1-candidate', 1)`, acct); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO security_audit_events (account_id, event_type) VALUES ($1::uuid, 'test_event')`, acct); err != nil {
		t.Fatalf("audit: %v", err)
	}
	if _, err := s.CreateDeletionRequest(ctx, acct, now); err != nil {
		t.Fatalf("delete: %v", err)
	}
	return acct
}

// assertCount fails unless the account has exactly want rows in table.
func assertCount(t *testing.T, pool *pgxpool.Pool, table, acct string, want int) {
	t.Helper()
	var n int
	// #nosec — table is a fixed literal from the test, never user input.
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM `+table+` WHERE account_id=$1::uuid`, acct).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	if n != want {
		t.Errorf("%s for account: got %d rows, want %d", table, n, want)
	}
}

// TestRetentionTwelveMonthClockPurgesConsentOnly proves the 12-month clock: an
// account tombstoned 13 months ago has its consent-proof rows purged while its
// audit rows and the account row itself (24-month clock, not yet due) survive.
func TestRetentionTwelveMonthClockPurgesConsentOnly(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := seedTombstonedAccount(t, s, pool, "ret-12mo", now)

	// Backdate ONLY deleted_at to 13 months ago; purge_after stays at
	// deleted_at+24mo (i.e. 11 months in the FUTURE) as the deletion set it.
	if _, err := pool.Exec(ctx,
		`UPDATE accounts SET deleted_at = $2::timestamptz, purge_after = $2::timestamptz + interval '24 months' WHERE account_id=$1::uuid`,
		acct, now.Add(-13*30*24*time.Hour)); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	r, err := s.SweepRetention(ctx, now)
	if err != nil {
		t.Fatalf("SweepRetention: %v", err)
	}
	if r.ConsentPurged == 0 {
		t.Errorf("consent rows should be purged at the 12-month clock; got %d", r.ConsentPurged)
	}
	if r.AuditPurged != 0 || r.AccountsPurged != 0 {
		t.Errorf("24-month rows purged early: audit=%d accounts=%d, want 0/0", r.AuditPurged, r.AccountsPurged)
	}
	// The account row and its audit survive; consent is gone.
	assertCount(t, pool, "accounts", acct, 1)
	assertCount(t, pool, "security_audit_events", acct, 1)
	assertCount(t, pool, "consent_receipts", acct, 0)
	assertCount(t, pool, "consent_events", acct, 0)
}

// TestRetentionTwentyFourMonthClockPurgesAccountFKSafe proves the 24-month
// clock: when purge_after is due, the audit + lifecycle rows AND the
// pseudonymized account row are purged, children before the account (no FK
// violation). A second, recently-tombstoned account is untouched.
func TestRetentionTwentyFourMonthClockPurgesAccountFKSafe(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	due := seedTombstonedAccount(t, s, pool, "ret-24mo-due", now)
	fresh := seedTombstonedAccount(t, s, pool, "ret-24mo-fresh", now)

	// The due account: both clocks elapsed.
	if _, err := pool.Exec(ctx,
		`UPDATE accounts SET deleted_at = $2, purge_after = $3 WHERE account_id=$1::uuid`,
		due, now.Add(-25*30*24*time.Hour), now.Add(-24*time.Hour)); err != nil {
		t.Fatalf("backdate due: %v", err)
	}

	r, err := s.SweepRetention(ctx, now)
	if err != nil {
		t.Fatalf("SweepRetention (FK order bug surfaces here): %v", err)
	}
	if r.AccountsPurged != 1 {
		t.Fatalf("accounts_purged=%d, want 1", r.AccountsPurged)
	}
	if r.AuditPurged == 0 {
		t.Errorf("audit/lifecycle rows should be purged at 24 months; got %d", r.AuditPurged)
	}

	// The due account is entirely gone; every retained table is empty.
	for _, tbl := range []string{"accounts", "consent_receipts", "consent_events", "security_audit_events", "deletion_requests", "structural_grants", "community_grants"} {
		assertCount(t, pool, tbl, due, 0)
	}
	// The freshly-tombstoned account is untouched.
	assertCount(t, pool, "accounts", fresh, 1)
	assertCount(t, pool, "deletion_requests", fresh, 1)
}

// TestRetentionSweepFunctionDeployedShape pins the SECURITY DEFINER retention
// primitive (owner, secdef, pinned search_path, production-role EXECUTE).
//
// The search_path assertion was hardened by migration 0027 (Sol F1): the
// pre-0027 shape (search_path=public) let a caller holding TEMP privilege
// (sbci_api does, by default) shadow an unqualified relation name inside this
// SECURITY DEFINER body via CREATE TEMP TABLE — pg_temp is implicitly
// searched before public. 0027 schema-qualifies every relation as public.*
// AND pins search_path=pg_catalog,public,pg_temp so an explicit public.*
// reference can never resolve to the caller's shadow. See
// TestSweepRetentionIgnoresTempTableShadow in internal/cloudserver/db for the
// live-shadow-attempt regression proving the qualification actually holds.
func TestRetentionSweepFunctionDeployedShape(t *testing.T) {
	_, pool := newStore(t)
	ctx := context.Background()
	var owner, cfg string
	var secdef bool
	if err := pool.QueryRow(ctx,
		`SELECT pg_get_userbyid(proowner), prosecdef, coalesce(array_to_string(proconfig,','),'')
		   FROM pg_proc WHERE proname='sbci_sweep_retention'`).Scan(&owner, &secdef, &cfg); err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if owner != "sbci_defs" || !secdef || cfg != "search_path=pg_catalog, public, pg_temp" {
		t.Errorf("sweep fn shape wrong: owner=%q secdef=%v cfg=%q", owner, secdef, cfg)
	}
	var canExec bool
	if err := pool.QueryRow(ctx,
		`SELECT has_function_privilege('sbci_api', 'sbci_sweep_retention(timestamptz)', 'EXECUTE')`).Scan(&canExec); err != nil {
		t.Fatalf("has_function_privilege: %v", err)
	}
	if !canExec {
		t.Error("sbci_api lacks EXECUTE on sbci_sweep_retention")
	}
}
