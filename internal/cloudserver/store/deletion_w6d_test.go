package store_test

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// deletion_w6d_test.go holds the W6d deletion-completion invariants (divergence
// remediation plan §3 W6d; closes E6): the matrix-maintenance guard, the
// FK-safe-order purge, the production-role grant pin, and restore-suppression.

// deletionDisposition is the W6d matrix: every base table maps to how account
// deletion treats it. TestDeletionMatrixCoversEveryTable pins that this stays
// exhaustive — a future migration that adds a table fails until it is classified
// here (and the deletion code updated to match). Dispositions:
//
//	purge        — rows deleted outright on account deletion (tenant data).
//	pseudonymize — the account row itself: kept opaque, status='deleted'.
//	retain       — kept under a legal/billing/consent/audit basis (a later
//	               retention pass ages it out; structural_grants is revoked).
//	excluded     — not account data (system/global) or pre-auth anonymous rows.
var deletionDisposition = map[string]string{
	// Account row.
	"accounts":               "pseudonymize",
	"account_result_cursors": "retain", // opaque result watermark, cascades with account tombstone
	// Purged tenant data.
	"export_artifacts":          "purge", // W6d: an assembled export is account data
	"leaderboard_contributions": "purge", // W5: opt-out/deletion removes contributions
	"paddle_subscriptions":      "purge", // W9: account subscription linkage
	"checkout_intents":          "purge", // 0030: account-scoped single-use checkout nonce (ephemeral pre-checkout state)
	"identity_links":            "purge",
	"account_profiles":          "purge", // 0033: display-only email/name for the portal top bar
	"device_registrations":      "purge",
	"api_tokens":                "purge",
	"browser_sessions":          "purge",
	"pop_replay":                "purge",
	"step_up_authorizations":    "purge",
	"entitlements":              "purge",
	"account_plans":             "purge",
	"usage_cycles":              "purge",
	"usage_reservations":        "purge",
	"cloud_projects":            "purge",
	"cloud_sessions":            "purge",
	"evidence_objects":          "purge",
	"evidence_blobs":            "purge",
	"analysis_jobs":             "purge",
	"analysis_results":          "purge",
	"result_revisions":          "purge",
	"structural_snapshots":      "purge",
	"structural_account_days":   "purge",
	"portal_consent_choices":    "purge",
	// Retained (legal/billing/consent/audit basis).
	"consent_receipts":      "retain",
	"consent_events":        "retain",
	"portal_consent_events": "retain",
	"analysis_usage_ledger": "retain",
	"security_audit_events": "retain",
	"structural_grants":     "retain", // revoked, kept as the consent-registration fact
	"community_grants":      "retain", // W5: revoked, kept as the consent-registration fact (swept at 24mo, migration 0026)
	"deletion_requests":     "retain",
	// Not account data (system/global).
	"budget_pools":                 "excluded",
	"kill_switches":                "excluded",
	"plans":                        "excluded",
	"route_registry":               "excluded",
	"dialect_verification_records": "excluded",
	"provider_attestations":        "excluded",
	"sbci_rate_limit_counters":     "excluded",
	"workos_events":                "excluded",
	"sbci_migrations":              "excluded",
	"community_metrics":            "excluded", // W5: fixed versioned metric registry, not account data
	"community_band_snapshots":     "excluded", // W5: aggregate-only delayed bands, no account linkage
	"billing_events":               "excluded", // W9: Paddle webhook idempotency/audit log (mirrors workos_events)
	// Pre-auth anonymous (expire globally; auth_transactions ON DELETE CASCADE).
	"exchange_nonces":   "excluded",
	"auth_transactions": "excluded",
}

// TestDeletionMatrixCoversEveryTable is the matrix-maintenance guard (rev-4 F5):
// every base table in the deployed schema must be classified, and every
// classification must name a real table. A migration that adds a table without
// updating deletionDisposition (and the deletion code) fails here loudly.
func TestDeletionMatrixCoversEveryTable(t *testing.T) {
	_, pool := newStore(t)
	ctx := context.Background()

	rows, err := pool.Query(ctx, `
		SELECT table_name FROM information_schema.tables
		WHERE table_schema='public' AND table_type='BASE TABLE'`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	real := map[string]bool{}
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		real[n] = true
	}
	rows.Close()

	for name := range real {
		if _, ok := deletionDisposition[name]; !ok {
			t.Errorf("table %q is NOT classified in the W6d deletion matrix — add it to deletionDisposition (purge/pseudonymize/retain/excluded) and handle it in deletionCompleteTx", name)
		}
	}
	for name := range deletionDisposition {
		if !real[name] {
			t.Errorf("deletionDisposition classifies %q which is not a real base table (stale entry)", name)
		}
	}
}

// TestSbciApiHoldsDeleteGrantsOnPurgeTargets pins that the PRODUCTION serve role
// (sbci_api) can DELETE every purge target. The functional tests run as sbci_app,
// so without this a missing sbci_api grant would pass the suite but 500 in
// production (0019 grants both; this catches a future regression).
func TestSbciApiHoldsDeleteGrantsOnPurgeTargets(t *testing.T) {
	_, pool := newStore(t)
	ctx := context.Background()
	for table, disp := range deletionDisposition {
		if disp != "purge" {
			continue
		}
		var can bool
		if err := pool.QueryRow(ctx,
			`SELECT has_table_privilege('sbci_api', $1, 'DELETE')`, table).Scan(&can); err != nil {
			t.Fatalf("has_table_privilege(%s): %v", table, err)
		}
		if !can {
			t.Errorf("sbci_api lacks DELETE on purge target %q — the production deletion path would fail", table)
		}
	}
}

func countRows(t *testing.T, pool *pgxpool.Pool, table, acct string) int {
	t.Helper()
	var n int
	// #nosec — table is a fixed literal from deletionDisposition, never user input.
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM `+table+` WHERE account_id=$1::uuid`, acct).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// TestDeletionFKSafeOrderPurgesClusterAndRetainsAudit populates the FK-entangled
// enrichment cluster plus credentials and retained-audit rows, then deletes the
// account and proves: the delete order hit no FK violation, every purge target
// is empty, the retained-audit tables keep their rows, and the account is
// pseudonymized.
func TestDeletionFKSafeOrderPurgesClusterAndRetainsAudit(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := makeAccount(t, s) // accounts, identity_links, device_registrations, api_tokens
	setEntitlement(t, pool, acct, 1000, 10000, 1000)

	// Enrichment cluster: cloud_projects, cloud_sessions, analysis_jobs,
	// evidence_objects/blobs, usage_reservations, usage_cycles, analysis_results,
	// consent_receipts, consent_events, analysis_usage_ledger.
	rid := completeResultInSession(t, s, acct, "wk", "cs-1", "k-1", "AI title", now)
	if _, err := s.ApplyResultCorrection(ctx, acct, rid, 0, "kk1", []byte(`{"title":"edited"}`), store.CorrectionSourcePortal, now); err != nil {
		t.Fatalf("correction: %v", err) // result_revisions
	}
	// Billing pre-checkout state: an unconsumed, unexpired checkout intent
	// (migration 0030) bound to the account — purged with it.
	if _, _, err := s.CreateCheckoutIntent(ctx, acct, "pri_test_deletion", time.Hour, now); err != nil {
		t.Fatalf("CreateCheckoutIntent: %v", err) // checkout_intents
	}
	// Display identity (migration 0033): the one row holding a plain-text email,
	// so the purge assertion below is meaningful for it.
	if err := s.UpsertAccountProfile(ctx, acct, "deleted-user@example.test", "Deleted User", now); err != nil {
		t.Fatalf("UpsertAccountProfile: %v", err) // account_profiles
	}

	// Sanity: the entangled cluster is actually populated before we delete.
	for _, tbl := range []string{"analysis_results", "result_revisions", "analysis_jobs", "evidence_objects", "cloud_sessions", "cloud_projects", "usage_reservations", "identity_links", "api_tokens", "device_registrations", "entitlements", "checkout_intents", "account_profiles"} {
		if countRows(t, pool, tbl, acct) == 0 {
			t.Fatalf("fixture did not populate %s", tbl)
		}
	}
	// A retained table must be populated so the "kept" assertion is meaningful.
	if countRows(t, pool, "analysis_usage_ledger", acct) == 0 {
		t.Fatalf("fixture did not populate retained table analysis_usage_ledger")
	}

	dr, err := s.CreateDeletionRequest(ctx, acct, now)
	if err != nil {
		t.Fatalf("CreateDeletionRequest: %v", err) // an FK-order bug surfaces here
	}
	if dr.State != "done" {
		t.Fatalf("state=%q, want done", dr.State)
	}

	// Every purge target for this account is empty.
	var purgeTables []string
	for name, disp := range deletionDisposition {
		if disp == "purge" {
			purgeTables = append(purgeTables, name)
		}
	}
	sort.Strings(purgeTables)
	for _, tbl := range purgeTables {
		if n := countRows(t, pool, tbl, acct); n != 0 {
			t.Errorf("purge target %s still has %d row(s) for the deleted account", tbl, n)
		}
	}

	// Retained-audit tables keep their rows.
	for _, tbl := range []string{"analysis_usage_ledger", "deletion_requests"} {
		if countRows(t, pool, tbl, acct) == 0 {
			t.Errorf("retained table %s lost its rows on deletion", tbl)
		}
	}

	// structural_grants row survives but is revoked (if one exists).
	var revokedNulls int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM structural_grants WHERE account_id=$1::uuid AND revoked_at IS NULL`,
		acct).Scan(&revokedNulls); err != nil {
		t.Fatalf("structural_grants: %v", err)
	}
	if revokedNulls != 0 {
		t.Errorf("a structural_grants row survived deletion un-revoked")
	}

	// Account pseudonymized.
	var status string
	var gen *int64
	var deletedAt, purgeAfter *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT status, consent_generation, deleted_at, purge_after FROM accounts WHERE account_id=$1::uuid`,
		acct).Scan(&status, &gen, &deletedAt, &purgeAfter); err != nil {
		t.Fatalf("read account: %v", err)
	}
	if status != "deleted" || gen != nil || deletedAt == nil || purgeAfter == nil {
		t.Fatalf("account not pseudonymized: status=%q gen=%v deleted_at=%v purge_after=%v", status, gen, deletedAt, purgeAfter)
	}
	if !purgeAfter.After(*deletedAt) {
		t.Errorf("purge_after (%v) must be after deleted_at (%v)", *purgeAfter, *deletedAt)
	}
}

// TestSuppressFromJournalReDeletesResurrectedAccount proves restore-suppression
// (rev-4 F8): after a point-in-time restore resurrects a deleted account (and
// its data), replaying the OUT-OF-restore-domain journal re-applies the deletion
// before the service reopens. It also proves idempotence: an account still
// tombstoned is skipped.
func TestSuppressFromJournalReDeletesResurrectedAccount(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := makeAccount(t, s)

	// Delete it — the journal records an "accepted" for this account.
	if _, err := s.CreateDeletionRequest(ctx, acct, now); err != nil {
		t.Fatalf("CreateDeletionRequest: %v", err)
	}

	// A no-op run while the account is STILL tombstoned suppresses nothing.
	if n, err := s.SuppressFromJournal(ctx, now); err != nil || n != 0 {
		t.Fatalf("SuppressFromJournal on tombstoned account: n=%d err=%v, want 0,nil", n, err)
	}

	// Simulate a PITR restore to BEFORE the deletion: the account is active again
	// and a piece of its identity data has come back.
	if _, err := pool.Exec(ctx,
		`UPDATE accounts SET status='active', consent_generation=0, deleted_at=NULL, purge_after=NULL
		  WHERE account_id=$1::uuid`, acct); err != nil {
		t.Fatalf("resurrect account: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO identity_links (account_id, provider, subject) VALUES ($1::uuid, 'dev', 'restored-subject')`,
		acct); err != nil {
		t.Fatalf("restore identity_link: %v", err)
	}

	// Replay the journal — the restore-runbook step.
	n, err := s.SuppressFromJournal(ctx, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("SuppressFromJournal: %v", err)
	}
	if n != 1 {
		t.Fatalf("suppressed=%d, want 1", n)
	}

	// The account is tombstoned again and the resurrected identity is purged.
	var status string
	if err := pool.QueryRow(ctx,
		`SELECT status FROM accounts WHERE account_id=$1::uuid`, acct).Scan(&status); err != nil {
		t.Fatalf("read account: %v", err)
	}
	if status != "deleted" {
		t.Fatalf("account status=%q after suppression, want deleted", status)
	}
	if n := countRows(t, pool, "identity_links", acct); n != 0 {
		t.Fatalf("resurrected identity_link survived suppression: %d rows", n)
	}
}
