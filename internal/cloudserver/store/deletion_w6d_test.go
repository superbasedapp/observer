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
	"account_verified_emails":   "purge", // 0074: the provider-asserted address the OIDC issuer signs (A4)
	"device_registrations":      "purge",
	"api_tokens":                "purge",
	"browser_sessions":          "purge",
	"pop_replay":                "purge",
	"step_up_authorizations":    "purge",
	// C2 (0131, wave 17 portal-guardrails): the portal passkeys, their
	// ceremonies and the recovery code hashes.
	"portal_passkeys":           "purge",
	"portal_passkey_ceremonies": "purge",
	"portal_recovery_codes":     "purge",
	"entitlements":              "purge",
	"account_plans":             "purge",
	"usage_cycles":              "purge",
	"usage_token_windows":       "purge", // R-AI1 (0078): per-account token windows
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

	// FR-6 / FR-24 (0145): a passkey session's single-use approval of a new
	// device thumbprint and the per-account recovery-code failure counter.
	// Account-keyed credential state, purged with the passkeys (deletion.go).
	"device_approvals":         "purge",
	"portal_recovery_failures": "purge",

	// Getting started v2 (0150, CONNECT-1): the account's resolved connect
	// requests and their poll proofs are purged (deletion.go; the proofs
	// cascade with their request); the Connect consent receipt is retained
	// like the other consent records.
	"connect_requests":    "purge",
	"connect_poll_replay": "purge",
	"connect_consents":    "retain",

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
	"budget_pool_spend":            "excluded", // T-946: per-pool USD sums, no account linkage
	"kill_switches":                "excluded",
	"plans":                        "excluded",
	"enrichment_tiers":             "excluded", // R-AI1 (0078): platform tier configuration, no account linkage
	"route_registry":               "excluded",
	"dialect_verification_records": "excluded",
	"provider_attestations":        "excluded",
	"sbci_rate_limit_counters":     "excluded",
	"workos_events":                "excluded",
	"sbci_migrations":              "excluded",
	"sbci_tenant_context_keys":     "excluded", // M3b.2: the tenant-context MAC key pads (0066), no account linkage
	"community_metrics":            "excluded", // W5: fixed versioned metric registry, not account data
	"community_band_snapshots":     "excluded", // W5: aggregate-only delayed bands, no account linkage
	"billing_events":               "excluded", // W9: Paddle webhook idempotency/audit log (mirrors workos_events)
	// FR-2 / FR-8 (0135, 0136): Paddle ids, a price, a reason and times; no
	// account linkage (a refused binding's account is untrusted, an unbound
	// subscription has none).
	"paddle_binding_refusals":  "excluded",
	"paddle_pending_terminals": "excluded",
	// FR-10 (0137): the first free trial of an account scope or an org. Kept
	// as the billing fact that stops a repeat trial; dropped with the account
	// row by the tombstone sweep (ON DELETE CASCADE).
	"paddle_trial_uses": "retain",
	// Control-plane org registry (managed-SaaS M6.1a, 0047-0049). Account
	// deletion with orgs (succession refusal, member deactivation, the
	// personal org) is M6.9; until then the personal-plane deletion leaves
	// these untouched. org_members.account_id cascades with the 24-month
	// tombstone sweep; created_by / requested_by are opaque ids.
	"orgs":                  "excluded", // org-owned record, not the account's data
	"org_slugs":             "excluded", // slug namespace, no account linkage
	"org_outbox":            "excluded", // host-API intents, no personal data
	"org_members":           "retain",   // membership; M6.9: removed by the deletion driver (account_deletion_followups), not in this transaction
	"org_sub_seen":          "retain",   // WorkOS sub per org; M6.9 deactivates from it (the issuer's audit fact)
	"org_deletion_requests": "retain",   // the org deletion audit fact (M6.9, 0120)
	// M6.9 (0120): the org-side follow-up of an account deletion, written by
	// deletionCompleteTx and driven by the worker; its subjects are emptied
	// when it is done. The notices name an org and a time, no person.
	"account_deletion_followups":   "retain",
	"org_member_departure_notices": "excluded",
	// Host-API client (managed-SaaS M6.4, 0058-0060): the reconciler's
	// findings carry an org id, states, generations and enum classes only.
	"org_reconcile_findings": "excluded", // org-owned reconciliation record, no account linkage
	// Control-plane OIDC issuer (managed-SaaS M6.2, 0051-0054). Account
	// deletion with orgs is M6.9; until then the personal-plane deletion
	// leaves these untouched. account_id columns are opaque ids.
	"oidc_clients":      "excluded", // one client per org, no account linkage
	"oidc_signing_keys": "excluded", // public keys, no account linkage
	"oidc_codes":        "retain",   // 60-second single-use codes; swept by SweepOIDCCodes
	"oidc_issued":       "retain",   // the sign-in audit fact (jti, sub, org); M6.9 decides its end
	"oidc_audit_mirror": "retain",   // the sign-in mirror outbox (no email); M6.9 decides its end
	// M7a.2 (0087): the support path keys to staff members, never to a
	// customer account; codes are swept with the member codes.
	"oidc_support_codes":  "excluded",
	"oidc_support_issued": "excluded",
	// M6.3 (0055): signed documents per org and platform-wide, no account linkage.
	"org_entitlement_docs": "excluded",
	"availability_docs":    "excluded",
	// Wave 16 (0097, W16-D6): the operator's version floors per signed
	// document stream (an org id or "platform", a version, the record's
	// digest, the operator's name); no account linkage.
	"signed_doc_version_floors": "excluded",
	// M7b.2 (0085): the daily usage reports a billing period's seat count is
	// computed from. Member ids are the tenant's opaque member ids, never a
	// cloud account id or an email; a billing record of the org, so it
	// survives an account's deletion. Org deletion (M6.9) decides its end.
	"org_usage_days": "retain",
	// Wave 15 (0095, W15-D13): the operator's plan grants per org, an org's
	// entitlement record with no account linkage (actor is "operator").
	"org_plan_grants": "excluded",
	// Wave 15 (0094, W15-D12): the operator's raises of an account's team
	// org cap. An opaque account id, a number and the operator's reason;
	// kept as the operator's record and dropped with the account row by
	// the 24-month tombstone sweep (ON DELETE CASCADE).
	"account_team_org_limits": "retain",
	// Wave 17 (0130, portal-guardrails): the staff's team create
	// allow-list. An entry names an opaque account id or a domain (never an
	// address); kept as the staff's record, like the cap above. A deleted
	// account cannot sign in, so its entry allows nothing.
	"team_create_allowlist": "retain",
	// Individuals E3 (0134, D-IND-4): the migrate-personal ledger. Ids,
	// counts and digests only; the operator's record of the move, dropped
	// with the account row by the tombstone sweep (ON DELETE CASCADE).
	"personal_migrations": "retain",
	// M6.8 (0069): the staff console. Staff members are platform operators,
	// not customer accounts; no row carries an account id or an email.
	"staff_users":                "excluded",
	"staff_webauthn_credentials": "excluded",
	"staff_enrolments":           "excluded",
	"staff_ceremonies":           "excluded",
	"staff_sessions":             "excluded",
	"staff_actions":              "excluded", // append-only; an org id in it is opaque and survives the org
	"availability_inputs":        "excluded",
	// M6.3 (0154): availability issue requests (a staff id, a reason, a
	// digest, versions) and per-host delivery state (host ids, versions).
	// No account id, no email, no org's data.
	"availability_issue_requests": "excluded",
	"availability_deliveries":     "excluded",
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

// accountRowsViaParent counts an account's rows in a table that carries no
// account_id of its own and is reached through the parent row it cascades
// with (0150: a connect poll proof belongs to its connect request).
var accountRowsViaParent = map[string]string{
	"connect_poll_replay": `SELECT count(*) FROM connect_poll_replay p
		JOIN connect_requests r ON r.request_id = p.request_id
		WHERE r.account_id=$1::uuid`,
}

func countRows(t *testing.T, pool *pgxpool.Pool, table, acct string) int {
	t.Helper()
	var n int
	q := `SELECT count(*) FROM ` + table + ` WHERE account_id=$1::uuid`
	if viaParent, ok := accountRowsViaParent[table]; ok {
		q = viaParent
	}
	// #nosec — table is a fixed literal from deletionDisposition, never user input.
	if err := pool.QueryRow(context.Background(), q, acct).Scan(&n); err != nil {
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
	// The provider-asserted address (migration 0074, A4): also plain text.
	if err := s.UpsertVerifiedEmail(ctx, acct, "deleted-user@example.test", true, now); err != nil {
		t.Fatalf("UpsertVerifiedEmail: %v", err) // account_verified_emails
	}

	// Sanity: the entangled cluster is actually populated before we delete.
	for _, tbl := range []string{"analysis_results", "result_revisions", "analysis_jobs", "evidence_objects", "cloud_sessions", "cloud_projects", "usage_reservations", "identity_links", "api_tokens", "device_registrations", "entitlements", "checkout_intents", "account_profiles", "account_verified_emails"} {
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
