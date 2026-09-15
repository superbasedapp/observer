package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// tablePriv reports whether role holds priv on table (deployed-grant
// introspection, mirroring plans_test.go's has_table_privilege pattern).
func tablePriv(t *testing.T, pool *pgxpool.Pool, role, table, priv string) bool {
	t.Helper()
	var ok bool
	if err := pool.QueryRow(context.Background(),
		`SELECT has_table_privilege($1, $2, $3)`, role, table, priv).Scan(&ok); err != nil {
		t.Fatalf("has_table_privilege(%s,%s,%s): %v", role, table, priv, err)
	}
	return ok
}

// columnPriv reports whether role holds priv on a specific COLUMN of table
// (has_column_privilege). Used to pin the worker's column-level UPDATE on
// analysis_results (migration 0018): it may flip superseded/superseded_by but
// not rewrite a result body.
func columnPriv(t *testing.T, pool *pgxpool.Pool, role, table, column, priv string) bool {
	t.Helper()
	var ok bool
	if err := pool.QueryRow(context.Background(),
		`SELECT has_column_privilege($1, $2, $3, $4)`, role, table, column, priv).Scan(&ok); err != nil {
		t.Fatalf("has_column_privilege(%s,%s,%s,%s): %v", role, table, column, priv, err)
	}
	return ok
}

// funcPriv reports whether role holds EXECUTE on the function identified by its
// signature (e.g. "sbci_lease_next_job(text, timestamptz, text[], int)").
func funcPriv(t *testing.T, pool *pgxpool.Pool, role, signature string) bool {
	t.Helper()
	var ok bool
	if err := pool.QueryRow(context.Background(),
		`SELECT has_function_privilege($1, $2, 'EXECUTE')`, role, signature).Scan(&ok); err != nil {
		t.Fatalf("has_function_privilege(%s,%s): %v", role, signature, err)
	}
	return ok
}

// TestRoleSplitDeployedGrants pins the POSITIVE grant matrix: each application
// role holds the privileges its runtime paths need (migration 0015).
func TestRoleSplitDeployedGrants(t *testing.T) {
	pool := cloudtestpg.NewDB(t)

	// sbci_api: auth bootstrap, submit/enqueue, results read, deletion tombstone.
	apiHas := []struct{ table, priv string }{
		{"browser_sessions", "INSERT"},
		{"auth_transactions", "INSERT"},
		{"analysis_jobs", "INSERT"},
		{"analysis_results", "SELECT"},
		{"analysis_results", "UPDATE"}, // deletion tombstone (see correction note)
		{"evidence_objects", "INSERT"},
		{"evidence_blobs", "INSERT"},
		{"portal_consent_choices", "INSERT"},
		{"provider_attestations", "INSERT"}, // admission gate records at enqueue
		{"structural_snapshots", "INSERT"},
		{"result_revisions", "INSERT"}, // W6c: the correction append (0018)
		{"result_revisions", "UPDATE"}, // W6c: the deletion tombstone
		{"result_revisions", "SELECT"}, // W6c: ETag + Sessions detail
		{"account_profiles", "INSERT"}, // 0033: the sign-in leg upserts the display identity
		{"account_profiles", "UPDATE"}, // 0033: ON CONFLICT DO UPDATE on every re-login
		{"account_profiles", "SELECT"}, // 0033: the /portal/api/session bootstrap reads it
		{"sbci_migrations", "SELECT"},  // 0036: /healthz schema block + schema-check on the service DSN
	}
	for _, c := range apiHas {
		if !tablePriv(t, pool, "sbci_api", c.table, c.priv) {
			t.Errorf("sbci_api MISSING %s on %s", c.priv, c.table)
		}
	}
	if !tablePriv(t, pool, "sbci_app", "sbci_migrations", "SELECT") {
		t.Error("sbci_app MISSING SELECT on sbci_migrations (0036)")
	}
	if !funcPriv(t, pool, "sbci_api", "sbci_introspect_token(text)") {
		t.Error("sbci_api MISSING EXECUTE on sbci_introspect_token")
	}
	if !funcPriv(t, pool, "sbci_api", "sbci_introspect_browser_session(text)") {
		t.Error("sbci_api MISSING EXECUTE on sbci_introspect_browser_session")
	}
	if !funcPriv(t, pool, "sbci_api", "sbci_sweep_expired_pop_replay(timestamptz)") {
		t.Error("sbci_api MISSING EXECUTE on sbci_sweep_expired_pop_replay")
	}

	// sbci_worker: lease, run, write result, purge evidence, record attestation.
	workerHas := []struct{ table, priv string }{
		{"analysis_jobs", "SELECT"},
		{"analysis_jobs", "UPDATE"},
		{"analysis_results", "INSERT"},
		{"analysis_results", "SELECT"}, // RETURNING id needs SELECT on the column
		{"usage_reservations", "UPDATE"},
		{"usage_cycles", "UPDATE"},
		{"budget_pools", "UPDATE"},
		{"analysis_usage_ledger", "INSERT"},
		{"evidence_objects", "UPDATE"},
		{"evidence_blobs", "DELETE"},
		{"provider_attestations", "INSERT"},
		{"dialect_verification_records", "SELECT"},
	}
	for _, c := range workerHas {
		if !tablePriv(t, pool, "sbci_worker", c.table, c.priv) {
			t.Errorf("sbci_worker MISSING %s on %s", c.priv, c.table)
		}
	}
	if !funcPriv(t, pool, "sbci_worker", "sbci_lease_next_job(text, timestamptz, text[], int)") {
		t.Error("sbci_worker MISSING EXECUTE on sbci_lease_next_job")
	}
	// W6c (0018): the worker's regeneration supersede path needs a column-level
	// UPDATE on exactly the two supersede columns — no more.
	if !columnPriv(t, pool, "sbci_worker", "analysis_results", "superseded", "UPDATE") {
		t.Error("sbci_worker MISSING UPDATE on analysis_results.superseded (regeneration supersede path)")
	}
	if !columnPriv(t, pool, "sbci_worker", "analysis_results", "superseded_by", "UPDATE") {
		t.Error("sbci_worker MISSING UPDATE on analysis_results.superseded_by (regeneration supersede path)")
	}

	// Both application roles must EXECUTE sbci_current_account (the RLS helper) —
	// without it every tenant read/write fails inside the policy.
	if !funcPriv(t, pool, "sbci_api", "sbci_current_account()") {
		t.Error("sbci_api MISSING EXECUTE on sbci_current_account (RLS policy helper)")
	}
	if !funcPriv(t, pool, "sbci_worker", "sbci_current_account()") {
		t.Error("sbci_worker MISSING EXECUTE on sbci_current_account (RLS policy helper)")
	}
}

// TestRoleSplitLeastPrivilege pins the NEGATIVE matrix: each role is DENIED the
// other's exclusive objects, so a defect in one process cannot act as the other.
func TestRoleSplitLeastPrivilege(t *testing.T) {
	pool := cloudtestpg.NewDB(t)

	// api may NOT lease jobs and may NOT write model results.
	if funcPriv(t, pool, "sbci_api", "sbci_lease_next_job(text, timestamptz, text[], int)") {
		t.Error("sbci_api holds EXECUTE on sbci_lease_next_job; leasing is the worker's alone")
	}
	if tablePriv(t, pool, "sbci_api", "analysis_results", "INSERT") {
		t.Error("sbci_api holds INSERT on analysis_results; only the worker writes results")
	}

	// worker may NOT mint browser sessions / auth transactions / portal consent,
	// and may NOT tombstone (UPDATE) a result.
	if tablePriv(t, pool, "sbci_worker", "browser_sessions", "INSERT") {
		t.Error("sbci_worker holds INSERT on browser_sessions; that is an api-only path")
	}
	if tablePriv(t, pool, "sbci_worker", "auth_transactions", "INSERT") {
		t.Error("sbci_worker holds INSERT on auth_transactions; that is an api-only path")
	}
	if tablePriv(t, pool, "sbci_worker", "portal_consent_choices", "INSERT") {
		t.Error("sbci_worker holds INSERT on portal_consent_choices; that is an api-only path")
	}
	// 0033: a job runner never needs to know who the developer is. The display
	// identity is the one table holding a plain-text email, so the worker must
	// hold NOTHING on it — not even SELECT.
	if tablePriv(t, pool, "sbci_worker", "account_profiles", "SELECT") ||
		tablePriv(t, pool, "sbci_worker", "account_profiles", "INSERT") {
		t.Error("sbci_worker holds a grant on account_profiles; the developer's email is never a worker-plane read")
	}
	// The worker holds a COLUMN-level UPDATE on analysis_results (superseded,
	// superseded_by — the W6c regeneration supersede path, migration 0018), so
	// has_table_privilege(...,'UPDATE') is now true; the invariant that matters
	// is that it still cannot rewrite a result BODY or the ETag counter.
	if columnPriv(t, pool, "sbci_worker", "analysis_results", "result", "UPDATE") {
		t.Error("sbci_worker holds UPDATE on analysis_results.result; a worker must never rewrite a result body")
	}
	if columnPriv(t, pool, "sbci_worker", "analysis_results", "correction_seq", "UPDATE") {
		t.Error("sbci_worker holds UPDATE on analysis_results.correction_seq; the ETag counter is an api-plane column")
	}
	if tablePriv(t, pool, "sbci_worker", "result_revisions", "INSERT") ||
		tablePriv(t, pool, "sbci_worker", "result_revisions", "SELECT") {
		t.Error("sbci_worker holds a grant on result_revisions; user corrections are an api-plane path")
	}

	// worker must NOT run the auth-bootstrap introspect lookups.
	if funcPriv(t, pool, "sbci_worker", "sbci_introspect_token(text)") {
		t.Error("sbci_worker holds EXECUTE on sbci_introspect_token; that is an api-only bootstrap")
	}

	// api reads control-plane state at admission but NEVER mutates it — the
	// route/kill-switch writers are operator/prove paths (sbci_app). A
	// compromised front-door must not be able to flip a route binding or a
	// kill switch, so the api role is SELECT-only on both.
	if tablePriv(t, pool, "sbci_api", "route_registry", "UPDATE") {
		t.Error("sbci_api holds UPDATE on route_registry; the api only resolves routes — route mutation is an operator/prove path")
	}
	if tablePriv(t, pool, "sbci_api", "kill_switches", "UPDATE") {
		t.Error("sbci_api holds UPDATE on kill_switches; the api only reads the kill switch — mutation is an operator path")
	}
	if tablePriv(t, pool, "sbci_api", "kill_switches", "INSERT") {
		t.Error("sbci_api holds INSERT on kill_switches; the api only reads the kill switch")
	}
}

// TestRoleSplitRoleAttributes pins that all three new roles are NOLOGIN +
// NOBYPASSRLS, mirroring store_test.go's sbci_app assertion — the whole tenancy
// model assumes an application role cannot bypass RLS.
func TestRoleSplitRoleAttributes(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()
	for _, role := range []string{"sbci_api", "sbci_worker", "sbci_aggregator"} {
		var canLogin, bypass, super bool
		if err := pool.QueryRow(ctx,
			`SELECT rolcanlogin, rolbypassrls, rolsuper FROM pg_roles WHERE rolname = $1`,
			role).Scan(&canLogin, &bypass, &super); err != nil {
			t.Fatalf("read %s attrs: %v", role, err)
		}
		if canLogin {
			t.Errorf("%s must be NOLOGIN", role)
		}
		if bypass {
			t.Errorf("%s must be NOBYPASSRLS", role)
		}
		if super {
			t.Errorf("%s must not be superuser", role)
		}
	}
}

// TestRoleSplitAggregatorHasNoCrossTenantExecute pins the W5-not-yet-wired
// state: sbci_aggregator exists but holds EXECUTE on NONE of the cross-tenant
// SECURITY DEFINER functions (the ones REVOKEd from PUBLIC — lease, the auth
// introspects, identity-link, and the sweeps). The W5 cross-tenant aggregation
// function + its EXECUTE grant land in the W5 migration, not 0015.
//
// sbci_current_account() is deliberately EXCLUDED: it is EXECUTE-to-PUBLIC by
// design (a STABLE helper that reads the sbci.account_id GUC — it grants no
// cross-tenant access), so every role including aggregator can call it.
func TestRoleSplitAggregatorHasNoCrossTenantExecute(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	sigs := []string{
		"sbci_lease_next_job(text, timestamptz, text[], int)",
		"sbci_introspect_token(text)",
		"sbci_introspect_browser_session(text)",
		"sbci_find_identity_link(text, text)",
		"sbci_sweep_expired_evidence(timestamptz)",
		"sbci_sweep_expired_pop_replay(timestamptz)",
	}
	for _, sig := range sigs {
		if funcPriv(t, pool, "sbci_aggregator", sig) {
			t.Errorf("sbci_aggregator holds EXECUTE on %s; W5 must grant cross-tenant access, not 0015", sig)
		}
	}
}

// TestRoleSplitRuntimeSmoke proves the parameterized `SET LOCAL ROLE` actually
// works end-to-end for each role: a store bound to sbci_api runs a WithSystem
// read the api needs, and one bound to sbci_worker leases (no job present ⇒ nil)
// — i.e. the SET ROLE + EXECUTE + table grants line up on the running paths, not
// only in the has_*_privilege introspection.
func TestRoleSplitRuntimeSmoke(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()
	now := time.Now()

	apiStore, err := store.NewForRole(pool, store.RoleAPI)
	if err != nil {
		t.Fatalf("NewForRole(api): %v", err)
	}
	if apiStore.Role() != store.RoleAPI {
		t.Fatalf("apiStore.Role() = %q, want sbci_api", apiStore.Role())
	}
	// A control-plane read the api performs at every submit (WithSystem →
	// route_registry SELECT). Succeeds only if `SET LOCAL ROLE sbci_api` +
	// sbci_current_account EXECUTE + route_registry SELECT all hold.
	if _, err := apiStore.GlobalKillSwitchActive(ctx); err != nil {
		t.Fatalf("api GlobalKillSwitchActive under sbci_api: %v", err)
	}
	if _, err := apiStore.ResolveRoute(ctx, store.FeatureSessionEnrichment); err != nil {
		t.Fatalf("api ResolveRoute under sbci_api: %v", err)
	}

	workerStore, err := store.NewForRole(pool, store.RoleWorker)
	if err != nil {
		t.Fatalf("NewForRole(worker): %v", err)
	}
	if workerStore.Role() != store.RoleWorker {
		t.Fatalf("workerStore.Role() = %q, want sbci_worker", workerStore.Role())
	}
	// Lease under sbci_worker: no job is queued, so this returns (nil, nil) — but
	// it exercises `SET LOCAL ROLE sbci_worker` + EXECUTE sbci_lease_next_job.
	lj, err := workerStore.LeaseNextJob(ctx, "smoke-worker", []string{store.FeatureSessionEnrichment}, time.Minute, now)
	if err != nil {
		t.Fatalf("worker LeaseNextJob under sbci_worker: %v", err)
	}
	if lj != nil {
		t.Fatalf("worker LeaseNextJob returned a job on an empty queue: %+v", lj)
	}

	// NewForRole rejects an invalid role loudly.
	if _, err := store.NewForRole(pool, store.Role("sbci_bogus")); err == nil {
		t.Fatal("NewForRole accepted an invalid role; it must fail loudly")
	}
}
