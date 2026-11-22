package db_test

// db_definer_grants_test.go pins migration 0082 (managed-SaaS operator ruling
// A9): PUBLIC holds EXECUTE on no SECURITY DEFINER function in the cloud
// schema, and each one is executable by exactly the roles that call it. A new
// definer function must be added to definerGrants, which forces its author to
// revoke PUBLIC and name its callers.

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
)

// definerGrants maps every SECURITY DEFINER function (regprocedure text) to
// the roles other than its owner (sbci_defs) that hold EXECUTE on it. The
// owner's own grant (including 0047's explicit grant of sbci_current_account()
// to sbci_defs, which merges into it) is not listed; nil means only the owner.
var definerGrants = map[string][]string{
	"sbci_allocate_result_sequence()":                                       nil,
	"sbci_community_bands(text,text,integer,text)":                          {"sbci_aggregator"},
	"sbci_community_cohort_size(text,text,integer,text)":                    {"sbci_aggregator"},
	"sbci_community_windows()":                                              {"sbci_aggregator"},
	"sbci_current_account()":                                                {"sbci_aggregator", "sbci_api", "sbci_app", "sbci_worker"},
	"sbci_deletion_followup_check(uuid)":                                    {"sbci_app", "sbci_worker"},
	"sbci_expire_org_usage_days(date)":                                      {"sbci_app", "sbci_worker"},
	"sbci_find_identity_link(text,text)":                                    {"sbci_api", "sbci_app"},
	"sbci_introspect_browser_session(text)":                                 {"sbci_api", "sbci_app"},
	"sbci_introspect_token(text)":                                           {"sbci_api", "sbci_app"},
	"sbci_is_org_member(uuid,text)":                                         {"sbci_api", "sbci_app"},
	"sbci_lease_next_job(text,timestamp with time zone,text[],integer)":     {"sbci_app", "sbci_worker"},
	"sbci_oidc_note_sub_seen()":                                             nil,
	"sbci_org_create_owner_email_hint(uuid)":                                {"sbci_app", "sbci_worker"},
	"sbci_org_create_owner_email_verified(uuid)":                            {"sbci_app", "sbci_worker"},
	"sbci_org_create_owner_sub(uuid)":                                       {"sbci_app", "sbci_worker"},
	"sbci_org_live_member_counts(uuid)":                                     {"sbci_api", "sbci_app"},
	"sbci_org_member_write_ok(uuid,uuid,text,boolean)":                      {"sbci_api", "sbci_app"},
	"sbci_org_slug_available(text)":                                         {"sbci_api", "sbci_app"},
	"sbci_org_subscription(uuid)":                                           {"sbci_app", "sbci_worker"},
	"sbci_org_subscription_v2(uuid)":                                        {"sbci_app", "sbci_worker"},
	"sbci_paddle_one_live_guard()":                                          nil,
	"sbci_paddle_account_for_subscription(text)":                            {"sbci_api", "sbci_app"},
	"sbci_portal_org_create_status(uuid)":                                   {"sbci_api", "sbci_app"},
	"sbci_portal_org_deletion_cancel(uuid)":                                 {"sbci_api", "sbci_app"},
	"sbci_portal_org_deletion_open(uuid,timestamp with time zone)":          {"sbci_api", "sbci_app"},
	"sbci_portal_org_deletion_status(uuid)":                                 {"sbci_api", "sbci_app"},
	"sbci_portal_org_departure_notices(uuid)":                               {"sbci_api", "sbci_app"},
	"sbci_portal_org_last_seat_day(uuid)":                                   {"sbci_api", "sbci_app"},
	"sbci_portal_org_plan_grant(uuid)":                                      {"sbci_api", "sbci_app"},
	"sbci_portal_org_seats(uuid)":                                           {"sbci_api", "sbci_app"},
	"sbci_portal_org_subscription(uuid)":                                    {"sbci_api", "sbci_app"},
	"sbci_portal_org_subscription_v2(uuid)":                                 {"sbci_api", "sbci_app"},
	"sbci_rate_limit(text,text,integer,bigint)":                             {"sbci_api", "sbci_app", "sbci_staff"},
	"sbci_rate_limit_at(text,text,integer,bigint,timestamp with time zone)": nil,
	"sbci_slug_org(text)":                                                   {"sbci_api", "sbci_app"},
	"sbci_staff_availability_doc()":                                         {"sbci_staff"},
	"sbci_staff_org_deletion(uuid)":                                         {"sbci_staff"},
	"sbci_staff_org_entitlements(uuid)":                                     {"sbci_staff"},
	"sbci_staff_org_intents(uuid)":                                          {"sbci_staff"},
	"sbci_staff_org_plan_grants(uuid)":                                      {"sbci_staff"},
	"sbci_staff_org_usage(uuid,integer)":                                    {"sbci_staff"},
	"sbci_staff_orgs(uuid)":                                                 {"sbci_staff"},
	"sbci_support_target(uuid,uuid)":                                        {"sbci_api", "sbci_app"},
	"sbci_team_org_limit()":                                                 {"sbci_api", "sbci_app"},
	"sbci_team_create_allowed()":                                            {"sbci_api", "sbci_app"},
	"sbci_sweep_expired_evidence(timestamp with time zone)":                 {"sbci_app", "sbci_worker"}, // 0151 (CLOUD-01): the worker runs the sweep
	"sbci_sweep_expired_exports(timestamp with time zone)":                  {"sbci_api", "sbci_app"},
	"sbci_sweep_expired_pop_replay(timestamp with time zone)":               {"sbci_api", "sbci_app"},
	"sbci_sweep_results_retention(timestamp with time zone)":                {"sbci_app", "sbci_worker"},
	"sbci_sweep_retention(timestamp with time zone)":                        {"sbci_api", "sbci_app"},
	"sbci_project_digest_candidates(date,date,timestamp with time zone,timestamp with time zone,integer,timestamp with time zone,integer)": {"sbci_app", "sbci_worker"},
}

func TestDefinerFunctionExecuteGrants(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()

	rows, err := pool.Query(ctx, `
		SELECT p.oid::regprocedure::text,
		       pg_get_userbyid(p.proowner),
		       coalesce(array_agg(CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END)
		                FILTER (WHERE a.grantee <> p.proowner), '{}')
		  FROM pg_proc p
		  JOIN pg_namespace n ON n.oid = p.pronamespace
		  LEFT JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
		         ON a.privilege_type = 'EXECUTE'
		 WHERE n.nspname = 'public' AND p.prosecdef
		 GROUP BY p.oid, p.proowner`)
	if err != nil {
		t.Fatalf("read definer ACLs: %v", err)
	}
	type acl struct {
		owner    string
		grantees []string
	}
	got := map[string]acl{}
	for rows.Next() {
		var sig, owner string
		var grantees []string
		if err := rows.Scan(&sig, &owner, &grantees); err != nil {
			t.Fatalf("scan: %v", err)
		}
		sort.Strings(grantees)
		got[sig] = acl{owner: owner, grantees: grantees}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	for sig, a := range got {
		want, known := definerGrants[sig]
		if !known {
			t.Errorf("SECURITY DEFINER function %s (grantees %v) is not in definerGrants: revoke PUBLIC in its step and pin its callers here", sig, a.grantees)
			continue
		}
		if a.owner != "sbci_defs" {
			t.Errorf("%s is owned by %q, want sbci_defs", sig, a.owner)
		}
		for _, g := range a.grantees {
			if g == "PUBLIC" {
				t.Errorf("PUBLIC holds EXECUTE on SECURITY DEFINER function %s (0082, ruling A9)", sig)
			}
		}
		w := append([]string(nil), want...)
		sort.Strings(w)
		if len(w) == 0 {
			w = []string{}
		}
		if !reflect.DeepEqual(a.grantees, w) {
			t.Errorf("%s EXECUTE grantees = %v, want %v", sig, a.grantees, w)
		}
	}
	for sig := range definerGrants {
		if _, ok := got[sig]; !ok {
			t.Errorf("definerGrants lists %s, but no such SECURITY DEFINER function exists", sig)
		}
	}
}

// TestDefinerGrantsServeTheirCallers runs the paths 0082 had to keep working
// with real rows: each caller of sbci_current_account() can call it and a role
// with no grant cannot; the worker reads and updates an orgs row (its own
// policies are the constant true, so it never evaluates the member policy and
// needs no EXECUTE on sbci_is_org_member); and sbci_api's insert into
// oidc_issued still fires the sbci_oidc_note_sub_seen trigger, which no role
// but its owner may execute (PostgreSQL checks a trigger function's EXECUTE
// when the trigger is created, never when it fires).
func TestDefinerGrantsServeTheirCallers(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()

	asRole := func(role string, fn func(tx pgx.Tx) error) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+pgx.Identifier{role}.Sanitize()); err != nil {
			return err
		}
		return fn(tx)
	}
	isDenied := func(err error) bool {
		var pgErr *pgconn.PgError
		return errors.As(err, &pgErr) && pgErr.Code == "42501"
	}

	for _, role := range definerGrants["sbci_current_account()"] {
		if err := asRole(role, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `SELECT sbci_current_account()`)
			return err
		}); err != nil {
			t.Errorf("%s calling sbci_current_account(): %v", role, err)
		}
	}
	if err := asRole("sbci_staff", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT sbci_current_account()`)
		return err
	}); !isDenied(err) {
		t.Errorf("sbci_staff calling sbci_current_account(): err=%v, want permission denied (42501)", err)
	}

	var orgID, accountID string
	if err := pool.QueryRow(ctx, `
		WITH a AS (INSERT INTO accounts DEFAULT VALUES RETURNING account_id)
		INSERT INTO orgs (kind, slug, display_name, tenancy, created_by)
		SELECT 'team', 'w9l6-definer', 'Definer probe', 'managed', account_id FROM a
		RETURNING org_id::text, created_by::text`).Scan(&orgID, &accountID); err != nil {
		t.Fatalf("seed org: %v", err)
	}

	if err := asRole("sbci_worker", func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM orgs WHERE org_id = $1::uuid`, orgID).Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			return errors.New("worker does not see the org row")
		}
		tag, err := tx.Exec(ctx, `UPDATE orgs SET updated_at = now() WHERE org_id = $1::uuid`, orgID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("worker update touched no row")
		}
		return nil
	}); err != nil {
		t.Errorf("sbci_worker read/update of orgs after 0082: %v", err)
	}

	// Committed, so the trigger's row can be read afterwards as the test role.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE sbci_api`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO oidc_issued (jti, org_id, account_id, sub, client_id, kid, iat, exp)
		VALUES ('w9l6-definer-jti-0002', $1::uuid, $2::uuid, 'sub-w9l6', 'client', 'kid', now(), now() + interval '1 minute')`,
		orgID, accountID); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("sbci_api insert into oidc_issued: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var seen int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM org_sub_seen WHERE org_id = $1::uuid AND sub = 'sub-w9l6'`, orgID).Scan(&seen); err != nil || seen != 1 {
		t.Fatalf("org_sub_seen rows = %d err=%v, want 1 (the trigger did not fire)", seen, err)
	}
}
