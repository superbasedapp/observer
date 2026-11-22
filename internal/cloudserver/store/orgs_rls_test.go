package store_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// orgs_rls_test.go proves the org registry's row-level security and grants
// (cloud migrations 0047-0050, managed-SaaS M6.1a; design
// docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 3.2, 4.1):
// a member reads its org and a non-member cannot (row invisible, write
// refused), a missing context and WithSystem see nothing, the membership
// functions are hardened SECURITY DEFINERs that do not recurse, the
// owner/admin/member matrix, the class and grant of every new table, and the
// atomicity of the provisioning transaction. Every test needs Postgres
// (cloudtestpg; SKIPPED loudly without SBCI_TEST_PG_DSN).

// newAPIStore returns a store bound to the production serve role over pool.
func newAPIStore(t *testing.T, pool *pgxpool.Pool) *store.Store {
	t.Helper()
	s, err := store.NewForRole(pool, store.RoleAPI)
	if err != nil {
		t.Fatalf("NewForRole(api): %v", err)
	}
	return s
}

// provisionTeam provisions a managed team org with a unique slug for owner.
func provisionTeam(t *testing.T, s *store.Store, owner string) store.MyOrg {
	t.Helper()
	slug := fmt.Sprintf("team-%d", subjCounter.Add(1))
	o, err := s.ProvisionOrg(context.Background(), owner, store.ProvisionOrgInput{
		Kind: store.OrgTeam, Slug: slug, DisplayName: "Team " + slug, Tenancy: store.TenancyManaged,
	})
	if err != nil {
		t.Fatalf("ProvisionOrg(team %s): %v", slug, err)
	}
	return o
}

// asAccount runs fn under WithAccount as acct; nil means every statement
// succeeded and the transaction committed.
func asAccount(s *store.Store, acct string, fn func(ctx context.Context, tx pgx.Tx) error) error {
	return s.WithAccount(context.Background(), acct, fn)
}

// execOne runs one statement and fails unless it touched exactly one row.
func execOne(ctx context.Context, tx pgx.Tx, sql string, args ...any) error {
	tag, err := tx.Exec(ctx, sql, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("affected %d rows, want 1", tag.RowsAffected())
	}
	return nil
}

// countAdmin counts rows with the admin (superuser) pool, bypassing RLS.
func countAdmin(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", sql, err)
	}
	return n
}

func TestOrgProvisionCreatesOrgOwnerSlugAndIntent(t *testing.T) {
	t.Parallel()
	app, pool := newStore(t)
	api := newAPIStore(t, pool) // the production role: the grants must line up
	ctx := context.Background()
	owner := makeAccount(t, app)

	o := provisionTeam(t, api, owner)
	if o.Status != platformcontract.StateProvisioning || o.LifecycleGen != 0 || o.HostID != "" {
		t.Errorf("new org = %+v, want provisioning, generation 0, no host", o.Org)
	}
	if o.ConsoleRole != store.ConsoleOwner || !o.IsBillingOwner || o.CreatedBy != owner {
		t.Errorf("new org membership = role %s billing %v created_by %s, want owner, billing owner, %s", o.ConsoleRole, o.IsBillingOwner, o.CreatedBy, owner)
	}
	if !o.PlatformRailEnabled || o.Tenancy != store.TenancyManaged || o.Kind != store.OrgTeam {
		t.Errorf("new org defaults = %+v", o.Org)
	}

	if n := countAdmin(t, pool, `SELECT count(*) FROM org_slugs WHERE org_id=$1::uuid AND slug=$2 AND NOT is_alias`, o.OrgID, o.Slug); n != 1 {
		t.Errorf("org_slugs current rows = %d, want 1", n)
	}
	var verb, key, tenantID string
	if err := pool.QueryRow(ctx,
		`SELECT verb, idempotency_key, payload->>'tenant_id' FROM org_outbox WHERE org_id=$1::uuid AND state='pending'`,
		o.OrgID).Scan(&verb, &key, &tenantID); err != nil {
		t.Fatalf("read create_tenant intent: %v", err)
	}
	if verb != string(store.OutboxCreateTenant) || key != o.OrgID || tenantID != o.OrgID {
		t.Errorf("intent = %s / %s / %s, want create_tenant keyed and addressed by the org id %s", verb, key, tenantID, o.OrgID)
	}

	got, err := api.GetOrg(ctx, owner, o.OrgID)
	if err != nil || got.OrgID != o.OrgID {
		t.Fatalf("GetOrg = %+v, %v", got, err)
	}
	mine, err := api.ListMyOrgs(ctx, owner)
	if err != nil || len(mine) != 1 || mine[0].OrgID != o.OrgID {
		t.Fatalf("ListMyOrgs = %+v, %v; want the one org", mine, err)
	}
	members, err := api.ListOrgMembers(ctx, owner, o.OrgID)
	if err != nil || len(members) != 1 || members[0].AccountID != owner || members[0].ConsoleRole != store.ConsoleOwner {
		t.Fatalf("ListOrgMembers = %+v, %v; want the owner alone", members, err)
	}

	// A personal org: minted slug, individual, one per account.
	p, err := api.ProvisionOrg(ctx, owner, store.ProvisionOrgInput{Kind: store.OrgPersonal, DisplayName: "Personal"})
	if err != nil {
		t.Fatalf("ProvisionOrg(personal): %v", err)
	}
	if err := store.ValidateOrgSlug(p.Slug, store.OrgPersonal); err != nil || p.Tenancy != store.TenancyIndividual {
		t.Errorf("personal org slug %q tenancy %s (%v)", p.Slug, p.Tenancy, err)
	}
	if _, err := api.ProvisionOrg(ctx, owner, store.ProvisionOrgInput{Kind: store.OrgPersonal, DisplayName: "Again"}); !errors.Is(err, store.ErrPersonalOrgExists) {
		t.Errorf("second personal org = %v, want ErrPersonalOrgExists", err)
	}
	mine, err = api.ListMyOrgs(ctx, owner)
	if err != nil || len(mine) != 2 {
		t.Fatalf("ListMyOrgs after personal = %d orgs, %v; want 2", len(mine), err)
	}
}

func TestOrgRLSMemberReadsNonMemberCannot(t *testing.T) {
	t.Parallel()
	app, pool := newStore(t)
	api := newAPIStore(t, pool)
	ctx := context.Background()
	owner := makeAccount(t, app)
	outsider := makeAccount(t, app)
	o := provisionTeam(t, api, owner)

	// Reads: the org is invisible, indistinguishable from a missing one.
	if _, err := api.GetOrg(ctx, outsider, o.OrgID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("outsider GetOrg = %v, want ErrNotFound", err)
	}
	if _, err := api.ListOrgMembers(ctx, outsider, o.OrgID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("outsider ListOrgMembers = %v, want ErrNotFound", err)
	}
	if mine, err := api.ListMyOrgs(ctx, outsider); err != nil || len(mine) != 0 {
		t.Errorf("outsider ListMyOrgs = %+v, %v; want none", mine, err)
	}
	if _, err := api.GetOrg(ctx, owner, "not-a-uuid"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetOrg(non-uuid) = %v, want ErrNotFound", err)
	}
	var orgsSeen, membersSeen int
	if err := asAccount(api, outsider, func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM orgs`).Scan(&orgsSeen); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM org_members`).Scan(&membersSeen)
	}); err != nil {
		t.Fatalf("outsider count: %v", err)
	}
	if orgsSeen != 0 || membersSeen != 0 {
		t.Errorf("outsider sees %d orgs and %d memberships, want 0 and 0", orgsSeen, membersSeen)
	}

	// Writes: an update matches no row; joining the org is refused.
	if err := asAccount(api, outsider, func(ctx context.Context, tx pgx.Tx) error {
		return execOne(ctx, tx, `UPDATE orgs SET display_name='hijacked' WHERE org_id=$1::uuid`, o.OrgID)
	}); err == nil {
		t.Error("outsider renamed an org it does not belong to")
	}
	for _, role := range []string{"owner", "admin", "member"} {
		if err := asAccount(api, outsider, func(ctx context.Context, tx pgx.Tx) error {
			return execOne(ctx, tx,
				`INSERT INTO org_members (org_id, account_id, console_role) VALUES ($1::uuid, $2::uuid, $3)`,
				o.OrgID, outsider, role)
		}); err == nil {
			t.Errorf("outsider joined the org as %s", role)
		}
	}
	if n := countAdmin(t, pool, `SELECT count(*) FROM org_members WHERE org_id=$1::uuid`, o.OrgID); n != 1 {
		t.Errorf("org has %d members after the refused writes, want 1", n)
	}
	if n := countAdmin(t, pool, `SELECT count(*) FROM orgs WHERE org_id=$1::uuid AND display_name='hijacked'`, o.OrgID); n != 0 {
		t.Error("the refused rename landed")
	}
}

func TestOrgRLSMissingContextAndSystemSeeNothing(t *testing.T) {
	t.Parallel()
	app, pool := newStore(t)
	api := newAPIStore(t, pool)
	owner := makeAccount(t, app)
	o := provisionTeam(t, api, owner)

	for name, s := range map[string]*store.Store{"app": app, "api": api} {
		var orgsSeen, membersSeen int
		var isMember bool
		var slugOrg *string
		if err := s.WithSystem(context.Background(), func(ctx context.Context, tx pgx.Tx) error {
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM orgs`).Scan(&orgsSeen); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM org_members`).Scan(&membersSeen); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT sbci_is_org_member($1::uuid, 'member')`, o.OrgID).Scan(&isMember); err != nil {
				return err
			}
			return tx.QueryRow(ctx, `SELECT sbci_slug_org($1)::text`, o.Slug).Scan(&slugOrg)
		}); err != nil {
			t.Fatalf("%s WithSystem: %v", name, err)
		}
		if orgsSeen != 0 || membersSeen != 0 || isMember || slugOrg != nil {
			t.Errorf("%s with no context: orgs %d members %d member %v slug %v; want nothing", name, orgsSeen, membersSeen, isMember, slugOrg)
		}
		// Rule 1: with no context a membership write is refused.
		if err := s.WithSystem(context.Background(), func(ctx context.Context, tx pgx.Tx) error {
			return execOne(ctx, tx,
				`INSERT INTO org_members (org_id, account_id, console_role) VALUES ($1::uuid, $2::uuid, 'member')`, o.OrgID, owner)
		}); err == nil {
			t.Errorf("%s inserted a membership with no tenant context", name)
		}
	}
}

func TestOrgSlugOrgResolvesOnlyForMembers(t *testing.T) {
	t.Parallel()
	app, pool := newStore(t)
	api := newAPIStore(t, pool)
	ctx := context.Background()
	owner := makeAccount(t, app)
	outsider := makeAccount(t, app)
	o := provisionTeam(t, api, owner)
	if _, err := pool.Exec(ctx,
		`INSERT INTO org_slugs (slug, org_id, is_alias, alias_until) VALUES
		   ($1, $3::uuid, true, now() + interval '90 days'),
		   ($2, $3::uuid, true, now() - interval '1 second')`,
		o.Slug+"-old", o.Slug+"-gone", o.OrgID); err != nil {
		t.Fatalf("seed aliases: %v", err)
	}
	resolve := func(acct, slug string) string {
		var got *string
		if err := asAccount(api, acct, func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT sbci_slug_org($1)::text`, slug).Scan(&got)
		}); err != nil {
			t.Fatalf("sbci_slug_org(%s): %v", slug, err)
		}
		if got == nil {
			return ""
		}
		return *got
	}
	cases := []struct {
		name, acct, slug, want string
	}{
		{"member, current slug", owner, o.Slug, o.OrgID},
		{"member, live alias", owner, o.Slug + "-old", o.OrgID},
		{"member, expired alias", owner, o.Slug + "-gone", ""},
		{"member, unknown slug", owner, "no-such-org", ""},
		{"non-member, current slug", outsider, o.Slug, ""},
		{"non-member, live alias", outsider, o.Slug + "-old", ""},
	}
	for _, tc := range cases {
		if got := resolve(tc.acct, tc.slug); got != tc.want {
			t.Errorf("%s: sbci_slug_org(%q) = %q, want %q", tc.name, tc.slug, got, tc.want)
		}
	}
	// sbci_api has no SELECT on org_slugs: the function is its only read.
	if err := asAccount(api, owner, func(ctx context.Context, tx pgx.Tx) error {
		var n int
		return tx.QueryRow(ctx, `SELECT count(*) FROM org_slugs`).Scan(&n)
	}); err == nil {
		t.Error("sbci_api read org_slugs directly; it must have no SELECT")
	}
}

// orgAction is one row of the console-role matrix: run as the actor against
// a fresh fixture, it returns nil when the action was allowed and took effect.
type orgAction struct {
	name string
	run  func(ctx context.Context, tx pgx.Tx, f orgFixture) error
	// allowed by actor: owner, admin, member, outsider.
	owner, admin, member, outsider bool
}

type orgFixture struct {
	org, owner, admin, member, outsider, fresh string
}

func newOrgFixture(t *testing.T, app, api *store.Store) orgFixture {
	t.Helper()
	f := orgFixture{
		owner: makeAccount(t, app), admin: makeAccount(t, app), member: makeAccount(t, app),
		outsider: makeAccount(t, app), fresh: makeAccount(t, app),
	}
	f.org = provisionTeam(t, api, f.owner).OrgID
	if err := asAccount(api, f.owner, func(ctx context.Context, tx pgx.Tx) error {
		if err := execOne(ctx, tx, `INSERT INTO org_members (org_id, account_id, console_role) VALUES ($1::uuid, $2::uuid, 'admin')`, f.org, f.admin); err != nil {
			return err
		}
		return execOne(ctx, tx, `INSERT INTO org_members (org_id, account_id, console_role) VALUES ($1::uuid, $2::uuid, 'member')`, f.org, f.member)
	}); err != nil {
		t.Fatalf("seed admin and member: %v", err)
	}
	return f
}

// countIs fails unless the query returns want.
func countIs(ctx context.Context, tx pgx.Tx, want int, sql string, args ...any) error {
	var n int
	if err := tx.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
		return err
	}
	if n != want {
		return fmt.Errorf("count %d, want %d", n, want)
	}
	return nil
}

// orgRoleMatrix is the console-role matrix (0048's policy table and the rules
// of sbci_org_member_write_ok), one row per action. It runs as sbci_api, so
// the column grant on orgs (0049) is part of what it proves.
var orgRoleMatrix = []orgAction{
	{
		name: "read org", owner: true, admin: true, member: true,
		run: func(ctx context.Context, tx pgx.Tx, f orgFixture) error {
			return countIs(ctx, tx, 1, `SELECT count(*) FROM orgs WHERE org_id=$1::uuid`, f.org)
		},
	},
	{
		name: "list members", owner: true, admin: true, member: true,
		run: func(ctx context.Context, tx pgx.Tx, f orgFixture) error {
			return countIs(ctx, tx, 3, `SELECT count(*) FROM org_members WHERE org_id=$1::uuid`, f.org)
		},
	},
	{
		name: "rename org", owner: true, admin: true,
		run: func(ctx context.Context, tx pgx.Tx, f orgFixture) error {
			return execOne(ctx, tx, `UPDATE orgs SET display_name='Renamed', updated_at=now() WHERE org_id=$1::uuid`, f.org)
		},
	},
	{
		name: "set lifecycle status (host-API client's, not the console's)",
		run: func(ctx context.Context, tx pgx.Tx, f orgFixture) error {
			return execOne(ctx, tx, `UPDATE orgs SET status='active' WHERE org_id=$1::uuid`, f.org)
		},
	},
	{
		name: "delete org (only through the deletion queue)",
		run: func(ctx context.Context, tx pgx.Tx, f orgFixture) error {
			return execOne(ctx, tx, `DELETE FROM orgs WHERE org_id=$1::uuid`, f.org)
		},
	},
	{
		name: "add member", owner: true, admin: true,
		run: func(ctx context.Context, tx pgx.Tx, f orgFixture) error {
			return execOne(ctx, tx, `INSERT INTO org_members (org_id, account_id, console_role) VALUES ($1::uuid, $2::uuid, 'member')`, f.org, f.fresh)
		},
	},
	{
		name: "add admin", owner: true, admin: true,
		run: func(ctx context.Context, tx pgx.Tx, f orgFixture) error {
			return execOne(ctx, tx, `INSERT INTO org_members (org_id, account_id, console_role) VALUES ($1::uuid, $2::uuid, 'admin')`, f.org, f.fresh)
		},
	},
	{
		name: "add owner", owner: true,
		run: func(ctx context.Context, tx pgx.Tx, f orgFixture) error {
			return execOne(ctx, tx, `INSERT INTO org_members (org_id, account_id, console_role) VALUES ($1::uuid, $2::uuid, 'owner')`, f.org, f.fresh)
		},
	},
	{
		name: "promote member to admin", owner: true, admin: true,
		run: func(ctx context.Context, tx pgx.Tx, f orgFixture) error {
			return execOne(ctx, tx, `UPDATE org_members SET console_role='admin' WHERE org_id=$1::uuid AND account_id=$2::uuid`, f.org, f.member)
		},
	},
	{
		name: "promote member to owner", owner: true,
		run: func(ctx context.Context, tx pgx.Tx, f orgFixture) error {
			return execOne(ctx, tx, `UPDATE org_members SET console_role='owner' WHERE org_id=$1::uuid AND account_id=$2::uuid`, f.org, f.member)
		},
	},
	{
		name: "demote the owner", owner: true,
		run: func(ctx context.Context, tx pgx.Tx, f orgFixture) error {
			return execOne(ctx, tx, `UPDATE org_members SET console_role='member' WHERE org_id=$1::uuid AND account_id=$2::uuid`, f.org, f.owner)
		},
	},
	{
		name: "remove member", owner: true, admin: true,
		run: func(ctx context.Context, tx pgx.Tx, f orgFixture) error {
			return execOne(ctx, tx, `DELETE FROM org_members WHERE org_id=$1::uuid AND account_id=$2::uuid`, f.org, f.member)
		},
	},
	{
		name: "remove the owner", owner: true,
		run: func(ctx context.Context, tx pgx.Tx, f orgFixture) error {
			return execOne(ctx, tx, `DELETE FROM org_members WHERE org_id=$1::uuid AND account_id=$2::uuid`, f.org, f.owner)
		},
	},
	{
		name: "move billing ownership to the member", owner: true,
		run: func(ctx context.Context, tx pgx.Tx, f orgFixture) error {
			if err := execOne(ctx, tx, `UPDATE org_members SET is_billing_owner=false WHERE org_id=$1::uuid AND account_id=$2::uuid`, f.org, f.owner); err != nil {
				return err
			}
			return execOne(ctx, tx, `UPDATE org_members SET is_billing_owner=true WHERE org_id=$1::uuid AND account_id=$2::uuid`, f.org, f.member)
		},
	},
}

// TestOrgConsoleRoleMatrix runs every matrix row as each of the four actors,
// each against a fresh org, under the production role sbci_api.
func TestOrgConsoleRoleMatrix(t *testing.T) {
	t.Parallel()
	app, pool := newStore(t)
	api := newAPIStore(t, pool)
	for _, row := range orgRoleMatrix {
		for _, actor := range []struct {
			name    string
			allowed bool
			pick    func(orgFixture) string
		}{
			{"owner", row.owner, func(f orgFixture) string { return f.owner }},
			{"admin", row.admin, func(f orgFixture) string { return f.admin }},
			{"member", row.member, func(f orgFixture) string { return f.member }},
			{"outsider", row.outsider, func(f orgFixture) string { return f.outsider }},
		} {
			t.Run(row.name+"/"+actor.name, func(t *testing.T) {
				t.Parallel()
				f := newOrgFixture(t, app, api)
				err := asAccount(api, actor.pick(f), func(ctx context.Context, tx pgx.Tx) error { return row.run(ctx, tx, f) })
				if actor.allowed && err != nil {
					t.Fatalf("%s may %s, but it was refused: %v", actor.name, row.name, err)
				}
				if !actor.allowed && err == nil {
					t.Fatalf("%s may not %s, but it took effect", actor.name, row.name)
				}
			})
		}
	}
}

// TestOrgMembershipBootstrapRules covers the rows of sbci_org_member_write_ok
// the matrix does not reach: the bootstrap (rule 2) and the personal org
// (rule 3). Each case creates the orgs row as its creator, then attempts one
// membership insert as the named account.
func TestOrgMembershipBootstrapRules(t *testing.T) {
	t.Parallel()
	app, pool := newStore(t)
	api := newAPIStore(t, pool)
	cases := []struct {
		name    string
		kind    string
		byOther bool // the insert runs as another account
		forSelf bool // the row names the inserting account
		role    string
		billing bool
		allowed bool
	}{
		{"creator bootstraps as owner and billing owner", "team", false, true, "owner", true, true},
		{"creator bootstraps without the billing flag", "team", false, true, "owner", false, false},
		{"creator bootstraps as admin", "team", false, true, "admin", true, false},
		{"creator bootstraps someone else", "team", false, false, "owner", true, false},
		{"another account claims the empty org", "team", true, true, "owner", true, false},
		{"creator bootstraps a personal org", "personal", false, true, "owner", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			creator, other := makeAccount(t, app), makeAccount(t, app)
			slug := fmt.Sprintf("boot-%d", subjCounter.Add(1))
			tenancy := "managed"
			if tc.kind == "personal" {
				slug, tenancy = newPersonalSlug(t), "individual"
			}
			var orgID string
			if err := asAccount(api, creator, func(ctx context.Context, tx pgx.Tx) error {
				if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&orgID); err != nil {
					return err
				}
				return execOne(ctx, tx, `INSERT INTO orgs (org_id, kind, slug, display_name, tenancy, created_by)
					VALUES ($1::uuid, $2, $3, 'Boot', $4, $5::uuid)`, orgID, tc.kind, slug, tenancy, creator)
			}); err != nil {
				t.Fatalf("create org row: %v", err)
			}
			actor, subject := creator, creator
			if tc.byOther {
				actor = other
			}
			if tc.forSelf {
				subject = actor
			} else {
				subject = other
			}
			err := asAccount(api, actor, func(ctx context.Context, tx pgx.Tx) error {
				return execOne(ctx, tx, `INSERT INTO org_members (org_id, account_id, console_role, is_billing_owner)
					VALUES ($1::uuid, $2::uuid, $3, $4)`, orgID, subject, tc.role, tc.billing)
			})
			if tc.allowed != (err == nil) {
				t.Fatalf("insert allowed = %v (err %v), want %v", err == nil, err, tc.allowed)
			}
		})
	}

	// Rule 3: once a personal org has its owner, nobody can be added, not even
	// by the owner.
	owner, other := makeAccount(t, app), makeAccount(t, app)
	p, err := api.ProvisionOrg(context.Background(), owner, store.ProvisionOrgInput{Kind: store.OrgPersonal, DisplayName: "Mine"})
	if err != nil {
		t.Fatalf("ProvisionOrg(personal): %v", err)
	}
	if err := asAccount(api, owner, func(ctx context.Context, tx pgx.Tx) error {
		return execOne(ctx, tx, `INSERT INTO org_members (org_id, account_id, console_role) VALUES ($1::uuid, $2::uuid, 'member')`, p.OrgID, other)
	}); err == nil {
		t.Error("a personal org accepted a second member")
	}
	if n := countAdmin(t, pool, `SELECT count(*) FROM org_members WHERE org_id=$1::uuid`, p.OrgID); n != 1 {
		t.Errorf("personal org has %d members, want 1", n)
	}
}

// newPersonalSlug mints a personal org slug.
func newPersonalSlug(t *testing.T) string {
	t.Helper()
	s, err := store.NewPersonalOrgSlug()
	if err != nil {
		t.Fatalf("NewPersonalOrgSlug: %v", err)
	}
	return s
}

func TestOrgProvisioningIsAtomic(t *testing.T) {
	t.Parallel()
	app, pool := newStore(t)
	api := newAPIStore(t, pool)
	ctx := context.Background()
	holder := makeAccount(t, app)
	held := provisionTeam(t, api, holder)

	// A live rename alias held by the first org. A second org asking for that
	// slug passes the orgs and org_members inserts (the current-slug index does
	// not know the alias) and fails at org_slugs: the earlier inserts must roll
	// back with it.
	alias := held.Slug + "-was"
	if _, err := pool.Exec(ctx,
		`INSERT INTO org_slugs (slug, org_id, is_alias, alias_until) VALUES ($1, $2::uuid, true, now() + interval '90 days')`,
		alias, held.OrgID); err != nil {
		t.Fatalf("seed alias: %v", err)
	}
	outboxBefore := countAdmin(t, pool, `SELECT count(*) FROM org_outbox`)

	cases := []struct {
		name string
		in   store.ProvisionOrgInput
		want error
	}{
		{"slug held as a live alias", store.ProvisionOrgInput{Kind: store.OrgTeam, Slug: alias, DisplayName: "Late", Tenancy: store.TenancyManaged}, store.ErrOrgSlugTaken},
		{"slug held as a current slug", store.ProvisionOrgInput{Kind: store.OrgTeam, Slug: held.Slug, DisplayName: "Late", Tenancy: store.TenancyManaged}, store.ErrOrgSlugTaken},
	}
	for _, tc := range cases {
		late := makeAccount(t, app)
		if _, err := api.ProvisionOrg(ctx, late, tc.in); !errors.Is(err, tc.want) {
			t.Fatalf("%s: ProvisionOrg = %v, want %v", tc.name, err, tc.want)
		}
		if n := countAdmin(t, pool, `SELECT count(*) FROM orgs WHERE created_by=$1::uuid`, late); n != 0 {
			t.Errorf("%s: %d orgs row(s) survived the failed provisioning", tc.name, n)
		}
		if n := countAdmin(t, pool, `SELECT count(*) FROM org_members WHERE account_id=$1::uuid`, late); n != 0 {
			t.Errorf("%s: %d membership(s) survived the failed provisioning", tc.name, n)
		}
	}
	if n := countAdmin(t, pool, `SELECT count(*) FROM org_outbox`); n != outboxBefore {
		t.Errorf("org_outbox grew from %d to %d across failed provisionings", outboxBefore, n)
	}

	// A second personal org fails on its own index and leaves nothing.
	owner := makeAccount(t, app)
	if _, err := api.ProvisionOrg(ctx, owner, store.ProvisionOrgInput{Kind: store.OrgPersonal, DisplayName: "One"}); err != nil {
		t.Fatalf("first personal org: %v", err)
	}
	if _, err := api.ProvisionOrg(ctx, owner, store.ProvisionOrgInput{Kind: store.OrgPersonal, DisplayName: "Two"}); !errors.Is(err, store.ErrPersonalOrgExists) {
		t.Fatalf("second personal org = %v, want ErrPersonalOrgExists", err)
	}
	for table, sql := range map[string]string{
		"orgs":        `SELECT count(*) FROM orgs WHERE created_by=$1::uuid`,
		"org_members": `SELECT count(*) FROM org_members WHERE account_id=$1::uuid`,
		"org_slugs":   `SELECT count(*) FROM org_slugs s JOIN orgs o USING (org_id) WHERE o.created_by=$1::uuid`,
		"org_outbox":  `SELECT count(*) FROM org_outbox x JOIN orgs o USING (org_id) WHERE o.created_by=$1::uuid`,
	} {
		if n := countAdmin(t, pool, sql, owner); n != 1 {
			t.Errorf("%s holds %d rows for the account, want exactly the first org's 1", table, n)
		}
	}
}

// orgTableClass is one new table's RLS class (design 3.2) and its expected
// table-level grants per role. A role not listed holds nothing.
type orgTableClass struct {
	table  string
	class  string // "M" (membership RLS) or "S" (system, no RLS)
	grants map[string][]string
}

var orgTableClasses = []orgTableClass{
	{"orgs", "M", map[string][]string{
		"sbci_api": {"SELECT", "INSERT"}, // UPDATE is column-level, pinned below
		"sbci_app": {"SELECT", "INSERT", "UPDATE"},
	}},
	{"org_members", "M", map[string][]string{
		"sbci_api":    {"SELECT", "INSERT", "UPDATE", "DELETE"},
		"sbci_app":    {"SELECT", "INSERT", "UPDATE", "DELETE"},
		"sbci_worker": {"DELETE"}, // M6.9 (0120/0121): the deletion driver removes memberships; its SELECT is column-level
	}},
	{"org_slugs", "S", map[string][]string{
		"sbci_api": {"INSERT"},
		"sbci_app": {"SELECT", "INSERT", "UPDATE"},
	}},
	{"org_sub_seen", "S", map[string][]string{
		"sbci_app": {"SELECT", "INSERT", "UPDATE"},
		// M6.9 (0120): the deletion driver fans members_deactivate out from it;
		// FR-23 (0140): it forgets a purged org's and a deleted account's rows.
		"sbci_worker": {"SELECT", "DELETE"},
	}},
	{"org_outbox", "S", map[string][]string{
		"sbci_api":    {"INSERT"},
		"sbci_app":    {"SELECT", "INSERT", "UPDATE"},
		"sbci_worker": {"SELECT", "INSERT", "UPDATE"}, // M6.4 (0058): the host-API client
	}},
	{"org_reconcile_findings", "S", map[string][]string{
		"sbci_app":    {"SELECT", "INSERT", "UPDATE"},
		"sbci_worker": {"SELECT", "INSERT", "UPDATE"}, // M6.4 (0060): the reconciler
	}},
	{"org_deletion_requests", "S", map[string][]string{ // M6.9 (0120): the console reaches it through definers
		"sbci_app":    {"SELECT", "INSERT", "UPDATE"},
		"sbci_worker": {"SELECT", "INSERT", "UPDATE"}, // the deletion driver
	}},
	{"org_member_departure_notices", "S", map[string][]string{ // M6.9 (0120): admins read through a definer
		"sbci_app":    {"SELECT", "INSERT", "DELETE"},
		"sbci_worker": {"INSERT"},
	}},
	{"org_entitlement_docs", "S", map[string][]string{ // M6.3 (0055/0056): append-only signed documents
		"sbci_worker": {"SELECT", "INSERT"},
		"sbci_app":    {"SELECT", "INSERT"},
	}},
	{"org_usage_days", "S", map[string][]string{ // M7b.2 (0085): the daily usage reports the worker pulls
		"sbci_worker": {"SELECT", "INSERT", "UPDATE"},
		"sbci_app":    {"SELECT", "INSERT", "UPDATE"},
	}},
	{"org_plan_grants", "S", map[string][]string{ // W15-D13 (0095): append-only operator grants; the console reads through a definer
		"sbci_worker": {"SELECT"},
		"sbci_app":    {"SELECT", "INSERT"},
	}},
}

// TestOrgRegistryTableClassesAndGrants checks that every table the M6.1a
// block creates has exactly one class with the matching RLS state, and exactly
// the declared grants for each application role (the aggregator holds nothing
// on the registry; the worker's M6.4 grants on org_outbox and
// org_reconcile_findings are declared below and its column grants on orgs are
// pinned by TestOrgOutboxWorkerAccess).
func TestOrgRegistryTableClassesAndGrants(t *testing.T) {
	t.Parallel()
	_, pool := newStore(t)
	ctx := context.Background()

	// Every table 0047-0050 creates is classified, and only those.
	rows, err := pool.Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname='public' AND (tablename LIKE 'org\_%' OR tablename='orgs')`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	real := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		real[n] = true
	}
	rows.Close()
	declared := map[string]bool{}
	for _, c := range orgTableClasses {
		declared[c.table] = true
		if !real[c.table] {
			t.Errorf("classified table %s does not exist", c.table)
		}
	}
	for n := range real {
		if !declared[n] {
			t.Errorf("table %s has no class in orgTableClasses", n)
		}
	}

	roles := []string{"sbci_api", "sbci_worker", "sbci_aggregator", "sbci_app"}
	privs := []string{"SELECT", "INSERT", "UPDATE", "DELETE"}
	for _, c := range orgTableClasses {
		var rls, force bool
		if err := pool.QueryRow(ctx, `SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = $1::regclass`, c.table).Scan(&rls, &force); err != nil {
			t.Fatalf("read RLS state of %s: %v", c.table, err)
		}
		if want := c.class == "M"; rls != want || force != want {
			t.Errorf("%s (class %s): RLS enabled %v forced %v, want %v", c.table, c.class, rls, force, want)
		}
		for _, role := range roles {
			for _, p := range privs {
				want := false
				for _, g := range c.grants[role] {
					want = want || g == p
				}
				if got := tablePriv(t, pool, role, c.table, p); got != want {
					t.Errorf("%s %s on %s = %v, want %v", role, p, c.table, got, want)
				}
			}
		}
	}

	// sbci_api's UPDATE on orgs is the display name only (plus updated_at).
	for col, want := range map[string]bool{
		"display_name": true, "updated_at": true, "status": false, "lifecycle_gen": false,
		"host_id": false, "slug": false, "tenancy": false, "platform_rail_enabled": false,
		"kind": false, "created_by": false,
	} {
		if got := columnPriv(t, pool, "sbci_api", "orgs", col, "UPDATE"); got != want {
			t.Errorf("sbci_api UPDATE on orgs.%s = %v, want %v", col, got, want)
		}
	}
}

// TestOrgMembershipFunctionsAreHardenedDefiners pins the three functions'
// shape (SECURITY DEFINER, owner sbci_defs, pinned search_path), that a member
// reading org_members does not recurse through its policy, and the EXECUTE
// posture since 0082: only sbci_app and sbci_api hold it (PUBLIC was revoked),
// while the roles with no business on the registry cannot call the functions
// or read a single row of it.
func TestOrgMembershipFunctionsAreHardenedDefiners(t *testing.T) {
	t.Parallel()
	app, pool := newStore(t)
	api := newAPIStore(t, pool)
	ctx := context.Background()
	owner := makeAccount(t, app)
	o := provisionTeam(t, api, owner)

	sigs := []string{
		"sbci_is_org_member(uuid, text)",
		"sbci_org_member_write_ok(uuid, uuid, text, boolean)",
		"sbci_slug_org(text)",
	}
	for _, sig := range sigs {
		var owner string
		var secDef bool
		var config []string
		if err := pool.QueryRow(ctx,
			`SELECT r.rolname, p.prosecdef, p.proconfig
			   FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner
			  WHERE p.oid = $1::regprocedure`, sig).Scan(&owner, &secDef, &config); err != nil {
			t.Fatalf("introspect %s: %v", sig, err)
		}
		// pg_temp last since 0152 (CLOUD-DEFINER-TEMP-2).
		if owner != "sbci_defs" || !secDef || !containsConfig(config, "search_path=pg_catalog, public, pg_temp") {
			t.Errorf("%s: owner %q definer %v config %v; want sbci_defs, true, a pinned search_path", sig, owner, secDef, config)
		}
		for _, role := range []string{"sbci_api", "sbci_app"} {
			if !funcPriv(t, pool, role, sig) {
				t.Errorf("%s lacks EXECUTE on %s; its policies or lookups would fail", role, sig)
			}
		}
		// 0082 (operator ruling A9) revoked the PUBLIC grant 0047 left open:
		// only the roles above hold EXECUTE.
		if publicHasExecute(t, pool, sig) {
			t.Errorf("%s: PUBLIC holds EXECUTE; 0082 revoked it", sig)
		}
	}

	// No recursion: the policy on org_members calls a function that reads
	// org_members (a direct self-query would fail with 42P17).
	if err := asAccount(api, owner, func(ctx context.Context, tx pgx.Tx) error {
		return countIs(ctx, tx, 1, `SELECT count(*) FROM org_members m JOIN orgs o USING (org_id) WHERE o.org_id=$1::uuid`, o.OrgID)
	}); err != nil {
		t.Fatalf("member read of org_members: %v", err)
	}

	// The roles with no registry grant: the functions answer nothing without
	// a context, and the tables refuse them outright.
	for _, role := range []string{"sbci_worker", "sbci_aggregator"} {
		func() {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+pgx.Identifier{role}.Sanitize()); err != nil {
				t.Fatalf("set role %s: %v", role, err)
			}
			// Since 0082 neither role may call the function at all (the
			// worker's own orgs policies are the constant true, so it never
			// evaluates the member policy either).
			var member bool
			err = tx.QueryRow(ctx, `SELECT sbci_is_org_member($1::uuid, 'member')`, o.OrgID).Scan(&member)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Errorf("%s sbci_is_org_member: err=%v member=%v, want permission denied (42501)", role, err, member)
			}
		}()
		func() {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+pgx.Identifier{role}.Sanitize()); err != nil {
				t.Fatalf("set role %s: %v", role, err)
			}
			// M6.4 (0058/0059) gave the worker column grants and its own
			// policy on orgs (TestOrgOutboxWorkerAccess pins them); M6.9
			// (0120/0121) gave it four columns of org_members and DELETE for
			// the deletion driver (TestDeletionWorkerMembershipAccess). It
			// still reads no profile (no name, no email).
			table := map[string]string{"sbci_worker": "account_profiles", "sbci_aggregator": "orgs"}[role]
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM `+pgx.Identifier{table}.Sanitize()).Scan(&n); err == nil {
				t.Errorf("%s read %s (%d rows); it must hold no grant", role, table, n)
			}
		}()
	}

	// An unknown minimum role is never met, even by an owner.
	if err := asAccount(api, owner, func(ctx context.Context, tx pgx.Tx) error {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT sbci_is_org_member($1::uuid, 'superuser')`, o.OrgID).Scan(&ok); err != nil {
			return err
		}
		if ok {
			return errors.New("an unknown min_role was met")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestOrgBillingColumnsAreNullable pins 0050: org_id exists, nullable, on both
// billing tables, so the running release (which never writes it) is unaffected.
func TestOrgBillingColumnsAreNullable(t *testing.T) {
	t.Parallel()
	_, pool := newStore(t)
	for _, table := range []string{"paddle_subscriptions", "checkout_intents"} {
		var nullable, typ string
		if err := pool.QueryRow(context.Background(),
			`SELECT is_nullable, data_type FROM information_schema.columns
			  WHERE table_schema='public' AND table_name=$1 AND column_name='org_id'`, table).Scan(&nullable, &typ); err != nil {
			t.Fatalf("%s.org_id: %v", table, err)
		}
		if nullable != "YES" || typ != "uuid" {
			t.Errorf("%s.org_id is %s nullable=%s, want a nullable uuid", table, typ, nullable)
		}
	}
}
