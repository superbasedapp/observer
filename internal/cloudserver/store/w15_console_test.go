package store_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/deletionjournal"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/entitlementwork"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/entitlements"
)

// w15_console_test.go proves the wave 15 console-fixes store changes against
// a real PostgreSQL: the team org cap (W15-D12, cloud 0094) including
// concurrent creates, the operator org plan grant and its place in the plan
// source (W15-D13, cloud 0095), the account deletion refused while the account
// pays for a live org (C2.front-door-5 A), and the owner address sent as
// verified when WorkOS verified it (C2.tenant-cloud-2, cloud 0096).

func provisionTeamSlug(ctx context.Context, s *store.Store, owner, slug string) (store.MyOrg, error) {
	return s.ProvisionOrg(ctx, owner, store.ProvisionOrgInput{
		Kind: store.OrgTeam, Slug: slug, DisplayName: "Team " + slug, Tenancy: store.TenancyManaged,
	})
}

// TestTeamOrgCapRefusesPastTheLimit: three team orgs, then a refusal naming
// the cap; a personal org is not counted; an org being purged frees its
// place; an operator raise lets one more through; 0 bars the account.
func TestTeamOrgCapRefusesPastTheLimit(t *testing.T) {
	t.Parallel()
	app, pool := newStore(t)
	api := newAPIStore(t, pool)
	ctx := context.Background()
	owner := makeAccount(t, app)
	tag := strings.ToLower(owner[:8])

	if _, err := api.ProvisionOrg(ctx, owner, store.ProvisionOrgInput{Kind: store.OrgPersonal, DisplayName: "Me"}); err != nil {
		t.Fatalf("personal org: %v", err)
	}
	var orgs []store.MyOrg
	for i := 0; i < store.DefaultMaxTeamOrgs; i++ {
		o, err := provisionTeamSlug(ctx, api, owner, fmt.Sprintf("cap-%s-%d", tag, i))
		if err != nil {
			t.Fatalf("team %d of %d: %v", i+1, store.DefaultMaxTeamOrgs, err)
		}
		orgs = append(orgs, o)
	}
	if a, err := api.TeamOrgAllowance(ctx, owner); err != nil || a.Used != 3 || a.Limit != 3 || a.Remaining() != 0 || a.Raised {
		t.Fatalf("allowance at the cap = %+v, %v", a, err)
	}
	_, err := provisionTeamSlug(ctx, api, owner, "cap-"+tag+"-x")
	var capErr *store.TeamOrgLimitError
	if !errors.Is(err, store.ErrTeamOrgLimit) || !errors.As(err, &capErr) || capErr.Limit != 3 {
		t.Fatalf("fourth team = %v, want a TeamOrgLimitError of 3", err)
	}
	// The refusal rolled the whole create back: no org, no slug, no intent.
	if n := countAdmin(t, pool, `SELECT count(*) FROM org_slugs WHERE slug = $1`, "cap-"+tag+"-x"); n != 0 {
		t.Fatalf("a refused create left %d slug rows", n)
	}
	if n := countAdmin(t, pool, `SELECT count(*) FROM orgs WHERE created_by = $1::uuid AND kind = 'team'`, owner); n != 3 {
		t.Fatalf("%d team orgs after the refusal, want 3", n)
	}
	// A second account is not affected by the first one's cap.
	if _, err := provisionTeamSlug(ctx, api, makeAccount(t, app), "cap-"+tag+"-other"); err != nil {
		t.Fatalf("another account's first team: %v", err)
	}

	// Pending deletion still counts (it can be restored); purging frees it.
	if _, err := pool.Exec(ctx, `UPDATE orgs SET status = 'pending_deletion' WHERE org_id = $1::uuid`, orgs[0].OrgID); err != nil {
		t.Fatal(err)
	}
	if _, err := provisionTeamSlug(ctx, api, owner, "cap-"+tag+"-y"); !errors.Is(err, store.ErrTeamOrgLimit) {
		t.Fatalf("with one pending deletion = %v, want the cap", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE orgs SET status = 'purging' WHERE org_id = $1::uuid`, orgs[0].OrgID); err != nil {
		t.Fatal(err)
	}
	if _, err := provisionTeamSlug(ctx, api, owner, "cap-"+tag+"-y"); err != nil {
		t.Fatalf("with one purging: %v, want a free place", err)
	}

	// Raised on request: one more.
	prev, err := app.SetTeamOrgLimit(ctx, owner, 4, "  internal: dogfood teams  ", time.Now())
	if err != nil || prev.Limit != 3 || prev.Raised {
		t.Fatalf("raise = %+v, %v; want the default 3 as previous", prev, err)
	}
	if a, err := api.TeamOrgAllowance(ctx, owner); err != nil || a.Limit != 4 || !a.Raised || a.Used != 3 {
		t.Fatalf("allowance after the raise = %+v, %v", a, err)
	}
	if _, err := provisionTeamSlug(ctx, api, owner, "cap-"+tag+"-z"); err != nil {
		t.Fatalf("after the raise: %v", err)
	}
	if _, err := provisionTeamSlug(ctx, api, owner, "cap-"+tag+"-w"); !errors.As(err, &capErr) || capErr.Limit != 4 {
		t.Fatalf("past the raised cap = %v, want 4", err)
	}
	// 0 bars the account; the history keeps every change, newest first.
	if _, err := app.SetTeamOrgLimit(ctx, owner, 0, "abuse report", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := provisionTeamSlug(ctx, api, owner, "cap-"+tag+"-v"); !errors.As(err, &capErr) || capErr.Limit != 0 {
		t.Fatalf("barred account = %v, want a cap of 0", err)
	}
	hist, err := app.TeamOrgLimitHistory(ctx, owner)
	if err != nil || len(hist) != 2 || hist[0].MaxTeamOrgs != 0 || hist[1].MaxTeamOrgs != 4 ||
		hist[1].Reason != "internal: dogfood teams" || hist[0].Actor != "operator" {
		t.Fatalf("history = %+v, %v", hist, err)
	}

	// Bad input and unknown accounts are refused; nothing is written.
	for _, tc := range []struct {
		max    int
		reason string
	}{{-1, "x"}, {store.MaxTeamOrgsCeiling + 1, "x"}, {5, "   "}} {
		if _, err := app.SetTeamOrgLimit(ctx, owner, tc.max, tc.reason, time.Now()); !errors.Is(err, store.ErrTeamOrgLimitInput) {
			t.Errorf("SetTeamOrgLimit(%d, %q) = %v, want ErrTeamOrgLimitInput", tc.max, tc.reason, err)
		}
	}
	for _, id := range []string{"not-a-uuid", "00000000-0000-4000-8000-000000000001"} {
		if _, err := app.SetTeamOrgLimit(ctx, id, 5, "x", time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetTeamOrgLimit(%s) = %v, want ErrNotFound", id, err)
		}
	}
}

// TestTeamOrgCapHoldsUnderConcurrentCreates: many simultaneous creates by one
// account, each with its own slug, make exactly the cap's number of orgs.
func TestTeamOrgCapHoldsUnderConcurrentCreates(t *testing.T) {
	t.Parallel()
	app, pool := newStore(t)
	api := newAPIStore(t, pool)
	ctx := context.Background()
	owner := makeAccount(t, app)
	tag := strings.ToLower(owner[:8])

	const n = 12
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = provisionTeamSlug(ctx, api, owner, fmt.Sprintf("race-%s-%d", tag, i))
		}(i)
	}
	close(start)
	wg.Wait()
	ok, capped := 0, 0
	for i, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, store.ErrTeamOrgLimit):
			capped++
		default:
			t.Errorf("create %d: unexpected error %v", i, err)
		}
	}
	if ok != store.DefaultMaxTeamOrgs || capped != n-store.DefaultMaxTeamOrgs {
		t.Fatalf("concurrent creates: %d made, %d capped; want %d and %d", ok, capped, store.DefaultMaxTeamOrgs, n-store.DefaultMaxTeamOrgs)
	}
	if got := countAdmin(t, pool, `SELECT count(*) FROM orgs WHERE created_by = $1::uuid AND kind = 'team'`, owner); got != store.DefaultMaxTeamOrgs {
		t.Fatalf("%d team org rows, want %d", got, store.DefaultMaxTeamOrgs)
	}
	if got := countAdmin(t, pool,
		`SELECT count(*) FROM org_outbox x JOIN orgs o USING (org_id) WHERE o.created_by = $1::uuid AND x.verb = 'create_tenant'`, owner); got != store.DefaultMaxTeamOrgs {
		t.Fatalf("%d create intents, want %d", got, store.DefaultMaxTeamOrgs)
	}
}

// TestTeamOrgLimitTableIsOperatorOnly: the api role neither reads nor writes
// the raises (it reads only its own cap, through the 0094 definer), the
// worker holds nothing, and no role may rewrite the history.
func TestTeamOrgLimitTableIsOperatorOnly(t *testing.T) {
	t.Parallel()
	_, pool := newStore(t)
	for _, tc := range []struct {
		role string
		want map[string]bool
	}{
		{"sbci_api", nil},
		{"sbci_worker", nil},
		{"sbci_aggregator", nil},
		{"sbci_app", map[string]bool{"SELECT": true, "INSERT": true}},
	} {
		for _, p := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
			if got := tablePriv(t, pool, tc.role, "account_team_org_limits", p); got != tc.want[p] {
				t.Errorf("%s %s on account_team_org_limits = %v, want %v", tc.role, p, got, tc.want[p])
			}
		}
	}
}

// grantPlansAt returns a plan source over the worker store at a fixed time.
func grantPlansAt(worker *store.Store, at time.Time) entitlementwork.SubscriptionPlans {
	return entitlementwork.SubscriptionPlans{Subs: worker, Now: func() time.Time { return at }}
}

// TestOrgPlanGrantPrecedenceInPlanSource: the worker's production plan
// source (SubscriptionPlans over the worker store, no explicit Grants: the
// store is found through Subs as hostapiworker.go composes it) reads the
// operator grant after a live subscription and before the launch window,
// and an ended or revoked grant falls through.
func TestOrgPlanGrantPrecedenceInPlanSource(t *testing.T) {
	t.Parallel()
	f := newOrgBillingFixture(t)
	ctx := context.Background()
	worker := newWorkerStore(t, f.pool)
	var _ entitlementwork.OrgGrantReader = worker
	acked := f.now.Add(-time.Hour)
	inWindow := store.OrgEntitlementView{OrgID: f.org.OrgID, Kind: store.OrgTeam, Status: "active", CreatedOnHostAt: acked}
	afterWindow := f.now.Add(entitlementwork.DefaultLaunchWindow + time.Hour)

	resolve := func(at time.Time) (entitlementwork.Plan, string) {
		t.Helper()
		pl, rule, err := grantPlansAt(worker, at).Resolve(ctx, inWindow, entitlements.KindTeam)
		if err != nil {
			t.Fatalf("Resolve at %s: %v", at, err)
		}
		return pl, rule
	}

	// No grant: launch in the window, then the floor.
	if pl, rule := resolve(f.now); rule != "launch" || pl.Name != "team" {
		t.Fatalf("no grant, in the window: %s %+v", rule, pl)
	}
	if pl, rule := resolve(afterWindow); rule != "floor" || pl.Name != "team_lapsed" {
		t.Fatalf("no grant, after the window: %s %+v", rule, pl)
	}

	// A grant with no end: it beats the launch window and keeps the org on
	// its plan after the window, with no not_after.
	g, prev, err := f.s.GrantOrgPlan(ctx, store.OrgPlanGrantInput{
		OrgID: f.org.OrgID, Kind: store.OrgTeam, Plan: "business", Reason: "internal org (W15-D13)",
	}, f.now)
	if err != nil || prev != nil || g.PlanName != "business" || g.PlanVersion < 1 || g.EffectiveUntil != nil {
		t.Fatalf("grant = %+v prev=%v err=%v", g, prev, err)
	}
	for _, at := range []time.Time{f.now, afterWindow, afterWindow.AddDate(1, 0, 0)} {
		pl, rule := resolve(at)
		if rule != "org_grant" || pl.Name != "business" || pl.Version != g.PlanVersion || pl.NotAfter != 0 {
			t.Fatalf("granted, at %s: %s %+v, want the open business grant", at, rule, pl)
		}
	}

	// A live subscription still wins.
	f.activateOrg(t, "evt_w15_g1", "sub_w15_g", orgTestPriceTeam, f.now)
	if pl, rule := resolve(afterWindow); rule != "subscription" || pl.Name != "team" {
		t.Fatalf("granted and subscribed: %s %+v, want the subscription", rule, pl)
	}
	if _, err := f.s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_w15_g2", EventType: "subscription.canceled", SubscriptionID: "sub_w15_g", CustomerID: "ctm_org",
		PriceID: orgTestPriceTeam, OccurredAt: f.now.Add(time.Minute), Now: f.now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if _, rule := resolve(afterWindow); rule != "org_grant" {
		t.Fatalf("after the cancel: %s, want the grant again", rule)
	}

	// A grant with an end carries it as not_after and falls through after.
	until := f.now.Add(30 * 24 * time.Hour)
	if _, prev, err := f.s.GrantOrgPlan(ctx, store.OrgPlanGrantInput{
		OrgID: f.org.OrgID, Kind: store.OrgTeam, Plan: "team", Version: 1, Until: until, Reason: "pilot",
	}, f.now.Add(2*time.Minute)); err != nil || prev == nil || prev.PlanName != "business" {
		t.Fatalf("second grant: prev=%+v err=%v", prev, err)
	}
	if pl, rule := resolve(afterWindow); rule != "org_grant" || pl.Name != "team" || pl.NotAfter != until.Unix() {
		t.Fatalf("bounded grant: %s %+v, want team until %d", rule, pl, until.Unix())
	}
	if _, rule := resolve(until.Add(time.Second)); rule != "floor" {
		t.Fatalf("after the grant's end: %s, want the floor", rule)
	}

	// Revoke: the org falls back at once; a second revoke has nothing to end.
	if _, err := f.s.RevokeOrgPlan(ctx, f.org.OrgID, "pilot over", f.now.Add(3*time.Minute)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, rule := resolve(f.now.Add(4 * time.Minute)); rule != "launch" {
		t.Fatalf("revoked, in the window: %s, want launch", rule)
	}
	if _, err := f.s.RevokeOrgPlan(ctx, f.org.OrgID, "again", f.now.Add(5*time.Minute)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second revoke = %v, want ErrNotFound", err)
	}
	hist, err := f.s.OrgPlanGrantHistory(ctx, f.org.OrgID)
	if err != nil || len(hist) != 3 || hist[0].Action != "revoke" || hist[1].PlanName != "team" || hist[2].PlanName != "business" ||
		hist[2].Reason != "internal org (W15-D13)" || hist[2].Actor != "operator" {
		t.Fatalf("history = %+v, %v", hist, err)
	}

	// Refusals: a plan of another kind, an unknown plan, no reason, an end in
	// the past, an unknown org.
	for name, in := range map[string]store.OrgPlanGrantInput{
		"personal plan on a team": {OrgID: f.org.OrgID, Kind: store.OrgTeam, Plan: "plus_beta", Reason: "x"},
		"unknown plan":            {OrgID: f.org.OrgID, Kind: store.OrgTeam, Plan: "platinum", Reason: "x"},
		"no reason":               {OrgID: f.org.OrgID, Kind: store.OrgTeam, Plan: "team", Reason: " "},
		"end in the past":         {OrgID: f.org.OrgID, Kind: store.OrgTeam, Plan: "team", Reason: "x", Until: f.now.Add(-time.Hour)},
	} {
		if _, _, err := f.s.GrantOrgPlan(ctx, in, f.now); !errors.Is(err, store.ErrOrgPlanGrantInput) {
			t.Errorf("%s: %v, want ErrOrgPlanGrantInput", name, err)
		}
	}
	for _, id := range []string{"nope", "00000000-0000-4000-8000-000000000002"} {
		if _, _, err := f.s.GrantOrgPlan(ctx, store.OrgPlanGrantInput{OrgID: id, Kind: store.OrgTeam, Plan: "team", Reason: "x"}, f.now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("unknown org %s: %v, want ErrNotFound", id, err)
		}
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM org_plan_grants WHERE org_id = $1::uuid`, f.org.OrgID); n != 3 {
		t.Fatalf("%d grant rows after the refusals, want 3", n)
	}
}

// TestOrgPlanGrantConsoleRead: the console's definer answers an owner and a
// billing owner with the newest row, never a plain member or a stranger, and
// the api role holds no grant on the table.
func TestOrgPlanGrantConsoleRead(t *testing.T) {
	t.Parallel()
	f := newOrgBillingFixture(t)
	ctx := context.Background()
	api := newAPIStore(t, f.pool)
	member := makeAccount(t, f.s)
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO org_members (org_id, account_id, console_role, is_billing_owner) VALUES ($1::uuid, $2::uuid, 'member', false)`,
		f.org.OrgID, member); err != nil {
		t.Fatal(err)
	}
	if _, err := api.PortalOrgPlanGrant(ctx, f.owner, f.org.OrgID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no grant yet = %v, want ErrNotFound", err)
	}
	until := f.now.Add(48 * time.Hour)
	if _, _, err := f.s.GrantOrgPlan(ctx, store.OrgPlanGrantInput{
		OrgID: f.org.OrgID, Kind: store.OrgTeam, Plan: "team", Version: 1, Until: until, Reason: "beta customer",
	}, f.now); err != nil {
		t.Fatal(err)
	}
	g, err := api.PortalOrgPlanGrant(ctx, f.owner, f.org.OrgID)
	if err != nil || g.Action != "grant" || g.PlanName != "team" || g.PlanVersion != 1 || g.EffectiveUntil == nil ||
		!g.EffectiveUntil.Equal(until) || g.Reason != "" || g.Actor != "" {
		t.Fatalf("owner's read = %+v, %v", g, err)
	}
	if _, err := api.PortalOrgPlanGrant(ctx, member, f.org.OrgID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("plain member's read = %v, want ErrNotFound", err)
	}
	if _, err := api.PortalOrgPlanGrant(ctx, makeAccount(t, f.s), f.org.OrgID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("stranger's read = %v, want ErrNotFound", err)
	}
	for _, p := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
		if tablePriv(t, f.pool, "sbci_api", "org_plan_grants", p) {
			t.Errorf("sbci_api holds %s on org_plan_grants", p)
		}
	}
	// The worker reads but cannot write: grants are the operator's.
	if _, _, err := newWorkerStore(t, f.pool).GrantOrgPlan(ctx, store.OrgPlanGrantInput{
		OrgID: f.org.OrgID, Kind: store.OrgTeam, Plan: "team", Reason: "x",
	}, f.now); err == nil {
		t.Fatal("the worker role wrote an org plan grant")
	}
}

// TestDeletionRefusedWhilePayingForLiveOrg: an account that pays for a live
// org is not deleted (nothing purged, no journal record); once the org's
// subscription ends, or the org is on its way out, it is.
func TestDeletionRefusedWhilePayingForLiveOrg(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("refused, then allowed after the cancel", func(t *testing.T) {
		t.Parallel()
		f := newOrgBillingFixture(t)
		journalPath := withJournal(t, f)
		f.activateOrg(t, "evt_w15_d1", "sub_w15_d", orgTestPriceTeam, f.now)

		paid, err := f.s.PaidLiveOrgs(ctx, f.owner)
		if err != nil || len(paid) != 1 || paid[0].OrgID != f.org.OrgID || paid[0].DisplayName != "Acme" {
			t.Fatalf("PaidLiveOrgs = %+v, %v", paid, err)
		}
		_, err = f.s.CreateDeletionRequest(ctx, f.owner, f.now)
		var refusal *store.PaysForLiveOrgError
		if !errors.Is(err, store.ErrDeletionPaysForLiveOrg) || !errors.As(err, &refusal) || len(refusal.Orgs) != 1 || refusal.Orgs[0].Slug != f.org.Slug {
			t.Fatalf("deletion while paying = %v, want a PaysForLiveOrgError naming the org", err)
		}
		// Nothing happened: the account is active, its subscription and
		// identity are there, and the journal has no record to re-apply.
		var status string
		if err := f.pool.QueryRow(ctx, `SELECT status FROM accounts WHERE account_id = $1::uuid`, f.owner).Scan(&status); err != nil || status != "active" {
			t.Fatalf("account status = %q, %v", status, err)
		}
		if n := countAdmin(t, f.pool, `SELECT count(*) FROM paddle_subscriptions WHERE account_id = $1::uuid`, f.owner); n != 1 {
			t.Fatalf("%d subscription rows after the refusal, want 1", n)
		}
		if n := countAdmin(t, f.pool, `SELECT count(*) FROM deletion_requests WHERE account_id = $1::uuid`, f.owner); n != 0 {
			t.Fatalf("%d deletion requests after the refusal", n)
		}
		if b, _ := os.ReadFile(journalPath); strings.Contains(string(b), f.owner) {
			t.Fatalf("the refused deletion was journaled: %s", b)
		}

		if _, err := f.s.ProcessPaddleEvent(ctx, store.PaddleEvent{
			EventID: "evt_w15_d2", EventType: "subscription.canceled", SubscriptionID: "sub_w15_d", CustomerID: "ctm_org",
			PriceID: orgTestPriceTeam, OccurredAt: f.now.Add(time.Hour), Now: f.now.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		if paid, err := f.s.PaidLiveOrgs(ctx, f.owner); err != nil || len(paid) != 0 {
			t.Fatalf("after the cancel PaidLiveOrgs = %+v, %v", paid, err)
		}
		// M6.9: with the billing ended the account is still the team's only
		// owner, so the team must be deleted (or handed over) first.
		_, err = f.s.CreateDeletionRequest(ctx, f.owner, f.now.Add(2*time.Hour))
		if !errors.Is(err, store.ErrAccountDeletionBlocked) {
			t.Fatalf("deletion of the team's only owner after the cancel = %v, want ErrAccountDeletionBlocked", err)
		}
		if _, err := f.pool.Exec(ctx, `UPDATE orgs SET status = 'pending_deletion' WHERE org_id = $1::uuid`, f.org.OrgID); err != nil {
			t.Fatal(err)
		}
		if dr, err := f.s.CreateDeletionRequest(ctx, f.owner, f.now.Add(2*time.Hour)); err != nil || dr.State != "done" {
			t.Fatalf("deletion after the cancel and the team's deletion = %+v, %v", dr, err)
		}
	})

	t.Run("an org on its way out does not hold the account", func(t *testing.T) {
		t.Parallel()
		f := newOrgBillingFixture(t)
		f.activateOrg(t, "evt_w15_d3", "sub_w15_d3", orgTestPriceTeam, f.now)
		if _, err := f.pool.Exec(ctx, `UPDATE orgs SET status = 'pending_deletion' WHERE org_id = $1::uuid`, f.org.OrgID); err != nil {
			t.Fatal(err)
		}
		if dr, err := f.s.CreateDeletionRequest(ctx, f.owner, f.now); err != nil || dr.State != "done" {
			t.Fatalf("deletion with the org pending deletion = %+v, %v", dr, err)
		}
	})

	t.Run("an account plan alone does not hold the account", func(t *testing.T) {
		t.Parallel()
		f := newOrgBillingFixture(t)
		if _, err := f.pool.Exec(ctx,
			`INSERT INTO paddle_subscriptions (account_id, paddle_customer_id, paddle_subscription_id, plan_name, plan_version, status)
			 VALUES ($1::uuid, 'ctm_acct', 'sub_acct', 'plus_beta', 1, 'active')`, f.owner); err != nil {
			t.Fatal(err)
		}
		// The fixture's team is on its way out, so only the account plan is
		// under test (M6.9 would otherwise hold its only owner).
		if _, err := f.pool.Exec(ctx, `UPDATE orgs SET status = 'pending_deletion' WHERE org_id = $1::uuid`, f.org.OrgID); err != nil {
			t.Fatal(err)
		}
		if dr, err := f.s.CreateDeletionRequest(ctx, f.owner, f.now); err != nil || dr.State != "done" {
			t.Fatalf("deletion with an account subscription = %+v, %v", dr, err)
		}
	})

	t.Run("billing for an org the account can no longer see still holds it", func(t *testing.T) {
		t.Parallel()
		f := newOrgBillingFixture(t)
		f.activateOrg(t, "evt_w15_d4", "sub_w15_d4", orgTestPriceTeam, f.now)
		if _, err := f.pool.Exec(ctx, `DELETE FROM org_members WHERE org_id = $1::uuid AND account_id = $2::uuid`, f.org.OrgID, f.owner); err != nil {
			t.Fatal(err)
		}
		_, err := f.s.CreateDeletionRequest(ctx, f.owner, f.now)
		var refusal *store.PaysForLiveOrgError
		if !errors.As(err, &refusal) || len(refusal.Orgs) != 1 || refusal.Orgs[0].OrgID != f.org.OrgID || refusal.Orgs[0].DisplayName != "" {
			t.Fatalf("deletion paying for an invisible org = %v, want a refusal naming only the id", err)
		}
	})
}

// withJournal gives the fixture's store a deletion journal at a known path
// (newStore's own is in a temp dir the fixture does not expose).
func withJournal(t *testing.T, f orgBillingFixture) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "w15-journal.jsonl")
	j, err := deletionjournal.NewFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	f.s.SetDeletionJournal(j)
	return path
}

// TestOrgCreateOwnerAddressVerified: the address and WorkOS's flag come
// together; no row is ErrNotFound; an org no longer being created answers
// nothing; the new 0096 lookup is a one-uuid-in, one-boolean-out definer
// the api cannot call.
func TestOrgCreateOwnerAddressVerified(t *testing.T) {
	t.Parallel()
	f := newOutboxFixture(t)
	ctx := context.Background()

	if _, err := f.worker.OrgCreateOwnerAddress(ctx, f.org.OrgID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no address = %v, want ErrNotFound", err)
	}
	if err := f.app.UpsertVerifiedEmail(ctx, f.owner, "owner@example.test", false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if a, err := f.worker.OrgCreateOwnerAddress(ctx, f.org.OrgID); err != nil || a.Hint != "owner@example.test" || a.Verified {
		t.Fatalf("unverified = %+v, %v", a, err)
	}
	if err := f.app.UpsertVerifiedEmail(ctx, f.owner, "owner@example.test", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if a, err := f.worker.OrgCreateOwnerAddress(ctx, f.org.OrgID); err != nil || a.Hint != "owner@example.test" || !a.Verified {
		t.Fatalf("verified = %+v, %v", a, err)
	}
	// StoreOwners sends it as verified, still bound by subject.
	owner, err := entitlementwork.StoreOwners{Store: f.worker}.Owner(ctx, f.org.OrgID)
	if err != nil || !owner.EmailVerified || owner.Email != "owner@example.test" || owner.Sub == "" {
		t.Fatalf("StoreOwners = %+v, %v", owner, err)
	}
	if _, err := f.worker.OrgCreateOwnerAddress(ctx, "not-a-uuid"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("malformed id = %v", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE orgs SET status = 'active' WHERE org_id = $1::uuid`, f.org.OrgID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.worker.OrgCreateOwnerAddress(ctx, f.org.OrgID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("active org = %v, want ErrNotFound", err)
	}

	var nargs int
	var retset, secdef bool
	var rettype, argtypes string
	if err := f.pool.QueryRow(ctx, `
		SELECT p.pronargs, p.proretset, p.prosecdef, p.prorettype::regtype::text, pg_get_function_identity_arguments(p.oid)
		  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		 WHERE n.nspname = 'public' AND p.proname = 'sbci_org_create_owner_email_verified'`).
		Scan(&nargs, &retset, &secdef, &rettype, &argtypes); err != nil {
		t.Fatal(err)
	}
	if nargs != 1 || retset || !secdef || rettype != "boolean" || argtypes != "p_org uuid" {
		t.Fatalf("verified lookup: %d %s set=%v type=%s definer=%v", nargs, argtypes, retset, rettype, secdef)
	}
	for role, want := range map[string]bool{"sbci_worker": true, "sbci_app": true, "sbci_api": false, "sbci_staff": false, "sbci_aggregator": false} {
		var got bool
		if err := f.pool.QueryRow(ctx, `SELECT has_function_privilege($1, 'sbci_org_create_owner_email_verified(uuid)', 'EXECUTE')`, role).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s EXECUTE = %v, want %v", role, got, want)
		}
	}
}
