package entitlementwork_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/entitlementwork"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/entitlements"
)

// fakeSubs is the OrgPlanReader fake (the front-door lane builds the real
// store.OrgSubscription; the lead wires it at merge).
type fakeSubs struct {
	mu   sync.Mutex
	subs map[string]store.PaddleSubscription
	err  error
}

func (f *fakeSubs) OrgSubscription(_ context.Context, org string) (store.PaddleSubscription, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return store.PaddleSubscription{}, f.err
	}
	s, ok := f.subs[org]
	if !ok {
		return store.PaddleSubscription{}, fmt.Errorf("wrapped: %w", store.ErrNotFound)
	}
	return s, nil
}

func (f *fakeSubs) set(org string, s store.PaddleSubscription) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subs[org] = s
}

func sub(plan string, version int, status string) store.PaddleSubscription {
	return store.PaddleSubscription{SubscriptionID: "sub_1", PlanName: plan, PlanVersion: version, Status: status}
}

// fakeGrants is the OrgGrantReader fake (the real one is store.OrgPlanGrant,
// proven on PostgreSQL in internal/cloudserver/store w15_console_test.go).
type fakeGrants struct {
	grants map[string]store.OrgPlanGrant
	err    error
}

func (f fakeGrants) OrgPlanGrant(_ context.Context, org string) (store.OrgPlanGrant, error) {
	if f.err != nil {
		return store.OrgPlanGrant{}, f.err
	}
	g, ok := f.grants[org]
	if !ok {
		return store.OrgPlanGrant{}, fmt.Errorf("wrapped: %w", store.ErrNotFound)
	}
	return g, nil
}

func grant(plan string, version int, until *time.Time) *store.OrgPlanGrant {
	return &store.OrgPlanGrant{Action: store.OrgPlanGrantActionGrant, PlanName: plan, PlanVersion: version, EffectiveUntil: until}
}

func createdTeam(org string, created time.Time) store.OrgEntitlementView {
	v := team(org, "active")
	v.CreatedOnHostAt = created
	return v
}

// TestPlanRules is one case per planRules row, in table order, then the
// fall-through cases each row's match must not take.
func TestPlanRules(t *testing.T) {
	t.Parallel()
	if got, want := entitlementwork.PlanRuleNames(), []string{"subscription", "account_subscription", "org_grant", "launch", "floor"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("plan rules = %v, want %v (one case per row below)", got, want)
	}
	created := testNow.Add(-24 * time.Hour)
	launchEnd := created.Add(entitlementwork.DefaultLaunchWindow).Unix()
	personal := store.OrgEntitlementView{OrgID: orgB, Kind: store.OrgPersonal, Status: "active", CreatedOnHostAt: created}
	grantEnd := testNow.Add(30 * 24 * time.Hour)
	ended := testNow.Add(-time.Second)
	lapsedTeam := createdTeam(orgA, testNow.Add(-entitlementwork.DefaultLaunchWindow-time.Hour))
	cases := []struct {
		name  string
		org   store.OrgEntitlementView
		kind  entitlements.Kind
		sub   *store.PaddleSubscription
		owner *store.PaddleSubscription
		grant *store.OrgPlanGrant
		want  entitlementwork.Plan
		rule  string
	}{
		// One per row.
		{name: "subscription", org: createdTeam(orgA, created), kind: entitlements.KindTeam, sub: ptr(sub("business", 1, "active")), grant: grant("team", 1, nil), want: entitlementwork.Plan{Name: "business", Version: 1}, rule: "subscription"},
		{name: "account_subscription", org: personal, kind: entitlements.KindPersonal, owner: ptr(sub("plus_beta", 5, "active")), grant: grant("personal_free", 2, nil), want: entitlementwork.Plan{Name: "personal_pro", Version: 3}, rule: "account_subscription"},
		{name: "org_grant", org: createdTeam(orgA, created), kind: entitlements.KindTeam, grant: grant("business", 1, nil), want: entitlementwork.Plan{Name: "business", Version: 1}, rule: "org_grant"},
		{name: "launch", org: createdTeam(orgA, created), kind: entitlements.KindTeam, want: entitlementwork.Plan{Name: "team", Version: 1, NotAfter: launchEnd}, rule: "launch"},
		{name: "floor", org: team(orgA, "provisioning"), kind: entitlements.KindTeam, want: entitlementwork.Plan{Name: "team_lapsed", Version: 2}, rule: "floor"},
		// The grant (W15-D13).
		{name: "grant outlives the launch window", org: lapsedTeam, kind: entitlements.KindTeam, grant: grant("team", 1, nil), want: entitlementwork.Plan{Name: "team", Version: 1}, rule: "org_grant"},
		{name: "grant before the create is acked", org: team(orgA, "provisioning"), kind: entitlements.KindTeam, grant: grant("team", 1, nil), want: entitlementwork.Plan{Name: "team", Version: 1}, rule: "org_grant"},
		{name: "bounded grant carries its end", org: lapsedTeam, kind: entitlements.KindTeam, grant: grant("team", 1, &grantEnd), want: entitlementwork.Plan{Name: "team", Version: 1, NotAfter: grantEnd.Unix()}, rule: "org_grant"},
		{name: "ended grant falls to the floor", org: lapsedTeam, kind: entitlements.KindTeam, grant: grant("business", 1, &ended), want: entitlementwork.Plan{Name: "team_lapsed", Version: 2}, rule: "floor"},
		{name: "ended grant falls to launch", org: createdTeam(orgA, created), kind: entitlements.KindTeam, grant: grant("business", 1, &ended), want: entitlementwork.Plan{Name: "team", Version: 1, NotAfter: launchEnd}, rule: "launch"},
		{name: "revoke row grants nothing", org: lapsedTeam, kind: entitlements.KindTeam, grant: &store.OrgPlanGrant{Action: store.OrgPlanGrantActionRevoke}, want: entitlementwork.Plan{Name: "team_lapsed", Version: 2}, rule: "floor"},
		{name: "grant of another kind grants nothing", org: lapsedTeam, kind: entitlements.KindTeam, grant: grant("personal_pro", 1, nil), want: entitlementwork.Plan{Name: "team_lapsed", Version: 2}, rule: "floor"},
		{name: "grant of version zero grants nothing", org: lapsedTeam, kind: entitlements.KindTeam, grant: grant("business", 0, nil), want: entitlementwork.Plan{Name: "team_lapsed", Version: 2}, rule: "floor"},
		{name: "canceled subscription falls to the grant", org: lapsedTeam, kind: entitlements.KindTeam, sub: ptr(sub("team", 1, "canceled")), grant: grant("business", 1, nil), want: entitlementwork.Plan{Name: "business", Version: 1}, rule: "org_grant"},
		// Fall-through.
		{name: "trialing subscription counts", org: createdTeam(orgA, created), kind: entitlements.KindTeam, sub: ptr(sub("team", 1, "trialing")), want: entitlementwork.Plan{Name: "team", Version: 1}},
		{name: "past_due subscription counts", org: createdTeam(orgA, created), kind: entitlements.KindTeam, sub: ptr(sub("team", 1, "past_due")), want: entitlementwork.Plan{Name: "team", Version: 1}},
		// W16-D5: the dunning grace.
		{name: "past_due within grace carries its end", org: lapsedTeam, kind: entitlements.KindTeam, sub: ptr(pastDue("team", testNow.Add(-13*24*time.Hour))), want: entitlementwork.Plan{Name: "team", Version: 1, NotAfter: testNow.Add(24 * time.Hour).Unix()}, rule: "subscription"},
		{name: "past_due past grace falls to the floor", org: lapsedTeam, kind: entitlements.KindTeam, sub: ptr(pastDue("team", testNow.Add(-14*24*time.Hour))), want: entitlementwork.Plan{Name: "team_lapsed", Version: 2}, rule: "floor"},
		{name: "past_due past grace falls to the grant", org: lapsedTeam, kind: entitlements.KindTeam, sub: ptr(pastDue("business", testNow.Add(-30*24*time.Hour))), grant: grant("team", 1, nil), want: entitlementwork.Plan{Name: "team", Version: 1}, rule: "org_grant"},
		{name: "past_due past grace falls to launch", org: createdTeam(orgA, created), kind: entitlements.KindTeam, sub: ptr(pastDue("business", testNow.Add(-15*24*time.Hour))), want: entitlementwork.Plan{Name: "team", Version: 1, NotAfter: launchEnd}, rule: "launch"},
		{name: "canceled subscription falls to launch", org: createdTeam(orgA, created), kind: entitlements.KindTeam, sub: ptr(sub("business", 1, "canceled")), want: entitlementwork.Plan{Name: "team", Version: 1, NotAfter: launchEnd}},
		{name: "paused subscription falls to launch", org: createdTeam(orgA, created), kind: entitlements.KindTeam, sub: ptr(sub("business", 1, "paused")), want: entitlementwork.Plan{Name: "team", Version: 1, NotAfter: launchEnd}},
		{name: "plan of another kind grants nothing", org: createdTeam(orgA, created), kind: entitlements.KindTeam, sub: ptr(sub("personal_pro", 1, "active")), want: entitlementwork.Plan{Name: "team", Version: 1, NotAfter: launchEnd}},
		{name: "unknown plan grants nothing", org: createdTeam(orgA, created), kind: entitlements.KindTeam, sub: ptr(sub("enterprise_gold", 1, "active")), want: entitlementwork.Plan{Name: "team", Version: 1, NotAfter: launchEnd}},
		{name: "version zero grants nothing", org: createdTeam(orgA, created), kind: entitlements.KindTeam, sub: ptr(sub("business", 0, "active")), want: entitlementwork.Plan{Name: "team", Version: 1, NotAfter: launchEnd}},
		{name: "launch window closed", org: createdTeam(orgA, testNow.Add(-entitlementwork.DefaultLaunchWindow)), kind: entitlements.KindTeam, want: entitlementwork.Plan{Name: "team_lapsed", Version: 2}},
		{name: "create not acked: no launch yet", org: team(orgA, "provisioning"), kind: entitlements.KindTeam, want: entitlementwork.Plan{Name: "team_lapsed", Version: 2}},
		{name: "personal org has no launch row", org: personal, kind: entitlements.KindPersonal, want: entitlementwork.Plan{Name: "personal_free", Version: 3}, rule: "floor"},
		{name: "personal subscription", org: personal, kind: entitlements.KindPersonal, sub: ptr(sub("personal_pro", 2, "active")), want: entitlementwork.Plan{Name: "personal_pro", Version: 3}, rule: "subscription"},
		// L-166: the move to the v2 personal plans. A Personal Pro v1
		// subscription (the version migrate-personal re-keyed Plus
		// subscriptions to) and a Personal Pro v1 grant are issued v2,
		// with no write to the row; Business v1 is not carried (its
		// holders move by the price mapping).
		{name: "personal_pro v1 subscription is carried to v3", org: personal, kind: entitlements.KindPersonal, sub: ptr(sub("personal_pro", 1, "active")), want: entitlementwork.Plan{Name: "personal_pro", Version: 3}, rule: "subscription"},
		{name: "personal_pro v1 grant is carried to v3", org: personal, kind: entitlements.KindPersonal, grant: grant("personal_pro", 1, nil), want: entitlementwork.Plan{Name: "personal_pro", Version: 3}, rule: "org_grant"},
		{name: "personal_free v1 grant is carried to v3", org: personal, kind: entitlements.KindPersonal, grant: grant("personal_free", 1, nil), want: entitlementwork.Plan{Name: "personal_free", Version: 3}, rule: "org_grant"},
		{name: "business v1 subscription is not carried", org: lapsedTeam, kind: entitlements.KindTeam, sub: ptr(sub("business", 1, "active")), want: entitlementwork.Plan{Name: "business", Version: 1}, rule: "subscription"},
		// L-167: a Plus purchase (the account plan plus_beta) lands on the
		// owner's personal org as Personal Pro at its newest version.
		{name: "plus trial pairs too", org: personal, kind: entitlements.KindPersonal, owner: ptr(sub("plus_beta", 5, "trialing")), want: entitlementwork.Plan{Name: "personal_pro", Version: 3}, rule: "account_subscription"},
		{name: "plus past_due within grace carries its end", org: personal, kind: entitlements.KindPersonal, owner: ptr(pastDue("plus_beta", testNow.Add(-13*24*time.Hour))), want: entitlementwork.Plan{Name: "personal_pro", Version: 3, NotAfter: testNow.Add(24 * time.Hour).Unix()}, rule: "account_subscription"},
		{name: "plus past grace falls to the floor", org: personal, kind: entitlements.KindPersonal, owner: ptr(pastDue("plus_beta", testNow.Add(-15*24*time.Hour))), want: entitlementwork.Plan{Name: "personal_free", Version: 3}, rule: "floor"},
		{name: "canceled plus falls to the floor", org: personal, kind: entitlements.KindPersonal, owner: ptr(sub("plus_beta", 5, "canceled")), want: entitlementwork.Plan{Name: "personal_free", Version: 3}, rule: "floor"},
		{name: "an unpaired account plan pairs nothing", org: personal, kind: entitlements.KindPersonal, owner: ptr(sub("free", 5, "active")), want: entitlementwork.Plan{Name: "personal_free", Version: 3}, rule: "floor"},
		{name: "the org's own row wins over the owner's", org: personal, kind: entitlements.KindPersonal, sub: ptr(sub("personal_pro", 1, "active")), owner: ptr(sub("plus_beta", 5, "canceled")), want: entitlementwork.Plan{Name: "personal_pro", Version: 3}, rule: "subscription"},
		{name: "a team org never reads an owner", org: lapsedTeam, kind: entitlements.KindTeam, owner: ptr(sub("plus_beta", 5, "active")), want: entitlementwork.Plan{Name: "team_lapsed", Version: 2}, rule: "floor"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			subs := &fakeSubs{subs: map[string]store.PaddleSubscription{}}
			if tc.sub != nil {
				subs.set(tc.org.OrgID, *tc.sub)
			}
			grants := fakeGrants{grants: map[string]store.OrgPlanGrant{}}
			if tc.grant != nil {
				grants.grants[tc.org.OrgID] = *tc.grant
			}
			owners := fakeOwners{}
			if tc.owner != nil {
				owners[tc.org.OrgID] = *tc.owner
			}
			p := entitlementwork.SubscriptionPlans{Subs: subs, Grants: grants, Owners: owners, Now: func() time.Time { return testNow }}
			got, err := p.PlanFor(context.Background(), tc.org, tc.kind)
			if err != nil || got != tc.want {
				t.Fatalf("PlanFor = %+v, %v; want %+v", got, err, tc.want)
			}
			if tc.rule != "" {
				if _, rule, err := p.Resolve(context.Background(), tc.org, tc.kind); err != nil || rule != tc.rule {
					t.Fatalf("Resolve rule = %q, %v; want %q", rule, err, tc.rule)
				}
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

// fakeOwners is the OwnerPlanReader fake (the real one is
// store.PersonalOrgOwnerSubscription over cloud 0155's definer). A team org
// reaching it is a test failure: the worker reads owners only for a kind an
// account plan pairs into.
type fakeOwners map[string]store.PaddleSubscription

func (f fakeOwners) PersonalOrgOwnerSubscription(_ context.Context, org string) (store.PaddleSubscription, error) {
	if s, ok := f[org]; ok {
		return s, nil
	}
	return store.PaddleSubscription{}, fmt.Errorf("wrapped: %w", store.ErrNotFound)
}

// pastDue is a past_due subscription that entered dunning at since.
func pastDue(plan string, since time.Time) store.PaddleSubscription {
	s := sub(plan, 1, "past_due")
	s.PastDueSince = &since
	return s
}

// TestPastDueGraceIsConfigurable: a configured grace replaces the default.
func TestPastDueGraceIsConfigurable(t *testing.T) {
	t.Parallel()
	org := createdTeam(orgA, testNow.Add(-entitlementwork.DefaultLaunchWindow-time.Hour))
	subs := &fakeSubs{subs: map[string]store.PaddleSubscription{orgA: pastDue("team", testNow.Add(-3*24*time.Hour))}}
	for _, tc := range []struct {
		grace time.Duration
		want  string
	}{
		{0, "team"}, // default 14 days
		{2 * 24 * time.Hour, "team_lapsed"},
		{4 * 24 * time.Hour, "team"},
	} {
		p := entitlementwork.SubscriptionPlans{Subs: subs, Grants: fakeGrants{}, Now: func() time.Time { return testNow }, PastDueGrace: tc.grace}
		got, err := p.PlanFor(context.Background(), org, entitlements.KindTeam)
		if err != nil || got.Name != tc.want {
			t.Fatalf("grace %v: PlanFor = %+v, %v; want %s", tc.grace, got, err, tc.want)
		}
	}
}

// subsAndGrants is one store answering both reads, as *store.Store does.
type subsAndGrants struct {
	*fakeSubs
	fakeGrants
}

// TestPlanSourceFindsGrantsThroughSubs: with no Grants set, a Subs reader that
// also reads grants is used for both (hostapiworker.go composes the worker's
// source with Subs only, so the grant takes effect there with no edit).
func TestPlanSourceFindsGrantsThroughSubs(t *testing.T) {
	t.Parallel()
	both := subsAndGrants{
		fakeSubs:   &fakeSubs{subs: map[string]store.PaddleSubscription{}},
		fakeGrants: fakeGrants{grants: map[string]store.OrgPlanGrant{orgA: *grant("business", 1, nil)}},
	}
	p := entitlementwork.SubscriptionPlans{Subs: both, Now: func() time.Time { return testNow }}
	got, err := p.PlanFor(context.Background(), team(orgA, "active"), entitlements.KindTeam)
	if err != nil || got.Name != "business" {
		t.Fatalf("PlanFor = %+v, %v; want the grant through Subs", got, err)
	}
	// A failed grant read keeps the document in force, like a failed
	// subscription read.
	both.fakeGrants.err = errors.New("connection reset")
	p.Subs = both
	if _, err := p.PlanFor(context.Background(), team(orgA, "active"), entitlements.KindTeam); err == nil {
		t.Fatal("a failed grant read answered a plan")
	}
}

// TestPlanSourceReadOutageKeepsTheDocument: a subscription read that fails
// is an error (the issuer keeps the document in force), never a downgrade.
func TestPlanSourceReadOutageKeepsTheDocument(t *testing.T) {
	t.Parallel()
	subs := &fakeSubs{subs: map[string]store.PaddleSubscription{}, err: errors.New("connection reset")}
	p := entitlementwork.SubscriptionPlans{Subs: subs, Now: func() time.Time { return testNow }}
	if _, err := p.PlanFor(context.Background(), createdTeam(orgA, testNow), entitlements.KindTeam); err == nil {
		t.Fatal("a failed subscription read answered a plan")
	}
	// No reader at all is "no subscription", not an error.
	if got, err := (entitlementwork.SubscriptionPlans{Now: func() time.Time { return testNow }}).PlanFor(context.Background(), team(orgA, "provisioning"), entitlements.KindTeam); err != nil || got.Name != "team_lapsed" {
		t.Fatalf("no reader = %+v, %v", got, err)
	}
	// A launch row naming a plan of another kind is refused, not issued.
	bad := entitlementwork.SubscriptionPlans{
		Launch: []entitlementwork.LaunchPlan{{Kind: entitlements.KindTeam, Plan: "personal_pro"}},
		Now:    func() time.Time { return testNow },
	}
	if _, err := bad.PlanFor(context.Background(), createdTeam(orgA, testNow), entitlements.KindTeam); err == nil {
		t.Fatal("a launch plan of another kind was answered")
	}
}

// TestIssuerLaunchLifecycle walks a team org through the production plan
// source: the floor while its create is in flight, the launch document once
// the create is acked (EnsureOrg, the dispatcher's post-create pass), current
// on the next pass, the paid plan once a subscription exists, and the floor
// again after the subscription ends and the launch window has closed.
func TestIssuerLaunchLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := testNow
	st := newStore(team(orgA, "provisioning"))
	sg := newMemSigner(entKey)
	subs := &fakeSubs{subs: map[string]store.PaddleSubscription{}}
	plans := entitlementwork.SubscriptionPlans{Subs: subs, Now: func() time.Time { return now }}
	iss := newIssuer(t, st, sg, keySet(entKey), plans, &now)

	planOf := func() (entitlements.Body, int64) {
		t.Helper()
		doc, err := st.LatestEntitlementDocument(ctx, orgA)
		if err != nil {
			t.Fatal(err)
		}
		v, err := entitlements.Verify(doc, entitlements.Binding{Org: orgA, Kind: entitlements.KindTeam}, keySet(entKey), 0)
		if err != nil {
			t.Fatalf("stored document does not verify: %v", err)
		}
		return v.Body, doc.Version
	}

	// 1. In flight: the floor document the create carries.
	if o, err := iss.EnsureOrg(ctx, orgA); err != nil || o != entitlementwork.OutcomeIssued {
		t.Fatalf("first = %v, %v", o, err)
	}
	if b, _ := planOf(); b.Plan.Name != "team_lapsed" {
		t.Fatalf("in-flight plan = %+v", b.Plan)
	}

	// 2. The create is acked: the launch document, ending with the window.
	now = now.Add(time.Minute)
	st.mu.Lock()
	st.orgs[0] = createdTeam(orgA, now)
	st.mu.Unlock()
	if o, err := iss.EnsureOrg(ctx, orgA); err != nil || o != entitlementwork.OutcomeIssued {
		t.Fatalf("post-create = %v, %v", o, err)
	}
	b, v2 := planOf()
	if b.Plan.Name != "team" || b.NotAfter != now.Add(entitlementwork.DefaultLaunchWindow).Unix() {
		t.Fatalf("launch document = plan %+v not_after %d", b.Plan, b.NotAfter)
	}
	if len(st.intents) != 2 || st.intents[1].IdempotencyKey != fmt.Sprintf("entitlements:%s:%d", orgA, v2) {
		t.Fatalf("launch intent = %+v", st.intents)
	}

	// 3. Nothing changed: current.
	now = now.Add(time.Hour)
	if o, err := iss.EnsureOrg(ctx, orgA); err != nil || o != entitlementwork.OutcomeCurrent {
		t.Fatalf("repeat = %v, %v", o, err)
	}

	// 4. A subscription: the paid plan, no end.
	subs.set(orgA, sub("team", 1, "active"))
	if o, err := iss.EnsureOrg(ctx, orgA); err != nil || o != entitlementwork.OutcomeIssued {
		t.Fatalf("subscribed = %v, %v", o, err)
	}
	if b, _ := planOf(); b.Plan.Name != "team" || b.NotAfter != 0 {
		t.Fatalf("paid document = plan %+v not_after %d", b.Plan, b.NotAfter)
	}

	// 5. The subscription ends after the launch window closed: the floor.
	now = now.Add(entitlementwork.DefaultLaunchWindow)
	subs.set(orgA, sub("team", 1, "canceled"))
	if o, err := iss.EnsureOrg(ctx, orgA); err != nil || o != entitlementwork.OutcomeIssued {
		t.Fatalf("lapsed = %v, %v", o, err)
	}
	if b, _ := planOf(); b.Plan.Name != "team_lapsed" {
		t.Fatalf("lapsed document = %+v", b.Plan)
	}

	// An org that no longer exists is skipped.
	if o, err := iss.EnsureOrg(ctx, orgB); err != nil || o != entitlementwork.OutcomeSkipped {
		t.Fatalf("unknown org = %v, %v", o, err)
	}
}

// pastDueSub is a past_due subscription that entered past_due at since (nil:
// a row written before cloud 0098 and not yet backfilled).
func pastDueSub(plan string, since *time.Time) *store.PaddleSubscription {
	s := sub(plan, 1, "past_due")
	s.PastDueSince = since
	return &s
}

// TestPastDueDunningWindow is W16-D5 (L-124's 14-day dunning window): a
// past_due subscription carries its plan while now is before entry + grace,
// and from that instant on the org falls through planRules to its grant,
// its launch window or its floor. One case per window position (inside, the
// instant it ends, after) and per fall-through row, plus the legacy row and
// a configured grace.
func TestPastDueDunningWindow(t *testing.T) {
	t.Parallel()
	at := func(d time.Duration) *time.Time { v := testNow.Add(-d); return &v }
	grace := entitlementwork.DefaultPastDueGrace
	if grace != 14*24*time.Hour {
		t.Fatalf("DefaultPastDueGrace = %s, want 14 days (L-124)", grace)
	}
	created := testNow.Add(-24 * time.Hour)
	launchEnd := created.Add(entitlementwork.DefaultLaunchWindow).Unix()
	lapsedTeam := createdTeam(orgA, testNow.Add(-entitlementwork.DefaultLaunchWindow-time.Hour))
	business := entitlementwork.Plan{Name: "business", Version: 1}
	// inGrace is business carried inside the window, its document ending at
	// the window's end (entered + grace: the not_after paddle-live added).
	inGrace := func(entered, g time.Duration) entitlementwork.Plan {
		b := business
		b.NotAfter = testNow.Add(-entered).Add(g).Unix()
		return b
	}
	floor := entitlementwork.Plan{Name: "team_lapsed", Version: 2}
	cases := []struct {
		name  string
		org   store.OrgEntitlementView
		sub   *store.PaddleSubscription
		grant *store.OrgPlanGrant
		grace time.Duration // 0: the default
		want  entitlementwork.Plan
		rule  string
	}{
		{name: "inside the window", org: lapsedTeam, sub: pastDueSub("business", at(13*24*time.Hour)), want: inGrace(13*24*time.Hour, grace), rule: "subscription"},
		{name: "one second before it ends", org: lapsedTeam, sub: pastDueSub("business", at(grace-time.Second)), want: inGrace(grace-time.Second, grace), rule: "subscription"},
		{name: "the instant it ends", org: lapsedTeam, sub: pastDueSub("business", at(grace)), want: floor, rule: "floor"},
		{name: "after it: the floor", org: lapsedTeam, sub: pastDueSub("business", at(20*24*time.Hour)), want: floor, rule: "floor"},
		{name: "after it: the operator grant", org: lapsedTeam, sub: pastDueSub("business", at(20*24*time.Hour)), grant: grant("team", 1, nil), want: entitlementwork.Plan{Name: "team", Version: 1}, rule: "org_grant"},
		{name: "after it: the launch window", org: createdTeam(orgA, created), sub: pastDueSub("business", at(20*24*time.Hour)), want: entitlementwork.Plan{Name: "team", Version: 1, NotAfter: launchEnd}, rule: "launch"},
		{name: "no recorded entry stays live", org: lapsedTeam, sub: pastDueSub("business", nil), want: business, rule: "subscription"},
		{name: "a configured 7-day grace has ended", org: lapsedTeam, sub: pastDueSub("business", at(8*24*time.Hour)), grace: 7 * 24 * time.Hour, want: floor, rule: "floor"},
		{name: "a configured 30-day grace still holds", org: lapsedTeam, sub: pastDueSub("business", at(20*24*time.Hour)), grace: 30 * 24 * time.Hour, want: inGrace(20*24*time.Hour, 30*24*time.Hour), rule: "subscription"},
		{name: "active ignores a stale entry", org: lapsedTeam, sub: func() *store.PaddleSubscription {
			s := sub("business", 1, "active")
			s.PastDueSince = at(90 * 24 * time.Hour)
			return &s
		}(), want: business, rule: "subscription"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			subs := &fakeSubs{subs: map[string]store.PaddleSubscription{tc.org.OrgID: *tc.sub}}
			grants := fakeGrants{grants: map[string]store.OrgPlanGrant{}}
			if tc.grant != nil {
				grants.grants[tc.org.OrgID] = *tc.grant
			}
			p := entitlementwork.SubscriptionPlans{Subs: subs, Grants: grants, PastDueGrace: tc.grace, Now: func() time.Time { return testNow }}
			got, rule, err := p.Resolve(context.Background(), tc.org, entitlements.KindTeam)
			if err != nil || got != tc.want || rule != tc.rule {
				t.Fatalf("Resolve = %+v (%s), %v; want %+v (%s)", got, rule, err, tc.want, tc.rule)
			}
		})
	}
}
