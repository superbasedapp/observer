package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/entitlementwork"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/entitlements"
)

// paddle_org_test.go covers the ORG branch of the Paddle subscription store
// (W14-D3, paddle_org.go; docs/security.md PORTALORG-3..6): binding through
// an org checkout intent, the plan transitions (activate, cancel, refund,
// chargeback and its reverse), idempotency, the scope refusals, one live
// subscription per org beside one per account (the 0090 trigger), the
// console's and the worker's reads (0091), and an end-to-end entitlementwork
// plan read through OrgSubscription. The account path is proven unchanged by
// the existing paddle_test.go suite.

const (
	orgTestPriceTeam     = "pri_test_team"
	orgTestPriceBusiness = "pri_test_business"
)

// orgBillingFixture is a database with one team org whose creator is its
// owner and billing owner.
type orgBillingFixture struct {
	s     *store.Store
	pool  *pgxpool.Pool
	owner string
	org   store.MyOrg
	now   time.Time
}

var orgTestPrices = map[string]store.PaddlePlan{
	testPrice:            {Name: "plus_beta", Version: 1},
	orgTestPriceTeam:     {Name: "team", Version: 1, Interval: "month"},
	orgTestPriceBusiness: {Name: "business", Version: 1, Interval: "month"},
}

func newOrgBillingFixture(t *testing.T) orgBillingFixture {
	t.Helper()
	s, pool := newStore(t)
	s.SetPaddlePriceMap(orgTestPrices)
	owner := makeAccount(t, s)
	org, err := s.ProvisionOrg(context.Background(), owner, store.ProvisionOrgInput{
		Kind: store.OrgTeam, Slug: "acme-" + strings.ToLower(owner[:8]), DisplayName: "Acme", Tenancy: store.TenancyManaged,
	})
	if err != nil {
		t.Fatalf("ProvisionOrg: %v", err)
	}
	return orgBillingFixture{s: s, pool: pool, owner: owner, org: org, now: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)}
}

// orgNonce mints an org checkout intent as the billing owner.
func (f orgBillingFixture) orgNonce(t *testing.T, price string) string {
	t.Helper()
	nonce, _, err := f.s.CreateOrgCheckoutIntent(context.Background(), f.owner, f.org.OrgID, price, time.Hour, f.now)
	if err != nil {
		t.Fatalf("CreateOrgCheckoutIntent: %v", err)
	}
	return nonce
}

// activateOrg delivers a binding subscription.activated for the org.
func (f orgBillingFixture) activateOrg(t *testing.T, evt, sub, price string, at time.Time) store.BillingIntake {
	t.Helper()
	in, err := f.s.ProcessPaddleEvent(context.Background(), store.PaddleEvent{
		EventID: evt, EventType: "subscription.activated", AccountID: f.owner, OrgID: f.org.OrgID,
		CheckoutNonce: f.orgNonce(t, price),
		CustomerID:    "ctm_org", SubscriptionID: sub, Status: "active", PriceID: price,
		OccurredAt: at, CurrentPeriodEnd: at.AddDate(0, 1, 0), Now: at,
	})
	if err != nil {
		t.Fatalf("activate org: %v", err)
	}
	return in
}

func TestOrgSubscriptionBindsThroughOrgCheckout(t *testing.T) {
	f := newOrgBillingFixture(t)
	ctx := context.Background()
	in := f.activateOrg(t, "evt_org_1", "sub_org_1", orgTestPriceTeam, f.now)
	if !in.Applied || in.Outcome != "applied" || in.AccountID != f.owner || in.OrgID != f.org.OrgID {
		t.Fatalf("intake = %+v, want applied for the owner and the org", in)
	}
	sub, err := f.s.OrgSubscription(ctx, f.org.OrgID)
	if err != nil {
		t.Fatalf("OrgSubscription: %v", err)
	}
	if sub.PlanName != "team" || sub.PlanVersion != 1 || sub.Status != "active" || sub.SubscriptionID != "sub_org_1" {
		t.Fatalf("org subscription = %+v", sub)
	}
	if sub.CustomerID != "" || sub.ManagementURLs != nil {
		t.Errorf("the worker read carries the customer id or links: %+v", sub)
	}
	// The account path sees no subscription and no paid plan: an org's plan
	// is never an account plan.
	if _, err := f.s.AccountSubscription(ctx, f.owner); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("AccountSubscription = %v, want ErrNotFound (the org row is not the account's)", err)
	}
	if al, err := f.s.ResolveAllowance(ctx, f.owner, "session_enrichment", f.now); err != nil || al.Plan.Name != "free" {
		t.Errorf("account plan after an org activation = %q err=%v, want free", al.Plan.Name, err)
	}
	var orgCol *string
	if err := f.pool.QueryRow(ctx, `SELECT org_id::text FROM paddle_subscriptions WHERE paddle_subscription_id='sub_org_1'`).Scan(&orgCol); err != nil || orgCol == nil || *orgCol != f.org.OrgID {
		t.Fatalf("row org_id = %v err=%v", orgCol, err)
	}
}

func TestOrgSubscriptionIdempotentReplay(t *testing.T) {
	f := newOrgBillingFixture(t)
	ev := store.PaddleEvent{
		EventID: "evt_org_dup", EventType: "subscription.activated", AccountID: f.owner,
		CheckoutNonce: f.orgNonce(t, orgTestPriceTeam),
		CustomerID:    "ctm_org", SubscriptionID: "sub_org_dup", Status: "active", PriceID: orgTestPriceTeam,
		OccurredAt: f.now, Now: f.now,
	}
	if in, err := f.s.ProcessPaddleEvent(context.Background(), ev); err != nil || !in.Applied {
		t.Fatalf("first = %+v err=%v", in, err)
	}
	in, err := f.s.ProcessPaddleEvent(context.Background(), ev)
	if err != nil || !in.Duplicate || in.Applied {
		t.Fatalf("replay = %+v err=%v, want duplicate", in, err)
	}
}

// TestOrgSubscriptionTransitions walks one org subscription through every
// action kind; each step moves only the row (no account plan) and the
// worker's read follows it.
func TestOrgSubscriptionTransitions(t *testing.T) {
	f := newOrgBillingFixture(t)
	ctx := context.Background()
	f.activateOrg(t, "evt_t0", "sub_t", orgTestPriceTeam, f.now)
	steps := []struct {
		name string
		ev   store.PaddleEvent
		want string
	}{
		{"past_due", store.PaddleEvent{EventType: "subscription.past_due"}, "past_due"},
		{"renewal back to active", store.PaddleEvent{EventType: "transaction.completed", PriceID: orgTestPriceTeam}, "active"},
		{"upgrade to business", store.PaddleEvent{EventType: "subscription.updated", Status: "active", PriceID: orgTestPriceBusiness}, "active"},
		{"chargeback revokes", store.PaddleEvent{EventType: "adjustment.created", AdjustmentAction: "chargeback", AdjustmentType: "full"}, "charged_back"},
		{"chargeback reverse restores", store.PaddleEvent{EventType: "adjustment.updated", AdjustmentAction: "chargeback_reverse"}, "active"},
		{"full approved refund revokes", store.PaddleEvent{EventType: "adjustment.updated", AdjustmentAction: "refund", AdjustmentType: "full", AdjustmentStatus: "approved"}, "refunded"},
	}
	at := f.now
	for i, st := range steps {
		at = at.Add(time.Hour)
		ev := st.ev
		ev.EventID = "evt_t" + string(rune('a'+i))
		ev.SubscriptionID = "sub_t"
		ev.CustomerID = "ctm_org"
		ev.OccurredAt, ev.Now = at, at
		in, err := f.s.ProcessPaddleEvent(ctx, ev)
		if err != nil || !in.Applied || in.OrgID != f.org.OrgID {
			t.Fatalf("%s: intake=%+v err=%v", st.name, in, err)
		}
		sub, err := f.s.OrgSubscription(ctx, f.org.OrgID)
		if err != nil || sub.Status != st.want {
			t.Fatalf("%s: status=%q err=%v, want %q", st.name, sub.Status, err, st.want)
		}
		if st.name == "upgrade to business" && sub.PlanName != "business" {
			t.Fatalf("plan after upgrade = %q, want business", sub.PlanName)
		}
		if al, _ := f.s.ResolveAllowance(ctx, f.owner, "session_enrichment", at); al.Plan.Name != "free" {
			t.Fatalf("%s: account plan moved to %q", st.name, al.Plan.Name)
		}
	}
	// A cancellation on a fresh subscription.
	f2 := newOrgBillingFixture(t)
	f2.activateOrg(t, "evt_c0", "sub_c", orgTestPriceTeam, f2.now)
	in, err := f2.s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_c1", EventType: "subscription.canceled", SubscriptionID: "sub_c", CustomerID: "ctm_org",
		PriceID: orgTestPriceTeam, OccurredAt: f2.now.Add(time.Hour), Now: f2.now.Add(time.Hour),
	})
	if err != nil || !in.Applied {
		t.Fatalf("cancel = %+v err=%v", in, err)
	}
	if sub, _ := f2.s.OrgSubscription(ctx, f2.org.OrgID); sub.Status != "canceled" || sub.CanceledAt == nil {
		t.Fatalf("after cancel: %+v", sub)
	}
}

func TestOrgSubscriptionScopeRefusals(t *testing.T) {
	f := newOrgBillingFixture(t)
	ctx := context.Background()
	cases := []struct {
		name  string
		nonce func() string
		org   string
		price string
		note  string
	}{
		{"org price on an account checkout", func() string {
			// The account checkout route refuses an org price; a legacy or
			// hand-made account intent for one is still refused at binding.
			n, _, err := f.s.CreateCheckoutIntent(ctx, f.owner, orgTestPriceTeam, time.Hour, f.now)
			if err != nil {
				t.Fatal(err)
			}
			return n
		}, "", orgTestPriceTeam, "org plan price cannot bind to an account"},
		{"custom_data org on an account checkout", func() string { return mintNonce(t, f.s, f.owner, f.now) }, f.org.OrgID, testPrice, "account checkout"},
		{"custom_data org differs from the intent", func() string { return f.orgNonce(t, orgTestPriceTeam) }, "00000000-0000-0000-0000-000000000001", orgTestPriceTeam, "does not match"},
	}
	for i, tc := range cases {
		in, err := f.s.ProcessPaddleEvent(ctx, store.PaddleEvent{
			EventID: "evt_ref_" + string(rune('a'+i)), EventType: "subscription.activated", AccountID: f.owner, OrgID: tc.org,
			CheckoutNonce: tc.nonce(), CustomerID: "ctm_x", SubscriptionID: "sub_ref_" + string(rune('a'+i)),
			Status: "active", PriceID: tc.price, OccurredAt: f.now, Now: f.now,
		})
		if err != nil || in.Applied || in.Outcome != "binding_refused" || !strings.Contains(in.Note, tc.note) {
			t.Errorf("%s: intake=%+v err=%v", tc.name, in, err)
		}
	}
	if _, err := f.s.OrgSubscription(ctx, f.org.OrgID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a refused binding wrote an org subscription: %v", err)
	}
}

func TestCreateOrgCheckoutIntentRules(t *testing.T) {
	f := newOrgBillingFixture(t)
	ctx := context.Background()
	stranger := makeAccount(t, f.s)
	member := makeAccount(t, f.s)
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO org_members (org_id, account_id, console_role) VALUES ($1::uuid, $2::uuid, 'admin')`,
		f.org.OrgID, member); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		account string
		price   string
		want    error
	}{
		{"billing owner, team price", f.owner, orgTestPriceTeam, nil},
		{"billing owner, account price", f.owner, testPrice, store.ErrBillingUnknownPrice},
		{"billing owner, unknown price", f.owner, "pri_nope", store.ErrBillingUnknownPrice},
		{"admin who is not the billing owner", member, orgTestPriceTeam, store.ErrOrgBillingForbidden},
		{"non-member", stranger, orgTestPriceTeam, store.ErrNotFound},
	}
	for _, tc := range cases {
		_, _, err := f.s.CreateOrgCheckoutIntent(ctx, tc.account, f.org.OrgID, tc.price, time.Hour, f.now)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err=%v, want %v", tc.name, err, tc.want)
		}
	}
	if _, err := f.pool.Exec(ctx, `UPDATE orgs SET status='purging' WHERE org_id=$1::uuid`, f.org.OrgID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.s.CreateOrgCheckoutIntent(ctx, f.owner, f.org.OrgID, orgTestPriceTeam, time.Hour, f.now); !errors.Is(err, store.ErrOrgNotBillable) {
		t.Errorf("purging org: err=%v, want ErrOrgNotBillable", err)
	}
}

// TestOneLivePerOrgAndPerAccount is the 0090 trigger: one account may hold a
// personal subscription AND pay for an org; a second live subscription of the
// same org is refused gracefully even when another account's row (hidden by
// RLS) holds it.
func TestOneLivePerOrgAndPerAccount(t *testing.T) {
	f := newOrgBillingFixture(t)
	ctx := context.Background()
	// Personal Plus, then the org's Team: both apply.
	if in, err := f.s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_personal", EventType: "subscription.activated", AccountID: f.owner,
		CheckoutNonce: mintNonce(t, f.s, f.owner, f.now), CustomerID: "ctm_p", SubscriptionID: "sub_personal",
		Status: "active", PriceID: testPrice, OccurredAt: f.now, Now: f.now,
	}); err != nil || !in.Applied {
		t.Fatalf("personal = %+v err=%v", in, err)
	}
	if in := f.activateOrg(t, "evt_org_a", "sub_org_a", orgTestPriceTeam, f.now); !in.Applied {
		t.Fatalf("org beside personal = %+v", in)
	}
	if sub, err := f.s.AccountSubscription(ctx, f.owner); err != nil || sub.SubscriptionID != "sub_personal" {
		t.Fatalf("account subscription = %+v err=%v", sub, err)
	}
	// The same account, a second live org subscription: refused.
	if in := f.activateOrg(t, "evt_org_b", "sub_org_b", orgTestPriceTeam, f.now.Add(time.Minute)); in.Applied || in.Outcome != "refused_second_live" {
		t.Fatalf("second org subscription = %+v, want refused_second_live", in)
	}

	// Another account's live row for a second org, invisible to the owner's
	// RLS: the owner's activation is refused by the trigger, not errored.
	g := newOrgBillingFixture(t)
	other := makeAccount(t, g.s)
	if _, err := g.pool.Exec(ctx,
		`INSERT INTO paddle_subscriptions (account_id, org_id, paddle_customer_id, paddle_subscription_id, plan_name, plan_version, status)
		 VALUES ($1::uuid, $2::uuid, 'ctm_other', 'sub_other', 'team', 1, 'active')`, other, g.org.OrgID); err != nil {
		t.Fatalf("seed other payer: %v", err)
	}
	in, err := g.s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_g", EventType: "subscription.activated", AccountID: g.owner,
		CheckoutNonce: g.orgNonce(t, orgTestPriceTeam), CustomerID: "ctm_g", SubscriptionID: "sub_g",
		Status: "active", PriceID: orgTestPriceTeam, OccurredAt: g.now, Now: g.now,
	})
	if err != nil || in.Applied || in.Outcome != "refused_second_live" {
		t.Fatalf("cross-account second live = %+v err=%v, want refused_second_live", in, err)
	}
	// The raw trigger still refuses a direct second live write.
	if _, err := g.pool.Exec(ctx,
		`INSERT INTO paddle_subscriptions (account_id, org_id, paddle_customer_id, paddle_subscription_id, plan_name, plan_version, status)
		 VALUES ($1::uuid, $2::uuid, 'ctm_g2', 'sub_g2', 'team', 1, 'trialing')`, g.owner, g.org.OrgID); !isOneLive(err) {
		t.Fatalf("direct second live insert err=%v, want the one-live refusal", err)
	}
	// A canceled row never occupies the slot.
	if _, err := g.pool.Exec(ctx,
		`INSERT INTO paddle_subscriptions (account_id, org_id, paddle_customer_id, paddle_subscription_id, plan_name, plan_version, status)
		 VALUES ($1::uuid, $2::uuid, 'ctm_g3', 'sub_g3', 'team', 1, 'canceled')`, g.owner, g.org.OrgID); err != nil {
		t.Fatalf("canceled row refused: %v", err)
	}
}

// isOneLive reports whether err is the 0090 trigger's refusal: SQLSTATE
// 23505 naming paddle_subscriptions_one_live, as the old index did.
func isOneLive(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "paddle_subscriptions_one_live"
}

func TestPortalOrgSubscriptionAccess(t *testing.T) {
	f := newOrgBillingFixture(t)
	ctx := context.Background()
	f.activateOrg(t, "evt_pa", "sub_pa", orgTestPriceTeam, f.now)
	admin := makeAccount(t, f.s)
	member := makeAccount(t, f.s)
	stranger := makeAccount(t, f.s)
	for acct, role := range map[string]string{admin: "admin", member: "member"} {
		if _, err := f.pool.Exec(ctx,
			`INSERT INTO org_members (org_id, account_id, console_role) VALUES ($1::uuid, $2::uuid, $3)`,
			f.org.OrgID, acct, role); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name    string
		account string
		ok      bool
	}{
		{"owner and billing owner", f.owner, true},
		{"admin", admin, true},
		{"plain member", member, false},
		{"non-member", stranger, false},
	}
	for _, tc := range cases {
		sub, err := f.s.PortalOrgSubscription(ctx, tc.account, f.org.OrgID)
		if tc.ok && (err != nil || sub.SubscriptionID != "sub_pa" || sub.CustomerID != "ctm_org") {
			t.Errorf("%s: sub=%+v err=%v", tc.name, sub, err)
		}
		if !tc.ok && !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s: err=%v, want ErrNotFound", tc.name, err)
		}
	}
	if _, err := f.s.PortalOrgSubscription(ctx, f.owner, "not-a-uuid"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("malformed id: %v", err)
	}
}

// TestOrgSubscriptionDrivesEntitlementPlan is the contract tenant-cloud left
// (W14-D3): the worker, as sbci_worker, reads the org-scoped row through
// OrgSubscription, and entitlementwork's PlanSource picks the subscription
// plan, then falls back when it is canceled.
func TestOrgSubscriptionDrivesEntitlementPlan(t *testing.T) {
	f := newOrgBillingFixture(t)
	ctx := context.Background()
	worker := newWorkerStore(t, f.pool)
	var _ entitlementwork.OrgPlanReader = worker
	plans := entitlementwork.SubscriptionPlans{Subs: worker, Now: func() time.Time { return f.now }}
	view := store.OrgEntitlementView{OrgID: f.org.OrgID, Kind: store.OrgTeam, Status: "active"}

	pl, err := plans.PlanFor(ctx, view, entitlements.KindTeam)
	if err != nil || pl.Name != "team_lapsed" {
		t.Fatalf("no subscription, no launch: plan=%+v err=%v, want the floor", pl, err)
	}
	f.activateOrg(t, "evt_e1", "sub_e", orgTestPriceBusiness, f.now)
	pl, err = plans.PlanFor(ctx, view, entitlements.KindTeam)
	if err != nil || pl.Name != "business" || pl.Version != 1 || pl.NotAfter != 0 {
		t.Fatalf("with a subscription: plan=%+v err=%v, want business", pl, err)
	}
	if _, err := f.s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_e2", EventType: "subscription.canceled", SubscriptionID: "sub_e", CustomerID: "ctm_org",
		PriceID: orgTestPriceBusiness, OccurredAt: f.now.Add(time.Hour), Now: f.now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	pl, err = plans.PlanFor(ctx, view, entitlements.KindTeam)
	if err != nil || pl.Name != "team_lapsed" {
		t.Fatalf("after cancel: plan=%+v err=%v, want the floor", pl, err)
	}
	if _, err := worker.OrgSubscription(ctx, "00000000-0000-0000-0000-000000000002"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown org: %v, want ErrNotFound", err)
	}
}

func TestPaddlePriceKindAndOrgPlanExists(t *testing.T) {
	f := newOrgBillingFixture(t)
	ctx := context.Background()
	kinds := []struct {
		price string
		want  entitlements.Kind
		ok    bool
	}{
		{testPrice, entitlements.KindAccount, true},
		{orgTestPriceTeam, entitlements.KindTeam, true},
		{orgTestPriceBusiness, entitlements.KindTeam, true},
		{"pri_unknown", "", false},
	}
	for _, k := range kinds {
		if got, ok := f.s.PaddlePriceKind(k.price); got != k.want || ok != k.ok {
			t.Errorf("PaddlePriceKind(%s) = %q,%v want %q,%v", k.price, got, ok, k.want, k.ok)
		}
	}
	exists := []struct {
		name    string
		version int
		want    bool
	}{
		{"team", 1, true},
		{"business", store.LatestPlanVersion, true},
		{"team", 2, false},
		{"team_lapsed", 1, true},
	}
	for _, e := range exists {
		if ok, err := f.s.PlanExists(ctx, e.name, e.version); err != nil || ok != e.want {
			t.Errorf("PlanExists(%s, %d) = %v err=%v, want %v", e.name, e.version, ok, err, e.want)
		}
	}
}
