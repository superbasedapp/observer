package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/entitlementwork"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/entitlements"
)

// TestPlusPurchaseLandsOnPersonalOrg is operator ruling L-167 (2026-11-24:
// Personal Pro is what the Plus subscription buys) end to end on PostgreSQL:
// a Plus activation through the real webhook path writes the account-scoped
// row as before (the account keeps its Plus plan), and the worker, as
// sbci_worker through cloud 0155's definer, issues the account's personal
// org Personal Pro at its newest version. A cancel drops the org back to its
// floor; a team org and an unknown org read nothing.
func TestPlusPurchaseLandsOnPersonalOrg(t *testing.T) {
	s, acct, now := paddleStore(t)
	ctx := context.Background()
	org, _, err := s.EnsurePersonalOrg(ctx, acct, "")
	if err != nil {
		t.Fatal(err)
	}
	worker := newWorkerStore(t, s.Pool())
	var _ entitlementwork.OwnerPlanReader = worker
	plans := entitlementwork.SubscriptionPlans{Subs: worker, Now: func() time.Time { return now }}
	view := store.OrgEntitlementView{OrgID: org.OrgID, Kind: store.OrgPersonal, Status: "active"}

	if pl, rule, err := plans.Resolve(ctx, view, entitlements.KindPersonal); err != nil || rule != "floor" || pl.Name != "personal_free" {
		t.Fatalf("before the purchase: %+v %s %v, want the personal floor", pl, rule, err)
	}
	if _, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_plus", EventType: "subscription.activated", AccountID: acct,
		CheckoutNonce: mintNonce(t, s, acct, now),
		CustomerID:    "ctm_1", SubscriptionID: "sub_plus", Status: "active", PriceID: testPrice,
		OccurredAt: now, CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if sub, err := s.AccountSubscription(ctx, acct); err != nil || sub.PlanName != "plus_beta" || sub.OrgID != "" {
		t.Fatalf("account row = %+v, %v; want the account-scoped Plus row", sub, err)
	}
	want, _ := entitlements.Plan("personal_pro", 0)
	pl, rule, err := plans.Resolve(ctx, view, entitlements.KindPersonal)
	if err != nil || rule != "account_subscription" || pl.Name != want.Plan.Name || pl.Version != want.Plan.Version {
		t.Fatalf("after the purchase: %+v %s %v, want %s v%d", pl, rule, err, want.Plan.Name, want.Plan.Version)
	}

	if _, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_plus_cancel", EventType: "subscription.canceled", AccountID: acct,
		CustomerID: "ctm_1", SubscriptionID: "sub_plus", PriceID: testPrice,
		OccurredAt: now.Add(time.Hour), Now: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if pl, rule, err := plans.Resolve(ctx, view, entitlements.KindPersonal); err != nil || rule != "floor" {
		t.Fatalf("after the cancel: %+v %s %v, want the floor", pl, rule, err)
	}

	team, err := s.ProvisionOrg(ctx, acct, store.ProvisionOrgInput{Kind: store.OrgTeam, Slug: "plus-team", DisplayName: "Team", Tenancy: store.TenancyManaged})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{team.OrgID, "00000000-0000-4000-8000-000000000009"} {
		if _, err := worker.PersonalOrgOwnerSubscription(ctx, id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("PersonalOrgOwnerSubscription(%s) = %v, want ErrNotFound", id, err)
		}
	}
}
