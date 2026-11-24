package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/entitlementwork"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/entitlements"
)

// paddle_floor_pg_test.go proves the one plan-version floor (paddle_floor.go)
// on both Paddle branches against PostgreSQL. NEW-12: before the fix an org's
// renewal at a price that still mapped to Business v1 wrote a Business v2 row
// (moved by hand when the live price moves to v2) back to v1, so the worker
// issued the org a v1 entitlement again at the first renewal.

// orgTestPriceBusinessV2 is a price that maps to Business v2.
const orgTestPriceBusinessV2 = "pri_test_business_v2"

// moveOrgRow moves an org subscription row to version v the way an operator
// moves in-force rows when the live price moves (an admin UPDATE).
func moveOrgRow(t *testing.T, f orgBillingFixture, sub string, v int) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE paddle_subscriptions SET plan_version = $2 WHERE paddle_subscription_id = $1`, sub, v); err != nil {
		t.Fatal(err)
	}
}

// TestOrgPlanVersionFloor is NEW-12 on the org path, one fresh org per row:
// what a renewal (or cancellation) at a price mapping to each version leaves
// on the row and in the entitlement the worker issues from it.
func TestOrgPlanVersionFloor(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		// bind is the price the subscription is bought at; moveTo, when
		// non-zero, is the version the row is moved to afterwards.
		bind   string
		moveTo int
		// event is the follow-up delivery (empty: none), at price.
		event string
		price string
		want  int
	}{
		{"renewal at a lower version keeps the moved version", orgTestPriceBusiness, 2, "transaction.completed", orgTestPriceBusiness, 2},
		{"update at a lower version keeps the moved version", orgTestPriceBusiness, 2, "subscription.updated", orgTestPriceBusiness, 2},
		{"renewal at the same version is unchanged", orgTestPriceBusiness, 2, "transaction.completed", orgTestPriceBusinessV2, 2},
		{"renewal at a higher version moves forward", orgTestPriceBusiness, 0, "transaction.completed", orgTestPriceBusinessV2, 2},
		{"a new subscription at v1 binds v1", orgTestPriceBusiness, 0, "", "", 1},
		{"a new subscription at v2 binds v2", orgTestPriceBusinessV2, 0, "", "", 2},
		{"a cancellation at a lower version keeps the moved version", orgTestPriceBusiness, 2, "subscription.canceled", orgTestPriceBusiness, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			f := newOrgBillingFixture(t)
			prices := map[string]store.PaddlePlan{orgTestPriceBusinessV2: {Name: "business", Version: 2, Interval: "month"}}
			for k, v := range orgTestPrices {
				prices[k] = v
			}
			f.s.SetPaddlePriceMap(prices)
			f.activateOrg(t, "evt_bind", "sub_floor", tc.bind, f.now)
			if tc.moveTo != 0 {
				moveOrgRow(t, f, "sub_floor", tc.moveTo)
			}
			if tc.event != "" {
				at := f.now.Add(24 * time.Hour)
				ev := store.PaddleEvent{
					EventID: "evt_next", EventType: tc.event, SubscriptionID: "sub_floor", CustomerID: "ctm_org",
					PriceID: tc.price, OccurredAt: at, CurrentPeriodEnd: at.AddDate(0, 1, 0), Now: at,
				}
				if tc.event == "subscription.updated" {
					ev.Status = "active"
				}
				if in, err := f.s.ProcessPaddleEvent(ctx, ev); err != nil || !in.Applied {
					t.Fatalf("%s: intake=%+v err=%v, want applied", tc.event, in, err)
				}
			}
			sub, err := f.s.OrgSubscription(ctx, f.org.OrgID)
			if err != nil || sub.PlanName != "business" || sub.PlanVersion != tc.want {
				t.Fatalf("row = %s v%d (status %s), err=%v, want business v%d", sub.PlanName, sub.PlanVersion, sub.Status, err, tc.want)
			}
			if sub.Status == "canceled" {
				return // a canceled row issues no plan
			}
			// The entitlement the worker issues from the row follows it.
			worker := newWorkerStore(t, f.pool)
			plans := entitlementwork.SubscriptionPlans{Subs: worker, Now: func() time.Time { return f.now.Add(25 * time.Hour) }}
			view := store.OrgEntitlementView{OrgID: f.org.OrgID, Kind: store.OrgTeam, Status: "active"}
			pl, err := plans.PlanFor(ctx, view, entitlements.KindTeam)
			if err != nil || pl.Name != "business" || pl.Version != tc.want {
				t.Fatalf("entitlement plan = %s v%d, err=%v, want business v%d", pl.Name, pl.Version, err, tc.want)
			}
		})
	}
}

// TestAccountPlanVersionFloorReadsTheRow is the account path's half of the one
// rule: besides the plan in force (D-299), the row's own version is a floor,
// so a row moved forward without its account plan is not written back either,
// and the account is assigned what the row says.
func TestAccountPlanVersionFloorReadsTheRow(t *testing.T) {
	t.Parallel()
	s, acct, now := paddleStore(t) // testPrice maps to plus_beta v1
	ctx := context.Background()
	if in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_act", EventType: "subscription.activated", AccountID: acct,
		CheckoutNonce: mintNonce(t, s, acct, now),
		CustomerID:    "ctm_1", SubscriptionID: "sub_1", Status: "active", PriceID: testPrice,
		OccurredAt: now, CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now,
	}); err != nil || !in.Applied {
		t.Fatalf("activation intake=%+v err=%v, want Applied", in, err)
	}
	// The row alone moves to plus_beta v3 (the account plan stays v1).
	if _, err := s.Pool().Exec(ctx, `UPDATE paddle_subscriptions SET plan_version = 3 WHERE paddle_subscription_id = 'sub_1'`); err != nil {
		t.Fatal(err)
	}
	renewAt := now.Add(time.Hour)
	if in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_renew", EventType: "transaction.completed",
		CustomerID: "ctm_1", SubscriptionID: "sub_1", PriceID: testPrice,
		OccurredAt: renewAt, CurrentPeriodEnd: renewAt.AddDate(0, 1, 0), Now: renewAt,
	}); err != nil || !in.Applied {
		t.Fatalf("renewal intake=%+v err=%v, want Applied", in, err)
	}
	sub, err := s.AccountSubscription(ctx, acct)
	if err != nil || sub.PlanName != store.PlanPlusBeta || sub.PlanVersion != 3 {
		t.Fatalf("row = %+v err=%v, want plus_beta v3 kept", sub, err)
	}
	// The account was assigned the row's version, never scheduled back.
	for _, at := range []time.Time{renewAt, store.NextMonthlyCycleStart(renewAt).Add(time.Hour)} {
		al, err := s.ResolveAllowance(ctx, acct, "session_enrichment", at)
		if err != nil || al.Plan.Name != store.PlanPlusBeta || al.Plan.Version != 3 {
			t.Fatalf("at %s the account is on %s v%d (err %v), want plus_beta v3", at, al.Plan.Name, al.Plan.Version, err)
		}
	}
}
