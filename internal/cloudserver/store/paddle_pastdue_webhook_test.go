package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// paddle_pastdue_webhook_test.go (wave 17 lane paddle-live) covers W16-D5's record (cloud 0098
// trigger, through the webhook): the webhook keeps the time a subscription ENTERED
// past_due, keeps it while later dunning deliveries arrive, clears it when
// the subscription leaves past_due, and both the worker's and the console's
// org reads carry it. One row per step.
func TestPastDueSinceFollowsTheStatus(t *testing.T) {
	f := newOrgBillingFixture(t)
	ctx := context.Background()
	f.activateOrg(t, "evt_pd0", "sub_pd", orgTestPriceTeam, f.now)
	entered := f.now.Add(time.Hour)
	steps := []struct {
		name   string
		ev     store.PaddleEvent
		status string
		since  *time.Time // nil: cleared
	}{
		{"enters past_due", store.PaddleEvent{EventType: "subscription.past_due"}, "past_due", &entered},
		{"a failed retry keeps the entry time", store.PaddleEvent{EventType: "transaction.payment_failed"}, "past_due", &entered},
		{"an updated past_due keeps it", store.PaddleEvent{EventType: "subscription.updated", Status: "past_due"}, "past_due", &entered},
		{"payment recovers: cleared", store.PaddleEvent{EventType: "transaction.completed", PriceID: orgTestPriceTeam}, "active", nil},
		{"enters again", store.PaddleEvent{EventType: "subscription.updated", Status: "past_due"}, "past_due", nil /* set below */},
		{"canceled from dunning: cleared", store.PaddleEvent{EventType: "subscription.canceled", PriceID: orgTestPriceTeam}, "canceled", nil},
	}
	at := f.now
	for i, st := range steps {
		at = at.Add(time.Hour)
		ev := st.ev
		ev.EventID = "evt_pd" + string(rune('a'+i))
		ev.SubscriptionID, ev.CustomerID = "sub_pd", "ctm_org"
		ev.OccurredAt, ev.Now = at, at
		in, err := f.s.ProcessPaddleEvent(ctx, ev)
		if err != nil || !in.Applied {
			t.Fatalf("%s: intake=%+v err=%v", st.name, in, err)
		}
		want := st.since
		if st.name == "enters again" {
			again := at
			want = &again
		}
		sub, err := f.s.OrgSubscription(ctx, f.org.OrgID)
		if err != nil || sub.Status != st.status {
			t.Fatalf("%s: status=%q err=%v, want %q", st.name, sub.Status, err, st.status)
		}
		portal, err := f.s.PortalOrgSubscription(ctx, f.owner, f.org.OrgID)
		if err != nil {
			t.Fatalf("%s: PortalOrgSubscription: %v", st.name, err)
		}
		for who, got := range map[string]*time.Time{"worker": sub.PastDueSince, "console": portal.PastDueSince} {
			switch {
			case want == nil && got != nil:
				t.Fatalf("%s: %s past_due_since = %v, want cleared", st.name, who, got)
			case want != nil && (got == nil || !got.Equal(*want)):
				t.Fatalf("%s: %s past_due_since = %v, want %v", st.name, who, got, *want)
			}
		}
	}
}

// TestPastDueSinceOnTheAccountPath: the same stamp on a personal (account)
// subscription, read by AccountSubscription.
func TestPastDueSinceOnTheAccountPath(t *testing.T) {
	s, _ := newStore(t)
	s.SetPaddlePriceMap(orgTestPrices)
	ctx := context.Background()
	acct := makeAccount(t, s)
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	nonce, _, err := s.CreateCheckoutIntent(ctx, acct, testPrice, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	deliver := func(id, typ, status string, at time.Time) {
		t.Helper()
		in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
			EventID: id, EventType: typ, AccountID: acct, CheckoutNonce: nonce, CustomerID: "ctm_acct",
			SubscriptionID: "sub_acct_pd", Status: status, PriceID: testPrice, OccurredAt: at, Now: at,
		})
		if err != nil || !in.Applied {
			t.Fatalf("%s: intake=%+v err=%v", id, in, err)
		}
	}
	deliver("evt_a0", "subscription.activated", "active", now)
	deliver("evt_a1", "subscription.past_due", "past_due", now.Add(time.Hour))
	sub, err := s.AccountSubscription(ctx, acct)
	if err != nil || sub.PastDueSince == nil || !sub.PastDueSince.Equal(now.Add(time.Hour)) {
		t.Fatalf("past_due: %+v err=%v", sub, err)
	}
	deliver("evt_a2", "subscription.updated", "active", now.Add(2*time.Hour))
	if sub, _ := s.AccountSubscription(ctx, acct); sub.PastDueSince != nil {
		t.Fatalf("recovered: past_due_since = %v, want cleared", sub.PastDueSince)
	}
}
