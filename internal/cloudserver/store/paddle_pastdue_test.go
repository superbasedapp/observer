package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/db/migrations"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/entitlementwork"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/entitlements"
)

// paddle_pastdue_test.go proves W16-D5's database half on Postgres (cloud
// 0098-0099): the trigger records when an org subscription ENTERED past_due
// from the Paddle event's occurrence time, keeps it across a repeated
// past_due event, clears it on recovery and starts again on a new lapse; the
// worker's and the console's _v2 reads return it; the plan source ends the
// dunning window from it; and 0099 backfills a row that was past_due before
// the trigger existed.

func TestPastDueSinceFollowsTheWebhook(t *testing.T) {
	t.Parallel()
	f := newOrgBillingFixture(t)
	ctx := context.Background()
	worker, err := store.NewForRole(f.pool, store.RoleWorker)
	if err != nil {
		t.Fatal(err)
	}
	f.activateOrg(t, "evt_pd0", "sub_pd", orgTestPriceTeam, f.now)
	t1, t2, t3, t4 := f.now.Add(time.Hour), f.now.Add(2*time.Hour), f.now.Add(3*time.Hour), f.now.Add(4*time.Hour)
	steps := []struct {
		name  string
		ev    store.PaddleEvent
		at    time.Time
		since *time.Time
	}{
		{"enters past_due", store.PaddleEvent{EventType: "subscription.past_due"}, t1, &t1},
		{"still past_due keeps the entry", store.PaddleEvent{EventType: "subscription.updated", Status: "past_due"}, t2, &t1},
		{"recovers", store.PaddleEvent{EventType: "transaction.completed", PriceID: orgTestPriceTeam}, t3, nil},
		{"lapses again: a new window", store.PaddleEvent{EventType: "subscription.past_due"}, t4, &t4},
	}
	for i, st := range steps {
		ev := st.ev
		ev.EventID = "evt_pd" + string(rune('a'+i))
		ev.SubscriptionID, ev.CustomerID = "sub_pd", "ctm_org"
		ev.OccurredAt, ev.Now = st.at, st.at
		if in, err := f.s.ProcessPaddleEvent(ctx, ev); err != nil || !in.Applied {
			t.Fatalf("%s: intake=%+v err=%v", st.name, in, err)
		}
		for reader, read := range map[string]func() (store.PaddleSubscription, error){
			"worker":  func() (store.PaddleSubscription, error) { return worker.OrgSubscription(ctx, f.org.OrgID) },
			"console": func() (store.PaddleSubscription, error) { return f.s.PortalOrgSubscription(ctx, f.owner, f.org.OrgID) },
		} {
			sub, err := read()
			if err != nil {
				t.Fatalf("%s: %s read: %v", st.name, reader, err)
			}
			switch {
			case st.since == nil && sub.PastDueSince != nil:
				t.Fatalf("%s: %s past_due_since = %v, want none", st.name, reader, sub.PastDueSince)
			case st.since != nil && (sub.PastDueSince == nil || !sub.PastDueSince.Equal(*st.since)):
				t.Fatalf("%s: %s past_due_since = %v, want %v", st.name, reader, sub.PastDueSince, *st.since)
			}
		}
	}

	// A direct write of the column does not move the entry.
	if _, err := f.pool.Exec(ctx, `UPDATE paddle_subscriptions SET past_due_since = $2, updated_at = now() WHERE paddle_subscription_id = $1`,
		"sub_pd", f.now.Add(-30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if sub, _ := worker.OrgSubscription(ctx, f.org.OrgID); sub.PastDueSince == nil || !sub.PastDueSince.Equal(t4) {
		t.Fatalf("a direct write moved the entry to %v", sub.PastDueSince)
	}

	// The plan source, over the worker's read: the plan inside the window,
	// the floor once it has ended (the launch window is long gone).
	view := store.OrgEntitlementView{OrgID: f.org.OrgID, Kind: store.OrgTeam, Status: "active", CreatedOnHostAt: f.now.Add(-60 * 24 * time.Hour)}
	for _, c := range []struct {
		now  time.Time
		want string
	}{
		{t4.Add(entitlementwork.DefaultPastDueGrace - time.Minute), "team"},
		{t4.Add(entitlementwork.DefaultPastDueGrace), "team_lapsed"},
	} {
		p := entitlementwork.SubscriptionPlans{Subs: worker, Now: func() time.Time { return c.now }}
		got, err := p.PlanFor(ctx, view, entitlements.KindTeam)
		if err != nil || got.Name != c.want {
			t.Fatalf("plan at %s = %+v, %v; want %s", c.now, got, err, c.want)
		}
	}
}

// TestPastDueSinceBackfill runs 0099's statement against a row that was
// past_due before the trigger existed (the trigger is disabled in this
// test's own database to make one), and again to show it changes nothing.
func TestPastDueSinceBackfill(t *testing.T) {
	t.Parallel()
	f := newOrgBillingFixture(t)
	ctx := context.Background()
	f.activateOrg(t, "evt_bf0", "sub_bf", orgTestPriceTeam, f.now)
	lastEvent := f.now.Add(5 * time.Hour)
	for _, q := range []string{
		`ALTER TABLE paddle_subscriptions DISABLE TRIGGER paddle_subscriptions_past_due_since`,
		`UPDATE paddle_subscriptions SET status = 'past_due', past_due_since = NULL, last_event_at = '` + lastEvent.Format(time.RFC3339) + `' WHERE paddle_subscription_id = 'sub_bf'`,
		`ALTER TABLE paddle_subscriptions ENABLE TRIGGER paddle_subscriptions_past_due_since`,
	} {
		if _, err := f.pool.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	raw, err := migrations.Files.ReadFile("0099_paddle_past_due_since_backfill.sql")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, string(raw)); err != nil {
			t.Fatalf("0099: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		var since *time.Time
		if err := f.pool.QueryRow(ctx, `SELECT past_due_since FROM paddle_subscriptions WHERE paddle_subscription_id = 'sub_bf'`).Scan(&since); err != nil {
			t.Fatal(err)
		}
		if since == nil || !since.Equal(lastEvent) {
			t.Fatalf("backfilled past_due_since = %v, want %v", since, lastEvent)
		}
	}
}
