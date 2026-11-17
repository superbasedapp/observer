package seatbilling

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/entitlements"
)

const seatPrice = "pri_seat"

func sub(status, interval string, items ...Item) Subscription {
	return Subscription{ID: "sub_1", Status: status, Interval: interval, Items: items, SeatPriceID: seatPrice}
}

// TestDecideOneRowPerRule: one case per row of the decision table.
func TestDecideOneRowPerRule(t *testing.T) {
	t.Parallel()
	seats := Item{PriceID: seatPrice, Quantity: 5}
	for _, tc := range []struct {
		name   string
		in     Input
		action Action
		reason Reason
		qty    int64
	}{
		{"no subscription", Input{Sub: Subscription{}, Seats: 4, Complete: true}, ActionSkip, ReasonNoSubscription, 4},
		{"trial usage is not billed", Input{Sub: sub("trialing", "month", seats), Seats: 9, Complete: true}, ActionSkip, ReasonTrial, 9},
		{"canceled", Input{Sub: sub("canceled", "month", seats), Seats: 9, Complete: true}, ActionSkip, ReasonNotBilledSeats, 9},
		{"paused", Input{Sub: sub("paused", "month", seats), Seats: 9, Complete: true}, ActionSkip, ReasonNotBilledSeats, 9},
		{"annual is committed seats", Input{Sub: sub("active", "year", seats), Seats: 9, Complete: true}, ActionSkip, ReasonNotMonthly, 9},
		{"no seat item", Input{Sub: sub("active", "month", Item{PriceID: "pri_addon", Quantity: 1}), Seats: 9, Complete: true}, ActionSkip, ReasonSeatItemMissing, 9},
		{"incomplete period holds", Input{Sub: sub("active", "month", seats), Seats: 2, Complete: false}, ActionHold, ReasonIncompletePeriod, 2},
		{"unchanged", Input{Sub: sub("active", "month", seats), Seats: 5, Complete: true}, ActionSkip, ReasonUnchanged, 5},
		{"more seats", Input{Sub: sub("active", "month", seats), Seats: 12, Complete: true}, ActionUpdate, ReasonQuantityChanged, 12},
		{"past due still bills", Input{Sub: sub("past_due", "month", seats), Seats: 7, Complete: true}, ActionUpdate, ReasonQuantityChanged, 7},
		{"fewer seats, raised to the minimum", Input{Sub: sub("active", "month", seats), Seats: 1, SeatsMin: 3, Complete: true}, ActionUpdate, ReasonQuantityChanged, 3},
		{"no seats is still one", Input{Sub: sub("active", "month", Item{PriceID: seatPrice, Quantity: 2}), Seats: 0, Complete: true}, ActionUpdate, ReasonQuantityChanged, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := Decide(tc.in)
			if d.Action != tc.action || d.Reason != tc.reason || d.Quantity != tc.qty {
				t.Fatalf("Decide = %+v, want %s/%s/%d", d, tc.action, tc.reason, tc.qty)
			}
		})
	}
}

// TestTheMinimumComesFromTheEntitlement: the Team and Business minimums are
// the catalog's seats.min caps (plan 06 8.3: 3 and 10), read through the
// entitlement, never a plan name.
func TestTheMinimumComesFromTheEntitlement(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		plan string
		want int64
	}{{"team", 3}, {"business", 10}} {
		b, ok := entitlements.Plan(tc.plan, 0)
		if !ok {
			t.Fatalf("no %s plan", tc.plan)
		}
		minSeats := b.Caps[entitlements.CapSeatsMin]
		if Quantity(2, minSeats) != tc.want {
			t.Errorf("%s: 2 seats bill %d, want %d", tc.plan, Quantity(2, minSeats), tc.want)
		}
	}
}

// TestRequestSendsEveryItem: Paddle replaces the item list, so the request
// carries every item in order and changes only the seat quantity.
func TestRequestSendsEveryItem(t *testing.T) {
	t.Parallel()
	s := sub("active", "month", Item{PriceID: "pri_addon", Quantity: 2}, Item{PriceID: seatPrice, Quantity: 5}, Item{PriceID: "pri_other", Quantity: 1})
	d := Decide(Input{Sub: s, Seats: 8, Complete: true})
	req, err := Request(s, d)
	if err != nil {
		t.Fatal(err)
	}
	body, err := req.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"items":[{"price_id":"pri_addon","quantity":2},{"price_id":"pri_seat","quantity":8},{"price_id":"pri_other","quantity":1}],"proration_billing_mode":"do_not_bill"}`
	if string(body) != want {
		t.Fatalf("body = %s\nwant   %s", body, want)
	}
	if s.Items[1].Quantity != 5 {
		t.Fatal("Request changed the caller's items")
	}
	if _, err := Request(s, Decision{Action: ActionSkip, Reason: ReasonUnchanged}); err == nil || !strings.Contains(err.Error(), "not update") {
		t.Fatalf("Request of a skip = %v", err)
	}
	noSeat := sub("active", "month", Item{PriceID: "pri_addon", Quantity: 2})
	if _, err := Request(noSeat, Decision{Action: ActionUpdate, Quantity: 3}); err == nil {
		t.Fatal("Request without a seat item succeeded")
	}
}
