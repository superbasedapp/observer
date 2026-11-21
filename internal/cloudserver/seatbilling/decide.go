package seatbilling

import (
	"encoding/json"
	"fmt"
)

// Item is one subscription item: a recurring price and its quantity.
type Item struct {
	PriceID  string `json:"price_id"`
	Quantity int64  `json:"quantity"`
}

// Subscription is what the decision needs of an org's Paddle subscription.
type Subscription struct {
	// ID is the Paddle subscription id (sub_...).
	ID string
	// Status is Paddle's subscription status (active, trialing, past_due,
	// paused, canceled).
	Status string
	// Interval is the billing cycle interval (month, year).
	Interval string
	// Items are the subscription's current items, all of them: Paddle's
	// update replaces the whole list, so every item is sent back.
	Items []Item
	// SeatPriceID is the item whose quantity is the seat count.
	SeatPriceID string
	// PeriodStart and PeriodEnd are the current billing period's bounds as
	// Paddle sent them (RFC3339; empty when Paddle sent none, as for a
	// canceled or paused subscription). Read by the seat sync pass to find
	// the period that just closed; the decision itself does not use them.
	PeriodStart string
	PeriodEnd   string
}

// Input is one decision's input.
type Input struct {
	Sub Subscription
	// Seats is the period's seat count (usage.PeriodSeatCount.Seats).
	Seats int64
	// Complete reports that every day of the period has a usage report
	// (usage.PeriodSeatCount.MissingDays is empty).
	Complete bool
	// SeatsMin is the plan minimum from the org's entitlement
	// (entitlements CapSeatsMin; 0 when the plan has none).
	SeatsMin int64
}

// Action is what to do.
type Action string

// The closed Action vocabulary.
const (
	// ActionUpdate: send the quantity change.
	ActionUpdate Action = "update"
	// ActionSkip: change nothing.
	ActionSkip Action = "skip"
	// ActionHold: change nothing now and try again (the input is not yet
	// complete); never treated as done.
	ActionHold Action = "hold"
)

// Reason names the rule that decided.
type Reason string

// The closed Reason vocabulary.
const (
	ReasonNoSubscription   Reason = "no_subscription"
	ReasonNotBilledSeats   Reason = "status_not_billed"
	ReasonTrial            Reason = "trial"
	ReasonNotMonthly       Reason = "not_monthly"
	ReasonSeatItemMissing  Reason = "seat_item_missing"
	ReasonIncompletePeriod Reason = "incomplete_period"
	ReasonUnchanged        Reason = "unchanged"
	ReasonQuantityChanged  Reason = "quantity_changed"
)

// ProrationDoNotBill is the proration mode of every change: nothing is
// charged now, and the next renewal bills the new quantity (billing in
// arrears).
const ProrationDoNotBill = "do_not_bill"

// Decision is the outcome.
type Decision struct {
	Action Action
	Reason Reason
	// Quantity is the seat quantity billed from the next renewal (set on
	// every decision that reached the quantity rule).
	Quantity int64
	// Current is the seat item's quantity now.
	Current int64
}

// rule is one row of the decision table, walked top-down; the first match
// decides. A row sees the computed quantity and the current one.
type rule struct {
	action Action
	reason Reason
	match  func(in Input, quantity, current int64, hasSeat bool) bool
}

// rules is the decision table (one test row each).
func rules() []rule {
	return []rule{
		{ActionSkip, ReasonNoSubscription, func(in Input, _, _ int64, _ bool) bool { return in.Sub.ID == "" }},
		{ActionSkip, ReasonTrial, func(in Input, _, _ int64, _ bool) bool { return in.Sub.Status == "trialing" }},
		{ActionSkip, ReasonNotBilledSeats, func(in Input, _, _ int64, _ bool) bool {
			return in.Sub.Status != "active" && in.Sub.Status != "past_due"
		}},
		{ActionSkip, ReasonNotMonthly, func(in Input, _, _ int64, _ bool) bool { return in.Sub.Interval != "month" }},
		{ActionSkip, ReasonSeatItemMissing, func(_ Input, _, _ int64, hasSeat bool) bool { return !hasSeat }},
		{ActionHold, ReasonIncompletePeriod, func(in Input, _, _ int64, _ bool) bool { return !in.Complete }},
		{ActionSkip, ReasonUnchanged, func(_ Input, q, cur int64, _ bool) bool { return q == cur }},
		{ActionUpdate, ReasonQuantityChanged, func(Input, int64, int64, bool) bool { return true }},
	}
}

// Quantity is the billed seat quantity: the seats, raised to the plan
// minimum, and never below one (a subscription item has a quantity of at
// least one).
func Quantity(seats, seatsMin int64) int64 { return max(seats, seatsMin, 1) }

// Decide applies the decision table.
func Decide(in Input) Decision {
	q := Quantity(in.Seats, in.SeatsMin)
	var cur int64
	hasSeat := false
	for _, it := range in.Sub.Items {
		if it.PriceID == in.Sub.SeatPriceID && in.Sub.SeatPriceID != "" {
			cur, hasSeat = it.Quantity, true
		}
	}
	for _, r := range rules() {
		if r.match(in, q, cur, hasSeat) {
			return Decision{Action: r.action, Reason: r.reason, Quantity: q, Current: cur}
		}
	}
	return Decision{Action: ActionSkip} // unreachable: the last row matches
}

// UpdateRequest is the body of Paddle's PATCH /subscriptions/{id}.
type UpdateRequest struct {
	Items                []Item `json:"items"`
	ProrationBillingMode string `json:"proration_billing_mode"`
}

// Request builds the update for an ActionUpdate decision: every current
// item, in its order, with only the seat item's quantity changed.
func Request(sub Subscription, d Decision) (UpdateRequest, error) {
	if d.Action != ActionUpdate {
		return UpdateRequest{}, fmt.Errorf("seatbilling.Request: decision is %s (%s), not %s", d.Action, d.Reason, ActionUpdate)
	}
	req := UpdateRequest{ProrationBillingMode: ProrationDoNotBill}
	found := false
	for _, it := range sub.Items {
		if it.PriceID == sub.SeatPriceID {
			it.Quantity = d.Quantity
			found = true
		}
		req.Items = append(req.Items, it)
	}
	if !found {
		return UpdateRequest{}, fmt.Errorf("seatbilling.Request: subscription %s has no seat item %s", sub.ID, sub.SeatPriceID)
	}
	return req, nil
}

// Encode returns the request's JSON body.
func (r UpdateRequest) Encode() ([]byte, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("seatbilling.UpdateRequest.Encode: %w", err)
	}
	return b, nil
}
