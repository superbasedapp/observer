package seatbilling

import (
	"context"
	"fmt"
)

// API is the Paddle surface Sync needs. paddleapi.Client implements it
// against Paddle's API; tests use a fake.
type API interface {
	// GetSubscription reads a subscription's status, interval and items.
	GetSubscription(ctx context.Context, id string) (Subscription, error)
	// UpdateSubscriptionItems sends PATCH /subscriptions/{id} and returns
	// the subscription Paddle answers with.
	UpdateSubscriptionItems(ctx context.Context, id string, req UpdateRequest) (Subscription, error)
}

// SyncInput is one org's seat sync.
type SyncInput struct {
	// SubscriptionID is the org's Paddle subscription.
	SubscriptionID string
	// SeatPriceID is the seat price on it.
	SeatPriceID string
	// Seats, Complete and SeatsMin are as in Input.
	Seats    int64
	Complete bool
	SeatsMin int64
}

// Sync reads the subscription fresh from Paddle (never a stored copy: the
// item list must be current, since the update replaces it), decides, and
// sends the update when the decision is ActionUpdate. It checks that Paddle
// answered with the decided quantity. A skip or a hold sends nothing.
func Sync(ctx context.Context, api API, in SyncInput) (Decision, error) {
	if in.SubscriptionID == "" {
		return Decide(Input{}), nil
	}
	sub, err := api.GetSubscription(ctx, in.SubscriptionID)
	if err != nil {
		return Decision{}, fmt.Errorf("seatbilling.Sync: read %s: %w", in.SubscriptionID, err)
	}
	sub.SeatPriceID = in.SeatPriceID
	return Apply(ctx, api, sub, in)
}

// Apply decides on a subscription the caller has just read from Paddle and
// sends the update when the decision is ActionUpdate, checking that Paddle
// answered with the decided quantity (Sync's second half; the seat sync
// pass reads the subscription itself because it needs its billing period
// first). sub.SeatPriceID must be set.
func Apply(ctx context.Context, api API, sub Subscription, in SyncInput) (Decision, error) {
	d := Decide(Input{Sub: sub, Seats: in.Seats, Complete: in.Complete, SeatsMin: in.SeatsMin})
	if d.Action != ActionUpdate {
		return d, nil
	}
	req, err := Request(sub, d)
	if err != nil {
		return Decision{}, fmt.Errorf("seatbilling.Sync: %w", err)
	}
	got, err := api.UpdateSubscriptionItems(ctx, sub.ID, req)
	if err != nil {
		return Decision{}, fmt.Errorf("seatbilling.Sync: update %s: %w", sub.ID, err)
	}
	for _, it := range got.Items {
		if it.PriceID == sub.SeatPriceID && it.Quantity == d.Quantity {
			return d, nil
		}
	}
	return Decision{}, fmt.Errorf("seatbilling.Sync: %s answered without the seat item at quantity %d", sub.ID, d.Quantity)
}
