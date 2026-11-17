package seatbilling

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeAPI is an in-memory Paddle: it records the updates it was sent.
type fakeAPI struct {
	sub       Subscription
	getErr    error
	updateErr error
	// answer, when set, is returned by the update instead of applying it.
	answer  *Subscription
	updates []UpdateRequest
}

func (f *fakeAPI) GetSubscription(_ context.Context, id string) (Subscription, error) {
	if f.getErr != nil {
		return Subscription{}, f.getErr
	}
	if id != f.sub.ID {
		return Subscription{}, errors.New("not found")
	}
	return f.sub, nil
}

func (f *fakeAPI) UpdateSubscriptionItems(_ context.Context, id string, req UpdateRequest) (Subscription, error) {
	f.updates = append(f.updates, req)
	if f.updateErr != nil {
		return Subscription{}, f.updateErr
	}
	if f.answer != nil {
		return *f.answer, nil
	}
	f.sub.Items = append([]Item(nil), req.Items...)
	return f.sub, nil
}

func monthly(items ...Item) Subscription {
	return Subscription{ID: "sub_01", Status: "active", Interval: "month", Items: items}
}

// TestSyncSendsOnlyWhatTheTableDecides: an update is sent once with every
// item; a skip and a hold send nothing.
func TestSyncSendsOnlyWhatTheTableDecides(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := &fakeAPI{sub: monthly(Item{PriceID: "pri_addon", Quantity: 1}, Item{PriceID: seatPrice, Quantity: 3})}
	d, err := Sync(ctx, f, SyncInput{SubscriptionID: "sub_01", SeatPriceID: seatPrice, Seats: 11, Complete: true, SeatsMin: 3})
	if err != nil || d.Action != ActionUpdate || d.Quantity != 11 {
		t.Fatalf("Sync = %+v, %v", d, err)
	}
	if len(f.updates) != 1 || len(f.updates[0].Items) != 2 || f.updates[0].ProrationBillingMode != ProrationDoNotBill {
		t.Fatalf("updates = %+v", f.updates)
	}
	// Same seats again: unchanged, nothing sent.
	if d, err := Sync(ctx, f, SyncInput{SubscriptionID: "sub_01", SeatPriceID: seatPrice, Seats: 11, Complete: true}); err != nil || d.Reason != ReasonUnchanged || len(f.updates) != 1 {
		t.Fatalf("second Sync = %+v, %v, %d updates", d, err, len(f.updates))
	}
	// An incomplete period holds.
	if d, err := Sync(ctx, f, SyncInput{SubscriptionID: "sub_01", SeatPriceID: seatPrice, Seats: 1, Complete: false}); err != nil || d.Action != ActionHold || len(f.updates) != 1 {
		t.Fatalf("incomplete Sync = %+v, %v", d, err)
	}
	// No subscription: nothing read, nothing sent.
	if d, err := Sync(ctx, f, SyncInput{}); err != nil || d.Reason != ReasonNoSubscription {
		t.Fatalf("no-subscription Sync = %+v, %v", d, err)
	}
}

// TestSyncSurfacesFailures: a read error, an update error and an answer
// that does not carry the decided quantity are errors, never a success.
func TestSyncSurfacesFailures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	in := SyncInput{SubscriptionID: "sub_01", SeatPriceID: seatPrice, Seats: 9, Complete: true}
	for _, tc := range []struct {
		name string
		f    *fakeAPI
		want string
	}{
		{"read", &fakeAPI{sub: monthly(Item{PriceID: seatPrice, Quantity: 3}), getErr: errors.New("boom")}, "read sub_01"},
		{"update", &fakeAPI{sub: monthly(Item{PriceID: seatPrice, Quantity: 3}), updateErr: errors.New("boom")}, "update sub_01"},
		{"answer", &fakeAPI{sub: monthly(Item{PriceID: seatPrice, Quantity: 3}), answer: &Subscription{ID: "sub_01", Items: []Item{{PriceID: seatPrice, Quantity: 3}}}}, "without the seat item"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Sync(ctx, tc.f, in); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Sync = %v, want %q", err, tc.want)
			}
		})
	}
}
