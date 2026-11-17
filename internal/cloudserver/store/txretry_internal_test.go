package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// TestTxRetrierRun is one row per failure script: which errors fn returns in
// order, how many calls and sleeps result, and the final error.
func TestTxRetrierRun(t *testing.T) {
	t.Parallel()
	dead := fmt.Errorf("wrapped: %w", &pgconn.PgError{Code: "40P01"})
	ser := &pgconn.PgError{Code: "40001"}
	other := &pgconn.PgError{Code: "23505"}
	plain := errors.New("boom")
	cases := []struct {
		name       string
		script     []error
		wantCalls  int
		wantSleeps int
		wantErr    error
	}{
		{"first try succeeds", []error{nil}, 1, 0, nil},
		{"deadlock then ok", []error{dead, nil}, 2, 1, nil},
		{"serialization then ok", []error{ser, nil}, 2, 1, nil},
		{"two failures then ok", []error{dead, ser, nil}, 3, 2, nil},
		{"always deadlock gives up after 3", []error{dead, dead, dead, dead}, 3, 2, dead},
		{"unique violation not retried", []error{other}, 1, 0, other},
		{"plain error not retried", []error{plain}, 1, 0, plain},
		{"deadlock then other stops", []error{dead, plain}, 2, 1, plain},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			calls, sleeps := 0, 0
			var last time.Duration
			r := txRetrier{
				sleep:  func(_ context.Context, d time.Duration) error { sleeps++; last = d; return nil },
				jitter: func() float64 { return 0.5 }, // factor 1.0
			}
			err := r.run(context.Background(), func() error {
				e := c.script[calls]
				calls++
				return e
			})
			if calls != c.wantCalls || sleeps != c.wantSleeps {
				t.Fatalf("calls=%d sleeps=%d, want %d/%d", calls, sleeps, c.wantCalls, c.wantSleeps)
			}
			if !errors.Is(err, c.wantErr) { // errors.Is(nil, nil) holds, so a nil wantErr needs no second test
				t.Fatalf("err=%v, want %v", err, c.wantErr)
			}
			if c.wantSleeps == 2 && last != 2*txRetryBaseBackoff {
				t.Fatalf("second backoff = %v, want doubled", last)
			}
		})
	}
}

// TestTxRetrierCancelledWait: a cancelled context during backoff stops retries.
func TestTxRetrierCancelledWait(t *testing.T) {
	t.Parallel()
	r := txRetrier{sleep: func(context.Context, time.Duration) error { return context.Canceled }}
	calls := 0
	err := r.run(context.Background(), func() error { calls++; return &pgconn.PgError{Code: "40P01"} })
	if calls != 1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}
