package hostapi

import (
	"testing"
	"time"
)

func TestBackoff(t *testing.T) {
	t.Parallel()
	cases := []struct {
		attempts int
		jitter   float64
		want     time.Duration
	}{
		{0, 0, 2500 * time.Millisecond},   // clamped to attempt 1
		{1, 0, 2500 * time.Millisecond},   // half of 5s
		{1, 0.5, 3750 * time.Millisecond}, // half plus half of the half
		{2, 0, 5 * time.Second},           // 10s base
		{3, 0, 10 * time.Second},          // 20s base
		{20, 0, 30 * time.Minute},         // capped at 1h before jitter
		{20, 0.999, 30*time.Minute + 1798200*time.Millisecond},
		{1, -1, 2500 * time.Millisecond},                         // jitter clamped low
		{1, 7, 2500*time.Millisecond + 2497500*time.Microsecond}, // clamped high
	}
	for _, tc := range cases {
		if got := Backoff(tc.attempts, tc.jitter); got != tc.want {
			t.Errorf("Backoff(%d, %v) = %s, want %s", tc.attempts, tc.jitter, got, tc.want)
		}
		if got := Backoff(tc.attempts, tc.jitter); got > BackoffCap {
			t.Errorf("Backoff(%d, %v) = %s exceeds the cap", tc.attempts, tc.jitter, got)
		}
	}
}

// TestRetryDelay is one case per delayRules row, plus the non-retrying
// actions.
func TestRetryDelay(t *testing.T) {
	t.Parallel()
	cases := []struct {
		action Action
		want   time.Duration
	}{
		{ActionRetry, Backoff(10, 0)},
		{ActionRetryNewRequest, RetryNewRequestCap},
		{ActionWaitlist, Backoff(10, 0)},
		{ActionAck, 0},
		{ActionPark, 0},
	}
	for _, tc := range cases {
		if got := RetryDelay(tc.action, 10, 0); got != tc.want {
			t.Errorf("RetryDelay(%s) = %s, want %s", tc.action, got, tc.want)
		}
	}
	if got := RetryDelay(ActionRetryNewRequest, 1, 0); got != Backoff(1, 0) {
		t.Errorf("an early 409 retry waits %s, want the plain backoff %s", got, Backoff(1, 0))
	}
	if got := RetryDelay(ActionWaitlist, 1, 0); got != WaitlistMinDelay {
		t.Errorf("an early waitlisted retry waits %s, want the floor %s", got, WaitlistMinDelay)
	}
	if got := RetryDelay(ActionWaitlist, 30, 0.999); got > BackoffCap {
		t.Errorf("a waitlisted retry waits %s, above the cap %s", got, BackoffCap)
	}
}

// TestRetryDelayWithWaitlistFloor: a configured waitlist floor replaces the
// default for the waitlist row only, still capped at BackoffCap; the other
// rows ignore it; CheckWaitlistFloor bounds it to [1m, 1h].
func TestRetryDelayWithWaitlistFloor(t *testing.T) {
	t.Parallel()
	o := DelayOptions{WaitlistFloor: 5 * time.Minute}
	if got := RetryDelayWith(ActionWaitlist, 1, 0, o); got != 5*time.Minute {
		t.Errorf("waitlist with a 5m floor = %s", got)
	}
	if got := RetryDelayWith(ActionWaitlist, 1, 0, DelayOptions{}); got != WaitlistMinDelay {
		t.Errorf("waitlist with no floor = %s, want %s", got, WaitlistMinDelay)
	}
	if got := RetryDelayWith(ActionWaitlist, 30, 0.999, o); got > BackoffCap {
		t.Errorf("waitlist past the cap: %s", got)
	}
	for _, a := range []Action{ActionRetry, ActionRetryNewRequest} {
		if got, want := RetryDelayWith(a, 1, 0, o), RetryDelay(a, 1, 0); got != want {
			t.Errorf("%s with a waitlist floor = %s, want %s", a, got, want)
		}
	}
	for _, c := range []struct {
		d  time.Duration
		ok bool
	}{{59 * time.Second, false}, {MinWaitlistFloor, true}, {15 * time.Minute, true}, {BackoffCap, true}, {BackoffCap + time.Second, false}} {
		if err := CheckWaitlistFloor(c.d); (err == nil) != c.ok {
			t.Errorf("CheckWaitlistFloor(%s) = %v, want ok=%v", c.d, err, c.ok)
		}
	}
}
