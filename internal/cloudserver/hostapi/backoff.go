package hostapi

import (
	"fmt"
	"time"
)

// Retry schedule (design 4.6: exponential backoff with jitter to a one-hour
// cap).
const (
	// BackoffBase is the delay before the second attempt (before jitter).
	BackoffBase = 5 * time.Second
	// BackoffCap bounds every delay.
	BackoffCap = time.Hour
	// RetryNewRequestCap bounds the delay of a 409-class retry: the host
	// asked for a new request, not for silence.
	RetryNewRequestCap = 30 * time.Second
	// WaitlistMinDelay is the default least delay before a waitlisted create
	// is sent again: capacity frees on the scale of an operator action or a
	// rebalance, not seconds. The worker may configure another floor
	// (SBCI_WAITLIST_RETRY_FLOOR, DelayOptions.WaitlistFloor; W16-D5) within
	// [MinWaitlistFloor, BackoffCap].
	WaitlistMinDelay = 15 * time.Minute
	// MinWaitlistFloor is the lowest configurable waitlist floor: below it a
	// full host would be asked again faster than capacity can change.
	MinWaitlistFloor = time.Minute
)

// DelayOptions are the configurable parts of the retry schedule. The zero
// value is the default schedule.
type DelayOptions struct {
	// WaitlistFloor is the least delay before a waitlisted create is sent
	// again (0: WaitlistMinDelay).
	WaitlistFloor time.Duration
}

// CheckWaitlistFloor reports whether d is a usable configured waitlist
// floor: within [MinWaitlistFloor, BackoffCap].
func CheckWaitlistFloor(d time.Duration) error {
	if d < MinWaitlistFloor || d > BackoffCap {
		return fmt.Errorf("hostapi.CheckWaitlistFloor: %s is outside [%s, %s]", d, MinWaitlistFloor, BackoffCap)
	}
	return nil
}

// waitlistFloor is the floor o configures, else the default.
func (o DelayOptions) waitlistFloor() time.Duration {
	if o.WaitlistFloor > 0 {
		return o.WaitlistFloor
	}
	return WaitlistMinDelay
}

// Backoff is the delay after the attempts-th attempt failed: BackoffBase
// doubled per earlier attempt, capped at BackoffCap, then "equal jitter":
// half the delay fixed and half scaled by jitter in [0, 1) (clamped). The
// result lies in [d/2, d). jitter is injected so tests are exact.
func Backoff(attempts int, jitter float64) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	d := BackoffBase
	for i := 1; i < attempts && d < BackoffCap; i++ {
		d *= 2
	}
	if d > BackoffCap {
		d = BackoffCap
	}
	switch {
	case jitter < 0:
		jitter = 0
	case jitter >= 1:
		jitter = 0.999
	}
	half := d / 2
	return half + time.Duration(float64(half)*jitter)
}

// delayRules picks the delay for a retrying action, walked top-down.
var delayRules = []struct {
	action Action
	delay  func(attempts int, jitter float64, o DelayOptions) time.Duration
}{
	{ActionRetry, func(attempts int, jitter float64, _ DelayOptions) time.Duration { return Backoff(attempts, jitter) }},
	{ActionRetryNewRequest, shortBackoff},
	{ActionWaitlist, waitlistBackoff},
}

// waitlistBackoff is Backoff raised to at least the waitlist floor, still
// capped at BackoffCap.
func waitlistBackoff(attempts int, jitter float64, o DelayOptions) time.Duration {
	return min(max(Backoff(attempts, jitter), o.waitlistFloor()), BackoffCap)
}

// shortBackoff is Backoff capped at RetryNewRequestCap.
func shortBackoff(attempts int, jitter float64, _ DelayOptions) time.Duration {
	return min(Backoff(attempts, jitter), RetryNewRequestCap)
}

// RetryDelay is the delay before the next attempt for a retrying decision
// after attempts attempts, on the default schedule; zero for ack and park.
func RetryDelay(a Action, attempts int, jitter float64) time.Duration {
	return RetryDelayWith(a, attempts, jitter, DelayOptions{})
}

// RetryDelayWith is RetryDelay on the schedule o configures.
func RetryDelayWith(a Action, attempts int, jitter float64, o DelayOptions) time.Duration {
	for _, r := range delayRules {
		if r.action == a {
			return r.delay(attempts, jitter, o)
		}
	}
	return 0
}
