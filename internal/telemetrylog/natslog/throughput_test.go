package natslog

import (
	"fmt"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
)

// TestCreditBoundFetchNeverIdlesWithBacklog is the T-807 regression: a durable
// holding an explicit MaxAckPending (the ordered apply worker runs with 1),
// fetched with a batch size far above its credit, must still drain a backlog at
// the speed of its acks. The shipped code asked for 64 records: after the
// blocking pull returned the ONE record the credit allowed, a second pull for 63
// more could not be served while that record was unacked, and the engine parked
// it until its periodic sweep, about a second per record. A backlog of n
// records therefore took about n seconds to drain (measured here: 1.0
// records/s before the fix).
func TestCreditBoundFetchNeverIdlesWithBacklog(t *testing.T) {
	for _, credit := range []int{1, 4} {
		t.Run(fmt.Sprintf("credit-%d", credit), func(t *testing.T) { drainUnderCredit(t, credit) })
	}
}

// drainUnderCredit drains a 40-record backlog through a durable holding the
// given credit, fetching 64 at a time and acking each batch before the next
// fetch (the Runner's shape), and fails below the throughput floor.
func drainUnderCredit(t *testing.T, credit int) {
	const n = 40
	log := newTestLog(t, Options{AckWait: time.Minute})
	subj := telemetrylog.PushSubject("org")
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("r%03d", i)
		if _, err := log.Publish(t.Context(), rec("org", subj, id, id, nil)); err != nil {
			t.Fatal(err)
		}
	}
	c, err := log.Subscribe(t.Context(), telemetrylog.ConsumerSpec{Name: "ordered", MaxAckPending: credit, AckWait: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	var want uint64 = 1
	for want <= n {
		got, err := c.Fetch(t.Context(), 64, 2*time.Second)
		if err != nil {
			t.Fatalf("fetch: %v", err)
		}
		if len(got) > credit {
			t.Fatalf("a credit-%d durable delivered %d records in one fetch", credit, len(got))
		}
		for _, d := range got {
			if d.Sequence() != want {
				t.Fatalf("sequence %d, want %d (order broken)", d.Sequence(), want)
			}
			want++
			if err := d.Ack(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
	}
	elapsed := time.Since(start)
	rate := float64(n) / elapsed.Seconds()
	t.Logf("credit-%d drain: %d records in %s (%.1f records/s)", credit, n, elapsed.Round(time.Millisecond), rate)
	// The stalled shape managed about 1 record/s. 10/s is a floor a busy
	// 2-vCPU CI runner clears by a wide margin while the stall cannot.
	if rate < 10 {
		t.Fatalf("credit-%d drain %.1f records/s, below the 10/s floor (the fetch is idling while records are pending)", credit, rate)
	}
}

// TestCreditBound pins the fetch-size clamp, one row per case.
func TestCreditBound(t *testing.T) {
	for _, tc := range []struct{ max, credit, want int }{
		{64, 1, 1},
		{64, 4, 4},
		{2, 4, 2},
		{64, 0, 64},
		{1, 1, 1},
	} {
		if got := creditBound(tc.max, tc.credit); got != tc.want {
			t.Errorf("creditBound(%d, %d) = %d, want %d", tc.max, tc.credit, got, tc.want)
		}
	}
}
