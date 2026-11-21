package openshellorg

import (
	"testing"
	"time"
)

// TestDecideReopen (FX3 item 11, F-L4P5-5): one case per row, and the
// allowed reopen.
func TestDecideReopen(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	good := ReopenFacts{Enabled: true, Drain: DrainDrained, Sync: SyncFacts{Present: true, Sound: true, CheckedAt: now.Add(-time.Minute), Interval: time.Minute}, Now: now}
	for _, c := range []struct {
		name string
		set  func(*ReopenFacts)
		want Reason
	}{
		{"allowed", func(*ReopenFacts) {}, ReasonNone},
		{"feature off", func(f *ReopenFacts) { f.Enabled = false }, ReasonOff},
		{"active", func(f *ReopenFacts) { f.Drain = DrainActive }, ReasonIllegalTransition},
		{"draining", func(f *ReopenFacts) { f.Drain = DrainDraining }, ReasonIllegalTransition},
		{"drain blocked", func(f *ReopenFacts) { f.Drain = DrainBlocked }, ReasonIllegalTransition},
		{"no sync", func(f *ReopenFacts) { f.Sync = SyncFacts{Interval: time.Minute} }, ReasonGatewayStateStale},
		{"stale sync", func(f *ReopenFacts) { f.Sync.CheckedAt = now.Add(-4 * time.Minute) }, ReasonGatewayStateStale},
		{"unsound", func(f *ReopenFacts) { f.Sync.Sound = false }, ReasonGatewayUnsound},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := good
			c.set(&f)
			if got := DecideReopen(f); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}
