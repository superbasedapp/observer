package main

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/govern"
)

// TestLowerShareOptionsManagedFollowsTheGrant pins ShareOptions.Managed (the
// gate of the managed-only wires, today the sandbox egress refusal counts,
// audit CG-15, decision D-11) at the one construction site: it is the live
// governance's Managed predicate, true only under a managed-class consent,
// false on an individual enrolment whatever the org body says, and it never
// turns raw content on by itself.
func TestLowerShareOptionsManagedFollowsTheGrant(t *testing.T) {
	now := time.Now().UTC()
	body := `{"schema":2}`
	for _, c := range []struct {
		name    string
		consent string
		want    bool
	}{
		{"managed consent", govern.ConsentManaged, true},
		{"individual consent", govern.ConsentInteractive, false},
	} {
		got := resolveRaiseBody(t, raiseChainGrant(now, c.consent), body)
		if got.Managed != c.want {
			t.Errorf("%s: Managed = %v, want %v", c.name, got.Managed, c.want)
		}
		if got.ShipsRawContent() {
			t.Errorf("%s: Managed alone turned raw content on", c.name)
		}
		// The managed policy tiers (G1, 2026-11-12): on by force on a
		// managed node, untouched on an individual one.
		if got.RoutingSummary != c.want || got.TerminalDetail != c.want {
			t.Errorf("%s: routing_summary=%v terminal_detail=%v, want %v", c.name, got.RoutingSummary, got.TerminalDetail, c.want)
		}
	}
}
