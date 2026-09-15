package runstate

import (
	"testing"
	"time"
)

// TestReconcile_PerRule walks one case per DefaultRules() row (plus the
// short-circuits) so a change to any rule's guard is caught in isolation.
func TestReconcile_PerRule(t *testing.T) {
	t.Parallel()
	rules := DefaultRules()

	cases := []struct {
		name        string
		sig         Signal
		wantChanged bool
		wantTo      string
		wantReason  string
	}{
		{
			name:        "arena candidate closes when parent run is terminal (no age needed)",
			sig:         Signal{Kind: KindArenaCandidate, Status: "running", Age: 0, ParentTerminal: true},
			wantChanged: true, wantTo: StatusFailed, wantReason: "parent_run_terminal",
		},
		{
			name:        "arena candidate pending closes when parent terminal",
			sig:         Signal{Kind: KindArenaCandidate, Status: "pending", ParentTerminal: true},
			wantChanged: true, wantTo: StatusFailed, wantReason: "parent_run_terminal",
		},
		{
			name:        "arena candidate stale by age with live-ish parent",
			sig:         Signal{Kind: KindArenaCandidate, Status: "running", Age: ArenaStaleAfter},
			wantChanged: true, wantTo: StatusFailed, wantReason: "stale_no_progress",
		},
		{
			name:        "arena candidate young and parent not terminal is left alone",
			sig:         Signal{Kind: KindArenaCandidate, Status: "running", Age: ArenaStaleAfter - time.Minute},
			wantChanged: false,
		},
		{
			name:        "arena run stale by age",
			sig:         Signal{Kind: KindArenaRun, Status: "judging", Age: ArenaStaleAfter},
			wantChanged: true, wantTo: StatusFailed, wantReason: "stale_no_progress",
		},
		{
			name:        "arena run young is left alone",
			sig:         Signal{Kind: KindArenaRun, Status: "running", Age: ArenaStaleAfter - time.Minute},
			wantChanged: false,
		},
		{
			name:        "terminal run stale by age",
			sig:         Signal{Kind: KindTerminalRun, Status: "running", Age: TerminalStaleAfter},
			wantChanged: true, wantTo: StatusAbandoned, wantReason: "stale_no_heartbeat",
		},
		{
			name:        "terminal run young is left alone",
			sig:         Signal{Kind: KindTerminalRun, Status: "running", Age: TerminalStaleAfter - time.Minute},
			wantChanged: false,
		},
		{
			name:        "terminal run already ended is not touched",
			sig:         Signal{Kind: KindTerminalRun, Status: "ended", Age: TerminalStaleAfter},
			wantChanged: false,
		},
		{
			name:        "known-live record is never reconciled even when old",
			sig:         Signal{Kind: KindArenaRun, Status: "running", Age: 10 * ArenaStaleAfter, KnownLive: true},
			wantChanged: false,
		},
		{
			name:        "terminal-run rule never fires on an arena candidate of the same status",
			sig:         Signal{Kind: KindArenaCandidate, Status: "running", Age: TerminalStaleAfter},
			wantChanged: true, wantTo: StatusFailed, wantReason: "stale_no_progress",
		},
		{
			name:        "already-terminal arena candidate does not re-fire",
			sig:         Signal{Kind: KindArenaCandidate, Status: "failed", Age: ArenaStaleAfter, ParentTerminal: true},
			wantChanged: false,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := Reconcile(rules, tc.sig)
			if got.Changed != tc.wantChanged {
				t.Fatalf("Changed = %v, want %v (%+v)", got.Changed, tc.wantChanged, got)
			}
			if tc.wantChanged && (got.To != tc.wantTo || got.Reason != tc.wantReason) {
				t.Fatalf("verdict = %+v, want To=%q Reason=%q", got, tc.wantTo, tc.wantReason)
			}
		})
	}
}
