package sandboxrelayd

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// TestFreshToPersistRows is one case per rule of freshToPersist (tracker
// F-039): an id within MaxFreshSessionID is persisted, a longer one is
// skipped and counted, and the order of the kept ids is kept.
func TestFreshToPersistRows(t *testing.T) {
	long := strings.Repeat("x", MaxFreshSessionID+1)
	edge := strings.Repeat("y", MaxFreshSessionID)
	for _, tc := range []struct {
		name    string
		ids     []string
		keep    []string
		skipped int
	}{
		{"short ids kept", []string{"sess-a", "sess-b"}, []string{"sess-a", "sess-b"}, 0},
		{"an id at the bound is kept", []string{edge}, []string{edge}, 0},
		{"an id past the bound is skipped and counted", []string{"sess-a", long, "sess-b"}, []string{"sess-a", "sess-b"}, 1},
		{"only long ids: nothing kept", []string{long, long + "z"}, nil, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keep, skipped := freshToPersist(tc.ids)
			if !slices.Equal(keep, tc.keep) || skipped != tc.skipped {
				t.Fatalf("freshToPersist = %d ids, %d skipped; want %d, %d", len(keep), skipped, len(tc.keep), tc.skipped)
			}
		})
	}
}

// TestClaimRowSkipsLongFreshIDs drives the binding table's claim row
// (F-039): a request naming a session id past MaxFreshSessionID still
// passes and claims it, the short fresh id is persisted, the long one is
// not, and the skip is counted on the run.
func TestClaimRowSkipsLongFreshIDs(t *testing.T) {
	var row *bindCheck
	for i := range bindChecks {
		if strings.Contains(bindChecks[i].name, "claimed by this run") {
			row = &bindChecks[i]
		}
	}
	if row == nil {
		t.Fatal("no claim row in bindChecks")
	}
	store := &memFresh{}
	d := &Daemon{FreshStore: store, SessionOwner: func(context.Context, string) (string, error) { return "", nil }}
	st := &RunState{}
	long := strings.Repeat("s", MaxFreshSessionID+1)
	in := bindInput{d: d, st: st, run: RunRecord{RunID: "runSENTINEL"}, facts: payloadFacts{sessions: []string{"sess-short", long}}}
	if r := row.check(context.Background(), in); r != "" {
		t.Fatalf("a long session id was fatal: %s", r)
	}
	if got := store.Fresh("runSENTINEL"); !slices.Equal(got, []string{"sess-short"}) {
		t.Fatalf("persisted %d ids, want only the short one", len(got))
	}
	if st.FreshSkipped.Load() != 1 {
		t.Fatalf("FreshSkipped = %d, want 1", st.FreshSkipped.Load())
	}
}

// TestClaimRowLogsTheFirstSkipOnce (audit FU11-A4): the first over-long
// fresh id of a run is one log line; later skips of the run are counted
// only.
func TestClaimRowLogsTheFirstSkipOnce(t *testing.T) {
	var row *bindCheck
	for i := range bindChecks {
		if strings.Contains(bindChecks[i].name, "claimed by this run") {
			row = &bindChecks[i]
		}
	}
	var lines []string
	d := &Daemon{
		FreshStore: &memFresh{}, SessionOwner: func(context.Context, string) (string, error) { return "", nil },
		Log: func(runID, reason string) { lines = append(lines, runID+": "+reason) },
	}
	st := &RunState{}
	for i, id := range []string{strings.Repeat("a", MaxFreshSessionID+1), strings.Repeat("b", MaxFreshSessionID+1)} {
		in := bindInput{d: d, st: st, run: RunRecord{RunID: "runSENTINEL"}, facts: payloadFacts{sessions: []string{id}}}
		if r := row.check(context.Background(), in); r != "" {
			t.Fatalf("request %d refused: %s", i, r)
		}
	}
	if len(lines) != 1 || st.FreshSkipped.Load() != 2 {
		t.Fatalf("log lines %d (want 1), skipped %d (want 2)", len(lines), st.FreshSkipped.Load())
	}
}
