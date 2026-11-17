package secassesssvc

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// maximalRun is a run carrying the most the caps allow: eight relaxations with
// every string and host list at its limit, and a held request at its limit.
func maximalRun(n int, phase string, ended bool, state secassess.RelaxState) Run {
	long := strings.Repeat("x", maxField)
	rs := make([]Relax, 8)
	for i := range rs {
		hosts := make([]string, 16)
		for j := range hosts {
			hosts[j] = strings.Repeat("h", 128)
		}
		rs[i] = Relax{
			Key: long, Type: long, Route: long, State: string(state), Scope: long, GrantedBy: long,
			SessionID: long, EndReason: long, Note: long, Hosts: hosts, ApprovalID: 1<<53 - 1, GrantID: 1<<53 - 1,
			ExpiresAt: time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC),
		}
	}
	r := Run{
		ID: runID(n), Kind: long, Tool: long, ProjectRootHash: long, ProjectName: long, Handle: "h", Target: long,
		Backend: long, Tier: long, Phase: phase, Tenancy: long, Relax: rs, Reported: true,
		Held: &Held{Rules: []string{long}, RequestIDs: []int64{1, 2, 3, 4, 5, 6, 7, 8}, QueuedIDs: []int64{1, 2, 3, 4, 5, 6, 7, 8}, Covered: []string{long}},
		// The plan's recorded choices (depth plan W3, W4) at their bounds: a
		// maximal record has to hold them too, or the test below no longer proves
		// what its name says.
		ScopeNote: strings.Repeat("n", secassess.MaxScopeNote*4), PreviousRun: long, Grounding: long,
		Start: strings.Repeat("s", secassess.MaxStartChoice), Prepare: true, SecretMode: long,
	}
	for i := 0; i < maxRunScopePaths; i++ {
		r.ScopePaths = append(r.ScopePaths, strings.Repeat("p", maxRunScopePath))
	}
	if ended {
		r.EndedAt = time.Date(2026, 11, 14, 11, 0, 0, 0, time.UTC)
	}
	return r
}

func fileBytes(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUnreadableRecordIsNeverOverwritten(t *testing.T) {
	// A valid, same-schema record that is merely over the cap: the exact shape
	// that used to read as "no runs" and be rewritten from the empty view.
	over := `{"schema":1,"runs":[{"id":"` + runID(7) + `","kind":"pentest_local","tool":"` + strings.Repeat("x", maxBytes) + `"}]}`
	cases := map[string]string{
		"over the cap": over,
		"garbage":      "{not json",
		"other schema": `{"schema":99,"runs":[{"id":"x"}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), Filename)
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			st := New(p)
			if _, err := st.Record(Run{ID: runID(1), Kind: "threat_model"}, time.Now()); !errors.Is(err, ErrUnreadable) {
				t.Fatalf("Record err = %v, want ErrUnreadable", err)
			}
			if err := st.SetImport(runID(7), ImportRecord{Outcome: "imported"}); !errors.Is(err, ErrUnreadable) {
				t.Errorf("SetImport err = %v, want ErrUnreadable", err)
			}
			if _, found, err := st.Mutate(runID(7), func(*Run) error { return nil }); found || !errors.Is(err, ErrUnreadable) {
				t.Errorf("Mutate = found %v, err %v, want not found and ErrUnreadable", found, err)
			}
			if _, err := st.ClaimHeld(runID(7)); !errors.Is(err, ErrUnreadable) {
				t.Errorf("ClaimHeld err = %v, want ErrUnreadable", err)
			}
			if got := fileBytes(t, p); !bytes.Equal(got, []byte(body)) {
				t.Errorf("the unreadable record was rewritten (%d bytes, was %d)", len(got), len(body))
			}
			// The readers still show nothing rather than failing.
			if len(st.Recent(5)) != 0 || len(st.All()) != 0 {
				t.Error("an unreadable record showed runs")
			}
		})
	}
}

func TestMissingOrEmptyRecordIsWritable(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(filepath.Join(dir, "missing.json")).Record(Run{ID: runID(1)}, time.Now()); err != nil {
		t.Errorf("a missing file must be created: %v", err)
	}
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(empty).Record(Run{ID: runID(2)}, time.Now()); err != nil {
		t.Errorf("an empty file holds nothing to erase: %v", err)
	}
}

func TestFullRecordDropsOnlyEndedRunsOldestFirst(t *testing.T) {
	p := filepath.Join(t.TempDir(), Filename)
	st := New(p)
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	at := func(i int) time.Time { return now.Add(time.Duration(i) * time.Minute) }
	rec := func(i int, r Run) {
		t.Helper()
		if _, err := st.Record(r, at(i)); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	// Oldest first: a held run, a started run with an open relaxation, then
	// ended runs. None of the first three may ever be dropped.
	rec(1, maximalRun(1, PhaseHeld, false, secassess.RelaxOrgGrant))
	rec(2, maximalRun(2, PhaseStarted, false, secassess.RelaxActive))
	rec(3, maximalRun(3, PhaseStarted, false, secassess.RelaxEnded)) // reported, end not yet recorded
	ended := []int{}
	for i := 4; ; i++ {
		before := len(st.All())
		rec(i, maximalRun(i, PhaseStarted, true, secassess.RelaxEnded))
		ended = append(ended, i)
		if len(st.All()) <= before { // the cap began to drop runs
			break
		}
		if i > 200 {
			t.Fatal("the record never reached its cap")
		}
	}
	if size := len(fileBytes(t, p)); size > maxBytes {
		t.Fatalf("file is %d bytes, over the cap %d", size, maxBytes)
	}
	have := map[string]bool{}
	for _, r := range st.All() {
		have[r.ID] = true
	}
	for _, n := range []int{1, 2, 3} {
		if !have[runID(n)] {
			t.Errorf("run %d (held, open relaxation or end not recorded) was dropped", n)
		}
	}
	// The oldest ended run went first, and the newest is kept.
	if have[runID(ended[0])] {
		t.Errorf("the oldest ended run %d was kept while the file was full", ended[0])
	}
	if !have[runID(ended[len(ended)-1])] {
		t.Error("the run being written was dropped")
	}
	// What is dropped is a prefix of the ended runs: every kept ended run is
	// newer than every dropped one.
	seenKept := false
	for _, n := range ended {
		if have[runID(n)] {
			seenKept = true
		} else if seenKept {
			t.Errorf("ended run %d was dropped after a newer ended run was kept", n)
		}
	}
}

func TestFullRecordWithNothingToDropRefusesAndKeepsTheFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), Filename)
	st := New(p)
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	var last []byte
	n := 1
	for ; n < 200; n++ {
		// Held runs are never dropped.
		_, err := st.Record(maximalRun(n, PhaseHeld, false, secassess.RelaxOrgGrant), now)
		if err != nil {
			if !errors.Is(err, ErrFull) {
				t.Fatalf("record %d: %v, want ErrFull", n, err)
			}
			break
		}
		last = fileBytes(t, p)
	}
	if n == 200 {
		t.Fatal("the record never refused a write")
	}
	if got := fileBytes(t, p); !bytes.Equal(got, last) {
		t.Error("a refused write changed the file")
	}
	if len(last) > maxBytes {
		t.Errorf("file is %d bytes, over the cap", len(last))
	}
	// A held run is still claimable and the record is still readable.
	if got := len(st.All()); got != n-1 {
		t.Errorf("runs = %d, want %d", got, n-1)
	}
	if _, err := st.ClaimHeld(runID(1)); err != nil && !errors.Is(err, ErrFull) {
		t.Errorf("ClaimHeld: %v", err)
	}
}

func TestHundredMaximalRunsStayReadable(t *testing.T) {
	p := filepath.Join(t.TempDir(), Filename)
	st := New(p)
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	for i := 1; i <= 100; i++ {
		if _, err := st.Record(maximalRun(i, PhaseStarted, true, secassess.RelaxEnded), now.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		if size := len(fileBytes(t, p)); size > maxBytes {
			t.Fatalf("after %d runs the file is %d bytes, over the cap", i, size)
		}
	}
	all := st.All()
	if len(all) == 0 || len(all) > MaxRuns {
		t.Fatalf("runs = %d", len(all))
	}
	if last := all[len(all)-1]; last.ID != runID(100) {
		t.Errorf("newest run = %s, want %s", last.ID, runID(100))
	}
	if got := st.Recent(1); len(got) != 1 || got[0].ID != runID(100) {
		t.Errorf("recent = %+v", got)
	}
	// A fresh store over the same file reads it back.
	if got := New(p).All(); len(got) != len(all) {
		t.Errorf("re-read %d runs, want %d", len(got), len(all))
	}
}
