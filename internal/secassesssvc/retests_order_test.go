package secassesssvc

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// TestReadRetestsOrderAndDatesFollowTheLaunch (N-11): the retests of a run are
// listed newest first by when each retest was launched, and each carries that
// date, whatever order they were checked in. The check time moves when a run is
// validated again, so a retest checked late would otherwise sit above a later
// one under a date that looks older (or the reverse).
func TestReadRetestsOrderAndDatesFollowTheLaunch(t *testing.T) {
	st := New(Path(filepath.Join(t.TempDir(), "observer.db")))
	of := runID(1)
	base := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	if _, err := st.Record(Run{ID: of, Kind: "pentest_local", Tool: "claude-code", ProjectRootHash: "h1", Contract: string(secassess.ContractPentest), Phase: PhaseStarted}, base); err != nil {
		t.Fatal(err)
	}
	// The retest launched first was checked last (checked again two days later); the one launched later was checked at once.
	rows := []struct {
		n        int
		launched time.Time
		checked  time.Time
	}{
		{2, base.Add(24 * time.Hour), base.Add(24*time.Hour + time.Minute)},
		{3, base.Add(48 * time.Hour), base.Add(48*time.Hour + time.Minute)},
		{4, base.Add(72 * time.Hour), base.Add(72*time.Hour + time.Minute)},
	}
	rows[0].checked = base.Add(5 * 24 * time.Hour) // launched first, checked last
	for _, r := range rows {
		id := runID(r.n)
		if _, err := st.Record(Run{ID: id, Kind: "pentest_retest", Tool: "claude-code", ProjectRootHash: "h1", Contract: string(secassess.ContractRetest), Phase: PhaseStarted, RetestOf: of, RetestFindings: []string{"F-1"}}, r.launched); err != nil {
			t.Fatal(err)
		}
		blob, err := json.Marshal(ModelRecord{
			Schema: ModelSchema, RunID: id, ValidatedAt: r.checked, Contract: secassess.ContractRetest,
			Result: secassess.Result{
				Report: secassess.Report{State: secassess.ValidationValid, Contract: secassess.ContractRetest},
				RT:     &secassess.RetestDoc{Started: true, Results: []secassess.RTResult{{Finding: "F-1", Result: secassess.RetestNotReproduced}}},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := st.Side().Put(id, SideModel, blob); err != nil {
			t.Fatal(err)
		}
	}
	got := ReadRetests(st.Side(), st.All(), of)
	if len(got) != 3 {
		t.Fatalf("%d retests listed", len(got))
	}
	for i, wantRun := range []string{runID(4), runID(3), runID(2)} {
		if got[i].Run != wantRun {
			t.Errorf("position %d is %s, want %s (newest launch first)", i, got[i].Run, wantRun)
		}
	}
	for _, v := range got {
		want := st.byIDForTest(t, v.Run).CreatedAt
		if !v.LaunchedAt.Equal(want) {
			t.Errorf("%s launched_at = %v, want the run's creation %v", v.Run, v.LaunchedAt, want)
		}
	}
	// The oldest launch was checked last: its check time is later than the newest launch's, and its label is still listed last.
	last := got[2]
	if !last.At.After(got[0].At) || !last.LaunchedAt.Before(got[0].LaunchedAt) {
		t.Errorf("the fixture no longer inverts the check and launch order: %v %v", last, got[0])
	}
	// The wire member is there under its name.
	blob, err := json.Marshal(got[0])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(blob, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"run", "launched_at", "at", "state", "started", "asked", "results"} {
		if _, ok := m[k]; !ok {
			t.Errorf("the retest view lacks %q: %s", k, blob)
		}
	}
}

// byIDForTest returns a recorded run.
func (s *Store) byIDForTest(t *testing.T, id string) Run {
	t.Helper()
	r, ok := s.Get(id)
	if !ok {
		t.Fatalf("run %s is not recorded", id)
	}
	return r
}
