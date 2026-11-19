package workspace

import (
	"reflect"
	"testing"
	"time"
)

// TestCopySweepSkip has one case per row of copySweepSkipRules, plus the
// copy that no row leaves.
func TestCopySweepSkip(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	p := CopySweepPolicy{MinAge: 30 * 24 * time.Hour, Recheck: 24 * time.Hour, Max: 5}
	old := now.Add(-31 * 24 * time.Hour)
	base := CopySweepCandidate{ID: "a", Since: old, Return: CopyReturnReturned}
	cases := []struct {
		name string
		edit func(c *CopySweepCandidate)
		want string
	}{
		{"an old returned copy is checked", func(*CopySweepCandidate) {}, ""},
		{"an old copy with no record is checked (its ref decides)", func(c *CopySweepCandidate) { c.Return = CopyReturnUnknown }, ""},
		{"the run is still going", func(c *CopySweepCandidate) { c.RunLive = true }, "live"},
		{"no date", func(c *CopySweepCandidate) { c.Since = time.Time{} }, "undated"},
		{"younger than the bound", func(c *CopySweepCandidate) { c.Since = now.Add(-29 * 24 * time.Hour) }, "young"},
		{"its return has not run", func(c *CopySweepCandidate) { c.Return = CopyReturnPending }, "not_returned"},
		{"its return was refused", func(c *CopySweepCandidate) { c.Return = CopyReturnRefused }, "not_returned"},
		{"kept an hour ago", func(c *CopySweepCandidate) { c.KeptAt = now.Add(-time.Hour) }, "kept_recently"},
		{"kept two days ago is checked again", func(c *CopySweepCandidate) { c.KeptAt = now.Add(-48 * time.Hour) }, ""},
	}
	for _, c := range cases {
		cand := base
		c.edit(&cand)
		if got := CopySweepSkip(cand, p, now); got != c.want {
			t.Errorf("%s: skip %q, want %q", c.name, got, c.want)
		}
	}
	if len(copySweepSkipRules) != 5 {
		t.Fatalf("copySweepSkipRules has %d rows; give the new row a case", len(copySweepSkipRules))
	}
}

func TestPlanCopySweep(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	cands := []CopySweepCandidate{
		{ID: "young", Since: now.Add(-2 * day), Return: CopyReturnReturned},
		{ID: "old3", Since: now.Add(-40 * day), Return: CopyReturnReturned},
		{ID: "old1", Since: now.Add(-90 * day), Return: CopyReturnNothingNew},
		{ID: "old2", Since: now.Add(-60 * day), Return: CopyReturnUnknown},
		{ID: "refused", Since: now.Add(-99 * day), Return: CopyReturnRefused},
	}
	p := CopySweepPolicy{MinAge: 30 * day, Recheck: day, Max: 2}
	check, due := PlanCopySweep(cands, p, now)
	if !reflect.DeepEqual(check, []string{"old1", "old2"}) || due != 3 {
		t.Errorf("the batch is capped, oldest first: got %v (due %d)", check, due)
	}
	p.Max = 10
	if check, due = PlanCopySweep(cands, p, now); len(check) != 3 || due != 3 {
		t.Errorf("under the cap every due copy is checked: got %v (due %d)", check, due)
	}
	if check, due = PlanCopySweep(cands, CopySweepPolicy{MinAge: 0, Max: 10}, now); check != nil || due != 0 {
		t.Errorf("0 days turns the sweep off: got %v (due %d)", check, due)
	}
	if check, _ = PlanCopySweep(cands, CopySweepPolicy{MinAge: 30 * day, Max: 0}, now); check != nil {
		t.Errorf("a zero batch checks nothing: got %v", check)
	}
}
