package sandboxadopt

import "testing"

// TestHoldDeadRecord pins the prune hold table (F-045), one case per row;
// a row that lets the prune go on names the row and code the run is
// logged and shown with (fix round 1, FU10-A4).
func TestHoldDeadRecord(t *testing.T) {
	t.Parallel()
	ok := HoldFacts{Active: true, Kept: true}
	cases := []struct {
		name string
		edit func(*HoldFacts)
		hold bool
		row  string
		code Code
	}{
		{"a kept run waits for the re-adoption step", func(*HoldFacts) {}, true, "", ""},
		{"component off", func(f *HoldFacts) { f.Active = false }, false, "component", CodeComponentInactive},
		{"nothing kept", func(f *HoldFacts) { f.Kept = false }, false, RowNotKept, CodePlanMissing},
		// The only caller reads the settings only for a kept run, so an
		// unkept run arrives with Active false: not-kept still wins (R2).
		{"nothing kept, settings not read", func(f *HoldFacts) { f.Kept, f.Active = false, false }, false, RowNotKept, CodePlanMissing},
		{"a CLI run", func(f *HoldFacts) { f.CLIRun = true }, false, "cli-run", CodeCLIRun},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := ok
			c.edit(&f)
			hold, d := HoldDeadRecord(f)
			if hold != c.hold || d.Row != c.row || d.Code != c.code {
				t.Fatalf("HoldDeadRecord(%+v) = %v %+v, want %v row %q code %q", f, hold, d, c.hold, c.row, c.code)
			}
			if !hold && (d.Action != ActionReap || d.Summary == "" || d.Summary != d.Reason) {
				t.Fatalf("a let-go decision %+v must be a reap with a fixed line", d)
			}
		})
	}
	if len(holdRules) != 3 {
		t.Fatalf("the hold table has %d rows; add a case above for the new one and update this count", len(holdRules))
	}
}
