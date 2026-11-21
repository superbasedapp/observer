package secassesssvc

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// TestValidateRunKeepsTheConditionsOfTheReferenceTally: a validation records
// the match window and the read budget its reference tally was made under, on the
// stored copy and on the run's scalars, so a count is never read without them
// (live defect 8: two checks of one file, 192 found against 198).
func TestValidateRunKeepsTheConditionsOfTheReferenceTally(t *testing.T) {
	cases := []struct {
		name       string
		window     int
		budget     RefBudget
		wantWindow int
		wantBudget RefBudgetRecord
	}{
		{"the defaults", 0, RefBudget{}, secassess.DefaultRefWindow, RefBudgetRecord{Files: maxRefFiles, MiB: int(maxRefTotalBytes >> 20), Seconds: int(RefDeadline / time.Second)}},
		{"a window and a budget named", 20, RefBudget{Files: 12, TotalBytes: 3 << 20, Deadline: 4 * time.Second}, 20, RefBudgetRecord{Files: 12, MiB: 3, Seconds: 4}},
		{"a partial unit rounds up, never down", 1, RefBudget{Files: 7, TotalBytes: 1<<20 + 1, Deadline: 1500 * time.Millisecond}, 1, RefBudgetRecord{Files: 7, MiB: 2, Seconds: 2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeAPIProject(t, root)
			writeModel(t, root, svcThreatModel)
			in := validateOpts(root, modelRun(secassess.ContractThreatModel, true), false)
			in.Options.RefWindow, in.Budget = tc.window, tc.budget
			side := newSide(t)
			rec, v, err := ValidateRun(context.Background(), side, in)
			if err != nil {
				t.Fatalf("validate: %v", err)
			}
			rc := rec.Result.Report.RefCheck
			if rc == nil || rc.WindowLines != tc.wantWindow || rc.TextHidden != 0 {
				t.Fatalf("RefCheck = %+v, want window %d", rc, tc.wantWindow)
			}
			if rec.RefBudget == nil || *rec.RefBudget != tc.wantBudget {
				t.Errorf("budget = %+v, want %+v", rec.RefBudget, tc.wantBudget)
			}
			if v.RefWindow != tc.wantWindow || v.RefTextHidden != 0 {
				t.Errorf("run scalars = %+v", v)
			}
			// The stored copy carries both, so a later read sees them.
			got, ok := ReadModel(side, svcRun)
			if !ok || got.RefBudget == nil || *got.RefBudget != tc.wantBudget || got.Result.Report.RefCheck == nil || got.Result.Report.RefCheck.WindowLines != tc.wantWindow {
				t.Errorf("stored copy = %+v %v", got, ok)
			}
		})
	}
}

// TestValidateRunCountsReferencesTheRedactorChanged: the node's check hides
// secrets in the quoted text before it looks for it, so a reference whose text the
// redactor rewrites cannot be found. The run says how many (live defect 8's 192
// and 7: six references quoted the plain words "bearer tokens").
func TestValidateRunCountsReferencesTheRedactorChanged(t *testing.T) {
	root := t.TempDir()
	lines := make([]string, 30)
	for i := range lines {
		lines[i] = "x := 1"
	}
	lines[11] = "func Login(w http.ResponseWriter, r *http.Request) { decode(bearer tokens are decoded here)"
	writeProjectFile(t, root, "cmd/api/main.go", strings.Join(lines, "\n")+"\n")
	writeModel(t, root, strings.Replace(svcThreatModel, `"needle":"func Login("}]}],`, `"needle":"decode(bearer tokens are decoded here)"}]}],`, 1))
	run := modelRun(secassess.ContractThreatModel, true)

	plain := validateOpts(root, run, false)
	_, vPlain, err := ValidateRun(context.Background(), newSide(t), plain)
	if err != nil {
		t.Fatal(err)
	}
	hiding := validateOpts(root, run, false)
	hiding.Options.Redact = func(s string) string { return strings.ReplaceAll(s, "bearer tokens", "[REDACTED]") }
	_, vHiding, err := ValidateRun(context.Background(), newSide(t), hiding)
	if err != nil {
		t.Fatal(err)
	}
	// Three references: the component's path and the threat's mitigation (both
	// quote the text) and the entry point (no text to match).
	if vPlain.Refs.Found != 2 || vPlain.Refs.Exists != 1 || vPlain.Refs.ClaimedNotFound != 0 || vPlain.RefTextHidden != 0 {
		t.Errorf("without a redactor: %+v", vPlain)
	}
	if vHiding.Refs.Found != 1 || vHiding.Refs.Exists != 1 || vHiding.Refs.ClaimedNotFound != 1 || vHiding.RefTextHidden != 1 {
		t.Errorf("with a redactor: %+v (one reference quotes text the redactor changed)", vHiding)
	}
	if vHiding.RefWindow != vPlain.RefWindow || vHiding.RefWindow == 0 {
		t.Errorf("windows %d and %d", vHiding.RefWindow, vPlain.RefWindow)
	}
}
