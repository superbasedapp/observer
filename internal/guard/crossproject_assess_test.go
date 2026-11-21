package guard

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// crossproject_assess_test.go: the R-151 false positive the 2026-11-15
// security-assessment live runs found (docs/plans/
// security-assessments-live-results-2026-11-15.md, follow-up row 11),
// pinned at the guard seams that raised it.

// TestCrossProjectBleedAtTheProxyAndWatcherSeams: R-151 at the two seams
// the live run exercised. The proxy's response inspection carries no
// project root, so a run's write into its own run folder is not
// cross-project bleed there (live 2026-11-15: 20 such flags and asks on
// the assessment runs' assessment.json and report.md); the watcher, which
// knows the session's recorded project, still flags a genuine write into
// another observed project.
func TestCrossProjectBleedAtTheProxyAndWatcherSeams(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	const runFolder = "/home/u/proj/.observer/assessments/f0d1386d2b395e14/"
	tests := []struct {
		name     string
		proxy    *ProxyToolUse // response-inspection seam
		watcher  *ActionInput  // post-hoc watcher seam
		wantR151 bool
	}{
		{
			name:  "proxy: a run writes its own assessment.json",
			proxy: &ProxyToolUse{Name: "Write", Input: []byte(`{"file_path":"` + runFolder + `assessment.json","content":"{}"}`)},
		},
		{
			name:  "proxy: a run writes its own report.md",
			proxy: &ProxyToolUse{Name: "Write", Input: []byte(`{"file_path":"` + runFolder + `report.md","content":"# report"}`)},
		},
		{
			name:    "watcher: the run-folder write in the session's recorded project",
			watcher: &ActionInput{SessionID: "s-run", ProjectRoot: "/home/u/proj", ActionType: models.ActionWriteFile, Target: runFolder + "report.md", Timestamp: now, Success: true},
		},
		{
			name:     "watcher: a genuine write into another observed project",
			watcher:  &ActionInput{SessionID: "s-run", ProjectRoot: "/home/u/proj", ActionType: models.ActionWriteFile, Target: "/home/u/other/main.go", Timestamp: now, Success: true},
			wantR151: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, mode := range []string{"observe", "enforce"} {
				g := newTestGuard(t, proxyCfg(mode, "mask"), nil)
				var out []ActionVerdict
				if tc.proxy != nil {
					out = g.InspectProxyResponse("s-run", []ProxyToolUse{*tc.proxy}, now)
				} else {
					out = g.EvaluateActions([]ActionInput{*tc.watcher})
				}
				got := false
				for _, v := range out {
					if v.Verdict.RuleID == "R-151" {
						got = true
					}
				}
				if got != tc.wantR151 {
					t.Fatalf("mode %s: R-151 = %v, want %v (verdicts %+v)", mode, got, tc.wantR151, out)
				}
			}
		})
	}
}
