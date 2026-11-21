package secrules

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestQuickScanUnknownWords is one row per reason: the commit gate's
// verdict says why the quick scan did not answer clean, from the scan's own
// detail (the reason code and its numbers), never from a tool name.
func TestQuickScanUnknownWords(t *testing.T) {
	for _, tc := range []struct {
		d    policy.QuickScanDetail
		want string
	}{
		{policy.QuickScanDetail{}, "the quick scan did not finish"},
		{policy.QuickScanDetail{Reason: "a reason from a newer daemon"}, "the quick scan did not finish"},
		{policy.QuickScanDetail{Reason: policy.QuickScanReasonBudget, Budget: 2 * time.Second, Files: 31}, "the quick scan timed out after 2 s on 31 files"},
		{policy.QuickScanDetail{Reason: policy.QuickScanReasonBudget, Budget: 10 * time.Second, Files: 1}, "the quick scan timed out after 10 s on 1 file"},
		{policy.QuickScanDetail{Reason: policy.QuickScanReasonBudget, Budget: 2 * time.Second}, "the quick scan timed out after 2 s while reading the change"},
		{policy.QuickScanDetail{Reason: policy.QuickScanReasonOverBudget, Budget: 1500 * time.Millisecond}, "the quick scan timed out after 1.5 s while reading the change"},
		{policy.QuickScanDetail{Reason: policy.QuickScanReasonOverBudget}, "the quick scan timed out"},
		{policy.QuickScanDetail{Reason: policy.QuickScanReasonIncomplete, Budget: 2 * time.Second, Files: 4}, "the quick scan did not finish: a detector ran out of time after 2 s on 4 files"},
		{policy.QuickScanDetail{Reason: policy.QuickScanReasonGit}, "the quick scan failed: git could not read the change"},
		{policy.QuickScanDetail{Reason: policy.QuickScanReasonDiffOverCap}, "the quick scan did not run: the change is larger than the scan reads"},
		{policy.QuickScanDetail{Reason: policy.QuickScanReasonNoUpstream}, "the quick scan did not run: the branch has no upstream to compare the push with"},
		{policy.QuickScanDetail{Reason: policy.QuickScanReasonNotModelled}, "the quick scan did not run: it does not model what this command records"},
		{policy.QuickScanDetail{Reason: policy.QuickScanReasonBadRequest}, "the quick scan did not run: it does not model what this command records"},
		{policy.QuickScanDetail{Reason: policy.QuickScanReasonUnplaced}, "the quick scan did not run: the command commits somewhere the hook cannot place"},
		{policy.QuickScanDetail{Reason: policy.QuickScanReasonRootNotAllowed}, "the quick scan did not run: the daemon does not know this repository"},
		{policy.QuickScanDetail{Reason: policy.QuickScanReasonBusy}, "the quick scan did not run: the daemon was busy with other scans"},
		{policy.QuickScanDetail{Reason: policy.QuickScanReasonScanFailed}, "the quick scan failed: the scanner stopped with an error"},
		{policy.QuickScanDetail{Reason: policy.QuickScanReasonNotServing}, "the quick scan did not run: the daemon's quick-scan service is not serving"},
		{policy.QuickScanDetail{Reason: policy.QuickScanReasonNoTime}, "the quick scan did not run: no time was left in the host's hook timeout"},
		{policy.QuickScanDetail{Reason: policy.QuickScanReasonNoAnswer}, "the quick scan got no answer from the Observer daemon"},
		// R3-86: a WSL daemon reading a Windows drive says which git it used.
		{policy.QuickScanDetail{Reason: policy.QuickScanReasonBudget, Budget: 2 * time.Second, Files: 3, Git: policy.QuickScanGitWindows}, "the quick scan timed out after 2 s on 3 files (read with Windows git through WSL interop)"},
		{policy.QuickScanDetail{Reason: policy.QuickScanReasonBudget, Budget: 2 * time.Second, Git: policy.QuickScanGitDrvFs}, "the quick scan timed out after 2 s while reading the change (read with WSL git across the Windows drive mount: no Windows git.exe was usable)"},
		{policy.QuickScanDetail{Reason: policy.QuickScanReasonGit, Git: policy.QuickScanGitDrvFsFallback}, "the quick scan failed: git could not read the change (read with WSL git across the Windows drive mount after Windows git failed to run)"},
		{policy.QuickScanDetail{Git: policy.QuickScanGitWindows}, "the quick scan did not finish (read with Windows git through WSL interop)"},
		{policy.QuickScanDetail{Reason: policy.QuickScanReasonGit, Git: "not a known git"}, "the quick scan failed: git could not read the change"},
	} {
		if got := quickScanUnknownWords(tc.d); got != tc.want {
			t.Errorf("%+v: %q, want %q", tc.d, got, tc.want)
		}
	}
}

// TestCommitGateSaysWhyTheQuickScanDidNotFinish: S-793's verdict carries
// the scan's reason through the gate (Event.Security.QuickScanDetail).
func TestCommitGateSaysWhyTheQuickScanDidNotFinish(t *testing.T) {
	eng := gateEngine(t, policy.ModeObserve)
	st := &policy.Security{
		Posture: policy.SecurityPostureDirty, QuickScan: policy.QuickScanUnknown,
		QuickScanDetail: policy.QuickScanDetail{Reason: policy.QuickScanReasonBudget, Budget: 2 * time.Second, Files: 31},
	}
	v := eng.Evaluate(shellEvent("git commit -m wip", true, st))
	if v.RuleID != "S-793" || v.Decision != policy.DecisionAsk {
		t.Fatalf("verdict = %+v, want S-793 ask", v)
	}
	if !strings.Contains(v.Reason, "the quick scan timed out after 2 s on 31 files") {
		t.Fatalf("reason %q does not say why", v.Reason)
	}
}
