package secrules

import (
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// quickScanUnknownLead is the verdict text of an unknown quick scan whose
// scanner said nothing more (an older daemon, or a reason this table does
// not know).
const quickScanUnknownLead = "the quick scan did not finish"

// quickScanWordsRow renders one reason of an unknown quick scan. timed
// rows add the budget and, when the scan got that far, the files it read.
type quickScanWordsRow struct {
	reasons []string
	words   string
	timed   bool
}

// quickScanWordsTable is the verdict text of each unknown reason
// (policy.QuickScanDetail.Reason), read top to bottom. The numbers come
// from the scan's own detail; nothing here branches on a tool or a path.
var quickScanWordsTable = []quickScanWordsRow{
	{reasons: []string{policy.QuickScanReasonBudget, policy.QuickScanReasonOverBudget}, words: "the quick scan timed out", timed: true},
	{reasons: []string{policy.QuickScanReasonIncomplete}, words: "the quick scan did not finish: a detector ran out of time", timed: true},
	{reasons: []string{policy.QuickScanReasonGit}, words: "the quick scan failed: git could not read the change"},
	{reasons: []string{policy.QuickScanReasonDiffOverCap}, words: "the quick scan did not run: the change is larger than the scan reads"},
	{reasons: []string{policy.QuickScanReasonNoUpstream}, words: "the quick scan did not run: the branch has no upstream to compare the push with"},
	{reasons: []string{policy.QuickScanReasonNotModelled, policy.QuickScanReasonBadRequest}, words: "the quick scan did not run: it does not model what this command records"},
	{reasons: []string{policy.QuickScanReasonUnplaced}, words: "the quick scan did not run: the command commits somewhere the hook cannot place"},
	{reasons: []string{policy.QuickScanReasonRootNotAllowed}, words: "the quick scan did not run: the daemon does not know this repository"},
	{reasons: []string{policy.QuickScanReasonBusy}, words: "the quick scan did not run: the daemon was busy with other scans"},
	{reasons: []string{policy.QuickScanReasonScanFailed}, words: "the quick scan failed: the scanner stopped with an error"},
	{reasons: []string{policy.QuickScanReasonNotServing}, words: "the quick scan did not run: the daemon's quick-scan service is not serving"},
	{reasons: []string{policy.QuickScanReasonNoTime}, words: "the quick scan did not run: no time was left in the host's hook timeout"},
	{reasons: []string{policy.QuickScanReasonNoAnswer}, words: "the quick scan got no answer from the Observer daemon"},
}

// quickScanUnknownWords says why a quick scan answered unknown, from its
// detail: "the quick scan timed out after 2 s on 31 files", "the quick
// scan failed: git could not read the change", or the plain lead when the
// scanner gave no reason.
func quickScanUnknownWords(d policy.QuickScanDetail) string {
	for _, row := range quickScanWordsTable {
		for _, r := range row.reasons {
			if r != d.Reason {
				continue
			}
			if !row.timed {
				return row.words + gitWords(d)
			}
			return row.words + timedWords(d) + gitWords(d)
		}
	}
	return quickScanUnknownLead + gitWords(d)
}

// quickScanGitWords says which git read the change, when it was not the
// host's own (policy.QuickScanDetail.Git, R3-86): a WSL daemon reading a
// checkout on a Windows drive, where the git it used decides how long the
// read takes.
var quickScanGitWords = map[string]string{
	policy.QuickScanGitWindows:       "read with Windows git through WSL interop",
	policy.QuickScanGitDrvFs:         "read with WSL git across the Windows drive mount: no Windows git.exe was usable",
	policy.QuickScanGitDrvFsFallback: "read with WSL git across the Windows drive mount after Windows git failed to run",
}

// gitWords is " (read with ...)" for a detail that names its git, "" else.
func gitWords(d policy.QuickScanDetail) string {
	if w, ok := quickScanGitWords[d.Git]; ok {
		return " (" + w + ")"
	}
	return ""
}

// timedWords is a timed row's numbers: " after N s" when the budget is
// known, then " on M files" when the scan read the change, or " while
// reading the change" when it stopped before.
func timedWords(d policy.QuickScanDetail) string {
	out := ""
	if d.Budget > 0 {
		out += " after " + seconds(d.Budget)
	}
	switch {
	case d.Files == 1:
		out += " on 1 file"
	case d.Files > 1:
		out += " on " + strconv.Itoa(d.Files) + " files"
	case d.Budget > 0:
		out += " while reading the change"
	}
	return out
}

// seconds renders a duration as whole seconds ("2 s"), or tenths below
// ten seconds when it is not whole ("1.5 s").
func seconds(d time.Duration) string {
	if d%time.Second == 0 || d >= 10*time.Second {
		return strconv.FormatInt(int64((d+time.Second/2)/time.Second), 10) + " s"
	}
	return strconv.FormatFloat(d.Seconds(), 'f', 1, 64) + " s"
}
