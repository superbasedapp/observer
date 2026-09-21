package processobs

import (
	"testing"
	"time"
)

var tCorr = time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)

func cRun(key, parent string, startOffset time.Duration, exe, argv string) ProcRunRef {
	return ProcRunRef{
		ProcessKey:       key,
		ParentProcessKey: parent,
		StartedAt:        tCorr.Add(startOffset),
		ExeBasename:      exe,
		ArgvPreview:      argv,
	}
}

func cAction(id int64, turn int, cmd string, offset time.Duration) ActionRef {
	t := turn
	return ActionRef{ActionID: id, TurnIndex: &t, Command: cmd, Timestamp: tCorr.Add(offset)}
}

// linkMap indexes the result by process key → action id for easy assertion.
func linkMap(links []ActionLink) map[string]int64 {
	m := make(map[string]int64, len(links))
	for _, l := range links {
		m[l.ProcessKey] = l.ActionID
	}
	return m
}

// TestCorrelateAnchorsAndPropagates pins the core: the `npm` process matches
// the "npm test" action by exe (score 2), the `sh -c` wrapper matches by argv
// (score 1), and the un-matching `node` descendant inherits the action down
// the tree.
func TestCorrelateAnchorsAndPropagates(t *testing.T) {
	t.Parallel()
	actions := []ActionRef{cAction(10, 5, "npm test", 0)}
	runs := []ProcRunRef{
		cRun("k_sh", "", time.Second, "bash", "bash -c npm test"),
		cRun("k_npm", "k_sh", time.Second, "npm", "npm test"),
		cRun("k_node", "k_npm", 2*time.Second, "node", "node x.js"),
	}
	got := linkMap(CorrelateActions(runs, actions, 0))
	for _, k := range []string{"k_sh", "k_npm", "k_node"} {
		if got[k] != 10 {
			t.Errorf("%s linked to action %d, want 10", k, got[k])
		}
	}
	// turn_index must carry through.
	for _, l := range CorrelateActions(runs, actions, 0) {
		if l.TurnIndex == nil || *l.TurnIndex != 5 {
			t.Errorf("link %s missing turn_index 5: %+v", l.ProcessKey, l.TurnIndex)
		}
	}
}

// TestCorrelateNestedCommandsNearestAnchorWins pins the subtree partition: a
// nested `go build` under `make` claims its own descendants; `make` does not
// TestCorrelateActionLoggedAtCommandEnd pins the codex case: the run_command
// action is timestamped at the command FINISH (exec_command_end) and carries
// the duration, so the process it spawned started ~Duration BEFORE the action
// timestamp. Without the duration-widened back-skew that process falls outside
// the 2s window and never links to the message that ran it.
func TestCorrelateActionLoggedAtCommandEnd(t *testing.T) {
	t.Parallel()
	// git ran for 10s; the action is logged at its end (tCorr+10s).
	runs := []ProcRunRef{cRun("k_git", "", 0, "git.exe", "git status")}
	act := ActionRef{
		ActionID:  42,
		Command:   "git status",
		Timestamp: tCorr.Add(10 * time.Second),
		Duration:  10 * time.Second,
	}

	// Control: with no recorded duration, the process (10s before the action)
	// is outside the 2s back-skew → must NOT link.
	noDur := act
	noDur.Duration = 0
	if linkMap(CorrelateActions(runs, []ActionRef{noDur}, 0))["k_git"] == 42 {
		t.Fatal("control: command-end action with no duration should not link a process that started 10s earlier")
	}
	// With the duration, the back-skew widens to cover it → links.
	if got := linkMap(CorrelateActions(runs, []ActionRef{act}, 0))["k_git"]; got != 42 {
		t.Errorf("git.exe should link via duration-widened back-skew, got action %d", got)
	}
}

// reach past the inner anchor.
func TestCorrelateNestedCommandsNearestAnchorWins(t *testing.T) {
	t.Parallel()
	actions := []ActionRef{
		cAction(10, 1, "make", 0),
		cAction(20, 2, "go build", 5*time.Second),
	}
	runs := []ProcRunRef{
		cRun("k_make", "", time.Second, "make", "make"),
		cRun("k_go", "k_make", 6*time.Second, "go", "go build"),
		cRun("k_compile", "k_go", 6*time.Second, "compile", "compile"),
	}
	got := linkMap(CorrelateActions(runs, actions, 0))
	if got["k_make"] != 10 {
		t.Errorf("make → %d, want 10", got["k_make"])
	}
	if got["k_go"] != 20 {
		t.Errorf("go → %d, want 20 (its own anchor)", got["k_go"])
	}
	if got["k_compile"] != 20 {
		t.Errorf("compile → %d, want 20 (nearest anchor is go, not make)", got["k_compile"])
	}
}

func TestCorrelateTimeWindow(t *testing.T) {
	t.Parallel()
	actions := []ActionRef{cAction(10, 1, "npm test", 0)}
	// starts 5 minutes after the action — outside the 30s window.
	runs := []ProcRunRef{cRun("k_npm", "", 5*time.Minute, "npm", "npm test")}
	if links := CorrelateActions(runs, actions, 0); len(links) != 0 {
		t.Errorf("out-of-window process linked: %+v", links)
	}
	// A small negative skew (process observed 1s before the action) still
	// matches.
	runs = []ProcRunRef{cRun("k_npm", "", -time.Second, "npm", "npm test")}
	if links := CorrelateActions(runs, actions, 0); len(links) != 1 {
		t.Errorf("within-skew process not linked: %+v", links)
	}
}

func TestCorrelateAlreadyLinkedUntouched(t *testing.T) {
	t.Parallel()
	actions := []ActionRef{cAction(10, 1, "npm test", 0)}
	r := cRun("k_npm", "", time.Second, "npm", "npm test")
	r.Linked = true
	if links := CorrelateActions([]ProcRunRef{r}, actions, 0); len(links) != 0 {
		t.Errorf("already-linked run reassigned: %+v", links)
	}
}

func TestCorrelateNoMatch(t *testing.T) {
	t.Parallel()
	actions := []ActionRef{cAction(10, 1, "npm test", 0)}
	runs := []ProcRunRef{cRun("k_py", "", time.Second, "python", "python app.py")}
	if links := CorrelateActions(runs, actions, 0); len(links) != 0 {
		t.Errorf("unrelated process linked: %+v", links)
	}
}

// TestParseInvokedBinaries pins the wrapper/compound-command binary parser:
// it sees through `cd … && go build` and `wsl … -- bash -lc '…'`, drops the
// `cd` builtin, and never anchors on the wrapper itself.
func TestParseInvokedBinaries(t *testing.T) {
	t.Parallel()
	contains := func(set []string, want string) bool {
		for _, s := range set {
			if s == want {
				return true
			}
		}
		return false
	}
	if got := parseInvokedBinaries("cd /x && go build"); !contains(got, "go") || contains(got, "cd") {
		t.Errorf(`parseInvokedBinaries("cd /x && go build") = %v, want contains go, not cd`, got)
	}
	if got := parseInvokedBinaries("wsl.exe -d Ubuntu -- bash -lc 'cd /x && go build'"); !contains(got, "go") {
		t.Errorf(`parseInvokedBinaries(wsl … go build) = %v, want contains go`, got)
	}
	if got := parseInvokedBinaries("FOO=1 python a.py | grep x"); !contains(got, "python") || !contains(got, "grep") {
		t.Errorf(`parseInvokedBinaries("FOO=1 python a.py | grep x") = %v, want python + grep`, got)
	}
	if got := parseInvokedBinaries("cd /x"); len(got) != 0 {
		t.Errorf(`parseInvokedBinaries("cd /x") = %v, want empty (builtin)`, got)
	}
	if got := parseInvokedBinaries("npm test"); !contains(got, "npm") {
		t.Errorf(`parseInvokedBinaries("npm test") = %v, want npm`, got)
	}
}

// TestCorrelateAmbiguousRepeatedCommandRejected pins the ambiguity rejection:
// two identical `go build` actions in the window mean a bare `go` process can't
// be attributed to either, so it stays unlinked (no coin-flip). A single such
// action links as before.
func TestCorrelateAmbiguousRepeatedCommandRejected(t *testing.T) {
	t.Parallel()
	twoActions := []ActionRef{
		cAction(10, 1, "go build", 0),
		cAction(20, 2, "go build", 3*time.Second),
	}
	run := cRun("k_go", "", 2*time.Second, "go", "go build")
	if links := CorrelateActions([]ProcRunRef{run}, twoActions, 0); len(links) != 0 {
		t.Errorf("ambiguous repeated command should produce no link, got %+v", links)
	}
	// Single action → unambiguous → links.
	oneAction := []ActionRef{cAction(10, 1, "go build", 0)}
	if got := linkMap(CorrelateActions([]ProcRunRef{run}, oneAction, 0))["k_go"]; got != 10 {
		t.Errorf("single go build action should link, got %d", got)
	}
}

// TestCorrelateWrapperArgvAnchorsAndPropagates pins that a wrapper process
// whose argv carries the compound command anchors by argv (score 1) and
// propagates the action down its subtree, so children that don't match on their
// own (the `compile` grandchild) still link.
func TestCorrelateWrapperArgvAnchorsAndPropagates(t *testing.T) {
	t.Parallel()
	actions := []ActionRef{cAction(30, 7, "cd /x && go build", 0)}
	runs := []ProcRunRef{
		// De-quoted, full-path-expanded argv, as the capture layer records it.
		cRun("k_wrap", "", time.Second, "bash", "/bin/bash -c cd /x && go build"),
		cRun("k_go", "k_wrap", time.Second, "go", "go build"),
		cRun("k_compile", "k_go", 2*time.Second, "compile", "compile -p"),
	}
	got := linkMap(CorrelateActions(runs, actions, 0))
	for _, k := range []string{"k_wrap", "k_go", "k_compile"} {
		if got[k] != 30 {
			t.Errorf("%s linked to %d, want 30", k, got[k])
		}
	}
	// turn_index carries through.
	for _, l := range CorrelateActions(runs, actions, 0) {
		if l.TurnIndex == nil || *l.TurnIndex != 7 {
			t.Errorf("link %s missing turn_index 7: %+v", l.ProcessKey, l.TurnIndex)
		}
	}
}

// TestCorrelateCompoundCommandScore2 pins that a process exe matches the real
// binary invoked inside a compound command (`cd /mnt/d && go build`) at score
// 2, so a single such action links.
func TestCorrelateCompoundCommandScore2(t *testing.T) {
	t.Parallel()
	actions := []ActionRef{cAction(40, 3, "cd /mnt/d && go build", 0)}
	runs := []ProcRunRef{cRun("k_go", "", time.Second, "go", "go build")}
	if got := linkMap(CorrelateActions(runs, actions, 0))["k_go"]; got != 40 {
		t.Errorf("go should link to compound command via score 2, got %d", got)
	}
}

// TestCorrelateCompoundVsStandaloneNoMisLink pins the MED-2 fix: when a
// compound action (`cd /x && go build`) and a standalone look-alike (`go build`)
// both fall in the window, the `go` process the compound spawned must NEVER be
// attributed to the standalone action just because its short argv (`go build`)
// matches it. Both the wrapper and the leaf tie ambiguously (the standalone's
// command is a substring of the compound's), so the correct, conservative
// outcome is to leave them unlinked rather than mis-link to the standalone.
func TestCorrelateCompoundVsStandaloneNoMisLink(t *testing.T) {
	t.Parallel()
	compound := cAction(10, 1, "cd /x && go build", 0)
	standalone := cAction(20, 2, "go build", time.Second)
	runs := []ProcRunRef{
		cRun("k_wrap", "", time.Second, "bash", "/bin/bash -c cd /x && go build"),
		cRun("k_go", "k_wrap", 2*time.Second, "go", "go build"),
	}
	got := linkMap(CorrelateActions(runs, []ActionRef{compound, standalone}, 0))
	if got["k_go"] == 20 {
		t.Errorf("k_go mis-linked to the standalone action 20; it was spawned by the compound (10) or is ambiguous — never the standalone look-alike")
	}
	if got["k_wrap"] == 20 {
		t.Errorf("k_wrap mis-linked to the standalone action 20")
	}
}

func TestLeadingBinary(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"npm test":              "npm",
		"FOO=bar python x.py":   "python",
		"sudo apt update":       "apt",
		"env GO=1 go build":     "go",
		"/usr/bin/go build":     "go",
		`C:\tools\node.exe app`: "node.exe",
		"":                      "",
	}
	for cmd, want := range cases {
		if got := leadingBinary(cmd); got != want {
			t.Errorf("leadingBinary(%q) = %q, want %q", cmd, got, want)
		}
	}
}

func TestExecMatchesLeadingBinary(t *testing.T) {
	t.Parallel()
	match := [][2]string{
		{"git", "git"},
		{"git.exe", "git"},         // Windows .exe suffix
		{"GIT.EXE", "git"},         // case-insensitive
		{"node.exe", "node"},       // .exe
		{"python3.8", "python3"},   // interpreter version tail (dot)
		{"node18", "node"},         // version tail (digit)
		{"python3", "python3.8"},   // either order
		{"codex.exe", "codex.exe"}, // both carry .exe
	}
	for _, c := range match {
		if !execMatchesLeadingBinary(c[0], c[1]) {
			t.Errorf("execMatchesLeadingBinary(%q, %q) = false, want true", c[0], c[1])
		}
	}
	noMatch := [][2]string{
		{"git", "gitk"},  // not a version boundary
		{"go", "gofmt"},  // 'fmt' tail is not version-ish
		{"node", "deno"}, // different binary
		{"", "git"},
		{"git", ""},
	}
	for _, c := range noMatch {
		if execMatchesLeadingBinary(c[0], c[1]) {
			t.Errorf("execMatchesLeadingBinary(%q, %q) = true, want false", c[0], c[1])
		}
	}
}
