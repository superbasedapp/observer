package processobs

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

var sessT0 = time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)

func cproc(key, parent, basename, cwd string, started time.Time) CrossOSProcRef {
	return CrossOSProcRef{
		ProcessKey: key, ParentProcessKey: parent,
		ExeBasename: basename, CWD: cwd, StartedAt: started,
		Source: AttrNone, Confidence: ConfNone,
	}
}

func claudeSession() CrossOSSessionRef {
	return CrossOSSessionRef{SessionID: "s1", Tool: "claude-code", ProjectID: 7, ProjectRoot: `C:\proj`, StartedAt: sessT0}
}

func TestCorrelateCrossOSAttributesRootAndSubtree(t *testing.T) {
	runs := []CrossOSProcRef{
		cproc("root", "", "claude.exe", `C:\proj`, sessT0.Add(2*time.Second)),           // anchor
		cproc("child", "root", "node.exe", `C:\proj\sub`, sessT0.Add(10*time.Second)),   // inherits (different cwd, later start — OK via tree)
		cproc("grandchild", "child", "git.exe", `C:\other`, sessT0.Add(20*time.Second)), //nolint:misspell // "other" is a path component, not a typo
		cproc("unrelated", "", "explorer.exe", `C:\Windows`, sessT0),
	}
	got := CorrelateCrossOS([]CrossOSSessionRef{claudeSession()}, runs, nil, 0)

	by := map[string]CrossOSAttribution{}
	for _, a := range got {
		by[a.ProcessKey] = a
	}
	for _, k := range []string{"root", "child", "grandchild"} {
		a, ok := by[k]
		if !ok {
			t.Errorf("%s not attributed", k)
			continue
		}
		if a.SessionID != "s1" || a.Source != AttrCrossOSCorrelation || a.Confidence != ConfMedium {
			t.Errorf("%s wrong attribution: %+v", k, a)
		}
	}
	if _, ok := by["unrelated"]; ok {
		t.Error("a process not in the subtree must not be attributed")
	}
	if len(got) != 3 {
		t.Fatalf("attributed %d, want 3", len(got))
	}
}

func TestCorrelateCrossOSCwdMustMatch(t *testing.T) {
	runs := []CrossOSProcRef{cproc("root", "", "claude.exe", `C:\elsewhere`, sessT0.Add(time.Second))}
	if got := CorrelateCrossOS([]CrossOSSessionRef{claudeSession()}, runs, nil, 0); len(got) != 0 {
		t.Fatalf("cwd mismatch must not anchor: %+v", got)
	}
}

func TestCorrelateCrossOSBasenameMustMatch(t *testing.T) {
	runs := []CrossOSProcRef{cproc("root", "", "explorer.exe", `C:\proj`, sessT0.Add(time.Second))}
	if got := CorrelateCrossOS([]CrossOSSessionRef{claudeSession()}, runs, nil, 0); len(got) != 0 {
		t.Fatalf("basename outside the tool set must not anchor: %+v", got)
	}
}

func TestCorrelateCrossOSOutsideWindow(t *testing.T) {
	runs := []CrossOSProcRef{cproc("root", "", "claude.exe", `C:\proj`, sessT0.Add(10*time.Minute))}
	if got := CorrelateCrossOS([]CrossOSSessionRef{claudeSession()}, runs, nil, 0); len(got) != 0 {
		t.Fatalf("a root started outside the window must not anchor: %+v", got)
	}
}

func TestCorrelateCrossOSNearestSessionWins(t *testing.T) {
	s1 := CrossOSSessionRef{SessionID: "s1", Tool: "claude-code", ProjectID: 1, ProjectRoot: `C:\proj`, StartedAt: sessT0}
	s2 := CrossOSSessionRef{SessionID: "s2", Tool: "claude-code", ProjectID: 1, ProjectRoot: `C:\proj`, StartedAt: sessT0.Add(90 * time.Second)}
	root := cproc("root", "", "claude.exe", `C:\proj`, sessT0.Add(86*time.Second)) // |86-0|=86s vs |86-90|=4s → s2
	got := CorrelateCrossOS([]CrossOSSessionRef{s1, s2}, []CrossOSProcRef{root}, nil, 0)
	if len(got) != 1 || got[0].SessionID != "s2" {
		t.Fatalf("nearest session should win (s2): %+v", got)
	}
}

func TestCorrelateCrossOSPreservesHighConfidence(t *testing.T) {
	root := cproc("root", "", "claude.exe", `C:\proj`, sessT0.Add(time.Second))
	child := cproc("child", "root", "node.exe", `C:\proj`, sessT0.Add(2*time.Second))
	child.Source, child.Confidence = AttrBridge, ConfHigh // authoritative
	got := CorrelateCrossOS([]CrossOSSessionRef{claudeSession()}, []CrossOSProcRef{root, child}, nil, 0)
	for _, a := range got {
		if a.ProcessKey == "child" {
			t.Error("must not override a high-confidence child")
		}
	}
	if len(got) != 1 || got[0].ProcessKey != "root" {
		t.Fatalf("expected only root attributed: %+v", got)
	}
}

func TestCorrelateCrossOSIdempotentReconfirm(t *testing.T) {
	root := cproc("root", "", "claude.exe", `C:\proj`, sessT0.Add(time.Second))
	root.Source, root.Confidence = AttrCrossOSCorrelation, ConfMedium // already cross-OS
	got := CorrelateCrossOS([]CrossOSSessionRef{claudeSession()}, []CrossOSProcRef{root}, nil, 0)
	if len(got) != 1 || got[0].ProcessKey != "root" || got[0].SessionID != "s1" {
		t.Fatalf("an already cross-OS run should re-confirm: %+v", got)
	}
}

func TestCorrelateCrossOSStopsAtOtherAnchor(t *testing.T) {
	s1 := CrossOSSessionRef{SessionID: "s1", Tool: "claude-code", ProjectID: 1, ProjectRoot: `C:\a`, StartedAt: sessT0}
	s2 := CrossOSSessionRef{SessionID: "s2", Tool: "codex", ProjectID: 2, ProjectRoot: `C:\b`, StartedAt: sessT0}
	runs := []CrossOSProcRef{
		cproc("r1", "", "claude.exe", `C:\a`, sessT0.Add(time.Second)),     // anchor s1
		cproc("mid", "r1", "node.exe", `C:\x`, sessT0.Add(2*time.Second)),  // inherits s1
		cproc("r2", "mid", "codex.exe", `C:\b`, sessT0.Add(3*time.Second)), // anchor s2 (nested under s1's tree)
		cproc("leaf", "r2", "git.exe", `C:\y`, sessT0.Add(4*time.Second)),  // inherits s2
	}
	got := CorrelateCrossOS([]CrossOSSessionRef{s1, s2}, runs, nil, 0)
	by := map[string]string{}
	for _, a := range got {
		by[a.ProcessKey] = a.SessionID
	}
	if by["r1"] != "s1" || by["mid"] != "s1" {
		t.Errorf("r1/mid should belong to s1: %v", by)
	}
	if by["r2"] != "s2" || by["leaf"] != "s2" {
		t.Errorf("r2/leaf should belong to s2 (subtree handed off at the nested anchor): %v", by)
	}
}

func TestBasenameMatchesPrefixPattern(t *testing.T) {
	set := DefaultCrossOSToolBasenames["codex"]
	match := []string{
		"codex.exe", "node.exe", "node_repl.exe",
		"codex-command-runner-0.140.0-alpha.19.exe", // version-stamped → prefix pattern
		"CODEX-COMMAND-RUNNER-0.99.exe",             // case-insensitive prefix
	}
	for _, b := range match {
		if !basenameMatches(b, set) {
			t.Errorf("basenameMatches(%q, codex set) = false, want true", b)
		}
	}
	noMatch := []string{
		"", "explorer.exe",
		"codex-helper.exe",   // shares "codex-" but not the runner prefix
		"command-runner.exe", // missing the codex- prefix
	}
	for _, b := range noMatch {
		if basenameMatches(b, set) {
			t.Errorf("basenameMatches(%q, codex set) = true, want false", b)
		}
	}
}

// TestGrokVersionedArtifactBasename pins the live-observed install shape
// (2026-08-21): grok ships as a version-stamped artifact
// (grok-1.0.0-linux-x86_64), which the exact-name set missed — the process
// rows persisted unattributed until the prefix pattern was added.
func TestGrokVersionedArtifactBasename(t *testing.T) {
	set := DefaultCrossOSToolBasenames["grok"]
	for _, b := range []string{"grok", "grok.exe", "grok-1.0.0-linux-x86_64"} {
		if !basenameMatches(b, set) {
			t.Errorf("basenameMatches(%q, grok set) = false, want true", b)
		}
	}
	for _, b := range []string{"grokkit", "grok"} {
		if b == "grok" {
			continue // exact entry, asserted above
		}
		if basenameMatches(b, set) {
			t.Errorf("basenameMatches(%q, grok set) = true, want false", b)
		}
	}
}

// TestCorrelateCrossOSCodexDesktopWorkers pins that the Codex desktop app's
// command-execution workers — the version-stamped codex-command-runner-<ver>.exe
// and node_repl.exe, both spawned in the project cwd — anchor a codex session at
// medium confidence. Regression: the codex basename set once listed only
// codex.exe/node.exe, so these rows stayed attribution_source=none and the
// per-session Processes panel was empty for Windows codex sessions.
func TestCorrelateCrossOSCodexDesktopWorkers(t *testing.T) {
	sess := CrossOSSessionRef{SessionID: "cdx", Tool: "codex", ProjectID: 9, ProjectRoot: `C:\programsx\superbased-observer`, StartedAt: sessT0}
	runs := []CrossOSProcRef{
		cproc("runner", "", "codex-command-runner-0.140.0-alpha.19.exe", `C:\programsx\superbased-observer`, sessT0.Add(8*time.Second)),
		cproc("repl", "", "node_repl.exe", `C:\programsx\superbased-observer`, sessT0.Add(time.Second)),
	}
	got := CorrelateCrossOS([]CrossOSSessionRef{sess}, runs, nil, 0)
	by := map[string]CrossOSAttribution{}
	for _, a := range got {
		by[a.ProcessKey] = a
	}
	for _, k := range []string{"runner", "repl"} {
		a, ok := by[k]
		if !ok {
			t.Errorf("%s not attributed (codex desktop worker basename should anchor)", k)
			continue
		}
		if a.SessionID != "cdx" || a.Source != AttrCrossOSCorrelation || a.Confidence != ConfMedium {
			t.Errorf("%s wrong attribution: %+v", k, a)
		}
	}
	if len(got) != 2 {
		t.Fatalf("attributed %d, want 2", len(got))
	}
}

// TestCorrelateCrossOSClimbsToSessionRoot mirrors the WSL-native codex case: the
// session ROOT (codex) launched ~14s before the session file logged its first
// event, so it falls outside bestSession's back-skew and only a later codex
// CHILD anchors directly. The root's OTHER children (a python the session ran)
// are siblings of that child — they must still be attributed by climbing the
// anchor up to the root, whose subtree then inherits.
func TestCorrelateCrossOSClimbsToSessionRoot(t *testing.T) {
	sess := CrossOSSessionRef{SessionID: "wsl", Tool: "codex", ProjectID: 3, ProjectRoot: "/home/u/proj", StartedAt: sessT0}
	runs := []CrossOSProcRef{
		cproc("shell", "", "bash", "/home/u", sessT0.Add(-20*time.Second)),              // launcher — climb must stop here
		cproc("root", "shell", "codex", "/home/u/proj", sessT0.Add(-14*time.Second)),    // session root: outside back-skew → won't anchor directly
		cproc("child", "root", "codex", "/home/u/proj", sessT0.Add(8*time.Second)),      // codex child: anchors directly
		cproc("py", "root", "python3.8", "/home/u/proj", sessT0.Add(10*time.Second)),    // the python the session ran — sibling of child
		cproc("pychild", "py", "python3.8", "/home/u/proj", sessT0.Add(11*time.Second)), // grandchild under python
	}
	got := CorrelateCrossOS([]CrossOSSessionRef{sess}, runs, nil, 0)
	by := map[string]CrossOSAttribution{}
	for _, a := range got {
		by[a.ProcessKey] = a
	}
	for _, k := range []string{"root", "child", "py", "pychild"} {
		a, ok := by[k]
		if !ok {
			t.Errorf("%s should be attributed (anchor climbed to root → subtree inherits)", k)
			continue
		}
		if a.SessionID != "wsl" || a.Confidence != ConfMedium {
			t.Errorf("%s wrong attribution: %+v", k, a)
		}
	}
	if _, ok := by["shell"]; ok {
		t.Error("the non-codex launcher must NOT be attributed (climb stops at it)")
	}
	if len(got) != 4 {
		t.Fatalf("attributed %d, want 4 (root, child, py, pychild)", len(got))
	}
}

// TestCorrelateCrossOSAnchorsRootStartedBeforeSession pins the back-skew widening:
// a codex root that launched ~12s BEFORE the session's first-logged event (codex
// starts its process, then started_at comes from the first user prompt) must
// still anchor — at the old 5s back-skew it fell out and nothing attributed.
func TestCorrelateCrossOSAnchorsRootStartedBeforeSession(t *testing.T) {
	sess := CrossOSSessionRef{SessionID: "s", Tool: "codex", ProjectID: 1, ProjectRoot: "/home/u/proj", StartedAt: sessT0}
	runs := []CrossOSProcRef{
		cproc("node", "", "node", "/home/u/proj", sessT0.Add(-12*time.Second)), // root, before session
		cproc("codex", "node", "codex", "/home/u/proj", sessT0.Add(-12*time.Second)),
		cproc("py", "codex", "python3.8", "/home/u/proj", sessT0.Add(5*time.Second)), // the command, after
	}
	got := CorrelateCrossOS([]CrossOSSessionRef{sess}, runs, nil, 0)
	by := map[string]bool{}
	for _, a := range got {
		by[a.ProcessKey] = true
	}
	for _, k := range []string{"node", "codex", "py"} {
		if !by[k] {
			t.Errorf("%s not attributed (a root started before the session must anchor via back-skew)", k)
		}
	}
}

// TestCorrelateCrossOSAttributesIDEWorkersViaLauncherAncestor pins the
// inverse-of-codex IDE shape: a branded IDE process runs from the INSTALL dir
// and spawns GENERIC workers (git/go/gopls) in the project cwd. The generic
// workers anchor because an ancestor is the tool's branded launcher, NOT
// because their own basename is in the worker set.
func TestCorrelateCrossOSAttributesIDEWorkersViaLauncherAncestor(t *testing.T) {
	sess := CrossOSSessionRef{SessionID: "cur", Tool: "cursor", ProjectID: 1, ProjectRoot: `C:\proj`, StartedAt: sessT0}
	runs := []CrossOSProcRef{
		// Cursor.exe runs from the install dir (NOT the project) — never anchors itself.
		cproc("cursor", "", "Cursor.exe", `C:\Users\me\AppData\Local\Programs\cursor`, sessT0.Add(-5*time.Second)),
		// Generic workers spawned by Cursor.exe, running in the project cwd.
		cproc("gopls", "cursor", "gopls.exe", `C:\proj`, sessT0.Add(10*time.Second)),
		cproc("go", "gopls", "go.exe", `C:\proj`, sessT0.Add(11*time.Second)),          // descendant of a worker (inherits)
		cproc("ps", "cursor", "powershell.exe", `C:\proj`, sessT0.Add(12*time.Second)), // sibling worker
	}
	got := CorrelateCrossOS([]CrossOSSessionRef{sess}, runs, nil, 0)
	by := map[string]bool{}
	for _, a := range got {
		by[a.ProcessKey] = true
	}
	for _, k := range []string{"gopls", "go", "ps"} {
		if !by[k] {
			t.Errorf("%s not attributed (a project-cwd worker under the tool's branded launcher must anchor)", k)
		}
	}
	if by["cursor"] {
		t.Error("Cursor.exe (install-dir cwd) must NOT be attributed — only its project-cwd descendants")
	}
}

// TestCorrelateCrossOSLauncherAncestorDisambiguatesAndGuards pins the two
// safety properties of launcher-ancestor anchoring: (1) the SAME generic
// worker basename in ONE shared project dir attributes to the right tool by
// its branded parent (a git under OpenCode.exe → opencode; a git under
// Codex.exe → codex — the live opencode-win case); (2) a manual git with NO
// branded ancestor in the same project+window is NOT attributed to either.
func TestCorrelateCrossOSLauncherAncestorDisambiguatesAndGuards(t *testing.T) {
	oc := CrossOSSessionRef{SessionID: "oc", Tool: "opencode", ProjectID: 1, ProjectRoot: `C:\proj`, StartedAt: sessT0}
	cx := CrossOSSessionRef{SessionID: "cx", Tool: "codex", ProjectID: 2, ProjectRoot: `C:\proj`, StartedAt: sessT0}
	runs := []CrossOSProcRef{
		cproc("ocapp", "", "OpenCode.exe", `C:\Users\me`, sessT0.Add(-3*time.Second)),
		cproc("cxapp", "", "Codex.exe", `C:\Program Files\WindowsApps\OpenAI.Codex`, sessT0.Add(-3*time.Second)),
		cproc("git-oc", "ocapp", "git.exe", `C:\proj`, sessT0.Add(5*time.Second)), // → opencode
		cproc("git-cx", "cxapp", "git.exe", `C:\proj`, sessT0.Add(6*time.Second)), // → codex
		cproc("git-manual", "shell", "git.exe", `C:\proj`, sessT0.Add(7*time.Second)),
		cproc("shell", "", "bash.exe", `C:\proj`, sessT0.Add(4*time.Second)), // no branded ancestor
	}
	got := CorrelateCrossOS([]CrossOSSessionRef{oc, cx}, runs, nil, 0)
	bySess := map[string]string{}
	for _, a := range got {
		bySess[a.ProcessKey] = a.SessionID
	}
	if bySess["git-oc"] != "oc" {
		t.Errorf("git under OpenCode.exe = %q, want opencode session", bySess["git-oc"])
	}
	if bySess["git-cx"] != "cx" {
		t.Errorf("git under Codex.exe = %q, want codex session", bySess["git-cx"])
	}
	if _, attributed := bySess["git-manual"]; attributed {
		t.Errorf("a manual git with no branded ancestor must NOT attribute; got %q", bySess["git-manual"])
	}
}

// TestCorrelateCrossOSAnchorsRootStartedWellBeforeSession pins the widened
// back-skew against the live Windows-capture case that motivated it: a CLI
// launched ~45s before the first logged prompt (the old 30s skew dropped it).
func TestCorrelateCrossOSAnchorsRootStartedWellBeforeSession(t *testing.T) {
	sess := CrossOSSessionRef{SessionID: "s", Tool: "pi", ProjectID: 1, ProjectRoot: `C:\programsx\salesAgentAI`, StartedAt: sessT0}
	// node root launched 45s before the session's first logged event; cwd is
	// the project root (Windows shape). Folds to the WSL form on a WSL daemon.
	runs := []CrossOSProcRef{
		cproc("node", "", "node.exe", `C:\programsx\salesAgentAI`, sessT0.Add(-45*time.Second)),
	}
	got := CorrelateCrossOS([]CrossOSSessionRef{sess}, runs, nil, 0)
	if len(got) != 1 || got[0].ProcessKey != "node" || got[0].Source != AttrCrossOSCorrelation {
		t.Fatalf("a root 45s before the session must anchor via the widened back-skew; got %+v", got)
	}
}

func TestPathsEqual(t *testing.T) {
	match := [][2]string{
		{`C:\proj`, `C:\proj\`},
		{`C:\Proj`, `c:\proj`},
		{`C:/proj`, `C:\proj`},
		{`C:\proj\`, `C:\proj`},
	}
	for _, c := range match {
		if !pathsEqual(c[0], c[1]) {
			t.Errorf("pathsEqual(%q, %q) = false, want true", c[0], c[1])
		}
	}
	noMatch := [][2]string{
		{`C:\proj`, `C:\proj2`},
		{"", ""},
		{"", `C:\proj`},
	}
	for _, c := range noMatch {
		if pathsEqual(c[0], c[1]) {
			t.Errorf("pathsEqual(%q, %q) = true, want false", c[0], c[1])
		}
	}
}

// TestPathsEqual_CrossOSFold pins Option A (cwd-attribution scoping B2): a
// Windows-shaped process cwd and a WSL-shaped session root that name the same
// directory must compare equal so a Windows-captured codex/cursor process can
// anchor to a WSL session. The fold depends on pathnorm rewriting drive-letter
// paths to /mnt/<drive>/… which only happens on a non-Windows host, so this is
// skipped on the Windows test host and validated via the WSL cross-compile
// workflow (GOOS=linux go test -c → run in WSL).
func TestPathsEqual_CrossOSFold(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("drive→/mnt fold is non-Windows only; validated via WSL cross-compile")
	}
	match := [][2]string{
		{`D:\programsx\superbased-observer`, "/mnt/d/programsx/superbased-observer"},
		{`D:\proj\`, "/mnt/d/proj"},
		{`C:/proj`, "/mnt/c/proj"},
		{`d:\Proj`, "/mnt/d/proj"},                               // case-fold too
		{`/c:/programsx/marmutmain`, `C:\programsx\marmutmain\`}, // VS Code URI fsPath (Cursor/Code session root)
		{`/c:/proj`, "/mnt/c/proj"},
	}
	for _, c := range match {
		if !pathsEqual(c[0], c[1]) {
			t.Errorf("pathsEqual(%q, %q) = false, want true (cross-OS fold)", c[0], c[1])
		}
	}
	// Different drives / different projects must still NOT match.
	noMatch := [][2]string{
		{`D:\proj`, "/mnt/c/proj"},  // different drive
		{`D:\proj`, "/mnt/d/proj2"}, // different dir
	}
	for _, c := range noMatch {
		if pathsEqual(c[0], c[1]) {
			t.Errorf("pathsEqual(%q, %q) = true, want false", c[0], c[1])
		}
	}
}

// TestRefreshLauncherCoversWaveNativeBinaries pins that every 2026-07-wave
// tool's DISTINCTIVE native-binary basename (and its .exe form) is in
// DefaultRefreshLauncherBasenames — without them the wave is silently
// downgraded to the fragile cwd-anchor rule (audit 2026-07-15 root-cause #4).
func TestRefreshLauncherCoversWaveNativeBinaries(t *testing.T) {
	t.Parallel()
	wave := []string{
		"qwen", "kiro-cli", "crush", "kimi",
		"grok", "devin", "aider", "qoder", "goose",
	}
	for _, name := range wave {
		for _, base := range []string{name, name + ".exe"} {
			if !IsAIToolLauncher(base) {
				t.Errorf("IsAIToolLauncher(%q) = false, want true (2026-07 wave native-binary launcher)", base)
			}
		}
	}
}

// TestRefreshLauncherExcludesGenericInterpreters pins the documented exclusion
// rule: the generic interpreter names the wave tools' shims present
// (node/python/bun) are NEVER refresh launchers — matching them on name alone
// (no cwd guard at the capturer) would false-anchor a stray interpreter and
// flood the cross-OS wire (crossos.go NOTE + the DefaultRefreshLauncherBasenames
// doc comment).
func TestRefreshLauncherExcludesGenericInterpreters(t *testing.T) {
	t.Parallel()
	for _, base := range []string{"node", "node.exe", "python", "python.exe", "python3", "bun", "bun.exe"} {
		if IsAIToolLauncher(base) {
			t.Errorf("IsAIToolLauncher(%q) = true, want false (generic interpreter must never be a refresh launcher)", base)
		}
	}
}

// TestIsAIToolLauncherMatching is the table over BOTH matching rules — the
// exact map and the version-stamped prefix list added for muse (task 9e).
// Every row is grounded on a live install (2026-08-27), including the negative
// ones: a tool absent here is absent because its launcher is a script whose
// exec'd basename is an interpreter, not because nobody looked.
func TestIsAIToolLauncherMatching(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		exe  string
		want bool
		why  string
	}{
		// --- exact map, unchanged semantics -----------------------------
		{"branded binary", "/usr/bin/claude", true, "exact map hit"},
		{"windows form", `C:\tools\codex.exe`, true, "exact map hit, .exe variant"},
		{"case folded", "/usr/bin/CLAUDE", true, "matched case-insensitively"},
		{
			"open-interpreter's real basename", "/home/u/.local/bin/interpreter", true,
			"grounded: the installed ELF is `interpreter`; there is no `open-interpreter` binary in PATH",
		},
		{"open-interpreter windows form", "interpreter.exe", true, "the .exe variant of the same"},
		{"droid native binary", "/home/u/.local/bin/droid", true, "grounded: Factory AI ships a native ELF named `droid`"},

		// --- prefix rule, the only thing this change adds ----------------
		{
			"muse versioned binary", "/home/u/.local/bin/muse-bin-0.2.1-R1215.1", true,
			"grounded: muse's real binary is version-stamped, so no exact name survives an upgrade",
		},
		{"muse a future version", "muse-bin-9.9.9-R0001.0", true, "the prefix is what is stable, not the tail"},
		{"muse windows form", `C:\muse\muse-bin-0.2.1.exe`, true, "prefix matches before the extension"},

		// --- the prefix must stay narrow --------------------------------
		{
			"muse wrapper script's interpreter", "/bin/bash", false,
			"~/.local/bin/muse is a bash script; matching bash would anchor every shell on the box",
		},
		{
			"a bare muse name is not the prefix", "muse", false,
			"the wrapper, not the binary — and `muse` alone is too generic to match on name",
		},
		{"an unrelated binary sharing a stem", "musexyz", false, "the prefix requires the -bin- separator"},
		{
			"prefix must anchor at the start", "/opt/x/not-muse-bin-1.0", false,
			"HasPrefix, never Contains — a substring rule would match arbitrary paths",
		},

		// --- the script-wrapper tools stay unrepresentable ---------------
		{
			"hermes wrapper", "/home/u/.local/bin/hermes", false,
			"grounded: a bash script; the worker execs as python (documented limitation)",
		},
		{"vibe wrapper", "/home/u/.local/bin/vibe", false, "grounded: a python script (mistral-code)"},
		{"zcode wrapper", "/home/u/.nvm/versions/node/v22.16.0/bin/zcode", false, "grounded: a node script"},
		{"freebuff wrapper", "/home/u/.nvm/versions/node/v22.16.0/bin/freebuff", false, "grounded: a node script"},

		// --- the daemon's own wrapper stays out -------------------------
		{
			"the observer wrapper itself", "/usr/local/bin/observer", false,
			"collides with ExcludeOwnBasenames; the launch_seeds.run_id binding (9f) is the principled fix",
		},

		{"empty path", "", false, "no basename, no claim"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsAIToolLauncher(tc.exe); got != tc.want {
				t.Errorf("IsAIToolLauncher(%q) = %v, want %v (%s)", tc.exe, got, tc.want, tc.why)
			}
		})
	}
}

// TestRefreshLauncherPrefixesAreNarrow guards the prefix list itself. A short
// or generic prefix would match far more than its tool and flood the cross-OS
// wire — the exact failure the exact-match design was chosen to avoid — so the
// bar for adding one is pinned here rather than left to review.
func TestRefreshLauncherPrefixesAreNarrow(t *testing.T) {
	t.Parallel()
	for _, p := range DefaultRefreshLauncherPrefixes {
		if p != strings.ToLower(p) {
			t.Errorf("prefix %q must be lowercase or it can never match", p)
		}
		if len(p) < 6 {
			t.Errorf("prefix %q is too short to be distinctive without a cwd guard", p)
		}
		// Every generic interpreter must stay unmatched by every prefix.
		for _, generic := range []string{"node", "python", "python3", "bun", "bash", "sh", "observer"} {
			if strings.HasPrefix(generic, p) || strings.HasPrefix(p, generic) {
				t.Errorf("prefix %q overlaps the generic name %q — it would anchor unrelated processes", p, generic)
			}
		}
	}
}
