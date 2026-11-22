package policy

import (
	"strings"
	"testing"
	"time"
)

// TestR101InCommandDirectoryAndLinks is the pass-2 review M2-01 corpus:
// a recursive delete judged from where the command line has moved to,
// and through links the same line created, rather than from the event's
// own working directory. The fixture is home /home/u, project and cwd
// /home/u/proj (Windows rows: home C:\Users\u, project C:\proj).
func TestR101InCommandDirectoryAndLinks(t *testing.T) {
	t.Parallel()
	const winHome, winRoot = `C:\Users\u`, `C:\proj`
	cases := []destructiveCase{
		// --- the review's bypasses -----------------------------------
		{name: "cd home then delete its contents", cmd: "cd ~ && rm -rf ./*", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "same-command symlink to home", cmd: "ln -s ~ o && rm -rf o/*", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "pushd home then bare glob", cmd: "pushd ~; rm -rf *", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "subshell cd home then dot", cmd: "(cd ~ && rm -rf .)", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "powershell Set-Location home then glob", cmd: "Set-Location ~; Remove-Item -Recurse -Force *", dialect: DialectPowerShell, wantRule: "R-101", wantEnforce: DecisionDeny},

		// --- directory-change variants --------------------------------
		{name: "cd root then glob", cmd: "cd / && rm -rf *", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "cd up twice leaves the project", cmd: "cd .. && cd .. && rm -rf ./*", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "bare cd goes home", cmd: "cd && rm -rf ./*", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "cd to a variable is unresolvable", cmd: "cd $TARGET && rm -rf ./build", wantRule: "R-102", wantEnforce: DecisionAsk},
		{name: "cd to a substitution is unresolvable", cmd: `cd "$(git rev-parse --show-toplevel)/.." && rm -rf ./x`, wantRule: "R-102", wantEnforce: DecisionAsk},
		{name: "cd to a mktemp substitution asks", cmd: "cd $(mktemp -d) && rm -rf ./*", wantRule: "R-102", wantEnforce: DecisionAsk},
		{name: "cd dash with an inherited OLDPWD", cmd: "cd - && rm -rf ./*", wantRule: "R-102", wantEnforce: DecisionAsk},
		{name: "popd past this line's stack", cmd: "pushd /tmp && popd && popd && rm -rf ./x", wantRule: "R-102", wantEnforce: DecisionAsk},
		{name: "cd home or-exit still runs the delete", cmd: "cd ~ || exit 1; rm -rf ./*", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "brace group", cmd: "{ cd ~; rm -rf ./*; }", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "if cd then delete", cmd: "if cd ~; then rm -rf ./*; fi", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "nested shell payload", cmd: `bash -c "cd ~ && rm -rf ./*"`, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "nested shell inherits the cd", cmd: "cd ~ && bash -c 'rm -rf ./*'", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "substitution sees the moved directory", cmd: "cd ~ && echo $(rm -rf ./*)", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "eval moves the shell", cmd: `eval "cd ~"; rm -rf ./*`, wantRule: "R-102", wantEnforce: DecisionAsk},
		{name: "env chdir wrapper", cmd: "env -C ~ rm -rf ./*", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "sudo chdir wrapper", cmd: "sudo -D / rm -rf *", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "inline interpreter after cd", cmd: `cd ~ && python3 -c "import shutil; shutil.rmtree('.')"`, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "powershell Push-Location", cmd: "Push-Location ~; Remove-Item -Recurse -Force *", dialect: DialectPowerShell, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "powershell sl alias with -Path", cmd: "sl -Path ~; ri -r *", dialect: DialectPowerShell, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "cmd cd /d to home", cmd: `cd /d C:\Users\u & rd /s /q .`, dialect: DialectCmd, home: winHome, root: winRoot, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "cmd pushd to drive root", cmd: `pushd C:\ & rd /s /q .`, dialect: DialectCmd, home: winHome, root: winRoot, wantRule: "R-101", wantEnforce: DecisionDeny},

		// --- the "cannot tell" tier: R-102 ASK, never R-101 DENY ----------
		// Orchestrator calibration 2026-10-05: an unresolved directory, or
		// a target outside the project only on the failure branch of a
		// `;`-chained cd / pushd, asks; a catastrophic path in ANY reachable
		// state still denies.
		{name: "ask: loop variable cd", cmd: "for d in a b; do (cd $d && rm -rf node_modules); done", wantRule: "R-102", wantEnforce: DecisionAsk},
		{name: "ask: git toplevel substitution", cmd: `cd "$(git rev-parse --show-toplevel)" && rm -rf dist`, wantRule: "R-102", wantEnforce: DecisionAsk},
		{name: "ask: project dir variable", cmd: "cd $PROJECT_DIR && rm -rf build", wantRule: "R-102", wantEnforce: DecisionAsk},
		{name: "ask: semicolon pushd popd", cmd: "pushd build; make; popd; rm -rf build", wantRule: "R-102", wantEnforce: DecisionAsk},
		{name: "ask: semicolon cd failure branch leaves the project", cmd: "cd build; make; cd ..; rm -rf build", wantRule: "R-102", wantEnforce: DecisionAsk},
		{name: "deny: failure branch that lands on home", cmd: "cd build; cd ..; rm -rf ./*", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "deny: unresolved cd but an absolute catastrophic target", cmd: "cd $X && rm -rf ~", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "deny: catastrophic in one state, unresolved in another", cmd: "cd ~; cd $X; rm -rf ./*", wantRule: "R-101", wantEnforce: DecisionDeny},

		// --- same-command link variants -------------------------------
		{name: "link then cd into it", cmd: "ln -s ~ o; cd o; rm -rf ./*", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "link renamed with mv", cmd: "ln -s ~ o && mv o p && rm -rf p/*", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "link itself with trailing slash", cmd: "ln -sfn ~ o && rm -rf o/", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "relative link target climbs to root", cmd: "ln -s ../../.. up && rm -rf up/*", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "link with -t into a directory", cmd: "ln -s -t links ~ && rm -rf links/u/*", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "link to a variable", cmd: "ln -s $X o && rm -rf o/build", wantRule: "R-102", wantEnforce: DecisionAsk},
		{name: "link with an empty variable tail", cmd: "ln -s ~ o && rm -rf o/$X", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "link outside the project", cmd: "ln -s /etc e && rm -rf e/nginx", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "bind mount", cmd: "mount --bind / m && rm -rf m/*", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "cmd mklink directory", cmd: `mklink /D o C:\Users\u & rd /s /q o`, dialect: DialectCmd, home: winHome, root: winRoot, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "cmd mklink junction", cmd: `mklink /J o C:\ & rd /s /q o`, dialect: DialectCmd, home: winHome, root: winRoot, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "powershell New-Item SymbolicLink", cmd: `New-Item -ItemType SymbolicLink -Path o -Target ~; Remove-Item -Recurse o\*`, dialect: DialectPowerShell, home: winHome, root: winRoot, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "powershell Rename-Item of a new link", cmd: `ni -ItemType Junction -Path o -Value C:\Users\u; Rename-Item o p; Remove-Item -Recurse p\*`, dialect: DialectPowerShell, home: winHome, root: winRoot, wantRule: "R-101", wantEnforce: DecisionDeny},

		// --- R-102 follows the moved directory too ---------------------
		{name: "R-102 project root from a subdirectory", cmd: "cd src && rm -rf ..", wantRule: "R-102", wantEnforce: DecisionAsk},
		{name: "R-102 safe pattern not taken from the event cwd", cmd: "cd /home/u/proj && rm -rf .git", cwd: "/tmp/build", wantRule: "R-102", wantEnforce: DecisionAsk},

		// --- benign controls: must stay allowed (no rule at all) ------
		{name: "ok: cd build then delete out", cmd: "cd build && rm -rf ./out"},
		{name: "ok: cd web then delete two dirs", cmd: "cd web && rm -rf node_modules dist"},
		{name: "ok: cd deep then climb inside the project", cmd: "cd src/app && rm -rf ../../build"},
		{name: "ok: absolute cd inside the project", cmd: "cd /home/u/proj/web && rm -rf .next"},
		{name: "ok: pushd popd round trip", cmd: "pushd web && rm -rf dist && popd"},
		{name: "ok: cd in and back out with and-chain", cmd: "cd build && make && cd .. && rm -rf ./build"},
		{name: "ok: subshell cd does not leak", cmd: "(cd web && npm ci) && rm -rf ./dist"},
		{name: "ok: semicolon cd inside the project", cmd: "cd build; rm -rf ./out"},
		{name: "ok: cd to allowlisted tmp", cmd: "cd /tmp/scratch && rm -rf ./*"},
		{name: "ok: cd home then delete inside the project", cmd: "cd ~ && rm -rf ./proj/build"},
		{name: "ok: cd home and back with dash", cmd: "cd ~ && cd - && rm -rf ./build"},
		{name: "ok: unrelated substitution later in the line", cmd: "cd build && rm -rf ./out && echo $(date)"},
		{name: "ok: quoted directory with a space", cmd: `cd "web app" && rm -rf dist`},
		{name: "ok: absolute allowlisted delete after cd", cmd: "cd web && rm -rf /tmp/cache"},
		{name: "ok: env chdir inside the project", cmd: "env -C web rm -rf dist"},
		{name: "ok: link the delete does not go through", cmd: "ln -s ../shared/config cfg && rm -rf ./build"},
		{name: "ok: link inside the project", cmd: "ln -s dist out && rm -rf out/*"},
		{name: "ok: cd with no delete", cmd: "cd ~ && ls -la"},
		{name: "ok: powershell Set-Location inside the project", cmd: `Set-Location .\web; Remove-Item -Recurse -Force .\dist`, dialect: DialectPowerShell},
		{name: "ok: cmd cd /d inside the project", cmd: `cd /d C:\proj\web & rd /s /q build`, dialect: DialectCmd, home: winHome, root: winRoot},
		{name: "ok: if-block cleanup inside the project", cmd: "if [ -d build ]; then rm -rf build; fi"},
	}
	runRuleCases(t, cases, KindShellExec, "run_command")
}

// TestR101InCommandReasonNamesTheMove pins that a hit judged from a moved
// directory says so, so the operator is not shown "./* is a root-depth
// wildcard" with no hint why.
func TestR101InCommandReasonNamesTheMove(t *testing.T) {
	t.Parallel()
	eng, err := New(Config{Mode: ModeEnforce, Home: "/home/u"})
	if err != nil {
		t.Fatal(err)
	}
	v := eng.Evaluate(Event{
		Kind: KindShellExec, ActionType: "run_command", Target: "cd ~ && rm -rf ./*",
		Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj", Now: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC),
	})
	if v.RuleID != "R-101" || !strings.Contains(v.Reason, "earlier step of this command") {
		t.Fatalf("verdict = %s %q, want R-101 naming the earlier directory change", v.RuleID, v.Reason)
	}
}

// TestR102UnresolvedReasonNamesTheStep pins the ask reason: it quotes the
// move the guard could not resolve and asks for confirmation.
func TestR102UnresolvedReasonNamesTheStep(t *testing.T) {
	t.Parallel()
	eng, err := New(Config{Mode: ModeEnforce, Home: "/home/u"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ cmd, want string }{
		{"cd $PROJECT_DIR && rm -rf build", "target build is relative to `cd $PROJECT_DIR`, which could not be resolved; confirm before a recursive delete"},
		{"cd build; make; cd ..; rm -rf build", "only if `cd build` fails and the line carries on; confirm before a recursive delete"},
	}
	for _, tc := range cases {
		v := eng.Evaluate(Event{
			Kind: KindShellExec, ActionType: "run_command", Target: tc.cmd,
			Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj", Now: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC),
		})
		if v.RuleID != "R-102" || v.Decision != DecisionAsk || !strings.Contains(v.Reason, tc.want) {
			t.Errorf("%q: verdict = %s %s %q, want R-102 ask containing %q", tc.cmd, v.RuleID, v.Decision, v.Reason, tc.want)
		}
	}
}

// TestR102UnresolvedSurvivesAnOrgR101Deny pins why the ask tier is an
// R-102 row: the starter org bundles override R-101 to deny+enforce, and
// that must not turn an unresolved directory back into a hard block.
func TestR102UnresolvedSurvivesAnOrgR101Deny(t *testing.T) {
	t.Parallel()
	deny := DecisionDeny
	eng, err := New(Config{
		Mode: ModeEnforce, Home: "/home/u",
		Overrides: []Override{{RuleID: "R-101", Decision: &deny, Enforced: true, Source: "org"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	v := eng.Evaluate(Event{
		Kind: KindShellExec, ActionType: "run_command", Target: "cd $PROJECT_DIR && rm -rf build",
		Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj", Now: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC),
	})
	if v.RuleID != "R-102" || v.Decision != DecisionAsk {
		t.Fatalf("verdict = %s %s, want R-102 ask under an org R-101 deny override", v.RuleID, v.Decision)
	}
}

// TestUnitAnchorsPlainWithoutMoves pins the compatibility promise: a line
// with no directory change, link or chdir wrapper keeps exactly one plain
// anchor, so every rule judges it as before the model existed.
func TestUnitAnchorsPlainWithoutMoves(t *testing.T) {
	t.Parallel()
	ev := &Event{Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj"}
	ctx := &MatchContext{Event: ev, Cfg: &Config{Home: "/home/u"}}
	for _, line := range []string{
		"rm -rf ./build",
		"make && rm -rf ./out || echo failed; ls | wc -l",
		"(rm -rf ./a) && cp -r x y",
		"bash -c 'rm -rf ./x' && echo $(pwd)",
	} {
		cmds := ParseCommand(line, DialectPosix)
		for i := range cmds {
			if as := unitAnchors(ctx, &cmds[i]); !plainOnly(as) {
				t.Errorf("%q unit %q: anchors %+v, want the single plain anchor", line, cmds[i].Raw, as)
			}
		}
	}
}

// TestParseRecordsListOperators pins the lexer/buildUnits half: each
// unit carries the list operator in front of it and its subshell parens.
func TestParseRecordsListOperators(t *testing.T) {
	t.Parallel()
	cmds := ParseCommand("a && b || c; d | e & (f) && g", DialectPosix)
	seq := cmds[0].seq
	if seq == nil {
		t.Fatal("no sequence recorded")
	}
	want := []struct {
		sep           seqSep
		opens, closes int
	}{{sepSeq, 0, 0}, {sepAnd, 0, 0}, {sepOr, 0, 0}, {sepSeq, 0, 0}, {sepPipe, 0, 0}, {sepSeq, 1, 0}, {sepAnd, 0, 1}}
	if len(seq.steps) != len(want) {
		t.Fatalf("steps = %d, want %d", len(seq.steps), len(want))
	}
	for i, w := range want {
		s := seq.steps[i]
		if s.sep != w.sep || s.opens != w.opens || s.closes != w.closes {
			t.Errorf("step %d: sep=%d opens=%d closes=%d, want %+v", i, s.sep, s.opens, s.closes, w)
		}
	}
}

// TestParseAttributesSubstitutionToItsUnit pins that a stripped command
// substitution marks only the unit it came from, and that words are
// unchanged by the marker.
func TestParseAttributesSubstitutionToItsUnit(t *testing.T) {
	t.Parallel()
	cmds := ParseCommand(`cd $(x) && cd build && echo "$(y)"`, DialectPosix)
	seq := cmds[0].seq
	got := []bool{seq.steps[0].argUnknown, seq.steps[1].argUnknown, seq.steps[2].argUnknown}
	if !got[0] || got[1] || !got[2] {
		t.Fatalf("argUnknown per unit = %v, want [true false true]", got)
	}
	for _, c := range cmds {
		for _, w := range c.Argv {
			if strings.ContainsRune(w, rune(subMarker)) {
				t.Fatalf("marker leaked into argv word %q", w)
			}
		}
	}
	// Since NF-6 (guard-parser lane, 2026-11-22) a whole-word substitution
	// keeps its place as an empty word, as the quoted `"$(x)"` always did,
	// recorded as lost; the directory change stays unknown (argUnknown).
	if cmds[0].Base != "cd" || !equalStrings(cmds[0].Argv, []string{"cd", ""}) || !equalInts(cmds[0].lostArgs, []int{1}) {
		t.Fatalf("cd $(x) argv = %q lost %v, want [cd \"\"] with the empty word lost", cmds[0].Argv, cmds[0].lostArgs)
	}
}

// TestParseStripsLeadingKeywords pins the reserved-word fix found while
// building the corpus: a command after `{`, `then`, `do`, `!` or a
// PowerShell block opener is parsed as that command.
func TestParseStripsLeadingKeywords(t *testing.T) {
	t.Parallel()
	cases := []struct {
		line string
		d    Dialect
	}{
		{"{ rm -rf /; }", DialectPosix},
		{"if true; then rm -rf /; fi", DialectPosix},
		{"while true; do rm -rf /; done", DialectPosix},
		{"! rm -rf /", DialectPosix},
		{"if x; then :; else FOO=1 rm -rf /; fi", DialectPosix},
		{"if ($x) { Remove-Item -Recurse / }", DialectPowerShell},
	}
	for _, tc := range cases {
		found := false
		for _, c := range ParseCommand(tc.line, tc.d) {
			if c.Base == "rm" || c.Base == "remove-item" {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: no delete unit parsed", tc.line)
		}
	}
}

// TestCwdFramesStayBounded pins the fail-closed bound: a line whose
// possible directories outgrow maxFrames ends in an opaque frame (deny),
// and a long ordinary line still evaluates promptly.
func TestCwdFramesStayBounded(t *testing.T) {
	t.Parallel()
	eng, err := New(Config{Mode: ModeEnforce, Home: "/home/u"})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for i := 0; i < 12; i++ {
		b.WriteString("cd d")
		b.WriteByte(byte('a' + i))
		b.WriteString("; ")
	}
	b.WriteString("rm -rf ./build")
	ev := Event{
		Kind: KindShellExec, ActionType: "run_command", Target: b.String(),
		Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj", Now: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC),
	}
	if v := eng.Evaluate(ev); v.RuleID != "R-102" || v.Decision != DecisionAsk {
		t.Fatalf("frame overflow verdict = %s %s %q, want the R-102 fail-closed ask", v.RuleID, v.Decision, v.Reason)
	}
	var long strings.Builder
	// 100 iterations (400 units): about 30ms plain and well under the
	// bound with -race; a frame model that grew per unit would not be.
	for i := 0; i < 100; i++ {
		long.WriteString("cd build && rm -rf ./out && cd .. && ")
	}
	long.WriteString("true")
	ev.Target = long.String()
	start := time.Now()
	if v := eng.Evaluate(ev); v.RuleID != "" {
		t.Fatalf("long benign line verdict = %s %q, want allow", v.RuleID, v.Reason)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("long line took %s", d)
	}
}
