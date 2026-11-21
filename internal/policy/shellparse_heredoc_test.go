package policy

import (
	"testing"
	"time"
)

// heredocCase is one engine-level row for heredoc / here-string bodies: a
// command line evaluated in ModeEnforce under a reading context, and the rule
// it must hit ("" = allow).
type heredocCase struct {
	name, cmd, rule string
	// win runs the event the way a Windows node sees an unstated-shell tool:
	// no dialect, a Windows working directory, and the PowerShell second
	// reading (Event.AltDialect). Otherwise the event is POSIX on /home/u.
	win bool
	// dialect overrides the POSIX default when set (and win is false).
	dialect Dialect
}

// runHeredocCases evaluates each row against a fresh enforce-mode engine.
func runHeredocCases(t *testing.T, cases []heredocCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			home, cwd, d, alt := "/home/u", "/home/u/proj", DialectPosix, Dialect("")
			if tc.dialect != "" {
				d = tc.dialect
			}
			if tc.win {
				home, cwd, d, alt = `C:\Users\u`, `D:\x\fx-selfappr`, "", DialectPowerShell
			}
			e, err := New(Config{Mode: ModeEnforce, Home: home})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			v := e.Evaluate(Event{
				Kind: KindShellExec, ActionType: "run_command", Target: tc.cmd,
				Dialect: d, AltDialect: alt, Cwd: cwd, ProjectRoot: cwd, SessionID: "s1",
				Now: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
			})
			if tc.rule == "" {
				if v.Decision != DecisionAllow {
					t.Errorf("%q = %s/%s (%s), want allow", tc.cmd, v.Decision, v.RuleID, v.Reason)
				}
				return
			}
			if v.RuleID != tc.rule || v.Decision != DecisionDeny {
				t.Errorf("%q = %s/%s (%s), want %s/deny", tc.cmd, v.Decision, v.RuleID, v.Reason, tc.rule)
			}
		})
	}
}

// appendGo is the live false-positive shape (2026-11-08): Go test text
// appended to a project file through a quoted heredoc. The write target is
// the .go file after `>>`; the body is data.
func appendGo(body string) string {
	return "cd /d/x/fx-selfappr && cat >> internal/policy/rules_selfapproval_recipes_test.go <<'EOF'\n" + body + "\nEOF"
}

// TestHeredocBodyIsNotAWriteTarget pins that a heredoc or here-string BODY is
// never read as a write-target path by R-152 / R-154 / R-160 (or any other
// boundary row), in the POSIX reading and in the Windows PowerShell second
// reading, while a real write to a protected file through a heredoc still
// denies.
func TestHeredocBodyIsNotAWriteTarget(t *testing.T) {
	t.Parallel()
	runHeredocCases(t, []heredocCase{
		// --- False positives: body text only, must allow ---
		{name: "live shape: plain mention", cmd: appendGo("// test text that mentions ~/.bashrc and export OBSERVER_GUARD_MODE=off")},
		{name: "live shape: plain mention, windows", cmd: appendGo("// test text that mentions ~/.bashrc and export OBSERVER_GUARD_MODE=off"), win: true},
		{name: "backtick raw string in quoted body", cmd: appendGo("{cmd: `echo 'export OBSERVER_GUARD_MODE=off' >> ~/.bashrc`}")},
		{name: "backtick raw string in quoted body, windows", cmd: appendGo("{cmd: `echo 'export OBSERVER_GUARD_MODE=off' >> ~/.bashrc`}"), win: true},
		{name: "dollar-paren in quoted body", cmd: appendGo("// $(cat > ~/.bashrc) is the shape")},
		{name: "double-quoted delimiter body", cmd: "cat >> notes.md <<\"EOF\"\nsee `tee -a ~/.zshrc`\nEOF"},
		{name: "redirect line in body, windows reading", cmd: appendGo("echo 'export X=1' >> ~/.bashrc"), win: true},
		{name: "R-152 path in body, windows reading", cmd: appendGo("echo key >> ~/.ssh/authorized_keys"), win: true},
		{name: "R-160 path in quoted body", cmd: appendGo("`sed -i s/a/b/ ~/.observer/config.toml`")},
		{name: "R-160 path in body, windows reading", cmd: appendGo("echo x > ~/.observer/config.toml"), win: true},
		{name: "single-quoted here-string", cmd: "cat >> notes.md <<< 'see `tee -a ~/.bashrc` here'"},
		{name: "powershell literal here-string body", cmd: "Set-Content -Path notes.md -Value @'\nAdd-Content -Path ~/.bashrc -Value x\n'@", dialect: DialectPowerShell},
		{name: "powershell expandable here-string body", cmd: "Set-Content -Path notes.md -Value @\"\nsee >> ~/.bashrc here\n\"@", dialect: DialectPowerShell},
		{name: "powershell here-string INTO bashrc still denies", cmd: "Set-Content -Path ~/.bashrc -Value @'\nx\n'@", rule: "R-154", dialect: DialectPowerShell},

		// --- True positives: the heredoc WRITES the protected file ---
		{name: "cat >> bashrc heredoc", cmd: "cat >> ~/.bashrc <<'EOF'\nalias ll='ls -la'\nEOF", rule: "R-154"},
		{name: "cat >> bashrc heredoc, windows", cmd: "cat >> ~/.bashrc <<'EOF'\nalias ll='ls -la'\nEOF", rule: "R-154", win: true},
		{name: "tee -a bashrc heredoc", cmd: "tee -a ~/.bashrc <<'EOF'\nexport X=1\nEOF", rule: "R-154"},
		{name: "tee -a bashrc heredoc, windows", cmd: "tee -a ~/.bashrc <<'EOF'\nexport X=1\nEOF", rule: "R-154", win: true},
		{name: "cat > observer config heredoc", cmd: "cat > ~/.observer/config.toml <<'EOF'\n[guard]\nEOF", rule: "R-160"},
		// An UNQUOTED body's substitutions do run, so they stay analysed.
		{name: "unquoted body substitution runs", cmd: "cat > out.txt <<EOF\n$(tee -a ~/.bashrc < /dev/null)\nEOF", rule: "R-154"},
		// An interpreter reading the body as code keeps the SA-1 inline row.
		{name: "python heredoc program still R-160", cmd: "python3 - <<'PY'\nopen('/home/u/.observer/config.toml','a').write('x')\nPY", rule: "R-160"},
		// A real PowerShell write with no heredoc is unchanged.
		{name: "powershell Add-Content bashrc", cmd: "Add-Content -Path ~/.bashrc -Value x", rule: "R-154", dialect: DialectPowerShell},
		// Fail-safe: when PowerShell sees the `<<` inside its own string, the
		// line parses under PowerShell, so its following line is still judged.
		{name: "powershell string holding <<, next line judged", cmd: "Write-Output \"<<EOF\"\nAdd-Content -Path ~/.bashrc -Value x", rule: "R-154", dialect: DialectPowerShell},
	})
}

// TestPSOperatorUnquoted pins the conservative PowerShell quote scan the
// heredoc reading depends on: it answers true only for a `<` outside every
// PowerShell string, and false whenever it cannot be sure.
func TestPSOperatorUnquoted(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, s string
		want    bool
	}{
		{"bare heredoc operator", "cat >> f <<'EOF'", true},
		{"inside double quotes", `echo "<<EOF"`, false},
		{"inside single quotes", `echo '<<EOF'`, false},
		{"after a closed string", `echo "a" <<EOF`, true},
		{"after doubled single quote", `echo 'it''s' <<EOF`, true},
		{"backtick-escaped", "echo `<<EOF", false},
		{"block comment opener", "echo <#x#>", false},
		{"after a comment", "# note\ncat <<EOF", false},
		{"after a here-string", "@'\nx\n'@ <<EOF", false},
		{"subexpression in string", `echo "$(x)" <<EOF`, false},
		{"non-ascii before", "echo \u201cx\u201d <<EOF", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pos := -1
			for i := 0; i+1 < len(tc.s); i++ {
				if tc.s[i] == '<' {
					pos = i
					break
				}
			}
			if got := psOperatorUnquoted(tc.s, pos); got != tc.want {
				t.Errorf("psOperatorUnquoted(%q, %d) = %v, want %v", tc.s, pos, got, tc.want)
			}
		})
	}
}
