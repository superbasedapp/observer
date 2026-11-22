package policy

import "testing"

// TestPSHostBarePositionalIsCommand pins NF-3 (guard-parser lane,
// 2026-11-22): Windows PowerShell 5.1 (`powershell.exe`) binds a bare
// positional argument to -Command, so `powershell "Remove-Item -Recurse
// -Force ~"` runs the delete exactly as the -Command form does; the guard
// only unwrapped the explicit -Command spelling, so the bare form ALLOWED in
// enforce mode. pwsh 7 binds the same positional to -File (a script the
// guard cannot read), so only the powershell base takes the 5.1 default.
func TestPSHostBarePositionalIsCommand(t *testing.T) {
	t.Parallel()
	ps, posix, cmd := DialectPowerShell, DialectPosix, DialectCmd
	var cases []destructiveCase
	for _, d := range []Dialect{ps, posix, cmd} {
		for _, c := range []string{
			`powershell "Remove-Item -Recurse -Force ~"`,
			`powershell.exe "Remove-Item -Recurse -Force ~"`,
			`powershell -NoProfile "Remove-Item -Recurse -Force ~"`,
			`powershell -ExecutionPolicy Bypass -NoProfile "Remove-Item -Recurse -Force ~"`,
			`powershell Remove-Item -Recurse -Force ~`,
			// A positional that may be a value, then an explicit -Command:
			// both readings are analysed.
			`powershell -Version 2 -Command "Remove-Item -Recurse -Force ~"`,
			`powershell "Remove-Item -Recurse -Force ~;" -c Get-Date`,
			// The -Command forms, which already denied.
			`powershell -Command "Remove-Item -Recurse -Force ~"`,
			`powershell -c "Remove-Item -Recurse -Force ~"`,
		} {
			cases = append(cases, destructiveCase{name: string(d) + ": " + c, cmd: c, dialect: d, wantRule: "R-101", wantEnforce: DecisionDeny})
		}
	}
	cases = append(cases,
		destructiveCase{name: "Start-Process powershell -ArgumentList", cmd: `Start-Process powershell -ArgumentList "Remove-Item -Recurse -Force ~"`, dialect: ps, wantRule: "R-101", wantEnforce: DecisionDeny},
		destructiveCase{name: "Start-Process powershell -ArgumentList -Command", cmd: `Start-Process powershell -ArgumentList "-Command Remove-Item -Recurse -Force ~"`, dialect: ps, wantRule: "R-101", wantEnforce: DecisionDeny},
		destructiveCase{name: "start powershell (cmd)", cmd: `start powershell "Remove-Item -Recurse -Force ~"`, dialect: cmd, wantRule: "R-101", wantEnforce: DecisionDeny},

		// Honest commands keep their verdicts.
		destructiveCase{name: "honest: powershell ./build.ps1", cmd: "powershell ./build.ps1", dialect: ps},
		destructiveCase{name: "honest: pwsh ./build.ps1", cmd: "pwsh ./build.ps1", dialect: ps},
		destructiveCase{name: "honest: powershell -File", cmd: "powershell -File ./build.ps1 -Configuration Release", dialect: ps},
		destructiveCase{name: "honest: powershell -NoProfile ./build.ps1", cmd: "powershell -NoProfile -ExecutionPolicy Bypass ./build.ps1", dialect: ps},
		destructiveCase{name: "honest: powershell Get-ChildItem", cmd: `powershell "Get-ChildItem -Recurse ./src"`, dialect: ps},
		destructiveCase{name: "honest: powershell -Version", cmd: "powershell -Version", dialect: ps},
		destructiveCase{name: "honest: powershell bare", cmd: "powershell", dialect: ps},
		// pwsh binds the positional to -File: the guard cannot read the
		// script, and does not take its name for command text.
		destructiveCase{name: "pwsh positional is a script", cmd: `pwsh "Remove-Item -Recurse -Force ~"`, dialect: ps},
	)
	runRuleCases(t, cases, KindShellExec, "run_command")
}

// TestPSCommandPayloadsPositional pins the host-argv walk itself: the
// powershell base reads its first positional as the start of the command
// text, pwsh does not, and when a positional and an explicit payload
// parameter both appear both readings are returned (the positional may be
// the value of a parameter the host table reads as a switch).
func TestPSCommandPayloadsPositional(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		argv []string
		want []string
	}{
		{[]string{"powershell", "Remove-Item -Recurse ~"}, []string{"Remove-Item -Recurse ~"}},
		{[]string{"powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "Get-Date", "-Format", "o"}, []string{"Get-Date -Format o"}},
		{[]string{"powershell", "-File", "a.ps1", "x"}, nil},
		{[]string{"powershell", "-Command", "Get-Date"}, []string{"Get-Date"}},
		{[]string{"powershell", "-Version", "2", "-Command", "Get-Date"}, []string{"Get-Date", "2 -Command Get-Date"}},
		{[]string{"powershell", "Get-Date;", "-c", "x"}, []string{"x", "Get-Date; -c x"}},
		{[]string{"powershell.exe", "a.ps1"}, []string{"a.ps1"}},
		{[]string{"pwsh", "a.ps1", "-Command", "Get-Date"}, []string{"Get-Date"}},
		{[]string{"pwsh", "Remove-Item -Recurse ~"}, nil},
		{[]string{"powershell"}, nil},
	} {
		got := psCommandPayloads(tc.argv, canonicalBase(tc.argv[0], DialectPowerShell))
		if !equalStrings(got, tc.want) {
			t.Errorf("psCommandPayloads(%q) = %q, want %q", tc.argv, got, tc.want)
		}
	}
}
