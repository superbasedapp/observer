package diag

import "testing"

// TestCodexManagedScriptPathReadsThePowerShellForm pins FU-162's managed
// half: the managed commandWindows of a script path that needs quoting is a
// PowerShell literal behind the call operator, and the doctor still finds
// the script it names.
func TestCodexManagedScriptPathReadsThePowerShellForm(t *testing.T) {
	for cmd, want := range map[string]string{
		`/etc/codex/hooks/observer-codex-hook.sh PreToolUse`:                   "/etc/codex/hooks/observer-codex-hook.sh",
		`"/opt/corp hooks/observer-codex-hook.sh" PreToolUse`:                  "/opt/corp hooks/observer-codex-hook.sh",
		`C:\ProgramData\OpenAI\Codex\hooks\observer-codex-hook.cmd PreToolUse`: `C:\ProgramData\OpenAI\Codex\hooks\observer-codex-hook.cmd`,
		`& 'D:\Corp Hooks\observer-codex-hook.cmd' PreToolUse`:                 `D:\Corp Hooks\observer-codex-hook.cmd`,
		`& 'D:\O''Brien Hooks\observer-codex-hook.cmd' Stop`:                   `D:\O'Brien Hooks\observer-codex-hook.cmd`,
		`"D:\Corp Hooks\observer-codex-hook.cmd" PreToolUse`:                   `D:\Corp Hooks\observer-codex-hook.cmd`,
		`& 'D:\Corp Hooks\other.cmd' PreToolUse`:                               "",
		`/usr/local/bin/observer hook codex PreToolUse`:                        "",
	} {
		if got := codexManagedScriptPath(cmd); got != want {
			t.Errorf("codexManagedScriptPath(%q) = %q, want %q", cmd, got, want)
		}
	}
}
