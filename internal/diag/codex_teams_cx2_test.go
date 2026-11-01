package diag

import (
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
)

// TestCodexManagedPathsFor pins the per-OS system-channel table with GOOS
// set explicitly per row (S-7): the probe used to name /etc/codex on every
// OS, so a Windows deployment always read "not deployed".
func TestCodexManagedPathsFor(t *testing.T) {
	for _, tc := range []struct {
		goos        string
		programData string
		want        []string
	}{
		{"linux", "", []string{"/etc/codex/requirements.toml", "/etc/codex/managed_config.toml"}},
		{"darwin", "", []string{"/etc/codex/requirements.toml", "/etc/codex/managed_config.toml"}},
		{"windows", `D:\ProgramData\`, []string{`D:\ProgramData\OpenAI\Codex\requirements.toml`}},
		{"windows", "", []string{`C:\ProgramData\OpenAI\Codex\requirements.toml`}},
	} {
		t.Run(tc.goos+"/"+tc.programData, func(t *testing.T) {
			got := codexManagedPathsFor(tc.goos, func(k string) string {
				if k == "ProgramData" {
					return tc.programData
				}
				return ""
			})
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("codexManagedPathsFor(%s) = %v, want %v", tc.goos, got, tc.want)
			}
		})
	}
}

// codexManagedHooksFixture renders a requirements.toml with Observer's
// managed hooks for the given events.
func codexManagedHooksFixture(only bool, events ...string) string {
	var b strings.Builder
	if only {
		b.WriteString("allow_managed_hooks_only = true\n\n")
	}
	if len(events) == 0 {
		return b.String()
	}
	b.WriteString("[hooks]\nmanaged_dir = \"/etc/codex/hooks\"\nwindows_managed_dir = 'C:\\ProgramData\\OpenAI\\Codex\\hooks'\n\n")
	for _, ev := range events {
		b.WriteString("[[hooks." + ev + "]]\nmatcher = \"*\"\n\n[[hooks." + ev + ".hooks]]\ntype = \"command\"\n")
		b.WriteString("command = \"/etc/codex/hooks/" + hook.CodexManagedHookScriptPOSIX + " " + ev + "\"\n")
		b.WriteString("commandWindows = 'C:\\ProgramData\\OpenAI\\Codex\\hooks\\" + hook.CodexManagedHookScriptWindows + " " + ev + "'\n\n")
	}
	return b.String()
}

func TestCodexManagedHookFindings(t *testing.T) {
	all := hook.CodexHookEvents()
	present := func(string) bool { return true }
	for _, tc := range []struct {
		name     string
		doc      string
		goos     string
		exists   func(string) bool
		want     []Status
		contains string
	}{
		{name: "no hook settings", doc: "allowed_sandbox_modes = [\"read-only\"]\n", goos: "linux", exists: present},
		{
			name: "flag alone leaves the node without Observer hooks", doc: codexManagedHooksFixture(true), goos: "linux", exists: present,
			want: []Status{StatusWarn}, contains: "runs no Observer hook",
		},
		{
			name: "flag with a foreign managed hook only", goos: "linux", exists: present,
			doc:  "allow_managed_hooks_only = true\n[hooks]\n[[hooks.PreToolUse]]\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = \"python3 /etc/codex/hooks/policy.py\"\n",
			want: []Status{StatusWarn}, contains: "runs no Observer hook",
		},
		{
			name: "flag with some events covered", doc: codexManagedHooksFixture(true, "PreToolUse"), goos: "linux", exists: present,
			want: []Status{StatusWarn}, contains: "miss Observer's SessionStart",
		},
		{
			name: "flag with every event covered", doc: codexManagedHooksFixture(true, all...), goos: "linux", exists: present,
			want: []Status{StatusOK},
		},
		{
			name: "managed hooks without the flag fire twice", doc: codexManagedHooksFixture(false, all...), goos: "linux", exists: present,
			want: []Status{StatusWarn}, contains: "fire twice",
		},
		{
			name: "missing POSIX script", doc: codexManagedHooksFixture(true, all...), goos: "linux", exists: func(string) bool { return false },
			want: []Status{StatusOK, StatusWarn}, contains: "/etc/codex/hooks/" + hook.CodexManagedHookScriptPOSIX + " is missing",
		},
		{
			name: "windows reads commandWindows", doc: codexManagedHooksFixture(true, all...), goos: "windows",
			exists: func(p string) bool {
				return p != `C:\ProgramData\OpenAI\Codex\hooks\`+hook.CodexManagedHookScriptWindows
			},
			want: []Status{StatusOK, StatusWarn}, contains: hook.CodexManagedHookScriptWindows + " is missing",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := codexManagedHookFindings("/etc/codex/requirements.toml", []byte(tc.doc), tc.goos, tc.exists)
			var statuses []Status
			var msgs []string
			for _, f := range got {
				statuses = append(statuses, f.status)
				msgs = append(msgs, f.msg)
			}
			if !reflect.DeepEqual(statuses, tc.want) {
				t.Fatalf("statuses = %v, want %v\n%s", statuses, tc.want, strings.Join(msgs, "\n"))
			}
			if tc.contains != "" && !strings.Contains(strings.Join(msgs, "\n"), tc.contains) {
				t.Errorf("findings miss %q:\n%s", tc.contains, strings.Join(msgs, "\n"))
			}
		})
	}
}
