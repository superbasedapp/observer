package diag

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/hook"
)

func TestCheckHooksDisabled(t *testing.T) {
	cases := []struct {
		name     string
		files    map[string]string
		want     Status
		contains string
	}{
		{"clean home", nil, StatusOK, "no vendor switch"},
		{"claude disableAllHooks", map[string]string{".claude/settings.json": `{"disableAllHooks":true}`}, StatusWarn, "grok"},
		{"claude hooks on", map[string]string{".claude/settings.json": `{"disableAllHooks":false,"hooks":{}}`}, StatusOK, "no vendor switch"},
		{"gemini disabled", map[string]string{".gemini/settings.json": `{"hooksConfig":{"enabled":false}}`}, StatusWarn, "gemini-cli"},
	}
	// The env-scope rows read the process environment: pin it.
	pinSwitchEnv(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			for rel, body := range tc.files {
				p := filepath.Join(home, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			c := checkHooksDisabled(home, home, nil, os.Getenv)
			if c.Status != tc.want {
				t.Fatalf("status = %v, want %v (%s)", c.Status, tc.want, c.Message)
			}
			if !strings.Contains(c.Message, tc.contains) {
				t.Fatalf("message %q lacks %q", c.Message, tc.contains)
			}
		})
	}
}

// TestCheckHooksDisabledProjectScope (T-910): a project's
// .claude/settings.local.json disableAllHooks is a WARN naming the project;
// a settings.local.json holding only permission grants is not.
func TestCheckHooksDisabledProjectScope(t *testing.T) {
	cases := []struct {
		name string
		body string
		want Status
	}{
		{"project local switch on", `{"permissions":{"allow":["Bash(ls)"]},"disableAllHooks":true}`, StatusWarn},
		{"project local permission grants only", `{"permissions":{"allow":["Bash(ls)"]}}`, StatusOK},
	}
	pinSwitchEnv(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home, proj := t.TempDir(), t.TempDir()
			p := filepath.Join(proj, ".claude", "settings.local.json")
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			c := checkHooksDisabled(home, home, []string{proj}, os.Getenv)
			if c.Status != tc.want {
				t.Fatalf("status = %v, want %v (%s)", c.Status, tc.want, c.Message)
			}
			if tc.want == StatusWarn && (len(c.Details) != 1 || !strings.Contains(c.Details[0], "in project "+proj)) {
				t.Fatalf("details = %v", c.Details)
			}
		})
	}
}

// TestHookSwitchManagedFilesMatchTheClaudePolicyReader pins CC-5: the
// hooks.disabled check reads Claude Code's managed settings from the same
// path the managed policy reader does (hook.ClaudeManagedPaths), per GOOS,
// so Windows is C:\Program Files\ClaudeCode and never C:\ProgramData.
func TestHookSwitchManagedFilesMatchTheClaudePolicyReader(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			noDir := func(string) ([]os.DirEntry, error) { return nil, os.ErrNotExist }
			got := managedFilesFor("claude-code/managed-settings", goos, agentconfig.Files(), hookSwitchDropInDirs, noDir)
			want := hook.ClaudeManagedPaths(goos).Settings
			if len(got) != 1 || got[0] != want {
				t.Fatalf("managed files = %v, want [%s]", got, want)
			}
			if strings.Contains(got[0], "ProgramData") {
				t.Fatalf("managed file %s is the legacy path Claude Code does not read", got[0])
			}
		})
	}
}

// TestManagedFilesForListsDropIns pins the drop-in order: the file, then
// managed-settings.d/*.json in name order, hidden and non-.json entries
// skipped; an unknown FileRow id resolves to nothing.
func TestManagedFilesForListsDropIns(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"20-b.json", "10-a.json", ".hidden.json", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "sub.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	dropIns := map[string]func(string) string{"claude-code/managed-settings": func(string) string { return dir }}
	got := managedFilesFor("claude-code/managed-settings", "linux", agentconfig.Files(), dropIns, os.ReadDir)
	want := []string{hook.ClaudeManagedPaths("linux").Settings, dir + "/10-a.json", dir + "/20-b.json"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("managed files = %v, want %v", got, want)
	}
	if got := managedFilesFor("no/such-row", "linux", agentconfig.Files(), dropIns, os.ReadDir); got != nil {
		t.Fatalf("unknown id = %v", got)
	}
}

// TestCheckHooksDisabledReplayOnly pins S-10's honest message: Devin's
// read_config_from.claude=false is reported as a lost Claude Code replay,
// not as Devin's hooks being off.
func TestCheckHooksDisabledReplayOnly(t *testing.T) {
	home := t.TempDir()
	// A sandboxed run (homeOverride set) reads no managed file and uses
	// the row's default path on every host.
	p := filepath.Join(home, ".config", "devin", "config.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"read_config_from":{"claude":false}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	pinSwitchEnv(t)
	c := checkHooksDisabled(home, home, nil, os.Getenv)
	if c.Status != StatusWarn || !strings.Contains(c.Message, "Claude Code hooks are not replayed on devin") || strings.Contains(c.Message, "do not run on devin") {
		t.Fatalf("check = %s: %s", c.Status, c.Message)
	}
}

// TestCheckHooksDisabledJunieEnv pins S-13 end to end: the variable in the
// doctor's environment is a WARN naming junie.
func TestCheckHooksDisabledJunieEnv(t *testing.T) {
	home := t.TempDir()
	pinSwitchEnv(t)
	t.Setenv("JUNIE_CONFIG_DEFAULT_LOCATIONS", "false")
	c := checkHooksDisabled(home, home, nil, os.Getenv)
	if c.Status != StatusWarn || !strings.Contains(c.Message, "junie") {
		t.Fatalf("check = %s: %s", c.Status, c.Message)
	}
}

// TestCheckHooksDisabledIgnoresCopilotCLIDisableAllHooks pins FU-159 at the
// doctor: disableAllHooks true in Copilot CLI's user, repo and local
// settings files is not reported as turning hooks off (Copilot CLI 1.0.105
// does not honour it for hooks; the guard still refuses the write).
func TestCheckHooksDisabledIgnoresCopilotCLIDisableAllHooks(t *testing.T) {
	pinSwitchEnv(t)
	home, proj := t.TempDir(), t.TempDir()
	for _, p := range []string{
		filepath.Join(home, ".copilot", "settings.json"),
		filepath.Join(proj, ".github", "copilot", "settings.json"),
		filepath.Join(proj, ".github", "copilot", "settings.local.json"),
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(`{"disableAllHooks":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c := checkHooksDisabled(home, home, []string{proj}, os.Getenv)
	if c.Status != StatusOK || strings.Contains(c.Message+strings.Join(c.Details, " "), "copilot") {
		t.Fatalf("hooks.disabled = %v %q %v, want OK and silent about Copilot CLI", c.Status, c.Message, c.Details)
	}
}
