package diag

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfigsvc"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/vscodehost"
)

func TestRemoteWorkspaceKinds(t *testing.T) {
	dir := t.TempDir()
	write := func(id, body string) {
		if err := os.MkdirAll(filepath.Join(dir, id), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, id, "workspace.json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("a", `{"folder":"vscode-remote://ssh-remote+devbox/home/me/p"}`)
	write("b", `{"folder":"vscode-remote://ssh-remote+other/x"}`)
	write("c", `{"workspace":"vscode-remote://dev-container+7b/w.code-workspace"}`)
	write("d", `{"folder":"vscode-remote://wsl+Ubuntu/home/me/p"}`)
	write("e", `{"folder":"file:///home/me/p"}`)
	write("f", `not json`)
	if err := os.MkdirAll(filepath.Join(dir, "g"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := remoteWorkspaceKinds(dir, agentconfigsvc.ReadRegularFile)
	if got[vscodehost.RemoteSSH] != 2 || got[vscodehost.RemoteContainer] != 1 || got[vscodehost.RemoteWSL] != 0 || len(got) != 2 {
		t.Errorf("kinds = %v", got)
	}
	c, ok := remoteHostsCheck(got)
	if !ok || c.Status != StatusWarn || c.Name != "vscode.remote_hosts" {
		t.Fatalf("check = %+v, %v", c, ok)
	}
	if !strings.HasPrefix(c.Message, "remote host not covered: container (1 workspace), ssh (2 workspaces)") {
		t.Errorf("message = %q", c.Message)
	}
	if _, ok := remoteHostsCheck(nil); ok {
		t.Error("nothing found must yield no row")
	}
}

func TestCheckRemoteHostsEmptyHome(t *testing.T) {
	if c, ok := checkRemoteHosts(t.TempDir(), true); ok {
		t.Errorf("empty home reported %+v", c)
	}
}

func TestCheckCodexInWSL(t *testing.T) {
	home := t.TempDir()
	var userDir string
	for _, ref := range vscodehost.UserDirs(crossmountHome(home)) {
		if ref.Product.Host == "vscode" {
			userDir = ref.Path
		}
	}
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "{\n  // comment\n  \"chatgpt.runCodexInWindowsSubsystemForLinux\": true,\n}\n"
	if err := os.WriteFile(filepath.Join(userDir, "settings.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, ok := checkCodexInWSL(home, true)
	if !ok || c.Name != "codex.runs_in_wsl" || !strings.Contains(c.Message, "vscode") || !strings.Contains(c.Details[0], "built, waiting on live check WSL-4") {
		t.Fatalf("check = %+v, %v", c, ok)
	}
	if err := os.WriteFile(filepath.Join(userDir, "settings.json"), []byte(`{"chatgpt.runCodexInWindowsSubsystemForLinux": false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := checkCodexInWSL(home, true); ok {
		t.Error("false must not warn")
	}
}

func crossmountHome(home string) crossmount.HomeRoot {
	return doctorHomeRoot(home, true)
}

// TestCodexInWSLSetIsJSONC pins the JSONC parse: a commented-out line is
// not a setting, comments and trailing commas elsewhere are fine.
func TestCodexInWSLSetIsJSONC(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"set true", `{"chatgpt.runCodexInWindowsSubsystemForLinux": true}`, true},
		{"set true with comments and a trailing comma", "{\n  // editor\n  /* block */ \"chatgpt.runCodexInWindowsSubsystemForLinux\": true,\n}", true},
		{"line comment", "{\n  // \"chatgpt.runCodexInWindowsSubsystemForLinux\": true,\n  \"x\": 1\n}", false},
		{"block comment", "{ /* \"chatgpt.runCodexInWindowsSubsystemForLinux\": true */ }", false},
		{"inside a string value", `{"note": "\"chatgpt.runCodexInWindowsSubsystemForLinux\": true"}`, false},
		{"false", `{"chatgpt.runCodexInWindowsSubsystemForLinux": false}`, false},
		{"not a bool", `{"chatgpt.runCodexInWindowsSubsystemForLinux": "true"}`, false},
		{"unparseable", `{"chatgpt.runCodexInWindowsSubsystemForLinux": true`, false},
	}
	for _, c := range cases {
		if got := codexInWSLSet([]byte(c.body)); got != c.want {
			t.Errorf("%s: codexInWSLSet = %v, want %v", c.name, got, c.want)
		}
	}
}
