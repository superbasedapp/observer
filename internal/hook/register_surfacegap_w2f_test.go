package hook

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// Surface-gap lane W2-F writer pins (S-10 Devin CLI paths, S-11 Kiro
// includeMcpJson and KIRO_HOME validation;
// docs/audits/surface-settings-precedence-gap-review-2026-10-25.md). Every
// registry here is pinned to a throwaway home, an explicit GOOS and a fake
// environment, so no row ever reads the real profile.

func w2fRegistry(t *testing.T, home, goos string, env map[string]string) *Registry {
	t.Helper()
	reg, err := NewRegistry(Options{
		BinaryPath:    "/opt/observer/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
		GOOS:          goos,
		Getenv:        func(k string) string { return env[k] },
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return reg
}

// TestDevinCLIConfigDirFollowsVendorLadder: the Devin CLI config dir reads
// %APPDATA% on Windows and $XDG_CONFIG_HOME elsewhere, falling back to the
// derived path when the variable is unset or relative.
func TestDevinCLIConfigDirFollowsVendorLadder(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	appdata := filepath.Join(root, "Roaming")
	xdg := filepath.Join(root, "xdg")
	for _, tc := range []struct {
		name string
		goos string
		env  map[string]string
		want string
	}{
		{"windows APPDATA wins", "windows", map[string]string{"APPDATA": rowAbs("windows", appdata), "XDG_CONFIG_HOME": xdg}, filepath.Join(appdata, "devin")},
		{"windows APPDATA unset", "windows", nil, filepath.Join(home, "AppData", "Roaming", "devin")},
		{"windows APPDATA relative", "windows", map[string]string{"APPDATA": filepath.Join("rel", "Roaming")}, filepath.Join(home, "AppData", "Roaming", "devin")},
		{"linux XDG_CONFIG_HOME", "linux", map[string]string{"XDG_CONFIG_HOME": xdg, "APPDATA": appdata}, filepath.Join(xdg, "devin")},
		{"linux XDG unset", "linux", nil, filepath.Join(home, ".config", "devin")},
		{"linux XDG relative", "linux", map[string]string{"XDG_CONFIG_HOME": "rel"}, filepath.Join(home, ".config", "devin")},
		{"darwin XDG_CONFIG_HOME", "darwin", map[string]string{"XDG_CONFIG_HOME": xdg}, filepath.Join(xdg, "devin")},
		{"darwin XDG unset", "darwin", nil, filepath.Join(home, ".config", "devin")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := filepath.Clean(w2fRegistry(t, home, tc.goos, tc.env).devinCLIConfigDir()); got != tc.want {
				t.Errorf("devinCLIConfigDir = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDevinCLIRegisterUnderRelocatedConfigHome: detection and the write
// follow the same relocated directory, so a Devin CLI living under
// %APPDATA% or $XDG_CONFIG_HOME is detected and gated there, and the
// derived default directory is never created.
func TestDevinCLIRegisterUnderRelocatedConfigHome(t *testing.T) {
	for _, tc := range []struct {
		name, goos, envKey string
	}{
		{"windows APPDATA", "windows", "APPDATA"},
		{"linux XDG_CONFIG_HOME", "linux", "XDG_CONFIG_HOME"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "home")
			relocated := filepath.Join(root, "relocated")
			cliDir := filepath.Join(relocated, "devin")
			if err := os.MkdirAll(cliDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(home, 0o755); err != nil {
				t.Fatal(err)
			}
			reg := w2fRegistry(t, home, tc.goos, map[string]string{tc.envKey: rowAbs(tc.goos, relocated)})
			// registerDevinAll gates the CLI write on this directory existing,
			// and Installed() probes the same devinCLIConfigDir (not called
			// here: it also probes cross-OS homes outside the sandbox).
			res := reg.Register("devin")
			if res.Error != nil {
				t.Fatalf("Register: %v", res.Error)
			}
			raw, err := os.ReadFile(filepath.Join(cliDir, "config.json"))
			if err != nil {
				t.Fatalf("no Devin CLI config written under %s: %v", tc.envKey, err)
			}
			if !strings.Contains(string(raw), "hook devin PreToolUse") {
				t.Errorf("config.json lacks Observer's PreToolUse hook:\n%s", raw)
			}
			for _, derived := range []string{filepath.Join(home, ".config", "devin"), filepath.Join(home, "AppData", "Roaming", "devin")} {
				if _, err := os.Stat(derived); !os.IsNotExist(err) {
					t.Errorf("derived default %s was created although %s is set (err %v)", derived, tc.envKey, err)
				}
			}
		})
	}
}

// TestKiroOwnAgentIncludesMCPJson: Observer's default agent sets
// includeMcpJson, on a fresh install and on an agent written before the
// field existed (the setting is ensured on every register).
func TestKiroOwnAgentIncludesMCPJson(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed string
	}{
		{name: "fresh install"},
		{
			name: "agent written by an older Observer is upgraded",
			seed: `{"name":"superbased-observer","description":"old","tools":["*"],"hooks":{}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			own := filepath.Join(home, ".kiro", "agents", kiroAgentName+".json")
			if tc.seed != "" {
				kiroWrite(t, own, tc.seed)
			}
			res := kiroRegistry(t, home, nil).Register("kiro-cli")
			if res.Error != nil {
				t.Fatalf("Register: %v", res.Error)
			}
			agent := kiroReadJSON(t, own)
			if agent["includeMcpJson"] != true {
				t.Errorf("includeMcpJson = %v, want true (the user's mcp.json servers would vanish from the default agent)", agent["includeMcpJson"])
			}
			if !reflect.DeepEqual(agent["tools"], []any{"*"}) {
				t.Errorf("tools = %v", agent["tools"])
			}
		})
	}
}

// TestKiroUserAgentNotGivenIncludeMCPJson: the field is set on Observer's
// own agent only; a user's agent keeps its own MCP choice.
func TestKiroUserAgentNotGivenIncludeMCPJson(t *testing.T) {
	home := t.TempDir()
	mine := filepath.Join(home, ".kiro", "agents", "mine.json")
	kiroWrite(t, mine, `{"name":"mine","tools":["read"],"hooks":{}}`)
	if res := kiroRegistry(t, home, nil).Register("kiro-cli"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if _, ok := kiroReadJSON(t, mine)["includeMcpJson"]; ok {
		t.Error("Register added includeMcpJson to a user agent")
	}
}

// TestKiroHomeAcceptance is Kiro's KIRO_HOME acceptance rule, one row per
// case, over each OS's path syntax (independent of the host OS). Since FU-5
// the rule is agentconfig's KIRO_HOME relocation on the Kiro rows, which
// kiroHome resolves through; the writer has no copy of its own.
func TestKiroHomeAcceptance(t *testing.T) {
	for _, tc := range []struct {
		name, goos, v, home string
		want                bool
	}{
		{"linux sibling dir", "linux", "/data/kiro", "/home/dev", true},
		{"linux below home", "linux", "/home/dev/kiro-state", "/home/dev", true},
		{"linux home itself", "linux", "/home/dev", "/home/dev", false},
		{"linux home with trailing slash", "linux", "/home/dev/", "/home/dev", false},
		{"linux ancestor of home", "linux", "/home", "/home/dev", false},
		{"linux root", "linux", "/", "/home/dev", false},
		{"linux relative", "linux", "kiro", "/home/dev", false},
		{"linux tilde is not absolute", "linux", "~/.kiro2", "/home/dev", false},
		{"linux prefix but not ancestor", "linux", "/home/de", "/home/dev", true},
		{"darwin ancestor", "darwin", "/Users", "/Users/dev", false},
		{"darwin elsewhere", "darwin", "/Volumes/x/kiro", "/Users/dev", true},
		{"windows other drive", "windows", `D:\kiro`, `C:\Users\dev`, true},
		{"windows home case-insensitive", "windows", `c:\users\DEV`, `C:\Users\dev`, false},
		{"windows ancestor", "windows", `C:\Users`, `C:\Users\dev`, false},
		{"windows drive root", "windows", `C:\`, `C:\Users\dev`, false},
		{"windows drive root forward slash", "windows", "C:/", `C:\Users\dev`, false},
		{"windows drive-relative", "windows", `C:kiro`, `C:\Users\dev`, false},
		{"windows rooted without drive", "windows", `\kiro`, `C:\Users\dev`, false},
		{"windows below home", "windows", `C:\Users\dev\kiro`, `C:\Users\dev`, true},
		{"windows UNC share root", "windows", `\\server\share`, `C:\Users\dev`, false},
		{"windows UNC dir", "windows", `\\server\share\kiro`, `C:\Users\dev`, true},
		{"no home known", "linux", "/data/kiro", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := agentconfig.ResolveArtifact(kiroHomeArtifact, agentconfig.PathEnv{GOOS: tc.goos, Home: tc.home, Getenv: func(k string) string {
				if k == "KIRO_HOME" {
					return tc.v
				}
				return ""
			}})
			if err != nil {
				t.Fatal(err)
			}
			if accepted := got.RelocatedBy == "KIRO_HOME"; accepted != tc.want {
				t.Errorf("KIRO_HOME=%q (home %q, %s): accepted %v, want %v (%+v)", tc.v, tc.home, tc.goos, accepted, tc.want, got)
			}
		})
	}
}

// TestKiroHomeRejectedFallsBackToDefault: a KIRO_HOME Kiro would refuse
// (the home, an ancestor of it, or a relative value) leaves every write in
// ~/.kiro and says so. The ancestor case uses a parent inside the test's own
// temp dir, so even a regression stays sandboxed.
func TestKiroHomeRejectedFallsBackToDefault(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value func(home string) string
	}{
		{"the home directory", func(home string) string { return home }},
		{"an ancestor of home", filepath.Dir},
		{"a relative path", func(string) string { return filepath.Join("rel", "kiro") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "sandbox", "home")
			if err := os.MkdirAll(home, 0o755); err != nil {
				t.Fatal(err)
			}
			v := tc.value(home)
			reg := kiroRegistry(t, home, map[string]string{"KIRO_HOME": v})
			if got, want := reg.kiroHome(), filepath.Join(home, ".kiro"); got != want {
				t.Fatalf("kiroHome = %q, want the default %q", got, want)
			}
			res := reg.Register("kiro-cli")
			if res.Error != nil {
				t.Fatalf("Register: %v", res.Error)
			}
			if !strings.Contains(res.ProbeWarning, "KIRO_HOME="+v+" ignored") {
				t.Errorf("ProbeWarning = %q, want the ignored KIRO_HOME named", res.ProbeWarning)
			}
			if _, err := os.Stat(filepath.Join(home, ".kiro", "agents", kiroAgentName+".json")); err != nil {
				t.Errorf("own agent not under the default home: %v", err)
			}
			for _, stray := range []string{"agents", "hooks", "settings"} {
				if _, err := os.Stat(filepath.Join(home, stray)); !os.IsNotExist(err) {
					t.Errorf("%s written directly into the home (err %v)", stray, err)
				}
			}
		})
	}
}
