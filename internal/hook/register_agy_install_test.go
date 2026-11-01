package hook

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestAntigravityInstallSignals: one case per agyHookFileReaderDirs row (the
// CLI, the Antigravity App and the Antigravity IDE data directories) puts
// the antigravity-cli target on the install list, once; the JetBrains ACP
// agent's directory and a bare ~/.gemini do not (surface-gap W-2c).
func TestAntigravityInstallSignals(t *testing.T) {
	for _, tc := range []struct {
		name string
		dirs []string
		want bool
	}{
		{"cli", []string{"antigravity-cli"}, true},
		{"app only", []string{"antigravity"}, true},
		{"ide only", []string{"antigravity-ide"}, true},
		{"all three, listed once", []string{"antigravity-cli", "antigravity", "antigravity-ide"}, true},
		{"jetbrains acp agent only", []string{"antigravity-acp"}, false},
		{"bare gemini home", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			if err := os.MkdirAll(filepath.Join(home, ".gemini"), 0o755); err != nil {
				t.Fatal(err)
			}
			for _, d := range tc.dirs {
				if err := os.MkdirAll(filepath.Join(home, ".gemini", d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			reg, err := NewRegistry(Options{
				BinaryPath:    "/opt/observer/bin/observer",
				HomeDir:       home,
				ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
				GOOS:          "linux",
				Getenv:        func(string) string { return "" },
			})
			if err != nil {
				t.Fatal(err)
			}
			installed := reg.Installed()
			n := 0
			for _, tool := range installed {
				if tool == "antigravity-cli" {
					n++
				}
			}
			if got := n > 0; got != tc.want || n > 1 {
				t.Fatalf("antigravity-cli listed %d times in %v, want listed=%v once", n, installed, tc.want)
			}
			if tc.want && !slices.Contains(installed, "gemini-cli") {
				// ~/.gemini is gemini-cli's own signal; the agy rows only add
				// the antigravity-cli target beside it.
				t.Fatalf("gemini-cli missing from %v", installed)
			}
		})
	}
}

// TestAntigravityRegistersForIDEAndExtensionUsers (WINNODE2 item 5b): a
// developer who uses Antigravity only through the IDE or the Google
// Antigravity VS Code extension (~/.gemini/antigravity and
// ~/.gemini/antigravity-ide, never antigravity-cli) gets the shared
// ~/.gemini/config/hooks.json gate; so does a home where only that config
// directory exists. A pinned (isolated) home is the only home looked at.
func TestAntigravityRegistersForIDEAndExtensionUsers(t *testing.T) {
	for _, tc := range []struct {
		name string
		dirs []string
		want bool
	}{
		{"ide only", []string{"antigravity-ide"}, true},
		{"vs code extension only", []string{"antigravity"}, true},
		{"shared hooks directory only", []string{"config"}, true},
		{"cli only", []string{"antigravity-cli"}, true},
		{"none", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			for _, d := range tc.dirs {
				if err := os.MkdirAll(filepath.Join(home, ".gemini", d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			reg, err := NewRegistry(Options{
				BinaryPath:    "/opt/observer/bin/observer",
				HomeDir:       home,
				ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
				GOOS:          "linux",
				Getenv:        func(string) string { return "" },
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := slices.Contains(reg.Installed(), "antigravity-cli"); got != tc.want {
				t.Fatalf("antigravity-cli on the install list = %v, want %v", got, tc.want)
			}
			if !tc.want {
				return
			}
			res := reg.Register("antigravity-cli")
			if res.Error != nil {
				t.Fatalf("Register: %v", res.Error)
			}
			raw, err := os.ReadFile(filepath.Join(home, ".gemini", "config", "hooks.json"))
			if err != nil {
				t.Fatalf("no shared hooks file: %v", err)
			}
			for _, ev := range []string{"PreToolUse", "PreInvocation"} {
				if !bytes.Contains(raw, []byte("hook antigravity-cli "+ev)) {
					t.Fatalf("hooks.json lacks the %s gate:\n%s", ev, raw)
				}
			}
		})
	}

	// The pinned home rule (R-188): a ~/.gemini/config under the process's
	// real home is not a signal for a registry pinned to another home.
	pinned, real := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(real, ".gemini", "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	reg, err := NewRegistry(Options{
		BinaryPath: "/opt/observer/bin/observer", HomeDir: pinned, GOOS: "linux",
		ChecksumsPath: filepath.Join(pinned, ".observer", "hook_checksums.json"),
		Getenv: func(k string) string {
			if k == "HOME" || k == "USERPROFILE" {
				return real
			}
			return ""
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(reg.Installed(), "antigravity-cli") {
		t.Fatal("a registry pinned to an empty home read the real home's ~/.gemini/config")
	}
}
