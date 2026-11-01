package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestFU212UninstallKeepsForeignGooseAndHermesFiles runs the real commands
// in an isolated home: `observer uninstall --all` over Observer's Goose
// plugin whose plugin.json is the developer's own, with a file of theirs
// beside it, and `observer init --hermes --uninstall` (Hermes' uninstall
// path; `observer uninstall` does not touch the Hermes plugin) over a
// Hermes plugin directory holding a foreign manifest and a file of theirs.
// With and without --force the foreign files stay byte for byte and are
// reported; Observer's own files go.
func TestFU212UninstallKeepsForeignGooseAndHermesFiles(t *testing.T) {
	const foreign = "the developer's own file, not Observer's\n"
	for _, force := range []bool{false, true} {
		name := "without --force"
		var extra []string
		if force {
			name, extra = "with --force", []string{"--force"}
		}
		t.Run("goose "+name, func(t *testing.T) {
			home := t.TempDir()
			pinToolHomesAt(t, home)
			t.Setenv(crossmount.EnvDisableForeignHomes, "1")
			// Goose is detected by its config home (~/.config/goose; on
			// Windows %APPDATA%\Block\goose\config).
			for _, d := range []string{filepath.Join(home, ".agents"), filepath.Join(home, ".config", "goose"), filepath.Join(home, "AppData", "Roaming", "Block", "goose", "config")} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			// An installed Observer's path (the test binary's own name is
			// not an observer binary's).
			r, err := hook.NewRegistry(hook.Options{BinaryPath: "/usr/lib/observer/observer", HomeDir: home})
			if err != nil {
				t.Fatal(err)
			}
			if res := r.Register("goose"); res.Error != nil {
				t.Fatalf("register goose: %v", res.Error)
			}
			plugin := filepath.Join(home, ".agents", "plugins", "superbased-observer")
			manifest := filepath.Join(plugin, "plugin.json")
			beside := filepath.Join(plugin, "NOTES.md")
			hooksFile := filepath.Join(plugin, "hooks", "hooks.json")
			for _, p := range []string{manifest, beside} {
				if err := os.WriteFile(p, []byte(foreign), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := newUninstallCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs(append([]string{"--all", "--skip-mcp", "--skip-proxy-route"}, extra...))
			if err := cmd.Execute(); err != nil {
				t.Fatalf("observer uninstall: %v\n%s", err, out.String())
			}
			for _, p := range []string{manifest, beside} {
				if got, err := os.ReadFile(p); err != nil || string(got) != foreign {
					t.Errorf("%s was not kept byte for byte: %q, %v\n%s", p, got, err, out.String())
				}
			}
			if _, err := os.Stat(hooksFile); !os.IsNotExist(err) {
				t.Errorf("Observer's own %s was not removed: %v\n%s", hooksFile, err, out.String())
			}
			if !strings.Contains(out.String(), "hook kept "+manifest+" ("+hook.ForeignFileReason+")") {
				t.Errorf("uninstall does not report the kept manifest:\n%s", out.String())
			}
		})
		t.Run("hermes "+name, func(t *testing.T) {
			home := t.TempDir()
			pinToolHomesAt(t, home)
			t.Setenv(crossmount.EnvDisableForeignHomes, "1")
			cfg := filepath.Join(home, ".observer", "config.toml")
			if err := os.MkdirAll(filepath.Dir(cfg), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(cfg, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			hermesHome := filepath.Join(home, ".hermes")
			if runtime.GOOS == "windows" {
				hermesHome = filepath.Join(home, "AppData", "Local", "hermes")
			}
			if err := os.MkdirAll(hermesHome, 0o755); err != nil {
				t.Fatal(err)
			}
			run := func(args ...string) string {
				t.Helper()
				cmd := newInitCmd()
				cmd.SetArgs(append(args, "--hermes", "--skip-mcp", "--skip-proxy-route", "--guard=false", "--skip-extension", "--config", cfg))
				var out bytes.Buffer
				cmd.SetOut(&out)
				cmd.SetErr(&out)
				cmd.SilenceUsage = true
				cmd.SilenceErrors = true
				if err := cmd.Execute(); err != nil {
					t.Fatalf("init %v: %v (%s)", args, err, out.String())
				}
				return out.String()
			}
			run()
			plugin := filepath.Join(hermesHome, "plugins", hook.HermesPluginDirName)
			manifest := filepath.Join(plugin, "plugin.yaml")
			beside := filepath.Join(plugin, "NOTES.md")
			bridge := filepath.Join(plugin, "__init__.py")
			if _, err := os.Stat(bridge); err != nil {
				t.Fatalf("init --hermes wrote no bridge: %v", err)
			}
			for _, p := range []string{manifest, beside} {
				if err := os.WriteFile(p, []byte(foreign), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			out := run(append([]string{"--uninstall"}, extra...)...)
			for _, p := range []string{manifest, beside} {
				if got, err := os.ReadFile(p); err != nil || string(got) != foreign {
					t.Errorf("%s was not kept byte for byte: %q, %v\n%s", p, got, err, out)
				}
				if !strings.Contains(out, "hermes: kept "+p+" ("+hook.ForeignFileReason+")") {
					t.Errorf("init --hermes --uninstall does not report %s:\n%s", p, out)
				}
			}
			if _, err := os.Stat(bridge); !os.IsNotExist(err) {
				t.Errorf("Observer's own %s was not removed: %v\n%s", bridge, err, out)
			}
		})
	}
}

// TestFU213UninstallNamesEachFileOfAKeptEntry: a removal spanning several
// files (Kiro's own agent and the user's agents) names the file of each
// kept entry, not only the result's ConfigPath.
func TestFU213UninstallNamesEachFileOfAKeptEntry(t *testing.T) {
	var out bytes.Buffer
	printHookUnregisterResult(&out, "kiro-cli", hook.UnregistrationResult{
		ConfigPath:       "/h/.kiro/agents/superbased-observer.json",
		HooksRemoved:     []string{"preToolUse"},
		HooksKeptForeign: []string{"preToolUse"},
		HooksKeptForeignIn: []hook.KeptForeignFile{
			{Path: "/h/.kiro/agents/mine.json", Events: []string{"preToolUse"}},
		},
	}, false)
	want := "hook kept [preToolUse] in /h/.kiro/agents/mine.json (" + hook.ForeignBinaryReason + ")"
	if !strings.Contains(out.String(), want) || strings.Contains(out.String(), "kept [preToolUse] in /h/.kiro/agents/superbased-observer.json") {
		t.Errorf("output does not name the user's agent file:\n%s", out.String())
	}
}
