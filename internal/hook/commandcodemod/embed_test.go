package commandcodemod

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWritePlugin_RoundTrip pins the embed -> write -> read loop
// (mirrors hermesplugin's own embed_test.go pattern).
func TestWritePlugin_RoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := WritePlugin(dir, "", ""); err != nil {
		t.Fatalf("WritePlugin: %v", err)
	}
	got, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(got) != 1 || got[0].Name() != ModFileName {
		t.Fatalf("ReadDir = %v, want exactly [%s]", got, ModFileName)
	}
	ts, err := os.ReadFile(filepath.Join(dir, ModFileName))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	for _, marker := range []string{
		"cmd.hooks(",
		"transformInput(",
		"OBSERVER_BIN",
		`"hook", "command-code", "transformInput"`,
		`action: "handled"`,
		`action: "continue"`,
	} {
		if !strings.Contains(string(ts), marker) {
			t.Errorf("observer-guard.ts missing %q", marker)
		}
	}
}

// TestWritePlugin_SubstitutesObserverBinDefault mirrors hermesplugin's
// own test of the same name/contract, adapted for TS string-literal
// escaping.
func TestWritePlugin_SubstitutesObserverBinDefault(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		defaultBin  string
		wantLiteral string
	}{
		{"linux_abs_path", "/usr/local/bin/observer", `"/usr/local/bin/observer"`},
		{"windows_abs_path_with_backslashes", `C:\Program Files\superbased\observer.exe`, `"C:\\Program Files\\superbased\\observer.exe"`},
		{"embedded_double_quote", `/tmp/weird "name"/observer`, `"/tmp/weird \"name\"/observer"`},
		{"empty_falls_back_to_observer", "", `"observer"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := WritePlugin(dir, tc.defaultBin, ""); err != nil {
				t.Fatalf("WritePlugin: %v", err)
			}
			ts, err := os.ReadFile(filepath.Join(dir, ModFileName))
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			if strings.Contains(string(ts), "{{OBSERVER_BIN_DEFAULT}}") {
				t.Errorf("placeholder leaked into rendered file for case %q", tc.name)
			}
			if !strings.Contains(string(ts), "const OBSERVER_BIN_DEFAULT = "+tc.wantLiteral) {
				t.Errorf("observer-guard.ts missing rendered default %q", tc.wantLiteral)
			}
		})
	}
}

// TestWritePlugin_Idempotent confirms re-running overwrites rather
// than appending or failing — the `observer init` re-run-after-upgrade
// contract every other writer in this repo guarantees.
func TestWritePlugin_Idempotent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := WritePlugin(dir, "", ""); err != nil {
		t.Fatalf("first WritePlugin: %v", err)
	}
	path := filepath.Join(dir, ModFileName)
	if err := os.WriteFile(path, []byte("stale content from a prior version"), 0o600); err != nil {
		t.Fatalf("trash file: %v", err)
	}
	if err := WritePlugin(dir, "", ""); err != nil {
		t.Fatalf("second WritePlugin: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(data), "stale content") {
		t.Error("WritePlugin didn't overwrite stale content")
	}
	if !strings.Contains(string(data), "cmd.hooks(") {
		t.Error("WritePlugin overwrote but the new content is missing the hooks() marker")
	}
}

// TestWritePlugin_SubstitutesConfigPath pins the OBSERVER_CONFIG_DEFAULT
// bake: a non-empty configPath survives into the rendered mod (FIX
// cluster item 5a — this used to be dropped entirely, so a custom
// --config never reached the registered hook invocation), and an
// empty one renders an empty default (the runtime OBSERVER_CONFIG env
// override is still honored either way — that part of the template is
// unchanged).
func TestWritePlugin_SubstitutesConfigPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		configPath  string
		wantLiteral string
	}{
		{"custom_config_path", "/home/u/.observer/custom-config.toml", `"/home/u/.observer/custom-config.toml"`},
		{"empty_config_path", "", `""`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := WritePlugin(dir, "", tc.configPath); err != nil {
				t.Fatalf("WritePlugin: %v", err)
			}
			ts, err := os.ReadFile(filepath.Join(dir, ModFileName))
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			if strings.Contains(string(ts), "{{OBSERVER_CONFIG_DEFAULT}}") {
				t.Errorf("placeholder leaked into rendered file for case %q", tc.name)
			}
			if !strings.Contains(string(ts), "const OBSERVER_CONFIG_DEFAULT = "+tc.wantLiteral) {
				t.Errorf("observer-guard.ts missing rendered config default %q", tc.wantLiteral)
			}
		})
	}
}

// TestWritePluginBridge_SubstitutesConfigPath is
// TestWritePlugin_SubstitutesConfigPath's WritePluginBridge counterpart.
func TestWritePluginBridge_SubstitutesConfigPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := WritePluginBridge(dir, "/home/u/bin/observer", "Ubuntu", "/home/u/.observer/custom-config.toml"); err != nil {
		t.Fatalf("WritePluginBridge: %v", err)
	}
	ts, err := os.ReadFile(filepath.Join(dir, ModFileName))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(ts), "{{OBSERVER_CONFIG_DEFAULT}}") {
		t.Error("placeholder leaked into rendered bridge file")
	}
	if !strings.Contains(string(ts), `const OBSERVER_CONFIG_DEFAULT = "/home/u/.observer/custom-config.toml"`) {
		t.Error("observer-guard.ts (bridge) missing rendered config default")
	}
}

// TestLooksLikeObserverPlugin pins the marker-based identity check
// registerCommandCode's conflict guard depends on: an observer-written
// copy (via WritePlugin/WritePluginBridge, any placeholder state) is
// recognized regardless of the substituted bin/config values, and an
// unrelated file at the same path is not.
func TestLooksLikeObserverPlugin(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := WritePlugin(dir, "/usr/local/bin/observer", "/etc/observer/config.toml"); err != nil {
		t.Fatalf("WritePlugin: %v", err)
	}
	written, err := os.ReadFile(filepath.Join(dir, ModFileName))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !LooksLikeObserverPlugin(written) {
		t.Error("LooksLikeObserverPlugin = false for an observer-written file")
	}
	if LooksLikeObserverPlugin([]byte("export default function (cmd) { /* some unrelated mod */ }")) {
		t.Error("LooksLikeObserverPlugin = true for an unrelated file")
	}
	if LooksLikeObserverPlugin(nil) {
		t.Error("LooksLikeObserverPlugin = true for empty content")
	}
}

func TestInstalled(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if Installed(dir) {
		t.Error("Installed = true before WritePlugin ever ran")
	}
	if err := WritePlugin(dir, "", ""); err != nil {
		t.Fatalf("WritePlugin: %v", err)
	}
	if !Installed(dir) {
		t.Error("Installed = false after WritePlugin")
	}
}

func TestRemovePlugin(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Removing from a dir where nothing was ever written must be a
	// silent no-op, not an error.
	if err := RemovePlugin(dir); err != nil {
		t.Fatalf("RemovePlugin on absent file: %v", err)
	}
	if err := WritePlugin(dir, "", ""); err != nil {
		t.Fatalf("WritePlugin: %v", err)
	}
	if err := RemovePlugin(dir); err != nil {
		t.Fatalf("RemovePlugin: %v", err)
	}
	if Installed(dir) {
		t.Error("Installed = true after RemovePlugin")
	}
}
