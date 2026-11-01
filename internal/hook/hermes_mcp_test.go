package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestRegisterHermesMCP_FreshConfig pins the install-into-empty
// case. No config.yaml exists; RegisterHermesMCP creates one with
// just the observer entry.
func TestRegisterHermesMCP_FreshConfig(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	got, err := RegisterHermesMCP(HermesOptions{HermesHome: home})
	if err != nil {
		t.Fatalf("RegisterHermesMCP: %v", err)
	}
	if got != filepath.Join(home, "config.yaml") {
		t.Errorf("config path = %q", got)
	}
	out := loadYAML(t, got)
	mcp := out["mcp_servers"].(map[string]any)
	entry := mcp[HermesMCPServerName].(map[string]any)
	if entry["command"] != "observer" {
		t.Errorf("command = %v", entry["command"])
	}
}

// TestRegisterHermesMCP_MergesIntoExistingConfig pins the merge
// semantics. A pre-existing config with `inference:` block and one
// non-observer mcp_server gets the observer entry added
// without touching the rest.
func TestRegisterHermesMCP_MergesIntoExistingConfig(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	path := filepath.Join(home, "config.yaml")
	before := `inference:
  provider: anthropic
  model: claude-sonnet-4.6
mcp_servers:
  filesystem:
    command: mcp-fs
    args:
    - serve
plugins:
  disabled: []
`
	if err := os.WriteFile(path, []byte(before), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := RegisterHermesMCP(HermesOptions{HermesHome: home}); err != nil {
		t.Fatalf("RegisterHermesMCP: %v", err)
	}
	out := loadYAML(t, path)
	// inference block preserved.
	inf := out["inference"].(map[string]any)
	if inf["model"] != "claude-sonnet-4.6" {
		t.Errorf("inference.model lost: %v", inf["model"])
	}
	// Both MCP servers exist.
	mcp := out["mcp_servers"].(map[string]any)
	if _, ok := mcp["filesystem"]; !ok {
		t.Error("pre-existing filesystem MCP entry was dropped")
	}
	if _, ok := mcp[HermesMCPServerName]; !ok {
		t.Error("observer entry not added")
	}
	// plugins block preserved.
	if _, ok := out["plugins"]; !ok {
		t.Error("plugins block dropped")
	}
}

// TestRegisterHermesMCP_BinaryPathLandsInCommand pins the BinaryPath
// option: when set, it overrides "observer" as the command — needed
// when observer isn't on $PATH for the agent.
func TestRegisterHermesMCP_BinaryPathLandsInCommand(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if _, err := RegisterHermesMCP(HermesOptions{
		HermesHome: home,
		BinaryPath: "/usr/local/bin/observer-v1.8.3",
	}); err != nil {
		t.Fatalf("RegisterHermesMCP: %v", err)
	}
	out := loadYAML(t, filepath.Join(home, "config.yaml"))
	entry := out["mcp_servers"].(map[string]any)[HermesMCPServerName].(map[string]any)
	if entry["command"] != "/usr/local/bin/observer-v1.8.3" {
		t.Errorf("command = %v, want absolute BinaryPath", entry["command"])
	}
}

// TestUnregisterHermesMCP_RemovesOnlyOurEntry pins the surgical
// removal. Other mcp_servers siblings must survive.
func TestUnregisterHermesMCP_RemovesOnlyOurEntry(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	path := filepath.Join(home, "config.yaml")
	before := `mcp_servers:
  filesystem:
    command: mcp-fs
    args:
    - serve
  observer:
    command: observer
    args:
    - serve
`
	if err := os.WriteFile(path, []byte(before), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := UnregisterHermesMCP(HermesOptions{HermesHome: home}); err != nil {
		t.Fatalf("UnregisterHermesMCP: %v", err)
	}
	out := loadYAML(t, path)
	mcp := out["mcp_servers"].(map[string]any)
	if _, ok := mcp[HermesMCPServerName]; ok {
		t.Error("observer entry not removed")
	}
	if _, ok := mcp["filesystem"]; !ok {
		t.Error("sibling filesystem entry was removed")
	}
}

// TestHermesMCPUsesTheSharedServerName pins FU-2: the Hermes writer uses
// the one Observer MCP server name every other writer uses.
func TestHermesMCPUsesTheSharedServerName(t *testing.T) {
	if HermesMCPServerName != models.ObserverMCPServerName {
		t.Fatalf("HermesMCPServerName = %q, want the shared %q", HermesMCPServerName, models.ObserverMCPServerName)
	}
	if HermesLegacyMCPServerName == HermesMCPServerName {
		t.Fatal("the legacy name must differ from the shared one")
	}
}

// TestHermesMCPLegacyEntry pins FU-2's migration: register and unregister
// remove a `superbased-observer` entry an older Observer build wrote, and
// never one Observer did not write (a user's own server under that name,
// or an `observer` server that runs something else).
func TestHermesMCPLegacyEntry(t *testing.T) {
	const ours = "  superbased-observer:\n    command: /opt/observer\n    args:\n    - serve\n"
	const oursCfg = "  superbased-observer:\n    command: observer.exe\n    args:\n    - serve\n    - --config\n    - /home/u/.observer/config.toml\n"
	const theirs = "  superbased-observer:\n    command: npx\n    args:\n    - -y\n    - some-other-server\n"
	const theirsURL = "  superbased-observer:\n    url: https://example.invalid/mcp\n"
	const foreignObserver = "  observer:\n    command: node\n    args:\n    - mine.js\n"
	cases := []struct {
		name         string
		seed         string
		register     bool
		wantLegacy   bool
		wantObserver bool
	}{
		{"register drops our legacy entry", ours, true, false, true},
		{"register drops our legacy entry with --config", oursCfg, true, false, true},
		{"register keeps a foreign legacy-named entry", theirs, true, true, true},
		{"register keeps a remote legacy-named entry", theirsURL, true, true, true},
		{"unregister drops our legacy entry", ours, false, false, false},
		{"unregister keeps a foreign legacy-named entry", theirs, false, true, false},
		{"unregister keeps a foreign observer entry", foreignObserver, false, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, "config.yaml")
			seed := "mcp_servers:\n  filesystem:\n    command: mcp-fs\n" + c.seed
			if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
				t.Fatal(err)
			}
			opts := HermesOptions{HermesHome: home, BinaryPath: "/opt/observer"}
			var err error
			if c.register {
				_, err = RegisterHermesMCP(opts)
			} else {
				_, err = UnregisterHermesMCP(opts)
			}
			if err != nil {
				t.Fatalf("write: %v", err)
			}
			mcp := loadYAML(t, path)["mcp_servers"].(map[string]any)
			if _, ok := mcp[HermesLegacyMCPServerName]; ok != c.wantLegacy {
				t.Errorf("legacy entry present = %v, want %v", ok, c.wantLegacy)
			}
			if _, ok := mcp[HermesMCPServerName]; ok != c.wantObserver {
				t.Errorf("observer entry present = %v, want %v", ok, c.wantObserver)
			}
			if _, ok := mcp["filesystem"]; !ok {
				t.Error("sibling filesystem entry was removed")
			}
		})
	}
}

// TestUnregisterHermesMCP_DropsEmptyMCPServersKey pins the post-
// removal cleanup: when removing the last mcp_servers entry, the
// whole mcp_servers key is removed too (avoids leaving an
// empty-mapping yaml.v3 marshals as `mcp_servers: {}`).
func TestUnregisterHermesMCP_DropsEmptyMCPServersKey(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if _, err := RegisterHermesMCP(HermesOptions{HermesHome: home}); err != nil {
		t.Fatalf("seed via RegisterHermesMCP: %v", err)
	}
	if _, err := UnregisterHermesMCP(HermesOptions{HermesHome: home}); err != nil {
		t.Fatalf("UnregisterHermesMCP: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(home, "config.yaml"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(data), "mcp_servers") {
		t.Errorf("mcp_servers key still present after removing last entry:\n%s", data)
	}
}

// TestUnregisterHermesMCP_AbsentConfigIsNoop pins the idempotent
// uninstall on a system that never had MCP wired.
func TestUnregisterHermesMCP_AbsentConfigIsNoop(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if _, err := UnregisterHermesMCP(HermesOptions{HermesHome: home}); err != nil {
		t.Errorf("UnregisterHermesMCP on absent config: %v", err)
	}
	// Config file should still not exist.
	if _, err := os.Stat(filepath.Join(home, "config.yaml")); !os.IsNotExist(err) {
		t.Errorf("UnregisterHermesMCP created a config file: %v", err)
	}
}

// TestRegisterHermesPluginEnabled_FreshConfig pins the auto-enable
// path on a system without any pre-existing plugins block. The
// validation 2026-06-06 finding: without this entry, Hermes parses
// the plugin manifest but skips loading the plugin — silent capture
// gap.
func TestRegisterHermesPluginEnabled_FreshConfig(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if _, err := RegisterHermesPluginEnabled(HermesOptions{HermesHome: home}); err != nil {
		t.Fatalf("RegisterHermesPluginEnabled: %v", err)
	}
	out := loadYAML(t, filepath.Join(home, "config.yaml"))
	plugins := out["plugins"].(map[string]any)
	enabled := plugins["enabled"].([]any)
	if len(enabled) != 1 || enabled[0] != HermesPluginDirName {
		t.Errorf("enabled = %v, want [%q]", enabled, HermesPluginDirName)
	}
}

// TestRegisterHermesPluginEnabled_IdempotentReadd confirms re-running
// against an already-enabled plugin doesn't duplicate the entry.
func TestRegisterHermesPluginEnabled_IdempotentReadd(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if _, err := RegisterHermesPluginEnabled(HermesOptions{HermesHome: home}); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := RegisterHermesPluginEnabled(HermesOptions{HermesHome: home}); err != nil {
		t.Fatalf("second: %v", err)
	}
	out := loadYAML(t, filepath.Join(home, "config.yaml"))
	enabled := out["plugins"].(map[string]any)["enabled"].([]any)
	if len(enabled) != 1 {
		t.Errorf("enabled = %v, want exactly 1 entry", enabled)
	}
}

// TestRegisterHermesPluginEnabled_PreservesSiblings confirms we
// merge into an existing enabled-list rather than overwriting.
func TestRegisterHermesPluginEnabled_PreservesSiblings(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	path := filepath.Join(home, "config.yaml")
	if err := os.WriteFile(path, []byte("plugins:\n  enabled:\n    - web-tavily\n    - fal\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := RegisterHermesPluginEnabled(HermesOptions{HermesHome: home}); err != nil {
		t.Fatalf("RegisterHermesPluginEnabled: %v", err)
	}
	enabled := loadYAML(t, path)["plugins"].(map[string]any)["enabled"].([]any)
	if len(enabled) != 3 {
		t.Fatalf("enabled = %v, want 3 entries", enabled)
	}
	want := map[string]bool{"web-tavily": false, "fal": false, HermesPluginDirName: false}
	for _, v := range enabled {
		if s, ok := v.(string); ok {
			want[s] = true
		}
	}
	for k, found := range want {
		if !found {
			t.Errorf("entry %q missing from final enabled list", k)
		}
	}
}

// TestUnregisterHermesPluginEnabled_RemovesOnlyOurEntry confirms
// surgical removal — sibling plugins on the enabled-list survive.
func TestUnregisterHermesPluginEnabled_RemovesOnlyOurEntry(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	path := filepath.Join(home, "config.yaml")
	if err := os.WriteFile(path, []byte("plugins:\n  enabled:\n    - web-tavily\n    - superbased-observer\n    - fal\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := UnregisterHermesPluginEnabled(HermesOptions{HermesHome: home}); err != nil {
		t.Fatalf("UnregisterHermesPluginEnabled: %v", err)
	}
	enabled := loadYAML(t, path)["plugins"].(map[string]any)["enabled"].([]any)
	if len(enabled) != 2 {
		t.Errorf("enabled = %v, want 2 (siblings only)", enabled)
	}
	for _, v := range enabled {
		if s, _ := v.(string); s == HermesPluginDirName {
			t.Error("superbased-observer not removed")
		}
	}
}

// TestUnregisterHermesPluginEnabled_DropsEmptyKeys confirms cleanup
// when our entry was the only one — both `plugins.enabled` and the
// `plugins:` parent get removed to avoid leaving `plugins: {}` YAML.
func TestUnregisterHermesPluginEnabled_DropsEmptyKeys(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if _, err := RegisterHermesPluginEnabled(HermesOptions{HermesHome: home}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := UnregisterHermesPluginEnabled(HermesOptions{HermesHome: home}); err != nil {
		t.Fatalf("UnregisterHermesPluginEnabled: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(home, "config.yaml"))
	if strings.Contains(string(data), "plugins") {
		t.Errorf("plugins key still present after removing only entry:\n%s", data)
	}
}

// TestWriteYAMLMap_BackupBehavior table-drives the writeYAMLMap /
// backupYAMLConfig backup-before-rewrite discipline (mirrors
// cmd/observer/hermes.go's ensureHermesObserverProvider): a pre-existing
// config.yaml gets a .bak copy of its PRE-REWRITE content before
// writeYAMLMap replaces it; a fresh install (no pre-existing file) gets no
// backup at all.
func TestWriteYAMLMap_BackupBehavior(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		seed       string // "" means don't create the file first
		wantBackup bool
	}{
		{
			name:       "pre-existing file gets backed up",
			seed:       "inference:\n  provider: anthropic\n# a hand-written comment\n",
			wantBackup: true,
		},
		{
			name:       "fresh install gets no backup",
			seed:       "",
			wantBackup: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			if tc.seed != "" {
				if err := os.WriteFile(path, []byte(tc.seed), 0o600); err != nil {
					t.Fatalf("seed: %v", err)
				}
			}
			if err := writeYAMLMap(path, map[string]any{"inference": map[string]any{"provider": "anthropic"}}); err != nil {
				t.Fatalf("writeYAMLMap: %v", err)
			}
			backup, err := os.ReadFile(path + ".bak")
			if tc.wantBackup {
				if err != nil {
					t.Fatalf("expected .bak file: %v", err)
				}
				if string(backup) != tc.seed {
					t.Errorf("backup content = %q, want pre-rewrite original %q", backup, tc.seed)
				}
			} else if !os.IsNotExist(err) {
				t.Errorf("expected no .bak on fresh install, stat err = %v", err)
			}
		})
	}
}

// TestWriteYAMLMap_PreservesPermissionBits confirms the original file's
// permission bits survive onto both the backup and the rewritten file.
func TestWriteYAMLMap_PreservesPermissionBits(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("plugins:\n  enabled: []\n"), 0o640); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := writeYAMLMap(path, map[string]any{"plugins": map[string]any{"enabled": []any{}}}); err != nil {
		t.Fatalf("writeYAMLMap: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat rewritten: %v", err)
	}
	if posixModes && info.Mode().Perm() != 0o640 {
		t.Errorf("rewritten file mode = %v, want 0640", info.Mode().Perm())
	}
	bakInfo, err := os.Stat(path + ".bak")
	if err != nil {
		t.Fatalf("stat backup: %v", err)
	}
	if posixModes && bakInfo.Mode().Perm() != 0o640 {
		t.Errorf("backup file mode = %v, want 0640", bakInfo.Mode().Perm())
	}
}

// TestRegisterHermesPluginEnabledThenMCP_KeepsOperatorBytes pins the
// combined-writers case: `observer init --hermes` runs
// RegisterHermesPluginEnabled followed by RegisterHermesMCP against the
// SAME config.yaml in one process (see cmd/observer/init.go). config.yaml
// holds provider keys, so both writers edit only their own node (review
// T-384): the operator's keys and comment survive and no backup copy of
// the file is made.
func TestRegisterHermesPluginEnabledThenMCP_KeepsOperatorBytes(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	path := filepath.Join(home, "config.yaml")
	original := "inference:\n  provider: anthropic\n  model: claude-sonnet-4.6\n# operator comment\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	opts := HermesOptions{HermesHome: home}
	if _, err := RegisterHermesPluginEnabled(opts); err != nil {
		t.Fatalf("RegisterHermesPluginEnabled: %v", err)
	}
	if _, err := RegisterHermesMCP(opts); err != nil {
		t.Fatalf("RegisterHermesMCP: %v", err)
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Errorf("a credential-file writer left a backup copy: stat err = %v", err)
	}
	if got, _ := os.ReadFile(path); !strings.Contains(string(got), "model: claude-sonnet-4.6") || !strings.Contains(string(got), "# operator comment") {
		t.Errorf("the operator's lines were rewritten:\n%s", got)
	}
	// Sanity: both writes actually landed (plugins.enabled + mcp_servers),
	// otherwise the test would trivially pass without exercising the
	// dual-writer path.
	out := loadYAML(t, path)
	if _, ok := out["mcp_servers"]; !ok {
		t.Fatal("mcp_servers not written — test didn't exercise both writers")
	}
	plugins, _ := out["plugins"].(map[string]any)
	if plugins == nil || plugins["enabled"] == nil {
		t.Fatal("plugins.enabled not written — test didn't exercise both writers")
	}
}

// TestRegisterHermesMCP_DryRunSkipsBackup confirms opts.DryRun never
// touches the filesystem at all — no rewrite AND no backup.
func TestRegisterHermesMCP_DryRunSkipsBackup(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	path := filepath.Join(home, "config.yaml")
	original := "inference:\n  provider: anthropic\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := RegisterHermesMCP(HermesOptions{HermesHome: home, DryRun: true}); err != nil {
		t.Fatalf("RegisterHermesMCP dry-run: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != original {
		t.Error("dry-run modified config.yaml")
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Errorf("dry-run created a .bak file, stat err = %v", err)
	}
}

// loadYAML is a test helper that parses path as a YAML map.
func loadYAML(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(data, &m); err != nil {
		t.Fatalf("yaml.Unmarshal: %v\nbody:\n%s", err, data)
	}
	return m
}
