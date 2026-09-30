package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/mcp/locate"
)

// newRegistrar wires a sandboxed Registrar against tmpHome so tests don't
// touch the real user config.
func newRegistrar(t *testing.T, force bool) (*Registrar, string) {
	t.Helper()
	home := t.TempDir()
	r, err := NewRegistrar(RegisterOptions{
		BinaryPath: "/usr/local/bin/observer",
		HomeDir:    home,
		Force:      force,
	})
	if err != nil {
		t.Fatalf("NewRegistrar: %v", err)
	}
	return r, home
}

func TestRegistrar_NewValidation(t *testing.T) {
	if _, err := NewRegistrar(RegisterOptions{}); err == nil {
		t.Error("missing BinaryPath should error")
	}
}

func TestRegistrar_Installed(t *testing.T) {
	r, home := newRegistrar(t, false)
	// Cross-OS "-windows" entries are crossmount/platform-dependent (a WSL
	// host may see a Windows VS Code Cline globalStorage regardless of the
	// test's temp home) — assert only the native same-OS triggers.
	nativeOnly := func() []string {
		var out []string
		for _, g := range r.Installed() {
			if !strings.HasSuffix(g, "-windows") {
				out = append(out, g)
			}
		}
		return out
	}
	if got := nativeOnly(); len(got) != 0 {
		t.Errorf("fresh home (native): %v", got)
	}
	for _, d := range []string{".claude", ".cursor", ".codex"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	want := map[string]bool{"claude-code": true, "cursor": true, "codex": true}
	for _, g := range nativeOnly() {
		if !want[g] {
			t.Errorf("unexpected native: %s", g)
		}
		delete(want, g)
	}
	if len(want) != 0 {
		t.Errorf("missing: %v", want)
	}
}

func TestRegistrar_ClaudeCodeJSON(t *testing.T) {
	r, home := newRegistrar(t, false)
	res := r.Register("claude-code")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if !res.Added {
		t.Errorf("expected Added=true: %+v", res)
	}
	if res.ConfigPath != filepath.Join(home, ".claude.json") {
		t.Errorf("ConfigPath: %s", res.ConfigPath)
	}

	body, err := os.ReadFile(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("parse: %v", err)
	}
	servers := top["mcpServers"].(map[string]any)
	entry := servers[ServerName].(map[string]any)
	if entry["command"] != "/usr/local/bin/observer" {
		t.Errorf("command: %v", entry["command"])
	}
	args := entry["args"].([]any)
	if len(args) != 1 || args[0] != "serve" {
		t.Errorf("args: %v", args)
	}

	// Idempotent re-register.
	res2 := r.Register("claude-code")
	if res2.Error != nil {
		t.Fatalf("re-register: %v", res2.Error)
	}
	if !res2.AlreadySet {
		t.Errorf("expected AlreadySet on re-register: %+v", res2)
	}
	if res2.Added {
		t.Errorf("expected Added=false on re-register")
	}
}

func TestRegistrar_CursorJSON(t *testing.T) {
	r, home := newRegistrar(t, false)
	res := r.Register("cursor")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	want := filepath.Join(home, ".cursor", "mcp.json")
	if res.ConfigPath != want {
		t.Errorf("ConfigPath: %s want %s", res.ConfigPath, want)
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("file not written: %v", err)
	}
}

func TestRegistrar_PreservesExistingMCPServers(t *testing.T) {
	r, home := newRegistrar(t, false)
	// Pre-seed Claude config with another MCP server we shouldn't clobber.
	path := filepath.Join(home, ".claude.json")
	prior := `{
  "feedbackSurveyState": {"shown": true},
  "mcpServers": {
    "other-server": {"command": "/opt/other", "args": ["serve"]}
  }
}`
	if err := os.WriteFile(path, []byte(prior), 0o644); err != nil {
		t.Fatal(err)
	}

	res := r.Register("claude-code")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	body, _ := os.ReadFile(path)
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("parse: %v: %s", err, body)
	}
	if _, ok := top["feedbackSurveyState"]; !ok {
		t.Error("feedbackSurveyState was clobbered")
	}
	servers := top["mcpServers"].(map[string]any)
	if _, ok := servers["other-server"]; !ok {
		t.Errorf("other-server lost: %v", servers)
	}
	if _, ok := servers[ServerName]; !ok {
		t.Errorf("our server missing: %v", servers)
	}
}

func TestRegistrar_ConflictRequiresForce(t *testing.T) {
	r, home := newRegistrar(t, false)
	path := filepath.Join(home, ".claude.json")
	prior := `{"mcpServers":{"observer":{"command":"/different/path","args":["x"]}}}`
	if err := os.WriteFile(path, []byte(prior), 0o644); err != nil {
		t.Fatal(err)
	}
	res := r.Register("claude-code")
	if res.Error == nil {
		t.Errorf("expected conflict error: %+v", res)
	}
	if !strings.Contains(res.Error.Error(), "--force") {
		t.Errorf("error should mention --force: %v", res.Error)
	}

	// With force=true, conflict is overwritten.
	rf, _ := NewRegistrar(RegisterOptions{
		BinaryPath: "/usr/local/bin/observer",
		HomeDir:    home,
		Force:      true,
	})
	res2 := rf.Register("claude-code")
	if res2.Error != nil {
		t.Fatalf("force register: %v", res2.Error)
	}
	if !res2.Added {
		t.Errorf("force should overwrite: %+v", res2)
	}
}

// TestRegistrar_ConfigPathThreadedIntoArgs pins the v1.4.43+ MCP/proxy
// config-split fix: when `observer init --config /path/to/x.toml` is
// invoked, the registered MCP launch becomes
// `observer serve --config /path/to/x.toml` so the MCP server reads the
// same config as whichever proxy is running with that config. Without
// this, stash + retrieve_stashed get out of sync because the proxy and
// MCP server look at different config files. Surfaced 2026-05-08
// dogfood when retrieve_stashed never registered against the A/B
// harness's config.
func TestRegistrar_ConfigPathThreadedIntoArgs(t *testing.T) {
	home := t.TempDir()
	r, err := NewRegistrar(RegisterOptions{
		BinaryPath: "/usr/local/bin/observer",
		HomeDir:    home,
		ConfigPath: "/tmp/ab-claude/on/observer-config.toml",
	})
	if err != nil {
		t.Fatalf("NewRegistrar: %v", err)
	}
	res := r.Register("claude-code")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}

	body, err := os.ReadFile(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("parse: %v", err)
	}
	servers := top["mcpServers"].(map[string]any)
	entry := servers[ServerName].(map[string]any)
	args := entry["args"].([]any)
	if len(args) != 3 || args[0] != "serve" || args[1] != "--config" || args[2] != "/tmp/ab-claude/on/observer-config.toml" {
		t.Errorf("args: got %v want [serve --config /tmp/ab-claude/on/observer-config.toml]", args)
	}
}

// TestRegistrar_ConfigPathChangeIsNotAlreadySet pins that re-running
// `observer init` with a different --config (or dropping it) refreshes
// the registration instead of being treated as already-set. Without
// this, switching A/B harnesses would silently keep the previous
// config wired up.
func TestRegistrar_ConfigPathChangeIsNotAlreadySet(t *testing.T) {
	home := t.TempDir()
	first, _ := NewRegistrar(RegisterOptions{
		BinaryPath: "/usr/local/bin/observer",
		HomeDir:    home,
		ConfigPath: "/tmp/old.toml",
	})
	if r := first.Register("claude-code"); r.Error != nil || !r.Added {
		t.Fatalf("first register: %+v", r)
	}

	second, _ := NewRegistrar(RegisterOptions{
		BinaryPath: "/usr/local/bin/observer",
		HomeDir:    home,
		ConfigPath: "/tmp/new.toml",
	})
	res := second.Register("claude-code")
	if res.Error != nil {
		t.Fatalf("second register: %v", res.Error)
	}
	if res.AlreadySet {
		t.Errorf("expected refresh on config change, got AlreadySet")
	}
	body, _ := os.ReadFile(res.ConfigPath)
	if !strings.Contains(string(body), "/tmp/new.toml") {
		t.Errorf("expected refreshed config path; got %s", body)
	}
}

// TestRegistrar_OpenCodeJSON pins OpenCode's own MCP shape (live-grounded
// 2026-06-26 against the operator's install): a top-level "mcp" object whose
// "observer" entry is {"type":"local","command":[binary,"serve"],"enabled":
// true} — NOT the {"mcpServers":{command,args}} shape Claude Code/Cursor use.
func TestRegistrar_OpenCodeJSON(t *testing.T) {
	r, home := newRegistrar(t, false)
	res := r.Register("opencode")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if !res.Added {
		t.Errorf("expected Added=true: %+v", res)
	}
	want := filepath.Join(home, ".config", "opencode", "opencode.json")
	if res.ConfigPath != want {
		t.Errorf("ConfigPath: %s want %s", res.ConfigPath, want)
	}

	body, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("file not written: %v", err)
	}
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("parse: %v: %s", err, body)
	}
	mcp, ok := top["mcp"].(map[string]any)
	if !ok {
		t.Fatalf("no mcp object: %v", top)
	}
	entry := mcp[ServerName].(map[string]any)
	if entry["type"] != "local" {
		t.Errorf("type: %v want local", entry["type"])
	}
	if entry["enabled"] != true {
		t.Errorf("enabled: %v want true", entry["enabled"])
	}
	cmd := entry["command"].([]any)
	if len(cmd) != 2 || cmd[0] != "/usr/local/bin/observer" || cmd[1] != "serve" {
		t.Errorf("command: %v want [/usr/local/bin/observer serve]", cmd)
	}

	// Idempotent re-register.
	res2 := r.Register("opencode")
	if res2.Error != nil {
		t.Fatalf("re-register: %v", res2.Error)
	}
	if !res2.AlreadySet || res2.Added {
		t.Errorf("expected AlreadySet on re-register: %+v", res2)
	}
}

// TestRegistrar_OpenCodePreservesConfig pins that the OpenCode writer keeps
// every unrelated top-level key ($schema, plugin) AND sibling MCP servers —
// including fields we don't model on a sibling entry (a remote server's
// "url", an "environment" map) — because siblings are round-tripped as raw
// JSON, not decoded through opencodeMCPEntry.
func TestRegistrar_OpenCodePreservesConfig(t *testing.T) {
	r, home := newRegistrar(t, false)
	path := filepath.Join(home, ".config", "opencode", "opencode.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	prior := `{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["superbased-opencode-plugin"],
  "mcp": {
    "remote-thing": {"type": "remote", "url": "https://example.com/mcp", "enabled": true},
    "local-thing": {"type": "local", "command": ["foo"], "enabled": false, "environment": {"K": "V"}}
  }
}`
	if err := os.WriteFile(path, []byte(prior), 0o644); err != nil {
		t.Fatal(err)
	}

	res := r.Register("opencode")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	body, _ := os.ReadFile(path)
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("parse: %v: %s", err, body)
	}
	if top["$schema"] != "https://opencode.ai/config.json" {
		t.Error("$schema clobbered")
	}
	if _, ok := top["plugin"]; !ok {
		t.Error("plugin clobbered")
	}
	mcp := top["mcp"].(map[string]any)
	if _, ok := mcp[ServerName]; !ok {
		t.Errorf("our server missing: %v", mcp)
	}
	remote, ok := mcp["remote-thing"].(map[string]any)
	if !ok || remote["url"] != "https://example.com/mcp" {
		t.Errorf("remote sibling url dropped: %v", mcp["remote-thing"])
	}
	local, ok := mcp["local-thing"].(map[string]any)
	if !ok {
		t.Fatalf("local sibling lost: %v", mcp)
	}
	if env, ok := local["environment"].(map[string]any); !ok || env["K"] != "V" {
		t.Errorf("local sibling environment dropped: %v", local)
	}
}

// TestRegistrar_OpenCodeConflictAndUnregister pins the --force conflict
// semantics on a foreign-binary observer entry plus the unregister round-trip
// (observer removed, sibling kept).
func TestRegistrar_OpenCodeConflictAndUnregister(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".config", "opencode", "opencode.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	prior := `{"mcp":{"observer":{"type":"local","command":["/different/path","serve"],"enabled":true},"keep":{"type":"local","command":["k"],"enabled":true}}}`
	if err := os.WriteFile(path, []byte(prior), 0o644); err != nil {
		t.Fatal(err)
	}

	r, _ := NewRegistrar(RegisterOptions{BinaryPath: "/usr/local/bin/observer", HomeDir: home})
	res := r.Register("opencode")
	if res.Error == nil || !strings.Contains(res.Error.Error(), "--force") {
		t.Fatalf("expected --force conflict, got: %+v", res)
	}

	rf, _ := NewRegistrar(RegisterOptions{BinaryPath: "/usr/local/bin/observer", HomeDir: home, Force: true})
	if res := rf.Register("opencode"); res.Error != nil || !res.Added {
		t.Fatalf("force register: %+v", res)
	}

	// Unregister removes observer, keeps the sibling.
	ures := rf.Unregister("opencode")
	if ures.Error != nil || !ures.Removed {
		t.Fatalf("unregister: %+v", ures)
	}
	body, _ := os.ReadFile(path)
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("parse: %v: %s", err, body)
	}
	mcp := top["mcp"].(map[string]any)
	if _, ok := mcp[ServerName]; ok {
		t.Errorf("observer not removed: %v", mcp)
	}
	if _, ok := mcp["keep"]; !ok {
		t.Errorf("sibling 'keep' lost on unregister: %v", mcp)
	}
}

// TestRegistrar_InstalledDetectsOpenCode pins that a present
// ~/.config/opencode directory surfaces opencode in Installed().
func TestRegistrar_InstalledDetectsOpenCode(t *testing.T) {
	r, home := newRegistrar(t, false)
	if err := os.MkdirAll(filepath.Join(home, ".config", "opencode"), 0o755); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, g := range r.Installed() {
		if g == "opencode" {
			found = true
		}
	}
	if !found {
		t.Errorf("opencode not detected: %v", r.Installed())
	}
}

// TestRegistrar_InstalledDetectsDroid pins the droid probe: a
// t.TempDir()-rooted ~/.factory present is enough for Installed() to
// report "droid" — mirrors TestRegistrar_InstalledDetectsOpenCode. Never
// touches the real ~/.factory.
func TestRegistrar_InstalledDetectsDroid(t *testing.T) {
	r, home := newRegistrar(t, false)
	if err := os.MkdirAll(filepath.Join(home, ".factory"), 0o755); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, g := range r.Installed() {
		if g == "droid" {
			found = true
		}
	}
	if !found {
		t.Errorf("droid not detected: %v", r.Installed())
	}
}

// TestRegistrar_DroidJSON pins droid's MCP write: the shared
// {"mcpServers":{command,args}} JSON shape at ~/.factory/mcp.json,
// mirroring claude-code/cursor. Existing sibling servers and other
// top-level keys survive registration, and Unregister cleanly removes only
// the observer entry.
func TestRegistrar_DroidJSON(t *testing.T) {
	r, home := newRegistrar(t, false)
	want := filepath.Join(home, ".factory", "mcp.json")

	// Pre-seed with another MCP server + an unrelated top-level key we
	// must not clobber.
	prior := `{
  "someOtherKey": {"shown": true},
  "mcpServers": {
    "other-server": {"command": "/opt/other", "args": ["serve"]}
  }
}`
	if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(want, []byte(prior), 0o644); err != nil {
		t.Fatal(err)
	}

	res := r.Register("droid")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if !res.Added {
		t.Errorf("expected Added=true: %+v", res)
	}
	if res.ConfigPath != want {
		t.Errorf("ConfigPath: %s want %s", res.ConfigPath, want)
	}

	body, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("file not written: %v", err)
	}
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("parse: %v: %s", err, body)
	}
	if _, ok := top["someOtherKey"]; !ok {
		t.Error("someOtherKey was clobbered")
	}
	servers := top["mcpServers"].(map[string]any)
	if _, ok := servers["other-server"]; !ok {
		t.Errorf("other-server lost: %v", servers)
	}
	entry, ok := servers[ServerName].(map[string]any)
	if !ok {
		t.Fatalf("our server missing: %v", servers)
	}
	if entry["command"] != "/usr/local/bin/observer" {
		t.Errorf("command: %v", entry["command"])
	}
	args := entry["args"].([]any)
	if len(args) != 1 || args[0] != "serve" {
		t.Errorf("args: %v", args)
	}

	// Idempotent re-register.
	res2 := r.Register("droid")
	if res2.Error != nil {
		t.Fatalf("re-register: %v", res2.Error)
	}
	if !res2.AlreadySet {
		t.Errorf("expected AlreadySet on re-register: %+v", res2)
	}

	// Unregister removes only observer's entry.
	ures := r.Unregister("droid")
	if ures.Error != nil {
		t.Fatalf("Unregister: %v", ures.Error)
	}
	if !ures.Removed {
		t.Errorf("expected Removed=true: %+v", ures)
	}
	body, err = os.ReadFile(want)
	if err != nil {
		t.Fatalf("file removed unexpectedly: %v", err)
	}
	top = map[string]any{}
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("parse after unregister: %v: %s", err, body)
	}
	servers = top["mcpServers"].(map[string]any)
	if _, ok := servers[ServerName]; ok {
		t.Errorf("observer entry still present after Unregister: %v", servers)
	}
	if _, ok := servers["other-server"]; !ok {
		t.Errorf("other-server lost after Unregister: %v", servers)
	}
}

// TestRegistrar_InstalledDetectsCommandCode pins the command-code probe: a
// t.TempDir()-rooted ~/.commandcode present is enough for Installed() to
// report "command-code" — mirrors TestRegistrar_InstalledDetectsDroid.
// Never touches the real ~/.commandcode.
func TestRegistrar_InstalledDetectsCommandCode(t *testing.T) {
	r, home := newRegistrar(t, false)
	if err := os.MkdirAll(filepath.Join(home, ".commandcode"), 0o755); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, g := range r.Installed() {
		if g == "command-code" {
			found = true
		}
	}
	if !found {
		t.Errorf("command-code not detected: %v", r.Installed())
	}
}

// TestRegistrar_CommandCodeJSON pins command-code's MCP write: the shared
// {"mcpServers":{command,args}} JSON shape at ~/.commandcode/mcp.json,
// mirroring claude-code/cursor/droid. Existing sibling servers and other
// top-level keys survive registration, and Unregister cleanly removes only
// the observer entry.
func TestRegistrar_CommandCodeJSON(t *testing.T) {
	r, home := newRegistrar(t, false)
	want := filepath.Join(home, ".commandcode", "mcp.json")

	// Pre-seed with another MCP server + an unrelated top-level key we
	// must not clobber.
	prior := `{
  "someOtherKey": {"shown": true},
  "mcpServers": {
    "other-server": {"command": "/opt/other", "args": ["serve"]}
  }
}`
	if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(want, []byte(prior), 0o644); err != nil {
		t.Fatal(err)
	}

	res := r.Register("command-code")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if !res.Added {
		t.Errorf("expected Added=true: %+v", res)
	}
	if res.ConfigPath != want {
		t.Errorf("ConfigPath: %s want %s", res.ConfigPath, want)
	}

	body, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("file not written: %v", err)
	}
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("parse: %v: %s", err, body)
	}
	if _, ok := top["someOtherKey"]; !ok {
		t.Error("someOtherKey was clobbered")
	}
	servers := top["mcpServers"].(map[string]any)
	if _, ok := servers["other-server"]; !ok {
		t.Errorf("other-server lost: %v", servers)
	}
	entry, ok := servers[ServerName].(map[string]any)
	if !ok {
		t.Fatalf("our server missing: %v", servers)
	}
	if entry["command"] != "/usr/local/bin/observer" {
		t.Errorf("command: %v", entry["command"])
	}
	args := entry["args"].([]any)
	if len(args) != 1 || args[0] != "serve" {
		t.Errorf("args: %v", args)
	}

	// Idempotent re-register.
	res2 := r.Register("command-code")
	if res2.Error != nil {
		t.Fatalf("re-register: %v", res2.Error)
	}
	if !res2.AlreadySet {
		t.Errorf("expected AlreadySet on re-register: %+v", res2)
	}

	// Unregister removes only observer's entry.
	ures := r.Unregister("command-code")
	if ures.Error != nil {
		t.Fatalf("Unregister: %v", ures.Error)
	}
	if !ures.Removed {
		t.Errorf("expected Removed=true: %+v", ures)
	}
	body, err = os.ReadFile(want)
	if err != nil {
		t.Fatalf("file removed unexpectedly: %v", err)
	}
	top = map[string]any{}
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("parse after unregister: %v: %s", err, body)
	}
	servers = top["mcpServers"].(map[string]any)
	if _, ok := servers[ServerName]; ok {
		t.Errorf("observer entry still present after Unregister: %v", servers)
	}
	if _, ok := servers["other-server"]; !ok {
		t.Errorf("other-server lost after Unregister: %v", servers)
	}
}

// TestRegistrar_ClineNativeJSON pins the native (same-OS) Cline MCP write:
// VS Code globalStorage cline_mcp_settings.json in the standard
// {"mcpServers":{command,args}} shape, created under the daemon's home.
func TestRegistrar_ClineNativeJSON(t *testing.T) {
	r, home := newRegistrar(t, false)
	res := r.Register("cline")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if !res.Added {
		t.Errorf("expected Added=true: %+v", res)
	}
	want := locate.ClineSettingsPath(home, runtime.GOOS)
	if res.ConfigPath != want {
		t.Errorf("ConfigPath: %s want %s", res.ConfigPath, want)
	}
	body, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("file not written: %v", err)
	}
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("parse: %v: %s", err, body)
	}
	entry := top["mcpServers"].(map[string]any)[ServerName].(map[string]any)
	if entry["command"] != "/usr/local/bin/observer" {
		t.Errorf("command: %v", entry["command"])
	}
}

// TestRegistrar_ClineWindowsBridge pins the cross-OS Cline MCP write: a
// wsl.exe bridge command into a Windows VS Code globalStorage path, resolved
// via WindowsClineHome (so the test doesn't depend on crossmount/`/mnt/c`).
func TestRegistrar_ClineWindowsBridge(t *testing.T) {
	// The Windows home must live UNDER the pinned HomeDir: once a caller
	// sandboxes its home, an override outside it is refused (containment half
	// of crossmount.AutoDetectSuppressed — the 2026-07-31 follow-up round).
	home := t.TempDir()
	winHome := filepath.Join(home, "mnt", "c", "Users", "tester")
	if err := os.MkdirAll(winHome, 0o755); err != nil {
		t.Fatalf("mkdir win home: %v", err)
	}
	r, err := NewRegistrar(RegisterOptions{
		BinaryPath:       "/home/u/.local/bin/observer",
		HomeDir:          home,
		WindowsClineHome: winHome,
		WSLDistro:        "Ubuntu",
	})
	if err != nil {
		t.Fatalf("NewRegistrar: %v", err)
	}
	res := r.Register("cline-windows")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	want := locate.ClineSettingsPath(winHome, "windows")
	if res.ConfigPath != want {
		t.Errorf("ConfigPath: %s want %s", res.ConfigPath, want)
	}
	body, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("file not written: %v", err)
	}
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("parse: %v: %s", err, body)
	}
	entry := top["mcpServers"].(map[string]any)[ServerName].(map[string]any)
	if entry["command"] != "wsl.exe" {
		t.Errorf("command: %v want wsl.exe", entry["command"])
	}
	args := entry["args"].([]any)
	wantArgs := []any{"-d", "Ubuntu", "--", "/home/u/.local/bin/observer", "serve"}
	if len(args) != len(wantArgs) {
		t.Fatalf("args: %v want %v", args, wantArgs)
	}
	for i := range wantArgs {
		if args[i] != wantArgs[i] {
			t.Errorf("args[%d] = %v want %v", i, args[i], wantArgs[i])
		}
	}

	// Idempotent re-register + unregister round-trip.
	if res2 := r.Register("cline-windows"); res2.Error != nil || !res2.AlreadySet {
		t.Errorf("re-register: %+v", res2)
	}
	if ures := r.Unregister("cline-windows"); ures.Error != nil || !ures.Removed {
		t.Errorf("unregister: %+v", ures)
	}
}

// TestRegistrar_ClineWindowsNoDistro pins the honest failure when the WSL
// distro can't be resolved (no WSLDistro and no $WSL_DISTRO_NAME).
func TestRegistrar_ClineWindowsNoDistro(t *testing.T) {
	t.Setenv("WSL_DISTRO_NAME", "")
	noDistroHome := t.TempDir()
	noDistroWin := filepath.Join(noDistroHome, "winhome") // contained, per the gate
	if err := os.MkdirAll(noDistroWin, 0o755); err != nil {
		t.Fatalf("mkdir win home: %v", err)
	}
	r, _ := NewRegistrar(RegisterOptions{
		BinaryPath:       "/x/observer",
		HomeDir:          noDistroHome,
		WindowsClineHome: noDistroWin,
	})
	res := r.Register("cline-windows")
	if res.Error == nil || !strings.Contains(res.Error.Error(), "distro") {
		t.Errorf("expected distro error, got: %+v", res)
	}
}

func TestRegistrar_DryRunDoesNotWrite(t *testing.T) {
	home := t.TempDir()
	r, _ := NewRegistrar(RegisterOptions{
		BinaryPath: "/usr/local/bin/observer",
		HomeDir:    home,
		DryRun:     true,
	})
	res := r.Register("claude-code")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if !res.DryRun || !res.Added {
		t.Errorf("expected DryRun+Added: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude.json")); err == nil {
		t.Error("file written despite dry-run")
	}
}

func TestRegistrar_CodexTOML(t *testing.T) {
	r, home := newRegistrar(t, false)
	// Pre-seed a config.toml with an unrelated section we must preserve.
	dir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.toml")
	prior := "model = \"o4-mini\"\n\n[mcp_servers.other]\ncommand = \"/opt/other\"\nargs = [\"serve\"]\n"
	if err := os.WriteFile(path, []byte(prior), 0o644); err != nil {
		t.Fatal(err)
	}

	res := r.Register("codex")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if !res.Added {
		t.Errorf("expected Added: %+v", res)
	}

	body, _ := os.ReadFile(path)
	var root map[string]any
	if err := toml.Unmarshal(body, &root); err != nil {
		t.Fatalf("re-parse: %v: %s", err, body)
	}
	if root["model"] != "o4-mini" {
		t.Errorf("top-level model lost: %v", root["model"])
	}
	servers := root["mcp_servers"].(map[string]any)
	if _, ok := servers["other"]; !ok {
		t.Errorf("other server lost: %v", servers)
	}
	ours := servers[ServerName].(map[string]any)
	if ours["command"] != "/usr/local/bin/observer" {
		t.Errorf("command: %v", ours["command"])
	}

	// Re-register is idempotent.
	res2 := r.Register("codex")
	if res2.Error != nil {
		t.Fatalf("re-register: %v", res2.Error)
	}
	if !res2.AlreadySet {
		t.Errorf("expected AlreadySet: %+v", res2)
	}
}

func TestRegistrar_UnknownTool(t *testing.T) {
	r, _ := newRegistrar(t, false)
	res := r.Register("nonexistent")
	if res.Error == nil {
		t.Error("expected error for unknown tool")
	}
}

// TestRegistrar_JSONSiblingsSurviveVerbatim pins the W4a fix to the stdio
// writer: sibling servers under mcpServers are kept as RAW JSON, so a user's
// remote server (url/type/headers) or env-bearing stdio server survives
// Register AND Unregister with every field intact. Before the fix the whole
// map was decoded into mcpServerEntry{Command,Args} and re-encoded, turning
// `{"url":…}` into `{"command":"","args":null}`.
func TestRegistrar_JSONSiblingsSurviveVerbatim(t *testing.T) {
	r, home := newRegistrar(t, false)
	path := filepath.Join(home, ".claude.json")
	prior := `{
  "mcpServers": {
    "remote-sib": {"type": "http", "url": "https://x.example/mcp", "headers": {"X-A": "1"}},
    "env-sib": {"command": "/opt/x", "args": ["a"], "env": {"K": "v"}, "disabled": true}
  }
}`
	if err := os.WriteFile(path, []byte(prior), 0o644); err != nil {
		t.Fatal(err)
	}
	var priorTop struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(prior), &priorTop); err != nil {
		t.Fatal(err)
	}
	check := func(stage string) {
		t.Helper()
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: read: %v", stage, err)
		}
		var top struct {
			MCPServers map[string]json.RawMessage `json:"mcpServers"`
		}
		if err := json.Unmarshal(body, &top); err != nil {
			t.Fatalf("%s: parse: %v", stage, err)
		}
		for name, want := range priorTop.MCPServers {
			if !jsonEquivalent(top.MCPServers[name], want) {
				t.Errorf("%s: sibling %s changed: %s -> %s", stage, name, want, top.MCPServers[name])
			}
		}
	}
	if res := r.Register("claude-code"); res.Error != nil || !res.Added {
		t.Fatalf("Register: %+v", res)
	}
	check("after register")
	if res := r.Register("claude-code"); res.Error != nil || !res.AlreadySet {
		t.Fatalf("re-register: %+v", res)
	}
	if ures := r.Unregister("claude-code"); ures.Error != nil || !ures.Removed {
		t.Fatalf("Unregister: %+v", ures)
	}
	check("after unregister")
}
