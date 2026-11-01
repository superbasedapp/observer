package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The Claude Code status line and the Claude Code hooks share one file,
// ~/.claude/settings.json, but not one owner. The file's
// hook_checksums.json entry is the HOOK writer's: for this
// credential-bearing file it is a digest of the "hooks" subtree only
// (D-268), which the status line never writes. The status line owns the
// "statusLine" member alone and reads ownership from the command itself
// (isObserverStatuslineEntry), the same rule the --statusline-tools
// writer follows. These tests pin that split: neither writer may record,
// re-baseline or remove state that belongs to the other.

// slChecksums reads the registry's hook_checksums.json ("" when absent).
func slChecksums(t *testing.T, r *Registry) string {
	t.Helper()
	b, err := os.ReadFile(r.opts.ChecksumsPath)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestClaudeStatuslineUnregisterKeepsHookChecksum: hooks + status line
// registered, status line removed, then the hook uninstall must still see
// its own install-time checksum and run without --force.
func TestClaudeStatuslineUnregisterKeepsHookChecksum(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	if res := r.Register("claude-code"); res.Error != nil {
		t.Fatalf("Register(claude-code): %v", res.Error)
	}
	hookEntry := slChecksums(t, r)
	if hookEntry == "" {
		t.Fatal("hook register recorded no checksum entry")
	}

	if res := r.RegisterClaudeCodeStatusline(); res.Error != nil {
		t.Fatalf("RegisterClaudeCodeStatusline: %v", res.Error)
	}
	if got := slChecksums(t, r); got != hookEntry {
		t.Errorf("status line register rewrote the hook's checksum entry:\nbefore %s\nafter  %s", hookEntry, got)
	}
	if res := r.UnregisterClaudeCodeStatusline(); res.Error != nil || len(res.HooksRemoved) != 1 {
		t.Fatalf("UnregisterClaudeCodeStatusline = %+v", res)
	}
	if got := slChecksums(t, r); got != hookEntry {
		t.Errorf("status line unregister changed the hook's checksum entry:\nbefore %s\nafter  %s", hookEntry, got)
	}

	un := r.Unregister("claude-code")
	if un.Error != nil {
		t.Fatalf("hook unregister after the status line uninstall: %v", un.Error)
	}
	if !un.ChecksumMatch || len(un.HooksRemoved) == 0 {
		t.Errorf("hook unregister = %+v, want a checksum match and hooks removed", un)
	}
}

// TestClaudeHookUnregisterThenStatuslineUnregister is the reverse order:
// the hook uninstall removes its own entry, and the status line uninstall
// that follows must not depend on that entry.
func TestClaudeHookUnregisterThenStatuslineUnregister(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	if res := r.RegisterClaudeCodeStatusline(); res.Error != nil {
		t.Fatalf("RegisterClaudeCodeStatusline: %v", res.Error)
	}
	if res := r.Register("claude-code"); res.Error != nil {
		t.Fatalf("Register(claude-code): %v", res.Error)
	}
	if un := r.Unregister("claude-code"); un.Error != nil {
		t.Fatalf("hook unregister: %v", un.Error)
	}
	res := r.UnregisterClaudeCodeStatusline()
	if res.Error != nil {
		t.Fatalf("status line unregister after the hook uninstall: %v", res.Error)
	}
	if len(res.HooksRemoved) != 1 || res.HooksRemoved[0] != "statusLine" {
		t.Errorf("HooksRemoved=%v want [statusLine]", res.HooksRemoved)
	}
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("settings.json held only Observer's keys and should be gone, stat err=%v", err)
	}
}

// TestClaudeStatuslineRegisterKeepsHookDriftVisible: a hand edit to the
// hooks after the hook install is drift the hook uninstall must refuse
// without --force. Registering the status line in between must not
// re-baseline the hook's checksum and so hide that edit.
func TestClaudeStatuslineRegisterKeepsHookDriftVisible(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	if res := r.Register("claude-code"); res.Error != nil {
		t.Fatalf("Register(claude-code): %v", res.Error)
	}
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(body, &settings); err != nil {
		t.Fatal(err)
	}
	var hooks map[string]json.RawMessage
	if err := json.Unmarshal(settings["hooks"], &hooks); err != nil {
		t.Fatal(err)
	}
	hooks["Elicitation"] = json.RawMessage(`[{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/mine"}]}]`)
	settings["hooks"], _ = json.Marshal(hooks)
	edited, _ := json.Marshal(settings)
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}

	if res := r.RegisterClaudeCodeStatusline(); res.Error != nil {
		t.Fatalf("RegisterClaudeCodeStatusline: %v", res.Error)
	}

	un := r.Unregister("claude-code")
	if un.Error == nil {
		t.Fatal("hook unregister ran over a hand-edited hooks block without --force: the status line register re-baselined the hook's checksum")
	}
	if un.ChecksumMatch {
		t.Error("ChecksumMatch=true for a hooks block edited after install")
	}
}
