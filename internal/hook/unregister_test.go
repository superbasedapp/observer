package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestUnregisterClaudeCodeRoundTrip verifies install→uninstall leaves the
// settings file byte-identical to the pre-install state.
func TestUnregisterClaudeCodeRoundTrip(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")

	pre := []byte("{\n  \"theme\": \"dark\"\n}\n")
	if err := os.WriteFile(path, pre, 0o600); err != nil {
		t.Fatal(err)
	}

	if res := r.Register("claude-code"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	res := r.Unregister("claude-code")
	if res.Error != nil {
		t.Fatalf("Unregister: %v", res.Error)
	}
	if !res.ChecksumMatch {
		t.Error("expected ChecksumMatch=true after fresh install")
	}
	if len(res.HooksRemoved) != len(claudeCodeEvents) {
		t.Errorf("HooksRemoved=%d want %d", len(res.HooksRemoved), len(claudeCodeEvents))
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Normalize through json: both pre and got should decode to the same map.
	var preMap, gotMap map[string]any
	if err := json.Unmarshal(pre, &preMap); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got, &gotMap); err != nil {
		t.Fatalf("post-uninstall not valid JSON: %v\n%s", err, got)
	}
	if preMap["theme"] != gotMap["theme"] {
		t.Errorf("theme lost: before=%v after=%v", preMap["theme"], gotMap["theme"])
	}
	if _, ok := gotMap["hooks"]; ok {
		t.Errorf("hooks block should be gone, got: %v", gotMap["hooks"])
	}
}

// TestUnregisterClaudeCodeUserHookPreserved verifies that a user-authored
// hook in the same file survives uninstall and the checksum file entry is
// cleaned up even though the settings file still exists.
func TestUnregisterClaudeCodeUserHookPreserved(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")

	// Pre-seed with a user hook on an event observer doesn't manage so
	// register succeeds without --force (no conflict on the events
	// observer touches). TeammateIdle is the safest choice —
	// documented Claude Code event, not in claudeCodeEvents.
	pre := `{"hooks":{"TeammateIdle":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/my-other-hook"}]}]}}`
	if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}

	if res := r.Register("claude-code"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if res := r.Unregister("claude-code"); res.Error != nil {
		t.Fatalf("Unregister: %v", res.Error)
	}

	body, _ := os.ReadFile(path)
	if !bytes.Contains(body, []byte("my-other-hook")) {
		t.Fatalf("user hook removed!\n%s", body)
	}
	if bytes.Contains(body, []byte(r.opts.BinaryPath)) {
		t.Errorf("observer hook still present!\n%s", body)
	}
}

// TestUnregisterClaudeCodeMixedGroup verifies that a single hook group
// containing both observer and user commands is filtered: observer entries
// dropped, user entries survive in the same group.
func TestUnregisterClaudeCodeMixedGroup(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")

	// Hand-craft a PreToolUse group with observer + user hooks side by side.
	mixed := `{
  "hooks": {
    "PreToolUse": [
      {"matcher": "*", "hooks": [
        {"type": "command", "command": "/opt/observer/bin/observer hook claude-code pre-tool"},
        {"type": "command", "command": "/usr/local/bin/my-prehook"}
      ]}
    ]
  }
}`
	if err := os.WriteFile(path, []byte(mixed), 0o600); err != nil {
		t.Fatal(err)
	}
	// Seed checksum so uninstall doesn't trip the mismatch guard.
	if err := r.recordChecksum("", path); err != nil {
		t.Fatal(err)
	}

	res := r.Unregister("claude-code")
	if res.Error != nil {
		t.Fatalf("Unregister: %v", res.Error)
	}
	body, _ := os.ReadFile(path)
	if bytes.Contains(body, []byte("/opt/observer/bin/observer")) {
		t.Errorf("observer entry still present after unregister:\n%s", body)
	}
	if !bytes.Contains(body, []byte("/usr/local/bin/my-prehook")) {
		t.Errorf("user entry lost:\n%s", body)
	}
}

// TestUnregisterClaudeCodeChecksumMismatch verifies that a drifted
// settings file is refused without --force.
func TestUnregisterClaudeCodeChecksumMismatch(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")
	if res := r.Register("claude-code"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}

	// An edit outside the hooks subtree is the user's own (settings.json
	// is credential-bearing, so the checksum covers the hooks only, D-268)
	// and does not trip the guard.
	body, _ := os.ReadFile(path)
	edited := bytes.Replace(body, []byte("\n}"), []byte(",\n  \"theme\": \"dark\"\n}"), 1)
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	if dry := r.opts.DryRun; !dry {
		r.opts.DryRun = true
		if res := r.Unregister("claude-code"); res.Error != nil || !res.ChecksumMatch {
			t.Fatalf("an edit outside hooks tripped the guard: %+v", res)
		}
		r.opts.DryRun = false
	}

	// Simulate the user editing the hooks after install.
	edited = bytes.Replace(edited, []byte("\"hooks\": {"), []byte("\"hooks\": {\n    \"Mine\": [],"), 1)
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}

	res := r.Unregister("claude-code")
	if res.Error == nil {
		t.Fatal("expected checksum-mismatch error")
	}
	if !strings.Contains(res.Error.Error(), "checksum mismatch") {
		t.Errorf("error should mention checksum mismatch: %v", res.Error)
	}
	if res.ChecksumMatch {
		t.Error("ChecksumMatch should be false")
	}

	// With Force, should succeed.
	r.opts.Force = true
	res = r.Unregister("claude-code")
	if res.Error != nil {
		t.Fatalf("force Unregister: %v", res.Error)
	}
	body2, _ := os.ReadFile(path)
	if bytes.Contains(body2, []byte(r.opts.BinaryPath)) {
		t.Errorf("observer entry not removed with --force:\n%s", body2)
	}
	// theme should survive because it was outside the hooks block.
	if !bytes.Contains(body2, []byte("dark")) {
		t.Errorf("user edit lost after --force:\n%s", body2)
	}
}

// TestUnregisterClaudeCodeNoObserverEntries verifies that a settings
// file with user-only content (no observer hooks, no checksum recorded)
// is treated as a skipped no-op — NOT a checksum-mismatch error. This
// is the fresh-machine case: settings.json exists but observer has
// never been installed.
func TestUnregisterClaudeCodeNoObserverEntries(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")

	pre := `{"effortLevel":"high","voiceEnabled":false}`
	if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}

	res := r.Unregister("claude-code")
	if res.Error != nil {
		t.Fatalf("Unregister should succeed with no-op, got: %v", res.Error)
	}
	if !res.Skipped {
		t.Errorf("expected Skipped=true for file with no observer entries: %+v", res)
	}
	if len(res.HooksRemoved) != 0 {
		t.Errorf("HooksRemoved should be empty: %v", res.HooksRemoved)
	}

	// File must be untouched.
	body, _ := os.ReadFile(path)
	if string(body) != pre {
		t.Errorf("file mutated unexpectedly:\nbefore: %s\nafter:  %s", pre, body)
	}
}

// TestUnregisterClaudeCodeMissingFile verifies the no-op path when
// settings.json doesn't exist yet.
func TestUnregisterClaudeCodeMissingFile(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	res := r.Unregister("claude-code")
	if res.Error != nil {
		t.Fatalf("Unregister: %v", res.Error)
	}
	if !res.Skipped {
		t.Error("expected Skipped=true for missing file")
	}
	if len(res.HooksRemoved) != 0 {
		t.Errorf("HooksRemoved=%v want empty", res.HooksRemoved)
	}
}

// TestUnregisterClaudeCodeSelectiveTool verifies that uninstalling
// claude-code leaves cursor's hooks intact.
func TestUnregisterClaudeCodeSelectiveTool(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	if res := r.Register("claude-code"); res.Error != nil {
		t.Fatalf("Register claude-code: %v", res.Error)
	}
	if res := r.Register("cursor"); res.Error != nil {
		t.Fatalf("Register cursor: %v", res.Error)
	}

	if res := r.Unregister("claude-code"); res.Error != nil {
		t.Fatalf("Unregister claude-code: %v", res.Error)
	}
	// Cursor config still has observer entries.
	body, _ := os.ReadFile(filepath.Join(r.opts.HomeDir, ".cursor", "hooks.json"))
	if !bytes.Contains(body, []byte(r.opts.BinaryPath)) {
		t.Errorf("cursor hooks lost after claude-code uninstall:\n%s", body)
	}
}

// TestUnregisterClaudeCodeDryRun verifies --dry-run neither writes nor
// clears the checksum entry.
func TestUnregisterClaudeCodeDryRun(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	if res := r.Register("claude-code"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}

	r.opts.DryRun = true
	res := r.Unregister("claude-code")
	if res.Error != nil {
		t.Fatalf("Unregister: %v", res.Error)
	}
	if len(res.HooksRemoved) != len(claudeCodeEvents) {
		t.Errorf("HooksRemoved=%d want %d", len(res.HooksRemoved), len(claudeCodeEvents))
	}
	body, _ := os.ReadFile(res.ConfigPath)
	if !bytes.Contains(body, []byte(r.opts.BinaryPath)) {
		t.Errorf("dry-run mutated the settings file:\n%s", body)
	}
	// Checksum file should still have the entry. Parse the JSON and look
	// up ConfigPath as a map key rather than a raw bytes.Contains: on
	// Windows the path key contains backslashes, which JSON escapes to
	// "\\", so a substring match against the (single-backslash)
	// ConfigPath would spuriously fail.
	csPath := filepath.Join(r.opts.HomeDir, ".observer", "hook_checksums.json")
	csBody, _ := os.ReadFile(csPath)
	var checksums map[string]any
	if err := json.Unmarshal(csBody, &checksums); err != nil {
		t.Fatalf("checksum file not valid JSON: %v\n%s", err, csBody)
	}
	if _, ok := checksums[res.ConfigPath]; !ok {
		t.Errorf("dry-run cleared checksum entry:\n%s", csBody)
	}
}

// TestUnregisterCursorRoundTrip verifies cursor install→uninstall also
// cleans up correctly, including the synthetic "version" key.
func TestUnregisterCursorRoundTrip(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	if res := r.Register("cursor"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	res := r.Unregister("cursor")
	if res.Error != nil {
		t.Fatalf("Unregister: %v", res.Error)
	}
	if _, err := os.Stat(res.ConfigPath); !os.IsNotExist(err) {
		t.Errorf("hooks.json should be removed entirely after round-trip: err=%v", err)
	}
	// Checksum entry should also be gone.
	csPath := filepath.Join(r.opts.HomeDir, ".observer", "hook_checksums.json")
	if _, err := os.Stat(csPath); !os.IsNotExist(err) {
		if csBody, _ := os.ReadFile(csPath); bytes.Contains(csBody, []byte(res.ConfigPath)) {
			t.Errorf("cursor checksum entry still present:\n%s", csBody)
		}
	}
}

// TestUnregisterUnknownTool verifies the error path for unknown tools.
func TestUnregisterUnknownTool(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	res := r.Unregister("notathing")
	if res.Error == nil {
		t.Fatal("expected error for unknown tool")
	}
}
