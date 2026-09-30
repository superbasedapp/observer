package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// oversizedWritePayload builds a Claude Code PreToolUse Write payload whose
// content pushes the body past promptSubmitBodyLimit.
func oversizedWritePayload(t *testing.T, target string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"session_id": "s1",
		"cwd":        "/tmp",
		"tool_name":  "Write",
		"tool_input": map[string]any{
			"file_path": target,
			"content":   strings.Repeat("A", promptSubmitBodyLimit+1024),
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// writeGuardConfig writes a config.toml enabling the guard in mode.
func writeGuardConfig(t *testing.T, mode string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := "[guard]\nenabled = true\nmode = \"" + mode + "\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestHandleClaudeCodePreToolTruncatedFailsClosedWhenEnforcing is the SR27-D2
// regression (security review 2026-09-27). The pre-tool body used to be read
// with a SILENT 2 MiB cap: a Write/Edit whose content pushed the payload past
// it arrived as truncated JSON, failed to parse, and was approved without
// evaluation - even with the guard in enforce mode and a deny rule covering
// the target (~/.bashrc, ~/.claude/settings.json, ~/.observer/**). A body the
// hook could not read in full must now be held for the human (ask) while the
// guard enforces, and keep the plain approve when it does not.
func TestHandleClaudeCodePreToolTruncatedFailsClosedWhenEnforcing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	payload := oversizedWritePayload(t, "/home/u/.bashrc")

	t.Run("enforce", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		handleClaudeCodePreTool(strings.NewReader(payload), &stdout, &stderr, "claude-code:pre-tool", writeGuardConfig(t, "enforce"))
		var reply struct {
			Decision           string `json:"decision"`
			HookSpecificOutput struct {
				PermissionDecision string `json:"permissionDecision"`
			} `json:"hookSpecificOutput"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &reply); err != nil {
			t.Fatalf("reply not one JSON object: %v - %q", err, stdout.String())
		}
		if reply.Decision == "approve" || reply.HookSpecificOutput.PermissionDecision != "ask" {
			t.Fatalf("truncated payload under enforce: decision=%q permission=%q, want a held (ask) call", reply.Decision, reply.HookSpecificOutput.PermissionDecision)
		}
	})

	t.Run("observe keeps approve", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		handleClaudeCodePreTool(strings.NewReader(payload), &stdout, &stderr, "claude-code:pre-tool", writeGuardConfig(t, "observe"))
		var reply preToolReply
		if err := json.Unmarshal(stdout.Bytes(), &reply); err != nil {
			t.Fatalf("reply not JSON: %v", err)
		}
		if reply.Decision != "approve" {
			t.Fatalf("observe-mode decision = %q, want approve (no new blocking outside enforce)", reply.Decision)
		}
	})
}
