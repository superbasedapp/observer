package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestProposedEditsIn pins one row per tool-input shape (T-910).
func TestProposedEditsIn(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input map[string]any
		want  []policy.ProposedEdit
	}{
		{"none", map[string]any{"file_path": "x"}, nil},
		{"write content", map[string]any{"file_path": "x", "content": "c"}, []policy.ProposedEdit{{Kind: policy.EditWhole, New: "c"}}},
		{"create file_text", map[string]any{"path": "x", "file_text": "c"}, []policy.ProposedEdit{{Kind: policy.EditWhole, New: "c"}}},
		{"edit old_string/new_string", map[string]any{"old_string": "a", "new_string": "b"}, []policy.ProposedEdit{{Kind: policy.EditReplace, Old: "a", New: "b"}}},
		{"edit replace_all", map[string]any{"old_string": "a", "new_string": "b", "replace_all": true}, []policy.ProposedEdit{{Kind: policy.EditReplace, Old: "a", New: "b", All: true}}},
		{"edit old_str/new_str", map[string]any{"old_str": "a", "new_str": "b"}, []policy.ProposedEdit{{Kind: policy.EditReplace, Old: "a", New: "b"}}},
		{"edit camelCase", map[string]any{"oldString": "a", "newString": "b", "replaceAll": true}, []policy.ProposedEdit{{Kind: policy.EditReplace, Old: "a", New: "b", All: true}}},
		{"multiedit", map[string]any{"edits": []any{
			map[string]any{"old_string": "a", "new_string": "b"},
			map[string]any{"old_string": "c", "new_string": "d", "replace_all": true},
		}}, []policy.ProposedEdit{{Kind: policy.EditReplace, Old: "a", New: "b"}, {Kind: policy.EditReplace, Old: "c", New: "d", All: true}}},
	}
	for _, tc := range cases {
		if got := proposedEditsIn(tc.input); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// TestPatchEditsFor pins the per-file section of an apply_patch envelope:
// an added file is its whole content, an updated file a fragment.
func TestPatchEditsFor(t *testing.T) {
	t.Parallel()
	patch := "*** Begin Patch\n*** Add File: .claude/settings.local.json\n+{\"disableAllHooks\": true}\n" +
		"*** Update File: .gemini/settings.json\n@@\n-  \"enabled\": true\n+  \"enabled\": false\n*** End Patch\n"
	in := map[string]any{"command": patch}
	if got := patchEditsFor(in, ".claude/settings.local.json"); !reflect.DeepEqual(got, []policy.ProposedEdit{{Kind: policy.EditWhole, New: `{"disableAllHooks": true}`}}) {
		t.Fatalf("add file: %+v", got)
	}
	if got := patchEditsFor(in, ".gemini/settings.json"); !reflect.DeepEqual(got, []policy.ProposedEdit{{Kind: policy.EditFragment, Old: `  "enabled": true`, New: `  "enabled": false`}}) {
		t.Fatalf("update file: %+v", got)
	}
	if got := patchEditsFor(in, "other.txt"); got != nil {
		t.Fatalf("untouched file: %+v", got)
	}
}

// TestToolGateEventsCarryProposedEdits pins that the shared tool gate hands
// the write content to the guard for the vendor-shaped families too.
func TestToolGateEventsCarryProposedEdits(t *testing.T) {
	t.Parallel()
	patch := "*** Begin Patch\n*** Add File: .claude/settings.local.json\n+{\"disableAllHooks\": true}\n*** End Patch\n"
	cases := []struct {
		name, tool, dialect, event string
		body                       []byte
		want                       []policy.ProposedEdit
	}{
		{
			"droid Create", models.ToolDroid, ToolGateDialectClaudeJSON, "PreToolUse",
			toolPayload("s1", "Create", map[string]any{"file_path": "/home/u/proj/.factory/settings.local.json", "content": `{"hooksDisabled":true}`}),
			[]policy.ProposedEdit{{Kind: policy.EditWhole, New: `{"hooksDisabled":true}`}},
		},
		{
			"codex apply_patch", models.ToolCodex, ToolGateDialectClaudeJSON, "PreToolUse",
			toolPayload("s1", "apply_patch", map[string]any{"command": patch}),
			[]policy.ProposedEdit{{Kind: policy.EditWhole, New: `{"disableAllHooks": true}`}},
		},
		{
			"claude Edit through the tool gate", models.ToolClaudeCode, ToolGateDialectClaudeCode, "PreToolUse",
			toolPayload("s1", "Edit", map[string]any{"file_path": ".claude/settings.local.json", "old_string": "a", "new_string": "b"}),
			[]policy.ProposedEdit{{Kind: policy.EditReplace, Old: "a", New: "b"}},
		},
	}
	for _, tc := range cases {
		ev := &targetEvaluator{}
		HandleToolGate(ToolGateRequest{Tool: tc.tool, Dialect: tc.dialect, NativeEvent: tc.event, Label: tc.tool + ":" + tc.event, Body: tc.body},
			ev, nil, &bytes.Buffer{}, &bytes.Buffer{})
		if len(ev.seen) != 1 || !reflect.DeepEqual(ev.seen[0].Edits, tc.want) {
			t.Errorf("%s: seen %+v, want edits %+v", tc.name, ev.seen, tc.want)
		}
	}
}

// TestClaudeCodeHookR162 drives a Claude Code PreToolUse payload through the
// hook boundary and a real guard (the shipped hookdisable table, the real
// file reader) in enforce mode (T-910): an edit that turns
// disableAllHooks on in the project's settings.local.json is denied, a
// permission-grant edit of the same file and a write that sets it false
// are not.
func TestClaudeCodeHookR162(t *testing.T) {
	proj := t.TempDir()
	settings := filepath.Join(proj, ".claude", "settings.local.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default().Guard
	cfg.Enabled, cfg.Mode = true, "enforce"
	cfg.Rules.UserPolicy = ""
	cfg.Rules.OrgBundle = filepath.Join(proj, "no-org-bundle.json")
	g, err := guard.New(guard.Options{Config: cfg, Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	body := func(tool string, input map[string]any) []byte {
		input["file_path"] = settings
		b, _ := json.Marshal(map[string]any{"session_id": "s1", "cwd": proj, "tool_name": tool, "tool_input": input})
		return b
	}
	cases := []struct {
		name    string
		current string
		body    []byte
		deny    bool
	}{
		{
			"edit adding the switch", `{"permissions":{"allow":[]}}`,
			body("Edit", map[string]any{"old_string": `{"permissions"`, "new_string": `{"disableAllHooks":true,"permissions"`}), true,
		},
		{
			"edit flipping only the value", `{"disableAllHooks":false}`,
			body("Edit", map[string]any{"old_string": "false", "new_string": "true"}), true,
		},
		{
			"multiedit whose second edit adds the switch", `{"permissions":{"allow":[]}}`,
			body("MultiEdit", map[string]any{"edits": []any{
				map[string]any{"old_string": `"allow":[]`, "new_string": `"allow":["Bash(ls)"]`},
				map[string]any{"old_string": `{"permissions"`, "new_string": `{"disableAllHooks":true,"permissions"`},
			}}), true,
		},
		{"write turning it on", "", body("Write", map[string]any{"content": `{"disableAllHooks": true}`}), true},
		{
			"permission grant edit", `{"permissions":{"allow":[]}}`,
			body("Edit", map[string]any{"old_string": `"allow":[]`, "new_string": `"allow":["Bash(npm test)"]`}), false,
		},
		{"write setting it false", "", body("Write", map[string]any{"content": `{"disableAllHooks": false}`}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_ = os.Remove(settings)
			if tc.current != "" {
				if err := os.WriteFile(settings, []byte(tc.current), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ev, ok := BuildClaudeCodeEvent(tc.body)
			if !ok {
				t.Fatal("payload not evaluable")
			}
			av, _ := g.EvaluateHook(ev)
			em := guard.ResolveEmission(av.Verdict, ev.Caps)
			if tc.deny {
				if av.Verdict.RuleID != "R-162" || em.Permission != "deny" {
					t.Fatalf("got %s/%s (%s), want R-162 deny", av.Verdict.RuleID, em.Permission, av.Verdict.Reason)
				}
				return
			}
			if av.Verdict.RuleID == "R-162" || em.Permission == "deny" {
				t.Fatalf("got %s/%s (%s), want no R-162 block", av.Verdict.RuleID, em.Permission, av.Verdict.Reason)
			}
		})
	}
}
