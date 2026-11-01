package vtcode

import (
	"encoding/json"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestMapVTCodeTool(t *testing.T) {
	tests := []struct{ name, want string }{
		{"exec_command", models.ActionRunCommand},
		{"EXEC-COMMAND", models.ActionRunCommand},
		{"write_stdin", models.ActionStdinWrite},
		{"apply_patch", models.ActionEditFile},
		{"code_search", models.ActionSearchText},
		{"search_tools", models.ActionToolSearch},
		{"web_fetch", models.ActionWebFetch},
		{"web_search", models.ActionWebSearch},
		{"request_user_input", models.ActionAskUser},
		{"task_tracker", models.ActionTodoUpdate},
		{"start_planning", models.ActionPermissionMode},
		{"load_skill", models.ActionSkillInvoke},
		{"load_skill_resource", models.ActionSkillInvoke},
		{"list_skills", models.ActionHarnessCall},
		{"record_decision", models.ActionHarnessCall},
		{"memory", models.ActionHarnessCall},
		{"mcp", models.ActionMCPCall},
		{"unified_file", models.ActionUnknown}, // removed legacy schema name
		{"", models.ActionUnknown},
	}
	for _, tc := range tests {
		if got := mapVTCodeTool(tc.name); got != tc.want {
			t.Errorf("mapVTCodeTool(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestToolTarget(t *testing.T) {
	patch := "*** Begin Patch\n*** Update File: src/main.rs\n@@\n-old\n+new line\n+second\n*** End Patch"
	patchObj, _ := json.Marshal(map[string]string{"input": patch})
	patchStr, _ := json.Marshal(patch)
	tests := []struct {
		name, tool, args, want string
	}{
		{"exec cmd", "exec_command", `{"cmd":"ls -la","command":"ls -la","action":"run"}`, "ls -la"},
		{"exec command only", "exec_command", `{"command":"pwd"}`, "pwd"},
		{"code_search query", "code_search", `{"query":"exec_command","path":".vtcode"}`, "exec_command"},
		{"patch object", "apply_patch", string(patchObj), "src/main.rs"},
		{"patch bare string", "apply_patch", string(patchStr), "src/main.rs"},
		{"stdin session", "write_stdin", `{"session_id":"run-1","chars":"y\n"}`, "run-1"},
		{"web fetch", "web_fetch", `{"url":"https://example.invalid/x"}`, "https://example.invalid/x"},
		{"streaming string args", "exec_command", `"{\"cmd\": \"git status\"}"`, "git status"},
		{"no args falls back to name", "record_decision", ``, "record_decision"},
		{"unknown tool generic key", "frobnicate", `{"path":"a.txt"}`, "a.txt"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := json.RawMessage(tc.args)
			if got := toolTarget(tc.tool, raw, argsMap(raw)); got != tc.want {
				t.Fatalf("toolTarget = %q, want %q", got, tc.want)
			}
		})
	}
	if n := patchAddedBytes(patch); n != int64(len("new line")+len("second")) {
		t.Errorf("patchAddedBytes = %d", n)
	}
	if patchAddedBytes("+++ b/x\n") != 0 {
		t.Error("a +++ header must not count as authored content")
	}
}

func TestArgsMapPhantom(t *testing.T) {
	for _, raw := range []string{``, `null`, `"not json"`} {
		if argsMap(json.RawMessage(raw)) != nil {
			t.Errorf("argsMap(%q) != nil", raw)
		}
	}
}
