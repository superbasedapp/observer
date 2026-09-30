package hook

import "testing"

// One case per signature row, plus genuine Claude Code payloads and
// undecodable input. Payload shapes are anonymized from cursor-agent's
// hook request (executeHookForStep: the step payload plus session_id,
// hook_event_name, cursor_version, workspace_roots, user_email,
// transcript_path) and from Claude Code's documented hook envelope.
func TestForeignClaudeHookHost(t *testing.T) {
	for _, tc := range []struct {
		name     string
		body     string
		wantHost string
		wantOK   bool
	}{
		{
			"cursor_prompt_with_version",
			`{"conversation_id":"c0c0c001-0000-4000-8000-000000000001","generation_id":"g1","prompt":"hi","session_id":"c0c0c001-0000-4000-8000-000000000001","hook_event_name":"beforeSubmitPrompt","cursor_version":"2026.09.18-9a7762b","workspace_roots":["/home/dev/repo"],"user_email":null,"transcript_path":null}`,
			"cursor", true,
		},
		{
			"cursor_step_name_without_version",
			`{"conversation_id":"c1","session_id":"c1","hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{"command":"ls"}}`,
			"cursor", true,
		},
		{
			"cursor_version_empty_string_still_cursor",
			`{"session_id":"c2","hook_event_name":"sessionEnd","cursor_version":""}`,
			"cursor", true,
		},
		{
			"claude_code_pre_tool",
			`{"session_id":"s1","transcript_path":"/home/dev/.claude/projects/x/s1.jsonl","cwd":"/home/dev/repo","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`,
			"", false,
		},
		{
			"claude_code_prompt",
			`{"session_id":"s1","cwd":"/r","hook_event_name":"UserPromptSubmit","prompt":"hi"}`,
			"", false,
		},
		{"claude_code_stop_pascal_case", `{"session_id":"s1","cwd":"/r","hook_event_name":"Stop"}`, "", false},
		{"undecodable", `{"session_id":`, "", false},
		{"empty", ``, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, ok := ForeignClaudeHookHost([]byte(tc.body))
			if host != tc.wantHost || ok != tc.wantOK {
				t.Fatalf("ForeignClaudeHookHost = %q,%v want %q,%v", host, ok, tc.wantHost, tc.wantOK)
			}
		})
	}
}
