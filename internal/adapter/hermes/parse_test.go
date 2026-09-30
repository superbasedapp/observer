package hermes

import (
	"database/sql"
	"testing"
)

// TestExtractTarget covers the per-tool argument-key extraction. Each
// row keys off a tool name normalizeToolName understands and the
// argument-shape variants the §17.1 reality check captured live in
// the corpus (path / command / pattern / urls / query).
func TestExtractTarget(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		toolName string
		args     string
		want     string
	}{
		// Live shapes from testdata/hermes/reality-check.txt:
		{"read_file_path", "read_file", `{"path":"/etc/hostname"}`, "/etc/hostname"},
		{"write_file_path", "write_file", `{"path":"/tmp/x.txt","content":"hello"}`, "/tmp/x.txt"},
		{"patch_path", "patch", `{"path":"/tmp/x.py","old_string":"a","new_string":"b"}`, "/tmp/x.py"},
		{"terminal_command", "terminal", `{"command":"ls -la /tmp"}`, "ls -la /tmp"},
		{"search_files_pattern", "search_files", `{"pattern":"*.py","target":"files","path":"/etc"}`, "*.py"},
		{"web_search_query", "web_search", `{"query":"go pure-sqlite library","limit":10}`, "go pure-sqlite library"},
		{"web_extract_urls_array", "web_extract", `{"urls":["https://example.com"]}`, "https://example.com"},

		// Synthetic per-plan shapes:
		{"web_extract_single_url_fallback", "web_extract", `{"url":"https://example.com/2"}`, "https://example.com/2"},
		{"delegate_task_prompt", "delegate_task", `{"task":"do the thing","context":"..."}`, "do the thing"},
		{"clarify_question", "clarify", `{"question":"which file?"}`, "which file?"},

		// Defensive: malformed JSON yields "".
		{"malformed_json", "terminal", `not json at all`, ""},
		// Defensive: empty argument string yields "".
		{"empty_args", "terminal", ``, ""},
		// Defensive: known tool but missing the expected key yields "".
		{"known_tool_missing_key", "read_file", `{"other":"x"}`, ""},
		// Unknown tool falls through to the best-effort key list.
		{"unknown_tool_url_key", "future_tool", `{"url":"https://example.com"}`, "https://example.com"},
		{"unknown_tool_name_key", "future_tool", `{"name":"some-resource"}`, "some-resource"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := extractTarget(tc.toolName, tc.args)
			if got != tc.want {
				t.Errorf("extractTarget(%q, %q) = %q, want %q", tc.toolName, tc.args, got, tc.want)
			}
		})
	}
}

// TestParseToolResult covers the Success / ErrorMessage / Output
// extraction from the structured JSON Hermes writes into the role='tool'
// message content column. §17.1 C documents the per-shape contract.
func TestParseToolResult(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		body        string
		wantSuccess bool
		wantErrMsg  string
		wantOutput  string
	}{
		{
			// Live: terminal success
			name:        "terminal_success",
			body:        `{"output": "Hello, World!", "exit_code": 0, "error": null}`,
			wantSuccess: true,
			wantOutput:  "Hello, World!",
		},
		{
			// Live: terminal failure via non-zero exit_code
			name:        "terminal_non_zero_exit_code",
			body:        `{"output": "sudo: A terminal is required to authenticate", "exit_code": 1, "error": null}`,
			wantSuccess: false,
			wantOutput:  "sudo: A terminal is required to authenticate",
		},
		{
			// Synthetic: explicit error string wins over exit_code=0
			name:        "error_string_present",
			body:        `{"output": "", "exit_code": 0, "error": "permission denied"}`,
			wantSuccess: false,
			wantErrMsg:  "permission denied",
			wantOutput:  "",
		},
		{
			// Live: write_file success — no output/content key; output
			// falls back to whole-body JSON for dashboard surface.
			name:        "write_file_success",
			body:        `{"bytes_written":128,"dirs_created":true,"resolved_path":"/tmp/x.py","files_modified":["/tmp/x.py"]}`,
			wantSuccess: true,
			wantOutput:  `{"bytes_written":128,"dirs_created":true,"resolved_path":"/tmp/x.py","files_modified":["/tmp/x.py"]}`,
		},
		{
			// Synthetic: read_file content key
			name:        "read_file_content_key",
			body:        `{"content":"hello\nworld","lines":2}`,
			wantSuccess: true,
			wantOutput:  "hello\nworld",
		},
		{
			// Synthetic: applied=false signals patch failure
			name:        "patch_failed_applied_false",
			body:        `{"applied":false,"output":"hunk failed to apply"}`,
			wantSuccess: false,
			wantOutput:  "hunk failed to apply",
		},
		{
			// Defensive: empty body
			name:        "empty_body",
			body:        ``,
			wantSuccess: true,
			wantOutput:  "",
		},
		{
			// Defensive: non-JSON body — treat as opaque output
			name:        "non_json_plain_text",
			body:        `just a plain string`,
			wantSuccess: true,
			wantOutput:  `just a plain string`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			success, errMsg, output := parseToolResult(tc.body)
			if success != tc.wantSuccess {
				t.Errorf("parseToolResult(%q) success = %v, want %v", tc.body, success, tc.wantSuccess)
			}
			if errMsg != tc.wantErrMsg {
				t.Errorf("parseToolResult(%q) errMsg = %q, want %q", tc.body, errMsg, tc.wantErrMsg)
			}
			if output != tc.wantOutput {
				t.Errorf("parseToolResult(%q) output = %q, want %q", tc.body, output, tc.wantOutput)
			}
		})
	}
}

// TestNormalizeProjectRoot pins the cross-OS path translation applied
// to sessions.cwd. Pre-audit-2026-06-05 the column was emitted
// verbatim, so a Hermes session captured on the Windows host while
// observer ran in WSL2 lit up the wrong project bucket. The fix
// routes through crossmount.TranslateForeignPath so Windows-shape
// paths canonicalise to /mnt/c/... before they reach the project-
// root resolver.
//
// We don't pin the EXACT translated form (crossmount has its own
// platform-specific behaviour) — only that the result is non-empty
// when the input is non-empty and equals the input on already-
// native paths.
func TestNormalizeProjectRoot(t *testing.T) {
	t.Parallel()
	// Empty in -> empty out.
	if got := normalizeProjectRoot(""); got != "" {
		t.Errorf("normalizeProjectRoot(\"\") = %q, want \"\"", got)
	}
	// Linux-native path is a no-op (no translation needed).
	if got := normalizeProjectRoot("/home/dev/proj"); got != "/home/dev/proj" {
		t.Errorf("normalizeProjectRoot linux-native = %q, want unchanged", got)
	}
	// Windows-shape path produces non-empty output. The exact form
	// depends on whether the test host is WSL2 (translates to
	// /mnt/c/...) or Windows-native (passes through). Both branches
	// satisfy the contract: don't drop the path.
	if got := normalizeProjectRoot(`C:\Users\dev\proj`); got == "" {
		t.Error("normalizeProjectRoot dropped a non-empty Windows path")
	}
}

// TestParseToolCalls round-trips the wrapper JSON shape Hermes emits
// in messages.tool_calls. Asserts we tolerate the extras (call_id,
// response_item_id, type) and pull out only id + function.name +
// function.arguments.
func TestParseToolCalls(t *testing.T) {
	t.Parallel()
	raw := `[
		{"id":"call_abc",
		 "call_id":"call_abc",
		 "response_item_id":"fc_abc",
		 "type":"function",
		 "function":{"name":"terminal","arguments":"{\"command\":\"ls\"}"}}]`
	calls, err := parseToolCalls(raw)
	if err != nil {
		t.Fatalf("parseToolCalls: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("len(calls) = %d, want 1", len(calls))
	}
	if calls[0].ID != "call_abc" {
		t.Errorf("calls[0].ID = %q, want %q", calls[0].ID, "call_abc")
	}
	if calls[0].Function.Name != "terminal" {
		t.Errorf("calls[0].Function.Name = %q, want %q", calls[0].Function.Name, "terminal")
	}
	if calls[0].Function.Arguments != `{"command":"ls"}` {
		t.Errorf("calls[0].Function.Arguments = %q, want %q", calls[0].Function.Arguments, `{"command":"ls"}`)
	}

	// Empty input → no calls, no error.
	calls, err = parseToolCalls("")
	if err != nil || len(calls) != 0 {
		t.Errorf("parseToolCalls(\"\") = (%v, %v), want ([], nil)", calls, err)
	}

	// Malformed JSON returns an error.
	if _, err := parseToolCalls("not json"); err == nil {
		t.Error("parseToolCalls(\"not json\") returned nil error, want non-nil")
	}
}

// TestSessionTokenEventCost pins that Hermes' own per-session cost is
// propagated (actual preferred over estimated), not discarded — mirroring
// the kilo adapter. Zero/absent leaves cost to the engine.
func TestSessionTokenEventCost(t *testing.T) {
	tests := []struct {
		name string
		est  sql.NullFloat64
		act  sql.NullFloat64
		want float64
	}{
		{"actual preferred", sql.NullFloat64{Float64: 0.5, Valid: true}, sql.NullFloat64{Float64: 0.42, Valid: true}, 0.42},
		{"estimate fallback", sql.NullFloat64{Float64: 0.5, Valid: true}, sql.NullFloat64{}, 0.5},
		{"neither -> zero", sql.NullFloat64{}, sql.NullFloat64{}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sess := sessionRow{ID: "s1", Model: "x", InputTokens: 10, EstimatedCostUSD: tc.est, ActualCostUSD: tc.act}
			ev := sessionTokenEvent(sess, "f")
			if ev.EstimatedCostUSD != tc.want {
				t.Errorf("EstimatedCostUSD = %v, want %v", ev.EstimatedCostUSD, tc.want)
			}
			// The SQLite (session-cumulative) path has no per-call
			// duration to attribute to a single generation, so it must
			// never stamp gen-timing fields.
			if ev.GenMs != 0 || ev.GenBasis != "" || ev.GenTimingV != 0 {
				t.Errorf("GenMs/GenBasis/GenTimingV = %d/%q/%d, want zero (SQLite path never stamps)", ev.GenMs, ev.GenBasis, ev.GenTimingV)
			}
		})
	}
}
