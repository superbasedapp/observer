package cline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// TestXMLToolTagsTable is the ONE-ROW-PER-TAG pin for the pseudo-tool
// table: every tag extracts, classifies, and targets as declared.
// Cline's legacy bundle emits these inside assistant text blocks, so a
// missing row means the call is silently swallowed into prose.
func TestXMLToolTagsTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		text       string
		wantRaw    string
		wantAction string
		wantTarget string
	}{
		{
			name:       "read_file",
			text:       "<read_file>\n<path>src/main.go</path>\n</read_file>",
			wantRaw:    "read_file",
			wantAction: models.ActionReadFile,
			wantTarget: "src/main.go",
		},
		{
			name:       "write_to_file",
			text:       "<write_to_file>\n<path>src/new.go</path>\n<content>package x</content>\n</write_to_file>",
			wantRaw:    "write_to_file",
			wantAction: models.ActionWriteFile,
			wantTarget: "src/new.go",
		},
		{
			name:       "replace_in_file",
			text:       "<replace_in_file>\n<path>src/main.go</path>\n<diff>---</diff>\n</replace_in_file>",
			wantRaw:    "replace_in_file",
			wantAction: models.ActionEditFile,
			wantTarget: "src/main.go",
		},
		{
			name:       "execute_command",
			text:       "<execute_command>\n<command>go test ./...</command>\n<requires_approval>false</requires_approval>\n</execute_command>",
			wantRaw:    "execute_command",
			wantAction: models.ActionRunCommand,
			wantTarget: "go test ./...",
		},
		{
			name:       "search_files",
			text:       "<search_files>\n<path>.</path>\n<regex>func Test</regex>\n</search_files>",
			wantRaw:    "search_files",
			wantAction: models.ActionSearchText,
			wantTarget: "func Test",
		},
		{
			name:       "list_files",
			text:       "<list_files>\n<path>internal</path>\n<recursive>true</recursive>\n</list_files>",
			wantRaw:    "list_files",
			wantAction: models.ActionSearchFiles,
			wantTarget: "internal",
		},
		{
			// Deliberate gap: no actionMap / tooltax row exists for
			// this real tag, so it lands as `unknown` rather than
			// staying invisible inside prose.
			name:       "list_code_definition_names_unknown",
			text:       "<list_code_definition_names>\n<path>internal/adapter</path>\n</list_code_definition_names>",
			wantRaw:    "list_code_definition_names",
			wantAction: models.ActionUnknown,
			wantTarget: "internal/adapter",
		},
		{
			name:       "browser_action",
			text:       "<browser_action>\n<action>launch</action>\n<url>http://localhost:3000</url>\n</browser_action>",
			wantRaw:    "browser_action",
			wantAction: models.ActionBrowserAction,
			wantTarget: "launch",
		},
		{
			name:       "use_mcp_tool_prefixes_server",
			text:       "<use_mcp_tool>\n<server_name>weather</server_name>\n<tool_name>get_forecast</tool_name>\n<arguments>{}</arguments>\n</use_mcp_tool>",
			wantRaw:    "use_mcp_tool",
			wantAction: models.ActionMCPCall,
			wantTarget: "weather:get_forecast",
		},
		{
			name:       "access_mcp_resource_prefixes_server",
			text:       "<access_mcp_resource>\n<server_name>weather</server_name>\n<uri>weather://today</uri>\n</access_mcp_resource>",
			wantRaw:    "access_mcp_resource",
			wantAction: models.ActionMCPCall,
			wantTarget: "weather:weather://today",
		},
		{
			name:       "attempt_completion",
			text:       "<attempt_completion>\n<result>All tests pass.</result>\n</attempt_completion>",
			wantRaw:    "attempt_completion",
			wantAction: models.ActionTaskComplete,
			wantTarget: "All tests pass.",
		},
		{
			// The regression that motivated the whole scanner: this
			// tag name contains `sk_followup_question`, which the
			// generic API-key rule redacts. Extracting the span means
			// the scrubber only ever sees the QUESTION.
			name:       "ask_followup_question_not_redacted",
			text:       "<ask_followup_question>\n<question>Which file should I edit?</question>\n</ask_followup_question>",
			wantRaw:    "ask_followup_question",
			wantAction: models.ActionAskUser,
			wantTarget: "Which file should I edit?",
		},
		{
			name:       "new_task_unknown",
			text:       "<new_task>\n<context>Continue the refactor.</context>\n</new_task>",
			wantRaw:    "new_task",
			wantAction: models.ActionUnknown,
			wantTarget: "Continue the refactor.",
		},
		{
			name:       "plan_mode_respond_unknown",
			text:       "<plan_mode_respond>\n<response>Here is the plan.</response>\n</plan_mode_respond>",
			wantRaw:    "plan_mode_respond",
			wantAction: models.ActionUnknown,
			wantTarget: "Here is the plan.",
		},
	}

	a := NewWithOptions(scrub.New(), []string{"/x"})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls, prose := scanXMLTools(tc.text)
			if len(calls) != 1 {
				t.Fatalf("calls = %d want 1", len(calls))
			}
			if prose != "" {
				t.Errorf("prose = %q, want empty (the block was pure XML)", prose)
			}
			evt := a.xmlToolEvent("/x/tasks/t1/api_conversation_history.json",
				models.ToolCline, "t1", "", "", "", "m", nowFixture(), 3, 0, calls[0])
			if evt.RawToolName != tc.wantRaw {
				t.Errorf("raw = %q want %q", evt.RawToolName, tc.wantRaw)
			}
			if evt.ActionType != tc.wantAction {
				t.Errorf("action = %q want %q", evt.ActionType, tc.wantAction)
			}
			if evt.Target != tc.wantTarget {
				t.Errorf("target = %q want %q", evt.Target, tc.wantTarget)
			}
			if evt.SourceEventID != "3:xml:0" {
				t.Errorf("source_event_id = %q want 3:xml:0", evt.SourceEventID)
			}
			if !evt.Success {
				t.Error("success should default true (outcome is not machine-readable)")
			}
		})
	}
}

// TestScanXMLToolsPassthrough pins that an assistant message with no
// pseudo-tool markup comes back untouched — the scanner must not
// perturb the existing assistant_message path.
func TestScanXMLToolsPassthrough(t *testing.T) {
	t.Parallel()
	const body = "I'll read the middleware file first.\nIt uses <T> generics and 1 < 2."
	calls, prose := scanXMLTools(body)
	if len(calls) != 0 {
		t.Fatalf("calls = %d want 0", len(calls))
	}
	if prose != body {
		t.Errorf("prose = %q want %q", prose, body)
	}
}

// TestScanXMLToolsAnchoring is the phantom-row pin. The pre-fix
// scanner matched an opening tag ANYWHERE in the text, so three shapes
// that occur constantly in real assistant messages minted tool rows
// that never happened AND excised the prose that contained them.
// Every case here must yield ZERO calls with the prose intact, except
// the positive controls, which must still mint.
func TestScanXMLToolsAnchoring(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		text       string
		wantCalls  int
		wantTag    string
		keepInProm []string
	}{
		{
			// (a) Prose that MENTIONS a tag. Minted a run_command
			// action against everything up to the closing mention.
			name:       "prose_mention_is_not_a_call",
			text:       "The `<execute_command>` tag wraps a shell command and closes with `</execute_command>`.",
			wantCalls:  0,
			keepInProm: []string{"<execute_command>", "</execute_command>", "wraps a shell command"},
		},
		{
			// A mention that happens to open the line still is not a
			// call: the byte after the tag is a space, not a newline
			// or the first parameter.
			name:       "line_leading_mention_is_not_a_call",
			text:       "<execute_command> is how Cline asks for a shell.",
			wantCalls:  0,
			keepInProm: []string{"<execute_command> is how Cline"},
		},
		{
			// (b) A documentation fence. Minted an ActionWriteFile
			// against the example's path.
			name:       "xml_fence_is_not_a_call",
			text:       "Here is how the tool looks:\n\n```xml\n<write_to_file>\n<path>/etc/passwd</path>\n<content>x</content>\n</write_to_file>\n```\n\nThat is the shape.",
			wantCalls:  0,
			keepInProm: []string{"```xml", "<write_to_file>", "/etc/passwd", "That is the shape."},
		},
		{
			name:       "tilde_fence_is_not_a_call",
			text:       "Example:\n~~~\n<read_file>\n<path>a.go</path>\n</read_file>\n~~~\ndone",
			wantCalls:  0,
			keepInProm: []string{"<read_file>", "done"},
		},
		{
			// An unterminated fence protects the rest of the message.
			name:       "unterminated_fence_protects_to_eof",
			text:       "Example:\n```\n<read_file>\n<path>a.go</path>\n</read_file>",
			wantCalls:  0,
			keepInProm: []string{"<read_file>", "a.go"},
		},
		{
			// (c) A <thinking> span: neither scanned nor excised.
			// Cline's own reasoning stays reasoning.
			name:       "thinking_block_is_left_intact",
			text:       "<thinking>\nI could run this:\n<execute_command>\n<command>rm -rf /</command>\n</execute_command>\nbut I will not.\n</thinking>\nLet me look around instead.",
			wantCalls:  0,
			keepInProm: []string{"<thinking>", "<execute_command>", "rm -rf /", "</thinking>", "Let me look around instead."},
		},
		{
			// POSITIVE CONTROL: a real line-anchored call still mints,
			// and is still excised from the prose.
			name:      "line_anchored_call_still_mints",
			text:      "Let me open it.\n<read_file>\n<path>a.go</path>\n</read_file>",
			wantCalls: 1,
			wantTag:   "read_file",
		},
		{
			// POSITIVE CONTROL: indented opener, parameter on the
			// same line (the '<' follow-byte case).
			name:      "indented_and_inline_parameter_still_mints",
			text:      "  <read_file><path>a.go</path>\n</read_file>",
			wantCalls: 1,
			wantTag:   "read_file",
		},
		{
			// POSITIVE CONTROL: a real call AFTER a closed fence is
			// still seen — the fence state must not leak.
			name:      "call_after_closed_fence_still_mints",
			text:      "```xml\n<write_to_file>\n<path>x</path>\n</write_to_file>\n```\nNow really:\n<read_file>\n<path>a.go</path>\n</read_file>",
			wantCalls: 1,
			wantTag:   "read_file",
		},
		{
			// POSITIVE CONTROL: a real call after a closed thinking
			// span — the shape a live Cline turn actually has.
			name:      "call_after_thinking_still_mints",
			text:      "<thinking>\nI should read it.\n</thinking>\n<read_file>\n<path>a.go</path>\n</read_file>",
			wantCalls: 1,
			wantTag:   "read_file",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls, prose := scanXMLTools(tc.text)
			if len(calls) != tc.wantCalls {
				t.Fatalf("calls = %d want %d (%+v)", len(calls), tc.wantCalls, calls)
			}
			if tc.wantTag != "" && calls[0].tool.tag != tc.wantTag {
				t.Errorf("tag = %q want %q", calls[0].tool.tag, tc.wantTag)
			}
			for _, frag := range tc.keepInProm {
				if !strings.Contains(prose, frag) {
					t.Errorf("prose lost %q: %q", frag, prose)
				}
			}
			if tc.wantCalls == 0 && prose != strings.TrimSpace(tc.text) {
				t.Errorf("prose was perturbed:\n got %q\nwant %q", prose, strings.TrimSpace(tc.text))
			}
		})
	}
}

// TestXMLRawToolInputIsCapped pins the raw_tool_input ceiling. The
// scrubber does NOT truncate, so before this the whole inner XML — for
// write_to_file, the entire file body — went to the DB uncapped.
func TestXMLRawToolInputIsCapped(t *testing.T) {
	t.Parallel()
	a := NewWithOptions(scrub.New(), []string{"/x"})
	const sentinel = "SENTINEL_TAIL_OF_THE_FILE_BODY"
	huge := strings.Repeat("A", scrub.MaxRawInputBytes) + sentinel

	t.Run("write_to_file_stores_path_not_body", func(t *testing.T) {
		text := "<write_to_file>\n<path>src/new.go</path>\n<content>" + huge + "</content>\n</write_to_file>"
		calls, _ := scanXMLTools(text)
		if len(calls) != 1 {
			t.Fatalf("calls = %d want 1", len(calls))
		}
		evt := a.xmlToolEvent("/x/tasks/t1/api_conversation_history.json",
			models.ToolCline, "t1", "", "", "", "m", nowFixture(), 0, 0, calls[0])
		if len(evt.RawToolInput) > scrub.MaxRawInputBytes {
			t.Errorf("raw_tool_input = %d bytes, over the %d cap", len(evt.RawToolInput), scrub.MaxRawInputBytes)
		}
		// CLAUDE.md: never store file contents. Only the path plus a
		// bounded excerpt survives.
		if len(evt.RawToolInput) > 4*xmlContentExcerptBytes {
			t.Errorf("raw_tool_input = %d bytes, want an excerpt not a body", len(evt.RawToolInput))
		}
		if strings.Contains(evt.RawToolInput, sentinel) {
			t.Error("raw_tool_input still carries the file body")
		}
		if !strings.Contains(evt.RawToolInput, "src/new.go") {
			t.Errorf("raw_tool_input lost the path: %q", evt.RawToolInput)
		}
		if evt.Target != "src/new.go" {
			t.Errorf("target = %q want src/new.go", evt.Target)
		}
	})

	t.Run("non_content_tag_is_truncated_at_the_cap", func(t *testing.T) {
		text := "<execute_command>\n<command>echo " + huge + "</command>\n</execute_command>"
		calls, _ := scanXMLTools(text)
		if len(calls) != 1 {
			t.Fatalf("calls = %d want 1", len(calls))
		}
		evt := a.xmlToolEvent("/x/tasks/t1/api_conversation_history.json",
			models.ToolCline, "t1", "", "", "", "m", nowFixture(), 0, 0, calls[0])
		if len(evt.RawToolInput) > scrub.MaxRawInputBytes {
			t.Errorf("raw_tool_input = %d bytes, over the %d cap", len(evt.RawToolInput), scrub.MaxRawInputBytes)
		}
		if strings.Contains(evt.RawToolInput, sentinel) {
			t.Error("raw_tool_input kept the tail past the cap")
		}
	})
}

// TestScanXMLToolsUnclosedTag pins the truncated-message case: an
// opening tag with no closer is NOT a call and stays in the prose, so
// a mid-stream snapshot never mints a half-read row.
func TestScanXMLToolsUnclosedTag(t *testing.T) {
	t.Parallel()
	const body = "Working on it.\n<execute_command>\n<command>go build"
	calls, prose := scanXMLTools(body)
	if len(calls) != 0 {
		t.Fatalf("calls = %d want 0 (%+v)", len(calls), calls)
	}
	if !strings.Contains(prose, "<execute_command>") {
		t.Errorf("unclosed opener should survive in prose: %q", prose)
	}
}

// TestScanXMLToolsMixedProseAndOrder pins that several calls in one
// block come back in WIRE order and the surrounding prose survives
// with the spans excised.
func TestScanXMLToolsMixedProseAndOrder(t *testing.T) {
	t.Parallel()
	const body = "First I read it.\n<read_file>\n<path>a.go</path>\n</read_file>\nThen I run tests.\n<execute_command>\n<command>go test</command>\n</execute_command>\nDone."
	calls, prose := scanXMLTools(body)
	if len(calls) != 2 {
		t.Fatalf("calls = %d want 2", len(calls))
	}
	if calls[0].tool.tag != "read_file" || calls[1].tool.tag != "execute_command" {
		t.Errorf("order = %q,%q", calls[0].tool.tag, calls[1].tool.tag)
	}
	for _, frag := range []string{"First I read it.", "Then I run tests.", "Done."} {
		if !strings.Contains(prose, frag) {
			t.Errorf("prose lost %q: %q", frag, prose)
		}
	}
	if strings.Contains(prose, "<read_file>") || strings.Contains(prose, "go test") {
		t.Errorf("prose still carries an XML span: %q", prose)
	}
}

// TestParseXMLFixture is the real-shape regression: the fixture is
// anonymized from the operator's live Cline 3.88.0 tasks (2026-09-02,
// read-only), which the audit found produced ZERO tool rows.
//
// Golden shape after the scanner: 4 pseudo-tool rows
// (ask_followup_question, read_file, execute_command,
// attempt_completion) + 1 user_prompt + 1 assistant_message (the
// "Sure — let me open that file." prose that preceded the read_file
// call). Nothing regressed the assistant_message path: the three
// assistant messages that are PURE markup now emit a tool row INSTEAD
// of a prose row, which is the entire point of IDE-07.
func TestParseXMLFixture(t *testing.T) {
	t.Parallel()
	src := filepath.Join("..", "..", "..", "testdata", "cline", "api_conversation_history_xml.json")
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "tasks", "1780707193341")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "api_conversation_history.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	a := New()
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	var raws []string
	for _, e := range res.ToolEvents {
		raws = append(raws, e.RawToolName)
	}
	want := []string{
		"user_message",
		"ask_followup_question",
		"cline.assistant_text",
		"read_file",
		"execute_command",
		"attempt_completion",
	}
	if len(raws) != len(want) {
		t.Fatalf("raw tool names = %v, want %v", raws, want)
	}
	for i := range want {
		if raws[i] != want[i] {
			t.Fatalf("raw tool names = %v, want %v", raws, want)
		}
	}

	// The ask_followup_question row must carry the QUESTION, not a
	// redaction — the pre-scanner path rendered the whole block as
	// "<a[REDACTED]>…".
	ask := res.ToolEvents[1]
	if !strings.Contains(ask.Target, "What would you like me to work on") {
		t.Errorf("ask target = %q", ask.Target)
	}
	if strings.Contains(ask.Target, "REDACTED") {
		t.Errorf("ask target was scrubbed as a token lookalike: %q", ask.Target)
	}
	if ask.ActionType != models.ActionAskUser {
		t.Errorf("ask action = %q", ask.ActionType)
	}
	// The thinking block preceding it threads through as reasoning,
	// exactly like it does for a tool_use block.
	if !strings.Contains(ask.PrecedingReasoning, "greeting") {
		t.Errorf("ask preceding_reasoning = %q", ask.PrecedingReasoning)
	}

	// Dedup keys are unique and message-anchored.
	seen := map[string]bool{}
	for _, e := range res.ToolEvents {
		if seen[e.SourceEventID] {
			t.Errorf("duplicate source_event_id %q", e.SourceEventID)
		}
		seen[e.SourceEventID] = true
	}
}

// TestAssistantTextIDHashesOriginalText is the UPGRADE DOUBLE-COUNT
// pin. assistant_message rows dedupe on (source_file, source_event_id),
// and the id embeds a content hash — so the hash input must be a
// property of the SOURCE FILE, never of how this adapter happens to
// render it today.
//
// The XML scanner changed the row's body from "the whole text block"
// to "the prose with the tool spans excised". Hashing that body would
// have given every historical assistant message a NEW id the moment
// the scanner shipped, so the next `observer scan --force` would write
// a second row beside each pre-scanner row instead of deduping onto
// it. The id therefore still hashes the ORIGINAL trimmed block text —
// the exact input the pre-0bdda1172 code used
// (`git show 0bdda1172^:internal/adapter/cline/adapter.go`, whose
// caller passed `strings.TrimSpace(block.Text)` straight through).
func TestAssistantTextIDHashesOriginalText(t *testing.T) {
	t.Parallel()
	const sessionID = "1780707193341"
	src := filepath.Join("..", "..", "..", "testdata", "cline", "api_conversation_history_xml.json")
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	var msgs []struct {
		Role    string `json:"role"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &msgs); err != nil {
		t.Fatal(err)
	}
	// Message 3 / block 0 is the fixture's only mixed prose+XML block:
	// prose, then a <read_file> call. Exactly the shape whose id moved.
	const msgIdx, blockIdx = 3, 0
	full := strings.TrimSpace(msgs[msgIdx].Content[blockIdx].Text)
	if !strings.Contains(full, "<read_file>") || !strings.Contains(full, "Sure") {
		t.Fatalf("fixture block %d/%d is no longer the mixed prose+XML block: %q", msgIdx, blockIdx, full)
	}
	// The pre-change formula, reconstructed verbatim.
	wantID := fmt.Sprintf("%s:asst:%s:%d:%d:%s", models.ToolCline, sessionID, msgIdx, blockIdx, shortHash(full))
	wantMsgID := models.ToolCline + ":asst:" + shortHash(full)

	dir := filepath.Join(t.TempDir(), "tasks", sessionID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "api_conversation_history.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := New().ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var found bool
	for _, e := range res.ToolEvents {
		if e.ActionType != models.ActionAssistantMessage {
			continue
		}
		found = true
		if e.SourceEventID != wantID {
			t.Errorf("source_event_id = %q\nwant                  %q\n(the id must survive the XML strip, or a re-parse double-counts)",
				e.SourceEventID, wantID)
		}
		if e.MessageID != wantMsgID {
			t.Errorf("message_id = %q want %q", e.MessageID, wantMsgID)
		}
		// The BODY is still the stripped prose — only the identity is
		// pinned to the source bytes.
		if strings.Contains(e.Target, "<read_file>") {
			t.Errorf("assistant prose still carries the XML span: %q", e.Target)
		}
	}
	if !found {
		t.Fatal("no assistant_message row emitted")
	}
}

// TestParseTwiceYieldsIdenticalDedupKeys pins the whole-file re-parse
// contract this adapter lives under: parsing the same task twice must
// produce the SAME (source_file, source_event_id) set, or the store's
// upsert writes duplicates on every poll.
func TestParseTwiceYieldsIdenticalDedupKeys(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "tasks", "1780707193341")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "cline", "api_conversation_history_xml.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "api_conversation_history.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	keys := func() map[string]bool {
		res, err := New().ParseSessionFile(context.Background(), path, 0)
		if err != nil {
			t.Fatalf("ParseSessionFile: %v", err)
		}
		out := map[string]bool{}
		for _, e := range res.ToolEvents {
			k := e.SourceFile + "\x00" + e.SourceEventID
			if out[k] {
				t.Errorf("duplicate dedup key within one parse: %q", e.SourceEventID)
			}
			out[k] = true
		}
		return out
	}
	first, second := keys(), keys()
	if len(first) != len(second) {
		t.Fatalf("key count changed across re-parse: %d then %d", len(first), len(second))
	}
	for k := range first {
		if !second[k] {
			t.Errorf("re-parse lost dedup key %q", k)
		}
	}
}

// nowFixture is a fixed timestamp for table-driven event construction.
func nowFixture() time.Time { return time.Unix(1780707193, 0).UTC() }
