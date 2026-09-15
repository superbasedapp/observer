package gemini

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestClassifyPath_ShapeFilter pins the path-shape classifier
// independently of the v1.4.51 under-WatchPaths constraint. Foreign-
// OS separators are accepted so tests + WSL2 /mnt/c paths still
// match. The integrated public API is covered by TestIsSessionFile
// below.
func TestClassifyPath_ShapeFilter(t *testing.T) {
	cases := []struct {
		path string
		want bool
		desc string
	}{
		{"/home/u/.gemini/tmp/abc/chats/session-2026-04-01T10-00-id1.json", true, "legacy json"},
		{"/home/u/.gemini/tmp/abc/chats/session-2026-04-01T10-00-id1.jsonl", true, "jsonl"},
		{`C:\Users\u\.gemini\tmp\abc\chats\session-2026-04-01T10-00-id1.json`, true, "windows path"},
		{"/mnt/c/Users/u/.gemini/tmp/abc/chats/session-X.json", true, "wsl cross-mount"},
		{"/home/u/.gemini/tmp/abc/checkpoints/cp-1.json", false, "checkpoints rejected"},
		{"/home/u/.gemini/tmp/abc/logs.json", false, "logs.json rejected"},
		{"/home/u/.gemini/antigravity/conversations/x.pb", false, "antigravity dir rejected"},
		{"/home/u/.gemini/tmp/abc/chats/parent-id/session-X.json", true, "subagent depth: classifier accepts (Parse rejects via classifySubagent — see TestSubagentRejectedExplicitly)"},
		{"/home/u/.gemini/tmp/abc/chats/foo.txt", false, "non-session basename"},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			got := classifyPath(c.path) != classifyOther
			if got != c.want {
				t.Fatalf("classifyPath(%q) != other = %v, want %v", c.path, got, c.want)
			}
		})
	}
}

// TestIsSessionFile pins the integrated public API: shape AND
// under-WatchPaths. Uses host-native paths so filepath.Abs behaves.
func TestIsSessionFile(t *testing.T) {
	root := t.TempDir()
	a := NewWithOptions(nil, root)
	good := filepath.Join(root, ".gemini", "tmp", "abc", "chats", "session-1.jsonl")
	if !a.IsSessionFile(good) {
		t.Errorf("matching path under watch root should match: %s", good)
	}
	// Shape match but outside watch root (v1.4.51 invariant).
	if a.IsSessionFile("/tmp/foreign/.gemini/tmp/abc/chats/session-1.jsonl") {
		t.Error("shape-match outside watch root must NOT match")
	}
}

func TestParseLegacySingleTurn(t *testing.T) {
	a := New()
	dst := writeFixture(t, "abc/chats/session-2026-04-01T10-00-id1.json", "../../../testdata/gemini/session-legacy-singleturn.json")
	res, err := a.ParseSessionFile(context.Background(), dst, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", res.Warnings)
	}
	// 2 events: user_prompt + the list_files tool call.
	// UPDATED 2026-07-31 (B3 convergence): the standalone
	// `gemini.reasoning` row this test used to expect is gone — the
	// `thought` part is threaded onto the tool call's
	// PrecedingReasoning instead of minting an action of its own.
	if got := len(res.ToolEvents); got != 2 {
		t.Fatalf("ToolEvents=%d, want 2 (1 user + 1 list_files), got %#v", got, summary(res.ToolEvents))
	}
	if res.ToolEvents[0].ActionType != models.ActionUserPrompt {
		t.Fatalf("first event = %s, want user_prompt", res.ToolEvents[0].ActionType)
	}
	for _, ev := range res.ToolEvents {
		if ev.RawToolName == "gemini.reasoning" {
			t.Fatalf("gemini.reasoning row minted: %+v", ev)
		}
	}
	if res.ToolEvents[1].ActionType != models.ActionSearchFiles {
		t.Fatalf("second event = %s, want search_files (list_files mapping)", res.ToolEvents[1].ActionType)
	}
	if res.ToolEvents[1].ToolOutput == "" {
		t.Fatalf("second event ToolOutput empty — functionResponse join failed")
	}
	if !strings.Contains(res.ToolEvents[1].ToolOutput, "main.go") {
		t.Fatalf("ToolOutput missing expected content: %q", res.ToolEvents[1].ToolOutput)
	}
	if res.ToolEvents[1].PrecedingReasoning == "" {
		t.Fatalf("expected reasoning threaded from the `thought` part onto the tool call")
	}
	if got := len(res.TokenEvents); got != 1 {
		t.Fatalf("TokenEvents=%d, want 1", got)
	}
	tok := res.TokenEvents[0]
	if tok.InputTokens != 1234 || tok.OutputTokens != 89 || tok.ReasoningTokens != 12 {
		t.Fatalf("token counts mismatch: %+v", tok)
	}
	if tok.Model != "gemini-2.5-pro" {
		t.Fatalf("token model = %q, want gemini-2.5-pro", tok.Model)
	}
	if res.ToolEvents[0].SessionID != "00000000-1111-2222-3333-444444444444" {
		t.Fatalf("user event session id = %q, want from JSON sessionId", res.ToolEvents[0].SessionID)
	}
}

func TestParseLegacyIdempotent(t *testing.T) {
	a := New()
	dst := writeFixture(t, "abc/chats/session-Y.json", "../../../testdata/gemini/session-legacy-multiturn.json")
	res1, err := a.ParseSessionFile(context.Background(), dst, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	res2, err := a.ParseSessionFile(context.Background(), dst, res1.NewOffset)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	// Re-parse with cursor at file size = no events (file unchanged).
	if len(res2.ToolEvents) != 0 || len(res2.TokenEvents) != 0 {
		t.Fatalf("re-parse with current cursor produced events: %+v", res2)
	}
	// Re-parse from scratch to confirm SourceEventIDs are deterministic
	// (caller-side dedup will collapse them).
	res3, _ := a.ParseSessionFile(context.Background(), dst, 0)
	if len(res3.ToolEvents) != len(res1.ToolEvents) || len(res3.TokenEvents) != len(res1.TokenEvents) {
		t.Fatalf("non-deterministic event count: first=%d/%d third=%d/%d",
			len(res1.ToolEvents), len(res1.TokenEvents),
			len(res3.ToolEvents), len(res3.TokenEvents))
	}
	for i := range res1.ToolEvents {
		if res1.ToolEvents[i].SourceEventID != res3.ToolEvents[i].SourceEventID {
			t.Fatalf("event %d SourceEventID drift: %q != %q", i, res1.ToolEvents[i].SourceEventID, res3.ToolEvents[i].SourceEventID)
		}
	}
}

func TestParseJSONL(t *testing.T) {
	a := New()
	dst := writeFixture(t, "abc/chats/session-jsonl-1.jsonl", "../../../testdata/gemini/session-jsonl-singleturn.jsonl")
	res, err := a.ParseSessionFile(context.Background(), dst, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", res.Warnings)
	}
	want := map[string]int{
		models.ActionUserPrompt: 1,
		models.ActionRunCommand: 1,
	}
	got := map[string]int{}
	for _, ev := range res.ToolEvents {
		got[ev.ActionType]++
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("action_type %s count = %d, want %d (full counts: %v)", k, got[k], v, got)
		}
	}
	// runShellCommand event should have its tool output joined.
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionRunCommand {
			if !strings.Contains(ev.ToolOutput, "hi") {
				t.Fatalf("run_command ToolOutput = %q, want it to contain 'hi'", ev.ToolOutput)
			}
		}
	}
	// Two TokenEvents: original gemini message + message_update.
	if len(res.TokenEvents) != 2 {
		t.Fatalf("TokenEvents = %d, want 2 (initial + update)", len(res.TokenEvents))
	}
	// Both should share the same MessageID; the update has refreshed counts.
	first, second := res.TokenEvents[0], res.TokenEvents[1]
	if first.MessageID != second.MessageID {
		t.Fatalf("token MessageIDs diverge: %q vs %q", first.MessageID, second.MessageID)
	}
	if second.OutputTokens != 11 || second.ReasoningTokens != 3 {
		t.Fatalf("update tokens not picked up: %+v", second)
	}
}

// TestParseJSONLStringAssistantContent is the regression guard for the
// live-capture bug (2026-06-27): the real Gemini CLI writes a `gemini`
// (assistant) message's `content` as a BARE STRING ("hi there"), while user
// messages use an ARRAY of parts. Before the contentParts unmarshaler the
// string shape failed to decode and the whole assistant line was dropped, so
// the dashboard showed only the user prompt. This pins that the assistant
// message + its token row are now captured. Mirrors the exact on-disk shape
// (incl. the `$set` mutation lines the CLI interleaves).
func TestParseJSONLStringAssistantContent(t *testing.T) {
	a := New()
	dir := t.TempDir()
	dst := filepath.Join(dir, ".gemini", "tmp", "abc", "chats", "session-live.jsonl")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	content := `{"sessionId":"live-1","projectHash":"abc","startTime":"2026-06-26T19:07:00.000Z","kind":"session"}
{"$set":{"lastUpdated":"2026-06-26T19:07:01.000Z"}}
{"id":"u1","timestamp":"2026-06-26T19:07:02.000Z","type":"user","content":[{"text":"respond with exactly: hi there"}]}
{"$set":{"lastUpdated":"2026-06-26T19:07:05.000Z"}}
{"id":"g1","timestamp":"2026-06-26T19:07:05.000Z","type":"gemini","content":"hi there","thoughts":[],"tokens":{"input":11092,"output":2,"cached":0,"thoughts":130,"tool":0,"total":11224},"model":"gemini-3.5-flash"}
`
	if err := os.WriteFile(dst, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	res, err := a.ParseSessionFile(context.Background(), dst, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	// The header line + the interleaved {"$set":…} mutation lines must NOT
	// produce warnings (they'd flood the watcher log otherwise).
	if len(res.Warnings) != 0 {
		t.Errorf("unexpected warnings (header/$set should be silent): %v", res.Warnings)
	}
	counts := map[string]int{}
	for _, ev := range res.ToolEvents {
		counts[ev.ActionType]++
	}
	if counts[models.ActionUserPrompt] != 1 {
		t.Errorf("user_prompt rows = %d, want 1", counts[models.ActionUserPrompt])
	}
	// The assistant message must now produce a visible row (was dropped before).
	var assistantRow bool
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionAssistantMessage && strings.Contains(ev.ToolOutput, "hi there") {
			assistantRow = true
		}
	}
	if !assistantRow {
		t.Errorf("assistant message row missing (the dropped-line bug); events: %+v", res.ToolEvents)
	}
	// And the token row must be captured (input netted, output, reasoning).
	if len(res.TokenEvents) != 1 {
		t.Fatalf("TokenEvents = %d, want 1", len(res.TokenEvents))
	}
	tok := res.TokenEvents[0]
	if tok.InputTokens != 11092 || tok.OutputTokens != 2 || tok.ReasoningTokens != 130 {
		t.Errorf("token counts = in %d/out %d/reason %d, want 11092/2/130", tok.InputTokens, tok.OutputTokens, tok.ReasoningTokens)
	}
	if tok.Model != "gemini-3.5-flash" {
		t.Errorf("token model = %q, want gemini-3.5-flash", tok.Model)
	}
	// All events MUST share the path-derived session id — the header's UUID
	// sessionId must NOT be adopted, or the session fragments into two rows
	// (user prompt under the path id, the rest under the UUID).
	wantSID := "session-live"
	for _, ev := range res.ToolEvents {
		if ev.SessionID != wantSID {
			t.Errorf("ToolEvent %s session=%q, want %q (header UUID must not override)", ev.ActionType, ev.SessionID, wantSID)
		}
	}
	if tok.SessionID != wantSID {
		t.Errorf("TokenEvent session=%q, want %q", tok.SessionID, wantSID)
	}
}

// TestParseJSONLImageOnlyUserTurn pins the multimodal image-marker:
// a user turn carrying only an `inlineData` image part (no text) is
// surfaced as a user_prompt marker row instead of being silently
// dropped. Observability-only — no image bytes are stored.
func TestParseJSONLImageOnlyUserTurn(t *testing.T) {
	a := New()
	dir := t.TempDir()
	dst := filepath.Join(dir, ".gemini", "tmp", "abc", "chats", "session-img.jsonl")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	content := `{"type":"session_metadata","sessionId":"img-1","cwd":"/tmp/p"}
{"type":"user","id":"u1","timestamp":"2026-04-03T09:00:01.000Z","content":[{"type":"image","inlineData":{"mimeType":"image/png","data":"AAAA"}}]}
`
	if err := os.WriteFile(dst, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	res, err := a.ParseSessionFile(context.Background(), dst, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var imgRows int
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionUserPrompt && strings.Contains(ev.Target, "image attachment") {
			imgRows++
		}
	}
	if imgRows != 1 {
		t.Fatalf("image-marker user_prompt rows = %d, want 1 (events: %+v)", imgRows, res.ToolEvents)
	}
}

func TestParseJSONLMalformedLine(t *testing.T) {
	a := New()
	dst := writeFixture(t, "abc/chats/session-malformed.jsonl", "../../../testdata/gemini/session-malformed.jsonl")
	res, err := a.ParseSessionFile(context.Background(), dst, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.Warnings) == 0 {
		t.Fatalf("expected at least 1 warning for malformed line")
	}
	// Should still capture the post-malformed user line.
	var sawUser bool
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionUserPrompt {
			sawUser = true
		}
	}
	if !sawUser {
		t.Fatalf("malformed-line skip did not advance — user event after malformed missed")
	}
}

func TestParseTruncatedJSONReturnsRetry(t *testing.T) {
	a := New()
	full, err := os.ReadFile("../../../testdata/gemini/session-legacy-singleturn.json")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	// Truncate mid-write.
	dir := t.TempDir()
	dst := filepath.Join(dir, "tmp", "abc", "chats", "session-X.json")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".gemini-marker"), nil, 0o644); err != nil {
		t.Fatalf("marker: %v", err)
	}
	// Re-anchor under a synthetic .gemini/tmp tree.
	dst2 := filepath.Join(dir, ".gemini", "tmp", "abc", "chats", "session-X.json")
	if err := os.MkdirAll(filepath.Dir(dst2), 0o755); err != nil {
		t.Fatalf("mkdir2: %v", err)
	}
	if err := os.WriteFile(dst2, full[:len(full)/2], 0o644); err != nil {
		t.Fatalf("write truncated: %v", err)
	}
	res, err := a.ParseSessionFile(context.Background(), dst2, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.Warnings) == 0 {
		t.Fatalf("expected mid-write warning, got none; events=%d tokens=%d", len(res.ToolEvents), len(res.TokenEvents))
	}
	if res.NewOffset != 0 {
		t.Fatalf("truncated parse advanced cursor to %d, expected 0 (retry)", res.NewOffset)
	}
}

func TestSubagentRejectedExplicitly(t *testing.T) {
	a := New()
	res, err := a.ParseSessionFile(context.Background(), "/home/u/.gemini/tmp/abc/chats/parent-id/session-X.json", 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "subagent") {
		t.Fatalf("expected subagent warning, got: %v", res.Warnings)
	}
	if len(res.ToolEvents) != 0 {
		t.Fatalf("expected zero events for rejected subagent, got %d", len(res.ToolEvents))
	}
}

func TestProjectHashFromPath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/home/u/.gemini/tmp/abc123/chats/session-X.json", "abc123"},
		{`C:\Users\u\.gemini\tmp\HASHHASH\chats\session-Y.jsonl`, "HASHHASH"},
		{"/no/match/here", ""},
	}
	for _, c := range cases {
		got := projectHashFromPath(c.path)
		if got != c.want {
			t.Fatalf("projectHashFromPath(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestMapToolName(t *testing.T) {
	cases := map[string]string{
		"read_file":         models.ActionReadFile,
		"readFile":          models.ActionReadFile,
		"runShellCommand":   models.ActionRunCommand,
		"run_shell_command": models.ActionRunCommand,
		"google_web_search": models.ActionWebSearch,
		"googleWebSearch":   models.ActionWebSearch,
		"replace":           models.ActionEditFile,
		"glob":              models.ActionSearchFiles,
		"grep":              models.ActionSearchText,
		"web_fetch":         models.ActionWebFetch,
		"unknown_tool":      models.ActionUnknown,
		"mcp__server__do":   models.ActionMCPCall,
		// WP-T6 G1 follow-up (live-grounded 2026-07-31).
		"list_directory": models.ActionSearchFiles,
		"grep_search":    models.ActionSearchText,
		"invoke_agent":   models.ActionSpawnSubagent,
		// update_topic is a DELIBERATE unknown — see mapToolName's
		// "updatetopic" case and tooltax_conformance_test.go's
		// unclassifiedDomain entry.
		"update_topic": models.ActionUnknown,
	}
	for in, want := range cases {
		if got := mapToolName(in); got != want {
			t.Fatalf("mapToolName(%q) = %q, want %q", in, got, want)
		}
	}
}

// writeFixture copies a fixture file under a synthetic .gemini/tmp/<rel>
// path inside t.TempDir() so cwd-less classifyPath / project_root
// resolution doesn't depend on a real ~/.gemini/ install.
func writeFixture(t *testing.T, rel, fixture string) string {
	t.Helper()
	body, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixture, err)
	}
	dir := t.TempDir()
	dst := filepath.Join(dir, ".gemini", "tmp", rel)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(dst, body, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return dst
}

func summary(events []models.ToolEvent) []string {
	out := make([]string, len(events))
	for i, ev := range events {
		out[i] = ev.ActionType + "/" + ev.RawToolName
	}
	return out
}

// TestAssistantTextEmission pins the new gemini.assistant_text emission:
// every text part on a role=gemini message produces an ActionTaskComplete
// row with RawToolName="gemini.assistant_text", the body in ToolOutput,
// MessageID linked to the assistant message id, and NO companion
// TokenEvent (token data flows through the existing tokens emitter).
// User-role text parts continue to emit user_prompt, NOT assistant_text.
func TestAssistantTextEmission(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, ".gemini", "tmp", "chats", "session-with-text.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := `{
  "sessionId": "asst-text-session",
  "projectHash": "0000",
  "startTime": "2026-05-12T10:00:00.000Z",
  "messages": [
    {"id":"u1","role":"user","timestamp":"2026-05-12T10:00:01.000Z","cwd":"/tmp/g","content":[{"type":"text","text":"ping"}]},
    {"id":"m1","role":"gemini","timestamp":"2026-05-12T10:00:02.000Z","model":"gemini-2.5-pro","content":[
      {"type":"text","text":"First gemini message."},
      {"type":"text","text":"Second gemini message."},
      {"type":"text","text":"   "},
      {"type":"functionCall","functionCall":{"id":"c1","name":"list_files","args":{"path":"."}}}
    ]}
  ]
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	res, err := New().ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	// Filter to just assistant_text rows for ordering-independent checks.
	var asst []models.ToolEvent
	for _, ev := range res.ToolEvents {
		if ev.RawToolName == "gemini.assistant_text" {
			asst = append(asst, ev)
		}
	}
	if len(asst) != 2 {
		t.Fatalf("gemini.assistant_text rows: got %d want 2 (whitespace-only suppressed); all: %v", len(asst), summary(res.ToolEvents))
	}

	for i, want := range []string{"First gemini message.", "Second gemini message."} {
		ev := asst[i]
		if ev.ActionType != models.ActionAssistantMessage {
			t.Errorf("asst[%d] action = %q, want assistant_message", i, ev.ActionType)
		}
		if ev.ToolOutput != want {
			t.Errorf("asst[%d] tool_output = %q, want %q", i, ev.ToolOutput, want)
		}
		if ev.Target != want {
			t.Errorf("asst[%d] target = %q, want %q", i, ev.Target, want)
		}
		if ev.MessageID != "m1" {
			t.Errorf("asst[%d] message_id = %q, want m1", i, ev.MessageID)
		}
		if ev.Tool != models.ToolGeminiCLI {
			t.Errorf("asst[%d] tool = %q", i, ev.Tool)
		}
	}
	if asst[0].SourceEventID == asst[1].SourceEventID {
		t.Errorf("SourceEventIDs must differ across distinct parts: %q vs %q",
			asst[0].SourceEventID, asst[1].SourceEventID)
	}

	// User-role text part still emits user_prompt, not assistant_text.
	var userPrompts int
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionUserPrompt {
			userPrompts++
		}
	}
	if userPrompts != 1 {
		t.Errorf("user_prompt count: got %d want 1", userPrompts)
	}
}

// TestBothOnDiskShapesEmitToolRows is the table-driven both-shapes pin
// for WP-T6 finding G1. The adapter was written against the
// content-parts shape (`functionCall` / `thought` parts inside
// `content`); the shipping Gemini CLI writes assistant messages as
// `content: ""` with SIBLING TOP-LEVEL `toolCalls[]` + `thoughts[]`
// arrays, so both emission loops iterated zero times and gemini-cli had
// never recorded a single tool call. Both shapes must now work — the
// live fixture is a scrubbed copy of a real probe session
// (2026-07-31, gemini-3.5-flash), the legacy fixture is the pre-existing
// content-parts one.
func TestBothOnDiskShapesEmitToolRows(t *testing.T) {
	type wantCall struct {
		rawName    string
		actionType string
		target     string
		outputHas  string
	}
	cases := []struct {
		name        string
		fixture     string
		rel         string
		wantCalls   []wantCall
		wantPrompts int
		reasonHas   string
	}{
		{
			name:    "live top-level toolCalls/thoughts shape",
			fixture: "../../../testdata/gemini/session-live-toolcalls.jsonl",
			rel:     "gemini/chats/session-2026-07-31T11-42-live.jsonl",
			wantCalls: []wantCall{
				{"update_topic", models.ActionUnknown, "File Operations and Verification", "Current topic"},
				{"read_file", models.ActionReadFile, "hello.txt", "hello from wpt6"},
				{"write_file", models.ActionWriteFile, "probe_out.txt", "Successfully created"},
				{"run_shell_command", models.ActionRunCommand, "echo probe-marker-gemini", "probe-marker-gemini"},
				{"update_topic", models.ActionUnknown, "Task Completed", "Current topic"},
			},
			wantPrompts: 1,
			// Within the 200-char preview the threading site caps at
			// (the pre-B3 row body was capped at 4000, which is why
			// this used to name a phrase deep in the thought).
			reasonHas: "Analyzing the Core Mandates",
		},
		{
			name:    "legacy content-parts shape",
			fixture: "../../../testdata/gemini/session-legacy-singleturn.json",
			rel:     "abc/chats/session-2026-04-01T10-00-id1.json",
			wantCalls: []wantCall{
				{"list_files", models.ActionSearchFiles, ".", "main.go"},
			},
			wantPrompts: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dst := writeFixture(t, tc.rel, tc.fixture)
			res, err := New().ParseSessionFile(context.Background(), dst, 0)
			if err != nil {
				t.Fatalf("ParseSessionFile: %v", err)
			}
			if len(res.Warnings) != 0 {
				t.Fatalf("unexpected warnings: %v", res.Warnings)
			}

			var calls []models.ToolEvent
			var prompts int
			for _, ev := range res.ToolEvents {
				switch {
				case ev.ActionType == models.ActionUserPrompt:
					prompts++
				case ev.RawToolName == "gemini.reasoning":
					// UPDATED 2026-07-31 (B3 convergence): this row no
					// longer exists — the thought is threaded onto the
					// tool calls of its own message instead.
					t.Fatalf("gemini.reasoning row minted: %+v", ev)
				case ev.RawToolName == "gemini.assistant_text":
					// covered by TestAssistantTextEmission
				default:
					calls = append(calls, ev)
				}
			}
			if prompts != tc.wantPrompts {
				t.Errorf("user_prompt rows = %d, want %d", prompts, tc.wantPrompts)
			}
			// The reasoning must arrive on the tool rows (200-char
			// preview — the cap is unchanged, it just moved to the
			// threading site).
			for _, ev := range calls {
				if tc.reasonHas != "" && strings.Contains(ev.PrecedingReasoning, tc.reasonHas) {
					tc.reasonHas = ""
				}
			}
			if tc.reasonHas != "" {
				t.Errorf("no tool row carried the threaded reasoning %q; got %v", tc.reasonHas, summary(calls))
			}
			if len(calls) != len(tc.wantCalls) {
				t.Fatalf("tool rows = %d, want %d; got %v", len(calls), len(tc.wantCalls), summary(calls))
			}
			for i, want := range tc.wantCalls {
				got := calls[i]
				if got.RawToolName != want.rawName {
					t.Errorf("call[%d] raw name = %q, want %q", i, got.RawToolName, want.rawName)
				}
				if got.ActionType != want.actionType {
					t.Errorf("call[%d] action = %q, want %q", i, got.ActionType, want.actionType)
				}
				if got.Target != want.target {
					t.Errorf("call[%d] target = %q, want %q", i, got.Target, want.target)
				}
				if !strings.Contains(got.ToolOutput, want.outputHas) {
					t.Errorf("call[%d] output = %q, want it to contain %q", i, got.ToolOutput, want.outputHas)
				}
				if !got.Success {
					t.Errorf("call[%d] Success = false, want true", i)
				}
				if got.MessageID == "" {
					t.Errorf("call[%d] MessageID empty — tool row does not join its assistant message", i)
				}
			}
		})
	}
}

// TestLiveShapeReappendIsStable pins the live CLI's append-only UPSERT
// behaviour: it writes the SAME assistant message twice — once when the
// text/thoughts land, again once its toolCalls resolve (lines 5+7 and
// 10+12 of the probe session). The re-append must reuse the same
// SourceEventIDs so the store's (source_file, source_event_id) upsert
// collapses them; keying per-message rows on the LINE number instead
// produced a duplicate row per assistant message.
//
// UPDATED 2026-07-31 (B3 convergence): the per-message rows this used to
// assert over were the `gemini.reasoning` rows, which no longer exist.
// The contract they pinned — messageKey, never the line index — is now
// carried by the assistant_text rows, and the re-appended thoughts land
// on the CLI's own call-id-keyed tool rows, which the second half
// already pins as unique.
func TestLiveShapeReappendIsStable(t *testing.T) {
	dst := writeFixture(t, "gemini/chats/session-live-dup.jsonl", "../../../testdata/gemini/session-live-toolcalls.jsonl")
	res, err := New().ParseSessionFile(context.Background(), dst, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var perMessage int
	for _, ev := range res.ToolEvents {
		if ev.RawToolName == "gemini.reasoning" {
			t.Fatalf("gemini.reasoning row minted: %+v", ev)
		}
		if ev.RawToolName != "gemini.assistant_text" {
			continue
		}
		perMessage++
		// asst:<session>:<messageKey>:<partIdx> — the messageKey half
		// must be the message's own id, never an "L<line>" fallback,
		// or the two appends produce two rows.
		if strings.Contains(ev.SourceEventID, ":L") {
			t.Errorf("assistant_text SourceEventID %q is line-keyed, not message-keyed", ev.SourceEventID)
		}
	}
	if perMessage == 0 {
		t.Fatalf("no per-message assistant rows to check; events: %v", summary(res.ToolEvents))
	}
	// The re-appended messages' thoughts must have reached the tool
	// rows rather than vanishing with the deleted reasoning rows.
	var threaded int
	for _, ev := range res.ToolEvents {
		if strings.HasPrefix(ev.RawToolName, "gemini.") || ev.ActionType == models.ActionUserPrompt {
			continue
		}
		if ev.PrecedingReasoning != "" {
			threaded++
		}
	}
	if threaded != 5 {
		t.Errorf("tool rows carrying threaded reasoning = %d, want 5", threaded)
	}
	// Tool-call ids come from the CLI itself and must be unique per call.
	toolIDs := map[string]bool{}
	for _, ev := range res.ToolEvents {
		if strings.HasPrefix(ev.RawToolName, "gemini.") || ev.ActionType == models.ActionUserPrompt {
			continue
		}
		if toolIDs[ev.SourceEventID] {
			t.Errorf("duplicate tool SourceEventID %q", ev.SourceEventID)
		}
		toolIDs[ev.SourceEventID] = true
	}
	if len(toolIDs) != 5 {
		t.Errorf("distinct tool SourceEventIDs = %d, want 5", len(toolIDs))
	}
}

// TestLiveToolCallStatusAndThoughtsShapes pins the two decode-tolerance
// details of the live shape: `status` drives ToolEvent.Success (a live
// read_file error was observed in the corpus), and the `thoughts` array
// must never fail a whole line — an unexpected encoding degrades to a
// best-effort body instead of dropping the assistant message.
func TestLiveToolCallStatusAndThoughtsShapes(t *testing.T) {
	t.Run("status", func(t *testing.T) {
		cases := map[string]bool{
			"success": true, "": true, "pending": true, "executing": true,
			"error": false, "Error": false, "failed": false, "cancelled": false,
			"canceled": false, "timeout": false,
		}
		for status, want := range cases {
			if got := callSucceeded(status); got != want {
				t.Errorf("callSucceeded(%q) = %v, want %v", status, got, want)
			}
		}
	})
	t.Run("thoughts decoding", func(t *testing.T) {
		cases := []struct {
			name string
			body string
			want string
		}{
			{"live object array", `[{"subject":"S","description":"D"},{"description":"D2"}]`, "S\nD\n\nD2"},
			{"string array", `["one","two"]`, "one\n\ntwo"},
			{"bare string", `"solo"`, "solo"},
			{"null", `null`, ""},
			{"empty array", `[]`, ""},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				var msg rawLegacyMsg
				if err := json.Unmarshal([]byte(`{"type":"gemini","thoughts":`+c.body+`}`), &msg); err != nil {
					t.Fatalf("unmarshal %s: %v", c.body, err)
				}
				if got := concatLiveThoughts(msg.Thoughts); got != c.want {
					t.Errorf("concatLiveThoughts(%s) = %q, want %q", c.body, got, c.want)
				}
			})
		}
	})
}

// TestResolveProjectRootRecordedTiers pins the project-root fallback
// chain added for the G1 secondary finding. The live session JSONL
// carries no cwd, so before this every gemini session landed on the
// synthetic "[gemini-cli:<key>]" key and was unjoinable to a real repo —
// even though the CLI records the answer twice on disk
// (tmp/<key>/.project_root and projects.json).
func TestResolveProjectRootRecordedTiers(t *testing.T) {
	const key = "myproj"
	write := func(t *testing.T, path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	cases := []struct {
		name  string
		setup func(t *testing.T, home string) string // returns want
	}{
		{
			name: "tmp sidecar wins",
			setup: func(t *testing.T, home string) string {
				root := filepath.Join(t.TempDir(), "realrepo")
				if err := os.MkdirAll(root, 0o755); err != nil {
					t.Fatal(err)
				}
				write(t, filepath.Join(home, "tmp", key, ".project_root"), root+"\n")
				write(t, filepath.Join(home, "projects.json"), `{"projects":{"/other":"`+key+`"}}`)
				return root
			},
		},
		{
			name: "history sidecar when tmp sidecar absent",
			setup: func(t *testing.T, home string) string {
				root := filepath.Join(t.TempDir(), "histrepo")
				if err := os.MkdirAll(root, 0o755); err != nil {
					t.Fatal(err)
				}
				write(t, filepath.Join(home, "history", key, ".project_root"), root)
				return root
			},
		},
		{
			name: "projects.json reverse map when no sidecar",
			setup: func(t *testing.T, home string) string {
				root := filepath.Join(t.TempDir(), "jsonrepo")
				if err := os.MkdirAll(root, 0o755); err != nil {
					t.Fatal(err)
				}
				write(t, filepath.Join(home, "projects.json"),
					`{"projects":{"`+root+`":"`+key+`","/elsewhere":"otherproj"}}`)
				return root
			},
		},
		{
			name: "ambiguous projects.json falls through to synthetic",
			setup: func(t *testing.T, home string) string {
				write(t, filepath.Join(home, "projects.json"),
					`{"projects":{"/a":"`+key+`","/b":"`+key+`"}}`)
				return "[gemini-cli:" + key + "]"
			},
		},
		{
			name: "nothing recorded stays synthetic",
			setup: func(t *testing.T, home string) string {
				return "[gemini-cli:" + key + "]"
			},
		},
		{
			name: "recorded root that does not exist here is still reported verbatim",
			setup: func(t *testing.T, home string) string {
				write(t, filepath.Join(home, "tmp", key, ".project_root"), "/mnt/c/Users/dev/proj")
				return "/mnt/c/Users/dev/proj"
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), ".gemini")
			session := filepath.Join(home, "tmp", key, "chats", "session-1.jsonl")
			if err := os.MkdirAll(filepath.Dir(session), 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			want := c.setup(t, home)
			if got, _, _ := resolveProjectRoot(session, ""); got != want {
				t.Errorf("resolveProjectRoot = %q, want %q", got, want)
			}
		})
	}
}

// TestResolveProjectRootPromotesToGitRoot pins the stat-gate-then-
// git.Resolve order: a recorded root that exists on this host is
// promoted to its enclosing git root (so gemini sessions join the same
// project row as every other adapter).
func TestResolveProjectRootPromotesToGitRoot(t *testing.T) {
	const key = "gitproj"
	repo := filepath.Join(t.TempDir(), "repo")
	sub := filepath.Join(repo, "pkg", "inner")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	home := filepath.Join(t.TempDir(), ".gemini")
	session := filepath.Join(home, "tmp", key, "chats", "session-1.jsonl")
	if err := os.MkdirAll(filepath.Dir(session), 0o755); err != nil {
		t.Fatalf("mkdir session: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(home, "tmp", key), 0o755); err != nil {
		t.Fatalf("mkdir key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, "tmp", key, ".project_root"), []byte(sub), 0o644); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}
	got, _, _ := resolveProjectRoot(session, "")
	want, err := filepath.EvalSymlinks(repo)
	if err != nil {
		t.Fatalf("evalsymlinks: %v", err)
	}
	if got != want {
		t.Errorf("resolveProjectRoot = %q, want git root %q", got, want)
	}
}

// TestTokenEventForNetsCachedInput pins the OpenAI-gross fix: Gemini's
// `input` is the gross prompt count including the cached portion, so
// tokenEventFor must emit NET input (gross − cacheRead) to match the cost
// engine's TokenBundle.Input contract and avoid double-billing the cached
// tokens (feedback_openai_input_is_gross).
func TestTokenEventForNetsCachedInput(t *testing.T) {
	st := &sessionState{SessionID: "s1", Model: "gemini-2.5-pro"}
	tests := []struct {
		name          string
		in            legacyTokens
		wantInput     int64
		wantCacheRead int64
	}{
		{"cacheRead field", legacyTokens{Input: 12000, Output: 50, CacheRead: 11000}, 1000, 11000},
		{"cached field", legacyTokens{Input: 12000, Output: 50, Cached: 11000}, 1000, 11000},
		{"max of both", legacyTokens{Input: 12000, Output: 50, CacheRead: 9000, Cached: 11000}, 1000, 11000},
		{"no cache", legacyTokens{Input: 1234, Output: 89, ThoughtsTokens: 12}, 1234, 0},
		{"clamp negative", legacyTokens{Input: 500, Cached: 900}, 0, 900},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := tokenEventFor("p", "m", time.Time{}, "", st, tc.in)
			if ev.InputTokens != tc.wantInput {
				t.Errorf("InputTokens = %d, want %d (net non-cached)", ev.InputTokens, tc.wantInput)
			}
			if ev.CacheReadTokens != tc.wantCacheRead {
				t.Errorf("CacheReadTokens = %d, want %d", ev.CacheReadTokens, tc.wantCacheRead)
			}
		})
	}
}

// TestTokenEventForReasoningKeys pins that reasoning tokens are captured
// from BOTH the live "thoughts" key and the fixture/proposed
// "thoughtsTokenCount" key (max of the two). Regression guard for the
// silent-zero bug where only thoughtsTokenCount was tagged.
func TestTokenEventForReasoningKeys(t *testing.T) {
	st := &sessionState{SessionID: "s1", Model: "gemini-3.5-flash"}
	tests := []struct {
		name string
		in   legacyTokens
		want int64
	}{
		{"live thoughts key", legacyTokens{Input: 100, Thoughts: 442}, 442},
		{"legacy thoughtsTokenCount key", legacyTokens{Input: 100, ThoughtsTokens: 12}, 12},
		{"both present takes max", legacyTokens{Input: 100, Thoughts: 442, ThoughtsTokens: 9}, 442},
		{"neither", legacyTokens{Input: 100}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := tokenEventFor("p", "m", time.Time{}, "", st, tc.in)
			if ev.ReasoningTokens != tc.want {
				t.Errorf("ReasoningTokens = %d, want %d", ev.ReasoningTokens, tc.want)
			}
		})
	}
}

// writeIncremental writes body to a session path under a fresh
// .gemini/tmp tree and returns the path. Companion to writeFixture for
// the incremental-parse tests, which need to control the exact bytes on
// disk at each step rather than copy a whole fixture.
func writeIncremental(t *testing.T, rel string, body []byte) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), ".gemini", "tmp", rel)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(dst, body, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return dst
}

// lineEnd returns the byte offset just past the n-th (1-based) '\n' in
// body — i.e. the cursor value a correct incremental parse must report
// after consuming exactly n terminated records.
func lineEnd(t *testing.T, body []byte, n int) int64 {
	t.Helper()
	off := 0
	for i := 0; i < n; i++ {
		idx := bytes.IndexByte(body[off:], '\n')
		if idx < 0 {
			t.Fatalf("fixture has fewer than %d terminated lines", n)
		}
		off += idx + 1
	}
	return int64(off)
}

func eventIDs(events []models.ToolEvent) map[string]bool {
	out := map[string]bool{}
	for _, ev := range events {
		out[ev.SourceEventID] = true
	}
	return out
}

// TestJSONLUnterminatedTailDeferredThenZeroLoss pins finding F9: a parse
// that lands mid-append must NOT advance the byte cursor past the
// partial record, or the completed record is stranded forever.
//
// The old reader was a bufio.Scanner and committed `len(line)+1` for
// every token it produced — including the final UNTERMINATED one. A
// truncated tail therefore either (a) parsed as malformed and advanced
// past itself, or (b) parsed as valid-JSON-prefix and advanced past
// itself, and in both cases the next pass resumed AFTER the record.
// The discriminator is now the '\n' terminator, matching the repo
// convention (internal/adapter/codex/adapter.go readRecord).
func TestJSONLUnterminatedTailDeferredThenZeroLoss(t *testing.T) {
	full, err := os.ReadFile("../../../testdata/gemini/session-live-toolcalls.jsonl")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	// Cut INSIDE line 7 — the append that carries the four resolved
	// toolCalls, i.e. the record whose loss is most expensive.
	sixLines := lineEnd(t, full, 6)
	sevenLines := lineEnd(t, full, 7)
	cut := sixLines + (sevenLines-sixLines)/2

	dst := writeIncremental(t, "gemini/chats/session-trunc.jsonl", full[:cut])
	first, err := New().ParseSessionFile(context.Background(), dst, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	if first.NewOffset != sixLines {
		t.Fatalf("cursor after mid-record parse = %d, want %d (end of the last TERMINATED record); "+
			"advancing past a partial record strands it", first.NewOffset, sixLines)
	}
	var deferred bool
	for _, w := range first.Warnings {
		if strings.Contains(w, "deferred unterminated trailing record") {
			deferred = true
		}
	}
	if !deferred {
		t.Errorf("no deferral warning surfaced; warnings=%v", first.Warnings)
	}

	// The append completes.
	if err := os.WriteFile(dst, full, 0o644); err != nil {
		t.Fatalf("complete write: %v", err)
	}
	second, err := New().ParseSessionFile(context.Background(), dst, first.NewOffset)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	if second.NewOffset != int64(len(full)) {
		t.Errorf("cursor after completed parse = %d, want %d", second.NewOffset, len(full))
	}

	// ZERO LOSS: the two-pass union must equal a single-pass parse.
	// Same BASENAME as the incremental file: gemini session ids come from
	// the path stem (sessionIDFromPath), and several SourceEventIDs embed
	// them, so a differently-named control file would compare unequal for
	// a reason that has nothing to do with the cursor.
	whole, err := New().ParseSessionFile(context.Background(),
		writeIncremental(t, "gemini/chats/session-trunc.jsonl", full), 0)
	if err != nil {
		t.Fatalf("whole parse: %v", err)
	}
	got := eventIDs(first.ToolEvents)
	for id := range eventIDs(second.ToolEvents) {
		got[id] = true
	}
	for id := range eventIDs(whole.ToolEvents) {
		if !got[id] {
			t.Errorf("incremental parse LOST event %q that a single pass captured", id)
		}
	}
	if len(got) != len(eventIDs(whole.ToolEvents)) {
		t.Errorf("incremental distinct SourceEventIDs = %d, single-pass = %d",
			len(got), len(eventIDs(whole.ToolEvents)))
	}
	// Specifically: the four tool calls that lived on the truncated line.
	for _, id := range []string{
		"update_topic__dfj3iatp", "read_file__d7cqxa69",
		"write_file__1aj33uk0", "run_shell_command__5kbzhaf5",
	} {
		if !got[id] {
			t.Errorf("tool call %q from the deferred record was never captured", id)
		}
	}
}

// TestJSONLTerminatedMalformedInteriorLineStillAdvances is the other
// half of F9: the deferral rule must not wedge the file on a record
// that IS '\n'-terminated and genuinely corrupt.
func TestJSONLTerminatedMalformedInteriorLineStillAdvances(t *testing.T) {
	body := []byte(`{"type":"session_metadata","sessionId":"s","startTime":"2026-04-04T00:00:00Z"}` + "\n" +
		`{corrupt but terminated` + "\n" +
		`{"type":"user","id":"u1","content":[{"type":"text","text":"after the corruption"}]}` + "\n")
	dst := writeIncremental(t, "abc/chats/session-corrupt.jsonl", body)
	res, err := New().ParseSessionFile(context.Background(), dst, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if res.NewOffset != int64(len(body)) {
		t.Fatalf("cursor = %d, want %d — a terminated corrupt record must be skipped, not deferred",
			res.NewOffset, len(body))
	}
	var sawUser bool
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionUserPrompt {
			sawUser = true
		}
	}
	if !sawUser {
		t.Fatalf("post-corruption user line missed; events=%v", summary(res.ToolEvents))
	}
}

// TestCRLFCursorArithmetic pins the byte-exact cursor the reader change
// brought with it: the old `len(token)+1` under-counted one byte per
// CRLF line (bufio.ScanLines strips "\r\n" but the arithmetic added
// back only the "\n"), so the cursor drifted backwards a byte per line
// and re-parsed garbage prefixes.
func TestCRLFCursorArithmetic(t *testing.T) {
	body := []byte(`{"type":"session_metadata","sessionId":"s","startTime":"2026-04-04T00:00:00Z"}` + "\r\n" +
		`{"type":"user","id":"u1","content":[{"type":"text","text":"hi"}]}` + "\r\n")
	dst := writeIncremental(t, "abc/chats/session-crlf.jsonl", body)
	res, err := New().ParseSessionFile(context.Background(), dst, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if res.NewOffset != int64(len(body)) {
		t.Fatalf("CRLF cursor = %d, want %d (file size)", res.NewOffset, len(body))
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("unexpected warnings on a clean CRLF file: %v", res.Warnings)
	}
}

// TestCrossBatchFunctionResponseEmitsOutcomeUpdate pins finding F7 for
// the shape where it IS reachable: the legacy `functionCall` content
// part, whose result arrives on a SEPARATE later record. When a parse
// window ends between the two, in-memory joining necessarily misses and
// the output used to be lost forever. The adapter now emits an
// ActionOutcomeUpdate keyed by the SAME (SourceFile, SourceEventID) the
// call row was inserted under, which the store applies after the batch.
func TestCrossBatchFunctionResponseEmitsOutcomeUpdate(t *testing.T) {
	full, err := os.ReadFile("../../../testdata/gemini/session-jsonl-singleturn.jsonl")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	// Line 3 carries the functionCall; line 4 carries its functionResponse.
	splitAt := lineEnd(t, full, 3)
	dst := writeIncremental(t, "abc/chats/session-split.jsonl", full[:splitAt])

	first, err := New().ParseSessionFile(context.Background(), dst, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	if first.NewOffset != splitAt {
		t.Fatalf("cursor after batch 1 = %d, want %d", first.NewOffset, splitAt)
	}
	var callRow *models.ToolEvent
	for i := range first.ToolEvents {
		if first.ToolEvents[i].SourceEventID == "call-jsonl-1" {
			callRow = &first.ToolEvents[i]
		}
	}
	if callRow == nil {
		t.Fatalf("batch 1 did not emit the tool call row; events=%v", summary(first.ToolEvents))
	}
	if callRow.ToolOutput != "" {
		t.Fatalf("batch 1 call row already carries output %q — the legacy shape cannot", callRow.ToolOutput)
	}

	// The response append lands in a LATER window; the call is NOT
	// re-appended (the proposed event-record format is append-only).
	if err := os.WriteFile(dst, full, 0o644); err != nil {
		t.Fatalf("complete write: %v", err)
	}
	second, err := New().ParseSessionFile(context.Background(), dst, first.NewOffset)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	for _, ev := range second.ToolEvents {
		if ev.SourceEventID == "call-jsonl-1" {
			t.Fatalf("batch 2 re-emitted the call row — the premise of the finding is wrong")
		}
	}
	if len(second.OutcomeUpdates) != 1 {
		t.Fatalf("OutcomeUpdates = %d, want 1 — the cross-batch result was DROPPED: %+v",
			len(second.OutcomeUpdates), second.OutcomeUpdates)
	}
	up := second.OutcomeUpdates[0]
	if up.SourceFile != dst || up.SourceEventID != "call-jsonl-1" {
		t.Errorf("outcome key = (%q,%q), want (%q,%q) — must match the call row's upsert key",
			up.SourceFile, up.SourceEventID, dst, "call-jsonl-1")
	}
	if !strings.Contains(up.ToolOutput, "hi") {
		t.Errorf("outcome output = %q, want it to carry the tool result", up.ToolOutput)
	}
	if up.SuccessKnown {
		t.Errorf("SuccessKnown must stay false — a functionResponse part reports no verdict")
	}
}

// TestSameBatchFunctionResponseStillJoinsInMemory guards the F7 fix
// against over-firing: when the call IS in the batch the join stays
// in-memory and no outcome update is emitted.
func TestSameBatchFunctionResponseStillJoinsInMemory(t *testing.T) {
	dst := writeFixture(t, "abc/chats/session-onepass.jsonl", "../../../testdata/gemini/session-jsonl-singleturn.jsonl")
	res, err := New().ParseSessionFile(context.Background(), dst, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.OutcomeUpdates) != 0 {
		t.Fatalf("single-pass parse emitted %d outcome updates, want 0: %+v",
			len(res.OutcomeUpdates), res.OutcomeUpdates)
	}
	var joined bool
	for _, ev := range res.ToolEvents {
		if ev.SourceEventID == "call-jsonl-1" && strings.Contains(ev.ToolOutput, "hi") {
			joined = true
		}
	}
	if !joined {
		t.Fatalf("in-batch join regressed; events=%v", summary(res.ToolEvents))
	}
}

// TestLiveShapeEmbedsResultOnEveryCall documents WHY F7 is unreachable
// for the live top-level `toolCalls` shape, and pins the invariant that
// makes it so. gemini-cli writes the `toolCalls` array only once the
// calls RESOLVE (the earlier append of the same assistant message
// carries no `toolCalls` key at all), and every entry embeds its own
// result — so the follow-up user-role functionResponse record is a
// REDUNDANT duplicate, and a parse window splitting the two loses
// nothing. Verified across the whole live corpus (8 sessions, 17 calls,
// 2026-06-26 → 2026-07-31): 17/17 embed a result, including the one
// status="error" call whose response carries an `error` key and no
// `output`. If this pin ever fails, the live shape has started
// persisting unresolved calls and the cross-batch fallback above
// becomes load-bearing for it too.
func TestLiveShapeEmbedsResultOnEveryCall(t *testing.T) {
	body, err := os.ReadFile("../../../testdata/gemini/session-live-toolcalls.jsonl")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var calls int
	for _, raw := range bytes.Split(body, []byte("\n")) {
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		var line rawJSONL
		if err := json.Unmarshal(raw, &line); err != nil {
			continue
		}
		for _, tc := range line.ToolCalls {
			calls++
			if callPending(tc.Status) {
				t.Errorf("call %q persisted with NON-TERMINAL status %q — the live shape is no longer resolve-only",
					tc.ID, tc.Status)
			}
			if tc.outputText() == "" {
				t.Errorf("call %q (status %q) carries NO embedded result — cross-batch loss is now reachable for the live shape",
					tc.ID, tc.Status)
			}
		}
	}
	if calls != 5 {
		t.Fatalf("live fixture tool calls = %d, want 5", calls)
	}
}

// TestNonTerminalThenFailedAppendCorrectsSuccess pins finding F8 across
// the CLI's double-append: a call snapshotted mid-flight and re-appended
// resolved must (a) not be filed as a measured success while pending,
// and (b) end success=false with a NON-EMPTY error_message — the store's
// asymmetric 1 → 0 self-heal (internal/store/store.go insertActionSQL)
// is gated on that evidence, so an empty ErrorMessage makes the
// correction structurally impossible.
//
// The two appends are SYNTHESIZED, not a live capture: gemini-cli's
// on-disk corpus only ever shows terminal statuses (see
// TestLiveShapeEmbedsResultOnEveryCall). The statuses used are its own
// CoreToolCallStatus values.
func TestNonTerminalThenFailedAppendCorrectsSuccess(t *testing.T) {
	const header = `{"sessionId":"s","projectHash":"h","startTime":"2026-07-31T11:00:00.000Z","kind":"chat"}` + "\n"
	const executing = `{"type":"gemini","id":"m1","timestamp":"2026-07-31T11:00:01.000Z","model":"gemini-3-pro",` +
		`"content":"","toolCalls":[{"id":"read_file__zz1","name":"read_file","args":{"absolute_path":"/tmp/nope.txt"},` +
		`"status":"executing","timestamp":"2026-07-31T11:00:01.000Z"}]}` + "\n"
	const failed = `{"type":"gemini","id":"m1","timestamp":"2026-07-31T11:00:02.000Z","model":"gemini-3-pro",` +
		`"content":"","toolCalls":[{"id":"read_file__zz1","name":"read_file","args":{"absolute_path":"/tmp/nope.txt"},` +
		`"status":"error","timestamp":"2026-07-31T11:00:02.000Z",` +
		`"result":[{"functionResponse":{"id":"read_file__zz1","name":"read_file",` +
		`"response":{"error":"File not found: /tmp/nope.txt"}}}]}]}` + "\n"

	find := func(t *testing.T, res adapter.ParseResult) models.ToolEvent {
		t.Helper()
		for _, ev := range res.ToolEvents {
			if ev.SourceEventID == "read_file__zz1" {
				return ev
			}
		}
		t.Fatalf("call row not emitted; events=%v", summary(res.ToolEvents))
		return models.ToolEvent{}
	}

	dst := writeIncremental(t, "gemini/chats/session-status.jsonl", []byte(header+executing))
	first, err := New().ParseSessionFile(context.Background(), dst, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	pending := find(t, first)
	if !pending.Success {
		t.Errorf("non-terminal snapshot Success = false, want true (optimistic placeholder)")
	}
	if !pending.OutcomePending {
		t.Errorf("non-terminal snapshot OutcomePending = false — an unobserved outcome would be filed as a measured success")
	}
	if pending.ErrorMessage != "" {
		t.Errorf("non-terminal snapshot ErrorMessage = %q, want empty", pending.ErrorMessage)
	}

	if err := os.WriteFile(dst, []byte(header+executing+failed), 0o644); err != nil {
		t.Fatalf("append: %v", err)
	}
	second, err := New().ParseSessionFile(context.Background(), dst, first.NewOffset)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	resolved := find(t, second)
	if resolved.SourceEventID != pending.SourceEventID || resolved.SourceFile != pending.SourceFile {
		t.Fatalf("re-append upsert key drifted: (%q,%q) vs (%q,%q)",
			resolved.SourceFile, resolved.SourceEventID, pending.SourceFile, pending.SourceEventID)
	}
	if resolved.Success {
		t.Errorf("resolved status=error row Success = true, want false")
	}
	if resolved.OutcomePending {
		t.Errorf("resolved row still OutcomePending — a terminal status is a measured outcome")
	}
	if resolved.ErrorMessage == "" {
		t.Fatalf("resolved failure carries NO ErrorMessage — the store's evidence-gated success 1 -> 0 flip can never fire")
	}
	if !strings.Contains(resolved.ErrorMessage, "File not found") {
		t.Errorf("ErrorMessage = %q, want the CLI's own error body", resolved.ErrorMessage)
	}
	if resolved.ToolOutput == "" {
		t.Errorf("resolved failure carries no output; the error body must still be readable")
	}
}

// TestFailedCallWithoutErrorBodyStillCarriesEvidence covers the fallback
// leg of F8: a failure the CLI reported with no `error` key must still
// produce a non-empty ErrorMessage, or the store flip stays dead.
func TestFailedCallWithoutErrorBodyStillCarriesEvidence(t *testing.T) {
	cases := []struct {
		name string
		call liveToolCall
		want string
	}{
		{"error body present", liveToolCall{
			ID: "c1", Name: "read_file", Status: "error",
			Result: []liveToolResult{{FunctionResponse: &legacyFnResp{
				ID: "c1", Response: map[string]any{"error": "boom"},
			}}},
		}, "boom"},
		{"structured error body", liveToolCall{
			ID: "c2", Name: "read_file", Status: "error",
			Result: []liveToolResult{{FunctionResponse: &legacyFnResp{
				ID: "c2", Response: map[string]any{"error": map[string]any{"message": "nested"}},
			}}},
		}, "nested"},
		{
			"no result at all",
			liveToolCall{ID: "c3", Name: "read_file", Status: "cancelled"},
			"status cancelled",
		},
		{"result but no error key", liveToolCall{
			ID: "c4", Name: "read_file", Status: "error",
			Result: []liveToolResult{{FunctionResponse: &legacyFnResp{
				ID: "c4", Response: map[string]any{"output": "partial"},
			}}},
		}, "status error"},
	}
	a := New()
	st := &sessionState{SessionID: "s", ProjectRoot: "/p"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := a.toolCallEvent("/p/f.jsonl", rawLegacyMsg{ID: "m1"}, 0, time.Time{}, st, tc.call.normalize(), "", "m1")
			if ev.Success {
				t.Fatalf("Success = true for status %q", tc.call.Status)
			}
			if ev.ErrorMessage == "" {
				t.Fatalf("ErrorMessage empty — store success 1 -> 0 flip is gated on it")
			}
			if !strings.Contains(ev.ErrorMessage, tc.want) {
				t.Errorf("ErrorMessage = %q, want it to contain %q", ev.ErrorMessage, tc.want)
			}
		})
	}
}

// TestSuccessfulCallCarriesNoErrorMessage is the negative half: the
// evidence gate only works if a SUCCESS never carries error text (the
// store would otherwise accept a bogus downgrade).
func TestSuccessfulCallCarriesNoErrorMessage(t *testing.T) {
	dst := writeFixture(t, "gemini/chats/session-ok.jsonl", "../../../testdata/gemini/session-live-toolcalls.jsonl")
	res, err := New().ParseSessionFile(context.Background(), dst, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	for _, ev := range res.ToolEvents {
		if ev.Success && ev.ErrorMessage != "" {
			t.Errorf("successful row %q carries ErrorMessage %q", ev.SourceEventID, ev.ErrorMessage)
		}
		if ev.OutcomePending {
			t.Errorf("terminal-status row %q marked OutcomePending", ev.SourceEventID)
		}
	}
}
