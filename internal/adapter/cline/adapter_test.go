package cline

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// copyFixture duplicates the cline fixture under a synthetic task directory
// so sessionIDFromPath resolves to a task-ID-shaped name.
func copyFixture(t *testing.T, taskID string) string {
	t.Helper()
	src := filepath.Join("..", "..", "..", "testdata", "cline", "api_conversation_history.json")
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "tasks", taskID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "api_conversation_history.json")
	if err := os.WriteFile(dst, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return dst
}

// TestScanAPIHistoryCwd_ExtractsFromEnvDetails covers the V1 fix:
// the Cline VSCode extension (v3.88.0+) no longer writes cwd as a
// top-level key on ui_messages.json — it embeds it in the first
// user message's <environment_details> block as
// `Current Working Directory (<path>)`. The adapter's
// scanAPIHistoryCwd must find that banner.
//
// Pre-fix behaviour: inferProjectContext returned "" → every emitted
// event landed with empty ProjectRoot → store.go:1058 silently
// dropped every event for the session.
func TestScanAPIHistoryCwd_ExtractsFromEnvDetails(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "windows_drive_path",
			body: `[{"role":"user","content":[{"type":"text","text":"<environment_details>\n# Current Working Directory (d:/benchmarks) Files\nfoo.md\n</environment_details>"}]}]`,
			want: "d:/benchmarks",
		},
		{
			name: "linux_absolute_path",
			body: `[{"role":"user","content":[{"type":"text","text":"# Current Working Directory (/home/me/proj) Files\n"}]}]`,
			want: "/home/me/proj",
		},
		{
			// Cline emits cwd with forward slashes in env_details (confirmed
			// against v3.88.0 on Windows-native — "d:/benchmarks" not
			// "d:\\benchmarks"). Space-in-path covered here.
			name: "forward_slash_path_with_spaces",
			body: `[{"role":"user","content":[{"type":"text","text":"Current Working Directory (D:/proj with space) Files"}]}]`,
			want: "D:/proj with space",
		},
		{
			name: "banner_absent_returns_empty",
			body: `[{"role":"user","content":[{"type":"text","text":"<task>Hi</task>"}]}]`,
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "api_conversation_history.json")
			if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			got := scanAPIHistoryCwd(p)
			if got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}

// TestInferProjectContext_PrefersEnvDetailsOverLegacyUIKey pins the
// dispatch order: the api_conversation_history.json env-details
// banner wins over a ui_messages.json top-level cwd key when both are
// present. Defends against a regression where the legacy ui-messages
// path silently steals project resolution from the canonical newer
// source.
func TestInferProjectContext_PrefersEnvDetailsOverLegacyUIKey(t *testing.T) {
	// The fixture's env-details banner names a Windows-style path
	// (d:/winner). On Windows, the adapter's path-norm leaves it as
	// `d:/winner` and the test passes. On Linux / macOS, the WSL-
	// cross-mount path-norm correctly translates `d:/winner` →
	// `/mnt/d/winner` — which is the right behaviour for an Observer
	// daemon running in WSL2 against a Windows-side Cline session,
	// but doesn't match the Windows-flavoured substring assertion.
	// Skipping the assertion on non-Windows hosts is the deterministic
	// fix: the dispatch order (env-details wins over ui_messages.cwd)
	// is the actual invariant the test was added to defend; the path
	// substring is incidental to that.
	if runtime.GOOS != "windows" {
		t.Skip("Windows-style path fixture; env-details/ui-messages dispatch order is the same on every OS — checked by TestInferProjectContext_FallsBackToUIMessagesCwd which uses an OS-agnostic path")
	}
	t.Parallel()
	dir := t.TempDir()
	apiPath := filepath.Join(dir, "api_conversation_history.json")
	uiPath := filepath.Join(dir, "ui_messages.json")
	apiBody := `[{"role":"user","content":[{"type":"text","text":"# Current Working Directory (d:/winner) Files\n"}]}]`
	uiBody := `[{"cwd": "/never/used"}]`
	if err := os.WriteFile(apiPath, []byte(apiBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(uiPath, []byte(uiBody), 0o600); err != nil {
		t.Fatal(err)
	}
	root, _, _, _ := New().inferProjectContext(apiPath)
	// git.Resolve is unlikely to find a repo at d:/winner under tests
	// — root falls through to the normalised cwd.
	if !strings.Contains(strings.ReplaceAll(root, "\\", "/"), "d:/winner") {
		t.Errorf("project root: got %q want substring d:/winner", root)
	}
}

// TestInferProjectContext_FallsBackToUIMessagesCwd confirms the
// pre-v3.88.0 sessions (no env-details banner) still resolve via the
// legacy top-level `cwd` key on ui_messages.json. Keeping this path
// alive means operators with old saved sessions don't lose
// resolution on adapter upgrades.
func TestInferProjectContext_FallsBackToUIMessagesCwd(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	apiPath := filepath.Join(dir, "api_conversation_history.json")
	uiPath := filepath.Join(dir, "ui_messages.json")
	if err := os.WriteFile(apiPath, []byte(`[{"role":"user","content":[{"type":"text","text":"<task>Hi</task>"}]}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(uiPath, []byte(`[{"ts":1,"type":"say","cwd":"/legacy/cwd"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	root, _, _, _ := New().inferProjectContext(apiPath)
	if !strings.Contains(strings.ReplaceAll(root, "\\", "/"), "/legacy/cwd") {
		t.Errorf("project root: got %q want substring /legacy/cwd", root)
	}
}

func TestParseClineTask(t *testing.T) {
	t.Parallel()
	path := copyFixture(t, "abc123")
	a := New()

	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 4 {
		t.Fatalf("tool events: %d want 4", len(res.ToolEvents))
	}

	// event 0: cline.assistant_text — emitted from the text block on the
	// first assistant message ("I'll read the middleware file first.").
	// Lands BEFORE the tool_use sibling block since blocks are iterated
	// in order and the text block precedes the tool_use in the fixture.
	e0 := res.ToolEvents[0]
	if e0.ActionType != models.ActionAssistantMessage {
		t.Errorf("e0 action: %s want assistant_message", e0.ActionType)
	}
	if e0.RawToolName != "cline.assistant_text" {
		t.Errorf("e0 raw_tool_name: %q want cline.assistant_text", e0.RawToolName)
	}
	if !strings.Contains(e0.ToolOutput, "middleware file") {
		t.Errorf("e0 tool_output: %q", e0.ToolOutput)
	}

	// event 1: read_file
	e1 := res.ToolEvents[1]
	if e1.ActionType != models.ActionReadFile {
		t.Errorf("e1: %s", e1.ActionType)
	}
	if e1.SessionID != "abc123" {
		t.Errorf("e1 session: %q", e1.SessionID)
	}
	if e1.Tool != models.ToolCline {
		t.Errorf("e1 tool: %q", e1.Tool)
	}
	if !strings.Contains(e1.Target, "auth.go") {
		t.Errorf("e1 target: %q", e1.Target)
	}
	if !strings.Contains(e1.ToolOutput, "package auth") {
		t.Errorf("e1 tool_output: %q", e1.ToolOutput)
	}

	// event 2: replace_in_file → edit_file
	if res.ToolEvents[2].ActionType != models.ActionEditFile {
		t.Errorf("e2: %s", res.ToolEvents[2].ActionType)
	}

	// event 3: execute_command → run_command, failed
	e3 := res.ToolEvents[3]
	if e3.ActionType != models.ActionRunCommand {
		t.Errorf("e3 action: %s", e3.ActionType)
	}
	if e3.Success {
		t.Error("e3 should be failure")
	}
	if !strings.Contains(e3.ErrorMessage, "FAIL") {
		t.Errorf("e3 error_message: %q", e3.ErrorMessage)
	}
	if !strings.Contains(e3.Target, "go test") {
		t.Errorf("e3 target: %q", e3.Target)
	}

	// Token event
	if len(res.TokenEvents) != 1 {
		t.Fatalf("token events: %d want 1", len(res.TokenEvents))
	}
	tk := res.TokenEvents[0]
	if tk.CacheReadTokens != 1500 {
		t.Errorf("cache read: %d", tk.CacheReadTokens)
	}
	if tk.Reliability != models.ReliabilityApproximate {
		t.Errorf("reliability: %q", tk.Reliability)
	}

	// NewOffset should equal file size.
	fi, _ := os.Stat(path)
	if res.NewOffset != fi.Size() {
		t.Errorf("offset: got %d want %d", res.NewOffset, fi.Size())
	}
}

// TestParseClineMetricsTokens389 pins the Cline 3.89.2 token-capture path:
// non-Anthropic providers (providerId="cline") drop the Anthropic-shape
// `usage` block and carry per-message `metrics` + `modelInfo` instead.
// Grounded against live session 1782474409049 (2026-06-26): metrics.tokens.
// prompt is NET input (it equals ui_messages api_req_started `tokensIn`, NOT
// a gross prompt total), cached == cacheReads, completion == tokensOut. The
// model comes from modelInfo.modelId (the legacy top-level `model` is gone).
func TestParseClineMetricsTokens389(t *testing.T) {
	t.Parallel()
	body := `[
	  {"role":"user","ts":1782474409820,"content":[{"type":"text","text":"hi"}]},
	  {"role":"assistant","ts":1782474409840,"modelInfo":{"modelId":"stepfun/step-3.7-flash","providerId":"cline","mode":"act"},"metrics":{"tokens":{"prompt":531,"completion":163,"cached":11264},"cost":0},"content":[{"type":"text","text":"done"}]}
	]`
	dir := filepath.Join(t.TempDir(), "tasks", "1782474409049")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "api_conversation_history.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := New().ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("token events: %d want 1", len(res.TokenEvents))
	}
	tk := res.TokenEvents[0]
	if tk.InputTokens != 531 {
		t.Errorf("input: %d want 531 (net, not gross)", tk.InputTokens)
	}
	if tk.OutputTokens != 163 {
		t.Errorf("output: %d want 163", tk.OutputTokens)
	}
	if tk.CacheReadTokens != 11264 {
		t.Errorf("cacheRead: %d want 11264", tk.CacheReadTokens)
	}
	if tk.CacheCreationTokens != 0 {
		t.Errorf("cacheCreation: %d want 0 (cache-write not in metrics)", tk.CacheCreationTokens)
	}
	if tk.Model != "stepfun/step-3.7-flash" {
		t.Errorf("model: %q want stepfun/step-3.7-flash (from modelInfo)", tk.Model)
	}
	// The assistant text row also gets the resolved model.
	for _, e := range res.ToolEvents {
		if e.RawToolName == "cline.assistant_text" && e.Model != "stepfun/step-3.7-flash" {
			t.Errorf("assistant_text model: %q want stepfun/step-3.7-flash", e.Model)
		}
	}
}

// TestParseClineUserPrompt pins that genuine user input (<task>/<feedback>)
// surfaces as a user_prompt row while programmatic role=user continuations
// (tool results, <environment_details>) are skipped. Grounded against live
// sessions where the real prompt is <task>-wrapped and follow-ups are
// `[tool] Result:` / `[ERROR]` text under role=user.
func TestParseClineUserPrompt(t *testing.T) {
	t.Parallel()
	body := `[
	  {"role":"user","ts":1,"content":[{"type":"text","text":"<task>\nHello\n</task>"},{"type":"text","text":"<environment_details>\n# noise\n</environment_details>"}]},
	  {"role":"assistant","ts":2,"content":[{"type":"text","text":"hi there"}]},
	  {"role":"user","ts":3,"content":[{"type":"text","text":"[list_files for '.'] Result:\nfoo.go"}]},
	  {"role":"user","ts":4,"content":[{"type":"text","text":"<feedback>\nnow do X\n</feedback>"}]}
	]`
	dir := filepath.Join(t.TempDir(), "tasks", "u1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "api_conversation_history.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := New().ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var prompts []string
	for _, e := range res.ToolEvents {
		if e.ActionType == models.ActionUserPrompt {
			prompts = append(prompts, e.Target)
			if e.RawToolName != "user_message" {
				t.Errorf("user_prompt RawToolName: %q want user_message", e.RawToolName)
			}
		}
	}
	if len(prompts) != 2 {
		t.Fatalf("user_prompt rows: %v want exactly [Hello, now do X]", prompts)
	}
	if prompts[0] != "Hello" || prompts[1] != "now do X" {
		t.Errorf("prompts = %v want [Hello, now do X]", prompts)
	}
}

// TestParseClineReasoning pins that assistant `thinking` blocks are captured
// as a standalone reasoning row (visible in the timeline) AND threaded into
// the following tool call's PrecedingReasoning. Cline 3.89.2 carries the
// chain-of-thought in a `thinking` field (not `text`); dropping it loses the
// model's decision-making lineage.
// TestParseClineImageAttachment pins the multimodal image-marker: an
// Anthropic image content block ({type:"image", source:{…}}) in a user
// turn — which would otherwise fall through the content switch silently
// — is surfaced as a marker row. The image bytes are never read/stored.
func TestParseClineImageAttachment(t *testing.T) {
	t.Parallel()
	body := `[
	  {"role":"user","ts":1,"content":[
	    {"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAA"}}
	  ]}
	]`
	dir := filepath.Join(t.TempDir(), "tasks", "img1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "api_conversation_history.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := New().ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var img *models.ToolEvent
	for i := range res.ToolEvents {
		if strings.HasSuffix(res.ToolEvents[i].RawToolName, ".image") {
			img = &res.ToolEvents[i]
		}
	}
	if img == nil {
		t.Fatalf("no <tool>.image row emitted for image block; events: %+v", res.ToolEvents)
	}
	if img.ActionType != models.ActionUserPrompt {
		t.Errorf("image ActionType = %q, want user_prompt", img.ActionType)
	}
	if img.Target != "[image attachment]" {
		t.Errorf("image Target = %q, want [image attachment]", img.Target)
	}
}

// TestParseClineReasoning pins the B3-converged behaviour (2026-07-31):
// a `thinking` block mints NO `<tool>.reasoning` row and instead reaches
// the timeline as PrecedingReasoning on the tool_use rows that follow it
// in the same message (fan-out semantics, unchanged).
func TestParseClineReasoning(t *testing.T) {
	t.Parallel()
	body := `[
	  {"role":"assistant","ts":1,"content":[
	    {"type":"thinking","thinking":"Let me think about this carefully."},
	    {"type":"text","text":"Here is my answer."},
	    {"type":"tool_use","id":"t1","name":"read_file","input":{"path":"x.go"}},
	    {"type":"tool_use","id":"t2","name":"list_files","input":{"path":"."}}
	  ]}
	]`
	dir := filepath.Join(t.TempDir(), "tasks", "r1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "api_conversation_history.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := New().ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var threaded int
	for i := range res.ToolEvents {
		ev := &res.ToolEvents[i]
		if strings.HasSuffix(ev.RawToolName, ".reasoning") {
			t.Fatalf("reasoning row minted: %+v", ev)
		}
		if ev.ActionType == models.ActionReadFile || ev.ActionType == models.ActionSearchFiles {
			if !strings.Contains(ev.PrecedingReasoning, "think about this carefully") {
				t.Errorf("%s PrecedingReasoning = %q, want the thinking text", ev.ActionType, ev.PrecedingReasoning)
			}
			threaded++
		}
	}
	// FAN-OUT: one thinking block, two tool calls, both carry it.
	if threaded != 2 {
		t.Fatalf("expected both tool rows to carry the reasoning; got %d (%+v)", threaded, res.ToolEvents)
	}
}

// TestParseRetaggedReasoningMintsNoRow pins that the row-suppression
// holds for the RETAGS of this parser too, not just for cline. The raw
// name was built by string concat from the resolved toolID
// (`toolID + ".reasoning"`), so roo-code and legacy kilo-code minted the
// same phantom class through the same site — a name-literal-only guard
// would miss all three.
func TestParseRetaggedReasoningMintsNoRow(t *testing.T) {
	t.Parallel()
	body := `[
	  {"role":"assistant","ts":1,"content":[
	    {"type":"thinking","thinking":"Roo is thinking."},
	    {"type":"tool_use","id":"t1","name":"read_file","input":{"path":"x.go"}}
	  ]}
	]`
	dir := filepath.Join(t.TempDir(), "rooveterinaryinc.roo-cline", "tasks", "roo-1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "api_conversation_history.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := New().ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var tool *models.ToolEvent
	for i := range res.ToolEvents {
		ev := &res.ToolEvents[i]
		if ev.Tool != models.ToolRooCode {
			t.Fatalf("row not retagged: %+v", ev)
		}
		if strings.HasSuffix(ev.RawToolName, ".reasoning") {
			t.Fatalf("roo-code reasoning row minted: %+v", ev)
		}
		if ev.ActionType == models.ActionReadFile {
			tool = ev
		}
	}
	if tool == nil {
		t.Fatalf("no read_file row; events=%+v", res.ToolEvents)
	}
	if !strings.Contains(tool.PrecedingReasoning, "Roo is thinking.") {
		t.Errorf("roo-code tool PrecedingReasoning = %q", tool.PrecedingReasoning)
	}
}

func TestIncrementalSkipsUnchanged(t *testing.T) {
	t.Parallel()
	path := copyFixture(t, "abc123")
	a := New()

	res1, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Second call with offset = prior size should short-circuit.
	res2, err := a.ParseSessionFile(context.Background(), path, res1.NewOffset)
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.ToolEvents) != 0 {
		t.Errorf("expected zero events when file unchanged, got %d", len(res2.ToolEvents))
	}
}

func TestToolInferredFromPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path string
		want string
	}{
		{"/x/saoudrizwan.claude-dev/tasks/abc/api_conversation_history.json", models.ToolCline},
		{"/x/saoudrizwan.cline-nightly/tasks/abc/api_conversation_history.json", models.ToolCline},
		{"/x/rooveterinaryinc.roo-cline/tasks/abc/api_conversation_history.json", models.ToolRooCode},
		{"/x/zoocodeorganization.zoo-code/tasks/abc/api_conversation_history.json", models.ToolZooCode},
		{"/x/other/tasks/abc/api_conversation_history.json", models.ToolCline},
	}
	for _, tc := range cases {
		if got := toolFromPath(tc.path); got != tc.want {
			t.Errorf("toolFromPath(%q) = %q want %q", tc.path, got, tc.want)
		}
	}
}

func TestIsSessionFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	a := NewWithOptions(nil, []string{root})
	if !a.IsSessionFile(filepath.Join(root, "abc", "api_conversation_history.json")) {
		t.Error("api_conversation_history.json under watch root should match")
	}
	if a.IsSessionFile(filepath.Join(root, "abc", "ui_messages.json")) {
		t.Error("ui_messages.json should NOT match")
	}
	// v1.4.51 invariant: shape-correct file outside watch root rejected.
	if a.IsSessionFile("/tmp/foreign/tasks/abc/api_conversation_history.json") {
		t.Error("api_conversation_history.json outside watch root must NOT match")
	}
}

// TestAssistantTextMultipleBlocksAndRoles pins per-text-block emission for
// role=assistant messages and the suppression of text blocks on
// role=user messages (those carry tool_result content, not assistant text).
// Also verifies that empty / whitespace-only text blocks don't emit rows.
func TestAssistantTextMultipleBlocksAndRoles(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "tasks", "asst-test")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "api_conversation_history.json")
	body := `[
{"role":"user","ts":1713000000000,"content":"Question?"},
{"role":"assistant","ts":1713000001000,"model":"claude-sonnet-4-20250514","content":[
  {"type":"text","text":"First thought."},
  {"type":"text","text":""},
  {"type":"text","text":"  "},
  {"type":"text","text":"Second thought."}
]},
{"role":"user","ts":1713000002000,"content":[{"type":"text","text":"Should not emit — wrong role."}]}
]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	a := New()
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 2 {
		t.Fatalf("tool events: %d want 2", len(res.ToolEvents))
	}
	for i, want := range []string{"First thought.", "Second thought."} {
		ev := res.ToolEvents[i]
		if ev.RawToolName != "cline.assistant_text" {
			t.Errorf("event[%d] raw_tool_name = %q, want cline.assistant_text", i, ev.RawToolName)
		}
		if ev.ActionType != models.ActionAssistantMessage {
			t.Errorf("event[%d] action = %q, want assistant_message", i, ev.ActionType)
		}
		if ev.Target != want {
			t.Errorf("event[%d] target = %q, want %q", i, ev.Target, want)
		}
		if ev.ToolOutput != want {
			t.Errorf("event[%d] tool_output = %q, want %q", i, ev.ToolOutput, want)
		}
		if !ev.Success {
			t.Errorf("event[%d] should be success", i)
		}
	}
	// SourceEventIDs must be content-derived (re-parse stable) AND distinct
	// between the two text blocks on the same message.
	if res.ToolEvents[0].SourceEventID == res.ToolEvents[1].SourceEventID {
		t.Errorf("SourceEventIDs collide: %q", res.ToolEvents[0].SourceEventID)
	}

	// Re-parse: SourceEventIDs must be byte-identical (UPSERT dedup).
	res2, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile (re-parse): %v", err)
	}
	if len(res2.ToolEvents) != 2 {
		t.Fatalf("re-parse events: %d want 2", len(res2.ToolEvents))
	}
	for i := range res.ToolEvents {
		if res.ToolEvents[i].SourceEventID != res2.ToolEvents[i].SourceEventID {
			t.Errorf("event[%d] SourceEventID drift: first=%q second=%q",
				i, res.ToolEvents[i].SourceEventID, res2.ToolEvents[i].SourceEventID)
		}
	}
}

// TestAssistantTextRooCodeRawToolName pins the toolID-derived RawToolName
// for the Roo Code variant of the same JSON-array format. The path matcher
// resolves Roo Code paths to ToolRooCode, which then prefixes the
// RawToolName as "roo-code.assistant_text".
func TestAssistantTextRooCodeRawToolName(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "rooveterinaryinc.roo-cline", "tasks", "roo-asst")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "api_conversation_history.json")
	body := `[
{"role":"assistant","ts":1713000000000,"model":"claude-sonnet-4-20250514","content":[
  {"type":"text","text":"Roo says hi."}
]}
]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	a := New()
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 1 {
		t.Fatalf("tool events: %d want 1", len(res.ToolEvents))
	}
	ev := res.ToolEvents[0]
	if ev.Tool != models.ToolRooCode {
		t.Errorf("tool = %q, want roo-code", ev.Tool)
	}
	if ev.RawToolName != "roo-code.assistant_text" {
		t.Errorf("raw_tool_name = %q, want roo-code.assistant_text", ev.RawToolName)
	}
}
