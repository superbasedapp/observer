package commandcode

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// interface conformance — the watcher only accepts adapter.Adapter.
var _ adapter.Adapter = (*Adapter)(nil)

// fixturePath resolves a file in testdata/commandcode/.
func fixturePath(name string) string {
	return filepath.Join("..", "..", "..", "testdata", "commandcode", name)
}

// stageTranscript writes body into a watch-rooted
// `<root>/.commandcode/projects/<slug>/<session>.jsonl` and returns the
// transcript path plus an adapter rooted at the projects dir. Sidecars
// (name → contents) are written beside it.
func stageTranscript(t *testing.T, session, body string, sidecars map[string]string) (string, *Adapter) {
	t.Helper()
	root := t.TempDir()
	projects := filepath.Join(root, ".commandcode", "projects")
	dir := filepath.Join(projects, "home-user-project")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, session+".jsonl")
	if err := os.WriteFile(dst, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, content := range sidecars {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dst, NewWithOptions(nil, projects)
}

// stageFixture stages a testdata fixture (transcript + its meta sidecar
// when one exists) and parses it end to end.
func stageFixture(t *testing.T, fixture string) (adapter.ParseResult, string) {
	t.Helper()
	body, err := os.ReadFile(fixturePath(fixture))
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixture, err)
	}
	sidecars := map[string]string{}
	metaName := strings.TrimSuffix(fixture, ".jsonl") + ".meta.json"
	if meta, err := os.ReadFile(fixturePath(metaName)); err == nil {
		sidecars["session.meta.json"] = string(meta)
	}
	path, a := stageTranscript(t, "session", string(body), sidecars)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return res, path
}

func TestIsSessionFile(t *testing.T) {
	root := "/home/u/.commandcode/projects"
	a := NewWithOptions(nil, root)
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"canonical transcript", "/home/u/.commandcode/projects/home-u-proj/c2bfd6d1.jsonl", true},
		{"windows-encoded slug", "/home/u/.commandcode/projects/c-users-user-example-project/27354697.jsonl", true},
		{"checkpoints sidecar rejected", "/home/u/.commandcode/projects/home-u-proj/c2bfd6d1.checkpoints.jsonl", false},
		{"meta sidecar rejected", "/home/u/.commandcode/projects/home-u-proj/c2bfd6d1.meta.json", false},
		{"per-project config rejected", "/home/u/.commandcode/projects/home-u-proj/config.json", false},
		{"top-level history rejected", "/home/u/.commandcode/history.jsonl", false},
		{"auth.json rejected", "/home/u/.commandcode/auth.json", false},
		{"shape ok but outside watch root", "/other/.commandcode/projects/p/x.jsonl", false},
		{"under root but not a projects path", "/home/u/.commandcode/projects2/p/x.jsonl", false},
		{"windows separators", `\home\u\.commandcode\projects\p\x.jsonl`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.IsSessionFile(tc.path); got != tc.want {
				t.Fatalf("IsSessionFile(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestWatchPathsDefaultShape(t *testing.T) {
	roots := New().WatchPaths()
	if len(roots) == 0 {
		t.Fatal("no default watch roots")
	}
	for _, r := range roots {
		if !strings.HasSuffix(filepath.ToSlash(r), "/.commandcode/projects") {
			t.Errorf("watch root %q does not end in .commandcode/projects", r)
		}
	}
}

func TestParseLinuxSessionFixture(t *testing.T) {
	res, path := stageFixture(t, "session-sample.jsonl")

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.NewOffset != fi.Size() {
		t.Errorf("NewOffset = %d, want EOF %d", res.NewOffset, fi.Size())
	}

	// Session identity comes from the header line, not the filename stem.
	for _, ev := range res.ToolEvents {
		if ev.SessionID != "c2bfd6d1-cc09-4661-ab19-164580a1323e" {
			t.Fatalf("session id = %q, want the header uuid", ev.SessionID)
		}
		if ev.Tool != models.ToolCommandCode {
			t.Fatalf("tool = %q", ev.Tool)
		}
		if ev.ProjectRoot != "/home/user/project" {
			t.Errorf("project root = %q, want /home/user/project (inline cwd, not the slug)", ev.ProjectRoot)
		}
	}

	byAction := map[string]int{}
	for _, ev := range res.ToolEvents {
		byAction[ev.ActionType]++
	}
	want := map[string]int{
		models.ActionSessionStart:     1,
		models.ActionUserPrompt:       2, // two text prompts; the third user line is tool results
		models.ActionAssistantMessage: 3,
		models.ActionReadFile:         2,
	}
	for action, n := range want {
		if byAction[action] != n {
			t.Errorf("action %q count = %d, want %d (all: %v)", action, byAction[action], n, byAction)
		}
	}

	// tool_use / tool_result pairing: both read_file calls get their
	// output stamped from the following user tool_result message.
	var reads []models.ToolEvent
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionReadFile {
			reads = append(reads, ev)
		}
	}
	if len(reads) != 2 {
		t.Fatalf("read_file events = %d, want 2", len(reads))
	}
	if reads[0].Target != "/home/user/project/README.md" {
		t.Errorf("target = %q, want the file_path input", reads[0].Target)
	}
	if reads[0].SourceEventID != "tool:chatcmpl-tool-a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1" {
		t.Errorf("SourceEventID = %q, want the chatcmpl tool id", reads[0].SourceEventID)
	}
	if !strings.Contains(reads[0].ToolOutput, "Example Project") {
		t.Errorf("tool output not stamped from tool_result: %q", reads[0].ToolOutput)
	}
	if !strings.Contains(reads[1].ToolOutput, "example-project") {
		t.Errorf("second tool output not stamped: %q", reads[1].ToolOutput)
	}
	for _, ev := range reads {
		if !ev.Success {
			t.Errorf("read_file %q should be success (is_error absent)", ev.SourceEventID)
		}
		if ev.Model != "poolside/laguna-s-2.1-free" {
			t.Errorf("tool model = %q, want the outer record model", ev.Model)
		}
		if ev.MessageID != "9c2f5a11-1234-4a11-9abc-1234567890ab" {
			t.Errorf("MessageID = %q, want meta.messageId", ev.MessageID)
		}
	}

	// Three assistant turns carry usage → three token events.
	if len(res.TokenEvents) != 3 {
		t.Fatalf("token events = %d, want 3", len(res.TokenEvents))
	}
	cases := []struct {
		gross, cacheRead, netInput, output int64
	}{
		{28168, 7424, 20744, 10},
		{28194, 28160, 34, 75},
		{33186, 0, 33186, 195},
	}
	for i, want := range cases {
		got := res.TokenEvents[i]
		if got.InputTokens != want.netInput {
			t.Errorf("turn %d net input = %d, want %d (%d gross − %d cacheRead)",
				i+1, got.InputTokens, want.netInput, want.gross, want.cacheRead)
		}
		if got.CacheReadTokens != want.cacheRead {
			t.Errorf("turn %d cacheRead = %d, want %d", i+1, got.CacheReadTokens, want.cacheRead)
		}
		if got.OutputTokens != want.output {
			t.Errorf("turn %d output = %d, want %d", i+1, got.OutputTokens, want.output)
		}
		if got.Source != models.TokenSourceJSONL || got.Reliability != models.ReliabilityApproximate {
			t.Errorf("turn %d source/reliability = %q/%q", i+1, got.Source, got.Reliability)
		}
		if got.Model != "poolside/laguna-s-2.1-free" {
			t.Errorf("turn %d model = %q", i+1, got.Model)
		}
		if got.EstimatedCostUSD != 0 {
			t.Errorf("turn %d cost = %v, want 0 (free model reports a genuine $0)", i+1, got.EstimatedCostUSD)
		}
	}
	if res.TokenEvents[0].SourceEventID != "tok:e5f6a7b8" {
		t.Errorf("token SourceEventID = %q, want tok:<line id>", res.TokenEvents[0].SourceEventID)
	}
}

func TestParseWindowsSessionFixture(t *testing.T) {
	res, _ := stageFixture(t, "windows-session-sample.jsonl")

	// read_directory is the second grounded tool name and normalizes to
	// search_files.
	var dirEv *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].RawToolName == "read_directory" {
			dirEv = &res.ToolEvents[i]
		}
	}
	if dirEv == nil {
		t.Fatal("read_directory event not captured")
	}
	if dirEv.ActionType != models.ActionSearchFiles {
		t.Errorf("read_directory mapped to %q, want %q", dirEv.ActionType, models.ActionSearchFiles)
	}

	// The Windows-origin cwd must be translated before git.Resolve —
	// a raw `C:\...` string reaching git.Resolve would get the observer's
	// own cwd prefixed onto it.
	for _, ev := range res.ToolEvents {
		if ev.ProjectRoot == "" {
			continue
		}
		if strings.Contains(ev.ProjectRoot, `\`) || strings.HasPrefix(ev.ProjectRoot, "C:") {
			t.Fatalf("project root not translated: %q", ev.ProjectRoot)
		}
		if !strings.Contains(ev.ProjectRoot, "example-project") {
			t.Errorf("project root = %q, want a path containing example-project", ev.ProjectRoot)
		}
	}

	if len(res.TokenEvents) != 3 {
		t.Fatalf("token events = %d, want 3", len(res.TokenEvents))
	}
	// 29400 gross − 29376 cacheRead = 24 net.
	if got := res.TokenEvents[1].InputTokens; got != 24 {
		t.Errorf("net input = %d, want 24", got)
	}
}

func TestUnknownToolNameTolerated(t *testing.T) {
	body := header("s1", "/home/user/project") + "\n" +
		assistantToolUse("m1", "chatcmpl-tool-zz", "quantum_refactor", `{"path":"/home/user/project/x.go"}`) + "\n" +
		toolResult("m2", "chatcmpl-tool-zz", "done") + "\n"
	path, a := stageTranscript(t, "s1", body, nil)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var ev *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].RawToolName == "quantum_refactor" {
			ev = &res.ToolEvents[i]
		}
	}
	if ev == nil {
		t.Fatal("unknown tool call was DROPPED; it must still be emitted")
	}
	if ev.ActionType != models.ActionUnknown {
		t.Errorf("action = %q, want %q", ev.ActionType, models.ActionUnknown)
	}
	if ev.Target != "/home/user/project/x.go" {
		t.Errorf("target = %q, want the path input", ev.Target)
	}
	if len(res.Warnings) == 0 || !strings.Contains(res.Warnings[0], "quantum_refactor") {
		t.Errorf("warnings = %v, want one naming the unmapped tool", res.Warnings)
	}
}

func TestMCPToolNameMapped(t *testing.T) {
	body := header("s1", "/home/user/project") + "\n" +
		assistantToolUse("m1", "chatcmpl-tool-mm", "mcp__github__list_issues", `{"query":"open"}`) + "\n" +
		toolResult("m2", "chatcmpl-tool-mm", "3 issues") + "\n"
	path, a := stageTranscript(t, "s1", body, nil)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ToolEvents) < 2 {
		t.Fatalf("tool events = %d", len(res.ToolEvents))
	}
	ev := res.ToolEvents[len(res.ToolEvents)-1]
	if ev.ActionType != models.ActionMCPCall {
		t.Errorf("action = %q, want mcp_call", ev.ActionType)
	}
	if ev.RawToolName != "mcp__github__list_issues" {
		t.Errorf("raw name not preserved: %q", ev.RawToolName)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("MCP name should not warn: %v", res.Warnings)
	}
}

func TestToolResultErrorMarksFailure(t *testing.T) {
	body := header("s1", "/home/user/project") + "\n" +
		assistantToolUse("m1", "chatcmpl-tool-ee", "read_file", `{"file_path":"/nope"}`) + "\n" +
		`{"type":"message","id":"m2","parentId":"m1","timestamp":"2026-07-28T18:40:24.945Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"chatcmpl-tool-ee","content":[{"type":"text","text":"ENOENT: no such file"}],"is_error":true}],"meta":{"source":"tool","messageId":"uuid-2"}}}` + "\n"
	path, a := stageTranscript(t, "s1", body, nil)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	var ev *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].RawToolName == "read_file" {
			ev = &res.ToolEvents[i]
		}
	}
	if ev == nil {
		t.Fatal("read_file event missing")
	}
	if ev.Success {
		t.Error("is_error:true must mark the event failed")
	}
	if !strings.Contains(ev.ErrorMessage, "ENOENT") {
		t.Errorf("error message = %q", ev.ErrorMessage)
	}
}

func TestMalformedAndTruncatedLines(t *testing.T) {
	good := header("s1", "/home/user/project")
	prompt := userText("m1", "first prompt")
	truncated := `{"type":"message","id":"m9","message":{"role":"user","content":[{"type":"text","te`
	body := good + "\n" + "{not json at all}\n" + "\n" + prompt + "\n" + truncated

	path, a := stageTranscript(t, "s1", body, nil)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	// The good records either side of the garbage line both parse.
	var sawStart, sawPrompt bool
	for _, ev := range res.ToolEvents {
		switch ev.ActionType {
		case models.ActionSessionStart:
			sawStart = true
		case models.ActionUserPrompt:
			sawPrompt = true
			if ev.Target != "first prompt" {
				t.Errorf("prompt target = %q", ev.Target)
			}
		}
	}
	if !sawStart || !sawPrompt {
		t.Errorf("recovery failed: start=%v prompt=%v", sawStart, sawPrompt)
	}
	if len(res.Warnings) == 0 {
		t.Error("malformed line produced no warning")
	}
	// The truncated final line must NOT be consumed — the cursor stops
	// at its first byte so the next parse re-reads it whole.
	wantOffset := int64(len(body) - len(truncated))
	if res.NewOffset != wantOffset {
		t.Fatalf("NewOffset = %d, want %d (before the partial trailing line)", res.NewOffset, wantOffset)
	}

	// Complete the partial line; the resumed parse must pick it up.
	completed := body + `xt":"second prompt"}]}}` + "\n"
	if err := os.WriteFile(path, []byte(completed), 0o600); err != nil {
		t.Fatal(err)
	}
	res2, err := a.ParseSessionFile(context.Background(), path, res.NewOffset)
	if err != nil {
		t.Fatal(err)
	}
	if res2.NewOffset != int64(len(completed)) {
		t.Errorf("resumed NewOffset = %d, want %d", res2.NewOffset, len(completed))
	}
	var sawSecond bool
	for _, ev := range res2.ToolEvents {
		if ev.Target == "second prompt" {
			sawSecond = true
		}
	}
	if !sawSecond {
		t.Errorf("completed line not parsed on resume: %+v", res2.ToolEvents)
	}
}

func TestCursorResume(t *testing.T) {
	body, err := os.ReadFile(fixturePath("session-sample.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	path, a := stageTranscript(t, "session", string(body), nil)

	full, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Resume just past the first three lines (header + prompt + first
	// assistant turn).
	lines := strings.SplitAfter(string(body), "\n")
	var mid int64
	for i := 0; i < 3; i++ {
		mid += int64(len(lines[i]))
	}
	res, err := a.ParseSessionFile(context.Background(), path, mid)
	if err != nil {
		t.Fatal(err)
	}
	if res.NewOffset != int64(len(body)) {
		t.Errorf("resume NewOffset = %d, want %d", res.NewOffset, len(body))
	}
	if got := len(res.ToolEvents) + len(res.TokenEvents); got >= len(full.ToolEvents)+len(full.TokenEvents) {
		t.Errorf("resume emitted %d events, full emitted %d — no resumption",
			got, len(full.ToolEvents)+len(full.TokenEvents))
	}
	// No duplicate session-start on a resumed parse.
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionSessionStart {
			t.Error("session_start re-emitted on a resumed parse")
		}
	}
	// The header is still re-read, so session id + project root survive.
	if len(res.ToolEvents) == 0 {
		t.Fatal("resume produced no tool events")
	}
	for _, ev := range res.ToolEvents {
		if ev.SessionID != "c2bfd6d1-cc09-4661-ab19-164580a1323e" {
			t.Errorf("resumed session id = %q", ev.SessionID)
		}
		if ev.ProjectRoot != "/home/user/project" {
			t.Errorf("resumed project root = %q", ev.ProjectRoot)
		}
	}
	// Idempotency: SourceEventIDs from the resumed range are a subset of
	// the full-parse ids, so re-parsing can't create new rows.
	fullIDs := map[string]bool{}
	for _, ev := range full.ToolEvents {
		fullIDs[ev.SourceEventID] = true
	}
	for _, ev := range res.ToolEvents {
		if !fullIDs[ev.SourceEventID] {
			t.Errorf("resumed event id %q not produced by the full parse", ev.SourceEventID)
		}
	}
}

func TestSessionIDFallsBackToFilenameStem(t *testing.T) {
	// A transcript whose header line is missing (truncated / rotated file)
	// still attributes to the session named by the filename.
	body := userText("m1", "orphan prompt") + "\n"
	path, a := stageTranscript(t, "deadbeef-0000-4000-8000-000000000001", body, nil)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ToolEvents) != 1 {
		t.Fatalf("tool events = %d, want 1", len(res.ToolEvents))
	}
	if res.ToolEvents[0].SessionID != "deadbeef-0000-4000-8000-000000000001" {
		t.Errorf("session id = %q, want the filename stem", res.ToolEvents[0].SessionID)
	}
	if res.ToolEvents[0].ProjectRoot != "" {
		t.Errorf("project root = %q, want empty (no header cwd, never fabricated from the lossy slug)",
			res.ToolEvents[0].ProjectRoot)
	}
}

func TestMetaSidecarModelFallbackAndAbsence(t *testing.T) {
	// A usage-bearing record with NO inline model picks up the sidecar's.
	line := `{"type":"message","id":"m1","timestamp":"2026-07-28T18:30:05.900Z","message":{"role":"assistant","content":[{"type":"text","text":"ok"}],"meta":{"source":"model","messageId":"uuid-1"}},"usage":{"inputTokens":100,"outputTokens":5,"cacheReadTokens":0,"cacheWriteTokens":0,"costUsd":0.25}}`
	body := header("s1", "/home/user/project") + "\n" + line + "\n"

	t.Run("sidecar present", func(t *testing.T) {
		path, a := stageTranscript(t, "s1", body, map[string]string{
			"s1.meta.json": `{"traceIds":["aa"],"model":"deepseek/deepseek-v4-pro","title":"Greeting"}`,
		})
		res, err := a.ParseSessionFile(context.Background(), path, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.TokenEvents) != 1 {
			t.Fatalf("token events = %d", len(res.TokenEvents))
		}
		if res.TokenEvents[0].Model != "deepseek/deepseek-v4-pro" {
			t.Errorf("model = %q, want the sidecar fallback", res.TokenEvents[0].Model)
		}
		if res.TokenEvents[0].EstimatedCostUSD != 0.25 {
			t.Errorf("cost = %v, want the provider-reported 0.25", res.TokenEvents[0].EstimatedCostUSD)
		}
	})

	t.Run("sidecar missing", func(t *testing.T) {
		path, a := stageTranscript(t, "s1", body, nil)
		res, err := a.ParseSessionFile(context.Background(), path, 0)
		if err != nil {
			t.Fatalf("a missing meta.json must not fail the parse: %v", err)
		}
		if len(res.TokenEvents) != 1 {
			t.Fatalf("token events = %d", len(res.TokenEvents))
		}
		if res.TokenEvents[0].Model != "" {
			t.Errorf("model = %q, want empty — never fabricated", res.TokenEvents[0].Model)
		}
	})

	t.Run("sidecar malformed", func(t *testing.T) {
		path, a := stageTranscript(t, "s1", body, map[string]string{"s1.meta.json": "{not json"})
		if _, err := a.ParseSessionFile(context.Background(), path, 0); err != nil {
			t.Fatalf("a malformed meta.json must not fail the parse: %v", err)
		}
	})
}

func TestZeroUsageEmitsNoTokenRow(t *testing.T) {
	line := `{"type":"message","id":"m1","timestamp":"2026-07-28T18:30:05.900Z","message":{"role":"assistant","content":[{"type":"text","text":"ok"}],"meta":{"source":"model"}},"usage":{"inputTokens":0,"outputTokens":0,"cacheReadTokens":0,"cacheWriteTokens":0,"costUsd":0}}`
	path, a := stageTranscript(t, "s1", header("s1", "/home/user/project")+"\n"+line+"\n", nil)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.TokenEvents) != 0 {
		t.Errorf("all-zero usage produced %d phantom token rows", len(res.TokenEvents))
	}
}

func TestScrubbing(t *testing.T) {
	// The credential patterns are assembled by concatenation so no
	// literal secret-shaped string appears in this source file.
	prefix := "gh" + "p_"
	pat := prefix + strings.Repeat("A1b2C3d4", 4)
	keyName := "api" + "_" + "key"

	body := header("s1", "/home/user/project") + "\n" +
		userText("m1", "deploy with "+pat) + "\n" +
		assistantToolUse("m2", "chatcmpl-tool-ss", "read_file",
			`{"file_path":"/home/user/project/.env","`+keyName+`":"`+pat+`"}`) + "\n" +
		`{"type":"message","id":"m3","timestamp":"2026-07-28T18:40:24.945Z","message":{"role":"user",` +
		`"content":[{"type":"tool_result","tool_use_id":"chatcmpl-tool-ss","content":[{"type":"text",` +
		`"text":"` + pat + `"}]}],"meta":{"source":"tool"}}}` + "\n"

	path, a := stageTranscript(t, "s1", body, nil)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ToolEvents) == 0 {
		t.Fatal("no events parsed")
	}
	for _, ev := range res.ToolEvents {
		for field, val := range map[string]string{
			"Target": ev.Target, "RawToolInput": ev.RawToolInput,
			"ToolOutput": ev.ToolOutput, "ErrorMessage": ev.ErrorMessage,
		} {
			if strings.Contains(val, prefix) {
				t.Errorf("%s leaked the credential verbatim: %q", field, val)
			}
		}
	}
	var sawRedaction bool
	for _, ev := range res.ToolEvents {
		if strings.Contains(ev.RawToolInput, scrub.Redacted) ||
			strings.Contains(ev.ToolOutput, scrub.Redacted) {
			sawRedaction = true
		}
	}
	if !sawRedaction {
		t.Error("no redaction marker anywhere - scrubbing did not run")
	}
}

func TestThinkingBlockBecomesPrecedingReasoning(t *testing.T) {
	line := `{"type":"message","id":"m1","timestamp":"2026-07-28T18:30:05.900Z","message":{"role":"assistant","content":[{"type":"thinking","thinking":"I should read the README first."},{"type":"tool_use","id":"chatcmpl-tool-tt","name":"read_file","input":{"file_path":"/home/user/project/README.md"}}],"meta":{"source":"model"}},"model":"claude-opus-5"}`
	body := header("s1", "/home/user/project") + "\n" + line + "\n" +
		toolResult("m2", "chatcmpl-tool-tt", "# README") + "\n"
	path, a := stageTranscript(t, "s1", body, nil)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	var ev *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].RawToolName == "read_file" {
			ev = &res.ToolEvents[i]
		}
	}
	if ev == nil {
		t.Fatal("tool event missing")
	}
	if !strings.Contains(ev.PrecedingReasoning, "README first") {
		t.Errorf("PrecedingReasoning = %q", ev.PrecedingReasoning)
	}
	if ev.Model != "claude-opus-5" {
		t.Errorf("model = %q — a bare (non-vendor-prefixed) paid model string must pass through verbatim", ev.Model)
	}
}

func TestBareStringContentTolerated(t *testing.T) {
	line := `{"type":"message","id":"m1","timestamp":"2026-07-28T18:30:03.113Z","message":{"role":"user","content":"plain string prompt","meta":{"source":"user"}}}`
	path, a := stageTranscript(t, "s1", header("s1", "/home/user/project")+"\n"+line+"\n", nil)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	var sawPrompt bool
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionUserPrompt && ev.Target == "plain string prompt" {
			sawPrompt = true
		}
	}
	if !sawPrompt {
		t.Errorf("bare-string content dropped the whole line: %+v", res.ToolEvents)
	}
}

func TestCRLFTranscript(t *testing.T) {
	body := header("s1", "/home/user/project") + "\r\n" + userText("m1", "windows line endings") + "\r\n"
	path, a := stageTranscript(t, "s1", body, nil)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.NewOffset != int64(len(body)) {
		t.Errorf("NewOffset = %d, want %d", res.NewOffset, len(body))
	}
	var sawPrompt bool
	for _, ev := range res.ToolEvents {
		if ev.Target == "windows line endings" {
			sawPrompt = true
		}
	}
	if !sawPrompt {
		t.Error("CRLF transcript not parsed")
	}
}

func TestContextCancellation(t *testing.T) {
	path, a := stageFixtureRaw(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.ParseSessionFile(ctx, path, 0); err == nil {
		t.Error("cancelled context should abort the parse")
	}
}

// stageFixtureRaw stages the Linux fixture without parsing it.
func stageFixtureRaw(t *testing.T) (string, *Adapter) {
	t.Helper()
	body, err := os.ReadFile(fixturePath("session-sample.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return stageTranscript(t, "session", string(body), nil)
}

// --- synthetic line builders -------------------------------------------

func header(id, cwd string) string {
	return `{"type":"session","version":3,"id":"` + id +
		`","timestamp":"2026-07-28T18:29:49.718Z","cwd":"` + cwd + `"}`
}

func userText(id, text string) string {
	return `{"type":"message","id":"` + id +
		`","parentId":null,"timestamp":"2026-07-28T18:30:03.113Z","message":{"role":"user","content":[{"type":"text","text":"` +
		text + `"}],"meta":{"source":"user","messageId":"uuid-` + id + `"}}}`
}

func assistantToolUse(id, callID, name, input string) string {
	return `{"type":"message","id":"` + id +
		`","timestamp":"2026-07-28T18:38:38.100Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"` +
		callID + `","name":"` + name + `","input":` + input +
		`}],"meta":{"source":"model","messageId":"uuid-` + id + `"}},"model":"poolside/laguna-s-2.1-free"}`
}

// toolResult is the user-role record that answers a tool_use. Every
// tool-call test needs one: an unanswered trailing tool_use is DEFERRED
// (see adapter.DeferUnpairedTail), so the row only materialises once the
// outcome is on disk.
func toolResult(id, callID, text string) string {
	return `{"type":"message","id":"` + id +
		`","timestamp":"2026-07-28T18:38:39.100Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"` +
		callID + `","content":[{"type":"text","text":"` + text +
		`"}]}],"meta":{"source":"tool","messageId":"uuid-` + id + `"}}}`
}

// --- cross-tick tool_use -> tool_result pairing (adapter.DeferUnpairedTail)

// appendLine appends one more JSONL record to a staged transcript, the
// way Command Code does while a session runs.
func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
}

// toolResultError is the failed answer to a tool_use.
func toolResultError(id, callID, text string) string {
	return `{"type":"message","id":"` + id +
		`","timestamp":"2026-07-28T18:40:24.945Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"` +
		callID + `","content":[{"type":"text","text":"` + text +
		`"}],"is_error":true}],"meta":{"source":"tool","messageId":"uuid-` + id + `"}}}`
}

// TestToolResultLandsOnNextPollTick is the regression for the
// cross-parse tool_result loss. Tick N sees the tool_use but not yet its
// result; tick N+1 sees the result. The pair MUST resolve into exactly
// one action row carrying the real outcome — the store's action
// ON CONFLICT clause updates neither `success` nor `error_message`, so a
// row shipped optimistically in tick N could never be corrected.
func TestToolResultLandsOnNextPollTick(t *testing.T) {
	hdr := header("s1", "/home/user/project")
	call := assistantToolUse("m1", "chatcmpl-tool-ee", "read_file", `{"file_path":"/nope"}`)
	path, a := stageTranscript(t, "s1", hdr+"\n"+call+"\n", nil)

	res1, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("tick N: %v", err)
	}
	for _, ev := range res1.ToolEvents {
		if ev.RawToolName == "read_file" {
			t.Fatalf("tick N shipped an unanswered tool call (Success=%v, output=%q); "+
				"the outcome can never be corrected once persisted", ev.Success, ev.ToolOutput)
		}
	}
	if !res1.RetrySuggested {
		t.Error("a deferred tail must set RetrySuggested so the watcher keeps polling")
	}
	if res1.NewOffset != int64(len(hdr)+1) {
		t.Errorf("tick N NewOffset = %d, want the tool_use line start %d", res1.NewOffset, len(hdr)+1)
	}

	appendLine(t, path, toolResultError("m2", "chatcmpl-tool-ee", "ENOENT: no such file"))
	res2, err := a.ParseSessionFile(context.Background(), path, res1.NewOffset)
	if err != nil {
		t.Fatalf("tick N+1: %v", err)
	}
	var rows []models.ToolEvent
	for _, ev := range res2.ToolEvents {
		if ev.RawToolName == "read_file" {
			rows = append(rows, ev)
		}
	}
	if len(rows) != 1 {
		t.Fatalf("tick N+1 read_file rows = %d, want exactly 1", len(rows))
	}
	if rows[0].Success {
		t.Error("resumed pair kept Success=true; the is_error result was lost")
	}
	if !strings.Contains(rows[0].ErrorMessage, "ENOENT") {
		t.Errorf("ErrorMessage = %q, want the result body", rows[0].ErrorMessage)
	}
	if !strings.Contains(rows[0].ToolOutput, "ENOENT") {
		t.Errorf("ToolOutput = %q, want the result body", rows[0].ToolOutput)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if res2.NewOffset != info.Size() {
		t.Errorf("tick N+1 NewOffset = %d, want EOF %d", res2.NewOffset, info.Size())
	}
}

// TestUnpairedToolUseFlushedWhenTranscriptGoesStale pins the first
// deferral bound: an interrupted session never writes the result, so the
// call must eventually be emitted with its optimistic outcome rather
// than stalling the cursor forever.
func TestUnpairedToolUseFlushedWhenTranscriptGoesStale(t *testing.T) {
	body := header("s1", "/home/user/project") + "\n" +
		assistantToolUse("m1", "chatcmpl-tool-ee", "read_file", `{"file_path":"/nope"}`) + "\n"
	path, a := stageTranscript(t, "s1", body, nil)
	old := time.Now().Add(-2 * adapter.PendingResultGrace)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	var seen bool
	for _, ev := range res.ToolEvents {
		if ev.RawToolName == "read_file" {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("a stale unanswered call must still be emitted: %+v", res.ToolEvents)
	}
	if res.NewOffset != int64(len(body)) {
		t.Errorf("stale flush must advance the cursor to EOF: %d != %d", res.NewOffset, len(body))
	}
	if res.RetrySuggested {
		t.Error("a flushed tail must not ask for a retry")
	}
}

// TestUnpairedToolUseFlushedWhenTailGrows pins the second deferral
// bound: a transcript that has written far past an unanswered call is
// plainly not waiting on it, so ingestion must not be held back.
func TestUnpairedToolUseFlushedWhenTailGrows(t *testing.T) {
	filler := userText("m9", strings.Repeat("x", 4096))
	body := header("s1", "/home/user/project") + "\n" +
		assistantToolUse("m1", "chatcmpl-tool-ee", "read_file", `{"file_path":"/nope"}`) + "\n"
	for i := 0; i*len(filler) <= adapter.MaxDeferTailBytes; i++ {
		body += filler + "\n"
	}
	path, a := stageTranscript(t, "s1", body, nil)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	var seen bool
	for _, ev := range res.ToolEvents {
		if ev.RawToolName == "read_file" {
			seen = true
		}
	}
	if !seen {
		t.Fatal("an unanswered call far behind the write head must be flushed, not deferred")
	}
	if res.NewOffset != int64(len(body)) {
		t.Errorf("NewOffset = %d, want EOF %d", res.NewOffset, len(body))
	}
}

// TestResumedParseUsesMetaFallbackModel pins the lazy meta.json read: a
// usage record with no inline model must pick up the sidecar fallback on
// a RESUMED parse too. Reading the sidecar only at offset 0 left every
// resumed cost row modelled as "".
func TestResumedParseUsesMetaFallbackModel(t *testing.T) {
	hdr := header("s1", "/home/user/project")
	prompt := userText("m0", "hello")
	usage := `{"type":"message","id":"m1","timestamp":"2026-07-28T18:30:05.900Z","message":{"role":"assistant","content":[{"type":"text","text":"ok"}],"meta":{"source":"model","messageId":"uuid-1"}},"usage":{"inputTokens":100,"outputTokens":5,"cacheReadTokens":0,"cacheWriteTokens":0,"costUsd":0.25}}`
	body := hdr + "\n" + prompt + "\n" + usage + "\n"
	path, a := stageTranscript(t, "s1", body, map[string]string{
		"s1.meta.json": `{"traceIds":["aa"],"model":"deepseek/deepseek-v4-pro","title":"Greeting"}`,
	})

	res, err := a.ParseSessionFile(context.Background(), path, int64(len(hdr)+1+len(prompt)+1))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("token events = %d, want 1", len(res.TokenEvents))
	}
	if res.TokenEvents[0].Model != "deepseek/deepseek-v4-pro" {
		t.Errorf("resumed model = %q, want the meta.json fallback", res.TokenEvents[0].Model)
	}
}

// TestMetaSidecarSymlinkRefused pins the sidecar symlink guard. The
// `<uuid>.meta.json` path is DERIVED from the transcript name, so a
// symlink planted there would redirect the read at a file the package
// doc promises is never read — `~/.commandcode/auth.json`, the account
// credential. A symlinked sidecar must behave exactly like a missing
// one: no read, no error, no content anywhere in the emitted events.
func TestMetaSidecarSymlinkRefused(t *testing.T) {
	root := t.TempDir()
	projects := filepath.Join(root, ".commandcode", "projects")
	dir := filepath.Join(projects, "home-user-project")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	credential := filepath.Join(root, ".commandcode", "auth.json")
	liveKey := "cc_" + "live_" + "CREDENTIAL-9f2b34e3"
	if err := os.WriteFile(credential, []byte(`{"model":"`+liveKey+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	usage := `{"type":"message","id":"m1","timestamp":"2026-07-28T18:30:05.900Z","message":{"role":"assistant","content":[{"type":"text","text":"ok"}],"meta":{"source":"model"}},"usage":{"inputTokens":100,"outputTokens":5,"cacheReadTokens":0,"cacheWriteTokens":0,"costUsd":0.25}}`
	transcript := filepath.Join(dir, "s1.jsonl")
	if err := os.WriteFile(transcript, []byte(header("s1", "/home/user/project")+"\n"+usage+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(credential, filepath.Join(dir, "s1"+metaSuffix)); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	if got := sidecarModel(transcript); got != "" {
		t.Fatalf("sidecarModel followed a symlink and returned %q", got)
	}

	a := NewWithOptions(nil, projects)
	res, err := a.ParseSessionFile(context.Background(), transcript, 0)
	if err != nil {
		t.Fatalf("a symlinked sidecar must be a silent no-op, got: %v", err)
	}
	if strings.Contains(renderEvents(res), liveKey) {
		t.Error("the symlink target's contents leaked into an emitted field")
	}
}

// renderEvents flattens every string field of a parse result so a test
// can assert that a credential appears NOWHERE.
func renderEvents(res adapter.ParseResult) string {
	var b strings.Builder
	for _, ev := range res.ToolEvents {
		b.WriteString(strings.Join([]string{
			ev.Target, ev.RawToolName, ev.RawToolInput, ev.ToolOutput,
			ev.ErrorMessage, ev.PrecedingReasoning, ev.Model, ev.SourceEventID,
		}, "\x00"))
	}
	for _, ev := range res.TokenEvents {
		b.WriteString(ev.Model + "\x00" + ev.SourceEventID)
	}
	b.WriteString(strings.Join(res.Warnings, "\x00"))
	return b.String()
}
