package dirac

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// copyFixture copies testdata/dirac/<layout>/data into a temp dir and
// returns (tasksRoot, dataDir).
func copyFixture(t *testing.T, layout string) (string, string) {
	t.Helper()
	src := filepath.Join("..", "..", "..", "testdata", "dirac", layout, "data")
	dst := filepath.Join(t.TempDir(), ".dirac", "data")
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		out := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(out, b, 0o644)
	})
	if err != nil {
		t.Fatalf("copy fixture: %v", err)
	}
	return filepath.Join(dst, "tasks"), dst
}

func parseAll(t *testing.T, a *Adapter, path string) adapter.ParseResult {
	t.Helper()
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return res
}

type tokenSums struct{ in, out, cr, cw, rs int64 }

func sumTokens(evs []models.TokenEvent) tokenSums {
	var s tokenSums
	for _, e := range evs {
		s.in += e.InputTokens
		s.out += e.OutputTokens
		s.cr += e.CacheReadTokens
		s.cw += e.CacheCreationTokens
		s.rs += e.ReasoningTokens
	}
	return s
}

func rawNames(evs []models.ToolEvent) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.RawToolName + "/" + e.ActionType
	}
	return out
}

// TestParseLiveFixtures replays the operator's anonymized real sessions
// (one per OS) and pins counts, token arithmetic against the task's own
// taskHistory totals, and the per-session stamps.
func TestParseLiveFixtures(t *testing.T) {
	cases := []struct {
		layout    string
		taskID    string
		model     string
		actions   []string
		sums      tokenSums
		firstOut  int64
		firstRs   int64
		rootSuffx string
	}{
		{
			layout: "linux", taskID: "1792563515376", model: "gpt-5.6-luna",
			actions: []string{
				"dirac.user_prompt/user_prompt",
				"write_to_file/write_file",
				"execute_command/run_command",
				"write_to_file/write_file",
				"execute_command/run_command",
				"execute_command/run_command",
				"respond.complete/task_complete",
			},
			// taskHistory: tokensIn 9817, tokensOut 517 (= output + reasoning,
			// OpenAI output ⊇ reasoning), cacheReads 16256.
			sums:     tokenSums{in: 9817, out: 517 - 247, cr: 16256, cw: 0, rs: 247},
			firstOut: 35, firstRs: 132,
			rootSuffx: "home/user/project",
		},
		{
			layout: "windows", taskID: "1792563501436", model: "gpt-6-luna",
			actions: []string{
				"dirac.user_prompt/user_prompt",
				"execute_command/run_command",
				"respond.complete/task_complete",
			},
			sums:     tokenSums{in: 4610, out: 219, cr: 3968},
			firstOut: 157, firstRs: 0,
			rootSuffx: "Users/user/project",
		},
	}
	for _, tc := range cases {
		t.Run(tc.layout, func(t *testing.T) {
			root, _ := copyFixture(t, tc.layout)
			a := NewWithOptions(nil, root)
			path := filepath.Join(root, tc.taskID, opsName)
			if !a.IsSessionFile(path) {
				t.Fatalf("IsSessionFile(%s) = false", path)
			}
			res := parseAll(t, a, path)
			if got := rawNames(res.ToolEvents); strings.Join(got, ",") != strings.Join(tc.actions, ",") {
				t.Fatalf("actions:\n got %v\nwant %v", got, tc.actions)
			}
			if len(res.Warnings) != 0 {
				t.Errorf("warnings: %v", res.Warnings)
			}
			if got := sumTokens(res.TokenEvents); got != tc.sums {
				t.Errorf("token sums = %+v, want %+v", got, tc.sums)
			}
			if res.TokenEvents[0].OutputTokens != tc.firstOut || res.TokenEvents[0].ReasoningTokens != tc.firstRs {
				t.Errorf("first token row out/rs = %d/%d, want %d/%d", res.TokenEvents[0].OutputTokens,
					res.TokenEvents[0].ReasoningTokens, tc.firstOut, tc.firstRs)
			}
			if len(res.CacheObservations) != len(res.TokenEvents) {
				t.Errorf("cache observations = %d, want %d", len(res.CacheObservations), len(res.TokenEvents))
			}
			for _, e := range res.ToolEvents {
				if e.SessionID != tc.taskID || e.Tool != models.ToolDirac || e.Model != tc.model {
					t.Errorf("event %s: session=%q tool=%q model=%q", e.SourceEventID, e.SessionID, e.Tool, e.Model)
				}
				if e.SourceFile != path {
					t.Errorf("SourceFile = %q, want %q", e.SourceFile, path)
				}
				if e.OutcomePending {
					t.Errorf("%s left OutcomePending", e.RawToolName)
				}
				if !strings.HasSuffix(filepath.ToSlash(e.ProjectRoot), tc.rootSuffx) {
					t.Errorf("ProjectRoot = %q, want suffix %q", e.ProjectRoot, tc.rootSuffx)
				}
			}
			for _, k := range res.TokenEvents {
				if k.Model != tc.model || k.Source != models.TokenSourceJSONL || k.Reliability != models.ReliabilityApproximate {
					t.Errorf("token row %s: model=%q source=%q rel=%q", k.SourceEventID, k.Model, k.Source, k.Reliability)
				}
			}
			wantSurf := []models.SessionSurface{{SessionID: tc.taskID, Surface: models.SurfaceCLI, SurfaceHost: "dirac-cli"}}
			if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0] != wantSurf[0] {
				t.Errorf("surfaces = %+v, want %+v", res.SessionSurfaces, wantSurf)
			}
			if len(res.SessionToolVersions) != 1 || res.SessionToolVersions[0].Version != "0.5.22" {
				t.Errorf("tool versions = %+v", res.SessionToolVersions)
			}
		})
	}
}

// TestParseIsDeterministic: a second full parse yields identical ids.
func TestParseIsDeterministic(t *testing.T) {
	root, _ := copyFixture(t, "linux")
	a := NewWithOptions(nil, root)
	path := filepath.Join(root, "1792563515376", opsName)
	first, second := parseAll(t, a, path), parseAll(t, a, path)
	ids := func(r adapter.ParseResult) string {
		var b strings.Builder
		for _, e := range r.ToolEvents {
			b.WriteString(e.SourceEventID + "|")
		}
		for _, e := range r.TokenEvents {
			b.WriteString(e.SourceEventID + "|")
		}
		return b.String()
	}
	if ids(first) != ids(second) {
		t.Fatalf("ids differ:\n%s\n%s", ids(first), ids(second))
	}
	seen := map[string]bool{}
	for _, e := range first.ToolEvents {
		if seen[e.SourceEventID] {
			t.Errorf("duplicate SourceEventID %s", e.SourceEventID)
		}
		seen[e.SourceEventID] = true
	}
}

// TestResumeEmitsOutcomeUpdate: a tool_result whose call was persisted
// by an earlier window becomes an ActionOutcomeUpdate keyed by the call
// id; the earlier window flags the call OutcomePending.
func TestResumeEmitsOutcomeUpdate(t *testing.T) {
	root, _ := copyFixture(t, "linux")
	a := NewWithOptions(nil, root)
	path := filepath.Join(root, "1792563515376", opsName)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(body), "\n")
	cut := int64(len(lines[0]) + len(lines[1])) // after the first assistant message
	if err := os.WriteFile(path, []byte(lines[0]+lines[1]), 0o644); err != nil {
		t.Fatal(err)
	}
	first := parseAll(t, a, path)
	if first.NewOffset != cut {
		t.Fatalf("NewOffset = %d, want %d", first.NewOffset, cut)
	}
	var callID string
	for _, e := range first.ToolEvents {
		if e.RawToolName == "write_to_file" {
			callID = e.SourceEventID
			if !e.OutcomePending {
				t.Error("unpaired call not flagged OutcomePending")
			}
		}
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := a.ParseSessionFile(context.Background(), path, cut)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.OutcomeUpdates) == 0 || second.OutcomeUpdates[0].SourceEventID != callID ||
		!second.OutcomeUpdates[0].SuccessKnown || !second.OutcomeUpdates[0].Success {
		t.Fatalf("outcome updates = %+v, want success for %s", second.OutcomeUpdates, callID)
	}
	if second.NewOffset != int64(len(body)) {
		t.Errorf("NewOffset = %d, want %d", second.NewOffset, len(body))
	}
}

// writeTask builds a synthetic task dir under a fresh tasks root.
func writeTask(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), ".dirac", "data", "tasks")
	dir := filepath.Join(root, "100")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root, filepath.Join(dir, opsName)
}

func jsonLine(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

func userMsg(ts int64, blocks ...map[string]any) map[string]any {
	return map[string]any{"role": "user", "ts": ts, "content": blocks}
}

func asstMsg(id string, ts int64, provider string, prompt, completion, cached int64, blocks ...map[string]any) map[string]any {
	return map[string]any{
		"role": "assistant", "id": id, "ts": ts, "content": blocks,
		"modelInfo": map[string]any{"modelId": "claude-sonnet-4-6", "providerId": provider, "mode": "act"},
		"metrics":   map[string]any{"tokens": map[string]any{"prompt": prompt, "completion": completion, "cached": cached}, "cost": 0},
	}
}

func toolUse(id, name string, input map[string]any) map[string]any {
	return map[string]any{"type": "tool_use", "id": id, "name": name, "input": input}
}

func toolResult(id, content string) map[string]any {
	return map[string]any{"type": "tool_result", "tool_use_id": id, "content": content}
}

func text(s string) map[string]any { return map[string]any{"type": "text", "text": s} }

// TestArchivesResetAndRotation: archived history is replayed on a parse
// from 0; a `reset` that re-lists earlier messages does not duplicate
// them; a cursor past EOF (rotation) re-reads from 0.
func TestArchivesResetAndRotation(t *testing.T) {
	m1 := userMsg(1000, text("<task>do it</task>"))
	m2 := asstMsg("resp_a", 2000, "anthropic", 100, 10, 0, toolUse("t1", "read_file", map[string]any{"paths": []string{"a.go"}}))
	m3 := userMsg(3000, toolResult("t1", "contents"))
	m4 := asstMsg("resp_b", 4000, "anthropic", 50, 5, 100, toolUse("t2", "execute_command", map[string]any{"commands": []string{"go test"}}))
	m5 := userMsg(5000, toolResult("t2", "--- Output for 'go test' ---\nCommand failed with exit code 1.\nFAIL"))
	archive := jsonLine(t, map[string]any{"offset": 0, "type": "append_message", "message": m1}) +
		jsonLine(t, map[string]any{"offset": 1, "type": "append_message", "message": m2})
	live := jsonLine(t, map[string]any{"offset": 2, "type": "append_message", "message": m3}) +
		jsonLine(t, map[string]any{"offset": 3, "type": "reset", "messages": []any{m1, m2, m3}}) +
		jsonLine(t, map[string]any{"offset": 4, "type": "append_message", "message": m4}) +
		jsonLine(t, map[string]any{"offset": 5, "type": "append_message", "message": m5})
	root, path := writeTask(t, map[string]string{
		archivePrefix + "1": archive,
		opsName:             live,
	})
	a := NewWithOptions(nil, root)
	res := parseAll(t, a, path)
	want := "dirac.user_prompt/user_prompt,read_file/read_file,execute_command/run_command"
	if got := strings.Join(rawNames(res.ToolEvents), ","); got != want {
		t.Fatalf("actions = %s, want %s", got, want)
	}
	if len(res.TokenEvents) != 2 {
		t.Fatalf("token rows = %d, want 2", len(res.TokenEvents))
	}
	if !res.ToolEvents[1].Success || res.ToolEvents[2].Success {
		t.Errorf("success read=%v exec=%v, want true/false", res.ToolEvents[1].Success, res.ToolEvents[2].Success)
	}
	if res.ToolEvents[0].ProjectRoot != placeholderRoot {
		t.Errorf("ProjectRoot = %q, want placeholder (no taskHistory)", res.ToolEvents[0].ProjectRoot)
	}
	// Rotation: a stale cursor past EOF re-reads the (new, shorter) file.
	rot, err := a.ParseSessionFile(context.Background(), path, int64(len(live))+999)
	if err != nil {
		t.Fatal(err)
	}
	if rot.NewOffset != int64(len(live)) || len(rot.ToolEvents) != 3 {
		t.Errorf("rotation parse: offset=%d events=%d", rot.NewOffset, len(rot.ToolEvents))
	}
	// Unchanged file at EOF: nothing.
	idle, err := a.ParseSessionFile(context.Background(), path, int64(len(live)))
	if err != nil || len(idle.ToolEvents) != 0 || idle.NewOffset != int64(len(live)) {
		t.Errorf("idle parse = %+v, %v", idle, err)
	}
}

// TestPartialLineDeferredAndMalformedSkipped: a partial trailing line is
// left for the next parse; a malformed complete line warns and advances.
func TestPartialLineDeferredAndMalformedSkipped(t *testing.T) {
	good := jsonLine(t, map[string]any{"offset": 0, "type": "append_message", "message": userMsg(1, text("<task>hi</task>"))})
	body := "{not json}\r\n" + good + `{"offset":1,"type":"append_mess`
	root, path := writeTask(t, map[string]string{opsName: body})
	res := parseAll(t, NewWithOptions(nil, root), path)
	if want := int64(len("{not json}\r\n") + len(good)); res.NewOffset != want {
		t.Errorf("NewOffset = %d, want %d", res.NewOffset, want)
	}
	if len(res.Warnings) != 1 || len(res.ToolEvents) != 1 {
		t.Errorf("warnings=%v events=%d", res.Warnings, len(res.ToolEvents))
	}
}

// TestTokenSplitFromUIMessages: the ui api_status split (cache writes vs
// reads) wins over the conflated metrics; without a ui log the metrics
// fallback books `cached` as reads.
func TestTokenSplitFromUIMessages(t *testing.T) {
	ops := jsonLine(t, map[string]any{
		"offset": 0, "type": "append_message",
		"message": asstMsg("resp_x", 10, "anthropic", 100, 40, 300, text("hello")),
	})
	ui := jsonLine(t, map[string]any{"offset": 0, "type": "create", "message": map[string]any{
		"id": "api-req-1", "ts": 1, "content": map[string]any{"type": "api_status", "status": map[string]any{"id": "api-req-1"}},
	}}) +
		jsonLine(t, map[string]any{
			"offset": 1, "type": "patch_api_status", "id": "api-req-1",
			"patch": map[string]any{"tokensIn": 100, "tokensOut": 40, "reasoningTokens": 0, "cacheWrites": 200, "cacheReads": 100},
		})
	cases := []struct {
		name   string
		files  map[string]string
		cr, cw int64
	}{
		{"split from ui", map[string]string{opsName: ops, uiOpsName: ui}, 100, 200},
		{"metrics fallback", map[string]string{opsName: ops}, 300, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, path := writeTask(t, tc.files)
			res := parseAll(t, NewWithOptions(nil, root), path)
			if len(res.TokenEvents) != 1 {
				t.Fatalf("token rows = %d", len(res.TokenEvents))
			}
			k := res.TokenEvents[0]
			if k.InputTokens != 100 || k.OutputTokens != 40 || k.CacheReadTokens != tc.cr || k.CacheCreationTokens != tc.cw {
				t.Errorf("got in=%d out=%d cr=%d cw=%d, want 100/40/%d/%d", k.InputTokens, k.OutputTokens,
					k.CacheReadTokens, k.CacheCreationTokens, tc.cr, tc.cw)
			}
			if got := res.ToolEvents[0].ActionType; got != models.ActionAssistantMessage {
				t.Errorf("text block action = %q", got)
			}
		})
	}
}

func i64(v int64) *int64 { return &v }

func TestResolveSplit(t *testing.T) {
	m := rawMetricTokens{Prompt: 10, Completion: 100, Cached: 5}
	st := &uiStatus{TokensIn: i64(10), TokensOut: i64(100), ReasoningTokens: i64(30), CacheReads: i64(5), CacheWrites: i64(0)}
	cases := []struct {
		provider     string
		status       *uiStatus
		out, rs, crd int64
	}{
		{"openai-codex", st, 70, 30, 5},
		{"OpenAI", st, 70, 30, 5},
		{"gemini", st, 100, 30, 5},
		{"anthropic", st, 100, 0, 5},
		{"some-new-provider", st, 100, 0, 5},
		{"openai-codex", nil, 100, 0, 5},
		{"openai-codex", &uiStatus{TokensIn: i64(10), TokensOut: i64(5), ReasoningTokens: i64(9)}, 0, 5, 0},
	}
	for _, tc := range cases {
		got := resolveSplit(m, tc.status, tc.provider)
		if got.output != tc.out || got.reasoning != tc.rs || got.cacheRead != tc.crd {
			t.Errorf("%s: out/rs/cr = %d/%d/%d, want %d/%d/%d", tc.provider, got.output, got.reasoning, got.cacheRead, tc.out, tc.rs, tc.crd)
		}
	}
}

func TestClassifyTool(t *testing.T) {
	cases := []struct {
		name, input, raw, action string
		ok                       bool
	}{
		{"execute_command", `{"commands":["ls"]}`, "execute_command", models.ActionRunCommand, true},
		{"edit_ast", `{}`, "edit_ast", models.ActionEditFile, true},
		{"use_subagents", `{}`, "use_subagents", models.ActionSpawnSubagent, true},
		{"respond", `{"operation":"complete","text":"done"}`, "respond.complete", models.ActionTaskComplete, true},
		{"respond", `{"operation":"question","text":"?"}`, "respond.question", models.ActionAskUser, true},
		{"respond", `{"operation":"progress","text":"x"}`, "respond.progress", models.ActionAssistantMessage, true},
		{"respond", `{"operation":"plan","text":"x"}`, "respond.plan", models.ActionAssistantMessage, true},
		{"respond", `{"operation":"weird"}`, "respond", models.ActionAssistantMessage, false},
		{"my_custom_tool", `{}`, "my_custom_tool", models.ActionUnknown, false},
	}
	for _, tc := range cases {
		raw, action, ok := classifyTool(tc.name, json.RawMessage(tc.input))
		if raw != tc.raw || action != tc.action || ok != tc.ok {
			t.Errorf("classifyTool(%s,%s) = %s/%s/%v, want %s/%s/%v", tc.name, tc.input, raw, action, ok, tc.raw, tc.action, tc.ok)
		}
	}
}

func TestResultFailed(t *testing.T) {
	cases := []struct {
		raw, text string
		isErr     bool
		want      bool
	}{
		{"execute_command", "--- Output for 'x' ---\nCommand executed successfully (exit code 0).\nOutput:\nok", false, false},
		{"execute_command", "--- Output for 'x' ---\nCommand failed with exit code 2.", false, true},
		{"execute_command", "--- Output for 'x' ---\nCommand executed successfully (exit code 0).\nOutput:\necho Command failed here", false, false},
		{"read_file", "The tool execution failed with the following error:\n<error>nope</error>", false, true},
		{"write_to_file", "The user denied this operation.", false, true},
		{"read_file", "Command failed", false, false},
		{"read_file", "anything", true, true},
	}
	for _, tc := range cases {
		if got := resultFailed(tc.raw, tc.isErr, tc.text); got != tc.want {
			t.Errorf("resultFailed(%s,%q) = %v, want %v", tc.raw, tc.text, got, tc.want)
		}
	}
}

func TestTargetsAndAuthoredBytes(t *testing.T) {
	cases := []struct {
		name, input, target string
		bytes               int64
	}{
		{"execute_command", `{"commands":["a","b"]}`, "a && b", 0},
		{"execute_command", `{"commands":null,"script":"echo hi"}`, "echo hi", 0},
		{"read_file", `{"paths":["x.go","y.go"]}`, "x.go", 0},
		{"search_files", `{"paths":["."],"regex":"foo"}`, "foo", 0},
		{"write_to_file", `{"path":"a.py","content":"print(1)\n"}`, "a.py", 9},
		{"edit_file", `{"files":[{"path":"b.go","edits":[{"text":"abc"},{"text":"de"}]}]}`, "b.go", 5},
		{"edit_ast", `{"operation":"replace","targets":[{"path":"c.go","symbol":"F","replacement":"func F(){}"}]}`, "c.go", 10},
		{"edit_ast", `{"operation":"rename","targets":[{"path":"c.go","symbol":"F","replacement":"G"}]}`, "c.go", 0},
		{"use_skill", `{"skill_name":"pdf"}`, "pdf", 0},
	}
	for _, tc := range cases {
		in := decodeToolInput(json.RawMessage(tc.input))
		if got, _ := targetFor(tc.name, in); got != tc.target {
			t.Errorf("targetFor(%s) = %q, want %q", tc.name, got, tc.target)
		}
		if got := authoredBytes(tc.name, in); got != tc.bytes {
			t.Errorf("authoredBytes(%s) = %d, want %d", tc.name, got, tc.bytes)
		}
	}
}

func TestExtractPrompt(t *testing.T) {
	cases := map[string]string{
		"<task>\nbuild it\n</task>":                      "build it",
		"<feedback>more</feedback>":                      "more",
		"<answer>yes</answer>":                           "yes",
		"<steering_message>stop</steering_message>":      "stop",
		"<environment_details>x</environment_details>":   "",
		"[TASK RESUMPTION] This task was interrupted ok": "",
	}
	for in, want := range cases {
		if got := extractPrompt(in); got != want {
			t.Errorf("extractPrompt(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestUserAttachmentsAndScrub: an image-only user turn still yields a
// prompt row with presence-only attachment metadata, and secrets in a
// command never reach a row.
func TestUserAttachmentsAndScrub(t *testing.T) {
	const secret = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd"
	img := map[string]any{"type": "image", "source": map[string]any{"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="}}
	body := jsonLine(t, map[string]any{"offset": 0, "type": "append_message", "message": userMsg(1, img)}) +
		jsonLine(t, map[string]any{"offset": 1, "type": "append_message", "message": asstMsg("resp_s", 2, "openai", 1, 1, 0,
			toolUse("c1", "execute_command", map[string]any{"commands": []string{"OPENAI_API_KEY=" + secret + " ./run"}}))})
	root, path := writeTask(t, map[string]string{opsName: body})
	res := parseAll(t, NewWithOptions(nil, root), path)
	if len(res.ToolEvents) != 2 {
		t.Fatalf("events = %d", len(res.ToolEvents))
	}
	p := res.ToolEvents[0]
	if p.ActionType != models.ActionUserPrompt || len(p.UserAttachments) != 1 ||
		p.UserAttachments[0] != (models.UserAttachment{Kind: "image", MediaType: "image/png"}) {
		t.Errorf("prompt row = %+v", p)
	}
	for _, e := range res.ToolEvents {
		for _, s := range []string{e.Target, e.RawToolInput, e.ToolOutput} {
			if strings.Contains(s, secret) || strings.Contains(s, "iVBOR") {
				t.Errorf("leaked secret/bytes in %q", s)
			}
		}
	}
}

func TestIsSessionFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".dirac", "data", "tasks")
	a := NewWithOptions(nil, root)
	task := filepath.Join(root, "1792563515376")
	cases := []struct {
		path string
		want bool
	}{
		{filepath.Join(task, opsName), true},
		{filepath.Join(task, uiOpsName), false},
		{filepath.Join(task, "api_conversation_history.baseline.jsonl"), false},
		{filepath.Join(task, archivePrefix+"41"), false},
		{filepath.Join(task, taskMetadataName), false},
		{filepath.Join(task, "subagents", "run-1", "transcript.md"), false},
		{filepath.Join(root, opsName), false},
		{filepath.Join(filepath.Dir(root), "secrets.json"), false},
		{filepath.Join(string(filepath.Separator)+"tmp", "foreign", ".dirac", "data", "tasks", "1", opsName), false},
		{filepath.Join(t.TempDir(), ".cline", "data", "tasks", "1", "api_conversation_history.json"), false},
	}
	for _, tc := range cases {
		if got := a.IsSessionFile(tc.path); got != tc.want {
			t.Errorf("IsSessionFile(%s) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestCursorSemantics(t *testing.T) {
	s := NewWithOptions(nil, t.TempDir()).CursorSemanticsFor("x")
	if s.Kind != adapter.CursorByteOffset || !s.StreamsFromCursor || !s.RewindsOnTruncate || !s.ActionsExpected() {
		t.Errorf("semantics = %+v", s)
	}
}

func TestDefaultRoots(t *testing.T) {
	home := t.TempDir()
	diracDir := t.TempDir()
	dataDir := t.TempDir()
	oldEnv, oldHomes := envLookup, allHomesFunc
	t.Cleanup(func() { envLookup, allHomesFunc = oldEnv, oldHomes })
	allHomesFunc = func() []crossmount.HomeRoot { return []crossmount.HomeRoot{{Path: home}, {Path: home}, {Path: ""}} }
	envLookup = func(k string) string {
		switch k {
		case "DIRAC_DIR":
			return diracDir
		case "DIRAC_DATA_DIR":
			return dataDir
		}
		return ""
	}
	got := defaultRoots()
	want := []string{
		filepath.Join(dataDir, "tasks"),
		filepath.Join(diracDir, "data", "tasks"),
		filepath.Join(home, ".dirac", "data", "tasks"),
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("defaultRoots = %v, want %v", got, want)
	}
	envLookup = func(string) string { return "" }
	if got := defaultRoots(); len(got) != 1 || got[0] != want[2] {
		t.Errorf("defaultRoots (no env) = %v", got)
	}
}

func TestIsAbsAnyOS(t *testing.T) {
	cases := map[string]bool{
		"/home/u/x":     true,
		`C:\Users\u\x`:  true,
		"c:/x":          true,
		`\\wsl$\Ubuntu`: true,
		"hello.py":      false,
		"./a":           false,
		"":              false,
		"C:":            false,
	}
	for in, want := range cases {
		if got := isAbsAnyOS(in); got != want {
			t.Errorf("isAbsAnyOS(%q) = %v, want %v", in, got, want)
		}
	}
}
