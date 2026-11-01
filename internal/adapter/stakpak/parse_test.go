package stakpak

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestNetUsage(t *testing.T) {
	i64 := func(v int64) *int64 { return &v }
	type det = struct {
		InputTokens      *int64 `json:"input_tokens"`
		OutputTokens     *int64 `json:"output_tokens"`
		CacheReadTokens  *int64 `json:"cache_read_input_tokens"`
		CacheWriteTokens *int64 `json:"cache_write_input_tokens"`
	}
	cases := []struct {
		name                string
		u                   rawUsage
		in, out, read, wrte int64
	}{
		{"plain live shape", rawUsage{PromptTokens: 16344, CompletionTokens: 64, TotalTokens: 16408}, 16344, 64, 0, 0},
		{"details with net input", rawUsage{PromptTokens: 1000, CompletionTokens: 5, Details: &det{
			InputTokens: i64(100), CacheReadTokens: i64(850), CacheWriteTokens: i64(50),
		}}, 100, 5, 850, 50},
		{"details cache only subtracts from gross", rawUsage{PromptTokens: 1000, CompletionTokens: 5, Details: &det{
			CacheReadTokens: i64(900),
		}}, 100, 5, 900, 0},
		{"cache larger than prompt clamps at zero", rawUsage{PromptTokens: 10, CompletionTokens: 1, Details: &det{
			CacheReadTokens: i64(20),
		}}, 0, 1, 20, 0},
		{"empty details block keeps gross", rawUsage{PromptTokens: 7, CompletionTokens: 2, Details: &det{}}, 7, 2, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in, out, read, wrte := netUsage(&tc.u)
			if in != tc.in || out != tc.out || read != tc.read || wrte != tc.wrte {
				t.Errorf("netUsage = %d/%d/%d/%d, want %d/%d/%d/%d", in, out, read, wrte, tc.in, tc.out, tc.read, tc.wrte)
			}
		})
	}
}

func TestMapTool(t *testing.T) {
	cases := []struct {
		name, args, wantAction, wantTarget string
	}{
		{"run_command", `{"command":"ls -la","description":"d"}`, models.ActionRunCommand, "ls -la"},
		{"run_remote_command", `{"command":"uptime"}`, models.ActionRunCommand, "uptime"},
		{"view", `{"path":"/p","glob":"*.py"}`, models.ActionReadFile, "/p"},
		{"view", `{"glob":"*.py"}`, models.ActionReadFile, "*.py"},
		{"create", `{"path":"/p/a.py","file_text":"x"}`, models.ActionWriteFile, "/p/a.py"},
		{"str_replace", `{"path":"/p/a.py","old_str":"a","new_str":"b"}`, models.ActionEditFile, "/p/a.py"},
		{"remove", `{"path":"/p/a.py"}`, models.ActionEditFile, "/p/a.py"},
		{"local_code_search", `{"query":"foo"}`, models.ActionSearchText, "foo"},
		{"search_docs", `{"query":"terraform"}`, models.ActionWebSearch, "terraform"},
		{"load_skill", `{"name":"k8s"}`, models.ActionSkillInvoke, "k8s"},
		{"dynamic_subagent_task", `{"description":"Store notes","context":"c"}`, models.ActionSpawnSubagent, "Store notes"},
		{"wait_for_tasks", `{"task_ids":"0bweq7","timeout":120}`, models.ActionSubagentWait, "0bweq7"},
		{"get_task_details", `{"task_id":"0bweq7"}`, models.ActionAgentControl, "0bweq7"},
		{"get_all_tasks", ``, models.ActionAgentControl, "get_all_tasks"},
		{"some_new_tool", `{"path":"/x"}`, models.ActionUnknown, "/x"},
		{"  RUN_COMMAND ", `{"command":"x"}`, models.ActionRunCommand, "x"},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/"+tc.args, func(t *testing.T) {
			a, target := mapTool(tc.name, []byte(tc.args))
			if a != tc.wantAction || target != tc.wantTarget {
				t.Errorf("mapTool = (%s, %q), want (%s, %q)", a, target, tc.wantAction, tc.wantTarget)
			}
		})
	}
}

func TestNativeNameAndAuthoredBytes(t *testing.T) {
	if got := nativeName(" stakpak__run_command "); got != "run_command" {
		t.Errorf("nativeName = %q", got)
	}
	if got := nativeName("other__tool"); got != "other__tool" {
		t.Errorf("nativeName must only strip its own namespace, got %q", got)
	}
	if got := authoredBytes("create", []byte(`{"file_text":"hello"}`)); got != 5 {
		t.Errorf("create bytes = %d", got)
	}
	if got := authoredBytes("str_replace", []byte(`{"new_str":"abc"}`)); got != 3 {
		t.Errorf("str_replace bytes = %d", got)
	}
	if got := authoredBytes("run_command", []byte(`{"command":"ls"}`)); got != 0 {
		t.Errorf("run_command bytes = %d", got)
	}
}

func TestResultVerdict(t *testing.T) {
	cases := []struct {
		in      string
		ok      bool
		wantErr string
	}{
		{"Successfully created file x", true, ""},
		{"TOOL_CALL_CANCELLED", false, "tool call cancelled"},
		{"  TOOL_CALL_CANCELLED\n", false, "tool call cancelled"},
		{"COMMAND_FAILED\nls: cannot access 'x'", false, "ls: cannot access 'x'"},
		{"", true, ""},
		{"output that merely mentions COMMAND_FAILED later", true, ""},
	}
	for _, tc := range cases {
		ok, msg := resultVerdict(tc.in)
		if ok != tc.ok || msg != tc.wantErr {
			t.Errorf("resultVerdict(%q) = (%v, %q), want (%v, %q)", tc.in, ok, msg, tc.ok, tc.wantErr)
		}
	}
}

func TestDecodeContent(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		wantText string
		wantAtts []models.UserAttachment
	}{
		{"string", `"hello"`, "hello", nil},
		{"null", `null`, "", nil},
		{"empty", ``, "", nil},
		{"text parts", `[{"type":"text","text":"a"},{"type":"text","text":"b"}]`, "a\nb", nil},
		{
			"image part keeps media type only", `[{"type":"text","text":"look"},{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}]`,
			"look",
			[]models.UserAttachment{{Kind: "image", MediaType: "image/png"}},
		},
		{
			"remote image url has no media type", `[{"type":"image_url","image_url":{"url":"https://example.invalid/x.png"}}]`,
			"",
			[]models.UserAttachment{{Kind: "image"}},
		},
		{"unparseable", `{"a":1}`, "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text, atts := decodeContent(json.RawMessage(tc.raw))
			if text != tc.wantText {
				t.Errorf("text = %q, want %q", text, tc.wantText)
			}
			if len(atts) != len(tc.wantAtts) {
				t.Fatalf("attachments = %v, want %v", atts, tc.wantAtts)
			}
			for i := range atts {
				if atts[i] != tc.wantAtts[i] {
					t.Errorf("attachment %d = %+v, want %+v", i, atts[i], tc.wantAtts[i])
				}
			}
		})
	}
}

func TestStripLocalContext(t *testing.T) {
	if got := stripLocalContext("do it\n<local_context>\nMachine\n</local_context>"); got != "do it\n" {
		t.Errorf("stripLocalContext = %q", got)
	}
	if got := stripLocalContext("plain"); got != "plain" {
		t.Errorf("stripLocalContext = %q", got)
	}
}

func TestArgumentBytes(t *testing.T) {
	if got := string(argumentBytes(json.RawMessage(`"{\"a\":1}"`))); got != `{"a":1}` {
		t.Errorf("string-encoded args = %q", got)
	}
	if got := string(argumentBytes(json.RawMessage(`{"a":1}`))); got != `{"a":1}` {
		t.Errorf("inline object args = %q", got)
	}
	if argumentBytes(json.RawMessage(`null`)) != nil || argumentBytes(nil) != nil {
		t.Error("null/empty args must be nil")
	}
}

func TestToolEventIDFallback(t *testing.T) {
	if got := toolEventID("s", "call_1", "c", 3, 0); got != "tool:s:call_1" {
		t.Errorf("with id = %q", got)
	}
	if got := toolEventID("s", "", "c", 3, 1); got != "tool:s:c:3:1" {
		t.Errorf("without id = %q", got)
	}
}

// synthetic builds a store from literal checkpoint states for the shapes the
// live captures do not contain.
func syntheticParse(t *testing.T, states ...[2]string) (adapter.ParseResult, string) {
	t.Helper()
	dbPath, root := emptyStore(t)
	addSession(t, dbPath, "s1", "")
	parent := ""
	for i, st := range states {
		ts := "2026-10-21T07:00:0" + string(rune('0'+i)) + ".000000000+00:00"
		addCheckpoint(t, dbPath, st[0], "s1", parent, ts, st[1])
		parent = st[0]
	}
	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	return res, dbPath
}

func TestSubagentModelAndDetailsShapes(t *testing.T) {
	const call = `{"id":"call_a","type":"function","function":{"name":"stakpak__dynamic_subagent_task","arguments":"{\"description\":\"Index docs\",\"tools\":[\"stakpak__view\"]}"}}`
	res, _ := syntheticParse(t,
		[2]string{"c1", stateJSON(`{"role":"user","content":[{"type":"text","text":"go"},{"type":"image_url","image_url":{"url":"data:image/jpeg;base64,AAAA"}}]}`)},
		[2]string{"c2", stateJSON(
			`{"role":"user","content":[{"type":"text","text":"go"},{"type":"image_url","image_url":{"url":"data:image/jpeg;base64,AAAA"}}]}`,
			`{"role":"assistant","content":"spawning","tool_calls":[`+call+`],"model":"anthropic/claude-sonnet-4","usage":{"prompt_tokens":1000,"completion_tokens":10,"total_tokens":1010,"prompt_tokens_details":{"input_tokens":100,"output_tokens":10,"cache_read_input_tokens":850,"cache_write_input_tokens":50}}}`,
		)},
		[2]string{"c3", stateJSON(
			`{"role":"user","content":[{"type":"text","text":"go"},{"type":"image_url","image_url":{"url":"data:image/jpeg;base64,AAAA"}}]}`,
			`{"role":"assistant","content":"spawning","tool_calls":[`+call+`]}`,
			`{"role":"tool","content":"Task ID: x","tool_call_id":"call_a"}`,
			`{"role":"assistant","content":"done","usage":{"prompt_tokens":1200,"completion_tokens":4,"total_tokens":1204}}`,
		)},
	)

	var prompt, spawn, text *models.ToolEvent
	for i := range res.ToolEvents {
		ev := &res.ToolEvents[i]
		switch {
		case ev.ActionType == models.ActionUserPrompt:
			prompt = ev
		case ev.ActionType == models.ActionSpawnSubagent:
			spawn = ev
		case ev.ActionType == models.ActionAssistantMessage && ev.Target == "spawning":
			text = ev
		}
	}
	if prompt == nil || len(prompt.UserAttachments) != 1 || prompt.UserAttachments[0] != (models.UserAttachment{Kind: "image", MediaType: "image/jpeg"}) {
		t.Fatalf("image-only-plus-text prompt attachments wrong: %+v", prompt)
	}
	if spawn == nil || spawn.Target != "Index docs" || spawn.IsSidechain {
		t.Fatalf("spawn event wrong (spawn row itself must not be a sidechain row): %+v", spawn)
	}
	if spawn.Success != true || spawn.OutcomePending || spawn.ToolOutput != "Task ID: x" {
		t.Errorf("spawn result not paired: %+v", spawn)
	}
	if spawn.Model != "anthropic/claude-sonnet-4" || text == nil || text.Model != "anthropic/claude-sonnet-4" {
		t.Errorf("per-message model not carried: spawn=%q text=%+v", spawn.Model, text)
	}

	if len(res.TokenEvents) != 2 {
		t.Fatalf("token rows = %d, want 2", len(res.TokenEvents))
	}
	d := res.TokenEvents[0]
	if d.InputTokens != 100 || d.OutputTokens != 10 || d.CacheReadTokens != 850 || d.CacheCreationTokens != 50 || d.Model != "anthropic/claude-sonnet-4" {
		t.Errorf("details-shaped usage wrong: %+v", d)
	}
	p := res.TokenEvents[1]
	if p.InputTokens != 1200 || p.OutputTokens != 4 || p.Model != "" {
		t.Errorf("plain usage wrong: %+v", p)
	}
	if len(res.OutcomeUpdates) != 0 {
		t.Errorf("same-window result must pair in place, got updates %+v", res.OutcomeUpdates)
	}
}

// TestForkedCheckpointsEmitOnce: two checkpoints sharing a parent (a session
// resumed at an older checkpoint) each contribute only their own delta; the
// shared prefix is not re-emitted, and a call without a provider id still
// gets a deterministic, collision-free key.
func TestForkedCheckpointsEmitOnce(t *testing.T) {
	dbPath, root := emptyStore(t)
	addSession(t, dbPath, "s1", "")
	base := `{"role":"user","content":"start"}`
	addCheckpoint(t, dbPath, "root", "s1", "", "2026-10-21T07:00:00.000000000+00:00", stateJSON(base))
	addCheckpoint(t, dbPath, "left", "s1", "root", "2026-10-21T07:00:01.000000000+00:00", stateJSON(base,
		`{"role":"assistant","content":null,"tool_calls":[{"id":"","type":"function","function":{"name":"stakpak__run_command","arguments":"{\"command\":\"a\"}"}}],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`))
	addCheckpoint(t, dbPath, "right", "s1", "root", "2026-10-21T07:00:02.000000000+00:00", stateJSON(base,
		`{"role":"assistant","content":null,"tool_calls":[{"id":"","type":"function","function":{"name":"stakpak__run_command","arguments":"{\"command\":\"b\"}"}}],"usage":{"prompt_tokens":6,"completion_tokens":1,"total_tokens":7}}`))
	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	prompts, cmds := 0, map[string]string{}
	for _, ev := range res.ToolEvents {
		switch ev.ActionType {
		case models.ActionUserPrompt:
			prompts++
		case models.ActionRunCommand:
			cmds[ev.SourceEventID] = ev.Target
		}
	}
	if prompts != 1 {
		t.Errorf("shared prompt emitted %d times, want 1", prompts)
	}
	if len(cmds) != 2 {
		t.Errorf("fork branches collapsed: %v", cmds)
	}
	if len(res.TokenEvents) != 2 || res.TokenEvents[0].SourceEventID == res.TokenEvents[1].SourceEventID {
		t.Errorf("token rows for forked checkpoints collided: %+v", res.TokenEvents)
	}
}

// TestShrunkStateEmitsNothing: a checkpoint whose message list is SHORTER
// than its parent's (history rewritten) has nothing provably new.
func TestShrunkStateEmitsNothing(t *testing.T) {
	dbPath, root := emptyStore(t)
	addSession(t, dbPath, "s1", "")
	addCheckpoint(t, dbPath, "p", "s1", "", "2026-10-21T07:00:00.000000000+00:00", stateJSON(
		`{"role":"user","content":"a"}`, `{"role":"assistant","content":"b"}`, `{"role":"user","content":"c"}`))
	addCheckpoint(t, dbPath, "child", "s1", "p", "2026-10-21T07:00:01.000000000+00:00", stateJSON(
		`{"role":"user","content":"summary"}`))
	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 1) // only the child
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ToolEvents) != 0 {
		t.Errorf("shrunk checkpoint emitted %+v", res.ToolEvents)
	}
}
