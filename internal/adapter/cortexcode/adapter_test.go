package cortexcode

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

const (
	wslSID = "0f1e2d3c-4b5a-4968-8778-a1b2c3d4e5f6"
	winSID = "9a8b7c6d-5e4f-4a3b-9c2d-1e0f9a8b7c6d"
	// winToolSID is the anonymized Windows tool-call session (real,
	// 2026-10-22): write, read, edit, two PowerShell-run bash calls, glob
	// and grep, every PreToolUse hook failing under PowerShell.
	winToolSID = "7e6d5c4b-3a29-4180-9f6e-5d4c3b2a1908"
)

// fixturePath resolves a path under testdata/cortexcode/.
func fixturePath(elem ...string) string {
	return filepath.Join(append([]string{"..", "..", "..", "testdata", "cortexcode"}, elem...)...)
}

// stageFixture copies one fixture session pair (history + metadata) into a
// fresh <tmp>/conversations directory and returns that directory.
func stageFixture(t *testing.T, osDir, sid string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "conversations")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{sid + historySuffix, sid + metaSuffix} {
		data, err := os.ReadFile(fixturePath(osDir, "conversations", name)) //nolint:gosec // test fixture
		if err != nil {
			t.Fatalf("read fixture %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func parse(t *testing.T, a *Adapter, path string, from int64) adapter.ParseResult {
	t.Helper()
	res, err := a.ParseSessionFile(context.Background(), path, from)
	if err != nil {
		t.Fatalf("ParseSessionFile(%s, %d): %v", path, from, err)
	}
	return res
}

func countBy(evs []models.ToolEvent) map[string]int {
	out := map[string]int{}
	for _, ev := range evs {
		out[ev.ActionType]++
	}
	return out
}

func TestName(t *testing.T) {
	if got := New().Name(); got != models.ToolCortexCode {
		t.Fatalf("Name() = %q, want %q", got, models.ToolCortexCode)
	}
}

func TestIsSessionFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".snowflake", "cortex", "conversations")
	a := NewWithOptions(nil, root)
	other := filepath.Join(t.TempDir(), "elsewhere", "conversations")
	cortexHome := filepath.Dir(root)
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"history log", filepath.Join(root, wslSID+".history.jsonl"), true},
		{"metadata document", filepath.Join(root, wslSID+".json"), true},
		{"subagent pair metadata", filepath.Join(root, "agent_abc123.json"), true},
		{"vendor backup rejected", filepath.Join(root, wslSID+".back.1.json"), false},
		{"last-session pointer rejected", filepath.Join(root, ".last-session"), false},
		{"bare jsonl rejected", filepath.Join(root, wslSID+".jsonl"), false},
		{"dotted history stem rejected", filepath.Join(root, "a.b.history.jsonl"), false},
		{"nested dir rejected", filepath.Join(root, "sub", wslSID+".json"), false},
		{"same shape outside root rejected", filepath.Join(other, wslSID+".json"), false},
		{"connections.toml rejected", filepath.Join(filepath.Dir(cortexHome), "connections.toml"), false},
		{"cortex settings rejected", filepath.Join(cortexHome, "settings.json"), false},
		{"credential cache rejected", filepath.Join(cortexHome, "cache", "credential_cache", "credential_cache_v1.json"), false},
		{"usage stats rejected", filepath.Join(cortexHome, "stats", "usage.json"), false},
		{"claude transcript rejected", filepath.Join(t.TempDir(), ".claude", "projects", "p", wslSID+".jsonl"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.IsSessionFile(tc.path); got != tc.want {
				t.Fatalf("IsSessionFile(%s) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestClassifyLayoutAcceptsBothSeparators(t *testing.T) {
	cases := []struct {
		path string
		want layout
	}{
		{`C:\Users\user\.snowflake\cortex\conversations\` + winSID + `.history.jsonl`, layoutHistory},
		{`C:\Users\user\.snowflake\cortex\conversations\` + winSID + `.json`, layoutMeta},
		{"/home/user/.snowflake/cortex/conversations/" + wslSID + ".json", layoutMeta},
		{"/home/user/.snowflake/cortex/debug_conversations/" + wslSID + ".json", layoutNone},
	}
	for _, tc := range cases {
		if got := classifyLayout(tc.path); got != tc.want {
			t.Errorf("classifyLayout(%s) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestDefaultRootsHonourEnvOverrides(t *testing.T) {
	ch := filepath.Join(t.TempDir(), "cortexhome")
	sh := filepath.Join(t.TempDir(), "sfhome")
	t.Setenv("CORTEX_HOME", ch)
	t.Setenv("SNOWFLAKE_HOME", sh)
	roots := defaultRoots()
	want := []string{filepath.Join(ch, "conversations"), filepath.Join(sh, "cortex", "conversations")}
	for _, w := range want {
		found := false
		for _, r := range roots {
			if r == filepath.Clean(w) {
				found = true
			}
		}
		if !found {
			t.Errorf("defaultRoots() = %v, missing %s", roots, w)
		}
	}
	for _, r := range roots {
		if filepath.Base(r) != conversationsDir {
			t.Errorf("root %s is not a conversations directory", r)
		}
	}
}

func TestCursorSemanticsFor(t *testing.T) {
	root := filepath.Join(t.TempDir(), "conversations")
	a := NewWithOptions(nil, root)
	hist := a.CursorSemanticsFor(filepath.Join(root, wslSID+historySuffix))
	if hist.Kind != adapter.CursorByteOffset || !hist.StreamsFromCursor || hist.RewindsOnTruncate {
		t.Errorf("history semantics = %+v", hist)
	}
	meta := a.CursorSemanticsFor(filepath.Join(root, wslSID+metaSuffix))
	if meta.Kind != adapter.CursorNoActions || !meta.RewindMeaningful() || meta.StreamsFromCursor {
		t.Errorf("metadata semantics = %+v", meta)
	}
}

// TestParseWSLFixture pins the live WSL session (write / bash / edit /
// bash, every result in the same window).
func TestParseWSLFixture(t *testing.T) {
	dir := stageFixture(t, "wsl", wslSID)
	a := NewWithOptions(nil, dir)
	res := parse(t, a, filepath.Join(dir, wslSID+historySuffix), 0)

	got := countBy(res.ToolEvents)
	want := map[string]int{
		models.ActionUserPrompt:       1,
		models.ActionWriteFile:        1,
		models.ActionRunCommand:       2,
		models.ActionEditFile:         1,
		models.ActionAssistantMessage: 1,
	}
	if len(got) != len(want) {
		t.Fatalf("action counts = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("count[%s] = %d, want %d (all %v)", k, got[k], v, got)
		}
	}
	if len(res.OutcomeUpdates) != 0 {
		t.Errorf("OutcomeUpdates = %d, want 0 (all results pair in-window)", len(res.OutcomeUpdates))
	}
	info, _ := os.Stat(filepath.Join(dir, wslSID+historySuffix))
	if res.NewOffset != info.Size() {
		t.Errorf("NewOffset = %d, want file size %d", res.NewOffset, info.Size())
	}
	durations := map[string]int64{}
	for _, ev := range res.ToolEvents {
		if ev.SessionID != wslSID || ev.Tool != models.ToolCortexCode || ev.SourceFile == "" {
			t.Errorf("bad identity on %+v", ev)
		}
		if ev.ProjectRoot == "" || ev.ProjectRoot == placeholderRoot {
			t.Errorf("project root not resolved: %q", ev.ProjectRoot)
		}
		if ev.Timestamp.IsZero() {
			t.Errorf("zero timestamp on %s", ev.SourceEventID)
		}
		switch ev.ActionType {
		case models.ActionUserPrompt:
			if ev.Metadata != nil || ev.Model != "" {
				t.Errorf("prompt carries assistant fields: %+v", ev)
			}
		default:
			if ev.Model != "claude-opus-5-5" {
				t.Errorf("%s model = %q", ev.SourceEventID, ev.Model)
			}
			if ev.Metadata == nil || ev.Metadata.EffortLevel != "low" {
				t.Errorf("%s effort = %+v, want low", ev.SourceEventID, ev.Metadata)
			}
		}
		if ev.RawToolName == "write" {
			if ev.ContentBytes != int64(len("print(\"Hello, World!\")\n")) {
				t.Errorf("write ContentBytes = %d", ev.ContentBytes)
			}
			// Absolute file paths are relativized against the root.
			if ev.Target != "hello_world.py" {
				t.Errorf("write target = %q", ev.Target)
			}
		}
		if ev.RawToolName == "edit" && ev.ContentBytes != int64(len("Hello, Autohand!")) {
			t.Errorf("edit ContentBytes = %d", ev.ContentBytes)
		}
		if ev.OutcomePending {
			t.Errorf("%s left pending", ev.SourceEventID)
		}
		durations[ev.RawToolName] += ev.DurationMs
	}
	if durations["write"] != 25 || durations["edit"] != 11 || durations["bash"] != 76+35 {
		t.Errorf("durations = %v", durations)
	}
}

// TestParseWindowsFixture pins the live Windows session: the user record
// is re-appended as growing snapshots, a second typed prompt arrives
// INSIDE an earlier record's snapshot under its own block message_id,
// harness-injected blocks (system reminders, hook output, the interrupt
// marker) are never prompts, and thinking text rides on the assistant
// events.
func TestParseWindowsFixture(t *testing.T) {
	dir := stageFixture(t, "windows", winSID)
	a := NewWithOptions(nil, dir)
	res := parse(t, a, filepath.Join(dir, winSID+historySuffix), 0)

	got := countBy(res.ToolEvents)
	if got[models.ActionUserPrompt] != 2 || got[models.ActionRunCommand] != 2 || got[models.ActionAssistantMessage] != 2 ||
		got[models.ActionTurnAborted] != 1 || len(got) != 4 {
		t.Fatalf("action counts = %v, want 2 prompts / 2 run_command / 2 assistant / 1 turn_aborted", got)
	}
	ids := map[string]bool{}
	var prompts []string
	for _, ev := range res.ToolEvents {
		if ids[ev.SourceEventID] {
			t.Errorf("duplicate SourceEventID %s in one window", ev.SourceEventID)
		}
		ids[ev.SourceEventID] = true
		if ev.ActionType == models.ActionUserPrompt {
			prompts = append(prompts, ev.Target)
			if strings.Contains(ev.Target, "system-reminder") || strings.Contains(ev.Target, "Request interrupted") {
				t.Errorf("harness block emitted as prompt: %q", ev.Target)
			}
		}
		if ev.ActionType == models.ActionTurnAborted && (ev.Success || ev.ErrorMessage == "" || ev.Timestamp.IsZero()) {
			t.Errorf("turn_aborted row = %+v, want a failed, timestamped row", ev)
		}
		if ev.ActionType == models.ActionAssistantMessage && ev.PrecedingReasoning == "" {
			t.Errorf("assistant %s lost its thinking text", ev.SourceEventID)
		}
	}
	if len(prompts) != 2 || !strings.HasPrefix(prompts[1], "Create a hello world python file") {
		t.Errorf("prompts = %q", prompts)
	}
	// Re-parsing from the cursor yields nothing new.
	again := parse(t, a, filepath.Join(dir, winSID+historySuffix), res.NewOffset)
	if len(again.ToolEvents) != 0 || len(again.OutcomeUpdates) != 0 {
		t.Errorf("re-parse from EOF produced %d events / %d updates", len(again.ToolEvents), len(again.OutcomeUpdates))
	}
}

// TestIncrementalParseMatchesWholeFile grows the history file one line at
// a time and parses each delta from the previous cursor: the union of
// emitted ids equals a whole-file parse, every call whose result landed in
// a later window is completed by an OutcomeUpdate carrying the same
// SourceEventID, and that call was marked OutcomePending in its own window.
func TestIncrementalParseMatchesWholeFile(t *testing.T) {
	for _, tc := range []struct{ osDir, sid string }{{"wsl", wslSID}, {"windows", winSID}, {"windows", winToolSID}} {
		t.Run(tc.osDir+"/"+tc.sid[:8], func(t *testing.T) {
			src := stageFixture(t, tc.osDir, tc.sid)
			whole := parse(t, NewWithOptions(nil, src), filepath.Join(src, tc.sid+historySuffix), 0)
			wantIDs := map[string]bool{}
			for _, ev := range whole.ToolEvents {
				wantIDs[ev.SourceEventID] = true
			}

			data, err := os.ReadFile(filepath.Join(src, tc.sid+historySuffix))
			if err != nil {
				t.Fatal(err)
			}
			meta, err := os.ReadFile(filepath.Join(src, tc.sid+metaSuffix))
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(t.TempDir(), "conversations")
			writeFile(t, filepath.Join(dir, tc.sid+metaSuffix), string(meta))
			path := filepath.Join(dir, tc.sid+historySuffix)
			a := NewWithOptions(nil, dir)

			gotIDs := map[string]bool{}
			pending := map[string]bool{}
			completed := map[string]bool{}
			var off int64
			lines := strings.SplitAfter(string(data), "\n")
			var buf strings.Builder
			for _, line := range lines {
				if line == "" {
					continue
				}
				buf.WriteString(line)
				writeFile(t, path, buf.String())
				res := parse(t, a, path, off)
				off = res.NewOffset
				for _, ev := range res.ToolEvents {
					gotIDs[ev.SourceEventID] = true
					if ev.OutcomePending {
						pending[ev.SourceEventID] = true
					}
				}
				for _, u := range res.OutcomeUpdates {
					completed[u.SourceEventID] = true
					if !u.SuccessKnown || !u.Success || u.DurationMs <= 0 {
						t.Errorf("outcome update %+v not carrying the live success verdict", u)
					}
				}
			}
			if len(gotIDs) != len(wantIDs) {
				t.Errorf("incremental ids = %d, whole-file ids = %d", len(gotIDs), len(wantIDs))
			}
			for id := range wantIDs {
				if !gotIDs[id] {
					t.Errorf("incremental parse missed %s", id)
				}
			}
			if len(pending) == 0 {
				t.Fatal("expected at least one call to straddle a window")
			}
			for id := range pending {
				if !completed[id] {
					t.Errorf("pending call %s never completed by an OutcomeUpdate", id)
				}
			}
		})
	}
}

func TestPartialTrailingLineIsDeferred(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "conversations")
	path := filepath.Join(dir, wslSID+historySuffix)
	full := `{"role":"user","id":"msg_1","content":[{"type":"text","text":"hello","is_user_prompt":true,"message_id":"msg_1"}],"user_sent_time":"2026-10-21T04:05:35.144Z"}` + "\n"
	writeFile(t, path, full+`{"role":"assistant","id":"9","content":[{"type":"te`)
	a := NewWithOptions(nil, dir)
	res := parse(t, a, path, 0)
	if res.NewOffset != int64(len(full)) {
		t.Fatalf("NewOffset = %d, want %d (partial line deferred)", res.NewOffset, len(full))
	}
	if len(res.ToolEvents) != 1 || res.ToolEvents[0].ProjectRoot != placeholderRoot {
		t.Fatalf("events = %+v, want one prompt on the placeholder root (no metadata)", res.ToolEvents)
	}
}

func TestMalformedLineIsSkippedAndAdvanced(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "conversations")
	path := filepath.Join(dir, wslSID+historySuffix)
	body := "not json\r\n" +
		`{"role":"user","id":"msg_1","content":"bare string prompt","user_sent_time":"2026-10-21T04:05:35.144Z"}` + "\r\n" +
		`{"role":"system","id":"x","content":[]}` + "\r\n"
	writeFile(t, path, body)
	res := parse(t, NewWithOptions(nil, dir), path, 0)
	if res.NewOffset != int64(len(body)) {
		t.Fatalf("NewOffset = %d, want %d (CRLF counted exactly)", res.NewOffset, len(body))
	}
	if len(res.Warnings) != 1 {
		t.Errorf("warnings = %v, want exactly one (the malformed line)", res.Warnings)
	}
	// A bare-string content decodes as a text block but carries no
	// is_user_prompt flag, so it is not claimed as a typed prompt.
	if len(res.ToolEvents) != 0 {
		t.Errorf("events = %+v, want none", res.ToolEvents)
	}
}

// TestFailedToolResult is SYNTHETIC: only "success" was observed live. Any
// other non-empty status marks the call failed with the result text as the
// error; an empty status leaves the optimistic verdict untouched.
func TestFailedToolResult(t *testing.T) {
	cases := []struct {
		status      string
		wantSuccess bool
		wantErr     bool
	}{
		{"success", true, false},
		{"error", false, true},
		{"cancelled", false, true},
		{"", true, false},
	}
	for _, tc := range cases {
		t.Run("status="+tc.status, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "conversations")
			path := filepath.Join(dir, wslSID+historySuffix)
			body := `{"role":"assistant","id":"100","content":[{"type":"tool_use","tool_use":{"tool_use_id":"tu_1","name":"bash","input":{"command":"false"}}}],"assistant_sent_time":"2026-10-21T04:05:41.823Z","model":"claude-opus-5-5"}` + "\n" +
				`{"role":"user","id":"msg_2","content":[{"type":"tool_result","tool_result":{"name":"bash","tool_use_id":"tu_1","content":[{"type":"text","text":"exit status 1"}],"status":"` + tc.status + `","metrics":{"duration_ms":7}}}],"user_sent_time":"2026-10-21T04:05:42.000Z"}` + "\n"
			writeFile(t, path, body)
			res := parse(t, NewWithOptions(nil, dir), path, 0)
			if len(res.ToolEvents) != 1 {
				t.Fatalf("events = %d", len(res.ToolEvents))
			}
			ev := res.ToolEvents[0]
			if ev.Success != tc.wantSuccess || (ev.ErrorMessage != "") != tc.wantErr || ev.DurationMs != 7 || ev.ToolOutput != "exit status 1" {
				t.Errorf("event = success %v err %q dur %d out %q", ev.Success, ev.ErrorMessage, ev.DurationMs, ev.ToolOutput)
			}
		})
	}
}

func TestParseMetaTokens(t *testing.T) {
	for _, tc := range []struct {
		osDir, sid                     string
		in, out, cacheRead, cacheWrite int64
	}{
		{"wsl", wslSID, 12, 574, 384189, 97032},
		{"windows", winSID, 12, 853, 173057, 85434},
		// 693453 gross - 519813 read - 173608 write.
		{"windows", winToolSID, 32, 761, 519813, 173608},
	} {
		t.Run(tc.osDir+"/"+tc.sid[:8], func(t *testing.T) {
			dir := stageFixture(t, tc.osDir, tc.sid)
			a := NewWithOptions(nil, dir)
			path := filepath.Join(dir, tc.sid+metaSuffix)
			res := parse(t, a, path, 0)
			if len(res.ToolEvents) != 0 {
				t.Errorf("metadata emitted %d actions, want 0", len(res.ToolEvents))
			}
			if len(res.TokenEvents) != 1 {
				t.Fatalf("token events = %d, want 1", len(res.TokenEvents))
			}
			tk := res.TokenEvents[0]
			if tk.InputTokens != tc.in || tk.OutputTokens != tc.out || tk.CacheReadTokens != tc.cacheRead || tk.CacheCreationTokens != tc.cacheWrite {
				t.Errorf("tokens = in %d out %d cr %d cw %d", tk.InputTokens, tk.OutputTokens, tk.CacheReadTokens, tk.CacheCreationTokens)
			}
			if tk.Model != "claude-opus-5-5" || tk.SessionID != tc.sid || tk.Tool != models.ToolCortexCode ||
				tk.SourceEventID != "tokens:session:"+tc.sid+":claude-opus-5-5" ||
				tk.Source != models.TokenSourceJSONL || tk.Reliability != models.ReliabilityApproximate || tk.ReasoningTokens != 0 {
				t.Errorf("token identity = %+v", tk)
			}
			if tk.Timestamp.IsZero() || tk.ProjectRoot == "" || tk.ProjectRoot == placeholderRoot {
				t.Errorf("token timestamp/root = %v %q", tk.Timestamp, tk.ProjectRoot)
			}
			info, _ := os.Stat(path)
			if res.NewOffset != info.Size() {
				t.Errorf("NewOffset = %d, want %d", res.NewOffset, info.Size())
			}
			// The document is re-read whole whatever the cursor says, so a
			// rewrite with identical size still re-emits the same row.
			again := parse(t, a, path, res.NewOffset)
			if len(again.TokenEvents) != 1 || again.TokenEvents[0] != tk {
				t.Errorf("re-parse differs: %+v", again.TokenEvents)
			}
		})
	}
}

func TestParseMetaMultiModelAndZeroRows(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "conversations")
	path := filepath.Join(dir, wslSID+metaSuffix)
	writeFile(t, path, `{"session_id":"`+wslSID+`","last_updated":"2026-10-21T04:10:55.682Z","token_usage":{
		"zeta-model":{"inputTokens":100,"outputTokens":5,"cacheReadTokens":60,"cacheWriteTokens":30},
		"alpha-model":{"inputTokens":10,"outputTokens":1,"cacheReadTokens":40,"cacheWriteTokens":0},
		"empty-model":{"inputTokens":0,"outputTokens":0,"cacheReadTokens":0,"cacheWriteTokens":0}}}`)
	res := parse(t, NewWithOptions(nil, dir), path, 0)
	if len(res.TokenEvents) != 2 {
		t.Fatalf("token events = %+v, want 2 (all-zero row skipped)", res.TokenEvents)
	}
	if res.TokenEvents[0].Model != "alpha-model" || res.TokenEvents[1].Model != "zeta-model" {
		t.Errorf("not sorted by model: %s, %s", res.TokenEvents[0].Model, res.TokenEvents[1].Model)
	}
	if res.TokenEvents[0].InputTokens != 0 {
		t.Errorf("net input must clamp at zero, got %d", res.TokenEvents[0].InputTokens)
	}
	if res.TokenEvents[1].InputTokens != 10 {
		t.Errorf("net input = %d, want 100-60-30 = 10", res.TokenEvents[1].InputTokens)
	}
}

// TestSubagentLineage is SYNTHETIC: parent_session_id is read off the
// v1.2.18 bundle's orphan-subagent sweep (both spellings), not yet
// observed live.
func TestSubagentLineage(t *testing.T) {
	cases := []struct {
		name, body, wantParent string
	}{
		{"snake", `{"session_id":"child1","parent_session_id":"` + wslSID + `"}`, wslSID},
		{"camel", `{"session_id":"child1","parentSessionId":"` + winSID + `"}`, winSID},
		{"main session", `{"session_id":"child1","session_type":"main"}`, ""},
		{"self parent ignored", `{"session_id":"child1","parent_session_id":"child1"}`, ""},
	}
	// Fork cases (bundle: setForkedFrom(<source id>) persisted as
	// forked_from; SYNTHETIC, not yet observed live).
	forks := []struct {
		name, body string
		want       models.SessionLineage
	}{
		{
			"user fork", `{"session_id":"child1","forked_from":"` + wslSID + `"}`,
			models.SessionLineage{SessionID: "child1", ForkedFromID: wslSID, ThreadSource: "user"},
		},
		{
			"camel fork", `{"session_id":"child1","forkedFrom":"` + winSID + `"}`,
			models.SessionLineage{SessionID: "child1", ForkedFromID: winSID, ThreadSource: "user"},
		},
		{
			"subagent with forked history", `{"session_id":"child1","session_type":"subagent","parent_session_id":"` + wslSID + `","forked_from":"` + wslSID + `"}`,
			models.SessionLineage{SessionID: "child1", ParentThreadID: wslSID, ForkedFromID: wslSID, ThreadSource: "subagent"},
		},
	}
	for _, tc := range forks {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "conversations")
			path := filepath.Join(dir, "child1"+metaSuffix)
			writeFile(t, path, tc.body)
			res := parse(t, NewWithOptions(nil, dir), path, 0)
			if len(res.SessionLineages) != 1 || res.SessionLineages[0] != tc.want {
				t.Fatalf("lineage = %+v, want %+v", res.SessionLineages, tc.want)
			}
		})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "conversations")
			path := filepath.Join(dir, "child1"+metaSuffix)
			writeFile(t, path, tc.body)
			res := parse(t, NewWithOptions(nil, dir), path, 0)
			if tc.wantParent == "" {
				if len(res.SessionLineages) != 0 {
					t.Fatalf("lineage = %+v, want none", res.SessionLineages)
				}
				return
			}
			want := models.SessionLineage{SessionID: "child1", ParentThreadID: tc.wantParent, ThreadSource: "subagent"}
			if len(res.SessionLineages) != 1 || res.SessionLineages[0] != want {
				t.Fatalf("lineage = %+v, want %+v", res.SessionLineages, want)
			}
		})
	}
}

func TestParseMetaTornRead(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "conversations")
	path := filepath.Join(dir, wslSID+metaSuffix)
	writeFile(t, path, `{"session_id":"`+wslSID+`","token_us`)
	res := parse(t, NewWithOptions(nil, dir), path, 40)
	if !res.RetrySuggested || res.NewOffset != 40 || len(res.TokenEvents) != 0 {
		t.Fatalf("torn read = %+v, want retry with cursor kept", res)
	}
	missing := parse(t, NewWithOptions(nil, dir), filepath.Join(dir, "gone"+metaSuffix), 0)
	if missing.RetrySuggested || len(missing.TokenEvents) != 0 {
		t.Fatalf("missing file = %+v", missing)
	}
}

// TestMetaNeverDecodesAccountFields pins the decode allow-list: of the
// account-bearing fields only thread.accountHost (an ACCOUNT, operator
// ruling 2026-10-21) is decoded; the connection name and the account
// locator list never are.
func TestMetaNeverDecodesAccountFields(t *testing.T) {
	data, err := os.ReadFile(fixturePath("wsl", "conversations", wslSID+metaSuffix)) //nolint:gosec // fixture
	if err != nil {
		t.Fatal(err)
	}
	var m sessionMeta
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(m)
	for _, forbidden := range []string{"EXAMPLE_CONN", "EXAMPLE_ACCOUNT", "100000001"} {
		if strings.Contains(string(blob), forbidden) {
			t.Errorf("decoded metadata carries account field value %q", forbidden)
		}
	}
	if got := m.accountHost(); got != "example.snowflakecomputing.com" {
		t.Errorf("accountHost() = %q", got)
	}
}

func TestScrubsSecrets(t *testing.T) {
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	dir := filepath.Join(t.TempDir(), "conversations")
	path := filepath.Join(dir, wslSID+historySuffix)
	body := `{"role":"user","id":"msg_1","content":[{"type":"text","text":"use key ` + secret + `","is_user_prompt":true,"message_id":"msg_1"}],"user_sent_time":"2026-10-21T04:05:35.144Z"}` + "\n" +
		`{"role":"assistant","id":"100","content":[{"type":"thinking","thinking":{"text":"the key is ` + secret + `","signature":"S"}},{"type":"text","text":"ok ` + secret + `"},{"type":"tool_use","tool_use":{"tool_use_id":"tu_1","name":"bash","input":{"command":"export AWS_ACCESS_KEY_ID=` + secret + `"}}}],"assistant_sent_time":"2026-10-21T04:05:41.823Z","model":"claude-opus-5-5"}` + "\n" +
		`{"role":"user","id":"msg_2","content":[{"type":"tool_result","tool_result":{"name":"bash","tool_use_id":"tu_1","content":[{"type":"text","text":"` + secret + `"}],"status":"success","metrics":{"duration_ms":3}}}],"user_sent_time":"2026-10-21T04:05:42.000Z"}` + "\n"
	writeFile(t, path, body)
	res := parse(t, NewWithOptions(nil, dir), path, 0)
	if len(res.ToolEvents) != 3 {
		t.Fatalf("events = %d", len(res.ToolEvents))
	}
	for _, ev := range res.ToolEvents {
		blob := strings.Join([]string{ev.Target, ev.RawToolInput, ev.ToolOutput, ev.PrecedingReasoning, ev.ErrorMessage}, "|")
		if strings.Contains(blob, secret) {
			t.Errorf("secret leaked in %s: %q", ev.ActionType, blob)
		}
	}
}

func TestMapTool(t *testing.T) {
	cases := []struct {
		name  string
		want  string
		known bool
	}{
		{"bash", models.ActionRunCommand, true},
		{"BASH", models.ActionRunCommand, true},
		{"write", models.ActionWriteFile, true},
		{"edit", models.ActionEditFile, true},
		{"read", models.ActionReadFile, true},
		{"glob", models.ActionSearchFiles, true},
		{"grep", models.ActionSearchText, true},
		{"web_search", models.ActionWebSearch, true},
		{"web_fetch", models.ActionWebFetch, true},
		{"task", models.ActionSpawnSubagent, true},
		{"ask_user_question", models.ActionAskUser, true},
		{"enter_plan_mode", models.ActionPermissionMode, true},
		{"notebook_edit", models.ActionEditFile, true},
		{"cron_create", models.ActionSchedule, true},
		{"sql_execute", models.ActionRunCommand, true},
		{"python_repl", models.ActionRunCommand, true},
		{"apply_patch", models.ActionEditFile, true},
		{"skill", models.ActionSkillInvoke, true},
		{"skill_manage", models.ActionHarnessCall, true},
		{"system_todo_write", models.ActionTodoUpdate, true},
		{"task_create", models.ActionTodoUpdate, true},
		{"task_update", models.ActionTodoUpdate, true},
		{"send_message", models.ActionAgentMessage, true},
		{"spawn_teammate", models.ActionSpawnSubagent, true},
		{"team_create", models.ActionAgentControl, true},
		{"agent_output", models.ActionSubagentWait, true},
		{"tgrep", models.ActionSearchText, true},
		{"tool_search", models.ActionToolSearch, true},
		{"not_a_cortex_tool", models.ActionUnknown, false},
		{"", models.ActionUnknown, false},
	}
	for _, tc := range cases {
		got, known := mapTool(tc.name)
		if got != tc.want || known != tc.known {
			t.Errorf("mapTool(%q) = %q,%v want %q,%v", tc.name, got, known, tc.want, tc.known)
		}
	}
}

func TestUnknownToolWarnsOnce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "conversations")
	path := filepath.Join(dir, wslSID+historySuffix)
	body := `{"role":"assistant","id":"100","content":[{"type":"tool_use","tool_use":{"tool_use_id":"tu_1","name":"not_a_cortex_tool","input":{"query":"select 1"}}},{"type":"tool_use","tool_use":{"tool_use_id":"tu_2","name":"not_a_cortex_tool","input":{"query":"select 2"}}}],"assistant_sent_time":"2026-10-21T04:05:41.823Z","model":"m"}` + "\n"
	writeFile(t, path, body)
	res := parse(t, NewWithOptions(nil, dir), path, 0)
	if len(res.ToolEvents) != 2 || len(res.Warnings) != 1 {
		t.Fatalf("events=%d warnings=%v", len(res.ToolEvents), res.Warnings)
	}
	for _, ev := range res.ToolEvents {
		if ev.ActionType != models.ActionUnknown || ev.RawToolName != "not_a_cortex_tool" || !ev.OutcomePending {
			t.Errorf("event = %+v", ev)
		}
	}
	ids := []string{res.ToolEvents[0].SourceEventID, res.ToolEvents[1].SourceEventID}
	sort.Strings(ids)
	if ids[0] != "tool:"+wslSID+":tu_1" || ids[1] != "tool:"+wslSID+":tu_2" {
		t.Errorf("ids = %v", ids)
	}
}
