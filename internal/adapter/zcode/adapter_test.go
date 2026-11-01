package zcode

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// setupZcodeDB builds a minimal zcode CLI store (db.sqlite) with the
// session/message/part triple plus the model_usage token table. The schema
// mirrors the live store (~/.zcode/cli/db/db.sqlite, re-verified live
// 2026-08-25): message.data.tokens IS populated on completed assistant
// messages and matches model_usage for the same call — this fixture mirrors
// that by giving msg_asst the same split as mu_1. The adapter still sources
// TokenEvents from model_usage (loadTokenEvents), not the message bundle,
// because model_usage is a strict superset (it also covers usage-only calls
// with no message at all, e.g. session-title generation) and model_usage.
// input_tokens is GROSS (includes cache_read).
func setupZcodeDB(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stmts := []string{
		`CREATE TABLE session (
			id TEXT PRIMARY KEY, project_id TEXT NOT NULL, directory TEXT NOT NULL,
			slug TEXT NOT NULL DEFAULT '', title TEXT NOT NULL DEFAULT '',
			version TEXT NOT NULL DEFAULT '0.16.1', time_created INTEGER NOT NULL,
			time_updated INTEGER NOT NULL)`,
		`CREATE TABLE message (
			id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time_created INTEGER NOT NULL,
			time_updated INTEGER NOT NULL, data TEXT NOT NULL, sequence INTEGER)`,
		`CREATE TABLE part (
			id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL,
			time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL,
			sequence INTEGER)`,
		`CREATE TABLE model_usage (
			id TEXT PRIMARY KEY, session_id TEXT NOT NULL, turn_id TEXT,
			assistant_message_id TEXT, provider_id TEXT NOT NULL, model_id TEXT NOT NULL,
			status TEXT NOT NULL, started_at INTEGER NOT NULL, completed_at INTEGER,
			input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0,
			reasoning_tokens INTEGER NOT NULL DEFAULT 0,
			cache_creation_input_tokens INTEGER NOT NULL DEFAULT 0,
			cache_read_input_tokens INTEGER NOT NULL DEFAULT 0)`,
		`INSERT INTO session(id, project_id, directory, time_created, time_updated) VALUES
			('sess_a', 'proj_a', '/home/dev/needlehaystack', 1000, 9000)`,
		`INSERT INTO message(id, session_id, time_created, time_updated, data) VALUES
			('msg_user', 'sess_a', 1000, 1001, '{"role":"user","agent":"code","time":{"created":1000}}'),
			('msg_asst', 'sess_a', 2000, 5000, '{"parentID":"msg_user","role":"assistant","agent":"code","path":{"cwd":"/home/dev/needlehaystack"},"modelID":"openrouter/free","providerID":"openrouter","time":{"created":2000,"completed":5000},"finish":"stop","tokens":{"input":12860,"output":91,"reasoning":0,"cache":{"read":8448,"write":0}},"cost":0}')`,
		`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
			('prt_user', 'msg_user', 'sess_a', 1000, 1001, '{"type":"text","text":"help me"}'),
			('prt_text', 'msg_asst', 'sess_a', 2100, 2200, '{"type":"text","text":"on it"}'),
			('prt_bash', 'msg_asst', 'sess_a', 2300, 2400, '{"type":"tool","tool":"bash","callID":"c1","state":{"status":"completed","input":{"command":"ls"},"output":"a\nb\n","metadata":{"exit":0},"title":"ls","time":{"start":2300,"end":2400}}}')`,
		// model_usage: one completed call. input_tokens GROSS=12860 includes
		// cache_read=8448 -> NET input must emit as 4412.
		`INSERT INTO model_usage(id, session_id, assistant_message_id, provider_id, model_id, status, started_at, completed_at, input_tokens, output_tokens, reasoning_tokens, cache_creation_input_tokens, cache_read_input_tokens) VALUES
			('mu_1', 'sess_a', 'msg_asst', 'openrouter', 'openrouter/free', 'completed', 4000, 5000, 12860, 91, 0, 0, 8448),
			('mu_running', 'sess_a', 'msg_asst', 'openrouter', 'openrouter/free', 'running', 4000, NULL, 0, 0, 0, 0, 0)`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}

func parseZcode(t *testing.T, dbPath string) (toolEvents []models.ToolEvent, tokenEvents []models.TokenEvent, newOffset int64) {
	t.Helper()
	a := NewWithOptions(nil, []string{filepath.Dir(dbPath)})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return res.ToolEvents, res.TokenEvents, res.NewOffset
}

func TestParseSessionFile_EmitsActionsAndSessions(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), ".zcode", "cli", "db", "db.sqlite")
	setupZcodeDB(t, dbPath)
	tools, _, _ := parseZcode(t, dbPath)
	if len(tools) == 0 {
		t.Fatal("expected tool events (user prompt + tool + assistant text), got 0")
	}
	var sawUserPrompt, sawBash bool
	for _, ev := range tools {
		if ev.Tool != models.ToolZcode {
			t.Errorf("tool = %q, want %q", ev.Tool, models.ToolZcode)
		}
		if ev.SessionID != "sess_a" {
			t.Errorf("session = %q, want sess_a", ev.SessionID)
		}
		if ev.ProjectRoot != "/home/dev/needlehaystack" {
			t.Errorf("project root = %q, want /home/dev/needlehaystack", ev.ProjectRoot)
		}
		if ev.ActionType == models.ActionUserPrompt {
			sawUserPrompt = true
		}
		if ev.RawToolName == "bash" || ev.Target == "ls" {
			sawBash = true
		}
	}
	if !sawUserPrompt {
		t.Error("no user-prompt action emitted")
	}
	if !sawBash {
		t.Error("no bash tool action emitted")
	}
}

// TestTokensFromModelUsageNetInput is the KEY divergence test: tokens come
// from model_usage (not the message bundle, even though that bundle is
// itself populated and matching — see setupZcodeDB), and gross input is
// netted against cache_read.
func TestTokensFromModelUsageNetInput(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), ".zcode", "cli", "db", "db.sqlite")
	setupZcodeDB(t, dbPath)
	_, tokens, _ := parseZcode(t, dbPath)
	if len(tokens) != 1 {
		t.Fatalf("expected exactly 1 token event (the completed model_usage row; the running row is skipped), got %d", len(tokens))
	}
	tk := tokens[0]
	if tk.SourceEventID != "tokens:mu_1" {
		t.Errorf("SourceEventID = %q, want tokens:mu_1", tk.SourceEventID)
	}
	if tk.Model != "openrouter/free" {
		t.Errorf("Model = %q, want openrouter/free", tk.Model)
	}
	if tk.InputTokens != 4412 { // 12860 gross - 8448 cache_read
		t.Errorf("InputTokens (net) = %d, want 4412 (12860 gross - 8448 cache_read)", tk.InputTokens)
	}
	if tk.OutputTokens != 91 {
		t.Errorf("OutputTokens = %d, want 91", tk.OutputTokens)
	}
	if tk.CacheReadTokens != 8448 {
		t.Errorf("CacheReadTokens = %d, want 8448", tk.CacheReadTokens)
	}
	if tk.MessageID != "msg_asst" {
		t.Errorf("MessageID = %q, want msg_asst", tk.MessageID)
	}
	if tk.SessionID != "sess_a" {
		t.Errorf("SessionID = %q, want sess_a", tk.SessionID)
	}
}

func TestParseSessionFile_IdempotentReparse(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), ".zcode", "cli", "db", "db.sqlite")
	setupZcodeDB(t, dbPath)
	a := NewWithOptions(nil, []string{filepath.Dir(dbPath)})
	first, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if first.NewOffset <= 0 {
		t.Fatalf("watermark should be > 0, got %d", first.NewOffset)
	}
	second, err := a.ParseSessionFile(context.Background(), dbPath, first.NewOffset)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.ToolEvents) != 0 || len(second.TokenEvents) != 0 {
		t.Errorf("reparse from watermark should yield nothing, got %d tool + %d token events",
			len(second.ToolEvents), len(second.TokenEvents))
	}
}

// TestWatermarkCoversModelUsage ensures a model_usage completed_at beyond the
// message watermark advances the cursor (else late usage rows strand).
func TestWatermarkCoversModelUsage(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), ".zcode", "cli", "db", "db.sqlite")
	setupZcodeDB(t, dbPath)
	_, _, off := parseZcode(t, dbPath)
	// model_usage completed_at is 5000, equal to the message watermark here;
	// the watermark must be at least the max across all tables.
	if off < 9000 { // session.time_updated
		t.Errorf("watermark = %d, want >= 9000 (max across message/part/session/model_usage)", off)
	}
}

// TestTokenEvent_NoMessageLinkage covers a model_usage row with no
// assistant_message_id at all — observed live as
// "usage_model_session_title_..." (a builtin session-title-generation
// call). model_usage is read precisely because it is a strict superset of
// message.data.tokens; this proves a usage-only call still emits.
func TestTokenEvent_NoMessageLinkage(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), ".zcode", "cli", "db", "db.sqlite")
	setupZcodeDB(t, dbPath)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO model_usage(id, session_id, assistant_message_id, provider_id, model_id, status, started_at, completed_at, input_tokens, output_tokens, reasoning_tokens, cache_creation_input_tokens, cache_read_input_tokens) VALUES
		('usage_model_session_title_0', 'sess_a', NULL, 'builtin:zai-start-plan', 'GLM-5.3', 'completed', 6000, 6100, 281, 13, 0, 0, 0)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	_, tokens, _ := parseZcode(t, dbPath)
	var found bool
	for _, tk := range tokens {
		if tk.SourceEventID == "tokens:usage_model_session_title_0" {
			found = true
			if tk.MessageID != "" {
				t.Errorf("MessageID = %q, want empty (no assistant message backs this usage row)", tk.MessageID)
			}
			if tk.InputTokens != 281 {
				t.Errorf("InputTokens = %d, want 281", tk.InputTokens)
			}
			if tk.Model != "GLM-5.3" {
				t.Errorf("Model = %q, want GLM-5.3", tk.Model)
			}
		}
	}
	if !found {
		t.Fatal("expected a TokenEvent for the message-less model_usage row, got none")
	}
}

// TestSubagentSpawn_ViaAgentTool covers the actual live shape of a subagent
// spawn: a `tool` part with tool="Agent" (input.subagent_type/prompt/
// description). No `subtask`-type part was observed live on zcode-app-cli
// 3.8.1-15 / runtime 0.16.3 — loadSubtaskEvents is a defensive fallback for
// a shape not seen on this grounding; the real path is mapTool's
// "agent"/"task"/"subagent" -> ActionSpawnSubagent branch inside
// loadToolEvents.
func TestSubagentSpawn_ViaAgentTool(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), ".zcode", "cli", "db", "db.sqlite")
	setupZcodeDB(t, dbPath)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
		('prt_agent', 'msg_asst', 'sess_a', 2500, 2600, '{"type":"tool","tool":"Agent","callID":"c2","state":{"status":"completed","input":{"description":"Explore repo","prompt":"look around","subagent_type":"Explore"},"output":"report text","time":{"start":2500,"end":2600}}}')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	tools, _, _ := parseZcode(t, dbPath)
	var found bool
	for _, ev := range tools {
		if ev.SourceEventID == "part:prt_agent" {
			found = true
			if ev.ActionType != models.ActionSpawnSubagent {
				t.Errorf("ActionType = %q, want %q", ev.ActionType, models.ActionSpawnSubagent)
			}
		}
	}
	if !found {
		t.Fatal("expected an ActionSpawnSubagent event from the Agent tool part, got none")
	}
}

// TestUnknownPartType_TimelineSkipped covers a `timeline` part
// (timelineType="model_change", a mid-session model-switch marker observed
// live). No loader filters on type='timeline', so it must be silently
// skipped rather than crash or emit a spurious event.
func TestUnknownPartType_TimelineSkipped(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), ".zcode", "cli", "db", "db.sqlite")
	setupZcodeDB(t, dbPath)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
		('prt_timeline', 'msg_asst', 'sess_a', 2700, 2700, '{"type":"timeline","timelineType":"model_change","fromModel":{"providerID":"zai","modelID":"glm-5.2"},"toModel":{"providerID":"openrouter","modelID":"openrouter/free"}}')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	tools, _, _ := parseZcode(t, dbPath)
	for _, ev := range tools {
		if ev.SourceEventID == "part:prt_timeline" || ev.SourceEventID == "text:prt_timeline" {
			t.Errorf("timeline part should not emit an event, got %+v", ev)
		}
	}
}

// TestTodoEvents covers the `todo` table -> ActionTodoUpdate path,
// including the composite (session_id, position) primary key (no native
// row id, hence the synthesized "todo:session:position:time_updated"
// SourceEventID).
func TestTodoEvents(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), ".zcode", "cli", "db", "db.sqlite")
	setupZcodeDB(t, dbPath)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE todo (
			session_id text not null, content text not null, status text not null,
			priority text not null, position integer not null,
			time_created integer not null, time_updated integer not null,
			primary key(session_id, position));
		INSERT INTO todo(session_id, content, status, priority, position, time_created, time_updated)
			VALUES ('sess_a', 'write tests', 'completed', 'high', 0, 3000, 3100)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	tools, _, _ := parseZcode(t, dbPath)
	var found bool
	for _, ev := range tools {
		if ev.SourceEventID == "todo:sess_a:0:3100" {
			found = true
			if ev.ActionType != models.ActionTodoUpdate {
				t.Errorf("ActionType = %q, want %q", ev.ActionType, models.ActionTodoUpdate)
			}
			if ev.Target != "completed" {
				t.Errorf("Target = %q, want completed", ev.Target)
			}
			if ev.RawToolName != "todo.completed" {
				t.Errorf("RawToolName = %q, want todo.completed", ev.RawToolName)
			}
		}
	}
	if !found {
		t.Fatal("expected a todo ActionTodoUpdate event, got none")
	}
}

// TestStepFinishEvent covers `step-finish` parts -> ActionHarnessCall.
func TestStepFinishEvent(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), ".zcode", "cli", "db", "db.sqlite")
	setupZcodeDB(t, dbPath)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
		('prt_stepfin', 'msg_asst', 'sess_a', 2800, 2800, '{"type":"step-finish"}')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	tools, _, _ := parseZcode(t, dbPath)
	var found bool
	for _, ev := range tools {
		if ev.SourceEventID == "step:prt_stepfin" {
			found = true
			if ev.ActionType != models.ActionHarnessCall {
				t.Errorf("ActionType = %q, want %q", ev.ActionType, models.ActionHarnessCall)
			}
			if ev.SessionID != "sess_a" {
				t.Errorf("SessionID = %q, want sess_a", ev.SessionID)
			}
		}
	}
	if !found {
		t.Fatal("expected a step-finish ActionHarnessCall event, got none")
	}
}

// TestReadTranscript_ByHint covers the session-handoff transcript reader
// end to end, including the D-P0.1 hint resolution — a regression guard for
// the "zcode.db" vs "db.sqlite" basename bug found live 2026-08-25 (the
// hint/root lookup previously searched for a file that never exists).
func TestReadTranscript_ByHint(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), ".zcode", "cli", "db", "db.sqlite")
	setupZcodeDB(t, dbPath)
	a := NewWithOptions(nil, nil) // no watch roots — must resolve via hint
	msgs, err := a.ReadTranscript(context.Background(), models.Session{ID: "sess_a"}, []string{dbPath})
	if err != nil {
		t.Fatalf("ReadTranscript: %v", err)
	}
	if len(msgs) == 0 {
		t.Fatal("expected transcript messages, got 0")
	}
	var sawUser, sawAssistantText, sawToolCall bool
	for _, m := range msgs {
		switch m.Role {
		case models.TranscriptUser:
			sawUser = true
		case models.TranscriptAssistant:
			if m.Text != "" {
				sawAssistantText = true
			}
			if len(m.ToolCalls) > 0 {
				sawToolCall = true
			}
		}
	}
	if !sawUser {
		t.Error("no user message in transcript")
	}
	if !sawAssistantText {
		t.Error("no assistant text message in transcript")
	}
	if !sawToolCall {
		t.Error("no tool-call message in transcript")
	}
}

// TestReadTranscript_NoStoreFound proves the fixed lookup fails cleanly (not
// silently) when neither a hint nor a watch root holds a db.sqlite.
func TestReadTranscript_NoStoreFound(t *testing.T) {
	a := NewWithOptions(nil, []string{t.TempDir()})
	_, err := a.ReadTranscript(context.Background(), models.Session{ID: "sess_a"}, nil)
	if err == nil {
		t.Fatal("expected an error when no db.sqlite exists under any root, got nil")
	}
}

// TestCursorSemanticsFor covers the watermark-cursor descriptor for a
// db.sqlite session file, and the zero-value for a non-session path.
func TestCursorSemanticsFor(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".zcode", "cli", "db")
	a := NewWithOptions(nil, []string{root})
	dbPath := filepath.Join(root, "db.sqlite")
	setupZcodeDB(t, dbPath)

	sem := a.CursorSemanticsFor(dbPath)
	if sem.Kind != adapter.CursorWatermark {
		t.Errorf("Kind = %v, want CursorWatermark", sem.Kind)
	}

	other := filepath.Join(root, "not-a-session.txt")
	var zero adapter.FileCursorSemantics
	if got := a.CursorSemanticsFor(other); got != zero {
		t.Errorf("expected zero-value semantics for a non-session path, got %+v", got)
	}
}

func TestIsSessionFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".zcode", "cli", "db")
	a := NewWithOptions(nil, []string{root})
	cases := []struct {
		path string
		want bool
	}{
		{filepath.Join(root, "db.sqlite"), true},
		{filepath.Join(root, "db.sqlite-wal"), true},
		{filepath.Join(root, "other.db"), false},
		{filepath.Join(t.TempDir(), "elsewhere", "db.sqlite"), false},
	}
	for _, c := range cases {
		if got := a.IsSessionFile(c.path); got != c.want {
			t.Errorf("IsSessionFile(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// TestMapTool is a table-driven pin of every mapTool branch — the tool
// name -> ActionType classification that drives the dashboard's action
// taxonomy.
func TestMapTool(t *testing.T) {
	cases := []struct {
		name       string
		part       toolPartData
		wantAction string
		wantTarget string
		wantOK     bool
	}{
		{
			name: "bash success",
			part: toolPartData{Tool: "bash", State: struct {
				Status   string          `json:"status"`
				Input    json.RawMessage `json:"input"`
				Output   string          `json:"output"`
				Metadata struct {
					Output      string `json:"output"`
					Exit        int    `json:"exit"`
					Description string `json:"description"`
					FilePath    string `json:"filepath"`
					Truncated   bool   `json:"truncated"`
				} `json:"metadata"`
				Title string `json:"title"`
				Time  struct {
					Start int64 `json:"start"`
					End   int64 `json:"end"`
				} `json:"time"`
			}{Status: "completed", Input: json.RawMessage(`{"command":"ls -la"}`)}},
			wantAction: models.ActionRunCommand,
			wantTarget: "ls -la",
			wantOK:     true,
		},
		{
			name:       "read",
			part:       toolPartData{Tool: "read"},
			wantAction: models.ActionReadFile,
		},
		{
			name:       "write",
			part:       toolPartData{Tool: "write"},
			wantAction: models.ActionWriteFile,
		},
		{
			name:       "edit",
			part:       toolPartData{Tool: "edit"},
			wantAction: models.ActionEditFile,
		},
		{
			name:       "grep",
			part:       toolPartData{Tool: "grep"},
			wantAction: models.ActionSearchText,
		},
		{
			name:       "glob",
			part:       toolPartData{Tool: "glob"},
			wantAction: models.ActionSearchFiles,
		},
		{
			name:       "webfetch",
			part:       toolPartData{Tool: "webfetch"},
			wantAction: models.ActionWebFetch,
		},
		{
			name:       "websearch",
			part:       toolPartData{Tool: "websearch"},
			wantAction: models.ActionWebSearch,
		},
		{
			name:       "task spawns subagent",
			part:       toolPartData{Tool: "task"},
			wantAction: models.ActionSpawnSubagent,
		},
		{
			name:       "todowrite",
			part:       toolPartData{Tool: "todowrite"},
			wantAction: models.ActionTodoUpdate,
		},
		{
			name:       "mcp fallback",
			part:       toolPartData{Tool: "mcp__github__search"},
			wantAction: models.ActionMCPCall,
		},
		{
			name:       "unknown tool",
			part:       toolPartData{Tool: "something-new"},
			wantAction: models.ActionUnknown,
			wantTarget: "something-new",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotAction, gotTarget, gotOK, _ := mapTool(c.part)
			if gotAction != c.wantAction {
				t.Errorf("action = %q, want %q", gotAction, c.wantAction)
			}
			if c.wantTarget != "" && gotTarget != c.wantTarget {
				t.Errorf("target = %q, want %q", gotTarget, c.wantTarget)
			}
			if c.name == "bash success" && gotOK != c.wantOK {
				t.Errorf("success = %v, want %v", gotOK, c.wantOK)
			}
		})
	}
}

// TestMapTool_BashFailure pins the bash-specific failure path: a nonzero
// exit code flips success false and surfaces the output as errMsg.
func TestMapTool_BashFailure(t *testing.T) {
	var part toolPartData
	part.Tool = "bash"
	part.State.Status = "completed"
	part.State.Metadata.Exit = 1
	part.State.Output = "boom: command not found"
	_, _, ok, errMsg := mapTool(part)
	if ok {
		t.Error("expected success = false on nonzero exit")
	}
	if errMsg != "boom: command not found" {
		t.Errorf("errMsg = %q, want the bash output", errMsg)
	}
}

// TestChooseTime pins the three-way fallback: primary wins when set,
// else fallback+delta, else now+delta.
func TestChooseTime(t *testing.T) {
	primary := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fallback := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := chooseTime(primary, fallback, time.Hour); !got.Equal(primary) {
		t.Errorf("chooseTime with primary set = %v, want %v", got, primary)
	}
	want := fallback.Add(time.Hour)
	if got := chooseTime(time.Time{}, fallback, time.Hour); !got.Equal(want) {
		t.Errorf("chooseTime with only fallback set = %v, want %v", got, want)
	}
	before := time.Now().UTC()
	got := chooseTime(time.Time{}, time.Time{}, time.Minute)
	if got.Before(before.Add(time.Minute - time.Second)) {
		t.Errorf("chooseTime with neither set = %v, want ~now+1m", got)
	}
}

// TestLoadSubtaskEvents_ViaSubtaskPart exercises the defensive
// `type='subtask'` fallback path directly (loadSubtaskEvents) — not
// observed live on the grounded schema (zcode-app-cli 3.8.1-15 / runtime
// 0.16.3; the real live path is TestSubagentSpawn_ViaAgentTool's `tool`
// part), but kept as tested dead code rather than untested dead code.
func TestLoadSubtaskEvents_ViaSubtaskPart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), ".zcode", "cli", "db", "db.sqlite")
	setupZcodeDB(t, dbPath)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
		('prt_subtask', 'msg_asst', 'sess_a', 2800, 2800, '{"type":"subtask","prompt":"look around","description":"Explore repo","agent":"explore","time":{"created":2800}}')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	tools, _, _ := parseZcode(t, dbPath)
	var found bool
	for _, ev := range tools {
		if ev.SourceEventID == "subtask:prt_subtask" {
			found = true
			if ev.ActionType != models.ActionSpawnSubagent {
				t.Errorf("ActionType = %q, want %q", ev.ActionType, models.ActionSpawnSubagent)
			}
			if ev.Target != "explore" {
				t.Errorf("Target = %q, want explore", ev.Target)
			}
		}
	}
	if !found {
		t.Fatal("expected an ActionSpawnSubagent event from the subtask part, got none")
	}
}

// TestIsForeignMountPath_OnlyForeignHomes pins the foreign-mount detection
// helper's contract — only paths under crossmount-detected non-native
// homes match. Mirrors the opencode adapter's equivalent test (zcode is a
// structural transposition sharing the same mirror machinery).
func TestIsForeignMountPath_OnlyForeignHomes(t *testing.T) {
	orig := allHomesFunc
	t.Cleanup(func() { allHomesFunc = orig })
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{
			{Path: "/home/me", OS: crossmount.OSLinux, Origin: "native"},
			{Path: "/mnt/c/Users/auzy_", OS: crossmount.OSWindows, Origin: "wsl-mnt:auzy_"},
		}
	}
	cases := []struct {
		path string
		want bool
	}{
		{"/home/me/.zcode/cli/db/db.sqlite", false},
		{"/mnt/c/Users/auzy_/.zcode/cli/db/db.sqlite", true},
		{"/tmp/something", false},
		{"/mnt/c/Users/other/.zcode/cli/db/db.sqlite", false},
	}
	for _, tc := range cases {
		if got := isForeignMountPath(tc.path); got != tc.want {
			t.Errorf("isForeignMountPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestStageMirrorIfForeign_NativePassThrough pins the no-op fast path for
// a native (non-foreign-mount) path — no copy, no cache dir touched.
func TestStageMirrorIfForeign_NativePassThrough(t *testing.T) {
	orig := allHomesFunc
	t.Cleanup(func() { allHomesFunc = orig })
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{
			{Path: "/home/me", OS: crossmount.OSLinux, Origin: "native"},
		}
	}
	got, err := stageMirrorIfForeign("/home/me/.zcode/cli/db/db.sqlite")
	if err != nil {
		t.Fatalf("stageMirrorIfForeign: %v", err)
	}
	if got != "/home/me/.zcode/cli/db/db.sqlite" {
		t.Errorf("native path got remapped to %q (want passthrough)", got)
	}
}

// TestConfigJSONNeverDispatchedOrIngested is the security guard for zcode's
// plaintext provider apiKey. config.json (and config.json.backup) under
// ~/.zcode/cli carry apiKey values in the clear. This adapter reads ONLY
// db.sqlite, so those files must never be dispatched to the parser and their
// key must never surface in emitted rows. IsSessionFile's base-name allowlist
// (db.sqlite / db.sqlite-wal) is the structural control; this pins it against
// a regression that widened the glob to sweep the cli dir. The stand-in
// secret is built from the test name at runtime so no secret-shaped literal
// exists in source.
func TestConfigJSONNeverDispatchedOrIngested(t *testing.T) {
	cliDir := filepath.Join(t.TempDir(), ".zcode", "cli")
	dbPath := filepath.Join(cliDir, "db", "db.sqlite")
	setupZcodeDB(t, dbPath)

	sentinel := "plaintext-secret-" + t.Name()
	body := `{"provider":{"openrouter":{"apiKey":"` + sentinel + `"}}}`
	names := []string{"config.json", "config.json.backup", "settings.json"}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(cliDir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	a := NewWithOptions(nil, []string{cliDir})

	// (1) No config/secret file may be treated as a session file.
	for _, name := range names {
		if a.IsSessionFile(filepath.Join(cliDir, name)) {
			t.Errorf("IsSessionFile(%s) = true; plaintext-apiKey file must never be dispatched", name)
		}
	}

	// (2) Parsing db.sqlite must never surface the planted secret.
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	blob, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(blob), sentinel) {
		t.Errorf("emitted rows contain the plaintext-secret sentinel — leaked from config.json")
	}
}
