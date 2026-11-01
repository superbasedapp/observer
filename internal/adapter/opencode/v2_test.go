package opencode

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// v2DDL is the OpenCode 2.x session_v2 + session_message DDL, copied
// from upstream packages/core/src/database/schema.gen.ts at tag v2.1.1
// (the columns the reader does not use are kept so the fixture has the
// real shape). A fresh 2.x install has NO session/message/part table.
var v2DDL = []string{
	`CREATE TABLE project (id text PRIMARY KEY, worktree text NOT NULL, time_created integer NOT NULL, time_updated integer NOT NULL)`,
	`CREATE TABLE session_v2 (
		id text PRIMARY KEY, project_id text NOT NULL, workspace_id text, parent_id text,
		fork_session_id text, fork_boundary text, slug text NOT NULL, directory text NOT NULL,
		path text, title text, version text NOT NULL, share_url text, summary_additions integer,
		summary_deletions integer, summary_files integer, summary_diffs text, metadata text,
		cost real DEFAULT 0 NOT NULL, tokens_input integer DEFAULT 0 NOT NULL,
		tokens_output integer DEFAULT 0 NOT NULL, tokens_reasoning integer DEFAULT 0 NOT NULL,
		tokens_cache_read integer DEFAULT 0 NOT NULL, tokens_cache_write integer DEFAULT 0 NOT NULL,
		revert text, permission text, agent text, model text,
		time_created integer NOT NULL, time_updated integer NOT NULL, time_idle integer,
		time_viewed integer, idle_outcome text, time_compacting integer, time_archived integer,
		time_suspended integer, resume_attempts integer DEFAULT 0 NOT NULL)`,
	`CREATE TABLE session_message (
		id text PRIMARY KEY, session_id text NOT NULL, type text NOT NULL, seq integer NOT NULL,
		time_created integer NOT NULL, time_updated integer NOT NULL, data text NOT NULL)`,
}

// v2Rows is a synthetic 2.x session shaped like the live capture: a user
// prompt, two completed assistant steps (read + failing shell, then
// write + text, finish stop), a step still streaming a tool, a completed
// compaction with its own usage, and a child sub-agent session. No real
// conversation content.
var v2Rows = []string{
	`INSERT INTO session_v2 (id, project_id, slug, directory, version, time_created, time_updated)
		VALUES ('ses_root', 'global', 'quiet-river', '/tmp/oc2', '2.0.1', 1000, 9000)`,
	`INSERT INTO session_v2 (id, project_id, parent_id, slug, directory, version, time_created, time_updated)
		VALUES ('ses_child', 'global', 'ses_root', 'calm-lake', '/tmp/oc2', '2.0.1', 1500, 1600)`,
	`INSERT INTO session_message (id, session_id, type, seq, time_created, time_updated, data) VALUES
		('msg_u1', 'ses_root', 'user', 1, 1000, 1001,
		 '{"time":{"created":1000},"text":"Do the synthetic task","files":[]}'),
		('msg_a1', 'ses_root', 'assistant', 2, 2000, 2600,
		 '{"time":{"created":2000,"streamed":2500,"completed":2600},"agent":"build","model":{"id":"big-pickle","providerID":"opencode","variant":"default"},"content":[{"type":"reasoning","text":"Read first.","time":{"created":2001,"completed":2002}},{"type":"tool","id":"call_read","name":"read","state":{"status":"completed","input":{"path":"README.md"},"content":[{"type":"text","text":"1: # demo"}],"metadata":{"truncated":false}},"time":{"created":2100,"ran":2200,"completed":2250}},{"type":"tool","id":"call_sh","name":"shell","state":{"status":"completed","input":{"command":"make test"},"content":[{"type":"text","text":"boom"},{"type":"text","text":"Command exited with code 2."}],"metadata":{"exit":2}},"time":{"created":2300,"ran":2310,"completed":2400}}],"finish":"tool-calls","cost":0.01,"tokens":{"input":800,"output":20,"reasoning":5,"cache":{"read":0,"write":100}}}'),
		('msg_a2', 'ses_root', 'assistant', 3, 3000, 3600,
		 '{"time":{"created":3000,"completed":3600},"agent":"build","model":{"id":"big-pickle","providerID":"opencode","variant":"high"},"content":[{"type":"tool","id":"call_w","name":"write","state":{"status":"error","input":{"path":"out.txt","content":"x"},"error":{"type":"unknown","message":"denied"}},"time":{"created":3100,"completed":3200}},{"type":"reasoning","text":"Old thought."},{"type":"reasoning","text":"Wrap up."},{"type":"text","text":"All done."}],"finish":"stop","cost":0.002,"tokens":{"input":40,"output":10,"reasoning":0,"cache":{"read":800,"write":0}}}'),
		('msg_a3', 'ses_root', 'assistant', 4, 4000, 4100,
		 '{"time":{"created":4000},"agent":"build","model":{"id":"big-pickle","providerID":"opencode"},"content":[{"type":"tool","id":"call_run","name":"shell","state":{"status":"running","input":{"command":"sleep 1"},"metadata":{}},"time":{"created":4050}},{"type":"text","text":"partial"}]}'),
		('msg_c1', 'ses_root', 'compaction', 5, 5000, 9000,
		 '{"time":{"created":5000},"status":"completed","reason":"auto","summary":"s","model":{"id":"big-pickle","providerID":"opencode"},"cost":0.001,"tokens":{"input":300,"output":30,"reasoning":0,"cache":{"read":0,"write":0}}}'),
		('msg_idle', 'ses_root', 'idle', 6, 6000, 6000, '{"time":{"created":6000},"outcome":"succeeded"}')`,
}

func createDB(t *testing.T, path string, stmts ...[]string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, group := range stmts {
		for _, stmt := range group {
			if _, err := db.Exec(stmt); err != nil {
				t.Fatalf("exec %q: %v", stmt, err)
			}
		}
	}
}

func eventsByID(res []models.ToolEvent) map[string]models.ToolEvent {
	out := map[string]models.ToolEvent{}
	for _, ev := range res {
		out[ev.SourceEventID] = ev
	}
	return out
}

// TestParseSessionFile_V2FreshSchema pins the OpenCode 2.x reader against
// a fresh 2.x database that has no 1.x table at all (the operator's
// "no such table: session" case on a fresh Windows install).
func TestParseSessionFile_V2FreshSchema(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	createDB(t, path, v2DDL, v2Rows)

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if res.NewOffset != 9000 {
		t.Errorf("NewOffset = %d, want 9000 (max time_updated)", res.NewOffset)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", res.Warnings)
	}

	byID := eventsByID(res.ToolEvents)
	tests := []struct {
		id        string
		action    string
		target    string
		success   bool
		reasoning string
		effort    string
	}{
		{"message:msg_u1", models.ActionUserPrompt, "Do the synthetic task", true, "Do the synthetic task", ""},
		{"tool:msg_a1:call_read", models.ActionReadFile, "README.md", true, "Read first.", ""},
		{"tool:msg_a1:call_sh", models.ActionRunCommand, "make test", false, "", ""},
		{"tool:msg_a2:call_w", models.ActionWriteFile, "out.txt", false, "", "high"},
		{"asst:msg_a2:3", models.ActionAssistantMessage, "All done.", true, "Wrap up.", "high"},
		{"complete:msg_a2", models.ActionTaskComplete, "stop", true, "", "high"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			ev, ok := byID[tt.id]
			if !ok {
				t.Fatalf("missing event %s (have %v)", tt.id, keys(byID))
			}
			if ev.ActionType != tt.action || ev.Target != tt.target || ev.Success != tt.success {
				t.Errorf("got action=%q target=%q success=%v, want %q %q %v", ev.ActionType, ev.Target, ev.Success, tt.action, tt.target, tt.success)
			}
			if tt.reasoning != "" && ev.PrecedingReasoning != tt.reasoning {
				t.Errorf("PrecedingReasoning = %q, want %q", ev.PrecedingReasoning, tt.reasoning)
			}
			gotEffort := ""
			if ev.Metadata != nil {
				gotEffort = ev.Metadata.EffortLevel
			}
			if gotEffort != tt.effort {
				t.Errorf("effort = %q, want %q (variant \"default\" carries none)", gotEffort, tt.effort)
			}
			if ev.SessionID != "ses_root" || ev.Tool != models.ToolOpenCode {
				t.Errorf("session/tool = %q/%q", ev.SessionID, ev.Tool)
			}
		})
	}
	if got := len(res.ToolEvents); got != len(tests) {
		t.Errorf("tool events = %d, want %d (running tool, unfinished text and non-stop step markers are not rows): %v", got, len(tests), keys(byID))
	}
	if ev := byID["tool:msg_a1:call_sh"]; !strings.Contains(ev.ErrorMessage, "boom") || ev.DurationMs != 90 {
		t.Errorf("shell failure: err=%q duration=%d, want output excerpt and 90ms", ev.ErrorMessage, ev.DurationMs)
	}
	if ev := byID["tool:msg_a2:call_w"]; ev.ErrorMessage != "denied" {
		t.Errorf("tool error message = %q, want denied", ev.ErrorMessage)
	}
	if ev := byID["tool:msg_a1:call_read"]; ev.ToolOutput != "1: # demo" || ev.Model != "big-pickle" || ev.MessageID != "msg_a1" {
		t.Errorf("read event output=%q model=%q message=%q", ev.ToolOutput, ev.Model, ev.MessageID)
	}

	toks := map[string]models.TokenEvent{}
	for _, tk := range res.TokenEvents {
		toks[tk.SourceEventID] = tk
	}
	if len(toks) != 3 {
		t.Fatalf("token events = %d, want 3 (two steps + compaction): %v", len(toks), toks)
	}
	if tk := toks["tokens:msg_a2"]; tk.InputTokens != 40 || tk.CacheReadTokens != 800 || tk.OutputTokens != 10 || tk.EstimatedCostUSD != 0.002 {
		t.Errorf("step tokens = %+v, want input 40 (net) cache_read 800 output 10 cost 0.002", tk)
	}
	if tk := toks["tokens:msg_a1"]; tk.CacheCreationTokens != 100 || tk.ReasoningTokens != 5 {
		t.Errorf("step tokens = %+v, want cache_write 100 reasoning 5", tk)
	}
	if tk := toks["tokens:msg_c1"]; tk.InputTokens != 300 || tk.Model != "big-pickle" {
		t.Errorf("compaction tokens = %+v", tk)
	}

	if len(res.SessionLineages) != 1 || res.SessionLineages[0].SessionID != "ses_child" || res.SessionLineages[0].ParentThreadID != "ses_root" {
		t.Errorf("lineages = %+v", res.SessionLineages)
	}
	if len(res.SessionToolVersions) != 1 || res.SessionToolVersions[0].Version != "2.0.1" {
		t.Errorf("tool versions = %+v", res.SessionToolVersions)
	}

	// Incremental: nothing new past the returned cursor.
	again, err := a.ParseSessionFile(context.Background(), path, res.NewOffset)
	if err != nil {
		t.Fatalf("incremental parse: %v", err)
	}
	if len(again.ToolEvents) != 0 || len(again.TokenEvents) != 0 {
		t.Errorf("incremental parse re-emitted %d tool / %d token events", len(again.ToolEvents), len(again.TokenEvents))
	}

	// The running step settles: its row is rewritten with a newer
	// time_updated and the settled tool + text now become rows.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE session_message SET time_updated = 9500, data = ? WHERE id = 'msg_a3'`,
		`{"time":{"created":4000,"completed":9400},"agent":"build","model":{"id":"big-pickle","providerID":"opencode"},"content":[{"type":"tool","id":"call_run","name":"shell","state":{"status":"completed","input":{"command":"sleep 1"},"content":[{"type":"text","text":"ok"}],"metadata":{"exit":0}},"time":{"created":4050,"ran":4060,"completed":5060}},{"type":"text","text":"finished"}],"finish":"stop","tokens":{"input":1,"output":1,"reasoning":0,"cache":{"read":0,"write":0}}}`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	settled, err := a.ParseSessionFile(context.Background(), path, res.NewOffset)
	if err != nil {
		t.Fatalf("settled parse: %v", err)
	}
	got := eventsByID(settled.ToolEvents)
	for _, id := range []string{"tool:msg_a3:call_run", "asst:msg_a3:1", "complete:msg_a3"} {
		if _, ok := got[id]; !ok {
			t.Errorf("settled step missing %s (have %v)", id, keys(got))
		}
	}
	if ev := got["tool:msg_a3:call_run"]; !ev.Success {
		t.Errorf("exit 0 shell should succeed")
	}
	if settled.NewOffset != 9500 {
		t.Errorf("settled NewOffset = %d, want 9500", settled.NewOffset)
	}
}

// TestParseSessionFile_V2BesideV1SkipsMigratedMessages pins the upgrade
// case: OpenCode 2.x copies every 1.x message into session_message under
// the SAME id and keeps the 1.x tables. The 1.x reader owns those; the
// 2.x reader emits only messages written after the upgrade.
func TestParseSessionFile_V2BesideV1SkipsMigratedMessages(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	setupOpenCodeDB(t, path)
	createDB(t, path, v2DDL, []string{
		`INSERT INTO session_v2 (id, project_id, slug, directory, version, time_created, time_updated)
			VALUES ('ses_1', 'global', 'a', '/tmp/oc', '1.14.29', 1, 10)`,
		// msg_user is the migrated copy of the 1.x message of the same id.
		`INSERT INTO session_message (id, session_id, type, seq, time_created, time_updated, data) VALUES
			('msg_user', 'ses_1', 'user', 0, 1, 2, '{"time":{"created":1},"text":"Build the app"}'),
			('msg_new', 'ses_1', 'user', 9, 20, 99999999, '{"time":{"created":20},"text":"Continue after upgrade"}')`,
	})

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	prompts := 0
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionUserPrompt {
			prompts++
			if ev.Target == "Continue after upgrade" && ev.SourceEventID != "message:msg_new" {
				t.Errorf("post-upgrade prompt id = %q", ev.SourceEventID)
			}
		}
	}
	// One prompt from the 1.x reader (msg_user) + one post-upgrade 2.x
	// prompt; the migrated 2.x copy of msg_user must not be a third.
	if prompts != 2 {
		t.Errorf("user prompts = %d, want 2 (1.x msg_user + 2.x msg_new, migrated copy skipped)", prompts)
	}
	if res.NewOffset != 99999999 {
		t.Errorf("NewOffset = %d, want the session_message watermark", res.NewOffset)
	}
}

// TestParseSessionFile_NoSchemaWarnsOnce pins the store-not-ready path: a
// database with neither generation is not an error, keeps the cursor,
// and warns once per file across the .db and -wal events.
func TestParseSessionFile_NoSchemaWarnsOnce(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	createDB(t, path, []string{`CREATE TABLE kv (key text PRIMARY KEY, value text)`})
	t.Cleanup(func() { adapter.ClearNotReady(models.ToolOpenCode, path) })

	a := NewWithOptions(nil, []string{root})
	tests := []struct {
		name      string
		path      string
		wantWarns int
	}{
		{"first sight warns", path, 1},
		{"second scan is quiet", path, 0},
		{"wal event resolves to the same db and is quiet", path + "-wal", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := a.ParseSessionFile(context.Background(), tt.path, 42)
			if err != nil {
				t.Fatalf("ParseSessionFile: %v (a missing table must not be an error)", err)
			}
			if res.NewOffset != 42 {
				t.Errorf("NewOffset = %d, want the unchanged cursor 42", res.NewOffset)
			}
			if len(res.Warnings) != tt.wantWarns {
				t.Errorf("warnings = %v, want %d", res.Warnings, tt.wantWarns)
			}
			if len(res.ToolEvents)+len(res.TokenEvents) != 0 {
				t.Errorf("rows emitted from an empty store")
			}
		})
	}

	// The tables appear (OpenCode finished bootstrapping): parsing works
	// and a later regression would warn again.
	createDB(t, path, v2DDL, v2Rows)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil || len(res.ToolEvents) == 0 {
		t.Fatalf("after bootstrap: err=%v events=%d", err, len(res.ToolEvents))
	}
	// A known schema clears the once-only marker, so a later regression
	// (tables gone again) is reported again.
	createDB(t, path, []string{`DROP TABLE session_message`, `DROP TABLE session_v2`})
	res, err = a.ParseSessionFile(context.Background(), path, 0)
	if err != nil || len(res.Warnings) != 1 {
		t.Errorf("after regression: err=%v warnings=%v, want one fresh warning", err, res.Warnings)
	}
}

// TestIsSessionFile_NeverClaimsSHM pins that only the database and its
// WAL are session files, and both resolve to the database itself.
func TestIsSessionFile_NeverClaimsSHM(t *testing.T) {
	root := t.TempDir()
	a := NewWithOptions(nil, []string{root})
	db := filepath.Join(root, "opencode.db")
	tests := []struct {
		path    string
		claimed bool
		resolve string
	}{
		{db, true, db},
		{db + "-wal", true, db},
		{db + "-shm", false, db},
		{filepath.Join(root, "opencode-dev.db"), false, filepath.Join(root, "opencode-dev.db")},
	}
	for _, tt := range tests {
		if got := a.IsSessionFile(tt.path); got != tt.claimed {
			t.Errorf("IsSessionFile(%s) = %v, want %v", filepath.Base(tt.path), got, tt.claimed)
		}
		if got := resolveDBPath(tt.path); got != tt.resolve {
			t.Errorf("resolveDBPath(%s) = %s, want %s", filepath.Base(tt.path), got, tt.resolve)
		}
	}
}

// TestReadTranscript_V2 pins session-handoff transcript reads over a 2.x
// session.
func TestReadTranscript_V2(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	createDB(t, path, v2DDL, v2Rows)
	a := NewWithOptions(nil, []string{root})
	msgs, err := a.ReadTranscript(context.Background(), models.Session{ID: "ses_root"}, []string{path})
	if err != nil {
		t.Fatalf("ReadTranscript: %v", err)
	}
	if len(msgs) == 0 {
		t.Fatal("empty transcript for a 2.x session")
	}
	if msgs[0].Role != "user" {
		t.Errorf("first message role = %q, want user", msgs[0].Role)
	}
}

func keys(m map[string]models.ToolEvent) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
