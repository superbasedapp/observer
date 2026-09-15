package openclaw

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// agentFixtureSessionID is the session both fixture layouts describe.
const agentFixtureSessionID = "sess-2-0-alpha"

// agentFixture is the OpenClaw 2.0 store + its pre-2.0 twin, written
// from ONE list of transcript entries so the two layouts can be proven
// to parse identically.
type agentFixture struct {
	root       string
	dbPath     string
	legacyPath string
	entries    []string
	cwd        string
}

// buildAgentFixture writes agents/main/agent/openclaw-agent.sqlite and
// the byte-equivalent agents/main/sessions/<sid>.jsonl. model/provider
// are written onto session_windows only when non-empty — the equality
// test leaves them NULL so the DB path gets no seed the JSONL path
// cannot have.
//
// transcript_events.seq is written 1-based so it lines up with the
// JSONL file's 1-based line numbering; that correspondence is what
// makes the two layouts' synthesized (id-less) SourceEventIDs match.
func buildAgentFixture(t *testing.T, provider, model string) agentFixture {
	t.Helper()

	root := t.TempDir()
	agentDir := filepath.Join(root, "agents", "main", "agent")
	sessionsDir := filepath.Join(root, "agents", "main", "sessions")
	cwd := filepath.Join(root, "workspace")
	for _, d := range []string{agentDir, sessionsDir, cwd} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cwdJSON, err := json.Marshal(cwd)
	if err != nil {
		t.Fatal(err)
	}

	entries := []string{
		fmt.Sprintf(`{"type":"session","id":%q,"cwd":%s,"timestamp":"2026-08-30T10:00:00.000Z"}`,
			agentFixtureSessionID, cwdJSON),
		`{"type":"message","id":"u1","timestamp":"2026-08-30T10:00:01.000Z","message":{"role":"user","content":[{"type":"text","text":"List the files in this repo."}],"timestamp":1787047201000}}`,
		`{"type":"message","id":"a1","timestamp":"2026-08-30T10:00:02.000Z","message":{"role":"assistant","provider":"anthropic","model":"claude-sonnet-4","content":[{"type":"text","text":"I'll list them."},{"type":"toolCall","id":"tc1","name":"bash","arguments":{"command":"ls -la"}}],"usage":{"input":120,"output":45,"cacheRead":1000,"cacheWrite":10},"timestamp":1787047202000}}`,
		`{"type":"message","id":"r1","timestamp":"2026-08-30T10:00:03.000Z","message":{"role":"toolResult","toolCallId":"tc1","content":[{"type":"text","text":"total 8\ndrwxr-xr-x  2 u u 4096 ."}],"timestamp":1787047203000}}`,
		`{"type":"compaction","id":"c1","timestamp":"2026-08-30T10:00:04.000Z","firstKeptEntryId":"a1","tokensBefore":5000}`,
	}

	legacyPath := filepath.Join(sessionsDir, agentFixtureSessionID+".jsonl")
	if err := os.WriteFile(legacyPath, []byte(strings.Join(entries, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(agentDir, agentDBBase)
	writeAgentDB(t, dbPath, provider, model, entries, 1787047200000)

	return agentFixture{root: root, dbPath: dbPath, legacyPath: legacyPath, entries: entries, cwd: cwd}
}

// writeAgentDB creates the subset of the OpenClaw 2.0 per-agent schema
// the adapter reads (vendor src/state/openclaw-agent-schema.sql, PR
// #78595). Column LISTS are grounded; exact types/constraints are not,
// so the reader is written to be tolerant of both.
func writeAgentDB(t *testing.T, dbPath, provider, model string, entries []string, createdAtBase int64) {
	t.Helper()

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	stmts := []string{
		`CREATE TABLE session_nodes (
			session_key TEXT PRIMARY KEY,
			current_session_id TEXT,
			entry_json TEXT,
			entry_valid INTEGER,
			updated_at INTEGER,
			status TEXT,
			created_at INTEGER,
			project_id TEXT,
			parent_session_key TEXT,
			spawned_by TEXT,
			label TEXT,
			display_name TEXT,
			pinned_at INTEGER,
			archived_at INTEGER,
			last_activity_at INTEGER
		)`,
		`CREATE TABLE session_windows (
			session_id TEXT PRIMARY KEY,
			session_key TEXT,
			previous_session_id TEXT,
			reason TEXT,
			session_scope TEXT,
			created_at INTEGER,
			updated_at INTEGER,
			started_at INTEGER,
			ended_at INTEGER,
			status TEXT,
			chat_type TEXT,
			channel TEXT,
			account_id TEXT,
			model_provider TEXT,
			model TEXT,
			agent_harness_id TEXT,
			display_name TEXT
		)`,
		`CREATE TABLE transcript_events (
			session_id TEXT NOT NULL,
			seq INTEGER NOT NULL,
			event_json TEXT NOT NULL,
			created_at INTEGER,
			PRIMARY KEY (session_id, seq)
		)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec schema: %v", err)
		}
	}

	entryJSON := fmt.Sprintf(
		`{"sessionId":%q,"sessionStartedAt":%d,"chatType":"agent","inputTokens":9999,"outputTokens":8888,"totalTokens":18887}`,
		agentFixtureSessionID, createdAtBase)
	if _, err := db.Exec(
		`INSERT INTO session_nodes (session_key, current_session_id, entry_json, entry_valid, updated_at, status)
		 VALUES (?, ?, ?, 1, ?, 'active')`,
		"agent:main:explicit:"+agentFixtureSessionID, agentFixtureSessionID, entryJSON, createdAtBase); err != nil {
		t.Fatal(err)
	}

	var p, m any
	if provider != "" {
		p = provider
	}
	if model != "" {
		m = model
	}
	if _, err := db.Exec(
		`INSERT INTO session_windows (session_id, session_key, reason, created_at, started_at, status, chat_type, channel, model_provider, model)
		 VALUES (?, ?, 'new', ?, ?, 'active', 'agent', 'cli', ?, ?)`,
		agentFixtureSessionID, "agent:main:explicit:"+agentFixtureSessionID,
		createdAtBase, createdAtBase, p, m); err != nil {
		t.Fatal(err)
	}

	for i, e := range entries {
		if _, err := db.Exec(
			`INSERT INTO transcript_events (session_id, seq, event_json, created_at) VALUES (?, ?, ?, ?)`,
			agentFixtureSessionID, i+1, e, createdAtBase+int64(i)*1000); err != nil {
			t.Fatalf("insert transcript event %d: %v", i, err)
		}
	}
}

// TestParseAgentDB_MatchesLegacyJSONL is the dedup contract: the same
// transcript entries, read out of the 2.0 store and out of the pre-2.0
// message log, must produce IDENTICAL events — same SourceFile, same
// SourceEventIDs, same tokens — so a session imported by `openclaw
// doctor --fix` collides on UNIQUE(source_file, source_event_id)
// instead of being ingested twice.
func TestParseAgentDB_MatchesLegacyJSONL(t *testing.T) {
	fx := buildAgentFixture(t, "", "")
	a := NewWithOptions(nil, []string{fx.root})
	ctx := context.Background()

	fromDB, err := a.ParseSessionFile(ctx, fx.dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile(sqlite): %v", err)
	}
	fromJSONL, err := a.ParseSessionFile(ctx, fx.legacyPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile(jsonl): %v", err)
	}

	if len(fromJSONL.ToolEvents) == 0 || len(fromJSONL.TokenEvents) == 0 {
		t.Fatalf("legacy fixture produced nothing: %d tool events, %d token events",
			len(fromJSONL.ToolEvents), len(fromJSONL.TokenEvents))
	}
	if !reflect.DeepEqual(fromDB.ToolEvents, fromJSONL.ToolEvents) {
		t.Fatalf("tool events differ:\n sqlite=%+v\n jsonl =%+v", fromDB.ToolEvents, fromJSONL.ToolEvents)
	}
	if !reflect.DeepEqual(fromDB.TokenEvents, fromJSONL.TokenEvents) {
		t.Fatalf("token events differ:\n sqlite=%+v\n jsonl =%+v", fromDB.TokenEvents, fromJSONL.TokenEvents)
	}
	if !reflect.DeepEqual(fromDB.CacheObservations, fromJSONL.CacheObservations) {
		t.Fatalf("cache observations differ")
	}
	if len(fromDB.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", fromDB.Warnings)
	}

	// The SQLite path must stamp the canonical LEGACY path, never the
	// DB path — that is the whole dedup mechanism.
	for _, ev := range fromDB.ToolEvents {
		if ev.SourceFile != fx.legacyPath {
			t.Fatalf("tool event %q source_file = %q, want %q", ev.SourceEventID, ev.SourceFile, fx.legacyPath)
		}
	}
	for _, ev := range fromDB.TokenEvents {
		if ev.SourceFile != fx.legacyPath {
			t.Fatalf("token event %q source_file = %q, want %q", ev.SourceEventID, ev.SourceFile, fx.legacyPath)
		}
	}

	var in, out, cr, cw int64
	for _, ev := range fromDB.TokenEvents {
		in += ev.InputTokens
		out += ev.OutputTokens
		cr += ev.CacheReadTokens
		cw += ev.CacheCreationTokens
	}
	if in != 120 || out != 45 || cr != 1000 || cw != 10 {
		t.Fatalf("token totals = %d/%d/%d/%d, want 120/45/1000/10", in, out, cr, cw)
	}
	// The session-level counters on session_nodes.entry_json
	// (9999/8888) must NEVER be added on top of per-call usage.
	if in >= 9999 {
		t.Fatalf("session-level entry_json counters leaked into token rows: input=%d", in)
	}
}

// TestParseAgentDB_WatermarkAdvancesAndStops pins the row watermark:
// a second parse from the returned offset emits nothing.
func TestParseAgentDB_WatermarkAdvancesAndStops(t *testing.T) {
	fx := buildAgentFixture(t, "", "")
	a := NewWithOptions(nil, []string{fx.root})
	ctx := context.Background()

	first, err := a.ParseSessionFile(ctx, fx.dbPath, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	if first.NewOffset != int64(len(fx.entries)) {
		t.Fatalf("NewOffset = %d, want %d (MAX(rowid))", first.NewOffset, len(fx.entries))
	}

	second, err := a.ParseSessionFile(ctx, fx.dbPath, first.NewOffset)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	if len(second.ToolEvents) != 0 || len(second.TokenEvents) != 0 {
		t.Fatalf("re-parse past the watermark emitted %d tool / %d token events",
			len(second.ToolEvents), len(second.TokenEvents))
	}
	if second.NewOffset != first.NewOffset {
		t.Fatalf("watermark moved on an empty delta: %d -> %d", first.NewOffset, second.NewOffset)
	}
}

// TestParseAgentDB_WALTriggerResolvesToMainFile pins that the `-wal`
// sidecar is a trigger only — fsnotify reports the WAL write, and the
// parse must open the main database.
func TestParseAgentDB_WALTriggerResolvesToMainFile(t *testing.T) {
	fx := buildAgentFixture(t, "", "")
	a := NewWithOptions(nil, []string{fx.root})
	ctx := context.Background()

	viaMain, err := a.ParseSessionFile(ctx, fx.dbPath, 0)
	if err != nil {
		t.Fatalf("parse main: %v", err)
	}
	viaWAL, err := a.ParseSessionFile(ctx, fx.dbPath+"-wal", 0)
	if err != nil {
		t.Fatalf("parse -wal: %v", err)
	}
	if !reflect.DeepEqual(viaMain.ToolEvents, viaWAL.ToolEvents) {
		t.Fatalf("-wal trigger produced different events than the main file")
	}
	if viaWAL.NewOffset != viaMain.NewOffset {
		t.Fatalf("-wal offset = %d, main = %d", viaWAL.NewOffset, viaMain.NewOffset)
	}
}

// TestParseAgentDB_ModelFromSessionWindows pins the session-level model
// fallback: entries that carry no provider/model of their own inherit
// session_windows.model / model_provider.
func TestParseAgentDB_ModelFromSessionWindows(t *testing.T) {
	fx := buildAgentFixture(t, "anthropic", "claude-opus-4")
	a := NewWithOptions(nil, []string{fx.root})

	res, err := a.ParseSessionFile(context.Background(), fx.dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var userPrompt *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].ActionType == models.ActionUserPrompt {
			userPrompt = &res.ToolEvents[i]
			break
		}
	}
	if userPrompt == nil {
		t.Fatal("no user_prompt event")
	}
	if !strings.Contains(userPrompt.Model, "claude-opus-4") {
		t.Fatalf("user prompt model = %q, want it to carry session_windows.model", userPrompt.Model)
	}
	if userPrompt.SessionID != agentFixtureSessionID {
		t.Fatalf("session id = %q, want %q", userPrompt.SessionID, agentFixtureSessionID)
	}
	if userPrompt.ProjectRoot == "" || userPrompt.ProjectRoot == "[openclaw]" {
		t.Fatalf("project root unresolved: %q", userPrompt.ProjectRoot)
	}
}

// TestParseAgentDB_FallsBackToCreatedAt covers a transcript entry with
// no timestamp of its own: the row's created_at column supplies it,
// through the seconds/millis helper.
func TestParseAgentDB_FallsBackToCreatedAt(t *testing.T) {
	root := t.TempDir()
	agentDir := filepath.Join(root, "agents", "main", "agent")
	if err := os.MkdirAll(agentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(agentDir, agentDBBase)
	const createdAtSeconds = int64(1787047200)
	writeAgentDB(t, dbPath, "", "", []string{
		`{"type":"message","id":"u1","message":{"role":"user","content":[{"type":"text","text":"hello"}]}}`,
	}, createdAtSeconds)

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 1 {
		t.Fatalf("expected 1 event, got %d", len(res.ToolEvents))
	}
	want := time.Unix(createdAtSeconds, 0).UTC()
	if !res.ToolEvents[0].Timestamp.Equal(want) {
		t.Fatalf("timestamp = %s, want %s", res.ToolEvents[0].Timestamp, want)
	}
}

// TestParseAgentDB_ToleratesMissingTables pins the tableExists-tolerant
// posture: a store without transcript_events is not an error.
func TestParseAgentDB_ToleratesMissingTables(t *testing.T) {
	root := t.TempDir()
	agentDir := filepath.Join(root, "agents", "main", "agent")
	if err := os.MkdirAll(agentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(agentDir, agentDBBase)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE unrelated (id TEXT)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 7)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 0 || res.NewOffset != 7 {
		t.Fatalf("expected a no-op parse, got %d events / offset %d", len(res.ToolEvents), res.NewOffset)
	}
}

// TestParseAgentDB_MalformedEventWarnsAndContinues pins that one bad
// event_json row does not abort the delta.
func TestParseAgentDB_MalformedEventWarnsAndContinues(t *testing.T) {
	root := t.TempDir()
	agentDir := filepath.Join(root, "agents", "main", "agent")
	if err := os.MkdirAll(agentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(agentDir, agentDBBase)
	writeAgentDB(t, dbPath, "", "", []string{
		`{not json`,
		`{"type":"message","id":"u1","timestamp":"2026-08-30T10:00:01.000Z","message":{"role":"user","content":[{"type":"text","text":"still captured"}]}}`,
	}, 1787047200000)

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.Warnings) != 1 {
		t.Fatalf("warnings = %v, want exactly 1", res.Warnings)
	}
	if len(res.ToolEvents) != 1 || res.ToolEvents[0].Target != "still captured" {
		t.Fatalf("good row not captured: %+v", res.ToolEvents)
	}
}

func TestIsSessionFile_AgentDBMatrix(t *testing.T) {
	root := t.TempDir()
	a := NewWithOptions(nil, []string{root})
	agentDir := filepath.Join(root, "agents", "main", "agent")
	sessionsDir := filepath.Join(root, "agents", "main", "sessions")

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"2.0 per-agent store", filepath.Join(agentDir, "openclaw-agent.sqlite"), true},
		{"2.0 store WAL sidecar", filepath.Join(agentDir, "openclaw-agent.sqlite-wal"), true},
		{"unrelated sqlite in the agent dir", filepath.Join(agentDir, "other.sqlite"), false},
		{"store outside an agents tree", filepath.Join(root, "agent", "openclaw-agent.sqlite"), false},
		{"store not in the agent dir", filepath.Join(sessionsDir, "openclaw-agent.sqlite"), false},
		{"pre-2.0 message log", filepath.Join(sessionsDir, "abc123.jsonl"), true},
		{"pre-2.0 trajectory", filepath.Join(sessionsDir, "abc123.trajectory.jsonl"), true},
		{"pre-2.0 session index", filepath.Join(sessionsDir, "sessions.json"), true},
		{"task runs db", filepath.Join(root, "runs.sqlite"), true},
		{"task runs wal", filepath.Join(root, "runs.sqlite-wal"), true},
		{"unrelated file", filepath.Join(sessionsDir, "notes.txt"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.IsSessionFile(tc.path); got != tc.want {
				t.Fatalf("IsSessionFile(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestIsSessionFile_AgentDBOutsideWatchRootsRejected(t *testing.T) {
	a := NewWithOptions(nil, []string{t.TempDir()})
	stray := filepath.Join(t.TempDir(), "agents", "main", "agent", "openclaw-agent.sqlite")
	if a.IsSessionFile(stray) {
		t.Fatalf("IsSessionFile accepted %q outside the watch roots", stray)
	}
}

func TestEpochToTime(t *testing.T) {
	cases := []struct {
		name string
		in   int64
		want time.Time
	}{
		{"zero", 0, time.Time{}},
		{"negative", -5, time.Time{}},
		{"seconds", 1787047200, time.Unix(1787047200, 0).UTC()},
		{"millis", 1787047200000, time.UnixMilli(1787047200000).UTC()},
		{"just below the cutoff is seconds", epochMillisCutoff - 1, time.Unix(epochMillisCutoff-1, 0).UTC()},
		{"at the cutoff is millis", epochMillisCutoff, time.UnixMilli(epochMillisCutoff).UTC()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := epochToTime(tc.in); !got.Equal(tc.want) {
				t.Fatalf("epochToTime(%d) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

func TestLegacySourceFile(t *testing.T) {
	db := filepath.Join("home", ".openclaw", "agents", "main", "agent", agentDBBase)
	want := filepath.Join("home", ".openclaw", "agents", "main", "sessions", "sid.jsonl")
	if got := legacySourceFile(db, "sid"); got != want {
		t.Fatalf("legacySourceFile = %q, want %q", got, want)
	}
	// No session id, or an unexpected layout, degrades to the DB path
	// rather than inventing an alias.
	if got := legacySourceFile(db, ""); got != db {
		t.Fatalf("empty session id: got %q, want %q", got, db)
	}
	odd := filepath.Join("somewhere", agentDBBase)
	if got := legacySourceFile(odd, "sid"); got != odd {
		t.Fatalf("unexpected layout: got %q, want %q", got, odd)
	}
}

// TestAssistantTextEventIDIgnoresOrdinal is the O1 unit pin: an entry
// that carries its own id must produce the SAME assistant-text
// SourceEventID no matter what file position it was read at. Only an
// id-LESS entry may fall back to the ordinal (which is the scheme every
// other row in this adapter already uses).
func TestAssistantTextEventIDIgnoresOrdinal(t *testing.T) {
	const body = "I'll list them."
	cases := []struct {
		name        string
		entryID     string
		a, b        int // two different ordinals for the same entry
		wantsSameID bool
	}{
		{"entry with id", "a1", 0, 1, true},
		{"entry with id, wide gap", "a1", 3, 4096, true},
		{"id-less entry falls back to the ordinal", "", 0, 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotA := assistantTextEventID(tc.entryID, tc.a, 0, body)
			gotB := assistantTextEventID(tc.entryID, tc.b, 0, body)
			if (gotA == gotB) != tc.wantsSameID {
				t.Fatalf("ids at ordinals %d/%d = %q / %q; same = %v, want %v",
					tc.a, tc.b, gotA, gotB, gotA == gotB, tc.wantsSameID)
			}
			if tc.entryID != "" && strings.Contains(gotA, ":L") {
				t.Errorf("id %q still carries a file-position component", gotA)
			}
		})
	}

	// partIdx and the content hash still discriminate within one entry.
	if a, b := assistantTextEventID("a1", 0, 0, body), assistantTextEventID("a1", 0, 1, body); a == b {
		t.Errorf("two parts of one entry collided on %q", a)
	}
	if a, b := assistantTextEventID("a1", 0, 0, body), assistantTextEventID("a1", 0, 0, body+"!"); a == b {
		t.Errorf("two different bodies collided on %q", a)
	}
}

// TestParseAgentDB_ZeroBasedSeqMatchesLegacyJSONL is the O1 end-to-end
// pin. The two capture paths number entries differently — the message
// log counts LINES 1-based, the store carries whatever `seq` its writer
// chose — so a session imported by `openclaw doctor --fix` and then read
// out of the store must STILL land the same SourceEventIDs as the log,
// even when seq is 0-based. Before the fix, the assistant-text row alone
// interpolated the ordinal and every assistant message double-ingested.
func TestParseAgentDB_ZeroBasedSeqMatchesLegacyJSONL(t *testing.T) {
	fx := buildAgentFixture(t, "", "")
	rebaseSeqToZero(t, fx.dbPath)

	a := NewWithOptions(nil, []string{fx.root})
	ctx := context.Background()

	fromDB, err := a.ParseSessionFile(ctx, fx.dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile(sqlite): %v", err)
	}
	fromJSONL, err := a.ParseSessionFile(ctx, fx.legacyPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile(jsonl): %v", err)
	}

	dbIDs := assistantTextIDs(fromDB)
	jsonlIDs := assistantTextIDs(fromJSONL)
	if len(jsonlIDs) == 0 {
		t.Fatal("fixture produced no assistant_message rows")
	}
	if !reflect.DeepEqual(dbIDs, jsonlIDs) {
		t.Fatalf("assistant-text SourceEventIDs differ under 0-based seq:\n sqlite=%v\n jsonl =%v", dbIDs, jsonlIDs)
	}
	for _, id := range dbIDs {
		if strings.Contains(id, ":L") {
			t.Errorf("assistant-text id %q still carries a file-position component", id)
		}
	}
}

// rebaseSeqToZero rewrites transcript_events.seq from 1-based to
// 0-based. The shift goes via a far-away offset so the
// PRIMARY KEY (session_id, seq) is never transiently violated.
func rebaseSeqToZero(t *testing.T, dbPath string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`UPDATE transcript_events SET seq = seq - 1000000`,
		`UPDATE transcript_events SET seq = seq + 999999`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("rebase seq (%s): %v", q, err)
		}
	}
}

func assistantTextIDs(res adapter.ParseResult) []string {
	var out []string
	for _, ev := range res.ToolEvents {
		if ev.RawToolName == "openclaw.assistant_text" {
			out = append(out, ev.SourceEventID)
		}
	}
	return out
}

// TestParseAgentDB_CreatedAtWatermarkKeepsBoundaryMillisecond is the
// second half of O1. When transcript_events has no usable rowid the
// watermark is MAX(created_at) — an epoch MILLISECOND that several rows
// of one model turn routinely share. A strict `>` delta would skip
// forever any row that shared the previous max but landed after the
// watermark was taken; `>=` re-reads that millisecond instead, and the
// UNIQUE(source_file, source_event_id) index absorbs the overlap.
func TestParseAgentDB_CreatedAtWatermarkKeepsBoundaryMillisecond(t *testing.T) {
	fx, dbPath := buildWithoutRowIDFixture(t)
	a := NewWithOptions(nil, []string{fx})
	ctx := context.Background()

	first, err := a.ParseSessionFile(ctx, dbPath, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	if first.NewOffset != 3000 {
		t.Fatalf("watermark = %d, want the max created_at 3000 (rowid must be unusable here)", first.NewOffset)
	}
	if !hasUserPrompt(first, "first prompt") {
		t.Fatalf("first parse missed the seeded rows: %+v", first.ToolEvents)
	}

	// A row that shares the watermark millisecond but was written AFTER
	// the watermark was read, plus a strictly-newer row that makes the
	// watermark advance at all.
	insertTranscriptRows(t, dbPath, [][3]any{
		{int64(90), `{"type":"message","id":"u-boundary","timestamp":"2026-08-30T10:00:03.000Z","message":{"role":"user","content":[{"type":"text","text":"boundary prompt"}],"timestamp":1787047203000}}`, int64(3000)},
		{int64(91), `{"type":"message","id":"u-later","timestamp":"2026-08-30T10:00:04.000Z","message":{"role":"user","content":[{"type":"text","text":"later prompt"}],"timestamp":1787047204000}}`, int64(4000)},
	})

	second, err := a.ParseSessionFile(ctx, dbPath, first.NewOffset)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	if !hasUserPrompt(second, "boundary prompt") {
		t.Errorf("the row sharing the watermark millisecond was LOST (a strict `>` delta): %+v", second.ToolEvents)
	}
	if !hasUserPrompt(second, "later prompt") {
		t.Errorf("the strictly-newer row was not read: %+v", second.ToolEvents)
	}
	if second.NewOffset != 4000 {
		t.Errorf("second watermark = %d, want 4000", second.NewOffset)
	}

	// An idle tick (no new rows) must still emit nothing: the caller's
	// `latest <= fromOffset` early return is what keeps `>=` from
	// re-reading the boundary on every poll.
	third, err := a.ParseSessionFile(ctx, dbPath, second.NewOffset)
	if err != nil {
		t.Fatalf("third parse: %v", err)
	}
	if len(third.ToolEvents) != 0 || len(third.TokenEvents) != 0 {
		t.Errorf("idle re-parse emitted %d tool / %d token events, want none",
			len(third.ToolEvents), len(third.TokenEvents))
	}
}

func hasUserPrompt(res adapter.ParseResult, want string) bool {
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionUserPrompt && strings.Contains(ev.Target, want) {
			return true
		}
	}
	return false
}

// buildWithoutRowIDFixture writes an agent store whose transcript_events
// is WITHOUT ROWID, so `SELECT rowid` errors and the reader falls back
// to the created_at watermark this test exercises.
func buildWithoutRowIDFixture(t *testing.T) (root, dbPath string) {
	t.Helper()
	root = t.TempDir()
	agentDir := filepath.Join(root, "agents", "main", "agent")
	if err := os.MkdirAll(agentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath = filepath.Join(agentDir, agentDBBase)

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE transcript_events (
		session_id TEXT NOT NULL,
		seq INTEGER NOT NULL,
		event_json TEXT NOT NULL,
		created_at INTEGER,
		PRIMARY KEY (session_id, seq)
	) WITHOUT ROWID`); err != nil {
		t.Fatalf("create WITHOUT ROWID transcript_events: %v", err)
	}
	if _, err := db.Exec(`SELECT rowid FROM transcript_events LIMIT 1`); err == nil {
		t.Fatal("transcript_events still exposes a rowid; the fixture would not exercise the created_at path")
	}
	db.Close()

	insertTranscriptRows(t, dbPath, [][3]any{
		{int64(1), fmt.Sprintf(`{"type":"session","id":%q,"timestamp":"2026-08-30T10:00:00.000Z"}`, agentFixtureSessionID), int64(1000)},
		{int64(2), `{"type":"message","id":"u-first","timestamp":"2026-08-30T10:00:02.000Z","message":{"role":"user","content":[{"type":"text","text":"first prompt"}],"timestamp":1787047202000}}`, int64(2000)},
		{int64(3), `{"type":"message","id":"a-first","timestamp":"2026-08-30T10:00:03.000Z","message":{"role":"assistant","content":[{"type":"text","text":"answering"}],"timestamp":1787047203000}}`, int64(3000)},
	})
	return root, dbPath
}

// insertTranscriptRows appends {seq, event_json, created_at} triples to
// an existing store.
func insertTranscriptRows(t *testing.T, dbPath string, rows [][3]any) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, r := range rows {
		if _, err := db.Exec(
			`INSERT INTO transcript_events (session_id, seq, event_json, created_at) VALUES (?, ?, ?, ?)`,
			agentFixtureSessionID, r[0], r[1], r[2]); err != nil {
			t.Fatalf("insert transcript row %v: %v", r[0], err)
		}
	}
}

func TestCursorSemanticsFor_AgentDBIsWatermark(t *testing.T) {
	root := t.TempDir()
	a := NewWithOptions(nil, []string{root})
	for _, base := range []string{agentDBBase, agentDBWAL} {
		p := filepath.Join(root, "agents", "main", "agent", base)
		got := a.CursorSemanticsFor(p)
		if got.Kind != adapter.CursorWatermark {
			t.Fatalf("CursorSemanticsFor(%s).Kind = %q, want watermark", base, got.Kind)
		}
		if got.Detail == "" {
			t.Fatalf("CursorSemanticsFor(%s) has no detail", base)
		}
	}
}

// TestParseAgentDB_LiveFixture2026_8_2 parses a REAL, anonymized OpenClaw
// 2.0 per-agent store captured from a live install (npm openclaw@2026.8.2,
// schema_meta.schema_version=19) running the standard prompt kit against a
// local Ollama provider. Assistant text is Lorem-ipsum'd, the username is
// replaced with "<u>", uuids/timestamps are synthetic, and the sqlite-vec
// / FTS mirror tables are dropped — but transcript_events.event_json keeps
// the real message/usage SHAPE. This grounds the reader against reality:
// message.usage = {input,output,cacheRead,cacheWrite} per assistant call,
// and session_windows carries the model/provider. See
// testdata/openclaw/README.md for provenance.
func TestParseAgentDB_LiveFixture2026_8_2(t *testing.T) {
	src := filepath.Join("..", "..", "..", "testdata", "openclaw", "agentdb", "openclaw-agent.sqlite")
	blob, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read live fixture: %v", err)
	}
	root := t.TempDir()
	agentDir := filepath.Join(root, "agents", "main", "agent")
	if err := os.MkdirAll(agentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(agentDir, "openclaw-agent.sqlite")
	if err := os.WriteFile(dbPath, blob, 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile(live 2.0 store): %v", err)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("unexpected warnings on a clean live store: %v", res.Warnings)
	}
	if len(res.TokenEvents) == 0 {
		t.Fatal("live store produced no token events")
	}

	// Exactly one session, resolved to the real Ollama model off
	// session_windows (not the null-provider equality fixture).
	sessions := map[string]struct{}{}
	for _, ev := range res.TokenEvents {
		sessions[ev.SessionID] = struct{}{}
		if ev.Tool != "openclaw" {
			t.Fatalf("token event tool = %q, want openclaw", ev.Tool)
		}
		if !strings.Contains(ev.Model, "qwen2.5:1.5b-instruct") {
			t.Fatalf("token event model = %q, want it to contain qwen2.5:1.5b-instruct", ev.Model)
		}
	}
	if len(sessions) != 1 {
		t.Fatalf("distinct sessions = %d, want 1", len(sessions))
	}

	// Per-call usage summed across the 9 assistant turns, exactly as
	// stored. Ollama does not cache, so input is gross-per-call (4095×9)
	// and cacheRead/cacheWrite are zero — the reader maps them straight
	// through, it does not synthesize a session-level total.
	var in, out, cr, cw int64
	for _, ev := range res.TokenEvents {
		in += ev.InputTokens
		out += ev.OutputTokens
		cr += ev.CacheReadTokens
		cw += ev.CacheCreationTokens
	}
	if in != 36855 || out != 1102 || cr != 0 || cw != 0 {
		t.Fatalf("token totals = %d/%d/%d/%d, want 36855/1102/0/0", in, out, cr, cw)
	}

	// A second parse from the returned watermark is a no-op.
	res2, err := a.ParseSessionFile(context.Background(), dbPath, res.NewOffset)
	if err != nil {
		t.Fatalf("re-parse from watermark: %v", err)
	}
	if len(res2.TokenEvents) != 0 || len(res2.ToolEvents) != 0 {
		t.Fatalf("re-parse emitted %d token / %d tool events, want 0/0",
			len(res2.TokenEvents), len(res2.ToolEvents))
	}
}
