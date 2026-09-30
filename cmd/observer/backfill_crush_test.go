package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/crush"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// crushFixtureSchema is the subset of the live Crush schema the adapter
// reads (see internal/adapter/crush/adapter_test.go).
const crushFixtureSchema = `
CREATE TABLE sessions (
	id TEXT PRIMARY KEY, parent_session_id TEXT, title TEXT NOT NULL,
	message_count INTEGER NOT NULL DEFAULT 0,
	prompt_tokens INTEGER NOT NULL DEFAULT 0, completion_tokens INTEGER NOT NULL DEFAULT 0,
	cost REAL NOT NULL DEFAULT 0.0, updated_at INTEGER NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE messages (
	id TEXT PRIMARY KEY, session_id TEXT NOT NULL, role TEXT NOT NULL,
	parts TEXT NOT NULL DEFAULT '[]', model TEXT, created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL, finished_at INTEGER, provider TEXT,
	is_summary_message INTEGER DEFAULT 0 NOT NULL);`

// TestCrushRescanCorrectsStaleTokenRows is the end-to-end proof for the
// --crush-rescan correcting pass, with the REAL crush parser: a
// multi-step session whose pre-fix row stored the last-step snapshot
// 8975/5 is corrected to 0/0 + Crush's own $0.08627345 with reliability
// unknown (the live session 30bc155f shape); a zero-cost MULTI-step
// session's stored snapshot is corrected IN PLACE to 0/0 $0 unknown and
// keeps its model (full coverage: it used to be deleted, losing the
// model); a zero-cost multi-step session the 2026-09-27 parser never
// stored gets its row from the rescan's ingest; a zero-cost ONE-step
// session keeps its real counts; a correct one-step row is untouched;
// and a second run changes nothing.
func TestCrushRescanCorrectsStaleTokenRows(t *testing.T) {
	ctx := context.Background()

	// A Crush project with its own .git so the project root is stable.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	crushDB := filepath.Join(root, ".crush", "crush.db")
	if err := os.MkdirAll(filepath.Dir(crushDB), 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := sql.Open("sqlite", crushDB)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		crushFixtureSchema,
		`INSERT INTO sessions(id,title,prompt_tokens,completion_tokens,cost,updated_at,created_at) VALUES
		 ('30bc155f','Do work',8975,5,0.08627345,1783572212,1783572197),
		 ('ses_flat','Flat rate',9120,40,0.0,1783572312,1783572300),
		 ('ses_flatmulti','Flat multi',9500,30,0.0,1783572512,1783572500),
		 ('ses_skipped','Flat multi 2',7000,12,0.0,1783572612,1783572600),
		 ('ses_one','Greeting',21749,5,0.05448195,1783572412,1783572400)`,
		`INSERT INTO messages(id,session_id,role,parts,model,provider,created_at,updated_at) VALUES
		 ('m1u','30bc155f','user','[{"type":"text","data":{"text":"make hello"}}]','','',1783572197,1783572197),
		 ('m1a','30bc155f','assistant','[{"type":"text","data":{"text":"step 1"}},{"type":"finish","data":{"reason":"tool_use","time":1783572205}}]','gpt-5.4-mini','openai',1783572200,1783572205),
		 ('m1b','30bc155f','assistant','[{"type":"text","data":{"text":"step 2"}},{"type":"finish","data":{"reason":"tool_use","time":1783572207}}]','gpt-5.4-mini','openai',1783572206,1783572207),
		 ('m1c','30bc155f','assistant','[{"type":"text","data":{"text":"Done"}},{"type":"finish","data":{"reason":"end_turn","time":1783572212}}]','gpt-5.4-mini','openai',1783572210,1783572212),
		 ('m2u','ses_flat','user','[{"type":"text","data":{"text":"hi"}}]','','',1783572300,1783572300),
		 ('m2a','ses_flat','assistant','[{"type":"text","data":{"text":"hello"}},{"type":"finish","data":{"reason":"end_turn","time":1783572312}}]','claude-sonnet-4-6','anthropic',1783572305,1783572312),
		 ('m3u','ses_one','user','[{"type":"text","data":{"text":"hi"}}]','','',1783572400,1783572400),
		 ('m4u','ses_flatmulti','user','[{"type":"text","data":{"text":"work"}}]','','',1783572500,1783572500),
		 ('m4a','ses_flatmulti','assistant','[{"type":"finish","data":{"reason":"tool_use","time":1783572505}}]','qwen3-coder','ollama',1783572501,1783572505),
		 ('m4b','ses_flatmulti','assistant','[{"type":"text","data":{"text":"done"}},{"type":"finish","data":{"reason":"end_turn","time":1783572512}}]','qwen3-coder','ollama',1783572506,1783572512),
		 ('m5u','ses_skipped','user','[{"type":"text","data":{"text":"work"}}]','','',1783572600,1783572600),
		 ('m5a','ses_skipped','assistant','[{"type":"finish","data":{"reason":"tool_use","time":1783572605}}]','qwen3-coder','ollama',1783572601,1783572605),
		 ('m5b','ses_skipped','assistant','[{"type":"text","data":{"text":"done"}},{"type":"finish","data":{"reason":"end_turn","time":1783572612}}]','qwen3-coder','ollama',1783572606,1783572612),
		 ('m3a','ses_one','assistant','[{"type":"text","data":{"text":"hi there"}},{"type":"finish","data":{"reason":"end_turn","time":1783572412}}]','gpt-5.4','openai',1783572405,1783572412)`,
	} {
		if _, err := src.Exec(stmt); err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}
	src.Close()

	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "observer.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)

	a := crush.NewWithOptions(nil, []string{filepath.Join(root, ".crush")})
	parse := func(ctx context.Context, path string) (adapter.ParseResult, error) {
		return a.ParseSessionFile(ctx, path, 0)
	}

	// Ingest with the fixed parser (sessions + actions + fresh rows) ...
	res, err := parse(ctx, crushDB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Ingest(ctx, res.ToolEvents, res.TokenEvents, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	// ... then plant what the PRE-FIX parsers stored: the pre-2026-09-27
	// parser kept the multi-step snapshots as approximate counts (a
	// MAX-upgrade the fixed parse can never undo, and the upsert never
	// rewrites reliability), and the 2026-09-27 parser stored NO row for
	// a zero-cost multi-step session.
	if _, err := database.Exec(`UPDATE token_usage SET input_tokens = 8975, output_tokens = 5, reliability = 'approximate'
		WHERE tool = 'crush' AND source_event_id = 'tokens:30bc155f'`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE token_usage SET input_tokens = 9500, output_tokens = 30, reliability = 'approximate'
		WHERE tool = 'crush' AND source_event_id = 'tokens:ses_flatmulti'`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`DELETE FROM token_usage WHERE tool = 'crush' AND source_event_id = 'tokens:ses_skipped'`); err != nil {
		t.Fatal(err)
	}
	// A plain re-ingest (what --crush-rescan's rescan row does) inserts
	// the missing row and, since the token-reliability rule table
	// (internal/store/tokenreliability.go), also replaces an approximate
	// snapshot the re-parse now reports as unknown. The correcting pass
	// stays for rows no re-ingest reaches; here it must find nothing left.
	if _, err := st.Ingest(ctx, res.ToolEvents, res.TokenEvents, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	type tok struct {
		in, out    int64
		cost       float64
		model, rel string
	}
	read := func(sess string) (tok, bool) {
		var r tok
		err := database.QueryRow(`SELECT input_tokens, output_tokens, estimated_cost_usd, COALESCE(model, ''), COALESCE(reliability, '')
			FROM token_usage WHERE tool = 'crush' AND source_event_id = ?`, "tokens:"+sess).Scan(&r.in, &r.out, &r.cost, &r.model, &r.rel)
		if err == sql.ErrNoRows {
			return r, false
		}
		if err != nil {
			t.Fatal(err)
		}
		return r, true
	}
	if r, _ := read("30bc155f"); r.in != 0 || r.out != 0 || r.rel != models.ReliabilityUnknown {
		t.Fatalf("setup: stale row = %+v, want the plain re-ingest to replace the 8975/5 approximate snapshot with 0/0 unknown", r)
	}
	if r, ok := read("ses_skipped"); !ok || r.in != 0 || r.out != 0 || r.cost != 0 || r.model != "qwen3-coder" || r.rel != models.ReliabilityUnknown {
		t.Fatalf("ses_skipped = %+v (present=%v), want the rescan ingest to insert 0/0 $0 qwen3-coder unknown", r, ok)
	}

	rep, err := runCrushTokenCorrection(ctx, st, parse)
	if err != nil {
		t.Fatal(err)
	}
	if rep.FilesChecked != 1 || rep.Errors != 0 || rep.Updated != 0 || rep.Deleted != 0 || rep.Missing != 0 {
		t.Errorf("first run = %+v, want 1 file, 0 updated (the re-ingest already corrected both), 0 deleted, 0 missing, 0 errors", rep)
	}
	if r, ok := read("30bc155f"); !ok || r.in != 0 || r.out != 0 || r.cost != 0.08627345 || r.rel != models.ReliabilityUnknown {
		t.Errorf("30bc155f = %+v (present=%v), want 0/0 $0.08627345 unknown", r, ok)
	}
	if r, ok := read("ses_flatmulti"); !ok || r.in != 0 || r.out != 0 || r.cost != 0 || r.model != "qwen3-coder" || r.rel != models.ReliabilityUnknown {
		t.Errorf("ses_flatmulti = %+v (present=%v), want 0/0 $0 qwen3-coder unknown (row kept, snapshot counts cleared)", r, ok)
	}
	if r, ok := read("ses_skipped"); !ok || r.in != 0 || r.out != 0 || r.rel != models.ReliabilityUnknown {
		t.Errorf("ses_skipped = %+v (present=%v), want its 0/0 unknown row untouched", r, ok)
	}
	if r, ok := read("ses_flat"); !ok || r.in != 9120 || r.out != 40 || r.cost != 0 || r.rel != models.ReliabilityApproximate {
		t.Errorf("ses_flat = %+v (present=%v), want its real 9120/40 $0 approximate kept", r, ok)
	}
	if r, ok := read("ses_one"); !ok || r.in != 21749 || r.out != 5 || r.cost != 0.05448195 || r.rel != models.ReliabilityApproximate {
		t.Errorf("ses_one = %+v, want untouched 21749/5 $0.05448195 approximate", r)
	}
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM token_usage WHERE tool = 'crush'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Errorf("crush token rows = %d, want 5 (one per session, no duplicates)", n)
	}

	again, err := runCrushTokenCorrection(ctx, st, parse)
	if err != nil {
		t.Fatal(err)
	}
	if again.Updated != 0 || again.Deleted != 0 || again.Errors != 0 {
		t.Errorf("second run = %+v, want no changes (idempotent)", again)
	}
}

// TestCrushRescanSkipsMissingFiles pins that a stored row whose crush.db
// is gone is left alone (nothing authoritative to correct from).
func TestCrushRescanSkipsMissingFiles(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "observer.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	pid, err := st.UpsertProject(ctx, "/gone", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSession(ctx, models.Session{ID: "s", ProjectID: pid, Tool: models.ToolCrush}); err != nil {
		t.Fatal(err)
	}
	gone := filepath.Join(t.TempDir(), "missing", "crush.db")
	if _, err := st.InsertTokenEvents(ctx, []models.TokenEvent{{
		SourceFile: gone, SourceEventID: "tokens:s", SessionID: "s", Tool: models.ToolCrush, InputTokens: 5,
	}}); err != nil {
		t.Fatal(err)
	}
	called := false
	rep, err := runCrushTokenCorrection(ctx, st, func(context.Context, string) (adapter.ParseResult, error) {
		called = true
		return adapter.ParseResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if called || rep.FilesMissing != 1 || rep.FilesChecked != 0 {
		t.Errorf("rep = %+v (parse called=%v), want the missing file skipped unparsed", rep, called)
	}
}
