package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/taskflow"
	"github.com/marmutapp/superbased-observer/internal/taskreport"
)

// seedTaskReportSession seeds a claude-code session with a TodoWrite
// snapshot lifecycle (one task activated+completed, one still pending)
// plus token_usage rows straddling the in_progress window, then runs
// BackfillTaskItems (ignores [tasks].enabled — exactly what a test
// setup wants) to populate task_items/task_transitions deterministically.
func seedTaskReportSession(t *testing.T, database *sql.DB, sessionID, model string) {
	t.Helper()
	ctx := context.Background()
	var projectID int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES (?, '2026-06-09T00:00:00Z') RETURNING id`,
		"/tmp/taskreport-"+sessionID).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at)
		 VALUES (?, 'claude-code', ?, ?, '2026-06-09T00:00:00Z')`,
		sessionID, projectID, model); err != nil {
		t.Fatal(err)
	}

	base := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	sourceFile := "f-" + sessionID + ".jsonl" // per-session, so multiple sessions in one test DB don't collide on (source_file, source_event_id)
	insertAction := func(offsetMin int, input string, srcEventID string) {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, raw_tool_name, raw_tool_input, source_file, source_event_id)
			 VALUES (?, ?, ?, 'todo_update', 'claude-code', 'TodoWrite', ?, ?, ?)`,
			sessionID, projectID, base.Add(time.Duration(offsetMin)*time.Minute).Format(time.RFC3339Nano),
			input, sourceFile, srcEventID); err != nil {
			t.Fatal(err)
		}
	}
	// t=0: both pending.
	insertAction(0, `{"todos":[{"content":"Fix the bug","status":"pending"},{"content":"Draft the doc","status":"pending"}]}`, "e0")
	// t=1: "Fix the bug" -> in_progress.
	insertAction(1, `{"todos":[{"content":"Fix the bug","status":"in_progress"},{"content":"Draft the doc","status":"pending"}]}`, "e1")
	// t=5: "Fix the bug" -> completed.
	insertAction(5, `{"todos":[{"content":"Fix the bug","status":"completed"},{"content":"Draft the doc","status":"pending"}]}`, "e2")

	insertToken := func(offsetMin int, input, output, cacheRead int64) {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, cache_read_tokens, source, source_file, source_event_id)
			 VALUES (?, ?, 'claude-code', ?, ?, ?, ?, 'watcher', 'f.jsonl', ?)`,
			sessionID, base.Add(time.Duration(offsetMin)*time.Minute).Format(time.RFC3339Nano),
			model, input, output, cacheRead, "tok-"+sessionID+"-"+strconv.Itoa(offsetMin)); err != nil {
			t.Fatal(err)
		}
	}
	// t=2: inside the "Fix the bug" in_progress window [1,5).
	insertToken(2, 1000, 500, 0)
	// t=8: after everything closed -> between_tasks.
	insertToken(8, 300, 100, 0)

	st := store.New(database)
	if _, err := st.BackfillTaskItems(ctx, 0); err != nil {
		t.Fatalf("BackfillTaskItems: %v", err)
	}
}

func TestLoadSessionTaskReport_AttributesTokensAndCost(t *testing.T) {
	t.Parallel()
	database, cleanup := openForecastTestDB(t)
	defer cleanup()
	seedTaskReportSession(t, database, "sT1", "claude-opus-4-8")

	st := store.New(database)
	engine := newForecastTestEngine(t)
	rep, err := taskreport.LoadSessionTaskReport(context.Background(), st, engine, "sT1", taskflow.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.HasTasks {
		t.Fatal("want HasTasks=true")
	}
	if len(rep.Items) != 2 {
		t.Fatalf("items = %+v", rep.Items)
	}

	var fixTheBug, draftTheDoc *taskreport.ReportItem
	for i := range rep.Items {
		switch rep.Items[i].Content {
		case "Fix the bug":
			fixTheBug = &rep.Items[i]
		case "Draft the doc":
			draftTheDoc = &rep.Items[i]
		}
	}
	if fixTheBug == nil || draftTheDoc == nil {
		t.Fatalf("items = %+v", rep.Items)
	}

	if fixTheBug.Status != "completed" || fixTheBug.ElapsedSeconds != 4*60 {
		t.Errorf("fixTheBug = %+v, want completed with 4m elapsed", fixTheBug)
	}
	if fixTheBug.Tokens.InputTokens != 1000 || fixTheBug.Tokens.OutputTokens != 500 {
		t.Errorf("fixTheBug tokens = %+v, want the t=2 row attributed here", fixTheBug.Tokens)
	}
	if fixTheBug.CostUSD <= 0 {
		t.Errorf("fixTheBug cost should be positive, got %v", fixTheBug.CostUSD)
	}
	if fixTheBug.Unpriced {
		t.Errorf("fixTheBug should be priced (model has a pricing entry)")
	}

	if draftTheDoc.NeverActivated {
		t.Errorf("draftTheDoc should still be pending, not never_activated: %+v", draftTheDoc)
	}
	if draftTheDoc.Tokens.InputTokens != 0 {
		t.Errorf("draftTheDoc should carry no attributed tokens, got %+v", draftTheDoc.Tokens)
	}

	// The t=8 row falls after every task closed -> between_tasks.
	if rep.BetweenTasks.Tokens.InputTokens != 300 {
		t.Errorf("between_tasks tokens = %+v, want the t=8 row", rep.BetweenTasks.Tokens)
	}
	if rep.CostNote == "" {
		t.Error("want a non-empty CostNote once any row is priced")
	}
}

func TestLoadSessionTaskReport_EmptyStateForSessionWithoutTasks(t *testing.T) {
	t.Parallel()
	database, cleanup := openForecastTestDB(t)
	defer cleanup()
	ctx := context.Background()
	var projectID int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES ('/tmp/no-tasks', '2026-06-09T00:00:00Z') RETURNING id`).
		Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at) VALUES ('sNoTasks', 'claude-code', ?, 'claude-opus-4-8', '2026-06-09T00:00:00Z')`,
		projectID); err != nil {
		t.Fatal(err)
	}

	st := store.New(database)
	rep, err := taskreport.LoadSessionTaskReport(ctx, st, newForecastTestEngine(t), "sNoTasks", taskflow.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.HasTasks {
		t.Errorf("want has_tasks=false for a session with no task_items rows, got %+v", rep)
	}
	if len(rep.Items) != 0 || rep.CostNote != "" {
		t.Errorf("empty state must carry no items/cost note, got %+v", rep)
	}
}

func TestHandleSessionTasks_HTTPRoundTrip(t *testing.T) {
	t.Parallel()
	database, cleanup := openForecastTestDB(t)
	defer cleanup()
	seedTaskReportSession(t, database, "sT2", "claude-opus-4-8")

	srv := &Server{opts: Options{DB: database, CostEngine: newForecastTestEngine(t)}}
	req := httptest.NewRequest(http.MethodGet, "/api/session/sT2/tasks", nil)
	rec := httptest.NewRecorder()
	srv.handleSessionDetail(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp taskreport.SessionTaskReport
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v — body %s", err, rec.Body.String())
	}
	if !resp.HasTasks || len(resp.Items) != 2 {
		t.Fatalf("resp = %+v", resp)
	}
}

func TestLoadTaskRollup_AggregatesAcrossSessionsAndTools(t *testing.T) {
	t.Parallel()
	database, cleanup := openForecastTestDB(t)
	defer cleanup()
	seedTaskReportSession(t, database, "sR1", "claude-opus-4-8")
	seedTaskReportSession(t, database, "sR2", "claude-opus-4-8")

	st := store.New(database)
	rep, err := taskreport.LoadTaskRollup(context.Background(), st, newForecastTestEngine(t), time.Time{}, time.Time{}, 0, "", "", taskflow.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.SessionsWithTasks != 2 {
		t.Fatalf("SessionsWithTasks = %d, want 2", rep.SessionsWithTasks)
	}
	if rep.Counts.Created != 4 { // 2 tasks × 2 sessions
		t.Errorf("Counts.Created = %d, want 4", rep.Counts.Created)
	}
	if rep.Counts.Completed != 2 {
		t.Errorf("Counts.Completed = %d, want 2 (one 'Fix the bug' per session)", rep.Counts.Completed)
	}
	if len(rep.ByTool) != 1 || rep.ByTool[0].Tool != "claude-code" || rep.ByTool[0].Sessions != 2 {
		t.Fatalf("ByTool = %+v", rep.ByTool)
	}
	if rep.CostNote == "" {
		t.Error("want a non-empty CostNote once any row is priced")
	}
}

func TestHandleTaskRollup_HTTPRoundTrip(t *testing.T) {
	t.Parallel()
	database, cleanup := openForecastTestDB(t)
	defer cleanup()
	seedTaskReportSession(t, database, "sR3", "claude-opus-4-8")

	srv := &Server{opts: Options{DB: database, CostEngine: newForecastTestEngine(t)}}
	req := httptest.NewRequest(http.MethodGet, "/api/tasks", nil)
	rec := httptest.NewRecorder()
	srv.handleTaskRollup(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp taskreport.TaskRollup
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v — body %s", err, rec.Body.String())
	}
	if resp.SessionsWithTasks != 1 {
		t.Fatalf("resp = %+v", resp)
	}
}

// seedConcurrentTaskReportSession seeds a session with two tasks that go
// in_progress SIMULTANEOUSLY (one TodoWrite snapshot listing both) plus
// one token_usage row while both are still open — the
// [tasks].concurrent_attribution fork point: "shared" (the default)
// buckets that row into `shared`, "none" instead buckets it into
// `between_tasks`. Used to prove the option actually reaches the report
// through dashboard.Options.Tasks (FIX-A).
func seedConcurrentTaskReportSession(t *testing.T, database *sql.DB, sessionID string) {
	t.Helper()
	ctx := context.Background()
	var projectID int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES (?, '2026-06-09T00:00:00Z') RETURNING id`,
		"/tmp/taskreport-conc-"+sessionID).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at)
		 VALUES (?, 'claude-code', ?, 'claude-opus-4-8', '2026-06-09T00:00:00Z')`,
		sessionID, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, raw_tool_name, raw_tool_input, source_file, source_event_id)
		 VALUES (?, ?, '2026-06-09T00:00:00Z', 'todo_update', 'claude-code', 'TodoWrite',
		         '{"todos":[{"content":"Task A","status":"in_progress"},{"content":"Task B","status":"in_progress"}]}',
		         ?, 'e0')`,
		sessionID, projectID, "f-"+sessionID+".jsonl"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, source, source_file, source_event_id)
		 VALUES (?, '2026-06-09T00:01:00Z', 'claude-code', 'claude-opus-4-8', 1000, 500, 'watcher', 'tok.jsonl', ?)`,
		sessionID, "tok-"+sessionID); err != nil {
		t.Fatal(err)
	}
	st := store.New(database)
	if _, err := st.BackfillTaskItems(ctx, 0); err != nil {
		t.Fatalf("BackfillTaskItems: %v", err)
	}
}

// TestHandleSessionTasks_AppliesConcurrentAttributionFromOptions is the
// FIX-A regression test for the dashboard read path: GET
// /api/session/<id>/tasks must apply [tasks].concurrent_attribution from
// dashboard.Options.Tasks (the config this Server was built with), NOT
// from a fresh store.New(db)'s never-configured Store.TasksOptions() —
// before the fix, every dashboard request built its own ephemeral
// store, so concurrent_attribution was silently inert here.
func TestHandleSessionTasks_AppliesConcurrentAttributionFromOptions(t *testing.T) {
	t.Parallel()
	database, cleanup := openForecastTestDB(t)
	defer cleanup()
	seedConcurrentTaskReportSession(t, database, "sConcNoneHTTP")

	srv := &Server{opts: Options{
		DB:         database,
		CostEngine: newForecastTestEngine(t),
		Tasks:      config.TasksConfig{MatchMode: "exact", ConcurrentAttribution: "none"},
	}}
	req := httptest.NewRequest(http.MethodGet, "/api/session/sConcNoneHTTP/tasks", nil)
	rec := httptest.NewRecorder()
	srv.handleSessionDetail(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp taskreport.SessionTaskReport
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v — body %s", err, rec.Body.String())
	}
	if resp.ConcurrentAttribution != "none" {
		t.Errorf("concurrent_attribution echo = %q, want %q", resp.ConcurrentAttribution, "none")
	}
	if resp.Shared.Tokens.InputTokens != 0 {
		t.Errorf("shared.tokens.input_tokens = %d, want 0 (concurrent_attribution=none)", resp.Shared.Tokens.InputTokens)
	}
	if resp.BetweenTasks.Tokens.InputTokens != 1000 {
		t.Errorf("between_tasks.tokens.input_tokens = %d, want 1000 (concurrent_attribution=none) — the option did not reach the report", resp.BetweenTasks.Tokens.InputTokens)
	}
}

// seedCodexTaskReportSession is seedTaskReportSession's codex-shaped
// sibling for the FIX-B project/tool-filter test below: one completed
// plan step via codex's OWN `update_plan` decoder shape
// (`{"plan":[{"step":...,"status":...}]}` — internal/taskflow/
// snapshot.go's decodeCodexUpdatePlan; codex is NOT decoded from a
// TodoWrite-shaped call, unlike claude-code), in its own project (root
// path derived from sessionID like every other seed helper here).
func seedCodexTaskReportSession(t *testing.T, database *sql.DB, sessionID string) {
	t.Helper()
	ctx := context.Background()
	var projectID int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES (?, '2026-06-09T00:00:00Z') RETURNING id`,
		"/tmp/taskreport-"+sessionID).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at) VALUES (?, 'codex', ?, 'gpt-5.1-codex', '2026-06-09T00:00:00Z')`,
		sessionID, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, raw_tool_name, raw_tool_input, source_file, source_event_id)
		 VALUES (?, ?, '2026-06-09T00:00:00Z', 'todo_update', 'codex', 'update_plan', '{"plan":[{"step":"Solo task","status":"completed"}]}', ?, 'e0')`,
		sessionID, projectID, "f-"+sessionID+".jsonl"); err != nil {
		t.Fatal(err)
	}
	st := store.New(database)
	if _, err := st.BackfillTaskItems(ctx, 0); err != nil {
		t.Fatalf("BackfillTaskItems: %v", err)
	}
}

// TestHandleTaskRollup_FiltersByProjectRootAndTool is the FIX-B
// regression test: GET /api/tasks must accept `project=<root>` (the
// string-keyed filter the Analysis page's global project selector
// actually sends — it never resolves to a numeric project id) and
// `tool=` the same way every other Analysis endpoint does.
func TestHandleTaskRollup_FiltersByProjectRootAndTool(t *testing.T) {
	t.Parallel()
	database, cleanup := openForecastTestDB(t)
	defer cleanup()
	seedTaskReportSession(t, database, "sFilterCC", "claude-opus-4-8") // tool=claude-code, root=/tmp/taskreport-sFilterCC
	seedCodexTaskReportSession(t, database, "sFilterCodex")

	srv := &Server{opts: Options{DB: database, CostEngine: newForecastTestEngine(t)}}

	req := httptest.NewRequest(http.MethodGet, "/api/tasks?project=/tmp/taskreport-sFilterCC", nil)
	rec := httptest.NewRecorder()
	srv.handleTaskRollup(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var byProject taskreport.TaskRollup
	if err := json.Unmarshal(rec.Body.Bytes(), &byProject); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if byProject.SessionsWithTasks != 1 {
		t.Fatalf("project-filtered rollup = %+v, want exactly the 1 session under that root", byProject)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/tasks?tool=codex", nil)
	rec2 := httptest.NewRecorder()
	srv.handleTaskRollup(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec2.Code, rec2.Body.String())
	}
	var byTool taskreport.TaskRollup
	if err := json.Unmarshal(rec2.Body.Bytes(), &byTool); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if byTool.SessionsWithTasks != 1 || len(byTool.ByTool) != 1 || byTool.ByTool[0].Tool != "codex" {
		t.Fatalf("tool-filtered rollup = %+v, want exactly the codex session", byTool)
	}
}
