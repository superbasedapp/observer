package taskreport

// batch_test.go pins the SOL-F18(b) fix (2026-09-22 Projects-page
// rework): LoadSessionTaskReportsBatch/LoadTaskRollup must compose the
// SAME per-session SessionTaskReport LoadSessionTaskReport would (see
// internal/store/taskflow.go's *Batch loaders + composeSessionTaskReport
// in report.go), and must do it in a query count that does NOT scale
// with the number of sessions — that was the actual regression (a
// per-session LoadSessionTaskReport loop, 6-7 queries per iteration,
// inside both LoadTaskRollup and GET /api/project/<id>/cost?by=task).
//
// TestNoForbiddenImports (imports_test.go) only scans non-_test.go files
// in this package, so this file is free to import database/sql and the
// migration/store machinery it needs to set up a real (if minimal)
// fixture — internal/taskreport's own production code stays a pure
// builder over internal/store's I/O either way.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	sqlitepkg "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/taskflow"
)

// --- fixtures -------------------------------------------------------

// newBatchTestStore opens a freshly migrated, task-tracking-enabled
// store in a throwaway temp file — the internal/store package's own
// newTestStore helper is unexported and package-local, so this is its
// taskreport-side equivalent (same dbtemplate.Open seeding path).
func newBatchTestStore(t *testing.T) *store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "taskreport-batch.db")
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatalf("dbtemplate.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	st.SetTasksEnabled(true)
	return st
}

// seedTaskSession creates one project+session and gives it exactly one
// COMPLETED task_items row — create, in_progress, completed, the same
// three-event lifecycle internal/store/taskflow_test.go's
// TestIngest_TaskTracking_ClaudeCodeTaskLifecycle already pins — via the
// normal Store.Ingest path. That is the path a real adapter's events
// take, and the one that actually runs the task-tracking decode
// (applyTaskEvents; it is a step INSIDE Ingest, not InsertActions, and
// is package-private to internal/store, so this package must go through
// the public Ingest entry point rather than internal/store's own test
// helpers). A bare TaskCreate with no further transition never gets a
// task_transitions row at all, so taskflow.Summarize has nothing to
// classify it by (neither NeverActivated nor StillOpen) — the full
// three-event lifecycle is what makes LoadTaskRollup's Counts.Completed
// deterministic for this fixture.
func seedTaskSession(t *testing.T, st *store.Store, sessionID string, ts time.Time) {
	t.Helper()
	ctx := context.Background()
	events := []models.ToolEvent{
		{
			SessionID: sessionID, ProjectRoot: "/tmp/taskreport-batch-" + sessionID,
			Timestamp: ts, ActionType: models.ActionTodoUpdate,
			Tool: models.ToolClaudeCode, RawToolName: "TaskCreate",
			RawToolInput: `{"subject":"batch task","activeForm":"doing"}`,
			ToolOutput:   "Task #1 created successfully: batch task",
			SourceFile:   "f.jsonl", SourceEventID: sessionID + "-create", Success: true,
		},
		{
			SessionID: sessionID, ProjectRoot: "/tmp/taskreport-batch-" + sessionID,
			Timestamp: ts.Add(time.Minute), ActionType: models.ActionTodoUpdate,
			Tool: models.ToolClaudeCode, RawToolName: "TaskUpdate",
			RawToolInput: `{"status":"in_progress","taskId":"1"}`,
			SourceFile:   "f.jsonl", SourceEventID: sessionID + "-update1", Success: true,
		},
		{
			SessionID: sessionID, ProjectRoot: "/tmp/taskreport-batch-" + sessionID,
			Timestamp: ts.Add(5 * time.Minute), ActionType: models.ActionTodoUpdate,
			Tool: models.ToolClaudeCode, RawToolName: "TaskUpdate",
			RawToolInput: `{"status":"completed","taskId":"1"}`,
			SourceFile:   "f.jsonl", SourceEventID: sessionID + "-update2", Success: true,
		},
	}
	if _, err := st.Ingest(ctx, events, nil, store.IngestOptions{}); err != nil {
		t.Fatalf("Ingest(%s): %v", sessionID, err)
	}
}

// --- correctness ------------------------------------------------------

// TestLoadSessionTaskReportsBatchMatchesIndividual pins that batching is
// purely a query-shape change: for every seeded session the batched
// report must be byte-for-byte (reflect.DeepEqual) identical to what
// LoadSessionTaskReport returns for that session alone, and a session
// with no task_items rows must be entirely ABSENT from the map (never a
// zero-value entry a caller could mistake for HasTasks=false-with-data).
func TestLoadSessionTaskReportsBatchMatchesIndividual(t *testing.T) {
	t.Parallel()
	st := newBatchTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)

	sessionIDs := []string{"tr-batch-a", "tr-batch-b", "tr-batch-c"}
	for i, sid := range sessionIDs {
		seedTaskSession(t, st, sid, base.Add(time.Duration(i)*time.Hour))
	}
	// A session with a project+session row but no task activity at all —
	// must not appear in the batch map.
	emptyPID, err := st.UpsertProject(ctx, "/tmp/taskreport-batch-empty", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSession(ctx, models.Session{
		ID: "tr-batch-empty", ProjectID: emptyPID, Tool: models.ToolClaudeCode, StartedAt: base,
	}); err != nil {
		t.Fatal(err)
	}

	opts := taskflow.Options{}
	batch, err := LoadSessionTaskReportsBatch(ctx, st, nil, append(append([]string{}, sessionIDs...), "tr-batch-empty"), opts)
	if err != nil {
		t.Fatalf("LoadSessionTaskReportsBatch: %v", err)
	}
	if len(batch) != len(sessionIDs) {
		t.Fatalf("batch has %d reports, want %d (the empty session must be absent): keys=%v", len(batch), len(sessionIDs), keysOf(batch))
	}
	if _, ok := batch["tr-batch-empty"]; ok {
		t.Errorf("tr-batch-empty (no task_items rows) unexpectedly present in the batch map")
	}

	for _, sid := range sessionIDs {
		individual, err := LoadSessionTaskReport(ctx, st, nil, sid, opts)
		if err != nil {
			t.Fatalf("LoadSessionTaskReport(%s): %v", sid, err)
		}
		got, ok := batch[sid]
		if !ok {
			t.Fatalf("session %s missing from batch map", sid)
		}
		if !reflect.DeepEqual(got, individual) {
			t.Errorf("session %s: batch report = %+v, want %+v (from LoadSessionTaskReport)", sid, got, individual)
		}
		if !got.HasTasks {
			t.Errorf("session %s: HasTasks = false, want true", sid)
		}
	}

	// Asking for a session id that was never seeded at all (not even a
	// project/session row) must return an empty map, not an error.
	none, err := LoadSessionTaskReportsBatch(ctx, st, nil, []string{"does-not-exist"}, opts)
	if err != nil {
		t.Fatalf("LoadSessionTaskReportsBatch(unknown session): %v", err)
	}
	if len(none) != 0 {
		t.Errorf("LoadSessionTaskReportsBatch(unknown session) = %+v, want empty", none)
	}

	// Empty input must short-circuit to an empty map with no error.
	empty, err := LoadSessionTaskReportsBatch(ctx, st, nil, nil, opts)
	if err != nil {
		t.Fatalf("LoadSessionTaskReportsBatch(nil): %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("LoadSessionTaskReportsBatch(nil) = %+v, want empty", empty)
	}
}

func keysOf(m map[string]SessionTaskReport) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestLoadTaskRollupMatchesBatchedComposition pins that the SOL-F18(b)
// extraction (LoadTaskRollup's per-session loop now folds
// loadSessionTaskReportsBatch instead of calling LoadSessionTaskReport
// per ref) did not change LoadTaskRollup's own output: one completed
// task per seeded session must still land as Counts.Completed across the
// whole window.
func TestLoadTaskRollupMatchesBatchedComposition(t *testing.T) {
	t.Parallel()
	st := newBatchTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)

	sessionIDs := []string{"tr-rollup-a", "tr-rollup-b", "tr-rollup-c"}
	for i, sid := range sessionIDs {
		seedTaskSession(t, st, sid, base.Add(time.Duration(i)*time.Hour))
	}

	rollup, err := LoadTaskRollup(ctx, st, nil, base.Add(-time.Hour), base.Add(24*time.Hour), 0, "", "", taskflow.Options{})
	if err != nil {
		t.Fatalf("LoadTaskRollup: %v", err)
	}
	if rollup.SessionsWithTasks != len(sessionIDs) {
		t.Errorf("SessionsWithTasks = %d, want %d", rollup.SessionsWithTasks, len(sessionIDs))
	}
	if rollup.Counts.Created != len(sessionIDs) {
		t.Errorf("Counts.Created = %d, want %d (one task per seeded session)", rollup.Counts.Created, len(sessionIDs))
	}
	if rollup.Counts.Completed != len(sessionIDs) {
		t.Errorf("Counts.Completed = %d, want %d (create -> in_progress -> completed for every seeded session)", rollup.Counts.Completed, len(sessionIDs))
	}
}

// --- query-count instrumentation --------------------------------------
//
// The counting driver below is internal/store/taskflow_test.go's
// countingConn/countingDriver/queryCounter, duplicated here rather than
// exported from internal/store: this package's imports_test.go pin
// (TestNoForbiddenImports) is a reminder that internal/taskreport's own
// non-test code must not grow a database/sql dependency, and importing a
// test-only helper across packages isn't possible in Go anyway (_test.go
// files aren't part of a package's importable surface).

type queryCounter struct{ n int64 }

func (c *queryCounter) add(delta int64) { atomic.AddInt64(&c.n, delta) }
func (c *queryCounter) load() int64     { return atomic.LoadInt64(&c.n) }

type countingConn struct {
	driver.Conn
	counter *queryCounter
}

func (c *countingConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.counter.add(1)
	qc, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, errors.New("countingConn: underlying conn does not implement driver.QueryerContext")
	}
	return qc.QueryContext(ctx, query, args)
}

type countingDriver struct {
	base    driver.Driver
	counter *queryCounter
}

func (d *countingDriver) Open(name string) (driver.Conn, error) {
	c, err := d.base.Open(name)
	if err != nil {
		return nil, err
	}
	return &countingConn{Conn: c, counter: d.counter}, nil
}

var countingDriverSeq int64

// newCountingTestStore is newBatchTestStore's counting-instrumented
// twin: migrate normally, then reopen the same file through a
// countingDriver so every subsequent QueryContext call is observable.
func newCountingTestStore(t *testing.T) (*store.Store, *queryCounter) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "taskreport-counting.db")
	seed, err := dbtemplate.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatalf("seed migrate: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("close seed: %v", err)
	}

	counter := &queryCounter{}
	name := fmt.Sprintf("sqlite-counting-taskreport-%d", atomic.AddInt64(&countingDriverSeq, 1))
	sql.Register(name, &countingDriver{base: &sqlitepkg.Driver{}, counter: counter})
	database, err := sql.Open(name, "file:"+path+"?_pragma=busy_timeout(30000)&_pragma=foreign_keys(1)&_pragma=synchronous(1)")
	if err != nil {
		t.Fatalf("sql.Open (counting driver): %v", err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	st.SetTasksEnabled(true)
	return st, counter
}

// TestLoadSessionTaskReportsBatchQueryCountIsIndependentOfSessionCount is
// the SOL-F18(b) fix's direct proof at the taskreport composition level
// (internal/store/taskflow_test.go's
// TestTaskBatchLoadersIssueOneQueryRegardlessOfSessionCount proves the
// same property one loader at a time): asking
// LoadSessionTaskReportsBatch for N sessions must cost the SAME query
// count asking for 1 session does. It also cross-checks against the OLD
// shape of the bug directly — looping LoadSessionTaskReport once per
// session — to make the regression concrete: that loop must cost
// meaningfully MORE than the batched call over the same N sessions.
func TestLoadSessionTaskReportsBatchQueryCountIsIndependentOfSessionCount(t *testing.T) {
	st, counter := newCountingTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)

	const n = 10
	sessionIDs := make([]string, n)
	for i := 0; i < n; i++ {
		sid := fmt.Sprintf("tr-qc-%d", i)
		sessionIDs[i] = sid
		seedTaskSession(t, st, sid, base.Add(time.Duration(i)*time.Hour))
	}
	opts := taskflow.Options{}

	before := counter.load()
	if _, err := LoadSessionTaskReportsBatch(ctx, st, nil, sessionIDs[:1], opts); err != nil {
		t.Fatalf("LoadSessionTaskReportsBatch(1 session): %v", err)
	}
	oneSessionQueries := counter.load() - before
	if oneSessionQueries == 0 {
		t.Fatal("observed 0 queries for a single session — instrumentation is broken")
	}

	before = counter.load()
	if _, err := LoadSessionTaskReportsBatch(ctx, st, nil, sessionIDs, opts); err != nil {
		t.Fatalf("LoadSessionTaskReportsBatch(%d sessions): %v", n, err)
	}
	allSessionsQueries := counter.load() - before

	if oneSessionQueries != allSessionsQueries {
		t.Errorf("LoadSessionTaskReportsBatch: 1 session cost %d queries, %d sessions cost %d — want equal (one chunked sweep per table, SOL-F18(b))",
			oneSessionQueries, n, allSessionsQueries)
	}

	// The regression this replaced: a per-session LoadSessionTaskReport
	// loop. Looping it over the same N sessions must cost meaningfully
	// more than the single batched call did.
	before = counter.load()
	for _, sid := range sessionIDs {
		if _, err := LoadSessionTaskReport(ctx, st, nil, sid, opts); err != nil {
			t.Fatalf("LoadSessionTaskReport(%s): %v", sid, err)
		}
	}
	individualLoopQueries := counter.load() - before
	if individualLoopQueries <= allSessionsQueries {
		t.Errorf("looping LoadSessionTaskReport over %d sessions cost %d queries, the batched call cost %d — expected the loop to cost meaningfully more (O(N) vs O(1) round trips)",
			n, individualLoopQueries, allSessionsQueries)
	}
}
