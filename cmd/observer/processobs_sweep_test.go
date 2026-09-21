package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/processobs"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// sweepUnattributedRun builds an unattributed cross-OS-shaped process run for
// the sweep tests (mirrors the store test's builder; kept local to the cmd
// package to avoid exporting a test helper).
func sweepUnattributedRun(key, parent, basename, cwd string, pid int, started time.Time) processobs.ProcessRun {
	return processobs.ProcessRun{
		ProcessKey:       key,
		BootID:           "win-boot",
		PID:              pid,
		PPID:             1,
		StartTimeTicks:   int64(pid) * 1000,
		ParentProcessKey: parent,
		Attribution:      processobs.Attribution{Source: processobs.AttrNone, Confidence: processobs.ConfNone},
		ExePath:          `C:\bin\` + basename,
		ExeBasename:      basename,
		CWD:              cwd,
		StartedAt:        started,
		LastSeenAt:       started,
	}
}

// sweepAttributedRun builds an already-session-attributed process run (mirrors
// the store package's execRun helper, kept local here for the same reason
// sweepUnattributedRun is) for the action-correlation sweep tests.
func sweepAttributedRun(key, sess string, projectID int64, parent, basename, argv string, pid int, started time.Time) processobs.ProcessRun {
	return processobs.ProcessRun{
		ProcessKey:     key,
		BootID:         "boot-1",
		PID:            pid,
		PPID:           1,
		StartTimeTicks: int64(pid) * 1000,
		Attribution: processobs.Attribution{
			SessionID:  sess,
			Tool:       "claude-code",
			ProjectID:  projectID,
			Source:     processobs.AttrBridge,
			Confidence: processobs.ConfHigh,
		},
		ParentProcessKey: parent,
		ExePath:          "/bin/" + basename,
		ExeBasename:      basename,
		CWD:              "/proj",
		ArgvPreview:      argv,
		StartedAt:        started,
		LastSeenAt:       started,
	}
}

func sweepTestStore(t *testing.T) (*store.Store, *sql.DB) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "sweep.db")
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return store.New(database), database
}

// sweepStamp formats a time the way the store's internal timestamp() helper
// does (RFC3339Nano, UTC), so a raw session INSERT here compares correctly
// against the correlator's start-time window.
func sweepStamp(tm time.Time) string { return tm.UTC().Format(time.RFC3339Nano) }

// TestSweepCrossOSCorrelationAttributes proves the background sweep attributes
// an unattributed process row (matching basename + cwd + time window) to its
// session WITHOUT any dashboard poll or `observer process tree` CLI trigger —
// it drives only sweepCrossOSCorrelation, the daemon goroutine's body. Before
// the sweep the row is invisible to ProcessRunsForSession; after, it is joined.
func TestSweepCrossOSCorrelationAttributes(t *testing.T) {
	t.Parallel()
	st, database := sweepTestStore(t)
	ctx := context.Background()

	projID, err := st.UpsertProject(ctx, `C:\proj`, "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	sessStart := time.Now().UTC()
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, ?, ?)`,
		"sweep-sess", projID, "claude-code", sweepStamp(sessStart)); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	// A claude.exe root in the project cwd within the window, plus unrelated
	// noise that must stay unattributed.
	root := sweepUnattributedRun("s_root", "", "claude.exe", `C:\proj`, 3001, sessStart.Add(2*time.Second))
	noise := sweepUnattributedRun("s_noise", "", "explorer.exe", `C:\Windows`, 3002, sessStart)
	if _, err := st.PersistRuns(ctx, []processobs.ProcessRun{root, noise}); err != nil {
		t.Fatalf("PersistRuns: %v", err)
	}

	// Before the sweep: the row is captured but invisible to the session.
	if runs, err := st.ProcessRunsForSession(ctx, "sweep-sess"); err != nil {
		t.Fatalf("ProcessRunsForSession (pre): %v", err)
	} else if len(runs) != 0 {
		t.Fatalf("pre-sweep runs = %d, want 0 (unattributed until the sweep joins it)", len(runs))
	}

	// The sweep alone (no dashboard/CLI) attributes the row.
	swept, attributed, err := sweepCrossOSCorrelation(ctx, st, 60, nil)
	if err != nil {
		t.Fatalf("sweepCrossOSCorrelation: %v", err)
	}
	if swept != 1 {
		t.Fatalf("swept %d sessions, want 1", swept)
	}
	if attributed != 1 {
		t.Fatalf("attributed %d rows, want 1 (the claude.exe root; noise excluded)", attributed)
	}

	runs, err := st.ProcessRunsForSession(ctx, "sweep-sess")
	if err != nil {
		t.Fatalf("ProcessRunsForSession (post): %v", err)
	}
	if len(runs) != 1 || runs[0].ProcessKey != "s_root" {
		t.Fatalf("post-sweep runs = %+v, want just s_root", runs)
	}
	if runs[0].AttributionSource != string(processobs.AttrCrossOSCorrelation) {
		t.Errorf("attribution source = %q, want cross_os_correlation", runs[0].AttributionSource)
	}

	// Idempotent: a second sweep re-confirms without new attributions (never
	// fights the lazy trigger).
	if _, attributed2, err := sweepCrossOSCorrelation(ctx, st, 60, nil); err != nil || attributed2 != 0 {
		t.Errorf("second sweep = %d attributed, %v; want 0 (idempotent)", attributed2, err)
	}
}

// TestSweepCrossOSCorrelationNoActiveSessions proves the sweep is a no-op when
// no session is active in the window — the structural stand-in for the
// disabled-capture case, where runProcessObserver returns before the sweep
// goroutine is ever started (the sweep only runs for enabled installs).
func TestSweepCrossOSCorrelationNoActiveSessions(t *testing.T) {
	t.Parallel()
	st, database := sweepTestStore(t)
	ctx := context.Background()

	projID, err := st.UpsertProject(ctx, `C:\proj`, "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	// A stale session (5h ago, no recent activity) is outside the window.
	old := time.Now().UTC().Add(-5 * time.Hour)
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, ?, ?)`,
		"stale-sess", projID, "claude-code", sweepStamp(old)); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	swept, attributed, err := sweepCrossOSCorrelation(ctx, st, 60, nil)
	if err != nil {
		t.Fatalf("sweepCrossOSCorrelation: %v", err)
	}
	if swept != 0 || attributed != 0 {
		t.Fatalf("sweep over no active sessions = (%d, %d), want (0, 0)", swept, attributed)
	}
}

// TestResolveCorrelateInterval pins the "0 = inherit the 90s default" contract
// and that an explicit positive value is honored.
func TestResolveCorrelateInterval(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ms   int
		want time.Duration
	}{
		{"zero inherits default", 0, 90 * time.Second},
		{"negative inherits default", -1, 90 * time.Second},
		{"explicit value honored", 30000, 30 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveCorrelateInterval(config.ProcessConfig{CorrelateIntervalMS: tc.ms})
			if got != tc.want {
				t.Errorf("resolveCorrelateInterval(%d) = %s, want %s", tc.ms, got, tc.want)
			}
		})
	}
}

// TestSweepActionCorrelationLinks proves the background action-correlation
// sweep links an already-session-attributed process_run to the run_command
// action that spawned it — WITHOUT any dashboard poll or `observer process
// tree` CLI trigger — driving only sweepActionCorrelation, the daemon
// goroutine's body. A second sweep with nothing new is idempotent AND, via
// the watermark, skips the correlate pass entirely.
func TestSweepActionCorrelationLinks(t *testing.T) {
	t.Parallel()
	st, database := sweepTestStore(t)
	ctx := context.Background()

	projID, err := st.UpsertProject(ctx, "/proj", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	sessStart := time.Now().UTC()
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, ?, ?)`,
		"link-sess", projID, "claude-code", sweepStamp(sessStart)); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	// A run_command action "npm test" at turn 4.
	if _, err := st.Ingest(ctx, []models.ToolEvent{{
		SourceFile: "cc.jsonl", SourceEventID: "a1", SessionID: "link-sess",
		ProjectRoot: "/proj", Timestamp: sessStart, Tool: models.ToolClaudeCode,
		ActionType: models.ActionRunCommand, Target: "npm test", TurnIndex: 4, Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatalf("Ingest action: %v", err)
	}

	// An already-attributed process (session_id set, action_id NULL) whose
	// argv matches the action, spawned within the correlation window.
	run := sweepAttributedRun("l_npm", "link-sess", projID, "", "npm", "npm test", 4001, sessStart.Add(time.Second))
	if _, err := st.PersistRuns(ctx, []processobs.ProcessRun{run}); err != nil {
		t.Fatalf("PersistRuns: %v", err)
	}

	cursors := make(map[string]actionSweepCursor)
	sessions, linked, err := sweepActionCorrelation(ctx, st, 60, nil, cursors)
	if err != nil {
		t.Fatalf("sweepActionCorrelation: %v", err)
	}
	if sessions != 1 {
		t.Fatalf("sessions = %d, want 1", sessions)
	}
	if linked != 1 {
		t.Fatalf("linked = %d, want 1", linked)
	}

	var actionID sql.NullInt64
	if err := database.QueryRowContext(ctx,
		`SELECT action_id FROM process_runs WHERE process_key = ?`, "l_npm").Scan(&actionID); err != nil {
		t.Fatalf("read process_runs: %v", err)
	}
	if !actionID.Valid {
		t.Fatalf("l_npm not linked to an action")
	}

	if len(cursors) != 1 {
		t.Fatalf("cursors = %+v, want exactly one entry", cursors)
	}

	// Re-run: idempotent (nothing new linked) via BOTH the store seam's own
	// guard AND the watermark skipping the correlate call entirely.
	sessions2, linked2, err := sweepActionCorrelation(ctx, st, 60, nil, cursors)
	if err != nil {
		t.Fatalf("sweepActionCorrelation (2nd): %v", err)
	}
	if sessions2 != 0 || linked2 != 0 {
		t.Fatalf("second sweep = (%d, %d), want (0, 0) — watermark should have skipped it", sessions2, linked2)
	}
}

// TestSweepActionCorrelationWatermarkSkips proves that once a session's
// watermark is populated, a second sweep with no new processes or
// run_command actions performs NO new linking work — the cursor comparison
// alone (not a re-run of the idempotent guard) is what skips it.
func TestSweepActionCorrelationWatermarkSkips(t *testing.T) {
	t.Parallel()
	st, database := sweepTestStore(t)
	ctx := context.Background()

	projID, err := st.UpsertProject(ctx, "/proj", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	sessStart := time.Now().UTC()
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, ?, ?)`,
		"watermark-sess", projID, "claude-code", sweepStamp(sessStart)); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if _, err := st.Ingest(ctx, []models.ToolEvent{{
		SourceFile: "cc.jsonl", SourceEventID: "a1", SessionID: "watermark-sess",
		ProjectRoot: "/proj", Timestamp: sessStart, Tool: models.ToolClaudeCode,
		ActionType: models.ActionRunCommand, Target: "npm test", TurnIndex: 1, Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatalf("Ingest action: %v", err)
	}
	run := sweepAttributedRun("w_npm", "watermark-sess", projID, "", "npm", "npm test", 4101, sessStart.Add(time.Second))
	if _, err := st.PersistRuns(ctx, []processobs.ProcessRun{run}); err != nil {
		t.Fatalf("PersistRuns: %v", err)
	}

	cursors := make(map[string]actionSweepCursor)
	if _, linked, err := sweepActionCorrelation(ctx, st, 60, nil, cursors); err != nil || linked != 1 {
		t.Fatalf("first sweep = %d, %v; want 1 linked", linked, err)
	}
	before := cursors["watermark-sess"]

	// No DB change between sweeps — the watermark must be untouched and the
	// sweep must report nothing swept.
	sessions, linked, err := sweepActionCorrelation(ctx, st, 60, nil, cursors)
	if err != nil {
		t.Fatalf("sweepActionCorrelation (2nd): %v", err)
	}
	if sessions != 0 || linked != 0 {
		t.Fatalf("second sweep = (%d, %d), want (0, 0)", sessions, linked)
	}
	if cursors["watermark-sess"] != before {
		t.Fatalf("cursor changed with no DB activity: before=%+v after=%+v", before, cursors["watermark-sess"])
	}
}

// TestSweepActionCorrelationRelinksLateRow pins the HIGH-1 fix: a process that
// joins a SETTLED session's turn-unlinked set with an EARLIER started_at than
// the rows already there — exactly what the cross-OS sweep's session_id UPDATE
// surfaces, since it stamps an already-captured (hence earlier-started) row —
// must still be re-linked on the next sweep. A MAX(started_at) watermark would
// not advance for such a row, so the sweep would skip the session forever; the
// COUNT(unlinked) watermark advances and the row links.
func TestSweepActionCorrelationRelinksLateRow(t *testing.T) {
	t.Parallel()
	st, database := sweepTestStore(t)
	ctx := context.Background()

	projID, err := st.UpsertProject(ctx, "/proj", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	sessStart := time.Now().UTC()
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, ?, ?)`,
		"late-sess", projID, "claude-code", sweepStamp(sessStart)); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	// "go build" ran first (turn 1, at sessStart); "npm test" later (turn 2).
	if _, err := st.Ingest(ctx, []models.ToolEvent{
		{SourceFile: "cc.jsonl", SourceEventID: "a2", SessionID: "late-sess", ProjectRoot: "/proj",
			Timestamp: sessStart, Tool: models.ToolClaudeCode,
			ActionType: models.ActionRunCommand, Target: "go build", TurnIndex: 1, Success: true},
		{SourceFile: "cc.jsonl", SourceEventID: "a1", SessionID: "late-sess", ProjectRoot: "/proj",
			Timestamp: sessStart.Add(10 * time.Second), Tool: models.ToolClaudeCode,
			ActionType: models.ActionRunCommand, Target: "npm test", TurnIndex: 2, Success: true},
	}, nil, store.IngestOptions{}); err != nil {
		t.Fatalf("Ingest actions: %v", err)
	}

	// A LATER-started npm run links and settles the session's watermark.
	if _, err := st.PersistRuns(ctx, []processobs.ProcessRun{
		sweepAttributedRun("late_npm", "late-sess", projID, "", "npm", "npm test", 5001, sessStart.Add(11*time.Second)),
	}); err != nil {
		t.Fatalf("PersistRuns npm: %v", err)
	}
	cursors := make(map[string]actionSweepCursor)
	if _, linked, err := sweepActionCorrelation(ctx, st, 60, nil, cursors); err != nil || linked != 1 {
		t.Fatalf("first sweep linked=%d err=%v; want 1", linked, err)
	}

	// A row now joins with an EARLIER started_at (its go-build turn ran first),
	// as a cross-OS session_id UPDATE would surface it.
	if _, err := st.PersistRuns(ctx, []processobs.ProcessRun{
		sweepAttributedRun("late_go", "late-sess", projID, "", "go", "go build", 5002, sessStart.Add(time.Second)),
	}); err != nil {
		t.Fatalf("PersistRuns go: %v", err)
	}
	_, linked, err := sweepActionCorrelation(ctx, st, 60, nil, cursors)
	if err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	if linked != 1 {
		t.Fatalf("late row linked=%d, want 1 — the count watermark must advance on the new unlinked row despite its earlier started_at", linked)
	}
	var actionID sql.NullInt64
	if err := database.QueryRowContext(ctx,
		`SELECT action_id FROM process_runs WHERE process_key = ?`, "late_go").Scan(&actionID); err != nil {
		t.Fatalf("read late_go: %v", err)
	}
	if !actionID.Valid {
		t.Fatalf("late_go not linked to its action")
	}
}

// TestSweepActionCorrelationNoActiveSessions proves the sweep is a no-op when
// no session is active in the window, and that the cursor map is pruned back
// to empty (the unbounded-growth guard has nothing to hold onto).
func TestSweepActionCorrelationNoActiveSessions(t *testing.T) {
	t.Parallel()
	st, database := sweepTestStore(t)
	ctx := context.Background()

	projID, err := st.UpsertProject(ctx, "/proj", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	// A stale session (5h ago, no recent activity) is outside the window.
	old := time.Now().UTC().Add(-5 * time.Hour)
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, ?, ?)`,
		"stale-action-sess", projID, "claude-code", sweepStamp(old)); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	cursors := map[string]actionSweepCursor{"stale-action-sess": {unlinked: 1, action: 1}}
	sessions, linked, err := sweepActionCorrelation(ctx, st, 60, nil, cursors)
	if err != nil {
		t.Fatalf("sweepActionCorrelation: %v", err)
	}
	if sessions != 0 || linked != 0 {
		t.Fatalf("sweep over no active sessions = (%d, %d), want (0, 0)", sessions, linked)
	}
	if len(cursors) != 0 {
		t.Fatalf("cursors = %+v, want pruned to empty (session not active)", cursors)
	}
}
