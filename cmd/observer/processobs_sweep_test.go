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
