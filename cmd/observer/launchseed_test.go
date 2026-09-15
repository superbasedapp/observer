package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/pidbridge"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newLaunchSeedTestDB opens a throwaway observer DB (all migrations applied)
// and returns its path plus the store/bridge pair the sweep consumes.
func newLaunchSeedTestDB(t *testing.T) (path string, database *sql.DB, st *store.Store, bridge *pidbridge.Store) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "launchseed.db")
	database, err := db.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return path, database, store.New(database), pidbridge.New(database)
}

// mustLaunchSeedSession inserts the project + session row a match requires.
func mustLaunchSeedSession(t *testing.T, database *sql.DB, st *store.Store, id, tool, root string, started time.Time) {
	t.Helper()
	ctx := context.Background()
	projectID, err := st.UpsertProject(ctx, root, "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, ?, ?)`,
		id, projectID, tool, started.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed session: %v", err)
	}
}

func TestRecordLaunchSeed_PersistsPastChildExit(t *testing.T) {
	// The launcher is fire-and-forget by design (live-verified 2026-08-21:
	// an exit-retract deleted headless-launch seeds before the 90s sweep
	// could consume them). After "exit" — i.e. simply returning from
	// recordLaunchSeed — the seed MUST still be pending so the sweep can
	// match it against the session the watcher ingests moments later.
	path, _, _, _ := newLaunchSeedTestDB(t)

	recordLaunchSeed(path, "opencode", "/proj", 555, nil)

	database, err := db.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer database.Close()
	pending, err := store.New(database).PendingLaunchSeeds(context.Background(), time.Hour)
	if err != nil || len(pending) != 1 || pending[0].PID != 555 {
		t.Fatalf("pending = (%+v, %v), want one seed for pid 555 still pending after exit", pending, err)
	}
}

func TestRecordLaunchSeed_DisabledOnEmptyPathOrPID(t *testing.T) {
	recordLaunchSeed("", "opencode", "/proj", 1, nil) // must not panic / no-op
	path, _, _, _ := newLaunchSeedTestDB(t)
	recordLaunchSeed(path, "opencode", "/proj", 0, nil)
	database, err := db.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer database.Close()
	pending, err := store.New(database).PendingLaunchSeeds(context.Background(), time.Hour)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending = (%+v, %v), want zero pid to write nothing", pending, err)
	}
}

func TestConsumeLaunchSeeds_BindsOpenCodeSession(t *testing.T) {
	path, database, st, bridge := newLaunchSeedTestDB(t)
	ctx := context.Background()

	spawn := time.Now().UTC().Add(-time.Minute)
	recordLaunchSeed(path, "opencode", "/proj", 777, nil)
	mustLaunchSeedSession(t, database, st, "sess-open-1", "opencode", "/proj", spawn.Add(30*time.Second))

	consumeLaunchSeeds(ctx, st, bridge, nil)

	e, ok, err := bridge.Lookup(ctx, 777)
	if err != nil || !ok {
		t.Fatalf("bridge.Lookup(777) = (%+v, %v), want a row", e, ok)
	}
	if e.SessionID != "sess-open-1" || e.Tool != "opencode" {
		t.Fatalf("bridge row = %+v, want sess-open-1/opencode", e)
	}
	pending, perr := st.PendingLaunchSeeds(ctx, time.Hour)
	if perr != nil || len(pending) != 0 {
		t.Fatalf("pending after consume = (%+v, %v), want seed consumed", pending, perr)
	}
}

func TestConsumeLaunchSeeds_ExistingBridgeRowWins(t *testing.T) {
	// Claude Code attribution must remain unchanged: a hook-written bridge
	// row for a pid is never overwritten by the launch-seed sweep.
	path, database, st, bridge := newLaunchSeedTestDB(t)
	ctx := context.Background()

	spawn := time.Now().UTC().Add(-time.Minute)
	if err := bridge.Write(ctx, pidbridge.Entry{
		PID: 888, SessionID: "hook-session", Tool: "claude-code", CWD: "/proj",
	}); err != nil {
		t.Fatalf("hook bridge write: %v", err)
	}
	recordLaunchSeed(path, "claude-code", "/proj", 888, nil)
	mustLaunchSeedSession(t, database, st, "sess-sweep-would-pick", "claude-code", "/proj", spawn.Add(30*time.Second))

	consumeLaunchSeeds(ctx, st, bridge, nil)

	e, ok, err := bridge.Lookup(ctx, 888)
	if err != nil || !ok {
		t.Fatalf("bridge.Lookup(888) = (%+v, %v), want the hook row intact", e, ok)
	}
	if e.SessionID != "hook-session" {
		t.Fatalf("bridge row = %+v, want hook-written session preserved verbatim", e)
	}
}

func TestConsumeLaunchSeeds_LaunchFailureLeavesNothingBehind(t *testing.T) {
	// A Start failure means recordLaunchSeed never ran; simulate the
	// launcher-side contract by asserting an empty DB sweeps to no rows.
	_, _, st, bridge := newLaunchSeedTestDB(t)
	consumeLaunchSeeds(context.Background(), st, bridge, nil)

	pending, err := st.PendingLaunchSeeds(context.Background(), time.Hour)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending = (%+v, %v), want empty on a fresh DB", pending, err)
	}
}

// TestConsumeLaunchSeeds_LauncherVerbLabelStillBinds is the end-to-end pin for
// the class the 2026-08-26 sweep found: a launcher that records its seed under
// its own VERB label (`gemini`) rather than the canonical adapter key the
// watcher stores on sessions.tool (`gemini-cli`) used to write a seed that
// MatchLaunchSeeds could never pair — the launch silently degraded to lazy
// correlation and the session's process/network panels stayed blank.
func TestConsumeLaunchSeeds_LauncherVerbLabelStillBinds(t *testing.T) {
	path, database, st, bridge := newLaunchSeedTestDB(t)
	ctx := context.Background()
	mustLaunchSeedSession(t, database, st, "sess-gemini", "gemini-cli", "/proj", time.Now().UTC())

	recordLaunchSeed(path, "gemini", "/proj", 4242, nil)
	consumeLaunchSeeds(ctx, st, bridge, nil)

	entry, ok, err := bridge.Lookup(ctx, 4242)
	if err != nil || !ok {
		t.Fatalf("bridge.Lookup(4242) = (%+v, %v, %v), want the seed bound to the gemini-cli session", entry, ok, err)
	}
	if entry.SessionID != "sess-gemini" {
		t.Fatalf("bound session = %q, want sess-gemini", entry.SessionID)
	}
}

// TestConsumeLaunchSeeds_FreshLaunchDoesNotCrossProjects pins the other half:
// a FRESH launch (dir == "", which is every dashboard "New Terminal" launch)
// must not bind to a same-tool session in a DIFFERENT project. The seed now
// carries the launcher's own cwd as the discriminator.
func TestConsumeLaunchSeeds_FreshLaunchDoesNotCrossProjects(t *testing.T) {
	path, database, st, bridge := newLaunchSeedTestDB(t)
	ctx := context.Background()
	// The only recent opencode session belongs to a DIFFERENT project than the
	// directory this launcher is running in.
	mustLaunchSeedSession(t, database, st, "sess-other", "opencode", t.TempDir(), time.Now().UTC())

	// Run the launcher from a directory that is not that project root.
	wd := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(wd); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	recordLaunchSeed(path, "opencode", "", 4343, nil)
	consumeLaunchSeeds(ctx, st, bridge, nil)

	if entry, ok, lerr := bridge.Lookup(ctx, 4343); lerr == nil && ok {
		t.Fatalf("bridge.Lookup(4343) bound session %q — a fresh launch cross-attributed to another project's session", entry.SessionID)
	}
}
