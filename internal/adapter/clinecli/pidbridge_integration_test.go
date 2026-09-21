//go:build linux

package clinecli_test

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter/clinecli"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/pidbridge"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestSessionProcessSeed_LiveEndToEnd is the live-pid, real-adapter,
// real-store proof of the "WorkerPIDReporter" rail (SessionProcessSeed →
// session_pid_bridge, docs/plans/apm-across-adapters-plan-2026-09-21.md S2).
// It closes the gap the two existing unit tests split between them
// (TestBuildProcessSeeds covers the adapter shape; TestIngest_
// SessionProcessSeeds covers the store seam with ExecHint=""): here the
// PRODUCTION adapter parses a REAL cline-cli sessions.db, and the store
// runs the real pidbridge.ValidateLocalProcess against /proc.
//
// Chain proven, in one fixture:
//
//	sessions.pid (open row)
//	  → clinecli.Adapter.ParseSessionFile → ParseResult.SessionProcessSeeds
//	  → store.Ingest → pidbridge.ValidateLocalProcess → session_pid_bridge.
//
// Crucially, the validator's TWO independent guards are each isolated by a
// dedicated negative, so a validator that dropped EITHER guard would fail
// this test (not merely a liveness-only one):
//
//   - open-live:    live process whose /proc identity contains "cline"   → BRIDGE row.
//   - open-nomatch: live process whose identity does NOT contain "cline"  → NO row
//     (isolates the IDENTITY guard — a liveness-only validator would bridge this).
//   - open-dead:    a "cline"-named process we reaped, so identity WOULD
//     match but the pid is dead                                          → NO row
//     (isolates the LIVENESS guard, with a guaranteed-dead pid — not a
//     guessed unassigned one).
//   - ended:        an ended session                                     → no seed at all
//     (adapter-side skip; never reaches the store).
//
// linux-only build tag: ValidateLocalProcess is /proc-based (a Windows
// pid read across a WSL mount is correctly refused elsewhere).
func TestSessionProcessSeed_LiveEndToEnd(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()

	sleeper, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Skipf("cannot read /bin/sleep to build a live worker: %v", err)
	}
	// spawnWorker copies /bin/sleep to a controlled basename and execs it,
	// so /proc/<pid>/comm carries that basename verbatim — the knob that
	// decides whether ValidateLocalProcess's "cline" identity check
	// matches. Shell-independent (Ubuntu /bin/sh is dash, which lacks the
	// `exec -a` argv-override bashism). Returns the pid and a reaper.
	spawnWorker := func(basename string) (int, func()) {
		p := filepath.Join(tmp, basename)
		if err := os.WriteFile(p, sleeper, 0o755); err != nil {
			t.Fatalf("write worker %s: %v", basename, err)
		}
		c := exec.Command(p, "120") //nolint:gosec // a copied /bin/sleep, path is test-owned
		if err := c.Start(); err != nil {
			t.Fatalf("start worker %s: %v", basename, err)
		}
		return c.Process.Pid, func() { _ = c.Process.Kill(); _, _ = c.Process.Wait() }
	}

	// 1. Live + identity MATCH ("cline" in comm).
	livePID, killLive := spawnWorker("clineworker")
	t.Cleanup(killLive)
	// 2. Live + identity NON-match (no "cline" anywhere in comm/cmdline) —
	//    the row that falsifies a liveness-only validator.
	noMatchPID, killNoMatch := spawnWorker("sleeperxyz")
	t.Cleanup(killNoMatch)
	// 3. Identity WOULD match, but reap it now → guaranteed-dead pid,
	//    isolating the liveness guard.
	deadPID, killDead := spawnWorker("clinedead")
	killDead() // kill + wait → deadPID is dead before the store validates.

	// Guard the test's own premise so a surprising /proc/comm can never
	// silently make a negative vacuous: assert the identity substring is
	// present/absent exactly as intended before trusting the outcomes.
	assertIdentity(t, livePID, "cline", true)
	assertIdentity(t, noMatchPID, "cline", false)

	// 4. A REAL cline-cli sessions.db with the four rows. Only the
	//    sessions table is read by the adapter's scanStateDB.
	dbPath := writeClineSessionsDB(t, tmp, []clineSessionFixture{
		{id: "open-live", pid: livePID, ended: false, cwd: tmp},
		{id: "open-nomatch", pid: noMatchPID, ended: false, cwd: tmp},
		{id: "open-dead", pid: deadPID, ended: false, cwd: tmp},
		{id: "ended", pid: 424242, ended: true, cwd: tmp},
	})

	// 5. Production adapter parses the real DB. Three open sessions → three
	//    seeds (the ended one is skipped adapter-side); the two negatives
	//    survive emission and are rejected only at store validation.
	res, err := clinecli.New().ParseSessionFile(ctx, dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if got := len(res.SessionProcessSeeds); got != 3 {
		t.Fatalf("SessionProcessSeeds = %d, want 3 (three open sessions; ended skipped)", got)
	}
	var liveSeed *models.SessionProcessSeed
	for i := range res.SessionProcessSeeds {
		if res.SessionProcessSeeds[i].PID == livePID {
			liveSeed = &res.SessionProcessSeeds[i]
		}
	}
	if liveSeed == nil {
		t.Fatalf("no seed for the live pid %d; got %+v", livePID, res.SessionProcessSeeds)
	}
	if liveSeed.SessionID != "open-live" || liveSeed.Tool != models.ToolClineCLI || liveSeed.ExecHint != "cline" {
		t.Errorf("live seed = %+v; want session=open-live tool=cline-cli hint=cline", *liveSeed)
	}

	// 6. Real store consumes the seeds; only the live + identity-matched
	//    one becomes a bridge row.
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(tmp, "observer.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()
	st := store.New(database)
	if _, err := st.Ingest(ctx, res.ToolEvents, res.TokenEvents, store.IngestOptions{
		SessionProcessSeeds: res.SessionProcessSeeds,
	}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	bridge := pidbridge.New(database)
	entry, ok, err := bridge.Lookup(ctx, livePID)
	if err != nil {
		t.Fatalf("bridge.Lookup(live): %v", err)
	}
	if !ok {
		t.Fatal("live+identity-matched pid produced NO session_pid_bridge row; the SessionProcessSeed rail did not fire")
	}
	if entry.SessionID != "open-live" || entry.Tool != models.ToolClineCLI {
		t.Errorf("bridge entry = %+v; want open-live/cline-cli", entry)
	}

	// Negative A (IDENTITY guard): live but no "cline" identity → no row.
	if _, ok, err := bridge.Lookup(ctx, noMatchPID); err != nil {
		t.Fatalf("bridge.Lookup(no-match): %v", err)
	} else if ok {
		t.Error("live-but-wrong-identity seed produced a bridge row; the identity guard is not discriminating")
	}
	// Negative B (LIVENESS guard): identity would match, but pid is dead → no row.
	if _, ok, err := bridge.Lookup(ctx, deadPID); err != nil {
		t.Fatalf("bridge.Lookup(dead): %v", err)
	} else if ok {
		t.Error("dead-pid seed produced a bridge row; the liveness guard is not rejecting")
	}
}

// assertIdentity fails the test unless "hint" appears (want=true) or is
// absent (want=false) across /proc/<pid>/comm + cmdline — the same two
// sources ValidateLocalProcess reads. It pins the test's OWN premise so a
// surprising comm (kernel 15-char cap, an unexpected temp-dir path) can
// never make an identity negative pass for the wrong reason.
func assertIdentity(t *testing.T, pid int, hint string, want bool) {
	t.Helper()
	comm, _ := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	cmdline, _ := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	got := strings.Contains(strings.ToLower(string(comm)), hint) ||
		strings.Contains(strings.ToLower(strings.ReplaceAll(string(cmdline), "\x00", " ")), hint)
	if got != want {
		t.Fatalf("identity premise broken for pid %d: %q present=%v, want present=%v (comm=%q)", pid, hint, got, want, string(comm))
	}
}

type clineSessionFixture struct {
	id    string
	pid   int
	ended bool
	cwd   string
}

// writeClineSessionsDB builds a minimal real cline-cli sessions.db (only
// the `sessions` table the adapter reads) under root and returns the db
// path. Column shape mirrors testdata/clinecli/sessions.sql.
func writeClineSessionsDB(t *testing.T, root string, rows []clineSessionFixture) string {
	t.Helper()
	dbDir := filepath.Join(root, "data", "db")
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dbPath := filepath.Join(dbDir, "sessions.db")
	sdb, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath))
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer sdb.Close()
	if _, err := sdb.Exec(`CREATE TABLE sessions (
		session_id TEXT PRIMARY KEY, source TEXT NOT NULL, pid INTEGER NOT NULL,
		started_at TEXT NOT NULL, ended_at TEXT, exit_code INTEGER, status TEXT NOT NULL,
		status_lock INTEGER NOT NULL DEFAULT 0, interactive INTEGER NOT NULL,
		provider TEXT NOT NULL, model TEXT NOT NULL, cwd TEXT NOT NULL,
		workspace_root TEXT NOT NULL, team_name TEXT, enable_tools INTEGER NOT NULL,
		enable_spawn INTEGER NOT NULL, enable_teams INTEGER NOT NULL,
		parent_session_id TEXT, parent_agent_id TEXT, agent_id TEXT,
		conversation_id TEXT, is_subagent INTEGER NOT NULL DEFAULT 0, prompt TEXT,
		metadata_json TEXT, transcript_path TEXT NOT NULL DEFAULT '',
		hook_path TEXT NOT NULL, messages_path TEXT, updated_at TEXT NOT NULL)`); err != nil {
		t.Fatalf("create sessions: %v", err)
	}
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	for _, r := range rows {
		var ended any
		if r.ended {
			ended = now
		}
		if _, err := sdb.Exec(`INSERT INTO sessions (
			session_id, source, pid, started_at, ended_at, exit_code, status,
			interactive, provider, model, cwd, workspace_root, team_name,
			enable_tools, enable_spawn, enable_teams, is_subagent, prompt,
			metadata_json, hook_path, messages_path, updated_at
		) VALUES (?, 'cli', ?, ?, ?, NULL, ?, 1, 'anthropic', 'claude', ?, ?, NULL,
			1, 0, 0, 0, '', NULL, '', NULL, ?)`,
			r.id, r.pid, now, ended, statusFor(r.ended), r.cwd, r.cwd, now); err != nil {
			t.Fatalf("insert %s: %v", r.id, err)
		}
	}
	return dbPath
}

func statusFor(ended bool) string {
	if ended {
		return "completed"
	}
	return "running"
}
