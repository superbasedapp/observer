package main

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/pidbridge"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsession"
)

// fakeBridge is an in-memory stand-in for the session_pid_bridge table with
// the SAME upsert-on-pid / scoped-delete semantics as pidbridge.Store, so the
// seeder's state machine can be asserted without SQLite in every case.
type fakeBridge struct {
	mu       sync.Mutex
	rows     map[int]pidbridge.Entry
	writes   []pidbridge.Entry
	deletes  []int
	writeErr error
}

func newFakeBridge() *fakeBridge {
	return &fakeBridge{rows: make(map[int]pidbridge.Entry)}
}

func (f *fakeBridge) Write(_ context.Context, e pidbridge.Entry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeErr != nil {
		return f.writeErr
	}
	f.rows[e.PID] = e
	f.writes = append(f.writes, e)
	return nil
}

func (f *fakeBridge) Delete(_ context.Context, pid int, sessionID string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, ok := f.rows[pid]
	if !ok || (sessionID != "" && cur.SessionID != sessionID) {
		return false, nil
	}
	delete(f.rows, pid)
	f.deletes = append(f.deletes, pid)
	return true, nil
}

func (f *fakeBridge) lookup(pid int) (pidbridge.Entry, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.rows[pid]
	return e, ok
}

func (f *fakeBridge) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writes)
}

func (f *fakeBridge) writtenAt(i int) pidbridge.Entry {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes[i]
}

// fakeResolver is a scriptable terminalRunResolver.
type fakeResolver struct {
	handles map[string]string // runID -> handle
	links   map[string]string // runID -> established session id
	tools   map[string]string // handle -> canonical tool
	roots   map[string]string // handle -> project root
	// spawnDirs is the factual child cwd for a run with NO authorized project
	// root (the default-cwd launch shape); roots wins when both are present.
	spawnDirs map[string]string
}

func (f fakeResolver) HandleForRun(runID string) (string, bool) {
	h, ok := f.handles[runID]
	return h, ok
}

func (f fakeResolver) SessionLinkForRun(runID string) (string, float64, bool) {
	s, ok := f.links[runID]
	if !ok {
		return "", 0, false
	}
	return s, 0.9, true
}

func (f fakeResolver) KindForHandle(handle string) (termrun.Kind, string, bool) {
	tool, ok := f.tools[handle]
	if !ok {
		return "", "", false
	}
	return termrun.KindFresh, tool, true
}

func (f fakeResolver) ProjectRoot(handle string) (string, bool) {
	r, ok := f.roots[handle]
	return r, ok
}

// SpawnDir mirrors the service: the launch root when the run carried one,
// otherwise the daemon cwd the child inherits (spawnDirs).
func (f fakeResolver) SpawnDir(handle string) (string, bool) {
	if r, ok := f.roots[handle]; ok && r != "" {
		return r, true
	}
	d, ok := f.spawnDirs[handle]
	return d, ok && d != ""
}

func spawnEvent(handle string, pid int) termsession.ProcessEvent {
	return termsession.ProcessEvent{
		Kind: termsession.ProcessSpawned, Handle: handle, PID: pid,
		Subcommand: "claude", Dir: "/repo", At: time.Now(),
	}
}

func exitEvent(handle string, pid int) termsession.ProcessEvent {
	return termsession.ProcessEvent{
		Kind: termsession.ProcessExited, Handle: handle, PID: pid, At: time.Now(),
	}
}

// TestTerminalPidSeeder is the table-driven contract for the seed side: what
// combination of spawn + correlation actually writes a direct pid seed.
func TestTerminalPidSeeder(t *testing.T) {
	res := fakeResolver{
		handles: map[string]string{"run-1": "h1"},
		links:   map[string]string{"run-1": "sess-1"},
		tools:   map[string]string{"h1": "claude-code"},
		roots:   map[string]string{"h1": "/repo"},
	}

	tests := []struct {
		name       string
		spawn      bool
		spawnPID   int
		runID      string
		res        terminalRunResolver
		wantWrites int
		wantEntry  *pidbridge.Entry
	}{
		{
			name:  "spawn then established correlation seeds once",
			spawn: true, spawnPID: 4242, runID: "run-1", res: res, wantWrites: 1,
			wantEntry: &pidbridge.Entry{PID: 4242, SessionID: "sess-1", Tool: "claude-code", CWD: "/repo"},
		},
		{
			name:  "correlation without a recorded spawn never seeds",
			spawn: false, runID: "run-1", res: res, wantWrites: 0,
		},
		{
			name:  "run whose handle is already gone never seeds",
			spawn: true, spawnPID: 4242, runID: "run-unknown", res: res, wantWrites: 0,
		},
		{
			name:  "unestablished link never seeds",
			spawn: true, spawnPID: 4242, runID: "run-2", wantWrites: 0,
			res: fakeResolver{handles: map[string]string{"run-2": "h1"}, links: map[string]string{}},
		},
		{
			name:  "empty run id never seeds",
			spawn: true, spawnPID: 4242, runID: "", res: res, wantWrites: 0,
		},
		{
			name:  "nil resolver never seeds",
			spawn: true, spawnPID: 4242, runID: "run-1", res: nil, wantWrites: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fb := newFakeBridge()
			s := newTerminalPidSeederWith(fb.Write, fb.Delete, nil)
			if tc.spawn {
				s.Observe(spawnEvent("h1", tc.spawnPID))
			}
			s.OnRunCorrelated(context.Background(), tc.runID, tc.res)
			if got := fb.writeCount(); got != tc.wantWrites {
				t.Fatalf("writes = %d, want %d", got, tc.wantWrites)
			}
			if tc.wantEntry != nil {
				got := fb.writtenAt(0)
				if got.PID != tc.wantEntry.PID || got.SessionID != tc.wantEntry.SessionID ||
					got.Tool != tc.wantEntry.Tool || got.CWD != tc.wantEntry.CWD {
					t.Errorf("entry = %+v, want %+v", got, *tc.wantEntry)
				}
			}
		})
	}
}

// TestTerminalPidSeederIdempotent pins that repeated correlations for the same
// established session write the seed exactly once — the discovery sweep
// re-correlates on every tick.
func TestTerminalPidSeederIdempotent(t *testing.T) {
	fb := newFakeBridge()
	s := newTerminalPidSeederWith(fb.Write, fb.Delete, nil)
	res := fakeResolver{
		handles: map[string]string{"run-1": "h1"},
		links:   map[string]string{"run-1": "sess-1"},
		tools:   map[string]string{"h1": "claude-code"},
	}
	s.Observe(spawnEvent("h1", 4242))
	for i := 0; i < 5; i++ {
		s.OnRunCorrelated(context.Background(), "run-1", res)
	}
	if got := fb.writeCount(); got != 1 {
		t.Fatalf("writes = %d, want 1 (idempotent)", got)
	}
}

// TestTerminalPidSeederRetract covers the lifecycle half: an exit retracts a
// seed that was written, and is a no-op when none was.
func TestTerminalPidSeederRetract(t *testing.T) {
	tests := []struct {
		name      string
		correlate bool
		wantRow   bool
	}{
		{name: "exit retracts a written seed", correlate: true, wantRow: false},
		{name: "exit without a seed is a no-op", correlate: false, wantRow: false},
	}
	res := fakeResolver{
		handles: map[string]string{"run-1": "h1"},
		links:   map[string]string{"run-1": "sess-1"},
		tools:   map[string]string{"h1": "claude-code"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fb := newFakeBridge()
			s := newTerminalPidSeederWith(fb.Write, fb.Delete, nil)
			s.Observe(spawnEvent("h1", 4242))
			if tc.correlate {
				s.OnRunCorrelated(context.Background(), "run-1", res)
				if _, ok := fb.lookup(4242); !ok {
					t.Fatal("seed was not written")
				}
			}
			s.Observe(exitEvent("h1", 4242))
			if _, ok := fb.lookup(4242); ok != tc.wantRow {
				t.Errorf("row present after exit = %v, want %v", ok, tc.wantRow)
			}
			// A second exit edge must stay a clean no-op.
			s.Observe(exitEvent("h1", 4242))
		})
	}
}

// TestTerminalPidSeederPidReuse is the correctness requirement: a recycled pid
// must never resolve to the dead terminal's session, and a late retract from
// the dead terminal must not destroy the new owner's row.
func TestTerminalPidSeederPidReuse(t *testing.T) {
	fb := newFakeBridge()
	s := newTerminalPidSeederWith(fb.Write, fb.Delete, nil)

	first := fakeResolver{
		handles: map[string]string{"run-A": "hA"},
		links:   map[string]string{"run-A": "sess-A"},
		tools:   map[string]string{"hA": "claude-code"},
	}
	second := fakeResolver{
		handles: map[string]string{"run-B": "hB"},
		links:   map[string]string{"run-B": "sess-B"},
		tools:   map[string]string{"hB": "codex"},
	}

	// Terminal A takes pid 100 and is seeded, then exits.
	s.Observe(spawnEvent("hA", 100))
	s.OnRunCorrelated(context.Background(), "run-A", first)
	s.Observe(exitEvent("hA", 100))
	if _, ok := fb.lookup(100); ok {
		t.Fatal("pid 100 still bridged after terminal A exited — a recycled pid would inherit a dead session")
	}

	// Terminal B is handed the SAME pid and correlates to a different session.
	s.Observe(spawnEvent("hB", 100))
	s.OnRunCorrelated(context.Background(), "run-B", second)
	e, ok := fb.lookup(100)
	if !ok {
		t.Fatal("terminal B's seed was not written")
	}
	if e.SessionID != "sess-B" || e.Tool != "codex" {
		t.Fatalf("pid 100 resolves to %+v, want sess-B/codex", e)
	}

	// A duplicate/late exit edge for the DEAD terminal must not touch it.
	s.Observe(exitEvent("hA", 100))
	if e, ok := fb.lookup(100); !ok || e.SessionID != "sess-B" {
		t.Fatalf("late retract from the dead terminal destroyed the live row: %+v ok=%v", e, ok)
	}
}

// TestTerminalPidSeederReleaseAll pins the daemon-shutdown retract.
func TestTerminalPidSeederReleaseAll(t *testing.T) {
	fb := newFakeBridge()
	s := newTerminalPidSeederWith(fb.Write, fb.Delete, nil)
	res := fakeResolver{
		handles: map[string]string{"run-1": "h1", "run-2": "h2"},
		links:   map[string]string{"run-1": "sess-1", "run-2": "sess-2"},
		tools:   map[string]string{"h1": "claude-code", "h2": "codex"},
	}
	s.Observe(spawnEvent("h1", 101))
	s.Observe(spawnEvent("h2", 102))
	s.Observe(spawnEvent("h3", 103)) // never correlated → nothing to retract
	s.OnRunCorrelated(context.Background(), "run-1", res)
	s.OnRunCorrelated(context.Background(), "run-2", res)

	s.releaseAll()
	for _, pid := range []int{101, 102, 103} {
		if _, ok := fb.lookup(pid); ok {
			t.Errorf("pid %d still bridged after releaseAll", pid)
		}
	}
	// Idempotent.
	s.releaseAll()
}

// TestTerminalPidSeederWriteFailureIsFailOpen pins that a bridge write error
// never records phantom ownership (which would leave the seeder believing a
// row exists and, worse, retracting a row it never wrote).
func TestTerminalPidSeederWriteFailureIsFailOpen(t *testing.T) {
	fb := newFakeBridge()
	fb.writeErr = errors.New("boom")
	s := newTerminalPidSeederWith(fb.Write, fb.Delete, nil)
	res := fakeResolver{
		handles: map[string]string{"run-1": "h1"},
		links:   map[string]string{"run-1": "sess-1"},
		tools:   map[string]string{"h1": "claude-code"},
	}
	s.Observe(spawnEvent("h1", 4242))
	s.OnRunCorrelated(context.Background(), "run-1", res)
	s.Observe(exitEvent("h1", 4242))
	if len(fb.deletes) != 0 {
		t.Errorf("retracted %v after a failed write, want no delete", fb.deletes)
	}
}

// TestTerminalPidSeederNilIsNoOp pins that every entry point tolerates a nil
// seeder — the shape the caller relies on when no DB is wired.
func TestTerminalPidSeederNilIsNoOp(t *testing.T) {
	var s *terminalPidSeeder
	s.Observe(spawnEvent("h1", 1))
	s.Observe(exitEvent("h1", 1))
	s.OnRunCorrelated(context.Background(), "run-1", fakeResolver{})
	s.releaseAll()
	if got := newTerminalPidSeeder(nil, nil); got != nil {
		t.Error("newTerminalPidSeeder(nil db) returned a non-nil seeder")
	}
}

// TestSeedingCorrelator pins the wrapper: it must pass the correlation through
// untouched, only seed on success, and return the original function when there
// is nothing to seed with.
func TestSeedingCorrelator(t *testing.T) {
	res := fakeResolver{
		handles: map[string]string{"run-1": "h1"},
		links:   map[string]string{"run-1": "sess-1"},
		tools:   map[string]string{"h1": "claude-code"},
	}
	t.Run("nil seeder returns the original func", func(t *testing.T) {
		called := false
		base := func(context.Context, string, string, termrun.Source, time.Time) error {
			called = true
			return nil
		}
		wrapped := seedingCorrelator(base, nil, res)
		if err := wrapped(context.Background(), "run-1", "sess-1", termrun.SourceOOB, time.Now()); err != nil {
			t.Fatalf("wrapped: %v", err)
		}
		if !called {
			t.Error("base correlate was not called")
		}
	})
	t.Run("success seeds", func(t *testing.T) {
		fb := newFakeBridge()
		s := newTerminalPidSeederWith(fb.Write, fb.Delete, nil)
		s.Observe(spawnEvent("h1", 4242))
		wrapped := seedingCorrelator(
			func(context.Context, string, string, termrun.Source, time.Time) error { return nil }, s, res,
		)
		if err := wrapped(context.Background(), "run-1", "sess-1", termrun.SourceOOB, time.Now()); err != nil {
			t.Fatalf("wrapped: %v", err)
		}
		if fb.writeCount() != 1 {
			t.Errorf("writes = %d, want 1", fb.writeCount())
		}
	})
	t.Run("correlation failure does not seed and propagates", func(t *testing.T) {
		fb := newFakeBridge()
		s := newTerminalPidSeederWith(fb.Write, fb.Delete, nil)
		s.Observe(spawnEvent("h1", 4242))
		want := errors.New("record correlation")
		wrapped := seedingCorrelator(
			func(context.Context, string, string, termrun.Source, time.Time) error { return want }, s, res,
		)
		if err := wrapped(context.Background(), "run-1", "sess-1", termrun.SourceOOB, time.Now()); !errors.Is(err, want) {
			t.Fatalf("err = %v, want %v", err, want)
		}
		if fb.writeCount() != 0 {
			t.Errorf("writes = %d, want 0 on a failed correlation", fb.writeCount())
		}
	})
}

// TestTerminalPidSeederEndToEnd drives the WHOLE seam against the real parts:
// a real termsession.Manager (which publishes the PTY child pid through
// Options.OnProcess), a real pidbridge.Store over a real migrated SQLite DB,
// and a real ancestor-walk-shaped Lookup. It proves the row a downstream
// attribution reader consults actually appears on correlation and actually
// disappears when the terminal's child is reaped.
func TestTerminalPidSeederEndToEnd(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	seeder := newTerminalPidSeeder(database, nil)
	if seeder == nil {
		t.Fatal("newTerminalPidSeeder returned nil for a live DB")
	}
	bridge := pidbridge.New(database)

	sp := &pidSpawnerStub{pid: 31337}
	mgr := termsession.NewManager(termsession.Options{
		Spawner:      sp,
		ReapInterval: time.Hour,
		ExitLinger:   30 * time.Second,
		OnProcess:    seeder.Observe,
	})
	t.Cleanup(mgr.Shutdown)

	handle, err := mgr.Create(termsession.Spec{
		BinPath: "/usr/local/bin/observer", Subcommand: "codex", SessionID: "source-sess",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Registered AFTER the mgr.Shutdown cleanup so it runs BEFORE it (LIFO):
	// the PTY must be released before Shutdown waits on the goroutines reading
	// it. Belt-and-braces alongside Kill/Close — this holds even if a future
	// terminate() path stops calling either.
	t.Cleanup(sp.release)
	if pid, ok := mgr.PIDForHandle(handle); !ok || pid != 31337 {
		t.Fatalf("PIDForHandle = (%d,%v), want (31337,true)", pid, ok)
	}
	// Before correlation there is deliberately NO row: the run's own session is
	// not known yet, and Spec.SessionID is the handoff SOURCE, which migration
	// 064's identity invariant forbids conflating with it.
	if _, ok, lerr := bridge.Lookup(ctx, 31337); lerr != nil || ok {
		t.Fatalf("pre-correlation Lookup: ok=%v err=%v, want a clean miss", ok, lerr)
	}

	res := fakeResolver{
		handles: map[string]string{"run-e2e": handle},
		links:   map[string]string{"run-e2e": "target-sess"},
		tools:   map[string]string{handle: "codex"},
		roots:   map[string]string{handle: "/home/me/repo"},
	}
	seeder.OnRunCorrelated(ctx, "run-e2e", res)

	e, ok, err := bridge.Lookup(ctx, 31337)
	if err != nil || !ok {
		t.Fatalf("post-correlation Lookup: ok=%v err=%v, want the seeded row", ok, err)
	}
	if e.SessionID != "target-sess" || e.Tool != "codex" || e.CWD != "/home/me/repo" {
		t.Fatalf("seeded row = %+v, want target-sess/codex//home/me/repo", e)
	}

	sp.release()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok, _ := bridge.Lookup(ctx, 31337); !ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("pid 31337 still bridged after the PTY child exited — a recycled pid would be misattributed")
}

// pidSpawnerStub is a minimal pid-reporting PTY for the end-to-end test: it
// blocks in Wait until release() is called.
type pidSpawnerStub struct {
	pid  int
	done chan struct{}
	once sync.Once
}

func (s *pidSpawnerStub) Spawn(termsession.Spec) (termsession.PTY, error) {
	s.done = make(chan struct{})
	return &stubPTY{pid: s.pid, done: s.done, release: s.release}, nil
}

func (s *pidSpawnerStub) release() { s.once.Do(func() { close(s.done) }) }

type stubPTY struct {
	pid  int
	done chan struct{}
	// release unblocks the parked Read/Wait. It is the spawner's own
	// single-shot release, so Kill-then-Close cannot double-close.
	release func()
}

func (p *stubPTY) Pid() int { return p.pid }

func (p *stubPTY) Read([]byte) (int, error) {
	<-p.done
	return 0, errClosedStub
}
func (p *stubPTY) Write(b []byte) (int, error) { return len(b), nil }
func (p *stubPTY) Resize(_, _ uint16) error    { return nil }
func (p *stubPTY) Wait() (int, error)          { <-p.done; return 0, nil }

// Kill and Close unblock the parked Read/Wait, the way a real PTY does. A
// stub that accepts Close and leaves its reader parked does not model a
// PTY, and the cost of that is not cosmetic: Manager.Shutdown ends in an
// unbounded m.wg.Wait(), so any t.Fatal between Create and release() parks
// the cleanup forever. On the 2026-08-01 cache-cleared sweep that turned
// ONE flaked assertion into a 40m cmd/observer timeout which starved ~340
// parallel tests in the same package — the whole package reported FAIL
// having actually run almost none of it.
func (p *stubPTY) Kill() error  { p.release(); return nil }
func (p *stubPTY) Close() error { p.release(); return nil }

var errClosedStub = errors.New("stub pty closed")

// TestTerminalPidSeederUsesSpawnDirForDefaultCwdLaunch pins the pid-bridge half
// of the default-cwd fix with the devbox's real values: a dashboard "New
// Terminal" launched with no authorized project root (the node has no
// [terminal.launch].allowed_project_roots) spawns with an empty Spec.Dir and has
// no ProjectRoot, yet its child demonstrably runs in the daemon's cwd
// (/home/azureuser — the value the launcher's own os.Getwd wrote into the
// launch_seeds row for pid 44993). Reading the factual SpawnDir seam instead of
// the authorization-bearing ProjectRoot keeps the bridge row's CWD real.
func TestTerminalPidSeederUsesSpawnDirForDefaultCwdLaunch(t *testing.T) {
	const daemonCwd = "/home/azureuser"
	var wrote []pidbridge.Entry
	seeder := newTerminalPidSeederWith(
		func(_ context.Context, e pidbridge.Entry) error { wrote = append(wrote, e); return nil },
		func(context.Context, int, string) (bool, error) { return true, nil },
		nil,
	)
	// Spawned with NO Dir — the default-cwd shape.
	seeder.Observe(termsession.ProcessEvent{
		Kind: termsession.ProcessSpawned, Handle: "h-devbox", PID: 44993,
		Subcommand: "opencode", Dir: "", At: time.Now(),
	})
	res := fakeResolver{
		handles:   map[string]string{"run-devbox": "h-devbox"},
		links:     map[string]string{"run-devbox": "ses_fb73193f7ffexyKthX20fRk905"},
		tools:     map[string]string{"h-devbox": "opencode"},
		roots:     map[string]string{},                      // no authorized project root
		spawnDirs: map[string]string{"h-devbox": daemonCwd}, // but a real child cwd
	}
	seeder.OnRunCorrelated(context.Background(), "run-devbox", res)

	if len(wrote) != 1 {
		t.Fatalf("writes = %d, want 1", len(wrote))
	}
	want := pidbridge.Entry{
		PID: 44993, SessionID: "ses_fb73193f7ffexyKthX20fRk905", Tool: "opencode", CWD: daemonCwd,
	}
	if wrote[0] != want {
		t.Fatalf("seeded row = %+v, want %+v", wrote[0], want)
	}
}
