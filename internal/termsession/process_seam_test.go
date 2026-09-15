package termsession

import (
	"sync"
	"testing"
	"time"
)

// pidPTY is a fakePTY that ALSO implements ProcessReporter, so a test can
// exercise the process-attribution seam without a real fork/exec. pid 0 models
// a backend that cannot report one.
type pidPTY struct {
	*fakePTY
	pid int
}

func (p *pidPTY) Pid() int { return p.pid }

// pidSpawner hands out pidPTYs with a caller-chosen pid sequence.
type pidSpawner struct {
	mu   sync.Mutex
	pids []int
	n    int
	last *pidPTY
}

func (s *pidSpawner) Spawn(Spec) (PTY, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pid := 0
	if s.n < len(s.pids) {
		pid = s.pids[s.n]
	}
	s.n++
	p := &pidPTY{fakePTY: newFakePTY(), pid: pid}
	s.last = p
	return p, nil
}

func (s *pidSpawner) lastPTY() *pidPTY {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// recorder collects ProcessEvents in order.
type recorder struct {
	mu     sync.Mutex
	events []ProcessEvent
}

func (r *recorder) observe(ev ProcessEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recorder) snapshot() []ProcessEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ProcessEvent(nil), r.events...)
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestOnProcessSeam is the table-driven contract for the process-attribution
// seam: a nil sink is a clean no-op, a backend that reports no pid fires
// nothing, and a pid-reporting backend fires exactly one Spawned edge per
// spawn followed by exactly one Exited edge.
func TestOnProcessSeam(t *testing.T) {
	tests := []struct {
		name        string
		wireSink    bool
		pid         int
		wantSpawned int
		wantExited  int
	}{
		{name: "nil seam is a clean no-op", wireSink: false, pid: 4242},
		{name: "backend reports no pid fires nothing", wireSink: true, pid: 0},
		{name: "pid-reporting backend fires both edges", wireSink: true, pid: 4242, wantSpawned: 1, wantExited: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sp := &pidSpawner{pids: []int{tc.pid}}
			rec := &recorder{}
			opts := Options{
				Spawner:      sp,
				ReapInterval: time.Hour,
				ExitLinger:   30 * time.Second,
				Now:          time.Now,
			}
			if tc.wireSink {
				opts.OnProcess = rec.observe
			}
			m := NewManager(opts)
			t.Cleanup(m.Shutdown)

			if _, err := m.Create(validSpec()); err != nil {
				t.Fatalf("Create: %v", err)
			}
			// Spawned must already be delivered when Create returns (it is
			// fired inline, before the lifecycle goroutines start).
			gotSpawned := countKind(rec.snapshot(), ProcessSpawned)
			if gotSpawned != tc.wantSpawned {
				t.Fatalf("spawned edges after Create = %d, want %d", gotSpawned, tc.wantSpawned)
			}

			sp.lastPTY().exit(0)
			if tc.wantExited > 0 {
				waitFor(t, "exited edge", func() bool {
					return countKind(rec.snapshot(), ProcessExited) == tc.wantExited
				})
			}
			// Give a stray edge a chance to show up before asserting counts.
			time.Sleep(20 * time.Millisecond)
			evs := rec.snapshot()
			if got := countKind(evs, ProcessSpawned); got != tc.wantSpawned {
				t.Errorf("spawned edges = %d, want %d", got, tc.wantSpawned)
			}
			if got := countKind(evs, ProcessExited); got != tc.wantExited {
				t.Errorf("exited edges = %d, want %d", got, tc.wantExited)
			}
		})
	}
}

func countKind(evs []ProcessEvent, k ProcessEventKind) int {
	n := 0
	for _, ev := range evs {
		if ev.Kind == k {
			n++
		}
	}
	return n
}

// TestOnProcessIdentity pins WHAT the seam publishes: the child's pid, the
// launcher verb, the launch dir, and Spec.SessionID under its honest name
// (SourceSessionID — the handoff source, never the run's own session).
func TestOnProcessIdentity(t *testing.T) {
	sp := &pidSpawner{pids: []int{9001}}
	rec := &recorder{}
	m := NewManager(Options{
		Spawner: sp, ReapInterval: time.Hour, ExitLinger: 30 * time.Second,
		Now: time.Now, OnProcess: rec.observe,
	})
	t.Cleanup(m.Shutdown)

	spec := validSpec()
	spec.Dir = "/home/me/repo"
	handle, err := m.Create(spec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	evs := rec.snapshot()
	if len(evs) != 1 {
		t.Fatalf("events after Create = %d, want 1", len(evs))
	}
	got := evs[0]
	if got.Kind != ProcessSpawned {
		t.Errorf("Kind = %q, want %q", got.Kind, ProcessSpawned)
	}
	if got.Handle != handle {
		t.Errorf("Handle = %q, want the Create handle", got.Handle)
	}
	if got.PID != 9001 {
		t.Errorf("PID = %d, want 9001", got.PID)
	}
	if got.Subcommand != spec.Subcommand {
		t.Errorf("Subcommand = %q, want %q", got.Subcommand, spec.Subcommand)
	}
	if got.SourceSessionID != spec.SessionID {
		t.Errorf("SourceSessionID = %q, want %q", got.SourceSessionID, spec.SessionID)
	}
	if got.Dir != spec.Dir {
		t.Errorf("Dir = %q, want %q", got.Dir, spec.Dir)
	}

	sp.lastPTY().exit(7)
	waitFor(t, "exited edge", func() bool { return len(rec.snapshot()) == 2 })
	exited := rec.snapshot()[1]
	if exited.Kind != ProcessExited || exited.PID != 9001 || exited.Handle != handle {
		t.Errorf("exit edge = %+v, want ProcessExited for pid 9001 on the same handle", exited)
	}
	if exited.ExitCode != 7 {
		t.Errorf("exit edge ExitCode = %d, want 7", exited.ExitCode)
	}
}

// TestPIDForHandle pins that an EXITED pid is never handed out as an
// attribution target — the pid-reuse guard on the read side.
func TestPIDForHandle(t *testing.T) {
	sp := &pidSpawner{pids: []int{555, 0}}
	m := newTestManager(t, sp, time.Now)

	handle, err := m.Create(validSpec())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if pid, ok := m.PIDForHandle(handle); !ok || pid != 555 {
		t.Fatalf("PIDForHandle(live) = (%d,%v), want (555,true)", pid, ok)
	}
	if _, ok := m.PIDForHandle("no-such-handle"); ok {
		t.Error("PIDForHandle(unknown) reported ok=true")
	}

	sp.lastPTY().exit(0)
	waitFor(t, "session marked exited", func() bool {
		_, ok := m.PIDForHandle(handle)
		return !ok
	})

	// A backend that reports no pid never yields one either.
	h2, err := m.Create(validSpec())
	if err != nil {
		t.Fatalf("Create #2: %v", err)
	}
	if pid, ok := m.PIDForHandle(h2); ok {
		t.Errorf("PIDForHandle(no-pid backend) = (%d,true), want ok=false", pid)
	}
}

// TestProcessAttributionForHandle pins the opposite contract from
// PIDForHandle: a caller correlating a run's exit against an external
// observation (the process-control policy-stop lookup) needs the pid to stay
// resolvable AFTER the child has exited, for as long as the handle remains in
// the manager's session map.
func TestProcessAttributionForHandle(t *testing.T) {
	sp := &pidSpawner{pids: []int{777, 0}}
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	m := newTestManager(t, sp, func() time.Time { return now })

	handle, err := m.Create(validSpec())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if pid, launchedAt, ok := m.ProcessAttributionForHandle(handle); !ok || pid != 777 || !launchedAt.Equal(now) {
		t.Fatalf("ProcessAttributionForHandle(live) = (%d,%v,%v), want (777,%v,true)", pid, launchedAt, ok, now)
	}

	// Unlike PIDForHandle, this stays populated once the child exits.
	sp.lastPTY().exit(0)
	waitFor(t, "session marked exited", func() bool {
		_, ok := m.PIDForHandle(handle)
		return !ok
	})
	if pid, launchedAt, ok := m.ProcessAttributionForHandle(handle); !ok || pid != 777 || !launchedAt.Equal(now) {
		t.Fatalf("ProcessAttributionForHandle(exited) = (%d,%v,%v), want (777,%v,true)", pid, launchedAt, ok, now)
	}

	if _, _, ok := m.ProcessAttributionForHandle("no-such-handle"); ok {
		t.Error("ProcessAttributionForHandle(unknown) reported ok=true")
	}

	// A backend that reports no pid never yields one either.
	h2, err := m.Create(validSpec())
	if err != nil {
		t.Fatalf("Create #2: %v", err)
	}
	if pid, _, ok := m.ProcessAttributionForHandle(h2); ok {
		t.Errorf("ProcessAttributionForHandle(no-pid backend) = (%d,true), want ok=false", pid)
	}
}

// TestOnProcessEdgeOrdering pins that a Spawned edge is always delivered
// before its own Exited edge even for an instantly-exiting child — the
// ordering the pid-seed consumer's state machine depends on.
func TestOnProcessEdgeOrdering(t *testing.T) {
	sp := &pidSpawner{pids: []int{1, 2, 3, 4}}
	rec := &recorder{}
	m := NewManager(Options{
		Spawner: sp, MaxConcurrent: 8, ReapInterval: time.Hour,
		ExitLinger: 30 * time.Second, Now: time.Now, OnProcess: rec.observe,
	})
	t.Cleanup(m.Shutdown)

	for i := 0; i < 4; i++ {
		if _, err := m.Create(validSpec()); err != nil {
			t.Fatalf("Create #%d: %v", i, err)
		}
		sp.lastPTY().exit(0)
	}
	waitFor(t, "all exit edges", func() bool {
		return countKind(rec.snapshot(), ProcessExited) == 4
	})

	seen := map[int]bool{}
	for _, ev := range rec.snapshot() {
		switch ev.Kind {
		case ProcessSpawned:
			if seen[ev.PID] {
				t.Errorf("pid %d spawned twice", ev.PID)
			}
			seen[ev.PID] = true
		case ProcessExited:
			if !seen[ev.PID] {
				t.Errorf("pid %d exited before it was announced as spawned", ev.PID)
			}
		}
	}
}
