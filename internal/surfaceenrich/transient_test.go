package surfaceenrich

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// busyErr is the exact shape the live daemon logged on 2026-09-03:
// the store's own wrapping around SQLite's BUSY/LOCKED text.
func busyErr() error {
	return fmt.Errorf("store.SetSessionSurface(hosted): %w", errors.New("database is locked"))
}

func TestIsTransientStoreError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"live busy stamp", busyErr(), true},
		{"table locked", errors.New("database table is locked"), true},
		{"driver code", errors.New("SQLITE_BUSY: cannot start a transaction"), true},
		{"interrupted", errors.New("context canceled: interrupted"), true},
		{"unknown surface", errors.New(`store.SetSessionSurface: unknown surface kind "codex_vscode"`), false},
		{"missing id", errors.New("store.SetSessionSurface: SessionID is required"), false},
		{"no rows", errors.New("sql: no rows in result set"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsTransientStoreError(tc.err); got != tc.want {
				t.Errorf("IsTransientStoreError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestStaleCandidateSurvivesTransientStampFailure pins Ticket E1
// (2026-09-03). Live evidence: two pointer files older than the 2h
// window resolved on the daemon's first tick, their SetSessionSurface
// hit `database is locked` in the startup write-lock contention, and the
// one-attempt-for-a-stale-pointer rule then retired them forever — a
// momentary lock became a permanent attribution gap while claude-code
// and copilot-cli stamped fine seconds later.
//
// The injected Stamp fails twice with a busy-shaped error and then
// succeeds; the stamp must land despite the pointer being 48h old.
func TestStaleCandidateSurvivesTransientStampFailure(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 3, 15, 10, 0, 0, time.UTC)
	f, home, _ := linuxFixture(now)
	for p := range f.mtimes {
		f.mtimes[p] = now.Add(-48 * time.Hour) // every pointer is stale
	}
	st := &fakeStore{sessions: map[string]models.SessionSurface{
		sidClaude: {SessionID: sidClaude, Surface: models.SurfaceSDK, SurfaceHost: "ts"},
	}}
	failures := 0
	e := New(Options{
		Load: st.load,
		Stamp: func(ctx context.Context, sf models.SessionSurface) (bool, error) {
			if failures < 2 {
				failures++
				return false, busyErr()
			}
			return st.stamp(ctx, sf)
		},
		Homes:  func() []crossmount.HomeRoot { return []crossmount.HomeRoot{home} },
		FS:     f.FS(),
		Now:    func() time.Time { return now },
		Window: 2 * time.Hour,
	})

	r := e.Tick(context.Background())
	if r.Retrying != 1 || r.Pending != 4 || r.Stamped != 0 {
		t.Fatalf("tick 1 (first busy stamp) = %+v", r)
	}
	// Tick 2: the busy candidate spends a retry grant and fails again;
	// the three merely-missing stale candidates expire as before.
	r = e.Tick(context.Background())
	if r.Retrying != 1 || r.Stamped != 0 || r.Expired != 3 {
		t.Fatalf("tick 2 (second busy stamp) = %+v", r)
	}
	// Tick 3: the store is no longer busy — the stale pointer still
	// stamps, which is the whole point of the ticket.
	r = e.Tick(context.Background())
	if r.Stamped != 1 {
		t.Fatalf("tick 3 (store recovered) = %+v", r)
	}
	if got := st.sessions[sidClaude]; got.SurfaceHost != "jetbrains-idea" || got.Surface != models.SurfaceIDE {
		t.Errorf("stale-but-transiently-failed session never got its hosted stamp: %+v", got)
	}
	// And it is landed: no further traffic.
	r = e.Tick(context.Background())
	if r.Stamped != 0 || r.Retrying != 0 {
		t.Fatalf("steady tick = %+v", r)
	}
}

// TestStaleCandidatePermanentErrorStillExpires pins the other half of the
// classification: a PERMANENT store error keeps today's rule — one
// attempt for a stale pointer, then gone. Retrying an unknown-vocabulary
// failure forever would just relog it every 30s.
func TestStaleCandidatePermanentErrorStillExpires(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 3, 15, 10, 0, 0, time.UTC)
	f, home, _ := linuxFixture(now)
	for p := range f.mtimes {
		f.mtimes[p] = now.Add(-48 * time.Hour)
	}
	st := &fakeStore{sessions: map[string]models.SessionSurface{
		sidClaude: {SessionID: sidClaude, Surface: models.SurfaceSDK, SurfaceHost: "ts"},
	}}
	calls := 0
	e := New(Options{
		Load: st.load,
		Stamp: func(context.Context, models.SessionSurface) (bool, error) {
			calls++
			return false, errors.New(`store.SetSessionSurface: unknown surface kind "nonsense"`)
		},
		Homes:  func() []crossmount.HomeRoot { return []crossmount.HomeRoot{home} },
		FS:     f.FS(),
		Now:    func() time.Time { return now },
		Window: 2 * time.Hour,
	})
	if r := e.Tick(context.Background()); r.Retrying != 0 || r.Pending != 4 {
		t.Fatalf("tick 1 = %+v", r)
	}
	if r := e.Tick(context.Background()); r.Expired != 4 || r.Pending != 0 {
		t.Fatalf("tick 2 = %+v", r)
	}
	if calls != 1 {
		t.Errorf("permanent failure retried %d times, want 1", calls)
	}
}

// TestTransientRetryBudgetIsBounded pins that the grant cannot become an
// infinite retry loop: a stale pointer whose store call never recovers
// stops after TransientRetries extra passes.
func TestTransientRetryBudgetIsBounded(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 3, 15, 10, 0, 0, time.UTC)
	f, home, hist := linuxFixture(now)
	// One stale, resolvable pointer only.
	only := filepath.Join(hist, "t-junie.agentsession")
	f.dirs[hist] = []string{filepath.Base(only)}
	f.mtimes[only] = now.Add(-48 * time.Hour)
	st := &fakeStore{sessions: map[string]models.SessionSurface{
		sidJunie: {SessionID: sidJunie},
	}}
	const budget = 3
	calls := 0
	e := New(Options{
		Load: st.load,
		Stamp: func(context.Context, models.SessionSurface) (bool, error) {
			calls++
			return false, busyErr()
		},
		Homes:            func() []crossmount.HomeRoot { return []crossmount.HomeRoot{home} },
		FS:               f.FS(),
		Now:              func() time.Time { return now },
		Window:           2 * time.Hour,
		TransientRetries: budget,
	})
	for i := 0; i < 10; i++ {
		e.Tick(context.Background())
	}
	if want := 1 + budget; calls != want {
		t.Errorf("stamp called %d times, want %d (one attempt + %d granted retries)", calls, want, budget)
	}
	if r := e.Tick(context.Background()); r.Expired != 1 {
		t.Errorf("exhausted candidate should expire: %+v", r)
	}
}

// TestRunResumeRetriesStartupFailures pins the resumable-Run half of
// E1: the daemon's first pass is the one most likely to hit a busy
// store, so Run re-attempts anything still outstanding a bounded number
// of times before settling into the interval ticker.
func TestRunResumeRetriesStartupFailures(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 3, 15, 10, 0, 0, time.UTC)
	f, home, hist := linuxFixture(now)
	only := filepath.Join(hist, "t-junie.agentsession")
	f.dirs[hist] = []string{filepath.Base(only)}
	f.mtimes[only] = now.Add(-48 * time.Hour)
	st := &fakeStore{sessions: map[string]models.SessionSurface{
		sidJunie: {SessionID: sidJunie},
	}}
	attempts := 0
	e := New(Options{
		Load: st.load,
		Stamp: func(ctx context.Context, sf models.SessionSurface) (bool, error) {
			attempts++
			if attempts == 1 {
				return false, busyErr() // the startup lock
			}
			return st.stamp(ctx, sf)
		},
		Homes:  func() []crossmount.HomeRoot { return []crossmount.HomeRoot{home} },
		FS:     f.FS(),
		Now:    func() time.Time { return now },
		Window: 2 * time.Hour,
		// Long interval: only the resume sweep can produce a second
		// attempt inside the test's lifetime.
		Interval:       time.Hour,
		ResumeAttempts: 2,
		ResumeDelay:    5 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { e.Run(ctx); close(done) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		st.mu.Lock()
		got := st.sessions[sidJunie].SurfaceHost
		st.mu.Unlock()
		if got == "jetbrains-idea" {
			cancel()
			<-done
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatalf("Run's startup resume never re-attempted the busy stamp (%d attempts)", attempts)
}
