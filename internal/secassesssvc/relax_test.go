package secassesssvc

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

type fakeApprovals struct {
	nextID   int64
	rows     map[int64]fakeRow
	taken    bool // the key is held by someone else
	renewOK  bool
	events   []string
	term     map[string]fakeTerm
	creates  int
	renews   int
	deletes  int
	countSet int
}

type fakeRow struct {
	by      string
	expires time.Time
	session string
}

type fakeTerm struct {
	live    bool
	session string
	conf    float64
}

func newFake() *fakeApprovals {
	return &fakeApprovals{nextID: 100, rows: map[int64]fakeRow{}, renewOK: true, term: map[string]fakeTerm{}}
}

func (f *fakeApprovals) ports(now *time.Time) Ports {
	return Ports{
		Now: func() time.Time { return *now },
		Terminal: func(h string) (bool, string, float64) {
			t := f.term[h]
			return t.live, t.session, t.conf
		},
		CreateApproval: func(_ context.Context, rule, scope, session, hash, by string, exp time.Time) (int64, bool, error) {
			if f.taken {
				return 0, false, nil
			}
			f.creates++
			f.nextID++
			f.rows[f.nextID] = fakeRow{by: by, expires: exp, session: session}
			return f.nextID, true, nil
		},
		RenewApproval: func(_ context.Context, id int64, by string, was, exp time.Time) (bool, error) {
			f.renews++
			row, ok := f.rows[id]
			if !f.renewOK || !ok || row.by != by || !row.expires.Equal(was) {
				return false, nil
			}
			row.expires = exp
			f.rows[id] = row
			return true, nil
		},
		DeleteApproval: func(_ context.Context, id int64, by string, exp time.Time) (bool, error) {
			row, ok := f.rows[id]
			if !ok || row.by != by || !row.expires.Equal(exp) {
				return false, nil
			}
			f.deletes++
			delete(f.rows, id)
			return true, nil
		},
		Event: func(_ context.Context, phase, hash, session, detail string) error {
			f.events = append(f.events, phase+"|"+session+"|"+detail)
			return nil
		},
		Count: func(_ context.Context, by string, sessions, rules []string, _, _ time.Time) (int, int, error) {
			f.countSet++
			return 2, 1, nil
		},
	}
}

func startedRun(t *testing.T, s *Store, id string, launched time.Time, mutate func(r *Run)) Run {
	t.Helper()
	r := Run{
		ID: id, Kind: "pentest_local", Tool: "claude-code", ProjectRootHash: "ph", Handle: "h-" + id, Sandboxed: true,
		ConfirmedAt: launched, RelaxMinutes: 60, Reported: true, Phase: PhaseStarted,
		Relax: []Relax{{Key: "R-179", Type: "rule", Route: "self", State: string(secassess.RelaxPendingBind), Scope: "session", GrantedBy: "assessment:" + id}},
	}
	if mutate != nil {
		mutate(&r)
	}
	if _, err := s.Record(r, launched); err != nil {
		t.Fatal(err)
	}
	return r
}

// TestReconcileLifecycle walks one session-scoped relaxation through bind,
// renew and end, with a heuristic link that must not bind.
func TestReconcileLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := New(filepath.Join(t.TempDir(), Filename))
	t0 := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	now := t0
	f := newFake()
	id := "0123456789abcdef"
	startedRun(t, s, id, t0, nil)
	f.term["h-"+id] = fakeTerm{live: true}
	p := f.ports(&now)

	// No session yet: nothing is created.
	now = t0.Add(time.Minute)
	Reconcile(ctx, s, p)
	if f.creates != 0 {
		t.Fatal("created a row before a session was bound")
	}
	// A discovered (heuristic) link never binds.
	f.term["h-"+id] = fakeTerm{live: true, session: "sess-1", conf: 0.75}
	now = t0.Add(2 * time.Minute)
	Reconcile(ctx, s, p)
	if f.creates != 0 {
		t.Fatal("a 0.75 link bound a relaxation")
	}
	// The launcher's own echo binds.
	f.term["h-"+id] = fakeTerm{live: true, session: "sess-1", conf: 0.95}
	now = t0.Add(3 * time.Minute)
	Reconcile(ctx, s, p)
	r, _ := s.Get(id)
	if f.creates != 1 || r.Relax[0].State != "active" || r.Relax[0].ApprovalID == 0 || r.Relax[0].SessionID != "sess-1" {
		t.Fatalf("not bound: %+v creates=%d", r.Relax[0], f.creates)
	}
	if !r.Relax[0].ExpiresAt.Equal(now.Add(secassess.ShortTTL)) {
		t.Fatalf("initial expiry %v", r.Relax[0].ExpiresAt)
	}
	// A later tick renews to ShortTTL from then.
	now = t0.Add(4 * time.Minute)
	Reconcile(ctx, s, p)
	r, _ = s.Get(id)
	if f.renews != 1 || !r.Relax[0].ExpiresAt.Equal(now.Add(secassess.ShortTTL)) {
		t.Fatalf("renew: %+v renews=%d", r.Relax[0], f.renews)
	}
	// The terminal exits: the row goes, the run ends once, and the end row and
	// the count are written.
	f.term["h-"+id] = fakeTerm{}
	now = t0.Add(5 * time.Minute)
	Reconcile(ctx, s, p)
	Reconcile(ctx, s, p)
	r, _ = s.Get(id)
	if f.deletes != 1 || len(f.rows) != 0 {
		t.Fatalf("row not removed: deletes=%d rows=%v", f.deletes, f.rows)
	}
	if r.Relax[0].State != "ended" || r.Relax[0].EndReason != secassess.EndTerminalExit || r.EndedAt.IsZero() || r.Relaxed == nil || r.Relaxed.Exact != 2 || r.Relaxed.Approx != 1 {
		t.Fatalf("end record: %+v %+v", r.Relax[0], r.Relaxed)
	}
	if len(f.events) != 1 || !strings.HasPrefix(f.events[0], "end|sess-1|run "+id) || !strings.Contains(f.events[0], "2 exact, 1 approx") {
		t.Fatalf("events %v", f.events)
	}
}

// TestReconcileEdges: one case per way a relaxation does not become, or
// stops being, an approval the run owns.
func TestReconcileEdges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t0 := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		setup     func(f *fakeApprovals, r *Run)
		at        time.Duration
		wantState string
		wantNote  string
		creates   int
		deletes   int
	}{
		{"the bind deadline passes without a session", func(f *fakeApprovals, _ *Run) { f.term["h"] = fakeTerm{live: true} }, 6 * time.Minute, "not_bound", "", 0, 0},
		{"a row the developer already holds is never taken or removed", func(f *fakeApprovals, _ *Run) {
			f.term["h"] = fakeTerm{live: true, session: "s", conf: 0.95}
			f.taken = true
		}, time.Minute, "existing", "existing_row", 0, 0},
		{"a terminal that is already gone ends it before any row", func(f *fakeApprovals, _ *Run) { f.term["h"] = fakeTerm{} }, time.Minute, "ended", "", 0, 0},
		{"the hard cap ends a bound relaxation and removes its row", func(f *fakeApprovals, r *Run) {
			r.Relax[0].State, r.Relax[0].ApprovalID, r.Relax[0].ExpiresAt = "active", 7, t0.Add(10*time.Minute)
			f.rows[7] = fakeRow{by: r.Relax[0].GrantedBy, expires: t0.Add(10 * time.Minute)}
			f.term["h"] = fakeTerm{live: true, session: "s", conf: 0.95}
		}, 60 * time.Minute, "ended", "", 0, 1},
		{"a row the developer changed is lost and never removed", func(f *fakeApprovals, r *Run) {
			r.Relax[0].State, r.Relax[0].ApprovalID, r.Relax[0].ExpiresAt = "active", 7, t0.Add(10*time.Minute)
			f.rows[7] = fakeRow{by: r.Relax[0].GrantedBy, expires: t0.Add(5 * time.Hour)}
			f.term["h"] = fakeTerm{live: true, session: "s", conf: 0.95}
		}, time.Minute, "lost", "row_changed", 0, 0},
		{"an unreadable terminal reads as gone (fail closed)", func(f *fakeApprovals, _ *Run) {}, time.Minute, "ended", "", 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := New(filepath.Join(t.TempDir(), Filename))
			f := newFake()
			now := t0.Add(tc.at)
			id := "00000000000000aa"
			startedRun(t, s, id, t0, func(r *Run) {
				r.Handle = "h"
				tc.setup(f, r)
			})
			Reconcile(ctx, s, f.ports(&now))
			r, _ := s.Get(id)
			if r.Relax[0].State != tc.wantState || r.Relax[0].Note != tc.wantNote || f.creates != tc.creates || f.deletes != tc.deletes {
				t.Fatalf("state %q note %q creates %d deletes %d; want %q %q %d %d", r.Relax[0].State, r.Relax[0].Note, f.creates, f.deletes, tc.wantState, tc.wantNote, tc.creates, tc.deletes)
			}
		})
	}
}

// TestReconcileWithoutRelaxations: a reported run with none still ends once
// with its audit row; an unreported run with none now has its end recorded too
// (W0.2: every launchable kind is watched) but writes no audit row.
func TestReconcileWithoutRelaxations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t0 := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	s := New(filepath.Join(t.TempDir(), Filename))
	f := newFake()
	now := t0.Add(time.Minute)
	startedRun(t, s, "00000000000000b1", t0, func(r *Run) { r.Relax, r.Handle, r.Kind = nil, "reported", "threat_model" })
	startedRun(t, s, "00000000000000b2", t0, func(r *Run) { r.Relax, r.Handle, r.Reported = nil, "quiet", false })
	f.term["reported"], f.term["quiet"] = fakeTerm{live: true}, fakeTerm{live: true}
	p := f.ports(&now)
	Reconcile(ctx, s, p)
	if len(f.events) != 0 {
		t.Fatalf("ended while live: %v", f.events)
	}
	f.term["reported"], f.term["quiet"] = fakeTerm{}, fakeTerm{}
	Reconcile(ctx, s, p)
	Reconcile(ctx, s, p)
	if len(f.events) != 1 || !strings.Contains(f.events[0], "00000000000000b1") {
		t.Fatalf("events %v", f.events)
	}
	q, _ := s.Get("00000000000000b2")
	if q.EndedAt.IsZero() || q.EndWhy != secassess.EndGone {
		t.Fatalf("an unreported run with no relaxation has no recorded end: %+v", q)
	}
	// A run with no handle (a held run) is never walked.
	startedRun(t, s, "00000000000000b3", t0, func(r *Run) { r.Handle, r.Phase = "", PhaseHeld })
	Reconcile(ctx, s, p)
	if len(f.events) != 1 {
		t.Fatalf("a held run was walked: %v", f.events)
	}
}

// TestStoreClaim: held to claimed in one conditional update, released on a
// failed start, and a legacy record reads as started.
func TestStoreClaim(t *testing.T) {
	t.Parallel()
	s := New(filepath.Join(t.TempDir(), Filename))
	id := "00000000000000c1"
	if _, err := s.Record(Run{ID: id, Kind: "pentest_local", Phase: PhaseHeld}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimHeld(id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimHeld(id); !errors.Is(err, ErrNotHeld) {
		t.Fatalf("second claim: %v", err)
	}
	if err := s.ReleaseClaim(id); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.Get(id); r.Phase != PhaseHeld {
		t.Fatalf("phase %q", r.Phase)
	}
	if _, err := s.ClaimHeld("00000000000000ff"); !errors.Is(err, ErrNotHeld) {
		t.Fatalf("unknown run: %v", err)
	}
	if !(Run{}).IsStarted() || (Run{Phase: PhaseHeld}).IsStarted() || (Run{Phase: PhaseCancelled}).IsStarted() {
		t.Fatal("IsStarted")
	}
}
