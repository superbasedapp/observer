package secassesssvc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// quietRun records a started run with no relaxation that is not reported to
// the org, the shape of a run on an individual node on defaults.
func quietRun(t *testing.T, s *Store, id string, launched time.Time, mutate func(r *Run)) {
	t.Helper()
	startedRun(t, s, id, launched, func(r *Run) {
		r.Relax, r.Reported, r.Kind = nil, false, "threat_model"
		r.Handle = "h-" + id
		r.TimeBoxMinutes, r.TimeBoxAction = 60, secassess.TimeBoxStopButton
		if mutate != nil {
			mutate(r)
		}
	})
}

// TestReconcileEndWatch: W0.2. Every launchable kind's end is recorded, with no
// audit row for a run that is not reported, and never when there is no
// terminal resolver to ask.
func TestReconcileEndWatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t0 := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	s := New(filepath.Join(t.TempDir(), Filename))
	f := newFake()
	now := t0.Add(time.Minute)
	quietRun(t, s, "00000000000000e1", t0, nil)
	p := f.ports(&now)

	// No resolver: nothing is ended, because a nil resolver reads every
	// terminal as gone.
	noTerm := p
	noTerm.Terminal = nil
	Reconcile(ctx, s, noTerm)
	if r, _ := s.Get("00000000000000e1"); !r.EndedAt.IsZero() {
		t.Fatal("a run was ended with no terminal resolver")
	}
	// A live terminal: not ended.
	f.term["h-00000000000000e1"] = fakeTerm{live: true}
	Reconcile(ctx, s, p)
	if r, _ := s.Get("00000000000000e1"); !r.EndedAt.IsZero() {
		t.Fatal("a live run was ended")
	}
	// Gone: ended once, no audit row.
	f.term["h-00000000000000e1"] = fakeTerm{}
	now = t0.Add(5 * time.Minute)
	Reconcile(ctx, s, p)
	Reconcile(ctx, s, p)
	r, _ := s.Get("00000000000000e1")
	if !r.EndedAt.Equal(now) || r.EndWhy != secassess.EndGone {
		t.Fatalf("run = %+v", r)
	}
	if len(f.events) != 0 {
		t.Fatalf("an unreported run wrote audit rows: %v", f.events)
	}
}

func TestReconcileEndWritesTheReasonIntoTheAuditRow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t0 := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	s := New(filepath.Join(t.TempDir(), Filename))
	f := newFake()
	now := t0.Add(time.Minute)
	quietRun(t, s, "00000000000000e2", t0, func(r *Run) { r.Reported = true })
	p := f.ports(&now)
	p.AtEnd = func(context.Context, Run) (string, time.Time) { return string(secassess.AuditChanged), now }
	Reconcile(ctx, s, p)
	if len(f.events) != 1 || !strings.Contains(f.events[0], "ended terminal_gone") || !strings.Contains(f.events[0], "boundary audit changed") {
		t.Fatalf("events = %v", f.events)
	}
}

// TestReconcileAudit: the closing snapshot is taken once, on the end
// transition, only for a run launched by a build that took the first one.
func TestReconcileAudit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t0 := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	s := New(filepath.Join(t.TempDir(), Filename))
	f := newFake()
	now := t0.Add(5 * time.Minute)
	quietRun(t, s, "00000000000000a1", t0, nil)
	quietRun(t, s, "00000000000000a2", t0, func(r *Run) { r.Audit = string(secassess.AuditOff) })
	quietRun(t, s, "00000000000000a3", t0, func(r *Run) { r.TimeBoxMinutes = 0 }) // recorded before the depth work
	p := f.ports(&now)
	calls := map[string]int{}
	snapAt := t0.Add(5*time.Minute + 3*time.Second)
	p.AtEnd = func(_ context.Context, r Run) (string, time.Time) {
		calls[r.ID]++
		return string(secassess.AuditNoChange), snapAt
	}
	Reconcile(ctx, s, p)
	Reconcile(ctx, s, p)
	if calls["00000000000000a1"] != 1 || calls["00000000000000a2"] != 0 || calls["00000000000000a3"] != 0 {
		t.Fatalf("snapshot calls = %v", calls)
	}
	a1, _ := s.Get("00000000000000a1")
	if a1.Audit != string(secassess.AuditNoChange) || !a1.AuditAt.Equal(snapAt) {
		t.Fatalf("run = %+v", a1)
	}
	if a2, _ := s.Get("00000000000000a2"); a2.Audit != string(secassess.AuditOff) {
		t.Fatalf("a verdict set at launch was replaced: %+v", a2)
	}
	if a3, _ := s.Get("00000000000000a3"); a3.Audit != "" {
		t.Fatalf("a run launched before the depth work got a verdict: %+v", a3)
	}
}

func TestReconcileAuditCatchUp(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t0 := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	s := New(filepath.Join(t.TempDir(), Filename))
	f := newFake()
	// The runs list's pass has no snapshotter: it ends the runs without one.
	now := t0.Add(10 * time.Minute)
	quietRun(t, s, "00000000000000d1", t0, nil)
	quietRun(t, s, "00000000000000d2", t0.Add(-5*time.Hour), nil)
	listPass := f.ports(&now)
	Reconcile(ctx, s, listPass)
	for _, id := range []string{"00000000000000d1", "00000000000000d2"} {
		if r, _ := s.Get(id); r.EndedAt.IsZero() || r.Audit != "" {
			t.Fatalf("%s: %+v", id, r)
		}
	}
	// The daemon loop's pass takes the snapshot soon after the end, and records
	// could-not-check for a run that ended long ago: never "no change".
	if _, _, err := s.Mutate("00000000000000d2", func(r *Run) error { r.EndedAt = now.Add(-3 * time.Hour); return nil }); err != nil {
		t.Fatal(err)
	}
	loop := f.ports(&now)
	loop.AtEnd = func(context.Context, Run) (string, time.Time) { return string(secassess.AuditNoChange), now }
	Reconcile(ctx, s, loop)
	if r, _ := s.Get("00000000000000d1"); r.Audit != string(secassess.AuditNoChange) {
		t.Fatalf("recent end: %+v", r)
	}
	if r, _ := s.Get("00000000000000d2"); r.Audit != string(secassess.AuditUnchecked) {
		t.Fatalf("old end: %+v", r)
	}
}

// TestReconcileTimeBox: W0.3. A run whose recorded action is auto_close has its
// terminal closed once when it is over its time box, and never earlier; a run
// with the stop button action is never closed by the pass.
func TestReconcileTimeBox(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t0 := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		action string
		now    time.Duration
		closes int
		why    string
	}{
		{"inside the box", secassess.TimeBoxAutoClose, 59 * time.Minute, 0, ""},
		{"on the deadline", secassess.TimeBoxAutoClose, 60 * time.Minute, 0, ""},
		{"over the box", secassess.TimeBoxAutoClose, 61 * time.Minute, 1, secassess.EndTimeBox},
		{"stop button action never closes", secassess.TimeBoxStopButton, 3 * time.Hour, 0, ""},
		{"a record with no action reads as stop button", "", 3 * time.Hour, 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := New(filepath.Join(t.TempDir(), Filename))
			f := newFake()
			now := t0.Add(c.now)
			quietRun(t, s, "00000000000000f1", t0, func(r *Run) { r.TimeBoxAction = c.action })
			f.term["h-00000000000000f1"] = fakeTerm{live: true}
			p := f.ports(&now)
			closes := 0
			p.Close = func(handle string) {
				if handle != "h-00000000000000f1" {
					t.Errorf("closed %q", handle)
				}
				closes++
			}
			Reconcile(ctx, s, p)
			Reconcile(ctx, s, p)
			if closes != c.closes {
				t.Fatalf("closed %d times, want %d", closes, c.closes)
			}
			r, _ := s.Get("00000000000000f1")
			if r.EndWhy != c.why || !r.EndedAt.IsZero() {
				t.Fatalf("run = %+v", r)
			}
			if c.closes > 0 {
				// The terminal goes gone: the end keeps the reason.
				f.term["h-00000000000000f1"] = fakeTerm{}
				Reconcile(ctx, s, p)
				if r, _ := s.Get("00000000000000f1"); r.EndWhy != secassess.EndTimeBox || r.EndedAt.IsZero() {
					t.Fatalf("after the close: %+v", r)
				}
			}
		})
	}
}

func TestReconcileTimeBoxWithoutClosePort(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t0 := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	s := New(filepath.Join(t.TempDir(), Filename))
	f := newFake()
	now := t0.Add(3 * time.Hour)
	quietRun(t, s, "00000000000000f2", t0, func(r *Run) { r.TimeBoxAction = secassess.TimeBoxAutoClose })
	f.term["h-00000000000000f2"] = fakeTerm{live: true}
	Reconcile(ctx, s, f.ports(&now))
	if r, _ := s.Get("00000000000000f2"); r.EndWhy != "" {
		t.Fatalf("a reason was recorded though nothing could close: %+v", r)
	}
}

func TestStorePersistsTheDepthFields(t *testing.T) {
	t.Parallel()
	s := New(filepath.Join(t.TempDir(), Filename))
	at := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	if _, err := s.Record(Run{ID: "00000000000000aa", Kind: "pentest_local", TimeBoxMinutes: 45, TimeBoxAction: "auto_close", EndWhy: "stopped", Audit: "changed", AuditAt: at}, at); err != nil {
		t.Fatal(err)
	}
	r, _ := New(s.path).Get("00000000000000aa")
	if r.TimeBoxMinutes != 45 || r.TimeBoxAction != "auto_close" || r.EndWhy != "stopped" || r.Audit != "changed" || !r.AuditAt.Equal(at) {
		t.Fatalf("run = %+v", r)
	}
}

func TestStoreUnreadable(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), Filename)
	s := New(path)
	if err := s.Unreadable(); err != nil {
		t.Fatalf("an absent record is not unreadable: %v", err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Unreadable(); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("err = %v", err)
	}
	if got := s.Recent(10); len(got) != 0 {
		t.Fatalf("an unreadable record listed %d runs", len(got))
	}
	if err := New("").Unreadable(); err != nil {
		t.Fatalf("a keep-nothing store: %v", err)
	}
}

// ---- side data ----

func TestSideData(t *testing.T) {
	t.Parallel()
	d := NewSideData(filepath.Join(t.TempDir(), SideDirName))
	run := "0123456789abcdef"
	if _, ok := d.Get(run, SideTree); ok || d.Has(run) {
		t.Fatal("an empty store has data")
	}
	if err := d.Put(run, SideTree, []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	if got, ok := d.Get(run, SideTree); !ok || string(got) != `{"ok":true}` || !d.Has(run) {
		t.Fatalf("get = %q %v", got, ok)
	}
	if err := d.Put(run, SideTree, []byte(`{"ok":false}`)); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.Get(run, SideTree); string(got) != `{"ok":false}` {
		t.Fatalf("not replaced: %q", got)
	}
	if err := d.Put(run, SideModel, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := d.Delete(run); err != nil || d.Has(run) {
		t.Fatalf("delete: %v has %v", err, d.Has(run))
	}
	if err := d.Delete(run); err != nil {
		t.Fatalf("deleting nothing: %v", err)
	}
}

func TestSideDataAllowListAndCaps(t *testing.T) {
	t.Parallel()
	d := NewSideData(filepath.Join(t.TempDir(), SideDirName))
	cases := []struct {
		name string
		run  string
		file string
		size int
		want error
	}{
		{"tree on the cap", hex16(1), SideTree, 64 << 10, nil},
		{"tree one over", hex16(2), SideTree, 64<<10 + 1, ErrSideTooLarge},
		{"model past the old 1 MiB cap", hex16(3), SideModel, 1<<20 + 1, nil},
		{"model of five MiB", hex16(4), SideModel, 5 << 20, nil},
		{"model on its cap (three times the ceiling and a MiB)", hex16(8), SideModel, maxSideModel, nil},
		{"model one over its cap", hex16(9), SideModel, maxSideModel + 1, ErrSideTooLarge},
		{"probes one over", hex16(5), SideProbes, 1<<20 + 1, ErrSideTooLarge},
		{"name not on the list", hex16(6), "evil.json", 1, ErrSideName},
		{"path in the name", hex16(7), "../tree.json", 1, ErrSideName},
		{"bad run id", "../../x", SideTree, 1, ErrSideRun},
		{"short run id", "abc", SideTree, 1, ErrSideRun},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := d.Put(c.run, c.file, make([]byte, c.size))
			if !errors.Is(err, c.want) && !(c.want == nil && err == nil) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if c.want != nil {
				if _, ok := d.Get(c.run, c.file); ok {
					t.Fatal("a refused file was readable")
				}
			}
		})
	}
	if err := d.Delete("../x"); !errors.Is(err, ErrSideRun) {
		t.Fatalf("delete of a bad id: %v", err)
	}
}

func TestSideDataFilePermissions(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), SideDirName)
	d := NewSideData(dir)
	if err := d.Put("0123456789abcdef", SideTree, []byte("x")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, "0123456789abcdef", SideTree))
	if err != nil {
		t.Fatal(err)
	}
	if m := st.Mode().Perm(); m&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("mode %v is readable by others", m)
	}
}

func TestSideDataKeepsNothingWithoutAPath(t *testing.T) {
	t.Parallel()
	var nilData *SideData
	for _, d := range []*SideData{nilData, NewSideData("")} {
		if err := d.Put("0123456789abcdef", SideTree, []byte("x")); err != nil {
			t.Fatal(err)
		}
		if _, ok := d.Get("0123456789abcdef", SideTree); ok || d.Has("0123456789abcdef") || d.Prune(func(string) bool { return false }) != 0 || d.Delete("0123456789abcdef") != nil {
			t.Fatal("a keep-nothing side data kept something")
		}
	}
}

func TestSideDataPrune(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), SideDirName)
	d := NewSideData(dir)
	for _, id := range []string{"0000000000000001", "0000000000000002", "0000000000000003"} {
		if err := d.Put(id, SideTree, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	// Strays: a file, and a directory that is not a run id.
	if err := os.WriteFile(filepath.Join(dir, "stray.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "not-a-run"), 0o700); err != nil {
		t.Fatal(err)
	}
	got := d.Prune(func(id string) bool { return id == "0000000000000002" })
	if got != 4 {
		t.Fatalf("removed %d, want 4 (two runs, a file and a directory)", got)
	}
	if !d.Has("0000000000000002") || d.Has("0000000000000001") {
		t.Fatal("the wrong runs were pruned")
	}
}

// TestRecordPrunesTheSideDataOfForgottenRuns: a run that falls out of the 100 the
// record keeps takes its side data with it, and a run's own side data stays.
func TestRecordPrunesTheSideDataOfForgottenRuns(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := New(filepath.Join(dir, Filename))
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	ids := make([]string, 0, MaxRuns+1)
	for i := 0; i <= MaxRuns; i++ {
		id := hex16(i + 1)
		ids = append(ids, id)
		if _, err := s.Record(Run{ID: id, Kind: "threat_model", Phase: PhaseStarted, EndedAt: now}, now); err != nil {
			t.Fatal(err)
		}
		if err := s.Side().Put(id, SideModel, []byte("{}")); err != nil {
			t.Fatal(err)
		}
		// A side directory younger than the prune grace is left alone (a launching
		// run); these were written an hour before the injected clock.
		old := now.Add(-time.Hour)
		if err := os.Chtimes(filepath.Join(dir, SideDirName, id), old, old); err != nil {
			t.Fatal(err)
		}
	}
	// The 101st Record pruned after its write: the first run is gone from the
	// record, so its side data is too (the 101st run's own data was written
	// after, and the next Record keeps it).
	if _, err := s.Record(Run{ID: hex16(9999), Kind: "threat_model", Phase: PhaseStarted, EndedAt: now}, now); err != nil {
		t.Fatal(err)
	}
	if s.Side().Has(ids[0]) || s.Side().Has(ids[1]) {
		t.Fatal("the side data of runs forgotten by the record survived")
	}
	if !s.Side().Has(ids[len(ids)-1]) {
		t.Fatal("the side data of a recorded run was pruned")
	}
}

func hex16(n int) string {
	const digits = "0123456789abcdef"
	b := []byte("0000000000000000")
	for i := len(b) - 1; i >= 0 && n > 0; i-- {
		b[i] = digits[n%16]
		n /= 16
	}
	return string(b)
}

func TestPruneSideRetention(t *testing.T) {
	t.Parallel()
	s := New(filepath.Join(t.TempDir(), Filename))
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	old, recent, running := hex16(1), hex16(2), hex16(3)
	mk := func(id string, ended time.Time, created time.Time) {
		if _, err := s.Record(Run{ID: id, Kind: "threat_model", Phase: PhaseStarted, EndedAt: ended, CreatedAt: created}, created); err != nil {
			t.Fatal(err)
		}
		if err := s.Side().Put(id, SideModel, []byte("{}")); err != nil {
			t.Fatal(err)
		}
		// Stored evidence is old enough for a prune pass at the test's clock.
		past := now.Add(-time.Hour)
		if err := os.Chtimes(filepath.Join(s.Side().dir, id), past, past); err != nil {
			t.Fatal(err)
		}
	}
	mk(old, now.Add(-100*24*time.Hour), now.Add(-101*24*time.Hour))
	mk(recent, now.Add(-2*24*time.Hour), now.Add(-3*24*time.Hour))
	mk(running, time.Time{}, now.Add(-40*24*time.Hour)) // never ended: aged by its start
	if n := s.PruneSide(0, now); n != 0 {
		t.Fatalf("a zero retention removed %d runs", n)
	}
	if n := s.PruneSide(30, now); n != 2 {
		t.Fatalf("removed %d runs, want 2", n)
	}
	if s.Side().Has(old) || s.Side().Has(running) || !s.Side().Has(recent) {
		t.Fatal("retention removed the wrong runs")
	}
	// The runs stay in the record: only the stored evidence goes.
	if len(s.All()) != 3 {
		t.Fatalf("the record holds %d runs", len(s.All()))
	}
	var nilStore *Store
	if nilStore.PruneSide(30, now) != 0 {
		t.Fatal("a nil store pruned")
	}
}

// ---- the run directory ----

func TestPrepareRunDir(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	run := "0123456789abcdef"
	cleanup, err := PrepareRunDir(root, run)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, ".observer", "assessments", run)
	gi, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil || string(gi) != "*\n" {
		t.Fatalf(".gitignore = %q, %v", gi, err)
	}
	// A second call (a retry) is fine and leaves the file as it was.
	again, err := PrepareRunDir(root, run)
	if err != nil {
		t.Fatal(err)
	}
	again()
	if _, err := os.Stat(filepath.Join(dir, ".gitignore")); err != nil {
		t.Fatalf("a retry's cleanup removed the file: %v", err)
	}
	cleanup()
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the cleanup left %s: %v", dir, err)
	}
}

func TestPrepareRunDirCleanupLeavesWhatItDidNotCreate(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	run := "0123456789abcdef"
	dir := filepath.Join(root, ".observer", "assessments", run)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte("kept"), 0o644); err != nil {
		t.Fatal(err)
	}
	cleanup, err := PrepareRunDir(root, run)
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if b, err := os.ReadFile(filepath.Join(dir, "report.md")); err != nil || string(b) != "kept" {
		t.Fatalf("an existing file was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".gitignore")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the .gitignore it created was left")
	}
}

func TestPrepareRunDirRefusals(t *testing.T) {
	t.Parallel()
	if _, err := PrepareRunDir(t.TempDir(), "../etc"); !errors.Is(err, ErrSideRun) {
		t.Fatalf("bad run id: %v", err)
	}
	if _, err := PrepareRunDir(filepath.Join(t.TempDir(), "nope"), "0123456789abcdef"); err == nil {
		t.Fatal("a missing project root was accepted")
	}
}

func TestPrepareRunDirDoesNotFollowASymlinkOutOfTheProject(t *testing.T) {
	t.Parallel()
	root, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, ".observer")); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}
	if _, err := PrepareRunDir(root, "0123456789abcdef"); err == nil {
		t.Fatal("the run directory was created through a symlink")
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatalf("something was written outside the project: %v", entries)
	}
}
