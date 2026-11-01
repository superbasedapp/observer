//go:build !sbo_omit_security

package secsvc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

type fakeStore struct {
	blocking    map[string][]string
	historyOnly map[string][]string
	held        map[string][]store.SecHeldRow
	q           store.SecBlockingQuery
}

func (f *fakeStore) SecHeldHistory(_ context.Context, q store.SecBlockingQuery, _ int) ([]store.SecHeldRow, error) {
	return f.held[q.ProjectRootHash], nil
}

func (f *fakeStore) SecBlockingKeys(_ context.Context, q store.SecBlockingQuery, limit int) ([]string, error) {
	if q.HistoryOnly {
		return f.historyOnly[q.ProjectRootHash], nil
	}
	f.q = q
	k := f.blocking[q.ProjectRootHash]
	if len(k) > limit {
		k = k[:limit]
	}
	return k, nil
}

func (f *fakeStore) SecOpenCounts(context.Context, string) ([]store.SecCount, error) {
	return []store.SecCount{{Category: policy.FindingSecret, Severity: policy.FindingSeverityHigh, N: 1}}, nil
}

func (f *fakeStore) SecLastScan(context.Context, string) (time.Time, error) { return time.Time{}, nil }

func newSvc(t *testing.T, st *fakeStore, now time.Time) (*Service, secposture.Layout) {
	t.Helper()
	l := secposture.Layout{Dir: filepath.Join(t.TempDir(), "security")}
	s, err := New(context.Background(), Options{
		Layout: l, Store: st, Now: func() time.Time { return now },
		Projects: func(context.Context, time.Time) ([]string, error) { return []string{"/a", "/b"}, nil },
		Packs:    func() []string { return []string{"security"} },
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, l
}

// TestWriteAllAndTheHookReadsIt: the daemon writes a file per known
// project and the hook-side reader derives the right state from it.
func TestWriteAllAndTheHookReadsIt(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	st := &fakeStore{blocking: map[string][]string{secposture.ProjectRootHash("/a"): {"k1"}}}
	s, l := newSvc(t, st, now)
	if n, err := s.WriteAll(context.Background()); err != nil || n != 2 {
		t.Fatalf("WriteAll = %d, %v", n, err)
	}
	if len(st.q.Severities) != 2 || st.q.Severities[0] != policy.FindingSeverityHigh {
		t.Fatalf("blocking severities = %v", st.q.Severities)
	}
	if r := secposture.Load(l, "/a", secposture.ModuleActive, now, secposture.Versions{}); r.State.Posture != policy.SecurityPostureBlocking {
		t.Fatalf("/a = %+v", r.State)
	}
	if r := secposture.Load(l, "/b", secposture.ModuleActive, now, secposture.Versions{}); r.State.Posture != policy.SecurityPostureClean {
		t.Fatalf("/b = %+v", r.State)
	}
	// Activity, then a clean quick scan covering it.
	hb := secposture.ProjectRootHash("/b")
	_ = secposture.RaiseDirty(l, hb)
	if r := secposture.Load(l, "/b", secposture.ModuleActive, now, secposture.Versions{}); r.State.Posture != policy.SecurityPostureDirty {
		t.Fatalf("/b after a raise = %+v", r.State)
	}
	s.RecordCleanScan("/b", 1)
	if _, err := s.WriteAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r := secposture.Load(l, "/b", secposture.ModuleActive, now, secposture.Versions{}); r.State.Posture != policy.SecurityPostureClean {
		t.Fatalf("/b after a clean scan = %+v", r.State)
	}
	// A restart keeps the clean-scan record and a rising sequence.
	first := s.memory[hb].Sequence
	s2, _ := New(context.Background(), s.o)
	if s2.clean[hb] != 1 || s2.seq < first {
		t.Fatalf("restart: clean %d, seq %d < %d", s2.clean[hb], s2.seq, first)
	}
	// The relay path reads the same state from memory.
	if m := s.Memory("/a", 0, true); m.Posture != policy.SecurityPostureBlocking || m.Blocking != 1 {
		t.Fatalf("memory /a = %+v", m)
	}
	if m := s.Memory("/b", 5, true); m.Posture != policy.SecurityPostureDirty {
		t.Fatalf("memory /b dirty = %+v", m)
	}
	if m := s.Memory("/unknown", 0, true); m.Posture != policy.SecurityPostureUnknown {
		t.Fatalf("memory of an unknown project = %+v", m)
	}
}

func TestOverflowAndSequence(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	var many []string
	for i := 0; i < secposture.MaxBlocking+3; i++ {
		many = append(many, string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	st := &fakeStore{blocking: map[string][]string{secposture.ProjectRootHash("/a"): many}}
	s, l := newSvc(t, st, now)
	if _, err := s.WriteAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r := secposture.Load(l, "/a", secposture.ModuleActive, now, secposture.Versions{}); r.State.Reason != secposture.ReasonOverflow {
		t.Fatalf("overflow = %+v", r.State)
	}
	a, b := s.nextSeq(now), s.nextSeq(now)
	if b <= a {
		t.Fatal("the sequence strictly rises within one millisecond")
	}
	if _, err := New(context.Background(), Options{}); err == nil {
		t.Fatal("a service needs its layout, store and project list")
	}
}

type fakeRunStore struct {
	findings []secfinding.Finding
	runs     []store.SecScanRun
	gone     []store.SecGoneQuery
}

func (f *fakeRunStore) CloseGoneSecFindings(_ context.Context, q store.SecGoneQuery, _ time.Time) (int, error) {
	f.gone = append(f.gone, q)
	return 0, nil
}

func (f *fakeRunStore) UpsertSecFinding(_ context.Context, x secfinding.Finding, _ time.Time) (string, bool, error) {
	f.findings = append(f.findings, x)
	return "id", true, nil
}

func (f *fakeRunStore) InsertSecScanRun(_ context.Context, r store.SecScanRun) error {
	f.runs = append(f.runs, r)
	return nil
}

func TestRecordRun(t *testing.T) {
	t.Parallel()
	st := &fakeRunStore{}
	notified := false
	res := secscan.Result{
		Findings: []secfinding.Finding{{LocalKey: "k", Rule: secfinding.Rule{ID: "R"}, Category: policy.FindingSecret, Severity: "bogus"}},
		Coverage: secscan.Coverage{Outcome: secscan.OutcomeFindings}, Engine: secscan.EngineIdentity{Name: "secrets"},
	}
	n, err := RecordRun(context.Background(), st, secscan.Target{ProjectRoot: "/p", Scope: policy.FindingScopeStaged}, res, time.Now(), time.Second, Gone{}, func() { notified = true })
	if err != nil || n != 1 || !notified {
		t.Fatalf("RecordRun = %d, %v, notified %v", n, err, notified)
	}
	f := st.findings[0]
	if f.Project.RootHash != secposture.ProjectRootHash("/p") || f.Scope != policy.FindingScopeStaged || f.Severity != policy.FindingSeverityInfo {
		t.Fatalf("finding not stamped and normalized: %+v", f)
	}
	if len(st.runs) != 1 || st.runs[0].Outcome != "findings" || st.runs[0].Driver != "secrets" {
		t.Fatalf("runs = %+v", st.runs)
	}
	if _, err := RecordRun(context.Background(), st, secscan.Target{}, res, time.Now(), 0, Gone{}, nil); err == nil {
		t.Fatal("a run needs a project")
	}
	if len(st.gone) != 0 {
		t.Fatalf("a run with no Gone closed something: %+v", st.gone)
	}
}

// TestRecordRunClosesWhatIsGone (lane SEC-GATEFIX milestone 2d): a
// completed run, with findings or none, closes what it proved gone except
// what it reported again; an unknown run closes nothing.
func TestRecordRunClosesWhatIsGone(t *testing.T) {
	t.Parallel()
	gone := Gone{Pack: "security.secrets", Paths: []string{"a.go"}, Removed: []store.SecSighting{{Key: "k9", Path: "b.go"}}}
	target := secscan.Target{ProjectRoot: "/p", Scope: policy.FindingScopePostWrite}
	eng := secscan.EngineIdentity{Name: "native"}
	for _, tc := range []struct {
		name  string
		res   secscan.Result
		close bool
		keep  int
	}{
		{"clean, zero findings", secscan.Result{Coverage: secscan.Coverage{Outcome: secscan.OutcomeClean}, Engine: eng}, true, 0},
		{"findings", secscan.Result{Findings: []secfinding.Finding{{LocalKey: "k1", Rule: secfinding.Rule{ID: "R"}, Category: policy.FindingSecret}}, Coverage: secscan.Coverage{Outcome: secscan.OutcomeFindings}, Engine: eng}, true, 1},
		{"unknown", secscan.Result{Coverage: secscan.Coverage{Outcome: secscan.OutcomeUnknown}, Engine: eng}, false, 0},
	} {
		st := &fakeRunStore{}
		if _, err := RecordRun(context.Background(), st, target, tc.res, time.Now(), 0, gone, nil); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(st.runs) != 1 {
			t.Errorf("%s: the run is not recorded", tc.name)
		}
		if (len(st.gone) == 1) != tc.close {
			t.Fatalf("%s: closes %+v, want %v", tc.name, st.gone, tc.close)
		}
		if tc.close {
			q := st.gone[0]
			if q.Driver != "native" || q.RulePack != "security.secrets" || len(q.Keep) != tc.keep || q.ProjectRootHash != secposture.ProjectRootHash("/p") {
				t.Errorf("%s: query %+v", tc.name, q)
			}
		}
	}
}

// TestWriteAllSkipsUnchangedAndPrunes: an unchanged body is not re-signed
// until its file nears expiry, a deleted file is rewritten at once, a
// project the hook marked dirty is signed before its session is known, and
// the posture file of a project no longer active is removed (audit P-002
// finding 5).
func TestWriteAllSkipsUnchangedAndPrunes(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	clock := now
	roots := []string{"/a", "/b"}
	l := secposture.Layout{Dir: filepath.Join(t.TempDir(), "security")}
	var since time.Time
	s, err := New(context.Background(), Options{
		Layout: l, Store: &fakeStore{}, Now: func() time.Time { return clock },
		Projects: func(_ context.Context, t time.Time) ([]string, error) { since = t; return roots, nil },
		Packs:    func() []string { return []string{"security"} },
	})
	if err != nil {
		t.Fatal(err)
	}
	write := func(want int) {
		t.Helper()
		if n, err := s.WriteAll(context.Background()); err != nil || n != want {
			t.Fatalf("at %s: WriteAll = %d, %v; want %d", clock.Sub(now), n, err, want)
		}
	}
	write(2)
	if want := now.Add(-DefaultActiveWithin); !since.Equal(want) {
		t.Fatalf("active since %s, want %s", since, want)
	}
	clock = now.Add(time.Minute)
	write(0) // unchanged, fresh past the next tick
	if err := secposture.Remove(l, secposture.ProjectRootHash("/a")); err != nil {
		t.Fatal(err)
	}
	write(1) // a deleted file is rewritten
	// A file replaced on disk (here: the same body re-signed under the same
	// key with another sequence, as a program holding the key could) is not
	// the one the service wrote: rewritten at once.
	ha := secposture.ProjectRootHash("/a")
	forged := s.memory[ha]
	forged.Sequence++
	if _, err := secposture.Write(l, forged, s.key); err != nil {
		t.Fatal(err)
	}
	write(1)
	clock = now.Add(secposture.DefaultTTL - secposture.ResignEvery - resignSlack + time.Second)
	write(1) // /b nears expiry; /a was rewritten a minute later
	// The hook marks /c dirty before its session is ingested.
	hc := secposture.ProjectRootHash("/c")
	if err := secposture.RaiseDirty(l, hc); err != nil {
		t.Fatal(err)
	}
	clock = time.Now() // the marker's mtime is the wall clock
	s.o.Now = func() time.Time { return clock }
	roots = []string{"/a"}
	n, err := s.WriteAll(context.Background())
	if err != nil || n != 2 {
		t.Fatalf("WriteAll = %d, %v; want /a re-signed and /c signed", n, err)
	}
	got, err := secposture.PostureHashes(l)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{secposture.ProjectRootHash("/a"), hc}
	if len(got) != 2 || !contains(got, want[0]) || !contains(got, want[1]) {
		t.Fatalf("posture files %v, want /a and /c (/b pruned)", got)
	}
	if _, ok := s.memory[secposture.ProjectRootHash("/b")]; ok {
		t.Fatal("a pruned project's in-memory posture must be forgotten")
	}
	if _, err := os.Stat(l.KeyPath()); err != nil {
		t.Fatalf("pruning must keep the key: %v", err)
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// TestRunReportsErrors: a failed pass reaches OnError and the loop keeps
// going (audit P-002 finding 8).
func TestRunReportsErrors(t *testing.T) {
	t.Parallel()
	l := secposture.Layout{Dir: filepath.Join(t.TempDir(), "security")}
	errs := make(chan error, 4)
	calls := 0
	s, err := New(context.Background(), Options{
		Layout: l, Store: &fakeStore{},
		Projects: func(context.Context, time.Time) ([]string, error) {
			calls++
			if calls == 1 {
				return nil, nil // New's seed
			}
			return nil, errors.New("db gone")
		},
		OnError: func(err error) { errs <- err },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Run(ctx, 10*time.Millisecond); close(done) }()
	for i := 0; i < 2; i++ {
		select {
		case err := <-errs:
			if !strings.Contains(err.Error(), "db gone") {
				t.Fatalf("error %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no error reported")
		}
	}
	cancel()
	<-done
}

// TestHeldPosture (lane sec-gate4 milestone 1a), one case per shape: a key
// is on a remote only when every commit holding it is; a key with no row is
// on none; a capped read keeps the commits but no count.
func TestHeldPosture(t *testing.T) {
	t.Parallel()
	a, b := strings.Repeat("a", 40), strings.Repeat("b", 40)
	for _, tc := range []struct {
		name   string
		keys   []string
		rows   []store.SecHeldRow
		capped bool
		on     map[string]int
		held   int
		over   bool
	}{
		{"no key", nil, nil, false, nil, 0, false},
		{"one commit on origin", []string{"k1"}, []store.SecHeldRow{{LocalKey: "k1", CommitSHA: a, Remotes: []string{"origin"}}}, false, map[string]int{"origin": 1}, 1, false},
		{"two commits, one lacks backup", []string{"k1"}, []store.SecHeldRow{
			{LocalKey: "k1", CommitSHA: a, Remotes: []string{"backup", "origin"}},
			{LocalKey: "k1", CommitSHA: b, Remotes: []string{"origin"}},
		}, false, map[string]int{"origin": 1}, 2, false},
		{"a key with no row is on none", []string{"k1", "k2"}, []store.SecHeldRow{{LocalKey: "k1", CommitSHA: a, Remotes: []string{"origin"}}}, false, map[string]int{"origin": 1}, 1, false},
		{"on no remote", []string{"k1"}, []store.SecHeldRow{{LocalKey: "k1", CommitSHA: a}}, false, nil, 1, false},
		{"capped", []string{"k1"}, []store.SecHeldRow{{LocalKey: "k1", CommitSHA: a, Remotes: []string{"origin"}}}, true, nil, 1, true},
	} {
		on, held, over := HeldPosture(tc.keys, tc.rows, tc.capped)
		if len(on) != len(tc.on) || len(held) != tc.held || over != tc.over {
			t.Errorf("%s: on=%v held=%v over=%v", tc.name, on, held, over)
			continue
		}
		for r, n := range tc.on {
			if on[r] != n {
				t.Errorf("%s: on[%s]=%d, want %d", tc.name, r, on[r], n)
			}
		}
	}
}

// TestComputeSignsTheDefaultPushRemote (lane sec-gate4 audit finding 5):
// a posture with a history-only hold carries the resolved default push
// remote; one without a hold does not ask for it.
func TestComputeSignsTheDefaultPushRemote(t *testing.T) {
	t.Parallel()
	ha, hb := secposture.ProjectRootHash("/a"), secposture.ProjectRootHash("/b")
	st := &fakeStore{
		blocking:    map[string][]string{ha: {"k1"}, hb: {"k2"}},
		historyOnly: map[string][]string{ha: {"k1"}},
		held:        map[string][]store.SecHeldRow{ha: {{LocalKey: "k1", CommitSHA: strings.Repeat("a", 40), Remotes: []string{"origin"}}}},
	}
	asked := map[string]bool{}
	l := secposture.Layout{Dir: filepath.Join(t.TempDir(), "security")}
	s, err := New(context.Background(), Options{
		Layout: l, Store: st,
		Projects:    func(context.Context, time.Time) ([]string, error) { return []string{"/a", "/b"}, nil },
		Packs:       func() []string { return []string{"security"} },
		PushDefault: func(h string) string { asked[h] = true; return "origin" },
	})
	if err != nil {
		t.Fatal(err)
	}
	fa, err := s.Compute(context.Background(), "/a", time.Now())
	if err != nil || fa.DefaultPushRemote != "origin" {
		t.Fatalf("/a = %q %v", fa.DefaultPushRemote, err)
	}
	fb, err := s.Compute(context.Background(), "/b", time.Now())
	if err != nil || fb.DefaultPushRemote != "" || asked[hb] {
		t.Fatalf("/b = %q %v (asked %v)", fb.DefaultPushRemote, err, asked[hb])
	}
}
