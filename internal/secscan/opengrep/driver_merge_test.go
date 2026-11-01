package opengrep

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/extrun/extruntest"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/secfinding/sarif"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// driver_merge_test.go pins the fixes the SEC-G1 merge made to the audit's
// findings 1 to 6 (plans orchestrator, merge of cloud/plans-sec-g1).

// TestFullScanClosesOnlyWhenComplete (audit finding 1): a full run hands
// back the files it read (the ones a gone finding closes in) only when the
// canary passed in that run, nothing was cut at the output cap and every
// skipped result is a partially parsed file.
func TestFullScanClosesOnlyWhenComplete(t *testing.T) {
	many := make([][3]string, sarif.MaxResults+1)
	for i := range many {
		many[i] = [3]string{"python.sql-string-concat", "b.py", strconv.Itoa(i + 1)}
	}
	cases := []struct {
		name    string
		prepare func(f *fake)
		outcome secscan.Outcome
		closes  []string
	}{
		{"a run without the canary closes nothing", func(f *fake) { f.noCanary = true }, secscan.OutcomeFindings, nil},
		{"a truncated run closes nothing", func(f *fake) { f.results = many }, secscan.OutcomeFindings, nil},
		{"a result refused for its location closes nothing", func(f *fake) {
			f.results = append(f.results, [3]string{"python.sql-string-concat", "../outside.py", "3"})
		}, secscan.OutcomeFindings, nil},
		{"a result refused for its rule id closes nothing", func(f *fake) {
			f.results = append(f.results, [3]string{"bad rule id!", "a.py", "3"})
		}, secscan.OutcomeFindings, nil},
		{"a partially parsed file is left out, the rest closes", func(f *fake) { f.errors = []string{"a.py"} }, secscan.OutcomeFindings, []string{"b.py"}},
		{"a clean complete run closes what it read", func(f *fake) { f.results = nil }, secscan.OutcomeClean, []string{"a.py", "b.py"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t)
			c.prepare(f)
			res, scanned, err := New(f.env(&extruntest.Executor{}, &memState{})).ScanFiles(context.Background(), full())
			if err != nil {
				t.Fatal(err)
			}
			if res.Coverage.Outcome != c.outcome {
				t.Fatalf("coverage %+v, want %s", res.Coverage, c.outcome)
			}
			if !slices.Equal(scanned.Files, c.closes) {
				t.Fatalf("closable files %v, want %v (coverage %+v)", scanned.Files, c.closes, res.Coverage)
			}
		})
	}
}

// TestLinkedWorktreeScansTheCheckout (audit finding 2): a run of a linked
// worktree reads the worktree's checkout, records its findings on the
// project (the main repository) and closes nothing.
func TestLinkedWorktreeScansTheCheckout(t *testing.T) {
	f := newFake(t)
	ex := &extruntest.Executor{}
	wt := root + "-wt"
	res, scanned, err := New(f.env(ex, &memState{})).ScanFiles(context.Background(), secscan.Target{ProjectRoot: root, CheckoutRoot: wt, Scope: policy.FindingScopeManual})
	if err != nil {
		t.Fatal(err)
	}
	if res.Coverage.Outcome != secscan.OutcomeFindings || len(res.Findings) != 1 {
		t.Fatalf("coverage %+v", res.Coverage)
	}
	for _, c := range ex.Calls() {
		if c.Dir != wt {
			t.Errorf("a run started in %s, want the worktree %s", c.Dir, wt)
		}
	}
	if fd := res.Findings[0]; fd.Project.RootHash != secposture.ProjectRootHash(root) || fd.Location.RelPath != "b.py" {
		t.Errorf("finding %+v, want it on the project at b.py", fd)
	}
	if len(scanned.Files) != 0 {
		t.Errorf("a worktree run returned closable files %v", scanned.Files)
	}
}

// TestDiffRefusedOnGitFilterDriver (audit finding 3): a diff run is refused
// before Opengrep starts when the repository's own config names a filter
// driver command (the base checkout would start it); a full run never asks.
func TestDiffRefusedOnGitFilterDriver(t *testing.T) {
	diff := secscan.Target{ProjectRoot: root, Scope: policy.FindingScopeDiff, BaseRev: "c3fef7c"}
	cases := []struct {
		name, config string
		exit         int
		reason       string
	}{
		{"an lfs smudge command", "filter.lfs.smudge\ngit-lfs smudge -- %f\x00filter.lfs.required\ntrue\x00", 0, ReasonGitFilter},
		{"a long-running process filter", "filter.x.process\nrun-filter\x00", 0, ReasonGitFilter},
		{"a clean command, subsection in another case", "filter.Mark.clean\ncat\x00", 0, ReasonGitFilter},
		{"config git cannot read", "", 128, ReasonGitConfig},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t)
			f.gitConfig, f.gitExit = c.config, c.exit
			ex := &extruntest.Executor{}
			res, scanned, err := New(f.env(ex, &memState{})).ScanFiles(context.Background(), diff)
			if err != nil {
				t.Fatal(err)
			}
			if res.Coverage.Outcome != secscan.OutcomeFailed || res.Coverage.Reason != c.reason || len(scanned.Files) != 0 {
				t.Fatalf("coverage %+v, want failed %s", res.Coverage, c.reason)
			}
			calls := ex.Calls()
			if len(calls) != 1 || calls[0].Path != "/usr/bin/git" || !slices.Equal(calls[0].Args, GitFilterArgs) || calls[0].Dir != root {
				t.Fatalf("runs %+v, want the filter-driver check only", calls)
			}
			for _, want := range []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_LFS_SKIP_SMUDGE=1"} {
				if !slices.Contains(calls[0].Env, want) {
					t.Errorf("the check's env lacks %s: %v", want, calls[0].Env)
				}
			}
		})
	}
	t.Run("a filter entry that names no command runs", func(t *testing.T) {
		f := newFake(t)
		f.gitConfig = "filter.lfs.required\ntrue\x00"
		ex := &extruntest.Executor{}
		if res, _, _ := New(f.env(ex, &memState{})).ScanFiles(context.Background(), diff); res.Coverage.Outcome != secscan.OutcomeFindings || len(ex.Calls()) != 4 {
			t.Fatalf("coverage %+v, %d runs", res.Coverage, len(ex.Calls()))
		}
	})
	t.Run("a full run never runs the check", func(t *testing.T) {
		f := newFake(t)
		f.gitConfig = "filter.lfs.smudge\ngit-lfs smudge -- %f\x00"
		ex := &extruntest.Executor{}
		res, _, _ := New(f.env(ex, &memState{})).ScanFiles(context.Background(), full())
		if res.Coverage.Outcome != secscan.OutcomeFindings {
			t.Fatalf("coverage %+v", res.Coverage)
		}
		for _, c := range ex.Calls() {
			if c.Path == "/usr/bin/git" {
				t.Errorf("a full run ran git: %v", c.Args)
			}
		}
	})
}

func TestFilterDriverSet(t *testing.T) {
	for out, want := range map[string]bool{
		"":                                      false,
		"filter.lfs.required\ntrue\x00":         false,
		"filter.lfs.smudge\ngit-lfs smudge\x00": true,
		"filter.a.b.process\nx\x00":             true,
		"FILTER.X.CLEAN\ncat\x00":               true,
		"core.fsmonitor\nfalse\x00filter.x.smudge\n\x00": true,
		// A value cannot forge an entry: only the key before the first
		// newline of each NUL-separated entry counts.
		"user.name\nfilter.x.smudge\x00": false,
	} {
		if got := FilterDriverSet([]byte(out)); got != want {
			t.Errorf("FilterDriverSet(%q) = %v, want %v", out, got, want)
		}
	}
}

// TestChangedAndAddedTreeFileIsRefused (audit finding 4): a changed file
// beside an added one refuses the run like a changed file alone: the
// recorded files still present reach the runner with their digests.
func TestChangedAndAddedTreeFileIsRefused(t *testing.T) {
	for _, managed := range []bool{false, true} {
		f := newFake(t)
		st := &memState{}
		if res, _, _ := New(f.env(&extruntest.Executor{}, st)).ScanFiles(context.Background(), full()); res.Coverage.Outcome != secscan.OutcomeFindings {
			t.Fatalf("first run %+v", res.Coverage)
		}
		f.files[treeDir+"/lib/_opcode.so"] = extruntest.File{Digest: strings.Repeat("3", 64)}
		f.tree.Files = append(f.tree.Files, "lib/planted.so")
		f.files[treeDir+"/lib/planted.so"] = extruntest.File{}
		ex := &extruntest.Executor{}
		e := f.env(ex, st)
		e.Managed = managed
		res, _, _ := New(e).ScanFiles(context.Background(), full())
		if res.Coverage.Outcome != secscan.OutcomeFailed || res.Coverage.Reason != secengine.ReasonUnverified || len(ex.Calls()) != 0 {
			t.Fatalf("managed=%v: %+v, %d processes", managed, res.Coverage, len(ex.Calls()))
		}
	}
}

// brokenState is a state store whose record does not load.
type brokenState struct{ saves int }

func (b *brokenState) Load() (State, error) {
	return State{}, errors.New("unexpected end of JSON input")
}
func (b *brokenState) Save(State) error { b.saves++; return nil }

// TestUnreadableRecordIsUnverified (audit finding 4): a state file that
// does not load is driver_unverified (labelled on an individual node,
// refused on a managed one), never "no record", and never re-baselined.
func TestUnreadableRecordIsUnverified(t *testing.T) {
	f := newFake(t)
	st := &brokenState{}
	res, _, _ := New(f.env(&extruntest.Executor{}, st)).ScanFiles(context.Background(), full())
	if res.Coverage.Outcome != secscan.OutcomeFindings || !hasNote(res.Coverage.Notes, UnverifiedPrefix) || !slices.Contains(res.Coverage.Notes, unverifiedRecNote) {
		t.Fatalf("individual: %+v", res.Coverage)
	}
	if in := New(f.env(&extruntest.Executor{}, st)).Inspect(); in.Decision.Detail != secengine.DetailRecordUnreadable || in.Tree != secengine.TreeRecordUnreadable {
		t.Errorf("inspect %+v", in)
	}
	ex := &extruntest.Executor{}
	e := f.env(ex, st)
	e.Managed = true
	res, _, _ = New(e).ScanFiles(context.Background(), full())
	if res.Coverage.Outcome != secscan.OutcomeFailed || res.Coverage.Reason != secengine.ReasonUnverified || len(ex.Calls()) != 0 {
		t.Fatalf("managed: %+v, %d processes", res.Coverage, len(ex.Calls()))
	}
	if st.saves != 0 {
		t.Errorf("a record that did not load was rewritten %d times", st.saves)
	}
}

// TestRevocationsOutliveTheManifest (audit finding 5): a revoked compiled
// pin is refused whatever the manifest's state: the revocation is
// remembered by the scan that saw it, and a manifest of revocations only (a
// stale one) still refuses.
func TestRevocationsOutliveTheManifest(t *testing.T) {
	pin, _ := secengine.CompiledPin("linux", "amd64")
	f := newFake(t)
	st := &memState{}
	ex := &extruntest.Executor{}
	e := f.env(ex, st)
	e.Manifest = &secengine.ManifestPins{Revoked: []string{strings.ToUpper(pin.SHA256)}}
	res, _, _ := New(e).ScanFiles(context.Background(), full())
	if res.Coverage.Reason != secengine.ReasonUnverified || len(ex.Calls()) != 0 {
		t.Fatalf("a revoked pin: %+v, %d processes", res.Coverage, len(ex.Calls()))
	}
	if s, _ := st.Load(); !slices.Contains(s.Revoked, pin.SHA256) {
		t.Fatalf("the revocation was not remembered: %+v", s)
	}
	// The manifest is gone (stale past its floor and dropped, or no longer
	// verifying): the remembered revocation still refuses.
	ex = &extruntest.Executor{}
	res, _, _ = New(f.env(ex, st)).ScanFiles(context.Background(), full())
	if res.Coverage.Reason != secengine.ReasonUnverified || len(ex.Calls()) != 0 {
		t.Fatalf("after the manifest went: %+v, %d processes", res.Coverage, len(ex.Calls()))
	}
	if in := New(f.env(&extruntest.Executor{}, st)).Inspect(); in.Decision.Detail != secengine.DetailRevoked {
		t.Errorf("inspect %+v", in.Decision)
	}
	// A stale manifest is handed over as its revocations only: no pins of
	// its own, so the compiled pins stay in force for everything else.
	e = f.env(&extruntest.Executor{}, &memState{})
	e.Manifest = &secengine.ManifestPins{Revoked: []string{pin.SHA256}}
	if res, _, _ := New(e).ScanFiles(context.Background(), full()); res.Coverage.Reason != secengine.ReasonUnverified {
		t.Fatalf("a stale manifest's revocation: %+v", res.Coverage)
	}
}
