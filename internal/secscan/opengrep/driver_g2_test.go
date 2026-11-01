package opengrep

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/extrun/extruntest"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// guided is where the guided install puts the engine in these tests.
const guided = "/home/u/.cache/sbo/scanners/opengrep/bin/opengrep"

// TestGuidedInstallIsUsedBeforeThePath: the guided install's binary runs
// even when another Opengrep is on the PATH, and is decided by its digest.
func TestGuidedInstallIsUsedBeforeThePath(t *testing.T) {
	f := newFake(t)
	pin, _ := secengine.CompiledPin("linux", "amd64")
	f.files[bin] = extruntest.File{Digest: "f00d"} // an unpinned PATH copy
	f.files[guided] = extruntest.File{Digest: pin.SHA256}
	ex := &extruntest.Executor{}
	env := f.env(ex, &memState{})
	env.Installed = guided
	res, _, err := New(env).ScanFiles(context.Background(), full())
	if err != nil {
		t.Fatal(err)
	}
	if res.Coverage.Outcome != secscan.OutcomeFindings || hasNote(res.Coverage.Notes, UnverifiedPrefix) {
		t.Fatalf("coverage %+v", res.Coverage)
	}
	for _, c := range ex.Calls() {
		if c.Path == bin {
			t.Fatalf("the PATH copy ran: %+v", c)
		}
	}
	// A symlink at the install path is not used.
	f.files[guided] = extruntest.File{LinkTo: bin}
	if got := New(env).installedBinary(); got != "" {
		t.Fatalf("a symlinked install was used: %q", got)
	}
	// Nothing there: the PATH copy is resolved as before.
	delete(f.files, guided)
	if got := New(env).installedBinary(); got != "" {
		t.Fatalf("a missing install was used: %q", got)
	}
}

func TestModeForRows(t *testing.T) {
	base := "c3fef7c"
	cases := []struct {
		name string
		t    secscan.Target
		mode Mode
		why  string
	}{
		{"manual is full", secscan.Target{Scope: policy.FindingScopeManual}, ModeFull, ""},
		{"scheduled is full", secscan.Target{Scope: policy.FindingScopeScheduled}, ModeFull, ""},
		{"diff with a base", secscan.Target{Scope: policy.FindingScopeDiff, BaseRev: base}, ModeDiff, ""},
		{"diff with a flag base", secscan.Target{Scope: policy.FindingScopeDiff, BaseRev: "--x"}, ModeDiff, ReasonBadBase},
		{"commit with a base is a diff", secscan.Target{Scope: policy.FindingScopeCommit, BaseRev: base}, ModeDiff, ""},
		{"commit without a base is full", secscan.Target{Scope: policy.FindingScopeCommit}, ModeFull, ""},
		{"post-write with paths", secscan.Target{Scope: policy.FindingScopePostWrite, Paths: []string{"a.py", "src/b.go"}}, ModeFiles, ""},
		{"post-write with no paths", secscan.Target{Scope: policy.FindingScopePostWrite}, ModeFiles, ReasonBadPaths},
		{"post-write with a flag path", secscan.Target{Scope: policy.FindingScopePostWrite, Paths: []string{"-x"}}, ModeFiles, ReasonBadPaths},
		{"post-write escaping the project", secscan.Target{Scope: policy.FindingScopePostWrite, Paths: []string{"../etc/passwd"}}, ModeFiles, ReasonBadPaths},
		{"post-write absolute", secscan.Target{Scope: policy.FindingScopePostWrite, Paths: []string{"/etc/passwd"}}, ModeFiles, ReasonBadPaths},
	}
	for _, c := range cases {
		m, why := ModeFor(c.t)
		if m != c.mode || why != c.why {
			t.Errorf("%s: %s %q", c.name, m, why)
		}
	}
	many := make([]string, MaxFiles+1)
	for i := range many {
		many[i] = "f" + strings.Repeat("x", i%7) + ".py"
	}
	if ValidPaths(many) {
		t.Error("more than MaxFiles paths passed")
	}
}

// TestFilesModeScansOnlyTheWrittenFiles: the post-write run passes each
// file as ./path, carries the canary, and its read files can close.
func TestFilesModeScansOnlyTheWrittenFiles(t *testing.T) {
	f := newFake(t)
	f.scanned = []string{"b.py"}
	ex := &extruntest.Executor{}
	tgt := secscan.Target{ProjectRoot: root, Scope: policy.FindingScopePostWrite, Paths: []string{"b.py"}}
	res, scanned, err := New(f.env(ex, &memState{})).ScanFiles(context.Background(), tgt)
	if err != nil {
		t.Fatal(err)
	}
	if res.Coverage.Outcome != secscan.OutcomeFindings || strings.Join(scanned.Files, ",") != "b.py" {
		t.Fatalf("coverage %+v scanned %+v", res.Coverage, scanned)
	}
	scan := ex.Calls()[len(ex.Calls())-1]
	if !slices.Contains(scan.Args, "./b.py") || !slices.Contains(scan.Args, canaryPath) || slices.Contains(scan.Args, ".") {
		t.Fatalf("args %v", scan.Args)
	}
	if scan.Limits.Wall != 120*time.Second {
		t.Errorf("wall %v", scan.Limits.Wall)
	}
	if res.Findings[0].Scope != policy.FindingScopePostWrite {
		t.Errorf("finding scope %s", res.Findings[0].Scope)
	}
}

// TestCommitScopeRunsAsADiff: a commit-scoped target with a base is a
// --baseline-commit run whose findings carry the commit scope and which
// closes nothing.
func TestCommitScopeRunsAsADiff(t *testing.T) {
	f := newFake(t)
	ex := &extruntest.Executor{}
	tgt := secscan.Target{ProjectRoot: root, Scope: policy.FindingScopeCommit, BaseRev: "c3fef7c"}
	res, scanned, err := New(f.env(ex, &memState{})).ScanFiles(context.Background(), tgt)
	if err != nil {
		t.Fatal(err)
	}
	var diffRun bool
	for _, c := range ex.Calls() {
		if slices.Contains(c.Args, "--baseline-commit") {
			diffRun = true
		}
	}
	if !diffRun || len(scanned.Files) != 0 {
		t.Fatalf("not a diff run, or it closes files: %v %+v", diffRun, scanned)
	}
	for _, fd := range res.Findings {
		if fd.Scope != policy.FindingScopeCommit {
			t.Errorf("finding scope %s", fd.Scope)
		}
	}
}

func TestDebouncer(t *testing.T) {
	var d Debouncer
	t0 := time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)
	d.Add("/p", "a.py", t0)
	d.Add("/p", "b.py", t0.Add(10*time.Second))
	d.Add("/p", "../x", t0) // refused
	d.Add("/q", "c.go", t0)
	if got := d.Due(t0.Add(20 * time.Second)); len(got) != 0 {
		t.Fatalf("due before the quiet window: %+v", got)
	}
	got := d.Due(t0.Add(41 * time.Second))
	if len(got) != 2 || got[0].Root != "/p" || strings.Join(got[0].Paths, ",") != "a.py,b.py" || got[1].Root != "/q" {
		t.Fatalf("due %+v", got)
	}
	if d.Pending() != 0 {
		t.Fatal("a due batch was not removed")
	}
	// A project written to all the time is still scanned by the max delay.
	for i := 0; i < 20; i++ {
		d.Add("/busy", "f.py", t0.Add(time.Duration(i)*20*time.Second))
	}
	if got := d.Due(t0.Add(6*time.Minute + 19*time.Second)); len(got) != 1 {
		t.Fatalf("a busy project was never scanned: %+v", got)
	}
	// A requeued batch is due at the next pass.
	d.Requeue(Batch{Root: "/r", Paths: []string{"z.py"}}, t0)
	if got := d.Due(t0); len(got) != 1 || got[0].Root != "/r" {
		t.Fatalf("requeue %+v", got)
	}
	// Over MaxFiles: the newest MaxFiles, the rest counted.
	for i := 0; i < MaxFiles+5; i++ {
		d.Add("/big", fmt.Sprintf("f%03d.py", i), t0.Add(time.Duration(i)*time.Millisecond))
	}
	got = d.Due(t0.Add(time.Hour))
	if len(got) != 1 || len(got[0].Paths) != MaxFiles || got[0].Dropped != 5 || slices.Contains(got[0].Paths, "f000.py") {
		t.Fatalf("over the cap: %d paths, %d dropped", len(got[0].Paths), got[0].Dropped)
	}
}

func TestScheduleAndHeadRules(t *testing.T) {
	now := time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		last  time.Time
		every time.Duration
		want  bool
	}{
		{time.Time{}, 0, false},
		{time.Time{}, 24 * time.Hour, true},
		{now.Add(-23 * time.Hour), 24 * time.Hour, false},
		{now.Add(-24 * time.Hour), 24 * time.Hour, true},
		{now.Add(-100 * time.Hour), 168 * time.Hour, false},
	} {
		if got := ScheduleDue(c.last, c.every, now); got != c.want {
			t.Errorf("ScheduleDue(%v, %v) = %v", c.last, c.every, got)
		}
	}
	a, b := "aaaaaaa1", "bbbbbbb2"
	for _, c := range []struct {
		prev, cur string
		want      HeadStep
	}{
		{"", a, HeadRemember},
		{a, a, HeadNone},
		{a, b, HeadScan},
		{a, "", HeadUnreadable},
		{a, "HEAD", HeadUnreadable},
	} {
		if got := HeadRule(c.prev, c.cur); got != c.want {
			t.Errorf("HeadRule(%q, %q) = %s", c.prev, c.cur, got)
		}
	}
}

// TestLinkedWorktreeIsolatedBindsTheMainGitReadOnly: an isolated run of a
// linked worktree hands the provider the main repository's git directory
// as a read-only program directory; a run of the main checkout does not.
func TestLinkedWorktreeIsolatedBindsTheMainGitReadOnly(t *testing.T) {
	const checkout = "/home/u/wt/feature"
	const common = root + "/.git"
	for _, c := range []struct {
		name   string
		target secscan.Target
		want   bool
	}{
		{"linked worktree", secscan.Target{ProjectRoot: root, CheckoutRoot: checkout, Scope: policy.FindingScopeManual}, true},
		{"main checkout", full(), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t)
			ex := &extruntest.Executor{}
			env := f.env(ex, &memState{})
			var got []extrun.OneShotDirs
			env.Isolate = func(d extrun.OneShotDirs) (extrun.IsolationProvider, error) {
				got = append(got, d)
				return nil, nil // no provider: the run goes on unisolated
			}
			env.IsolatedRunner = func(extrun.IsolationProvider) *extrun.Runner { return env.Runner }
			env.LinkedCommonDir = func(dir string) string {
				if dir == checkout {
					return common
				}
				return ""
			}
			if _, _, err := New(env).ScanFiles(context.Background(), c.target); err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 {
				t.Fatalf("isolate calls %d", len(got))
			}
			if has := slices.Contains(got[0].ProgramDirs, common); has != c.want || !slices.Contains(got[0].ProgramDirs, packDir) {
				t.Fatalf("program dirs %v", got[0].ProgramDirs)
			}
		})
	}
}
