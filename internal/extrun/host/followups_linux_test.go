//go:build linux

package host

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
)

// withLauncherSource swaps the cgroup-source table for one row that makes
// the run's cgroup under parent (as the configured source does) and puts
// launcher in front of the trampoline, the shape of the systemd scope rung.
// Not parallel: it changes a package var and restores it before returning.
func withLauncherSource(t *testing.T, parent string, launcher ...string) *Executor {
	t.Helper()
	saved := cgroupSources
	cgroupSources = []cgroupSource{{
		name:      extrun.CgroupSourceUserScope,
		available: func(*Executor) bool { return true },
		setup: func(e *Executor, p extrun.Plan) (rungSetup, error) {
			s, err := setupConfigured(e, p)
			s.launcher = launcher
			return s, err
		},
	}}
	t.Cleanup(func() { cgroupSources = saved })
	return &Executor{DrainTimeout: 300 * time.Millisecond, CgroupParent: parent}
}

// TestSelfPathBehindALauncherIsResolved: started directly the trampoline is
// /proc/self/exe; behind a launcher that link would name the launcher, so
// the resolved executable is used (P-018 item a).
func TestSelfPathBehindALauncherIsResolved(t *testing.T) {
	t.Parallel()
	if got, err := selfPath(false); err != nil || got != "/proc/self/exe" {
		t.Fatalf("direct: %q %v", got, err)
	}
	want, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	want, _ = filepath.EvalSymlinks(want)
	got, err := selfPath(true)
	if err != nil || got != want || strings.HasPrefix(got, "/proc/") {
		t.Fatalf("via launcher: %q %v, want %q", got, err, want)
	}
}

// TestLauncherInFrontStartsTheTrampoline: with a launcher that execs its
// argument in its own process (env does, as systemd-run --scope does), the
// trampoline still starts and the program runs on the cgroup rung.
func TestLauncherInFrontStartsTheTrampoline(t *testing.T) {
	parent := writableCgroup2Parent(t)
	env := "/usr/bin/env"
	if _, err := os.Stat(env); err != nil {
		t.Skip("no /usr/bin/env")
	}
	e := withLauncherSource(t, parent, env)
	res := NewRunner(Options{Executor: e}).Run(context.Background(), helperRequest(t, "exit", "0"))
	if res.Outcome != extrun.OutcomeOK || res.Containment.Rung != extrun.RungCgroup || !res.Trampoline {
		t.Fatalf("outcome %s rung %s skipped %+v (%s)", res.Outcome, res.Containment.Rung, res.Containment.Skipped, res.Detail)
	}
}

// hungLauncher is a launcher that never starts the trampoline.
var hungLauncher = []string{"/bin/sh", "-c", "sleep 30", "--"}

// TestHungRungSpendsTheRunsOwnWallTime: one wall deadline is taken at the
// start of Exec; a rung that hangs in its ready wait ends the run as a
// timeout at that deadline instead of falling through and starting the wall
// cap again on the next rung (P-018 item b).
func TestHungRungSpendsTheRunsOwnWallTime(t *testing.T) {
	parent := writableCgroup2Parent(t)
	e := withLauncherSource(t, parent, hungLauncher...)
	req := helperRequest(t, "sleep")
	req.Limits.Wall = 800 * time.Millisecond
	began := time.Now()
	res := NewRunner(Options{Executor: e}).Run(context.Background(), req)
	took := time.Since(began)
	if res.Outcome != extrun.OutcomeTimeout {
		t.Fatalf("outcome %s rung %s skipped %+v (%s)", res.Outcome, res.Containment.Rung, res.Containment.Skipped, res.Detail)
	}
	if res.Containment.Rung != extrun.RungCgroup || len(res.Containment.Skipped) != 0 {
		t.Fatalf("the hung rung fell through: %+v", res.Containment)
	}
	if took > 1600*time.Millisecond {
		t.Fatalf("the run took %s against a %s wall cap", took, req.Limits.Wall)
	}
}

// TestCancelDuringTheReadyWaitIsCanceled: a context cancelled while a rung
// waits for the trampoline ends the run as canceled, never as a start
// failure that goes on to the next rungs (P-018 item c).
func TestCancelDuringTheReadyWaitIsCanceled(t *testing.T) {
	parent := writableCgroup2Parent(t)
	e := withLauncherSource(t, parent, hungLauncher...)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	res := NewRunner(Options{Executor: e}).Run(ctx, helperRequest(t, "sleep"))
	if res.Outcome != extrun.OutcomeCanceled || len(res.Containment.Skipped) != 0 {
		t.Fatalf("outcome %s containment %+v (%s)", res.Outcome, res.Containment, res.Detail)
	}
}

// TestChildrenCapBelowTheTrampolineFailsTheRun: a children cap the
// trampoline could not start under is a failed run with a plain sentence,
// never a silent drop to the not-contained rung (P-018 item e).
func TestChildrenCapBelowTheTrampolineFailsTheRun(t *testing.T) {
	t.Parallel()
	parent := writableCgroup2Parent(t)
	r := NewRunner(Options{Executor: &Executor{DrainTimeout: 300 * time.Millisecond, CgroupParent: parent, NoSystemdScope: true}})
	req := helperRequest(t, "exit", "0")
	req.Limits.Children = 4
	res := r.Run(context.Background(), req)
	if res.Outcome != extrun.OutcomeStartFailed || !strings.Contains(res.Detail, "below the 16 tasks") {
		t.Fatalf("outcome %s rung %s (%s)", res.Outcome, res.Containment.Rung, res.Detail)
	}
}

// TestSilentTrampolineDeathUnderAChildrenCapIsNotRetried: a trampoline
// that started (its first status word arrived) and then died without
// another on the cgroup rung while a children cap is set may have hit
// pids.max; the run fails instead of being retried without the cap.
func TestSilentTrampolineDeathUnderAChildrenCapIsNotRetried(t *testing.T) {
	parent := writableCgroup2Parent(t)
	e := withLauncherSource(t, parent, "/usr/bin/env", trampolineDieEnv+"=1")
	req := helperRequest(t, "exit", "0")
	req.Limits.Children = 64
	res := NewRunner(Options{Executor: e}).Run(context.Background(), req)
	if res.Outcome != extrun.OutcomeStartFailed || len(res.Containment.Skipped) != 0 || !strings.Contains(res.Detail, "not retried without the cap") {
		t.Fatalf("outcome %s containment %+v (%s)", res.Outcome, res.Containment, res.Detail)
	}
	// Without a children cap the same failure falls through, as before.
	req.Limits.Children = 0
	res = NewRunner(Options{Executor: e}).Run(context.Background(), req)
	if res.Outcome != extrun.OutcomeOK || res.Containment.Rung == extrun.RungCgroup || len(res.Containment.Skipped) == 0 {
		t.Fatalf("no cap: outcome %s containment %+v (%s)", res.Outcome, res.Containment, res.Detail)
	}
}

// TestLauncherFailureUnderAChildrenCapFallsThrough: a launcher that exits
// with its own stderr before the trampoline ran (a systemd scope that
// cannot start) is a rung error even under a cap at or above the
// trampoline floor: the run goes on to the next rung, and the skipped rung
// carries the launcher's own words (decision log P-023).
func TestLauncherFailureUnderAChildrenCapFallsThrough(t *testing.T) {
	parent := writableCgroup2Parent(t)
	e := withLauncherSource(t, parent, "/bin/sh", "-c", "echo 'Failed to start transient scope unit: Access denied' >&2; exit 1", "--")
	for _, children := range []int{trampolineMinTasks, 64} {
		req := helperRequest(t, "exit", "0")
		req.Limits.Children = children
		res := NewRunner(Options{Executor: e}).Run(context.Background(), req)
		if res.Outcome != extrun.OutcomeOK || res.Containment.Rung == extrun.RungCgroup {
			t.Fatalf("cap %d: outcome %s containment %+v (%s)", children, res.Outcome, res.Containment, res.Detail)
		}
		var said bool
		for _, s := range res.Containment.Skipped {
			said = said || (s.Rung == extrun.RungCgroup && strings.Contains(s.Reason, "Failed to start transient scope unit"))
		}
		if !said {
			t.Fatalf("cap %d: the skipped cgroup rung does not carry the launcher's words: %+v", children, res.Containment.Skipped)
		}
	}
}

func TestChildrenBelowTrampolineTable(t *testing.T) {
	t.Parallel()
	cg := extrun.ContainmentFacts{Cgroup: true, ProcessGroup: true}
	cases := []struct {
		name     string
		cf       extrun.ContainmentFacts
		tramp    bool
		children int
		refused  bool
	}{
		{"cgroup rung, cap below the floor", cg, true, 15, true},
		{"cgroup rung, cap at the floor", cg, true, 16, false},
		{"no cap", cg, true, 0, false},
		{"no trampoline: no cgroup rung", cg, false, 4, false},
		{"no cgroup: the poll counts processes", extrun.ContainmentFacts{ProcessGroup: true}, true, 4, false},
		{"a job object counts processes", extrun.ContainmentFacts{JobObject: true, Cgroup: true}, true, 4, false},
	}
	for _, tc := range cases {
		if got := childrenBelowTrampoline(tc.cf, tc.tramp, tc.children) != ""; got != tc.refused {
			t.Errorf("%s: refused %v, want %v", tc.name, got, tc.refused)
		}
	}
}

// TestNotContainedLabelSaysWhatWasDone: on the process-group rung the
// label claims a sweep only when the supervisor ran it (P-018 item d).
func TestNotContainedLabelSaysWhatWasDone(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		e      *Executor
		label  string
		superv bool
	}{
		{"supervisor", &Executor{DrainTimeout: 300 * time.Millisecond, NoSystemdScope: true}, "not contained (process group kill and subreaper sweep)", true},
		{"no trampoline", &Executor{DrainTimeout: 300 * time.Millisecond, NoSystemdScope: true, NoTrampoline: true}, "not contained (process group kill only, no sweep)", false},
	} {
		res := NewRunner(Options{Executor: tc.e}).Run(context.Background(), helperRequest(t, "exit", "0"))
		c := res.Containment
		if res.Outcome != extrun.OutcomeOK || c.Rung != extrun.RungProcessGroup || c.Label != tc.label || c.Supervised != tc.superv {
			t.Errorf("%s: outcome %s containment %+v", tc.name, res.Outcome, c)
		}
	}
}

// TestSurvivorsAreCountedAfterTheCgroupEmptied: a setsid grandchild killed
// by the cgroup kill is swept, never counted as a survivor (P-018 item f).
func TestSurvivorsAreCountedAfterTheCgroupEmptied(t *testing.T) {
	parent := writableCgroup2Parent(t)
	r := NewRunner(Options{Executor: &Executor{DrainTimeout: 300 * time.Millisecond, CgroupParent: parent, NoSystemdScope: true}})
	for i := 0; i < 3; i++ {
		res := r.Run(context.Background(), helperRequest(t, "escape"))
		pid := firstPid(t, res.Stdout)
		t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
		if res.Containment.Rung != extrun.RungCgroup || res.Containment.Survivors != 0 {
			t.Fatalf("run %d: containment %+v", i, res.Containment)
		}
	}
	var _ settler = cgroupGroup{}
}
