//go:build linux

package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
)

// testRunner is the production runner with short drain and poll times.
func testRunner() *extrun.Runner {
	return NewRunner(Options{Executor: &Executor{DrainTimeout: 300 * time.Millisecond, PollInterval: 20 * time.Millisecond}})
}

// waitForFile returns once path exists, ctx ends or max passes.
func waitForFile(ctx context.Context, path string, max time.Duration) {
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// helperRequest runs this test binary as the helper with args.
func helperRequest(t *testing.T, args ...string) extrun.Request {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return extrun.Request{
		Component: "core",
		Program:   extrun.Program{Path: self},
		Args:      args,
		Env:       extrun.EnvSpec{Set: []string{helperEnv}},
		Dir:       t.TempDir(),
		Limits:    extrun.Limits{Wall: 20 * time.Second},
	}
}

// gone reports whether pid has exited (no process, or a zombie no one has
// reaped yet), waiting up to two seconds.
func gone(pid int) bool {
	// Generous for a loaded machine; a dead process returns at once.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return true
		}
		if data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat")); err == nil {
			if _, state, ok := parseStat(data); ok && (state == 'Z' || state == 'X') {
				return true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// firstPid reads the pid the helper printed on its first line.
func firstPid(t *testing.T, out []byte) int {
	t.Helper()
	line, _, _ := strings.Cut(string(out), "\n")
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || pid <= 0 {
		t.Fatalf("no pid in helper output %q", out)
	}
	return pid
}

func TestExecExitCodeAndStdin(t *testing.T) {
	t.Parallel()
	r := testRunner()
	res := r.Run(context.Background(), helperRequest(t, "exit", "3"))
	if res.Outcome != extrun.OutcomeExitNonZero || res.ExitCode != 3 {
		t.Fatalf("exit 3: %s code %d (%s)", res.Outcome, res.ExitCode, res.Detail)
	}
	req := helperRequest(t, "cat")
	req.Stdin = []byte("hello from stdin")
	res = r.Run(context.Background(), req)
	if res.Outcome != extrun.OutcomeOK || string(res.Stdout) != "hello from stdin" {
		t.Fatalf("cat: %s %q", res.Outcome, res.Stdout)
	}
	if res.Digests.Binary == "" || res.Path == "" {
		t.Fatalf("no digest recorded: %+v", res)
	}
}

func TestExecMinimalEnvironment(t *testing.T) {
	// Not parallel: it sets variables in this process's environment to prove
	// they do not leak into the program.
	t.Setenv("EXTRUN_SHOULD_NOT_LEAK", "leak")
	t.Setenv("ANTHROPIC_API_KEY", "sk-test-not-real")
	t.Setenv("EXTRUN_NAMED", "named-value")
	req := helperRequest(t, "env")
	req.Env.Inherit = []string{"EXTRUN_NAMED"}
	req.Env.PathDirs = []string{"/usr/bin"}
	res := testRunner().Run(context.Background(), req)
	if res.Outcome != extrun.OutcomeOK {
		t.Fatalf("env: %s (%s)", res.Outcome, res.Detail)
	}
	got := strings.Fields(string(res.Stdout))
	want := []string{"EXTRUN_HELPER=1", "EXTRUN_NAMED=named-value", "PATH=/usr/bin"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("the program saw %q, want exactly %q", got, want)
	}

	req.Env.Inherit = []string{"ANTHROPIC_API_KEY"}
	if res := testRunner().Run(context.Background(), req); res.Reason != extrun.RefuseEnv {
		t.Fatalf("inheriting a provider key: %s/%s", res.Outcome, res.Reason)
	}
}

func TestExecTimeoutKillsTheGroup(t *testing.T) {
	t.Parallel()
	req := helperRequest(t, "grandchild")
	req.Limits.Wall = time.Second
	start := time.Now()
	res := testRunner().Run(context.Background(), req)
	if res.Outcome != extrun.OutcomeTimeout {
		t.Fatalf("outcome %s (%s)", res.Outcome, res.Detail)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("the timeout took %s", took)
	}
	pid := firstPid(t, res.Stdout)
	if !gone(pid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("grandchild %d outlived the group kill", pid)
	}
	if res.Leftover {
		t.Fatal("a run whose group was killed reports a leftover")
	}
}

// TestExecCancelKillsTheGroup: a cancel kills the program and its
// grandchild. The cancel waits until the helper has started the grandchild
// (its pid file), not a fixed delay, so a loaded machine that starts the
// helper slowly cannot cancel it before there is a grandchild to kill.
func TestExecCancelKillsTheGroup(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := helperRequest(t, "grandchild")
	go func() {
		waitForFile(ctx, filepath.Join(req.Dir, helperPidFile), 15*time.Second)
		cancel()
	}()
	res := testRunner().Run(ctx, req)
	if res.Outcome != extrun.OutcomeCanceled {
		t.Fatalf("outcome %s (%s)", res.Outcome, res.Detail)
	}
	if pid := firstPid(t, res.Stdout); !gone(pid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("grandchild %d outlived the cancel", pid)
	}
}

func TestExecNormalExitStillKillsBackgroundChildren(t *testing.T) {
	t.Parallel()
	start := time.Now()
	res := testRunner().Run(context.Background(), helperRequest(t, "background"))
	if res.Outcome != extrun.OutcomeOK {
		t.Fatalf("outcome %s (%s)", res.Outcome, res.Detail)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("a background child held the run open for %s", took)
	}
	if pid := firstPid(t, res.Stdout); !gone(pid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("background child %d outlived the run", pid)
	}
	if res.Leftover {
		t.Fatal("leftover reported for a child inside the group")
	}
}

// TestExecSessionEscapeIsSwept: a grandchild that leaves the process group
// with setsid is still ended. Under the cgroup rung it is in the run's
// cgroup; under the process-group rung it is re-parented to the supervisor
// (the child subreaper), which sweeps it when the program exits.
func TestExecSessionEscapeIsSwept(t *testing.T) {
	t.Parallel()
	res := testRunner().Run(context.Background(), helperRequest(t, "escape"))
	pid := firstPid(t, res.Stdout)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	if res.Outcome != extrun.OutcomeOK {
		t.Fatalf("outcome %s (%s)", res.Outcome, res.Detail)
	}
	if !gone(pid) {
		t.Fatalf("the setsid grandchild %d outlived the run (rung %s)", pid, res.Containment.Rung)
	}
	if res.Leftover {
		t.Fatalf("leftover reported although the grandchild was swept (rung %s)", res.Containment.Rung)
	}
	if res.Containment.Rung == extrun.RungProcessGroup && res.Containment.Swept < 1 {
		t.Fatalf("the supervisor swept nothing: %+v", res.Containment)
	}
}

// TestExecSessionEscapeWithoutTrampolineIsReported: with no trampoline
// there is no supervisor and no cgroup, so the documented residual stays: a
// process that leaves the group with setsid is not killed, and the run says
// so twice, as a leftover (it holds the pipe) and as a survivor (found by
// executable identity).
func TestExecSessionEscapeWithoutTrampolineIsReported(t *testing.T) {
	t.Parallel()
	r := NewRunner(Options{Executor: &Executor{DrainTimeout: 300 * time.Millisecond, NoTrampoline: true}})
	res := r.Run(context.Background(), helperRequest(t, "escape"))
	pid := firstPid(t, res.Stdout)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	if res.Outcome != extrun.OutcomeOK {
		t.Fatalf("outcome %s (%s)", res.Outcome, res.Detail)
	}
	if !res.Leftover {
		t.Fatal("a child that escaped the group with setsid was not reported")
	}
	if res.Containment.Survivors < 1 {
		t.Fatalf("the escaped grandchild was not found by executable identity: %+v", res.Containment)
	}
	if res.Containment.Contained || res.Containment.Rung != extrun.RungProcessGroup {
		t.Fatalf("containment %+v, want the not-contained process group", res.Containment)
	}
}

func TestExecOutputCap(t *testing.T) {
	t.Parallel()
	req := helperRequest(t, "flood")
	req.Limits.StdoutBytes = 100 << 10
	res := testRunner().Run(context.Background(), req)
	if res.Outcome != extrun.OutcomeOutputCap {
		t.Fatalf("outcome %s (%s)", res.Outcome, res.Detail)
	}
	if len(res.Stdout) != 100<<10 || !res.StdoutTruncated || res.StderrTruncated {
		t.Fatalf("kept %d bytes, truncated %v/%v", len(res.Stdout), res.StdoutTruncated, res.StderrTruncated)
	}
	if !bytes.Equal(res.Stdout[:10], make([]byte, 10)) {
		t.Fatal("kept bytes are not the program's output")
	}
}

// spawnSleepArg names a helper behaviour this file adds beside the shared
// helper in main_test.go: start N /bin/sleep children, one task each, and
// report the first start the kernel refuses.
const spawnSleepArg = "spawnsleep"

// init runs the spawnsleep behaviour before TestMain when this binary is
// started as the helper with it (the trampoline's own start carries neither
// the helper marker nor the argument, so it is never caught here). The
// children are single-threaded, so each start adds exactly one task and a
// pids.max refusal is deterministic: a Go child would die of a refused
// thread, free its tasks and let the next start succeed.
func init() {
	if os.Getenv("EXTRUN_HELPER") != "1" || len(os.Args) < 3 || os.Args[1] != spawnSleepArg {
		return
	}
	os.Exit(spawnSleep(os.Args[2]))
}

// spawnSleep starts n sleeping children and then sleeps itself. A refused
// start prints "spawn refused after <i>" and exits 103.
func spawnSleep(arg string) int {
	n, err := strconv.Atoi(arg)
	if err != nil || n <= 0 {
		return 104
	}
	for i := 0; i < n; i++ {
		c := exec.Command("/bin/sleep", "3600")
		c.Env = []string{}
		if err := c.Start(); err != nil {
			fmt.Printf("spawn refused after %d: %v\n", i, err)
			return 103
		}
	}
	time.Sleep(time.Hour)
	return 0
}

// TestExecChildrenCap: the child-process cap is held by whatever this
// host's rung offers, and the record names it. A probe under a cap the
// trampoline can start with shows the rung, and its Containment decides
// which rows apply. Where the run's cgroup holds the cap (pids.max, in
// tasks), a cap below the trampoline's floor fails the run (decision log
// P-018 item e) and the kernel refuses the starts past a cap at or above
// it. Where no cgroup holds it, the cap is counted by polling (in
// processes) and passing it kills the run; that row also runs on every host
// through an executor with no cgroup source.
func TestExecChildrenCap(t *testing.T) {
	t.Parallel()
	// Above the trampoline's floor with room for the race detector's
	// threads, and half of what the spawnsleep row starts.
	const capAboveFloor = 32
	probe := helperRequest(t, "exit", "0")
	probe.Limits.Children = capAboveFloor
	pr := testRunner().Run(context.Background(), probe)
	if pr.Outcome != extrun.OutcomeOK {
		t.Fatalf("probe: outcome %s (%s)", pr.Outcome, pr.Detail)
	}
	onCgroup := pr.Containment.Rung == extrun.RungCgroup && pr.Containment.Contained
	if onCgroup && pr.Containment.CgroupSource == "" {
		t.Fatalf("probe: a cgroup run names no cgroup source: %+v", pr.Containment)
	}
	// The floor refusal is decided before the start, from the facts that
	// put the cgroup rung first, so it also applies where that rung was
	// tried and fell through.
	cgroupFirst := onCgroup
	for _, s := range pr.Containment.Skipped {
		cgroupFirst = cgroupFirst || s.Rung == extrun.RungCgroup
	}
	noCgroup := NewRunner(Options{Executor: &Executor{DrainTimeout: 300 * time.Millisecond, PollInterval: 20 * time.Millisecond, NoSystemdScope: true}})

	// polled checks a run whose cap was counted by polling: it passed the
	// cap before the kill, on a rung other than the cgroup. The cap counts
	// the program too (extrun.Limits.Children), so with the polled rows'
	// cap of 2 a peak of 2 children beside the program is already 3
	// processes, past the cap (a loaded host can stop the run right there).
	const polledCap = 2
	polled := func(t *testing.T, res extrun.Result) {
		if res.PeakChildren+1 <= polledCap {
			t.Fatalf("peak %d children beside the program does not show the cap of %d was passed", res.PeakChildren, polledCap)
		}
		if res.Containment.Rung == extrun.RungCgroup {
			t.Fatalf("a polled cap on the cgroup rung: %+v", res.Containment)
		}
	}
	// refused checks a run the kernel stopped at pids.max: a start was
	// refused (or the helper's runtime could not get a thread, which the
	// same cap causes), and no more processes than tasks ever ran.
	refused := func(t *testing.T, res extrun.Result) {
		out, errOut := string(res.Stdout), string(res.Stderr)
		if !(res.ExitCode == 103 && strings.Contains(out, "spawn refused after")) && !strings.Contains(errOut, "failed to create new OS thread") {
			t.Fatalf("no refused start: exit %d stdout %q stderr %q", res.ExitCode, out, firstLine(res.Stderr))
		}
		t.Logf("refused: exit %d, %s", res.ExitCode, firstLine(append(res.Stdout, res.Stderr...)))
		if res.PeakChildren+1 > capAboveFloor {
			t.Fatalf("peak %d processes beside the program under a cap of %d tasks", res.PeakChildren, capAboveFloor)
		}
		if res.Containment.Rung != extrun.RungCgroup || !res.Containment.Contained {
			t.Fatalf("containment %+v, want the cgroup rung", res.Containment)
		}
	}
	cases := []struct {
		name     string
		runner   *extrun.Runner
		applies  bool
		args     []string
		children int
		wall     time.Duration
		want     extrun.Outcome
		// detail is a phrase the run's Detail must carry, or "".
		detail string
		// state, mech and unit are the children row's, or "" when the row
		// has no cap row to check (a run that never started).
		state extrun.CapState
		mech  string
		unit  string
		check func(*testing.T, extrun.Result)
	}{
		{
			name: "no cgroup source: passing the polled cap kills the run", runner: noCgroup, applies: true,
			args: []string{"spawn", "6"}, children: polledCap, wall: 20 * time.Second, want: extrun.OutcomeChildrenCap,
			state: extrun.CapBestEffort, mech: extrun.MechPoll, unit: extrun.UnitProcesses, check: polled,
		},
		{
			name: "default rung without a cgroup: passing the polled cap kills the run", runner: testRunner(), applies: !cgroupFirst,
			args: []string{"spawn", "6"}, children: polledCap, wall: 20 * time.Second, want: extrun.OutcomeChildrenCap,
			state: extrun.CapBestEffort, mech: extrun.MechPoll, unit: extrun.UnitProcesses, check: polled,
		},
		{
			name: "cgroup rung: a cap below the trampoline's floor fails the run", runner: testRunner(), applies: cgroupFirst,
			args: []string{"exit", "0"}, children: 2, wall: 20 * time.Second, want: extrun.OutcomeStartFailed,
			detail: "the child-process cap of 2 tasks is below the 16 tasks the trampoline needs to start the program inside the run's cgroup",
		},
		{
			name: "cgroup rung: pids.max refuses the starts past the cap", runner: testRunner(), applies: onCgroup,
			args: []string{spawnSleepArg, strconv.Itoa(2 * capAboveFloor)}, children: capAboveFloor, wall: 10 * time.Second,
			want: extrun.OutcomeExitNonZero, state: extrun.CapEnforced, mech: extrun.MechCgroup, unit: extrun.UnitTasks, check: refused,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.applies {
				t.Skipf("not this host: the probe ran on rung %s (contained %v)", pr.Containment.Rung, pr.Containment.Contained)
			}
			req := helperRequest(t, tc.args...)
			req.Limits.Children = tc.children
			req.Limits.Wall = tc.wall
			res := tc.runner.Run(context.Background(), req)
			if res.Outcome != tc.want {
				t.Fatalf("outcome %s, want %s (%s), peak %d, containment %+v", res.Outcome, tc.want, res.Detail, res.PeakChildren, res.Containment)
			}
			if tc.detail != "" && !strings.Contains(res.Detail, tc.detail) {
				t.Fatalf("detail %q lacks %q", res.Detail, tc.detail)
			}
			if tc.state != "" {
				c := capOf(t, res, extrun.CapChildren)
				if c.State != tc.state || c.Mechanism != tc.mech || c.Unit != tc.unit || c.Limit != int64(tc.children) {
					t.Fatalf("children cap %+v, want %s by %s in %s with limit %d", c, tc.state, tc.mech, tc.unit, tc.children)
				}
			}
			if tc.check != nil {
				tc.check(t, res)
			}
		})
	}
}

// TestExecMemoryCap: a capped allocation fails where the same uncapped one
// succeeds, and the record names what held the cap on this run: a cgroup
// rung with the memory controller enforces it (memory.max with
// memory.swap.max = 0); otherwise RLIMIT_DATA holds it, best effort.
func TestExecMemoryCap(t *testing.T) {
	t.Parallel()
	req := helperRequest(t, "alloc", "512")
	req.Limits.MemoryBytes = 128 << 20
	res := testRunner().Run(context.Background(), req)
	if res.Outcome == extrun.OutcomeOK {
		t.Fatalf("a 512 MiB allocation passed a 128 MiB cap: %q", res.Stdout)
	}
	// The Go runtime reports a refused allocation in several ways (a fatal
	// "out of memory", or a crash inside the collector), and the cgroup's
	// OOM killer ends it with a signal, so the proof is the pair: this run
	// fails and the same run without the cap succeeds.
	cont := res.Containment
	holders := []struct {
		name  string
		when  bool
		state extrun.CapState
		mech  string
	}{
		{"cgroup memory controller", cont.Rung == extrun.RungCgroup && cont.Contained && slices.Contains(cont.Controllers, "memory"), extrun.CapEnforced, extrun.MechCgroup},
		{"RLIMIT_DATA", true, extrun.CapBestEffort, extrun.MechRlimitData},
	}
	for _, h := range holders {
		if !h.when {
			continue
		}
		if c := capOf(t, res, extrun.CapMemory); c.State != h.state || c.Mechanism != h.mech {
			t.Fatalf("memory cap %+v on rung %s (controllers %v), want %s by the %s", c, cont.Rung, cont.Controllers, h.state, h.name)
		}
		break
	}
	// The same allocation with no cap succeeds, so the cap is what stopped it.
	req.Limits.MemoryBytes = 0
	if res := testRunner().Run(context.Background(), req); res.Outcome != extrun.OutcomeOK {
		t.Fatalf("uncapped allocation: %s %q", res.Outcome, res.Stderr)
	}
}

func TestExecVersionProbe(t *testing.T) {
	t.Parallel()
	r := testRunner()
	req := helperRequest(t)
	req.Env.Set = append(req.Env.Set, "EXTRUN_VERSION=tool v4.5.6")
	// The helper's "env" behaviour prints EXTRUN_VERSION=tool v4.5.6.
	v, res := r.ProbeVersion(context.Background(), req, extrun.VersionProbe{Args: []string{"env"}})
	if v.Version != "4.5.6" || res.Outcome != extrun.OutcomeOK {
		t.Fatalf("probe = %+v %s", v, res.Outcome)
	}
	v, res = r.ProbeVersion(context.Background(), req, extrun.VersionProbe{Args: []string{"env"}})
	if !v.Cached || res.Outcome != extrun.OutcomeCached {
		t.Fatalf("second probe not cached: %+v %s", v, res.Outcome)
	}
}

// TestExecNeverSignalsAReapedLeader pins the kill ordering. The only raw
// kill(2) the executor sends is to the group (a negative id); the leader is
// signalled through its os.Process, and every leader signal sent after Wait
// has reaped it is refused with os.ErrProcessDone, so a pid recycled after
// the reap is never signalled. Not parallel: it swaps the package's kill
// seams (the parallel tests resume only after it has restored them).
func TestExecNeverSignalsAReapedLeader(t *testing.T) {
	var (
		mu     sync.Mutex
		raw    []int
		leader []error
	)
	origKill, origSignal := sysKill, signalLeader
	t.Cleanup(func() { sysKill, signalLeader = origKill, origSignal })
	sysKill = func(pid int, sig syscall.Signal) error {
		mu.Lock()
		raw = append(raw, pid)
		mu.Unlock()
		return origKill(pid, sig)
	}
	signalLeader = func(p *os.Process) error {
		err := origSignal(p)
		mu.Lock()
		leader = append(leader, err)
		mu.Unlock()
		return err
	}
	cases := []struct {
		name string
		args []string
		wall time.Duration
		want extrun.Outcome
		// afterWaitOnly: every kill of this run happens after Wait returned.
		afterWaitOnly bool
	}{
		{"normal exit", []string{"exit", "0"}, 20 * time.Second, extrun.OutcomeOK, true},
		{"timeout", []string{"grandchild"}, time.Second, extrun.OutcomeTimeout, false},
	}
	for _, tc := range cases {
		mu.Lock()
		raw, leader = nil, nil
		mu.Unlock()
		req := helperRequest(t, tc.args...)
		req.Limits.Wall = tc.wall
		res := testRunner().Run(context.Background(), req)
		if res.Outcome != tc.want {
			t.Fatalf("%s: outcome %s (%s)", tc.name, res.Outcome, res.Detail)
		}
		if tc.name == "timeout" {
			if pid := firstPid(t, res.Stdout); !gone(pid) {
				_ = syscall.Kill(pid, syscall.SIGKILL)
				t.Fatalf("%s: grandchild %d outlived the group kill", tc.name, pid)
			}
		}
		mu.Lock()
		gotRaw, gotLeader := append([]int(nil), raw...), append([]error(nil), leader...)
		mu.Unlock()
		if len(gotRaw) == 0 || len(gotLeader) == 0 {
			t.Fatalf("%s: no kill recorded (raw %v, leader %v)", tc.name, gotRaw, gotLeader)
		}
		for _, pid := range gotRaw {
			if pid >= 0 {
				t.Errorf("%s: raw kill(2) to pid %d: only the group (a negative id) may be killed by number", tc.name, pid)
			}
		}
		// The final kill always runs after Wait returned: os.Process refused it.
		if last := gotLeader[len(gotLeader)-1]; !errors.Is(last, os.ErrProcessDone) {
			t.Errorf("%s: the leader signal after Wait returned %v, want os.ErrProcessDone (nothing sent)", tc.name, last)
		}
		if tc.afterWaitOnly {
			for i, err := range gotLeader {
				if !errors.Is(err, os.ErrProcessDone) {
					t.Errorf("%s: leader signal %d after Wait returned %v, want os.ErrProcessDone", tc.name, i, err)
				}
			}
		}
	}
}

func TestParseStat(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in    string
		pgrp  int
		state byte
		ok    bool
		desc  string
	}{
		{"1234 (sleep) S 1 1234 1234 0 -1", 1234, 'S', true, "plain"},
		{"42 (a (weird) name) R 7 99 99 0", 99, 'R', true, "parentheses in comm"},
		{"42 (with space) Z 7 13 13", 13, 'Z', true, "zombie"},
		{"42 no parens", 0, 0, false, "no comm"},
		{"42 (x) S 7", 0, 0, false, "too short"},
		{"42 (x) S 7 notanumber", 0, 0, false, "bad pgrp"},
	}
	for _, tc := range cases {
		pgrp, state, ok := parseStat([]byte(tc.in))
		if pgrp != tc.pgrp || state != tc.state || ok != tc.ok {
			t.Errorf("%s: got %d %q %v", tc.desc, pgrp, state, ok)
		}
	}
}

// capOf returns the run record's row for one cap.
func capOf(t *testing.T, res extrun.Result, c extrun.Cap) extrun.CapResult {
	t.Helper()
	for _, r := range res.Caps {
		if r.Cap == c {
			return r
		}
	}
	t.Fatalf("no %s row in %+v", c, res.Caps)
	return extrun.CapResult{}
}

// TestTrampolineAppliesCapsBeforeExec: the program reads its own rlimits as
// its first act and already sees every cap, so they were set before exec
// (a prlimit after the start could not promise that).
func TestTrampolineAppliesCapsBeforeExec(t *testing.T) {
	t.Parallel()
	req := helperRequest(t, "limits")
	req.Limits.CPU = 1500 * time.Millisecond
	// A large memory cap: the race detector's own shadow mappings count
	// against RLIMIT_DATA, and the point here is only that the value is set.
	req.Limits.MemoryBytes = 1 << 40
	req.Limits.FileBytes = 1 << 20
	res := testRunner().Run(context.Background(), req)
	if res.Outcome != extrun.OutcomeOK || !res.Trampoline {
		t.Fatalf("outcome %s trampoline %v (%s) %q", res.Outcome, res.Trampoline, res.Detail, res.Stderr)
	}
	out := string(res.Stdout)
	for _, want := range []string{"cpu=2/2", "fsize=1048576/1048576"} {
		if !strings.Contains(out, want) {
			t.Errorf("program saw %q, want %s", out, want)
		}
	}
	mem := capOf(t, res, extrun.CapMemory)
	switch mem.Mechanism {
	case extrun.MechRlimitData:
		if !strings.Contains(out, "data=1099511627776/1099511627776") || mem.State != extrun.CapBestEffort {
			t.Errorf("RLIMIT_DATA run: program saw %q, cap %+v", out, mem)
		}
	case extrun.MechCgroup:
		if mem.State != extrun.CapEnforced {
			t.Errorf("cgroup memory cap %+v", mem)
		}
	default:
		t.Errorf("memory cap held by %q", mem.Mechanism)
	}
	if c := capOf(t, res, extrun.CapCPU); c.Mechanism != extrun.MechRlimitCPU || c.State != extrun.CapBestEffort || c.Limit != 2 {
		t.Errorf("cpu cap %+v", c)
	}
	if c := capOf(t, res, extrun.CapFileSize); c.Mechanism != extrun.MechRlimitFsize || c.State != extrun.CapEnforced {
		t.Errorf("file size cap %+v", c)
	}
}

// TestTrampolineNeverPassesItsMarker: the program sees exactly the plan's
// environment, not the trampoline's marker.
func TestTrampolineNeverPassesItsMarker(t *testing.T) {
	t.Parallel()
	res := testRunner().Run(context.Background(), helperRequest(t, "env"))
	if res.Outcome != extrun.OutcomeOK || !res.Trampoline {
		t.Fatalf("outcome %s (%s)", res.Outcome, res.Detail)
	}
	if strings.Contains(string(res.Stdout), trampolineEnv) {
		t.Fatalf("the program saw the trampoline marker: %q", res.Stdout)
	}
}

func TestCPUCapKills(t *testing.T) {
	t.Parallel()
	req := helperRequest(t, "spin")
	req.Limits.CPU = time.Second
	res := testRunner().Run(context.Background(), req)
	if res.Outcome != extrun.OutcomeSignaled || res.Duration > 15*time.Second {
		t.Fatalf("spinner with a 1 s CPU cap: %s after %v (%s)", res.Outcome, res.Duration, res.Detail)
	}
}

func TestFileSizeCap(t *testing.T) {
	t.Parallel()
	req := helperRequest(t, "bigfile", filepath.Join(t.TempDir(), "big"))
	req.Limits.FileBytes = 1 << 20
	res := testRunner().Run(context.Background(), req)
	if res.Outcome != extrun.OutcomeExitNonZero || !strings.Contains(string(res.Stdout), "write stopped at") {
		t.Fatalf("4 MiB write under a 1 MiB cap: %s %q", res.Outcome, res.Stdout)
	}
}

// TestNoTrampolineReportsPerProcessCapsNotEnforced: without the trampoline
// nothing sets an rlimit, and the record says so rather than claiming it.
func TestNoTrampolineReportsPerProcessCapsNotEnforced(t *testing.T) {
	t.Parallel()
	r := NewRunner(Options{Executor: &Executor{DrainTimeout: 300 * time.Millisecond, NoTrampoline: true}})
	req := helperRequest(t, "limits")
	req.Limits.CPU = time.Second
	req.Limits.MemoryBytes = 300 << 20
	req.Limits.FileBytes = 1 << 20
	res := r.Run(context.Background(), req)
	if res.Outcome != extrun.OutcomeOK || res.Trampoline {
		t.Fatalf("outcome %s trampoline %v", res.Outcome, res.Trampoline)
	}
	for _, c := range []extrun.Cap{extrun.CapCPU, extrun.CapFileSize, extrun.CapMemory} {
		if got := capOf(t, res, c); got.State != extrun.CapNotEnforced || got.Mechanism != "" {
			t.Errorf("%s reported %+v without a trampoline", c, got)
		}
	}
}

// TestTrampolineExecFailureIsAStartFailure: a program the trampoline cannot
// exec is reported as never started, with the trampoline's reason.
func TestTrampolineExecFailureIsAStartFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	notExec := filepath.Join(dir, "not-executable")
	if err := os.WriteFile(notExec, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	facts := (&Executor{DrainTimeout: 300 * time.Millisecond}).Exec(context.Background(), extrun.Plan{
		Path: notExec, Dir: dir, Limits: extrun.Limits{Wall: 10 * time.Second, StdoutBytes: 1024, StderrBytes: 1024},
	})
	if !strings.Contains(facts.StartErr, "trampoline: exec") {
		t.Fatalf("StartErr %q", facts.StartErr)
	}
	if extrun.Classify(facts) != extrun.OutcomeStartFailed {
		t.Fatalf("classified %s", extrun.Classify(facts))
	}
}

// TestOutputCapKillsTheWholeRun: passing the output cap kills the run, and
// a grandchild that left the group with setsid dies with it (swept by the
// supervisor, or by the cgroup kill), so the cap is a kill, not a cut.
func TestOutputCapKillsTheWholeRun(t *testing.T) {
	t.Parallel()
	req := helperRequest(t, "floodkid")
	req.Limits.StdoutBytes = 256 << 10
	res := testRunner().Run(context.Background(), req)
	if res.Outcome != extrun.OutcomeOutputCap || !res.StdoutTruncated {
		t.Fatalf("outcome %s truncated %v (%s)", res.Outcome, res.StdoutTruncated, res.Detail)
	}
	pid := firstPid(t, res.Stdout)
	if !gone(pid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("the setsid grandchild %d outlived the output cap (rung %s)", pid, res.Containment.Rung)
	}
	if res.Duration > 10*time.Second {
		t.Fatalf("the output cap took %v to end the run", res.Duration)
	}
}

// TestChildrenCapUnitIsNamed: the child cap's unit is the one of the
// mechanism that held it: tasks under a cgroup's pids.max, processes under
// polling (the same number means different things, JSP-12).
func TestChildrenCapUnitIsNamed(t *testing.T) {
	t.Parallel()
	req := helperRequest(t, "exit", "0")
	req.Limits.Children = 64
	res := testRunner().Run(context.Background(), req)
	c := capOf(t, res, extrun.CapChildren)
	want := map[string]string{extrun.MechCgroup: extrun.UnitTasks, extrun.MechPoll: extrun.UnitProcesses}[c.Mechanism]
	if want == "" || c.Unit != want || c.Limit != 64 {
		t.Fatalf("children cap %+v", c)
	}
}

// TestEngineOwnHomeIsCreatedAndUsed: an engine with its own home gets HOME
// and XDG_CACHE_HOME inside the cache directory, created before the start,
// and the hardening environment beside them.
func TestEngineOwnHomeIsCreatedAndUsed(t *testing.T) {
	t.Parallel()
	cache := filepath.Join(t.TempDir(), "engine-cache")
	req := helperRequest(t, "env")
	req.CacheDir = cache
	req.Engine = &extrun.Engine{Name: "test-engine", GitHardening: true, OwnHome: true, ExitCodes: []extrun.ExitCodeRow{{Code: 0, Meaning: extrun.ExitClean}}}
	res := testRunner().Run(context.Background(), req)
	if res.Outcome != extrun.OutcomeOK || res.ExitMeaning != extrun.ExitClean {
		t.Fatalf("outcome %s meaning %q (%s)", res.Outcome, res.ExitMeaning, res.Detail)
	}
	out := string(res.Stdout)
	for _, want := range []string{"HOME=" + cache + "/home", "XDG_CACHE_HOME=" + cache + "/xdg-cache", "GIT_CONFIG_NOSYSTEM=1"} {
		if !strings.Contains(out, want) {
			t.Errorf("program env lacks %s:\n%s", want, out)
		}
	}
	for _, d := range []string{"home", "xdg-cache"} {
		if fi, err := os.Stat(filepath.Join(cache, d)); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v %v", d, fi, err)
		}
	}
}
