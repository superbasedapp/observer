//go:build windows

package poll

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/processobs"
)

// TestPlatformEnumerateWindows validates the ToolHelp32 enumeration against
// the live process table: the current test process must appear, with a parent,
// a readable creation-time stamp (HasStart), and its own image path. Runs
// natively on a Windows host.
func TestPlatformEnumerateWindows(t *testing.T) {
	procs, err := platformEnumerate()
	if err != nil {
		t.Fatalf("platformEnumerate: %v", err)
	}
	if len(procs) == 0 {
		t.Fatal("platformEnumerate returned no processes")
	}

	self := os.Getpid()
	var me *ProcInfo
	for i := range procs {
		if procs[i].PID == self {
			me = &procs[i]
			break
		}
	}
	if me == nil {
		t.Fatalf("current process (pid %d) not found in the snapshot of %d procs", self, len(procs))
	}
	// We can always open our own process, so the enrichment must succeed.
	if !me.HasStart || me.StartTicks == 0 {
		t.Errorf("self has no creation-time stamp: %+v", *me)
	}
	if me.PPID == 0 {
		t.Errorf("self has no parent pid: %+v", *me)
	}
	if me.ExePath == "" || !strings.Contains(strings.ToLower(me.ExePath), ".exe") {
		t.Errorf("self image path looks wrong: %q", me.ExePath)
	}

	// PID-reuse-proof key inputs differ per process within a boot: every
	// process with a creation stamp should yield a distinct (pid, start) pair.
	seen := map[procKey]bool{}
	for _, p := range procs {
		if !p.HasStart {
			continue
		}
		k := procKey{pid: p.PID, start: p.StartTicks}
		if seen[k] {
			t.Errorf("duplicate (pid,start) key for pid %d", p.PID)
		}
		seen[k] = true
	}
}

// TestPollBackendCapturesChildWindows is the Windows end-to-end smoke: the
// real poll backend, run over the live process table, must synthesize an exec
// event for a child spawned after Start (the diff detects it as a new
// (pid,start) entry). Validates enumerate → diff → events on Windows — the
// path that observes the operator's Windows-native AI-tool spawns.
func TestPollBackendCapturesChildWindows(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a child process")
	}
	b := New(Options{Interval: 150 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ch, err := b.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer b.Close() //nolint:errcheck

	// A child that lives several poll intervals so the snapshot diff sees it
	// (the poll backend misses sub-interval processes by design).
	child := exec.Command("ping", "-n", "6", "127.0.0.1")
	if err := child.Start(); err != nil {
		t.Skipf("cannot spawn child (no ping?): %v", err)
	}
	defer func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	}()
	childPID := child.Process.Pid

	timeout := time.After(6 * time.Second)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatal("event channel closed before observing the child exec")
			}
			if ev.Type == processobs.EventExec && ev.PID == childPID {
				if !ev.HasStartTime {
					t.Errorf("child exec event has no start time: %+v", ev)
				}
				return // success
			}
		case <-timeout:
			t.Fatalf("did not observe an exec event for child pid %d within the window", childPID)
		}
	}
}

// TestPlatformSessionTokenWindows pins the §5.5 P-B6 env-token read: the
// capturer recovers an allowlisted session-id env var (CLAUDE_CODE_SESSION_ID)
// from a same-user child's PEB environment BY VALUE, returns "" for a child
// that does not set it, and never reads out a non-allowlisted key (the planted
// secret is not what comes back). Runs natively on a Windows host.
func TestPlatformSessionTokenWindows(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns child processes")
	}
	const want = "19f16087-7d3d-40f9-aec0-f59c3849447b"

	// Child WITH the token plus a planted secret. The test runner itself
	// inherits CLAUDE_CODE_SESSION_ID (it runs under Claude Code), so the child
	// envs are built explicitly to control the variable.
	withTok := exec.Command("ping", "-n", "20", "127.0.0.1")
	withTok.Env = append(envWithout("CLAUDE_CODE_SESSION_ID"),
		"CLAUDE_CODE_SESSION_ID="+want, "MY_SECRET_API_KEY=do-not-leak")
	if err := withTok.Start(); err != nil {
		t.Skipf("cannot spawn child (no ping?): %v", err)
	}
	defer func() { _ = withTok.Process.Kill(); _ = withTok.Wait() }()

	without := exec.Command("ping", "-n", "20", "127.0.0.1")
	without.Env = envWithout("CLAUDE_CODE_SESSION_ID")
	if err := without.Start(); err != nil {
		t.Skipf("cannot spawn child: %v", err)
	}
	defer func() { _ = without.Process.Kill(); _ = without.Wait() }()

	time.Sleep(300 * time.Millisecond) // let the children's PEBs settle

	if got := platformSessionToken(withTok.Process.Pid); got != want {
		t.Errorf("platformSessionToken(with token) = %q, want %q", got, want)
	}
	if got := platformSessionToken(without.Process.Pid); got != "" {
		t.Errorf("platformSessionToken(without token) = %q, want empty", got)
	}
	if got := platformSessionToken(0); got != "" {
		t.Errorf("platformSessionToken(0) = %q, want empty", got)
	}
}

// envWithout returns the current environment with `key` removed (Windows env
// keys are case-insensitive, so the match is case-fold).
func envWithout(key string) []string {
	env := os.Environ()
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if eq := strings.IndexByte(kv, '='); eq > 0 && strings.EqualFold(kv[:eq], key) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// TestPlatformEnumerateMetricsWindows pins that the Windows poll enumerate now
// reads resource metrics: the current process must come back with a working
// set, a thread count, and a handle count (CPU may be ~0 for a short run).
func TestPlatformEnumerateMetricsWindows(t *testing.T) {
	procs, err := platformEnumerate()
	if err != nil {
		t.Fatalf("platformEnumerate: %v", err)
	}
	self := os.Getpid()
	var me *ProcInfo
	for i := range procs {
		if procs[i].PID == self {
			me = &procs[i]
			break
		}
	}
	if me == nil {
		t.Fatalf("current process (pid %d) not found", self)
	}
	if !me.HasMetrics {
		t.Errorf("self should carry metrics: %+v", *me)
	}
	if me.WorkingSetBytes <= 0 {
		t.Errorf("working set should be > 0, got %d", me.WorkingSetBytes)
	}
	if me.ThreadCount <= 0 {
		t.Errorf("thread count should be > 0, got %d", me.ThreadCount)
	}
	if me.HandleCount <= 0 {
		t.Errorf("handle count should be > 0, got %d", me.HandleCount)
	}
}

func TestPlatformBootIDWindows(t *testing.T) {
	id := platformBootID()
	if !strings.HasPrefix(id, "win-boot-") || len(id) <= len("win-boot-") {
		t.Errorf("boot id = %q, want a non-empty win-boot-<unix> string", id)
	}
	// Stable across calls within a run (boot time doesn't move).
	if id2 := platformBootID(); id2 != id {
		t.Errorf("boot id not stable: %q vs %q", id, id2)
	}
}

// TestPlatformEnumerateSkipsTheIdlePseudoProcess: ToolHelp's PID 0 entry
// ("[System Process]", the idle process) is not a process and never leaves
// the enumerator; it crossed the process bridge as a malformed event
// (Windows 11 Pro rerun 2026-10-25, D5 group 8).
func TestPlatformEnumerateSkipsTheIdlePseudoProcess(t *testing.T) {
	procs, err := platformEnumerate()
	if err != nil {
		t.Fatalf("platformEnumerate: %v", err)
	}
	for _, p := range procs {
		if p.PID == 0 {
			t.Fatalf("PID 0 left the enumerator: %+v", p)
		}
	}
}
