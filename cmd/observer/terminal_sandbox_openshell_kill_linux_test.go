//go:build linux && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestOpenShellDescendants pins the tree walk, one case per shape.
func TestOpenShellDescendants(t *testing.T) {
	parents := map[int]int{10: 1, 11: 10, 12: 10, 13: 11, 20: 1, 21: 20}
	for _, c := range []struct {
		root int
		want []int
	}{
		{10, []int{10, 11, 12, 13}},
		{20, []int{20, 21}},
		{13, []int{13}},
		{99, []int{99}},
	} {
		if got := openShellDescendants(c.root, parents); !slices.Equal(got, c.want) {
			t.Errorf("descendants of %d = %v, want %v", c.root, got, c.want)
		}
	}
	if f := openShellStatFields("42 (a b) c) S 7 42 42"); len(f) < 2 || f[1] != "7" {
		t.Fatalf("stat fields after a comm with spaces and parens: %v", f)
	}
}

// TestOpenShellChildKill (fix round 2, FU8-R3): the kill reaches the
// child's descendants, says false before a child or after it is cleared,
// and never signals a pid whose start time changed.
func TestOpenShellChildKill(t *testing.T) {
	c := &openShellChild{}
	if c.kill() {
		t.Fatal("no child yet: nothing to kill")
	}
	cmd := exec.Command("sh", "-c", "sleep 30 & wait")
	if err := cmd.Start(); err != nil {
		t.Skip("no sh:", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	c.set(cmd.Process.Pid)
	// The grandchild sleep exists once sh forked it.
	deadline := time.Now().Add(5 * time.Second)
	for len(openShellDescendants(cmd.Process.Pid, openShellParents())) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	tree := openShellDescendants(cmd.Process.Pid, openShellParents())
	if len(tree) < 2 {
		t.Fatalf("no grandchild seen: %v", tree)
	}
	stale := &openShellChild{pid: cmd.Process.Pid, start: "1"}
	if stale.kill() {
		t.Fatal("a pid whose start time changed was signalled")
	}
	if !c.kill() {
		t.Fatal("the child was not killed")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the child did not end")
	}
	for _, pid := range tree[1:] {
		for time.Now().Before(deadline) && fu8Alive(pid) {
			time.Sleep(10 * time.Millisecond)
		}
		if fu8Alive(pid) {
			t.Errorf("descendant %d outlived the kill", pid)
		}
	}
	c.clear()
	if c.kill() {
		t.Fatal("a cleared child was killed")
	}
}

// fu8Alive reports whether pid runs (gone or a zombie is not running).
func fu8Alive(pid int) bool {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return false
	}
	f := openShellStatFields(string(b))
	return len(f) > 0 && f[0] != "Z"
}

// TestOpenShellChildKillReadsTheStartLate (fix rounds 3 and 4, FU8-R7,
// FU8-R9): a child whose start time set could not read is killed once kill
// reads it, but only when the process at that pid is this process's child;
// a pid whose parent is another process (recycled after the reap) is
// never signalled and the child is marked reaped.
func TestOpenShellChildKillReadsTheStartLate(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skip("no sleep:", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	c := &openShellChild{pid: cmd.Process.Pid} // start "" as after a failed read
	if !c.kill() {
		t.Fatal("our own child with an unread start time was not killed")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the child did not end")
	}

	// A recycled pid: the late read sees a process whose parent is not us.
	var signalled bool
	recycled := &openShellChild{pid: 4242, stat: func(pid int) (string, int, bool) {
		if pid != 4242 {
			signalled = true
		}
		return "777", 1, true
	}}
	if recycled.kill() {
		t.Fatal("a recycled pid was reported killed")
	}
	if recycled.pid != 0 || signalled {
		t.Fatalf("a recycled pid must mark the child reaped: pid %d", recycled.pid)
	}
	// A read that fails is retried, never taken as reaped.
	unread := &openShellChild{pid: 4243, stat: func(int) (string, int, bool) { return "", 0, false }}
	if unread.kill() || unread.pid != 4243 {
		t.Fatalf("an unreadable stat must be retried: pid %d", unread.pid)
	}
}

// TestOpenShellChildKillPidfd (audit FU8-R12): with the pidfd set opens,
// the late start read is taken only while the pid is still the child's.
// One row per case: a live child with an unread start is killed (the root
// through its pidfd); a child reaped since, whose pid now reads as another
// child of this helper (the shape the parent check alone accepted), is
// never signalled and is marked reaped; a stat that cannot be read is
// retried, never taken as reaped.
func TestOpenShellChildKillPidfd(t *testing.T) {
	for _, tc := range []struct {
		name     string
		reap     bool // the child ends and is reaped before the kill
		statFail bool // the late stat read fails
		killed   bool
		marked   bool // the child is marked reaped (pid 0)
	}{
		{name: "live child, unread start", killed: true},
		{name: "reaped, pid recycled into another child of ours", reap: true, marked: true},
		{name: "reaped, stat unreadable", reap: true, statFail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("sleep", "30")
			if err := cmd.Start(); err != nil {
				t.Skip("no sleep:", err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			pid := cmd.Process.Pid
			c := &openShellChild{}
			c.set(pid)
			t.Cleanup(c.clear)
			if !c.hasFD {
				_ = cmd.Process.Kill()
				<-done
				t.Skip("pidfd_open is not available here")
			}
			c.start = "" // as after a failed early read
			if tc.reap {
				_ = cmd.Process.Kill()
				<-done
				// The pid now reads as a fresh child of this process.
				c.stat = func(p int) (string, int, bool) {
					if tc.statFail {
						return "", 0, false
					}
					return "777", os.Getpid(), true
				}
			}
			if got := c.kill(); got != tc.killed {
				t.Fatalf("kill() = %v, want %v", got, tc.killed)
			}
			if marked := c.pid == 0; marked != tc.marked {
				t.Fatalf("marked reaped %v, want %v (pid %d)", marked, tc.marked, c.pid)
			}
			if tc.killed {
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("the child did not end")
				}
			}
		})
	}
}

// TestOpenShellChildKillRootFallback (audit FU12-A1): the root's SIGKILL
// through its pidfd is done on success or ESRCH; on any other answer the
// kill falls back to the start-checked kill by pid, and when that fails
// too it reports false so the next tick retries. One row per answer.
func TestOpenShellChildKillRootFallback(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fdErr    error
		pidErr   bool // the fallback kill by pid fails
		killed   bool // kill() reports true
		fallback bool // the kill by pid was sent to the root
	}{
		{name: "pidfd kills", killed: true},
		{name: "pidfd ESRCH, already gone", fdErr: unix.ESRCH, killed: true},
		{name: "pidfd EPERM, kill by pid works", fdErr: unix.EPERM, killed: true, fallback: true},
		{name: "pidfd EPERM, kill by pid fails", fdErr: unix.EPERM, pidErr: true, fallback: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("sleep", "30")
			if err := cmd.Start(); err != nil {
				t.Skip("no sleep:", err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			t.Cleanup(func() { _ = cmd.Process.Kill(); <-done })
			pid := cmd.Process.Pid
			c := &openShellChild{}
			c.set(pid)
			t.Cleanup(c.clear)
			if !c.hasFD || c.start == "" {
				t.Skip("pidfd_open or the start read is not available here")
			}
			var fellBack bool
			c.sendFD = func(fd int, sig unix.Signal) error {
				if tc.fdErr != nil && sig == unix.SIGKILL {
					return tc.fdErr
				}
				return unix.PidfdSendSignal(fd, sig, nil, 0)
			}
			c.killPID = func(p int, sig unix.Signal) error {
				if p == pid {
					fellBack = true
					if tc.pidErr {
						return unix.EPERM
					}
				}
				return unix.Kill(p, sig)
			}
			if got := c.kill(); got != tc.killed {
				t.Fatalf("kill() = %v, want %v", got, tc.killed)
			}
			if fellBack != tc.fallback {
				t.Fatalf("fell back to the kill by pid %v, want %v", fellBack, tc.fallback)
			}
			if tc.killed && tc.fdErr == nil || tc.fallback && !tc.pidErr {
				select {
				case <-done:
					done <- nil // for the cleanup's receive
				case <-time.After(5 * time.Second):
					t.Fatal("the child did not end")
				}
			}
		})
	}
}
