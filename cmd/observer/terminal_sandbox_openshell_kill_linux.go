//go:build linux && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// terminal_sandbox_openshell_kill_linux.go is the host helper's enforced
// stop of a supervised `openshell sandbox create` (lane FU8 fix round 2,
// FU8-R3). The child keeps the run's terminal (no new process group: the
// CLI's --tty session needs the terminal's foreground group), so the stop
// kills the child and every descendant it has at that moment (the attach
// spawns ssh with a ProxyCommand that can outlive the CLI), found through
// /proc. The child is named by its pid AND its start time, so a pid the
// kernel recycled after the child was reaped is never signalled, and by a
// pidfd opened when it starts (before any reap can free its pid), which
// tells the late start read whether the pid is still the child's (audit
// FU8-R12).

// openShellChild is the supervised child, by pid, start time and pidfd.
type openShellChild struct {
	mu    sync.Mutex
	pid   int
	start string
	// pidfd names the child itself while hasFD (pidfd_open in set, Linux
	// 5.3 or later; the row needs 6.2). Without one the late read falls
	// back to the parent check alone.
	pidfd int
	hasFD bool
	// stat reads a process's start time and parent pid (nil:
	// openShellProcStat; tests inject a fake).
	stat func(pid int) (start string, ppid int, ok bool)
	// sendFD signals through a pidfd and killPID by pid (nil:
	// unix.PidfdSendSignal and unix.Kill; tests inject failures).
	sendFD  func(fd int, sig unix.Signal) error
	killPID func(pid int, sig unix.Signal) error
}

// signalFD signals the child through its pidfd with c's sender.
func (c *openShellChild) signalFD(sig unix.Signal) error {
	if c.sendFD != nil {
		return c.sendFD(c.pidfd, sig)
	}
	return unix.PidfdSendSignal(c.pidfd, sig, nil, 0)
}

// signalPID signals pid with c's killer.
func (c *openShellChild) signalPID(pid int, sig unix.Signal) error {
	if c.killPID != nil {
		return c.killPID(pid, sig)
	}
	return unix.Kill(pid, sig)
}

// statOf reads pid's start time and parent through c's reader.
func (c *openShellChild) statOf(pid int) (string, int, bool) {
	if c.stat != nil {
		return c.stat(pid)
	}
	return openShellProcStat(pid)
}

// set records the child (postStart); clear forgets it (after the run).
func (c *openShellChild) set(pid int) {
	start := ""
	// The child was just started (runSupervisedChild reaps it only when it
	// ends), so its stat is there; a transient read failure is retried
	// (FU8-R7).
	for i := 0; i < openShellStartReads && start == ""; i++ {
		if i > 0 {
			time.Sleep(10 * time.Millisecond)
		}
		start, _, _ = c.statOf(pid)
	}
	// The child is not reaped before runSupervisedChild returns, so the
	// pidfd opened now is the child's, whatever happens to the pid later.
	fd, err := unix.PidfdOpen(pid, 0)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeFDLocked()
	c.pid, c.start = pid, start
	if err == nil {
		c.pidfd, c.hasFD = fd, true
	}
}

// closeFDLocked closes the child's pidfd, if any (c.mu held).
func (c *openShellChild) closeFDLocked() {
	if c.hasFD {
		_ = unix.Close(c.pidfd)
		c.pidfd, c.hasFD = 0, false
	}
}

// pidStillChild reports, through the pidfd, whether the child's pid is
// still the child's (a signal 0 reaches it: it runs or is a zombie, which
// holds its pid). known is false without a pidfd or on an answer other
// than success or ESRCH; the caller then falls back to the parent check
// (c.mu held).
func (c *openShellChild) pidStillChild() (still, known bool) {
	if !c.hasFD {
		return false, false
	}
	err := c.signalFD(0)
	if err == nil {
		return true, true
	}
	if errors.Is(err, unix.ESRCH) {
		return false, true
	}
	return false, false
}

// openShellStartReads is how many times set reads the child's start time.
const openShellStartReads = 5

func (c *openShellChild) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeFDLocked()
	c.pid, c.start = 0, ""
}

// kill kills the child's tree and reports whether a child was there to
// kill (false while the child has not started yet, so the caller retries).
func (c *openShellChild) kill() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pid <= 0 {
		return false
	}
	if c.start == "" {
		// set could not read it: read it now. runSupervisedChild reaps the
		// child before clear runs, so between the two the pid may already
		// belong to another process. The stat is read first, then the
		// pidfd is asked whether the pid is still the child's: if it is
		// now, it was when the stat was read, so a pid recycled into
		// another child of this same helper is refused too (audit
		// FU8-R12). Without a pidfd answer the late read is taken only
		// from a process whose parent is this helper (fix round 4,
		// FU8-R9), which such a recycled pid still passes (the residual
		// where pidfd_open was refused). Anything else marks the child
		// reaped.
		start, ppid, ok := c.statOf(c.pid)
		if !ok || start == "" {
			return false // retried on the next tick
		}
		still, known := c.pidStillChild()
		if (known && !still) || (!known && ppid != os.Getpid()) {
			c.closeFDLocked()
			c.pid, c.start = 0, ""
			return false
		}
		c.start = start
	}
	if start, _, _ := c.statOf(c.pid); start != c.start {
		return false
	}
	tree := openShellDescendants(c.pid, openShellParents())
	starts := make([]string, len(tree))
	for i, pid := range tree {
		starts[i] = openShellProcStart(pid)
	}
	// Children first, then the root, so none is reparented away between.
	// Each pid's start time is read again just before its signal, so a
	// descendant that exited and whose pid was reused since the snapshot is
	// skipped (a residual window between that read and the signal remains).
	for i := len(tree) - 1; i >= 0; i-- {
		if i == 0 && c.hasFD {
			// The root through its pidfd: no recycle window at all. Done
			// on success or ESRCH (the child is already gone); any other
			// answer (EPERM, ENOSYS from a seccomp profile) falls back to
			// the start-checked kill below (audit FU12-A1).
			if err := c.signalFD(unix.SIGKILL); err == nil || errors.Is(err, unix.ESRCH) {
				continue
			}
		}
		if starts[i] == "" || openShellProcStart(tree[i]) != starts[i] {
			if i == 0 && c.hasFD {
				return false // the pidfd failed and the root cannot be checked: retried
			}
			continue
		}
		if err := c.signalPID(tree[i], unix.SIGKILL); err != nil && i == 0 && c.hasFD {
			return false // neither signal reached the root: the next tick retries
		}
	}
	return true
}

// openShellProcStat reads field 22 (the start time) and field 4 (the
// parent pid) of /proc/<pid>/stat; ok is false when it cannot be read.
func openShellProcStat(pid int) (start string, ppid int, ok bool) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat")) //nolint:gosec // G304: a fixed /proc path
	if err != nil {
		return "", 0, false
	}
	f := openShellStatFields(string(b))
	if len(f) < 20 {
		return "", 0, false
	}
	pp, err := strconv.Atoi(f[1])
	if err != nil {
		return "", 0, false
	}
	return f[19], pp, true
}

// openShellProcStart is field 22 of /proc/<pid>/stat (the start time in
// clock ticks), "" when it cannot be read.
func openShellProcStart(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat")) //nolint:gosec // G304: a fixed /proc path
	if err != nil {
		return ""
	}
	f := openShellStatFields(string(b))
	if len(f) < 20 {
		return ""
	}
	return f[19] // field 22: the fields after the comm start at field 3
}

// openShellStatFields splits /proc/<pid>/stat after the comm field (which
// may hold spaces and parentheses) into fields 3 onwards.
func openShellStatFields(stat string) []string {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return nil
	}
	return strings.Fields(stat[i+1:])
}

// openShellParents reads every process's parent from /proc.
func openShellParents() map[int]int {
	out := map[int]int{}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat")) //nolint:gosec // G304: a fixed /proc path
		if err != nil {
			continue
		}
		f := openShellStatFields(string(b))
		if len(f) < 2 {
			continue
		}
		if ppid, err := strconv.Atoi(f[1]); err == nil {
			out[pid] = ppid
		}
	}
	return out
}

// openShellDescendants returns root and every descendant in parents, root
// first, then breadth first, each level sorted.
func openShellDescendants(root int, parents map[int]int) []int {
	kids := map[int][]int{}
	for pid, ppid := range parents {
		kids[ppid] = append(kids[ppid], pid)
	}
	out := []int{root}
	seen := map[int]bool{root: true}
	for i := 0; i < len(out); i++ {
		next := kids[out[i]]
		sort.Ints(next)
		for _, k := range next {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	return out
}
