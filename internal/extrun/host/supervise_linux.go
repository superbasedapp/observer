//go:build linux

package host

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// supervise is the not-contained rung's helper (modeSupervise). It makes
// itself the child subreaper, starts the program through a second,
// exec-mode trampoline (so the caps hold from the program's first
// instruction and do not bind the supervisor), and waits. When the program
// exits, or the executor sends SIGTERM, it kills the program and sweeps
// every process re-parented to it or still in its process group, reports
// the program's exit and the sweep on the status pipe, and exits with the
// program's code. A process that leaves the group AND is re-parented
// elsewhere (to an ancestor that is also a subreaper, or after the
// supervisor itself was killed) still escapes: the rung stays labelled
// "not contained".
func supervise(p trampolinePayload, status *os.File, report func(trampolineStatus), fail func(string, error, int) int) int {
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return fail("subreaper", err, trampExitStart)
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	if status == nil {
		return fail("supervise", errors.New("no status pipe"), trampExitStart)
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return fail("supervise", err, trampExitStart)
	}
	self, _ := selfPath(false)
	child := exec.Command(self, trampolineArg) //nolint:gosec // G204: the binary itself, in its exec-mode trampoline
	child.Env = []string{trampolineEnv + "=1"}
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.ExtraFiles = []*os.File{pr, status}
	if err := child.Start(); err != nil {
		closeAll(pr, pw)
		return fail("supervise_start", err, trampExitStart)
	}
	_ = pr.Close()
	sub := p
	sub.Mode = modeExec
	_, _ = pw.Write(encodePayload(sub))
	_ = pw.Close()

	childPid := child.Process.Pid
	exited := make(chan unix.WaitStatus, 1)
	go func() {
		// The one reaper: as the subreaper, every orphan is ours to reap,
		// and nothing else here waits on a child.
		for {
			var ws unix.WaitStatus
			pid, err := unix.Wait4(-1, &ws, 0, nil)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				return
			}
			if pid == childPid {
				exited <- ws
			}
		}
	}()
	var ws unix.WaitStatus
	select {
	case ws = <-exited:
	case <-sigs:
		_ = unix.Kill(childPid, unix.SIGKILL)
		ws = <-exited
	}
	ev := trampolineStatus{Ev: evExit, Swept: sweepDescendants()}
	code := 0
	switch {
	case ws.Exited():
		code = ws.ExitStatus()
		ev.Code = code
	case ws.Signaled():
		ev.Code = -1
		ev.Signal = ws.Signal().String()
		code = 128 + int(ws.Signal())
	}
	report(ev)
	return code
}

// sweepDescendants kills every live process that is this supervisor's
// child (an orphan re-parented to it, the subreaper) or a member of its
// process group, round after round until none is left, and returns how many
// distinct processes it killed. The reaper goroutine reaps them.
func sweepDescendants() int {
	self := os.Getpid()
	pgid := unix.Getpgrp()
	killed := map[int]bool{}
	for round := 0; round < 100; round++ {
		entries, err := os.ReadDir(procRoot)
		if err != nil {
			break
		}
		found := 0
		for _, e := range entries {
			pid, err := strconv.Atoi(e.Name())
			if err != nil || pid == self {
				continue
			}
			data, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "stat"))
			if err != nil {
				continue
			}
			st, ok := parseProcStat(data)
			if !ok || !st.alive() || (st.ppid != self && st.pgrp != pgid) {
				continue
			}
			_ = unix.Kill(pid, unix.SIGKILL)
			killed[pid] = true
			found++
		}
		if found == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return len(killed)
}
