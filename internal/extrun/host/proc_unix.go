//go:build unix

package host

import (
	"os"
	"os/exec"
	"syscall"

	"github.com/marmutapp/superbased-observer/internal/extrun"
)

// prepareCmd starts the program as the leader of its own process group, so
// the group kill reaches everything it starts that does not leave the group.
func prepareCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// The kill seams. Tests swap them to see what a kill sends; production
// code never does.
var (
	// sysKill is kill(2). The group kill is its only caller, always with a
	// negative id (the group), never a positive pid.
	sysKill = syscall.Kill
	// signalLeader signals the leader through its os.Process, never by raw
	// pid. os.Process marks the process done before Wait reaps it (holding
	// its signal lock, so an in-flight signal finishes first) and uses a
	// pidfd where the kernel has one, so once Wait has reaped the leader this
	// returns os.ErrProcessDone and sends nothing: a recycled pid is never
	// signalled.
	signalLeader = func(p *os.Process) error { return p.Signal(syscall.SIGKILL) }
)

// unixGroup is a process group led by pid.
type unixGroup struct {
	pid  int
	proc *os.Process
}

// kill sends SIGKILL to the whole group, then to the leader itself in case
// it moved to another group. Errors (the group is already gone) are ignored.
// The leader is signalled only while it is unreaped (see signalLeader); the
// group id stays reserved while any member is alive, so the group kill
// cannot reach an unrelated process while it still has work to do.
func (g unixGroup) kill() {
	_ = sysKill(-g.pid, syscall.SIGKILL)
	if g.proc != nil {
		_ = signalLeader(g.proc)
	}
}

func (g unixGroup) close() {}

// signalOf reports the signal that ended the program, if one did.
func signalOf(ps *os.ProcessState) (string, bool) {
	ws, ok := ps.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() {
		return "", false
	}
	return ws.Signal().String(), true
}

// appliedCaps reports what the trampoline applied for every requested
// per-process cap (an empty mechanism, as when no trampoline ran, means not
// enforced) and how the child cap is held.
func appliedCaps(l extrun.Limits, ready trampolineStatus, _ bool) map[extrun.Cap]extrun.CapApplied {
	out := map[extrun.Cap]extrun.CapApplied{}
	if l.MemoryBytes > 0 {
		out[extrun.CapMemory] = extrun.CapApplied{Mechanism: ready.Memory}
	}
	if l.CPU > 0 {
		out[extrun.CapCPU] = extrun.CapApplied{Mechanism: ready.CPU}
	}
	if l.FileBytes > 0 {
		out[extrun.CapFileSize] = extrun.CapApplied{Mechanism: ready.Fsize}
	}
	if l.Children > 0 {
		out[extrun.CapChildren] = childrenApplied(ready)
	}
	return out
}

// abortStart kills a start that never reached the program (the launcher
// or the trampoline gave up) and reaps it.
func abortStart(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = sysKill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Process.Kill()
	}
	_ = cmd.Wait()
}
