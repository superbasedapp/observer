//go:build unix

package termsession

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
)

// newOSSpawner returns the unix creack/pty-backed spawner.
func newOSSpawner() Spawner { return unixSpawner{} }

// ptySupported reports whether this OS can host an in-process PTY. Unix has
// creack/pty, so the embedded web terminal is available; the windows build
// returns false (see spawn_windows.go). cmd uses this to leave the launch
// seam unwired on an unsupported OS — the "Launch here" affordance then
// simply doesn't appear, while the platform-independent handoff-doc
// migration ("Write handover doc") is unaffected.
func ptySupported() bool { return true }

// unixSpawner starts an observer launcher in a pseudo-terminal. creack/pty's
// StartWithSize puts the child in a new session (Setsid) with the pty as its
// controlling terminal, so the child is a process-group leader (pgid == pid)
// — killing the negative pid reaps the whole `observer <tool>` → `<tool>`
// tree, not just the launcher.
type unixSpawner struct{}

func (unixSpawner) Spawn(spec Spec) (PTY, error) {
	// Resolve argv[0] through the shared helper rather than leaving it to
	// exec.Command's implicit LookPath, so the Spec argv contract (and the
	// cwd-only refusal) lives in ONE place for both platforms. exec.Command
	// then finds cmd.Path already absolute and re-runs a no-op lookup.
	argv, err := resolveSpawnArgv(spec.argv())
	if err != nil {
		return nil, err
	}
	//nolint:gosec // argv is fully server-derived from a validated Spec
	// (BinPath from os.Executable, Subcommand from the capability registry,
	// SessionID/Carry validated by the dashboard) — never client argv.
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = spec.Env
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	// Fresh launches set the child cwd to the validated, canonicalized project
	// root (F1); a handoff launch leaves Dir empty (inherit the daemon cwd).
	cmd.Dir = spec.Dir
	// Inherit the trusted out-of-band control-channel FD(s) at fd 3+ (F1).
	cmd.ExtraFiles = spec.ExtraFiles

	ws := &pty.Winsize{Rows: spec.Rows, Cols: spec.Cols}
	f, err := pty.StartWithSize(cmd, ws)
	if err != nil {
		if errors.Is(err, pty.ErrUnsupported) {
			return nil, ErrPlatformUnsupported
		}
		return nil, fmt.Errorf("termsession: start pty for observer %s: %w", spec.Subcommand, err)
	}
	return &unixPTY{f: f, cmd: cmd}, nil
}

// The unix backend reports its child's pid, so the Manager can publish a
// ProcessEvent for it (compile-time pin — the windows sibling has the same
// assertion, so neither platform can silently lose the seam).
var _ ProcessReporter = (*unixPTY)(nil)

// unixPTY wraps a creack/pty master fd and its process.
type unixPTY struct {
	f        *os.File
	cmd      *exec.Cmd
	killOnce sync.Once
}

// Pid implements [ProcessReporter]: the OS pid of the launcher child, which
// is also its process-group id (StartWithSize sets Setsid). 0 once the
// process handle is gone. This is the pid an injected process-attribution
// sink seeds against — the whole `observer <tool>` → `<tool>` subtree hangs
// off it.
func (p *unixPTY) Pid() int {
	if p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

func (p *unixPTY) Read(b []byte) (int, error)  { return p.f.Read(b) }
func (p *unixPTY) Write(b []byte) (int, error) { return p.f.Write(b) }
func (p *unixPTY) Close() error                { return p.f.Close() }

func (p *unixPTY) Resize(rows, cols uint16) error {
	return pty.Setsize(p.f, &pty.Winsize{Rows: rows, Cols: cols})
}

// Wait blocks until the launcher process exits and returns its exit code.
func (p *unixPTY) Wait() (int, error) {
	err := p.cmd.Wait()
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	return -1, err
}

// Kill force-reaps the whole process group and closes the master fd. It is
// idempotent. A graceful SIGTERM is sent first; a delayed SIGKILL backstops
// a child that ignores it (a dead group returns ESRCH, harmlessly).
func (p *unixPTY) Kill() error {
	p.killOnce.Do(func() {
		_ = p.f.Close()
		proc := p.cmd.Process
		if proc == nil {
			return
		}
		pgid := proc.Pid // Setsid → the child leads its own process group
		_ = syscall.Kill(-pgid, syscall.SIGTERM)
		time.AfterFunc(2*time.Second, func() {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		})
	})
	return nil
}
