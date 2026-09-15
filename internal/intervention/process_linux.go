//go:build linux

package intervention

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/processobs/poll"
)

const exitPollInterval = 20 * time.Millisecond

// Inspect reads the nonsensitive identity fields required to control pid.
// It returns no argv, environment, working directory, or executable pathname.
func Inspect(ctx context.Context, pid int) (Identity, error) {
	if ctx == nil {
		return Identity{}, fmt.Errorf("intervention.Inspect: %w: nil context", ErrInvalidIdentity)
	}
	if err := ctx.Err(); err != nil {
		return Identity{}, fmt.Errorf("intervention.Inspect: %w", err)
	}
	if pid <= 0 {
		return Identity{}, fmt.Errorf("intervention.Inspect: %w: pid must be positive", ErrInvalidIdentity)
	}

	startTicks, err := readProcessStart(pid)
	if err != nil {
		return Identity{}, err
	}
	if err := ctx.Err(); err != nil {
		return Identity{}, fmt.Errorf("intervention.Inspect: %w", err)
	}
	uid, err := readUniformUID(pid)
	if err != nil {
		return Identity{}, err
	}
	if err := ctx.Err(); err != nil {
		return Identity{}, fmt.Errorf("intervention.Inspect: %w", err)
	}

	var stat unix.Stat_t
	if err := unix.Stat(fmt.Sprintf("/proc/%d/exe", pid), &stat); err != nil {
		return Identity{}, inspectExecutableError(pid, err)
	}
	id := Identity{
		BootID:     poll.PlatformBootID(),
		PID:        pid,
		StartTicks: startTicks,
		UID:        uid,
		Executable: ExecutableIdentity{Device: uint64(stat.Dev), Inode: stat.Ino}, //nolint:unconvert // dev_t differs across Linux architectures.
	}
	if !validIdentity(id) {
		return Identity{}, fmt.Errorf("intervention.Inspect: %w: incomplete process metadata", ErrInvalidIdentity)
	}
	return id, nil
}

func readUniformUID(pid int) (int, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			return 0, classifyUnreadableProcess(pid)
		case errors.Is(err, os.ErrPermission):
			return 0, fmt.Errorf("intervention.Inspect: status UID: %w", ErrPermission)
		default:
			return 0, fmt.Errorf("intervention.Inspect: status UID: %w", err)
		}
	}
	uid, ok := parseUniformUID(raw)
	if !ok {
		return 0, fmt.Errorf("intervention.Inspect: status UID: %w", ErrInspectionUnavailable)
	}
	return uid, nil
}

// parseUniformUID requires Linux status's real, effective, saved-set and
// filesystem UIDs and accepts the identity only when all four agree. A setuid
// transition is not a safe single-principal target for this primitive.
func parseUniformUID(raw []byte) (int, bool) {
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
		if len(fields) != 4 {
			return 0, false
		}
		var values [4]uint64
		for i, field := range fields {
			value, err := strconv.ParseUint(field, 10, strconv.IntSize)
			if err != nil {
				return 0, false
			}
			values[i] = value
		}
		if values[0] != values[1] || values[0] != values[2] || values[0] != values[3] {
			return 0, false
		}
		return int(values[0]), true
	}
	return 0, false
}

// Acquire opens a pidfd for expected and re-inspects the complete identity
// after acquisition. It refuses the current process, incomplete identities,
// PID reuse, exec replacement, and a second live handle for the same identity.
func Acquire(ctx context.Context, expected Identity) (*Process, error) {
	if ctx == nil {
		return nil, fmt.Errorf("intervention.Acquire: %w: nil context", ErrInvalidIdentity)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("intervention.Acquire: %w", err)
	}
	if !validIdentity(expected) || strings.TrimSpace(expected.BootID) != expected.BootID {
		return nil, fmt.Errorf("intervention.Acquire: %w", ErrInvalidIdentity)
	}
	if expected.PID == os.Getpid() {
		return nil, ErrSelfTarget
	}

	before, err := Inspect(ctx, expected.PID)
	if err != nil {
		return nil, fmt.Errorf("intervention.Acquire: inspect before pidfd: %w", err)
	}
	if !sameIdentity(before, expected) {
		return nil, ErrIdentityMismatch
	}

	pidfd, err := unix.PidfdOpen(expected.PID, 0)
	if err != nil {
		return nil, pidfdOpenError(err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = unix.Close(pidfd)
		}
	}()

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("intervention.Acquire: %w", err)
	}
	after, err := Inspect(ctx, expected.PID)
	if err != nil {
		return nil, fmt.Errorf("intervention.Acquire: inspect after pidfd: %w", err)
	}
	if !sameIdentity(after, expected) {
		return nil, ErrIdentityMismatch
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("intervention.Acquire: %w", err)
	}
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
		return nil, pidfdSignalError("intervention.Acquire: probe", err)
	}

	p := &Process{identity: expected, handle: pidfd, inspect: Inspect}
	if !registerProcess(p) {
		return nil, ErrAlreadyAcquired
	}
	closeOnError = false
	return p, nil
}

// Terminate sends SIGTERM through the acquired pidfd and waits for pidfd exit
// readiness. It is a compatibility convenience for direct primitive callers;
// Supervisor uses SignalTerminate and WaitExit separately so policy fences do
// not span exit observation.
func (p *Process) Terminate(ctx context.Context) (ExitResult, error) {
	result, err := p.SignalTerminate(ctx)
	if err != nil || result.Observed {
		return result, err
	}
	return p.WaitExit(ctx)
}

// Kill sends SIGKILL through the acquired pidfd and waits for pidfd exit
// readiness. It is an explicit operation, never an automatic fallback from
// Terminate. The context must have a deadline.
func (p *Process) Kill(ctx context.Context) (ExitResult, error) {
	result, err := p.SignalKill(ctx)
	if err != nil || result.Observed {
		return result, err
	}
	return p.WaitExit(ctx)
}

// SignalTerminate revalidates the acquired identity and sends SIGTERM. A
// successful delivery is unobserved until WaitExit proves pidfd readiness.
func (p *Process) SignalTerminate(ctx context.Context) (ExitResult, error) {
	return p.signal(ctx, unix.SIGTERM, "SignalTerminate")
}

// SignalKill revalidates the acquired identity and sends SIGKILL. A successful
// delivery is unobserved until WaitExit proves pidfd readiness.
func (p *Process) SignalKill(ctx context.Context) (ExitResult, error) {
	return p.signal(ctx, unix.SIGKILL, "SignalKill")
}

func (p *Process) signal(ctx context.Context, sig unix.Signal, operation string) (ExitResult, error) {
	if p == nil {
		return ExitResult{}, fmt.Errorf("intervention.%s: %w", operation, ErrClosed)
	}
	if err := boundedContext(ctx, operation); err != nil {
		return ExitResult{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.handle < 0 {
		return ExitResult{}, fmt.Errorf("intervention.%s: %w", operation, ErrClosed)
	}
	if err := boundedContext(ctx, operation); err != nil {
		return ExitResult{}, err
	}

	if err := unix.PidfdSendSignal(p.handle, 0, nil, 0); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return ExitResult{Observed: true, AlreadyExited: true}, nil
		}
		return ExitResult{}, pidfdSignalError("intervention."+operation+": probe", err)
	}
	// This is a point-in-time defense against an exec replacement that already
	// completed. pidfd signalling and exec cannot be made atomic here, so a
	// privileged supervisor must not report this primitive as exec admission.
	live, err := p.inspect(ctx, p.identity.PID)
	if err != nil {
		return ExitResult{}, fmt.Errorf("intervention.%s: revalidate: %w", operation, err)
	}
	if !sameIdentity(live, p.identity) {
		return ExitResult{}, ErrIdentityMismatch
	}
	if err := boundedContext(ctx, operation); err != nil {
		return ExitResult{}, err
	}

	if err := unix.PidfdSendSignal(p.handle, sig, nil, 0); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return ExitResult{Observed: true, AlreadyExited: true}, nil
		}
		return ExitResult{}, pidfdSignalError("intervention."+operation+": signal", err)
	}
	return ExitResult{}, nil
}

// WaitExit waits for the acquired pidfd to report exit readiness. It performs
// no policy, identity, or signal operation and may therefore run outside the
// authority transaction used for signal delivery.
func (p *Process) WaitExit(ctx context.Context) (ExitResult, error) {
	const operation = "WaitExit"
	if p == nil {
		return ExitResult{}, fmt.Errorf("intervention.%s: %w", operation, ErrClosed)
	}
	if err := boundedContext(ctx, operation); err != nil {
		return ExitResult{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.handle < 0 {
		return ExitResult{}, fmt.Errorf("intervention.%s: %w", operation, ErrClosed)
	}
	if err := boundedContext(ctx, operation); err != nil {
		return ExitResult{}, err
	}
	if err := waitForExit(ctx, p.handle); err != nil {
		return ExitResult{}, fmt.Errorf("intervention.WaitExit: exit unobserved: %w", err)
	}
	return ExitResult{Observed: true}, nil
}

// Close releases the pidfd and the process-local single-owner registration.
// It does not send a signal.
func (p *Process) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	unregisterProcess(p)
	err := unix.Close(p.handle)
	p.handle = -1
	if err != nil {
		return fmt.Errorf("intervention.Process.Close: %w", err)
	}
	return nil
}

func boundedContext(ctx context.Context, operation string) error {
	if ctx == nil {
		return fmt.Errorf("intervention.%s: %w: nil context", operation, ErrUnboundedContext)
	}
	if _, ok := ctx.Deadline(); !ok {
		return fmt.Errorf("intervention.%s: %w", operation, ErrUnboundedContext)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("intervention.%s: %w", operation, err)
	}
	return nil
}

func waitForExit(ctx context.Context, pidfd int) error {
	return waitForExitWith(ctx, pidfd, unix.Poll)
}

func waitForExitWith(
	ctx context.Context,
	pidfd int,
	poll func([]unix.PollFd, int) (int, error),
) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		deadline, _ := ctx.Deadline()
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return context.DeadlineExceeded
		}
		wait := min(remaining, exitPollInterval)
		timeoutMS := max(1, int((wait+time.Millisecond-1)/time.Millisecond))
		fds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
		n, err := poll(fds, timeoutMS)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n > 0 {
			switch revents := fds[0].Revents; {
			case revents&unix.POLLNVAL != 0:
				return unix.EBADF
			case revents&unix.POLLERR != 0:
				return unix.EIO
			case revents&unix.POLLIN != 0:
				return nil
			case revents&unix.POLLHUP != 0:
				return fmt.Errorf("unexpected pidfd poll hangup")
			}
		}
	}
}

func classifyUnreadableProcess(pid int) error {
	var stat unix.Stat_t
	err := unix.Stat(fmt.Sprintf("/proc/%d", pid), &stat)
	switch {
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ESRCH):
		return fmt.Errorf("intervention.Inspect: pid %d: %w", pid, ErrProcessGone)
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
		return fmt.Errorf("intervention.Inspect: pid %d: %w", pid, ErrPermission)
	case err != nil:
		return fmt.Errorf("intervention.Inspect: pid %d: %w", pid, err)
	default:
		return fmt.Errorf("intervention.Inspect: pid %d: %w", pid, ErrInspectionUnavailable)
	}
}

func inspectExecutableError(pid int, err error) error {
	switch {
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ESRCH):
		return classifyUnreadableProcess(pid)
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
		return fmt.Errorf("intervention.Inspect: executable: %w", ErrPermission)
	default:
		return fmt.Errorf("intervention.Inspect: executable: %w", err)
	}
}

func pidfdOpenError(err error) error {
	switch {
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EINVAL):
		return fmt.Errorf("intervention.Acquire: pidfd_open: %w", ErrUnsupported)
	case errors.Is(err, unix.ESRCH):
		return fmt.Errorf("intervention.Acquire: pidfd_open: %w", ErrProcessGone)
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
		return fmt.Errorf("intervention.Acquire: pidfd_open: %w", ErrPermission)
	default:
		return fmt.Errorf("intervention.Acquire: pidfd_open: %w", err)
	}
}

func pidfdSignalError(prefix string, err error) error {
	switch {
	case errors.Is(err, unix.ESRCH):
		return fmt.Errorf("%s: %w", prefix, ErrProcessGone)
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
		return fmt.Errorf("%s: %w", prefix, ErrPermission)
	default:
		return fmt.Errorf("%s: %w", prefix, err)
	}
}
