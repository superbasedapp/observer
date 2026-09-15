package intervention

import (
	"context"
	"errors"
	"sync"
)

var (
	// ErrUnsupported reports that this operating system or kernel does not
	// provide the process-handle primitive required by this package.
	ErrUnsupported = errors.New("intervention: process control unsupported")
	// ErrInvalidIdentity reports a missing or unsafe expected-identity field.
	ErrInvalidIdentity = errors.New("intervention: invalid process identity")
	// ErrSelfTarget reports an attempt to acquire the Observer process itself.
	ErrSelfTarget = errors.New("intervention: refusing to control self")
	// ErrIdentityMismatch reports that the live process is not the exact
	// process the caller expected.
	ErrIdentityMismatch = errors.New("intervention: process identity mismatch")
	// ErrProcessGone reports that the expected process no longer exists.
	ErrProcessGone = errors.New("intervention: process no longer exists")
	// ErrPermission reports that the operating system refused inspection or
	// control of the expected process.
	ErrPermission = errors.New("intervention: process control permission denied")
	// ErrInspectionUnavailable reports that the PID still exists but the
	// complete identity needed for safe control could not be read.
	ErrInspectionUnavailable = errors.New("intervention: complete process identity unavailable")
	// ErrAlreadyAcquired reports that this package already owns a live handle
	// for the exact process identity in this Observer process.
	ErrAlreadyAcquired = errors.New("intervention: process already acquired")
	// ErrClosed reports use of a released process handle.
	ErrClosed = errors.New("intervention: process handle closed")
	// ErrUnboundedContext reports a termination request without a deadline.
	ErrUnboundedContext = errors.New("intervention: operation requires a context deadline")
)

// ExecutableIdentity identifies the file currently installed as a process's
// executable. Device and Inode come from the executable reached through the
// process filesystem, rather than from its mutable pathname.
type ExecutableIdentity struct {
	Device uint64
	Inode  uint64
}

// Identity is the complete expected identity required before acquiring a
// process. BootID plus PID and StartTicks protect against PID reuse; UID binds
// the operating-system principal; Executable detects an observed exec
// replacement while remaining independent of mutable executable pathnames.
// Identity intentionally contains no argv or environment fields.
type Identity struct {
	BootID     string
	PID        int
	StartTicks int64
	UID        int
	Executable ExecutableIdentity
}

// ExitResult describes what the pidfd proved about a requested exit. Observed
// is true only when the pidfd reported process exit or was already dead before
// the signal. AlreadyExited distinguishes that latter case. An unobserved
// result never means the process terminated.
type ExitResult struct {
	Observed      bool
	AlreadyExited bool
}

// Process is one acquired operating-system process handle. It never represents
// a process group, cgroup, job object, descendant tree, adapter, or session.
// Call Close when control is no longer required.
type Process struct {
	mu       sync.Mutex
	identity Identity
	handle   int
	closed   bool
	inspect  func(context.Context, int) (Identity, error)
}

var acquired = struct {
	sync.Mutex
	byIdentity map[Identity]*Process
}{byIdentity: make(map[Identity]*Process)}

// Identity returns the immutable identity this handle acquired. It performs no
// process inspection and does not imply that the process is still alive.
func (p *Process) Identity() Identity {
	if p == nil {
		return Identity{}
	}
	return p.identity
}

func validIdentity(id Identity) bool {
	return id.BootID != "" && id.PID > 1 && id.StartTicks > 0 && id.UID >= 0 &&
		id.Executable.Device != 0 && id.Executable.Inode != 0
}

func sameIdentity(a, b Identity) bool { return a == b }

func registerProcess(p *Process) bool {
	acquired.Lock()
	defer acquired.Unlock()
	if _, exists := acquired.byIdentity[p.identity]; exists {
		return false
	}
	acquired.byIdentity[p.identity] = p
	return true
}

func unregisterProcess(p *Process) {
	acquired.Lock()
	defer acquired.Unlock()
	if acquired.byIdentity[p.identity] == p {
		delete(acquired.byIdentity, p.identity)
	}
}
