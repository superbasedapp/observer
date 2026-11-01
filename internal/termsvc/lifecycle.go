package termsvc

import (
	"context"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// lifecycle.go is the sandbox lifecycle service (sandbox plan v2 section
// 4.6, phase P1a): the eight explicit operations a sandbox driver exposes,
// each returning a plain result and a typed verdict. The shipped Sandboxer
// seam (Prepare) could only describe a synchronous bwrap prefix; a container,
// a VM or a hosted box needs an asynchronous create, a separate attach, and
// resize, signal, copy, checkpoint, stop and destroy outside the PTY.
//
// Prepare survives as the composition Create then Attach (ComposePrepare),
// so every caller that reads PrepareResult.Dir and WrapArgv is untouched and
// the bwrap argv stays byte-identical. The daemon calls the remaining
// operations (teardown, checkpoint timer, orphan sweep, update deferral)
// through the same interface as drivers grow them.

// SandboxRun names one prepared sandbox run to the lifecycle operations.
type SandboxRun struct {
	// ID is the run's workspace id (minted by Create).
	ID string
	// Tool is the target tool.
	Tool string
	// Dir is the run's workspace directory.
	Dir string
	// ProjectRoot is the host's attribution of the run (the project the
	// launch was authorized for); additive, empty for a driver that does
	// not need it.
	ProjectRoot string
	// Copy reports a managed (non-live) workspace: the agent edits a copy.
	Copy bool
}

// CreateResult is what Create prepared: the run handle, its workspace, the
// isolation evidence computed for it and an operator note.
type CreateResult struct {
	Run       SandboxRun
	Isolation termrun.Isolation
	Note      string
	// ProxyRouted: the launch will actually go through the Observer proxy
	// (the route the launch gets, not the registry row). Attach composes the
	// network posture from the same fact the evidence was computed from.
	ProxyRouted bool
	// SignInShared names the tool whose own state, sign-in included, the
	// backend binds into the box (operator ruling P-183): "" for a run that
	// projects the tool's state, a hosted row, or a tool with no sign-in
	// row. Additive.
	SignInShared string
}

// AttachResult is how the PTY child enters the run: the argv prefix the
// launcher prepends (empty for a backend that needs none).
type AttachResult struct {
	WrapArgv []string
}

// LifecycleVerdict is the typed outcome of a non-composing operation.
type LifecycleVerdict string

// The closed LifecycleVerdict vocabulary.
const (
	// VerdictDone: the driver performed the operation.
	VerdictDone LifecycleVerdict = "done"
	// VerdictPTYOwned: the operation belongs to the daemon's PTY for this
	// driver (bwrap: the agent is a direct child of the host PTY, so a
	// resize or a signal goes through termsession), so the driver does
	// nothing and the caller must not treat it as a failure.
	VerdictPTYOwned LifecycleVerdict = "pty_owned"
	// VerdictNotSupported: the driver cannot do this at all (bwrap has no
	// checkpoint); the caller must not pretend it happened.
	VerdictNotSupported LifecycleVerdict = "not_supported"
	// VerdictNothingToRelease: the run holds nothing the driver must free
	// (the host helper already removed its sockets and placeholders).
	VerdictNothingToRelease LifecycleVerdict = "nothing_to_release"
)

// LifecycleResult is the plain result of Resize, Signal, Copy, Checkpoint,
// Stop and Destroy.
type LifecycleResult struct {
	Verdict LifecycleVerdict
	// Detail is a short operator-facing sentence (no path, no argv).
	Detail string
}

// CopyRequest names one copy between the host and a run.
type CopyRequest struct {
	Run SandboxRun
	// ToBox: copy from the host into the run; false copies out.
	ToBox bool
	// HostPath and BoxPath are absolute.
	HostPath string
	BoxPath  string
}

// SandboxLifecycle is the eight-operation lifecycle service a sandbox driver
// implements behind the one seam.
type SandboxLifecycle interface {
	// Create prepares the run (workspace, evidence) without starting it.
	Create(ctx context.Context, req PrepareRequest) (CreateResult, error)
	// Attach returns how the PTY child enters the created run.
	Attach(ctx context.Context, created CreateResult) (AttachResult, error)
	// Resize changes the run's terminal size outside the PTY.
	Resize(ctx context.Context, run SandboxRun, rows, cols uint16) (LifecycleResult, error)
	// Signal delivers a signal (by name, for example "TERM") to the run.
	Signal(ctx context.Context, run SandboxRun, signal string) (LifecycleResult, error)
	// Copy moves one file or directory between the host and the run.
	Copy(ctx context.Context, req CopyRequest) (LifecycleResult, error)
	// Checkpoint saves the run's state for a later restore.
	Checkpoint(ctx context.Context, run SandboxRun) (LifecycleResult, error)
	// Stop asks the run to end within grace.
	Stop(ctx context.Context, run SandboxRun, grace time.Duration) (LifecycleResult, error)
	// Destroy releases everything the run holds.
	Destroy(ctx context.Context, run SandboxRun) (LifecycleResult, error)
}

// ComposePrepare is Prepare as the composition Create then Attach, so a
// SandboxLifecycle driver satisfies the shipped Sandboxer seam unchanged.
// An Attach failure after a successful Create destroys the run before
// returning, so a failed launch leaves nothing behind. That holds because
// a driver's Destroy of a run that was never attached releases everything
// Create made, its managed workspace included (the bwrap driver does since
// lane sbx-p2, P-017 (f)), and a Create that fails removes what it made
// itself.
func ComposePrepare(ctx context.Context, lc SandboxLifecycle, req PrepareRequest) (PrepareResult, error) {
	created, err := lc.Create(ctx, req)
	if err != nil {
		return PrepareResult{}, err
	}
	// The agent's own-sandbox switch is decided from Create's evidence (N6):
	// a state the tool has no per-run switch for refuses here, before the
	// run is attached, and the created run is destroyed, so a refused launch
	// leaves no prepared workspace behind (SBX-P3D audit finding 9).
	// LaunchFresh applies the same function to the same state afterwards.
	if req.Tool != ShellTool {
		if _, serr := integration.NativeSwitchArgsForState(req.Tool, vocab.NativeSandboxState(created.Isolation.NativeSandboxState)); serr != nil {
			if _, derr := lc.Destroy(ctx, created.Run); derr != nil {
				return PrepareResult{}, fmt.Errorf("%w (and destroying the run failed: %w)", serr, derr)
			}
			return PrepareResult{}, serr
		}
	}
	att, err := lc.Attach(ctx, created)
	if err != nil {
		if _, derr := lc.Destroy(ctx, created.Run); derr != nil {
			return PrepareResult{}, fmt.Errorf("%w (and destroying the run failed: %w)", err, derr)
		}
		return PrepareResult{}, err
	}
	return PrepareResult{
		Dir:          created.Run.Dir,
		WrapArgv:     att.WrapArgv,
		Note:         created.Note,
		Isolation:    created.Isolation,
		SignInShared: created.SignInShared,
	}, nil
}
