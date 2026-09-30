package mcprelay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/mcprelay/localpdp"
)

// wrapper.go is the TRUE stdio wrapper (§12.2, finding-28): spawned by the
// AI client in place of the original stdio MCP server, it spawns that
// original server itself and sits between the two stdio streams. Every
// client request is decided by the local PDP and recorded BEFORE the child
// sees it; the child's frames are relayed verbatim; cwd, env and signals
// are the original launch's.
//
// Lifetime vs signals (Sol P3+P4 finding 6): the child is NOT run under a
// cancelling context. A terminating signal the client sends the wrapper
// (SIGINT / SIGTERM / SIGHUP) is FORWARDED to the child first, the child
// gets WrapperOptions.Grace to handle it, and only then is it killed; every
// other signal is forwarded and nothing more. The wrapper ends when the
// client closes its stream (child stdin closed -> ExitGrace -> interrupt ->
// kill), when ctx ends (same ladder), or when the child exits on its own -
// in which case the child's exit status is propagated as a ChildExitError.

// LaunchSpec is the approved original stdio server launch (the
// mcp_relay_launch_spec row's orig_* columns with the env RESOLVED by the
// caller from its secret references - the spec never crosses the wire and
// is never journaled with raw values).
type LaunchSpec struct {
	ServerID string
	VServer  string
	Command  string
	Args     []string
	Cwd      string
	// Env is the child's full environment (KEY=VALUE): the wrapper's own
	// os.Environ() with the journaled secret-reference keys overlaid (the
	// composition root builds it; a one-variable environment is never
	// passed). nil inherits the wrapper's own.
	Env []string
}

// LaunchSpecs resolves an approved (client, server id) pair to its launch
// spec (the composition root adapts Lane N-M's journal store). client is
// the AI client tool id the wrapper was spawned for ("" = any client that
// journaled serverID, first match).
type LaunchSpecs interface {
	Lookup(ctx context.Context, client, serverID string) (LaunchSpec, error)
}

// WrapperOptions configure one stdio-wrapper run.
type WrapperOptions struct {
	Spec LaunchSpec
	// Stdin / Stdout are the CLIENT's pipes (the wrapper's own os.Stdin /
	// os.Stdout when launched by the client).
	Stdin  io.Reader
	Stdout io.Writer
	// Stderr receives the child's stderr (os.Stderr when nil).
	Stderr io.Writer
	// Attestor verifies the parent process (nil -> the platform default).
	Attestor Attestor
	// Clients is the signed registered-client list the parent is checked
	// against (nil -> no parent can be verified -> configured).
	Clients ClientRegistry
	// Signals, when set, are forwarded to the child (the cmd layer relays
	// SIGINT/SIGTERM/SIGHUP through signal.Notify - never a cancelling
	// context).
	Signals <-chan os.Signal
	// Corr anchors the stream to a coding session when the launcher knows
	// it (R11.8).
	Corr Correlation
	// ProjectDir is the wrapper process's OWN working directory, recorded
	// at spawn (the AI client launched the wrapper inside the project; P11
	// fold PF2). The relay resolves it to the project hash it attests on
	// every call of the stream (the node-local PDP principal's
	// sbo_project_hash); "" = no project context (project-scoped grants fail
	// closed). It is never the journaled LaunchSpec.Cwd, which is the
	// original entry's configuration, not where the client runs.
	ProjectDir string
	// ExitGrace bounds the wait for the child after the client closes its
	// stdin before the child is signalled/killed (zero -> 5 s).
	ExitGrace time.Duration
	// Grace is how long a forwarded terminating signal (SIGINT / SIGTERM /
	// SIGHUP) gives the child before it is killed (zero -> DefaultGrace).
	Grace time.Duration
}

// DefaultGrace is the forwarded-signal grace before SIGKILL.
const DefaultGrace = 5 * time.Second

// ErrChildFailed is wrapped when the original server exited with an error.
var ErrChildFailed = errors.New("mcprelay: the original MCP server exited with an error")

// ChildExitError carries the original server's exit status so the wrapper
// process can propagate it to the client (errors.Is(err, ErrChildFailed)).
type ChildExitError struct {
	// Code is the child's exit code (-1 when it was killed by a signal).
	Code int
	// Signal names the signal that killed the child ("" when it exited).
	Signal string
}

// Error implements error.
func (e *ChildExitError) Error() string {
	if e.Signal != "" {
		return fmt.Sprintf("%v: killed by %s", ErrChildFailed, e.Signal)
	}
	return fmt.Sprintf("%v: exit status %d", ErrChildFailed, e.Code)
}

// Unwrap makes errors.Is(err, ErrChildFailed) true.
func (e *ChildExitError) Unwrap() error { return ErrChildFailed }

// terminatingSignals are the forwarded signals that start the grace ->
// kill ladder; every other forwarded signal is delivered and nothing more.
var terminatingSignals = map[os.Signal]bool{os.Interrupt: true, syscall.SIGTERM: true, syscall.SIGHUP: true}

// ServeStdioWrapper runs the wrapper until the client closes its stream,
// ctx ends, or the child exits; see the file comment for the lifetime and
// signal contract. The attestation result is applied to every call on the
// stream.
func (r *Relay) ServeStdioWrapper(ctx context.Context, o WrapperOptions) error {
	if o.Spec.Command == "" {
		return errors.New("mcprelay.ServeStdioWrapper: launch spec has no command")
	}
	if o.Stdin == nil || o.Stdout == nil {
		return errors.New("mcprelay.ServeStdioWrapper: client stdin/stdout required")
	}
	o.applyDefaults()
	parent := o.Attestor.Attest(o.Clients)
	r.log().Info("mcprelay: stdio wrapper parent attestation", "attestation", parent.Attestation, "agent", parent.Agent, "reason", parent.Reason)

	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// No CommandContext: the child's lifetime is governed by the ladder
	// below, never by a context cancel racing a forwarded signal.
	cmd := exec.Command(o.Spec.Command, o.Spec.Args...) //nolint:gosec // G204: launching the operator-configured original MCP server is this wrapper's purpose; argv exec, no shell
	cmd.Dir = o.Spec.Cwd
	cmd.Env = o.Spec.Env
	cmd.Stderr = o.Stderr
	childIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("mcprelay.ServeStdioWrapper: stdin pipe: %w", err)
	}
	// The stdout pipe is OURS (os.Pipe), not cmd.StdoutPipe: exec.Wait
	// closes a StdoutPipe as soon as the process exits, which could drop a
	// final frame still buffered in it; with our own pipe the pump reads
	// to EOF (every writer closed) before anything is lost.
	outR, outW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("mcprelay.ServeStdioWrapper: stdout pipe: %w", err)
	}
	cmd.Stdout = outW
	if err := cmd.Start(); err != nil {
		_ = outR.Close()
		_ = outW.Close()
		return fmt.Errorf("mcprelay.ServeStdioWrapper: spawn %q: %w", o.Spec.Command, err)
	}
	_ = outW.Close() // the child holds its own copy
	defer func() { _ = outR.Close() }()

	spec := sessionSpec{
		target:      Target{VServer: o.Spec.VServer, ServerID: o.Spec.ServerID, Local: true},
		transport:   localpdp.TransportStdioWrapper,
		attestation: parent.Attestation,
		agent:       parent.Agent,
		product:     parent.Product,
		corr:        o.Corr,
		projectHash: r.projectHash(o.ProjectDir),
	}
	up := &childUpstream{in: childIn}
	s := newSession(r, spec, o.Stdin, o.Stdout, up)

	// child stdout -> client (verbatim, completions recorded).
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		fr := NewFrameReader(outR, 0)
		for {
			frame, err := fr.Next()
			if err != nil {
				return
			}
			if werr := s.reply(sessionCtx, frame); werr != nil {
				return
			}
		}
	}()
	// The child's exit, observed concurrently (safe: the stdout pipe is
	// ours, Wait cannot close it under the pump).
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	childExited := make(chan struct{})
	var exitOnce sync.Once
	observeExit := func(error) { exitOnce.Do(func() { close(childExited) }) }
	// signals -> child; a terminating one starts grace -> kill.
	if o.Signals != nil {
		go r.forwardSignals(sessionCtx, cmd, o.Signals, o.Grace, childExited)
	}
	// The client stream, mediated.
	runDone := make(chan error, 1)
	go func() { runDone <- s.run(sessionCtx) }()

	select {
	case werr := <-waitDone:
		// The child ended first (on its own, or after a forwarded signal):
		// propagate its status. The client's stream goroutine ends with the
		// client's pipe (the wrapper process exits right after).
		observeExit(werr)
		cancel()
		up.close()
		waitBounded(pumpDone, o.ExitGrace)
		return wrapExit(nil, werr)
	case runErr := <-runDone:
		// Client stream ended (EOF) or ctx cancelled: shut the child down in
		// the order a client would - close its stdin, wait, then interrupt.
		up.close()
		select {
		case werr := <-waitDone:
			observeExit(werr)
			waitBounded(pumpDone, o.ExitGrace)
			return wrapExit(runErr, werr)
		case <-time.After(o.ExitGrace):
		}
		if cmd.Process != nil {
			_ = cmd.Process.Signal(os.Interrupt)
		}
		select {
		case werr := <-waitDone:
			observeExit(werr)
			waitBounded(pumpDone, o.ExitGrace)
			return wrapExit(runErr, werr)
		case <-time.After(o.ExitGrace):
		}
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		werr := <-waitDone
		observeExit(werr)
		waitBounded(pumpDone, o.ExitGrace)
		return wrapExit(runErr, werr)
	}
}

// applyDefaults fills the zero-valued WrapperOptions fields with their
// documented defaults.
func (o *WrapperOptions) applyDefaults() {
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.Attestor == nil {
		o.Attestor = DefaultAttestor()
	}
	if o.ExitGrace <= 0 {
		o.ExitGrace = 5 * time.Second
	}
	if o.Grace <= 0 {
		o.Grace = DefaultGrace
	}
}

// forwardSignals relays signals to the child until it exits, ctx ends or
// the channel closes; a terminating signal starts the grace -> kill ladder
// and ends forwarding.
func (r *Relay) forwardSignals(ctx context.Context, cmd *exec.Cmd, signals <-chan os.Signal, grace time.Duration, childExited <-chan struct{}) {
	for {
		select {
		case <-childExited:
			return
		case <-ctx.Done():
			return
		case sig, ok := <-signals:
			if !ok {
				return
			}
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
			if !terminatingSignals[sig] {
				continue
			}
			select {
			case <-childExited:
			case <-time.After(grace):
				r.log().Warn("mcprelay: original server ignored the forwarded signal; killing it", "signal", sig.String(), "grace", grace.String())
				_ = cmd.Process.Kill()
			}
			return
		}
	}
}

// waitBounded waits for done, giving up after d (a grandchild holding the
// child's stdout open must never wedge the wrapper).
func waitBounded(done <-chan struct{}, d time.Duration) {
	select {
	case <-done:
	case <-time.After(d):
	}
}

func wrapExit(runErr, waitErr error) error {
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		return runErr
	}
	var ee *exec.ExitError
	if errors.As(waitErr, &ee) {
		ce := &ChildExitError{Code: ee.ExitCode()}
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			ce.Signal = ws.Signal().String()
		}
		return ce
	}
	return nil
}

// childUpstream writes decided client frames to the child's stdin.
type childUpstream struct {
	mu     sync.Mutex
	in     io.WriteCloser
	closed bool
}

// Send implements Upstream: the frame's bytes go to the child unchanged.
func (u *childUpstream) Send(_ context.Context, c Call, _ Verdict) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return errors.New("child stdin closed")
	}
	return WriteFrame(u.in, c.Raw)
}

func (u *childUpstream) close() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.closed {
		u.closed = true
		_ = u.in.Close()
	}
}
