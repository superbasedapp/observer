//go:build !linux

package intervention

import (
	"context"
	"fmt"
)

// Inspect reports ErrUnsupported because an identity-safe backend has not been
// implemented on this operating system.
func Inspect(context.Context, int) (Identity, error) {
	return Identity{}, ErrUnsupported
}

// Acquire reports ErrUnsupported because an identity-safe backend has not been
// implemented on this operating system.
func Acquire(context.Context, Identity) (*Process, error) {
	return nil, ErrUnsupported
}

// Terminate reports ErrUnsupported on a non-Linux process handle.
func (p *Process) Terminate(context.Context) (ExitResult, error) {
	return ExitResult{}, ErrUnsupported
}

// Kill reports ErrUnsupported on a non-Linux process handle.
func (p *Process) Kill(context.Context) (ExitResult, error) {
	return ExitResult{}, ErrUnsupported
}

// SignalTerminate reports ErrUnsupported on a non-Linux process handle.
func (p *Process) SignalTerminate(context.Context) (ExitResult, error) {
	return ExitResult{}, ErrUnsupported
}

// SignalKill reports ErrUnsupported on a non-Linux process handle.
func (p *Process) SignalKill(context.Context) (ExitResult, error) {
	return ExitResult{}, ErrUnsupported
}

// WaitExit reports ErrUnsupported on a non-Linux process handle.
func (p *Process) WaitExit(context.Context) (ExitResult, error) {
	return ExitResult{}, ErrUnsupported
}

// Close releases a non-Linux placeholder handle without sending a signal.
func (p *Process) Close() error {
	if p == nil {
		return nil
	}
	return fmt.Errorf("intervention.Process.Close: %w", ErrUnsupported)
}
