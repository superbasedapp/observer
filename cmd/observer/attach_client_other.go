//go:build !unix

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// runAttachSession is the non-unix stub for `observer <tool> --attach`.
//
// What is and is NOT missing here, as of DI-09 (T9): the DAEMON side now
// serves the attach control channel on native Windows — attachsock's Transport
// seam gives it a named pipe with an owner-only protected DACL, so
// `observer start` listens and `attachsock.Dial` connects. What is still
// missing is this INTERACTIVE CLIENT: it needs POSIX raw-mode termios,
// job-control signals (SIGTSTP/SIGCONT/SIGWINCH) and a deadline-capable
// /dev/tty reader — Attach's ClientReader contract (SetReadDeadline) is what
// guarantees no keystroke is forwarded after the session ends, and a Windows
// console handle does not satisfy it. A native console client (CONIN$ +
// SetConsoleMode + polled window size) is a separate, designed follow-up.
//
// Return an honest error instead of silently doing nothing, and keep the build
// green everywhere (B2-1).
func runAttachSession(_ context.Context, in attachLaunch) error {
	// Honest floor FIRST, exactly as the unix client does (attach_client_unix.go):
	// a tool with no grounded Attach capability cannot be attach-launched on ANY
	// platform, so say that rather than blaming the OS. Ordering matters — the
	// platform message below would otherwise mask a capability gap that is not
	// platform-specific at all.
	capab, ok := integration.For(in.tool)
	if !ok || capab.Attach == nil {
		msg := fmt.Sprintf(
			"observer: --attach is not available for %q — no grounded attach capability. Launch it without --attach.",
			in.tool,
		)
		if in.stderr != nil {
			fmt.Fprintln(in.stderr, msg)
		}
		return errors.New(msg)
	}

	// Name the LAUNCHER subcommand (e.g. `observer claude`), not the registry
	// tool name (`claude-code`), so the copy matches the command the operator
	// actually typed (B3-5). Fall back to the tool name if unresolved.
	label := in.tool
	if capab.Attach.Subcommand != "" {
		label = capab.Attach.Subcommand
	}
	msg := fmt.Sprintf(
		"observer %s --attach: the interactive attach client is not available on this OS yet. "+
			"The daemon does serve the attach channel here (%s), but the client needs a native console "+
			"implementation. Launch without --attach — dashboard launch and Jump-in work — or run the launcher inside WSL.",
		label, attachsock.DefaultTransport().Describe(),
	)
	if in.stderr != nil {
		fmt.Fprintln(in.stderr, msg)
	}
	return errors.New(msg)
}
