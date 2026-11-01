// hookbridge.go: `observer hook-bridge`, the fail-closed Windows hook bridge
// (surface-gap ruling AW-37, decision D12), and the `observer hook
// --bridge-sentinel` mapping it relies on. The Windows observer.exe runs the
// bridge for the tool-gate events of an ENFORCING MANAGED node: it starts
// the WSL daemon's `observer hook` through wsl.exe and, when wsl.exe could
// not start it (WSL down, disabled or broken), BLOCKS the call in the hook
// dialect's own fail-closed shape instead of letting the host read a stray
// exit code as "allow". The decisions are internal/hookbridge (pure, a
// table), the process internal/hookbridgesvc; this file parses the entry and
// writes the answer. The writer that puts the bridge into a settings file
// is switched off behind live check LC6 (integration.WriterKindHookBridge,
// DEC-12), so nothing runs this until LC6 grounds it.

package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/hookbridge"
	"github.com/marmutapp/superbased-observer/internal/hookbridgesvc"
)

// hookBridgeRun is the process seam (tests substitute a canned run).
var hookBridgeRun = hookbridgesvc.Run

// hookBridgeExit ends the bridge process (tests substitute a recorder).
var hookBridgeExit = os.Exit

// hookBridgeDeadline is the bridge's own deadline for a host timeout
// (hookbridge.Deadline; tests shorten it).
var hookBridgeDeadline = hookbridge.Deadline

func newHookBridgeCmd() *cobra.Command {
	var e hookbridge.Entry
	cmd := &cobra.Command{
		Use:    "hook-bridge",
		Short:  "Run a WSL daemon's hook from Windows, blocking a gated call when WSL cannot run it",
		Hidden: true,
		Args:   cobra.NoArgs,
		Long: "Written by Observer into a Windows tool's hook settings for the tool-gate\n" +
			"events of an enforcing managed node (built, waiting on live check LC6).\n" +
			"It starts the WSL daemon's `observer hook` through wsl.exe, passes stdin\n" +
			"through and replays the hook's stdout and stderr byte for byte; when\n" +
			"wsl.exe could not start the hook, it blocks the call with Observer's\n" +
			"fail-closed reason.",
		Run: func(cmd *cobra.Command, _ []string) {
			e.Bin, e.Config = hookbridge.NormalizePath(e.Bin), hookbridge.NormalizePath(e.Config)
			hookBridgeExit(runHookBridge(cmd.Context(), e, os.Getenv("SystemRoot"), os.Stdin, os.Stdout, os.Stderr))
		},
	}
	cmd.Flags().StringVar(&e.Distro, "distro", "", "WSL distribution the daemon runs in")
	cmd.Flags().StringVar(&e.Bin, "bin", "", "the observer binary inside the distribution")
	cmd.Flags().StringVar(&e.Tool, "tool", "", "the `observer hook` tool argument")
	cmd.Flags().StringVar(&e.Event, "event", "", "the `observer hook` event argument")
	cmd.Flags().StringVar(&e.Config, "config", "", "the observer config inside the distribution")
	return cmd
}

// runHookBridge runs one bridged hook and returns the exit code, having
// written the answer: the hook's own bytes when it ran (hookbridge.Decide
// passthrough rows), else the dialect's fail-closed reply.
//
// The run has its own deadline below the host's hook timeout (from the
// entry's registry binding, hookbridge.Deadline): a host that gives up on a
// hung hook lets the call through, so a wsl.exe that hangs (a VM that is
// starting, a stuck vmcompute) is killed first and the call is blocked with
// the timeout reason.
func runHookBridge(ctx context.Context, e hookbridge.Entry, systemRoot string, stdin io.Reader, stdout, stderr io.Writer) int {
	argv, err := e.Argv()
	var d hookbridge.Decision
	var res hookbridgesvc.Result
	if err != nil {
		d = hookbridge.Decide(hookbridge.Run{Started: false})
	} else {
		b, _ := resolveHookInvocationBinding(e.Tool, canonicalHookEvent(e.Tool, e.Event))
		runCtx, cancel := context.WithTimeout(ctx, hookBridgeDeadline(b.HostTimeout))
		res = hookBridgeRun(runCtx, hookbridge.WSLExe(systemRoot), argv, stdin)
		cancel()
		d = hookbridge.Decide(res.Run)
	}
	if d.Passthrough {
		_, _ = stdout.Write(res.Stdout)
		hookErr, notices := hookbridge.SplitWSLNotices(res.Stderr)
		_, _ = stderr.Write(hookErr)
		// On a hook's own exit-2 block the host shows stderr as the block
		// reason: wsl.exe's notices stay out of it. Otherwise they are
		// kept, named as wsl.exe's.
		if d.Outcome != hookbridge.OutcomeHookBlock && len(notices) > 0 {
			fmt.Fprintf(stderr, "observer hook-bridge: wsl.exe said: %s", notices)
		}
		return d.ExitCode
	}
	return writeHookBridgeBlock(e, d, stdout, stderr)
}

// writeHookBridgeBlock writes the fail-closed block of the entry's hook
// binding, the same reply `observer hook` writes when it fails under
// enforcement (hook.BuildFailClosedReply, the internal-error reason, or the
// timeout reason when the bridge's deadline fired). A
// binding with no blocking reply still blocks by exit code 2 with the reason
// on stderr: the bridge exists only for enforced tool gates.
func writeHookBridgeBlock(e hookbridge.Entry, d hookbridge.Decision, stdout, stderr io.Writer) int {
	reason := hook.FailClosedErrorReason
	if d.Outcome == hookbridge.OutcomeTimedOut {
		reason = hook.FailClosedTimeoutReason
	}
	b, bound := resolveHookInvocationBinding(e.Tool, canonicalHookEvent(e.Tool, e.Event))
	reply, ok := hook.FailClosedReply{}, false
	if bound {
		reply, ok = hook.BuildFailClosedReply(b.Dialect, reason)
	}
	if !ok {
		fmt.Fprintln(stderr, hook.StderrBlockReason(reason))
		return 2
	}
	if len(reply.Stdout) > 0 {
		_, _ = stdout.Write(reply.Stdout)
	}
	if reply.StderrReason {
		fmt.Fprintln(stderr, hook.StderrBlockReason(reason))
	} else {
		fmt.Fprintf(stderr, "observer hook-bridge: %s\n", d.Outcome)
	}
	return reply.ExitCode
}

// sentinelExit wraps an exit function with hookbridge.HookExit, for an
// `observer hook` invocation that carries hookbridge.SentinelFlag.
func sentinelExit(exit func(int)) func(int) {
	return func(code int) { exit(hookbridge.HookExit(code)) }
}

// hookbridgeSentinelFlagName is hookbridge.SentinelFlag without its dashes.
const hookbridgeSentinelFlagName = "bridge-sentinel"
