//go:build sbo_omit_terminals

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/diag"
)

// terminals_omit.go stands in for the terminals component's cmd wiring in a
// build without it (-tags sbo_omit_terminals, lane MP-L1K, T-715): the PTY
// session manager, the terminal service, the attach socket server and
// client, the out-of-band channel, guided setup, workspaces and IDE / GUI
// launch are not linked (internal/termsession, termsvc, termrun, termfeed,
// termlease, termoob, termscan, termstatus, attachsock, workspace and
// guilaunch leave the binary). terminals.ssh and terminals.sandbox require
// terminals, so they leave with it.
//
// What such a build does instead of refusing (operator rule D-514): the
// daemon starts with no terminal stack (the dashboard's terminal routes
// answer as for a disabled launch manager and the New Terminal tools route
// answers component_not_installed), `observer start` prints one
// session-attach line, a tool launcher runs bare (a default-on attach has
// nothing to attach to, so it stays silent; an explicit --attach names the
// build), and `observer workspaces`, `observer ide` and `observer ssh` answer
// "not in this build" with exit 3. The launcher env scrub, the daemon-child
// marker and the tool preflight stay core (terminal_env.go,
// tool_install_plan.go), so a child still never inherits a channel variable.
func init() {
	components.MarkOmitted("terminals")
	components.MarkOmitted("terminals.ssh")
	components.MarkOmitted("terminals.sandbox")
}

// terminalsNotInBuild is the one reason line every refused terminal action
// prints.
func terminalsNotInBuild(what string) string {
	return fmt.Sprintf("%s: the terminals component is not in this build; %s.", what, components.DistrosHaving("terminals"))
}

// attachSocketHost has no implementation in this build: no attach host is
// ever built, so the value stays nil.
type attachSocketHost interface{}

// ptySupported is false: no PTY backend is linked.
func ptySupported() bool { return false }

// serveAttach refuses: the attach server is not in this build. start.go
// never reaches it (it reports session-attach disabled first).
func serveAttach(_ context.Context, ln net.Listener, _ attachSocketHost, _ *slog.Logger) error {
	if ln != nil {
		_ = ln.Close()
	}
	return errors.New(terminalsNotInBuild("session-attach"))
}

// buildTerminalSurfaces builds no terminal stack: every surface is the
// honest disabled zero value and close is a no-op.
func buildTerminalSurfaces(context.Context, config.Config, *sql.DB, *slog.Logger, *nodeFeaturesHandle) (terminalSurfaces, error) {
	return terminalSurfaces{close: func() {}}, nil
}

// wireRemoteExecuteTier has no terminal stack to arm.
func wireRemoteExecuteTier(config.Config, dashapi.LaunchManager, dashapi.RemoteController) {}

// projectRootResolver resolves no terminal project root (no runs exist).
func projectRootResolver(dashapi.LaunchManager) func(string) (dashapi.TerminalRoot, bool) {
	return nil
}

// sessionResolver links no terminal run to a session (no runs exist).
func sessionResolver(dashapi.LaunchManager) func(string) (dashapi.TerminalSessionLink, bool) {
	return nil
}

// acquireBareResumeClaim is a no-op: without the attach server there is no
// daemon-side attach-resume a bare resume could collide with.
func acquireBareResumeClaim(io.Writer, string, string, string) (release func(), ok bool) {
	return func() {}, true
}

// attachSocketReachable is false: no daemon in a build like this one serves
// the attach socket through this client.
func attachSocketReachable(string) bool { return false }

// runAttachSession refuses an explicit --attach, naming the build.
func runAttachSession(_ context.Context, in attachLaunch) error {
	msg := "observer: " + terminalsNotInBuild("--attach") + " Launch without --attach."
	if in.stderr != nil {
		fmt.Fprintln(in.stderr, msg)
	}
	return errors.New(msg)
}

// sandboxDoctorChecks adds nothing: the Components section of doctor
// already says the module is not in this build.
func sandboxDoctorChecks(context.Context, config.Config) []diag.Check { return nil }

// sandboxDoctorSection adds nothing and reports no sandbox: the module is
// not in this build.
func sandboxDoctorSection(context.Context, config.Config, string) ([]diag.Check, bool) {
	return nil, false
}

// newSandboxCmd registers `observer sandbox` as a compiled-out verb.
func newSandboxCmd() *cobra.Command {
	return compiledOutVerb("sandbox", "Sandboxes and VMs (not in this build)", "terminals.sandbox")
}

// newWorkspacesCmd registers `observer workspaces` as a compiled-out verb.
func newWorkspacesCmd() *cobra.Command {
	return compiledOutVerb("workspaces", "Sandbox workspaces (not in this build)", "terminals")
}

// newIDECmd registers `observer ide` as a compiled-out verb.
func newIDECmd() *cobra.Command {
	return compiledOutVerb("ide", "Launch an IDE or desktop app (not in this build)", "terminals")
}

// newSSHCmd registers `observer ssh` as a compiled-out verb (terminals.ssh
// requires terminals).
func newSSHCmd() *cobra.Command {
	return compiledOutVerb("ssh", "SSH terminals (not in this build)", "terminals.ssh")
}

// sandboxEnvMarker repeats internal/sandbox.EnvMarker: a build without the
// sandbox never sets it, but still strips a spoofed one from a child's env.
const sandboxEnvMarker = "OBSERVER_SANDBOX"

// sandboxTierRouteNotice says nothing in a build without the sandbox (no
// launch here ever runs inside one).
func sandboxTierRouteNotice(string, string) string { return "" }

// sandboxHelperDispatch runs no helper: a build without terminals never
// plans a sandboxed launch.
func sandboxHelperDispatch([]string) (int, bool) { return 0, false }

// guiPreflight answers the GUI rung of the tool preflight without the
// launcher's dry-run routing fact (the GUI launcher is not in this build):
// installed / how to install is still reported.
func guiPreflight(id, configPath string, allowInstall func() bool) (dashapi.ToolPreflight, bool) {
	return guiPreflightVerdict(id, configPath, allowInstall)
}

// attachInBuild is false: no attach server or client is linked, so the
// launchers treat every tool as not attach-grounded (a default-on attach is
// a silent bare launch; an explicit --attach names the build).
const attachInBuild = false

// sandboxSignInForbiddenSeam is nil in a build without terminals.
func sandboxSignInForbiddenSeam(string) func() bool { return nil }
