package main

import (
	"fmt"
	"os"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guardfallback"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// launch_sandbox_gate.go is the ONE owner of the "proxied tool without a
// sandbox" launch decision (D-178 / D-221 / D-333, T-497). Before T-497 the
// org's org_disallow choice was honoured only by the dashboard's fresh
// launch (launchManagerAdapter.CreateFresh); `observer <tool>` typed in any
// terminal started the same tool unsandboxed, so the org setting was a
// dashboard preference rather than a node rule. Both paths now ask this file
// and render the same reason, so they cannot drift. The launch-gate table
// (launch_gates.go, row sandbox.select) is what calls the decision on both
// paths and fixes its place among the other launch gates.

// sandboxLaunchOutcome is what a launch must do about the sandbox.
type sandboxLaunchOutcome int

const (
	// sandboxLaunchProceed: launch as requested.
	sandboxLaunchProceed sandboxLaunchOutcome = iota
	// sandboxLaunchUpgrade: the tool can only be contained by the sandbox and
	// one is available here, so an unsandboxed request is upgraded.
	sandboxLaunchUpgrade
	// sandboxLaunchRefuse: no sandbox here and the organization chose
	// org_disallow for a proxied tool without one.
	sandboxLaunchRefuse
)

// sandboxLaunchDecision is the decision itself. gd is the node's guard (nil
// or not enforcing for the tool family: proceed); sandboxed says the launch
// is already inside a sandbox (never downgraded, never refused);
// sandboxAvailable is consulted only when it matters; gate reports whether a
// tool's blocking hook is registered and current here (D-262).
//
// "Enforcing" is the tool family's own answer (Guard.GateEnforcement.Tool,
// review M2-13): the global mode is enforce, or an effective rule is
// per-rule enforced, or an org bundle is unverifiable on a managed node.
func sandboxLaunchDecision(gd *guard.Guard, tool string, sandboxed bool, sandboxAvailable func() bool, gate func(string) nodeToolGateState) sandboxLaunchOutcome {
	if gd == nil || sandboxed || !gd.GateEnforcement().Tool {
		return sandboxLaunchProceed
	}
	available := sandboxAvailable != nil && sandboxAvailable()
	noSandbox := integration.EnforcementChannel(gd.OrgFallbacks().Get(guardfallback.KeySandboxUnavailable))
	switch launchEnforcement(tool, available, gate, noSandbox) {
	case integration.EnforceSandbox:
		return sandboxLaunchUpgrade
	case integration.EnforceOrgDisallow:
		return sandboxLaunchRefuse
	default:
		return sandboxLaunchProceed
	}
}

// sandboxRefusalReason is the one wording of the refusal, naming the org
// setting by its dashboard label and value so a developer knows exactly
// which choice stopped the launch and who owns it.
func sandboxRefusalReason(tool string) string {
	label := guardfallback.KeySandboxUnavailable
	if s, ok := guardfallback.Lookup(guardfallback.KeySandboxUnavailable); ok {
		label = s.Label
	}
	return fmt.Sprintf("%s has no working blocking hook or sandbox here; org guard setting %q is %s",
		tool, label, guardfallback.SandboxOrgDisallow)
}

// sandboxRefusalError carries the refusal text while matching
// dashapi.ErrLaunchSandboxRequired (errors.Is), so the dashboard maps it to
// its 403 and the CLI recognises it, without the sentinel's own wording
// taking room in the dashboard's 200-byte error display.
type sandboxRefusalError struct{ msg string }

func (e sandboxRefusalError) Error() string { return e.msg }

func (e sandboxRefusalError) Unwrap() error { return dashapi.ErrLaunchSandboxRequired }

// dashboardSandboxRefusal is the dashboard's fresh-launch refusal. Kept under
// 200 bytes for the longest proxied tool name (pinned by
// TestCreateFreshSandboxFallback).
func dashboardSandboxRefusal(tool string) error {
	return sandboxRefusalError{msg: sandboxRefusalReason(tool) + "; turn on the sandbox (Terminals > Settings) or ask your admin"}
}

// cliSandboxRefusal is the `observer <tool>` refusal, shown at the terminal.
func cliSandboxRefusal(tool string) error {
	msg := fmt.Sprintf("observer %s: refusing to start the AI process: %s. A command-line launch never runs in a sandbox; "+
		"start it from the dashboard (Terminals > New Terminal, sandbox isolation on) on a machine that supports one, or ask your admin",
		tool, sandboxRefusalReason(tool))
	return newVisibleLauncherError(sandboxRefusalError{msg: msg}, msg)
}

// cliSandboxedEnv reports whether this process runs inside a sandbox the
// dashboard built (its launch already passed sandboxLaunchDecision). A seam
// so tests do not depend on the ambient environment. The marker is not a
// security boundary (D-233): a user who sets it by hand bypasses only an
// honest-UX refusal, never a hook, the proxy or the org's view of the launch.
var cliSandboxedEnv = func() bool { return os.Getenv(sandboxEnvMarker) == "1" }

// cliLaunchGuard builds the node's guard for a CLI launch from the same
// inputs the daemon and the hook fallback use (nodeGuard). A seam for tests.
var cliLaunchGuard = nodeGuard

// cliLaunchToolGate is the CLI's view of a tool's blocking hook on this
// node, the same reader the dashboard adapter holds. A seam for tests.
var cliLaunchToolGate = func(configPath, tool string) nodeToolGateState {
	bin, err := os.Executable()
	if err != nil {
		return nodeToolGateState{Tool: tool}
	}
	return nodeToolGate(bin, configPath, tool)
}

// cliLaunchDir is the directory an `observer <tool>` launch starts the tool
// in (the process's working directory). A seam for tests.
var cliLaunchDir = os.Getwd
