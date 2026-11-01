package main

import (
	"context"
	"fmt"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/hookdisable"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// The node's EFFECTIVE tool-call enforcement (T-340 follow-up, security).
//
// The registry's hook_block says a tool CAN deny a call through its
// live-verified tool-gate hook. On a given node that hook may not be there:
// auto-register is off, the user never ran init, the hook was removed, the
// host has not trusted it, a vendor switch turned hooks off, or an older
// Observer left a script that no longer gates (the legacy `observer hook
// cline` script fails open). Trusting the capability alone would launch an
// enforcing node's tool with neither a sandbox nor a working gate, so every
// enforcement decision on this node asks nodeToolGate first and passes the
// answer to integration.Capability.NodeEnforcement.
//
// "Registered and current" is read from the same sources `observer doctor
// --hooks` uses: the registration writers in DryRun mode (an event counts
// only when it carries the exact command Observer writes today, so a stale
// binary path or a legacy script reads as not registered), the host's trust
// step, and the vendor hook-disable switches.

// nodeToolGateState is this node's verdict on one tool's tool-gate hook.
type nodeToolGateState struct {
	Tool string
	// Current is true only when every live-verified blocking tool-gate
	// binding of the tool is registered as Observer writes it today,
	// trusted where the host has a trust step, and not switched off.
	Current bool
	// Installed is false when the tool has no config home on this machine.
	Installed bool
	// Reason says why the hook does or does not hold, as a clause.
	Reason string
}

// toolGateRegReason is the reason clause per registration verdict
// (bindingRegistration's vocabulary) for a binding that does not hold.
var toolGateRegReason = map[string]string{
	"no":       "its %s hook is missing or stale (not the command Observer writes today)",
	"conflict": "its %s hook conflicts with an entry Observer did not write",
	"unknown":  "its %s hook registration could not be read",
	"n/a":      "its %s hook cannot be registered here (not applicable on this platform)",
}

// liveBlockingToolGateBindings are the bindings that make a row hook_block
// (integration.HookSpec.LiveBlockingToolGate), one per native event.
func liveBlockingToolGateBindings(c integration.Capability) []integration.HookBinding {
	var out []integration.HookBinding
	for _, b := range wiredToolGateBindings(c) {
		if b.Grounding.Kind == integration.GroundingLive && b.HasDecision(integration.HookDecisionDeny) {
			out = append(out, b)
		}
	}
	return out
}

// nodeToolGate reads whether tool's blocking tool-gate hook is registered
// and current on this machine. It never writes, and it fails closed: any
// state it cannot confirm reads as not current.
func nodeToolGate(binary, configPath, tool string) nodeToolGateState {
	c, ok := integration.For(tool)
	if !ok {
		return nodeToolGateState{Tool: tool, Installed: true, Reason: "not a registry adapter"}
	}
	return nodeToolGateFor(c, binary, configPath)
}

// nodeToolGateFor is nodeToolGate over one capability row.
func nodeToolGateFor(c integration.Capability, binary, configPath string) nodeToolGateState {
	tool := c.Tool
	st := nodeToolGateState{Tool: tool, Installed: true}
	bindings := liveBlockingToolGateBindings(c)
	if len(bindings) == 0 {
		st.Reason = "no live-verified blocking tool-gate hook"
		return st
	}
	if !c.Hook.AutoWired {
		st.Reason = "its tool-gate hook is installed by hand, so Observer cannot confirm it"
		return st
	}
	if !hookInstalled(binary, configPath, tool) {
		st.Installed = false
		st.Reason = "not installed on this machine (no config home), so no hook is registered"
		return st
	}
	homes := launchHookHomes(c, readHookHomeEvents(binary, configPath, tool))
	home := probeHookHome(binary, configPath)
	trust := diag.HookTrustFor(c.Hook.Mechanism, home)
	var events []string
	for _, b := range bindings {
		reg, _ := bindingRegistration(c, b, homes)
		if reg != "yes" {
			format, known := toolGateRegReason[reg]
			if !known {
				format = toolGateRegReason["unknown"]
			}
			st.Reason = fmt.Sprintf(format, b.NativeEvent)
			return st
		}
		if t := bindingTrusted(trust, b, reg); t == "no" || t == "unknown" {
			st.Reason = fmt.Sprintf("its %s hook is registered but not trusted by the host", b.NativeEvent)
			return st
		}
		events = append(events, b.NativeEvent)
	}
	for _, f := range hookdisable.Detect(diag.HookSwitchInputs(hookdisable.Options{Home: home, GOOS: runtime.GOOS, ReadFile: diag.ReadHookSwitchFile})) {
		if slices.Contains(f.Tools, tool) {
			st.Reason = "hooks are switched off (" + f.Key + " in " + f.Path + ")"
			return st
		}
	}
	st.Current = true
	st.Reason = fmt.Sprintf("its %s hook is registered and current", strings.Join(events, ", "))
	return st
}

// Config homes a hook registration is read from (readHookHomeEvents).
const (
	hookHomeNative = "native"
	hookHomeBridge = "bridge"
	// hookHomeXcode is an Xcode agent home (the hook doctor's
	// xcodeHookChecks; never a launch home).
	hookHomeXcode = "xcode"
	// hookHomeWSL is a WSL distro's Linux home a Windows observer writes a
	// "-wsl" twin into (the hook doctor's wslHookChecks, FU-211).
	hookHomeWSL = "wsl"
)

// launchHookHomes keeps only the config home whose hook governs a launch of
// c on this node (review M2-06). A tool installed both natively and on the
// Windows side of a WSL host has two homes; the hook that runs is the one
// in the home of the binary the launch resolves, so a current bridge hook
// must not stand in for a missing native one (or the reverse). With one
// home there is nothing to choose and the binary is not resolved at all.
func launchHookHomes(c integration.Capability, homes []hookHomeEvents) []hookHomeEvents {
	if len(homes) < 2 {
		return homes
	}
	want := toolGateLaunchHome(c)
	var out []hookHomeEvents
	for _, h := range homes {
		if h.home == want {
			out = append(out, h)
		}
	}
	return out
}

// toolGateLaunchHome names the home of the binary a launch of c resolves on
// this node (a seam: tests pin it). The resolution is the launcher's own
// ladder (toolresolve), so the gate reads the same binary the launch runs.
var toolGateLaunchHome = func(c integration.Capability) string {
	if c.Binary == nil {
		return hookHomeNative
	}
	return launchHomeForResolution(toolresolve.Resolve(*c.Binary, dashResolveEnv()))
}

// launchHomeForResolution maps a resolution onto the home whose hook runs:
// the bridge (Windows-side) home when the only launchable binary is a
// Windows install reached through WSL interop, the native home otherwise
// (a native binary, or nothing launchable, where the native home is the
// honest default because no other hook can run either).
func launchHomeForResolution(r toolresolve.Resolution) string {
	if _, interop := toolresolve.ForeignInteropLaunchable(r); interop {
		return hookHomeBridge
	}
	return hookHomeNative
}

// launchHookSwitchDirs is the directories whose project-scope hook switches
// govern a launch in dir (T-910): dir itself and, when different, the
// checkout's top level above it (Claude Code reads the working directory's
// .claude, Copilot CLI the repository's .github/copilot; in a linked
// worktree both read the worktree's own files, git.FindCheckoutRoot).
func launchHookSwitchDirs(dir string) []string {
	if dir == "" {
		return nil
	}
	out := []string{dir}
	if root, ok := git.FindCheckoutRoot(dir); ok && root != dir {
		out = append(out, root)
	}
	return out
}

// withProjectHookSwitches narrows a node tool-gate reader to one launch: a
// hook that is current on the node is NOT current for a launch whose
// project sets a switch that silences the tool (T-910), so an enforce-mode
// launch there falls back exactly like a tool whose hook does not hold
// (D-262). It reads only; Observer never edits the project file. A nil gate
// or no directory returns gate unchanged.
func withProjectHookSwitches(gate func(string) nodeToolGateState, dirs []string) func(string) nodeToolGateState {
	if gate == nil || len(dirs) == 0 {
		return gate
	}
	return func(tool string) nodeToolGateState {
		st := gate(tool)
		if !st.Current {
			return st
		}
		for _, f := range hookdisable.Detect(hookdisable.Options{ProjectRoots: dirs, ReadFile: diag.ReadHookSwitchFile}) {
			if slices.Contains(f.Tools, tool) {
				st.Current = false
				st.Reason = "hooks are switched off in this project (" + f.Key + " in " + f.Path + ")"
				return st
			}
		}
		return st
	}
}

// daemonToolGate is nodeToolGate for the running daemon: its own binary and
// --config, the pair its hooks are registered with.
func daemonToolGate(tool string) nodeToolGateState {
	bin, err := absoluteBinaryPath()
	if err != nil {
		return nodeToolGateState{Tool: tool, Installed: true, Reason: "the observer binary path is unknown"}
	}
	return nodeToolGate(bin, daemonConfigPath(), tool)
}

// toolGateCurrent asks gate only for a row whose capability is hook_block (no
// other row's channel depends on it). A nil gate is not current.
func toolGateCurrent(c integration.Capability, gate func(string) nodeToolGateState) bool {
	if gate == nil || c.EnforcementChannel() != integration.EnforceHookBlock {
		return false
	}
	return gate(c.Tool).Current
}

// launchAutoSandbox is the enforce-mode launch decision for an unsandboxed
// request: sandbox the run when the tool's channel ON THIS NODE is
// sandbox_enforce, including a hook_block tool whose hook is not registered
// and current here.
func launchAutoSandbox(tool string, sandboxAvailable bool, gate func(string) nodeToolGateState) bool {
	return launchEnforcement(tool, sandboxAvailable, gate, integration.EnforceRecordedAcceptance) == integration.EnforceSandbox
}

// launchEnforcement is the enforce-mode launch channel for an unsandboxed
// request ON THIS NODE (D-262): the node's own tool-gate state, the
// platform's sandbox, and the organization's choice of what a missing
// sandbox degrades to (noSandbox, D-178), in one call. A hook_block tool
// whose gate is not registered and current here falls through to the
// sandbox, and from there to the org's fallback, exactly like a tool with no
// hook. An unknown tool has no lever (recorded_acceptance).
func launchEnforcement(tool string, sandboxAvailable bool, gate func(string) nodeToolGateState, noSandbox integration.EnforcementChannel) integration.EnforcementChannel {
	c, ok := integration.For(tool)
	if !ok {
		return integration.EnforceRecordedAcceptance
	}
	return c.EffectiveEnforcementUnder(toolGateCurrent(c, gate), sandboxAvailable, noSandbox)
}

// hookBlockTools is every registry tool whose capability is hook_block, sorted.
func hookBlockTools() []string {
	var out []string
	for _, c := range integration.Capabilities() {
		if c.EnforcementChannel() == integration.EnforceHookBlock {
			out = append(out, c.Tool)
		}
	}
	sort.Strings(out)
	return out
}

// toolGateEnforcementChecks is `observer doctor`'s one line per hook_block
// tool: does hook_block hold on this node, and if not, what the tool falls
// back to and why. A tool that is not installed is informational (OK); an
// installed tool whose hook does not hold is a WARN with the remedy.
// sandboxAvailable is this node's real sandbox availability (doctor's own
// probe, sandboxDoctorSection), never assumed: the fallback is
// sandbox_enforce only where a sandbox can be built, else recorded
// acceptance (live check macOS 2026-10-22, D2).
func toolGateEnforcementChecks(sandboxAvailable bool, gate func(string) nodeToolGateState) []diag.Check {
	var out []diag.Check
	for _, tool := range hookBlockTools() {
		c, _ := integration.For(tool)
		st := gate(tool)
		ck := diag.Check{Name: "hooks.enforcement:" + tool, Status: diag.StatusOK}
		if st.Current {
			ck.Message = fmt.Sprintf("%s: hook_block on this node (%s)", tool, st.Reason)
			out = append(out, ck)
			continue
		}
		fallback := c.NodeEnforcement(false, sandboxAvailable)
		ck.Message = fmt.Sprintf("%s: %s on this node, not hook_block: %s", tool, fallback, st.Reason)
		if st.Installed {
			ck.Status = diag.StatusWarn
			ck.Details = []string{
				"in guard enforce mode its dashboard launches run sandboxed where sandboxing is available",
				"remedy: " + autoRegisterRemediation(tool),
			}
		}
		out = append(out, ck)
	}
	return out
}

// guardToolGatesSeam answers the Security page's per-tool question: which
// hook_block tools actually block by hook on this node, and the channel the
// others fall back to (sandbox availability from the daemon's own prober).
func guardToolGatesSeam(configPath string, prober dashapi.SandboxProber) func() []dashapi.GuardToolGate {
	return func() []dashapi.GuardToolGate {
		bin, err := absoluteBinaryPath()
		gate := func(tool string) nodeToolGateState {
			if err != nil {
				return nodeToolGateState{Tool: tool, Installed: true, Reason: "the observer binary path is unknown"}
			}
			return nodeToolGate(bin, configPath, tool)
		}
		sandbox := prober != nil && prober.ProbeSandbox(context.Background()).Available
		var out []dashapi.GuardToolGate
		for _, tool := range hookBlockTools() {
			c, _ := integration.For(tool)
			st := gate(tool)
			out = append(out, dashapi.GuardToolGate{
				Tool:      tool,
				Channel:   string(c.NodeEnforcement(st.Current, sandbox)),
				Current:   st.Current,
				Installed: st.Installed,
				Reason:    st.Reason,
			})
		}
		return out
	}
}
