package clientwire

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// WindowsSuffix is the cross-OS virtual target suffix: "<tool>-windows" is a
// WSL daemon writing into the Windows-side home of the same machine.
const WindowsSuffix = "-windows"

// AdvertisedCapability resolves a write TARGET name to its registry row,
// applying the two rules every predicate below shares:
//
//  1. the cross-OS "-windows" virtual target resolves to its BASE adapter;
//     isWindows tells the caller to gate on that capability's own
//     CrossOSBridge flag;
//  2. a row the harness lifecycle policy no longer ADVERTISES (deprecated or
//     dead) is refused up front, so nothing wires a fresh install into a
//     sunset product. Capture is untouched: lifecycle gates advertising only
//     (docs/harness-lifecycle-policy.md).
//
// ok is false for an unknown tool and for an unadvertised one.
func AdvertisedCapability(tool string) (c integration.Capability, isWindows bool, ok bool) {
	base, isWindows := strings.CutSuffix(tool, WindowsSuffix)
	c, ok = integration.For(base)
	if !ok || !c.Advertised() {
		return integration.Capability{Tool: base}, isWindows, false
	}
	return c, isWindows, true
}

// HookSupported reports whether the hook registry can write tool's hooks AND
// the registry row says Observer auto-wires them. A mechanism with no
// registry writer (Hermes' plugin, the Cline CLI tailer, the browser
// extension), a manual registration (AutoWired false) and a writer switched
// off behind a live check (HookSpec.LiveGate, DEC-12) all answer false.
//
// A target in another home of the same tool (hook.HomeTargetBase: an Xcode
// agent home "claude-code-xcode", FU-145, or a WSL distro home reached from
// Windows "cursor-wsl", FU-197) answers for its base tool's hook capability,
// and only while the target itself is switched on (hook.LiveCheckGate;
// gemini-cli-xcode stays off on LCR-91's finding: Xcode's Gemini runs no
// BeforeTool, FU-195; every twin but cursor-wsl waits on WSL-4). It is a
// hook target only: AdvertisedCapability does not resolve it, so the MCP,
// route and telemetry predicates answer false for it. Whether its home
// exists here (macOS for Xcode; a Windows host's running WSL distros for a
// twin) is hook.Registry.Installed's answer, which every caller reads first.
func HookSupported(tool string) bool {
	if base, ok := hook.HomeTargetBase(tool); ok {
		if _, gated := hook.LiveCheckGate(tool); gated {
			return false
		}
		c, _, ok := AdvertisedCapability(base)
		return ok && c.Hook.AutoWiredNow() && hookRegistryWrites(c, false)
	}
	c, isWindows, ok := AdvertisedCapability(tool)
	if !ok || !c.Hook.AutoWiredNow() {
		return false
	}
	return hookRegistryWrites(c, isWindows)
}

// HookTargetCapability is the registry row a hook registration target
// answers for: AdvertisedCapability's (the "-windows" bridge resolves to its
// base), and for an other-home target (Xcode agent home, WSL twin) its base
// tool's row. ok is false for an unknown or unadvertised tool.
func HookTargetCapability(tool string) (integration.Capability, bool) {
	if base, ok := hook.HomeTargetBase(tool); ok {
		tool = base
	}
	c, _, ok := AdvertisedCapability(tool)
	return c, ok
}

// HookTargetBase is the adapter a hook registration target belongs to: the
// "-windows" bridge's base, an other-home target's base tool (Xcode agent
// home, WSL twin), else the target itself. Component gates and per-tool
// tables key on it.
func HookTargetBase(tool string) string {
	if base, ok := hook.HomeTargetBase(tool); ok {
		return base
	}
	return strings.TrimSuffix(tool, WindowsSuffix)
}

// HookRemovable reports whether a removal should ask the hook registry to
// remove tool's registration: every HookSupported tool, plus a tool whose
// mechanism has a registry writer but is no longer AUTO-WIRED (a retired
// registration an earlier version wrote). Unregister removes only Observer's
// own entries, so asking for a tool that was never registered is a no-op.
//
// An other-home target (Xcode agent home, WSL twin) is removable whenever
// its base tool's mechanism has a registry writer (Unregister is never
// gated).
func HookRemovable(tool string) bool {
	if base, ok := hook.HomeTargetBase(tool); ok {
		c, _, ok := AdvertisedCapability(base)
		return ok && hookRegistryWrites(c, false)
	}
	c, isWindows, ok := AdvertisedCapability(tool)
	if !ok {
		return false
	}
	return hookRegistryWrites(c, isWindows)
}

// hookRegistryWrites reports whether hook.Registry has a register / unregister
// writer for c's mechanism (and, for a foreign-OS target, a cross-OS bridge).
func hookRegistryWrites(c integration.Capability, isWindows bool) bool {
	if !hook.RegistryWrites(c.Hook.Mechanism) {
		return false
	}
	if isWindows {
		return c.Hook.CrossOSBridge
	}
	return true
}

// mcpRegistrarFormats is the closed set of MCP config formats mcp.Registrar
// writes (and removes). Hermes' YAML target is written by its own
// `observer init --hermes` path, so it is deliberately absent.
var mcpRegistrarFormats = map[integration.MCPFormat]bool{
	integration.MCPServersJSON:  true,
	integration.MCPCodexTOML:    true,
	integration.MCPOpenCodeJSON: true,
}

// MCPSupported reports whether mcp.Registrar can write (and remove) tool's
// MCP server entry: the SHAPE of the tool's MCP capability, never its name.
func MCPSupported(tool string) bool {
	c, isWindows, ok := AdvertisedCapability(tool)
	if !ok || c.MCP == nil || !c.MCP.Implemented {
		return false
	}
	if isWindows && !c.MCP.CrossOSBridge {
		return false
	}
	return mcpRegistrarFormats[c.MCP.Format]
}

// RouteSupported reports whether `observer init` PERSISTS a proxy route for
// tool into a per-tool config file: true only for the persisted route kinds
// the proxyroute.Registrar writes (RouteEnvSettings, RouteConfigFile).
// Launcher-routed and proxy-exempt tools answer false.
func RouteSupported(tool string) bool {
	c, isWindows, ok := AdvertisedCapability(tool)
	if !ok || c.Proxy == nil {
		return false
	}
	if isWindows && !c.Proxy.CrossOSBridge {
		return false
	}
	switch c.Proxy.Kind {
	case integration.RouteEnvSettings, integration.RouteConfigFile:
		return true
	default:
		return false
	}
}

// HookRegistrationWanted reports whether a hook registration for tool has
// anything to do: the tool's mechanism carries a registered binding whose
// feature is on. promptLaneEnabled is the prompt-submit engine's hook lane
// ([guard.prompt] enabled and hook_lane); the tool gate is treated as on.
// skip, when non-nil, excludes the bindings the caller will not write
// (`observer start` and the dashboard pass the auto-registration owes-live
// filter; `observer init` writes every registered binding and passes nil).
// An unknown or unadvertised tool answers true: the registry's own refusal
// is the honest answer there.
func HookRegistrationWanted(tool string, promptLaneEnabled bool, skip func(tool, event string) bool) bool {
	c, ok := HookTargetCapability(tool)
	if !ok {
		return true
	}
	h := c.Hook
	if skip != nil {
		kept := make([]integration.HookBinding, 0, len(h.Bindings))
		for _, b := range h.Bindings {
			if !skip(tool, b.NativeEvent) {
				kept = append(kept, b)
			}
		}
		h.Bindings = kept
	}
	return h.WantsRegistration(integration.HookFeatures{PromptGate: promptLaneEnabled, ToolGate: true})
}
