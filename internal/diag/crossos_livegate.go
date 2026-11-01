package diag

import (
	"fmt"
	"os"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/mcpregister"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// checkCrossOSLiveGated reports every cross-OS hook target whose home is
// detected on this host but which is built and switched off behind a live
// check (hook.LiveCheckGate, DEC-12): the tool on the other side of the
// WSL / Windows pair has no Observer hook until the check passes. One WARN
// per target, named "<target>.hooks.live_gate" ("<target>.route.live_gate"
// for a proxy-route twin, "cline-wsl.mcp.live_gate" for the MCP twin) so `observer doctor
// <tool>` and `observer doctor hooks` both scope to it. homeOverride is the
// caller's raw HomeDir: a pinned home switches cross-OS detection off, so a
// sandboxed run reports nothing.
func checkCrossOSLiveGated(homeOverride, binaryPath string) []Check {
	if binaryPath == "" {
		binaryPath = "observer"
	}
	reg, err := hook.NewRegistry(hook.Options{
		BinaryPath: binaryPath, HomeDir: homeOverride, WSLDistro: os.Getenv("WSL_DISTRO_NAME"),
	})
	if err != nil {
		return nil
	}
	out := liveGatedChecks(reg.InstalledLiveGated())
	// The Windows to WSL proxy-route twins carry their own gate in
	// proxyroute; detection names no port, so any valid one serves.
	if rr, rerr := proxyroute.NewRegistrar(proxyroute.RegisterOptions{ProxyPort: 8820, HomeDir: homeOverride}); rerr == nil {
		for _, g := range rr.WSLRouteGatedTargets() {
			out = append(out, liveGatedCheck(g[0]+".route.live_gate", hook.LiveGate{Target: g[0] + " proxy route", LiveCheck: g[1]}))
		}
	}
	// The MCP twin cline-wsl carries its gate in mcpregister.
	if mr, merr := mcpregister.NewRegistrar(mcpregister.RegisterOptions{BinaryPath: binaryPath, HomeDir: homeOverride}); merr == nil && mr.ClineWSLDetected() {
		if id, gated := mcpregister.ClineWSLLiveGate(); gated {
			out = append(out, liveGatedCheck("cline-wsl.mcp.live_gate", hook.LiveGate{Target: "cline-wsl MCP server", LiveCheck: id}))
		}
	}
	return out
}

// liveGatedChecks renders gated targets as doctor rows.
func liveGatedChecks(gated []hook.LiveGate) []Check {
	out := make([]Check, 0, len(gated))
	for _, g := range gated {
		out = append(out, liveGatedCheck(g.Target+".hooks.live_gate", g))
	}
	return out
}

// liveGatedCheck is one gated target's row.
func liveGatedCheck(name string, g hook.LiveGate) Check {
	return Check{
		Name:    name,
		Status:  StatusWarn,
		Message: fmt.Sprintf("%s: %s; its home is detected but Observer writes nothing there yet", g.Target, g.Note()),
	}
}
