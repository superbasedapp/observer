package mcpregister

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/mcp/locate"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// The Windows to WSL twin of cline-windows (surface-gap Wave 7, DEC-10):
// "cline-wsl", a Windows-native daemon writing the observer MCP server into
// the shared Cline file of a Cline that runs inside a WSL distro (the VS
// Code extension in a Remote-WSL window, or the Cline CLI), reached as
// \\wsl.localhost\<distro>\home\<user>\.cline\data\settings\cline_mcp_settings.json.
//
// Cline spawns the server's command directly (child_process, no shell), so
// the entry runs the Windows observer.exe through WSL interop by its
// /mnt/<drive> spelling, and the MCP stdio stream crosses interop the way a
// Windows tool's stdio does. The distro's CLINE_* variables are not visible
// from Windows, so the vendor default under the home is the target.
//
// It waits on live check WSL-4 and lands switched off (DEC-12): Register
// writes nothing and says so, and Installed never lists it. Unregister
// still removes an entry.

// clineWSLLiveCheck is the live check cline-wsl waits on.
const clineWSLLiveCheck = "WSL-4"

// clineWSLGated is the gate switch: true until WSL-4 passes.
var clineWSLGated = true

// ClineWSLLiveGate reports whether cline-wsl is switched off behind a live
// check, and which one.
func ClineWSLLiveGate() (liveCheck string, gated bool) {
	return clineWSLLiveCheck, clineWSLGated
}

// wslHomeOwned is the WSL-home ownership seam (crossmount's rule).
var wslHomeOwned = crossmount.WSLHomeOwnedByCurrentUser

// registerClineWSL is Register("cline-wsl").
func (r *Registrar) registerClineWSL() RegistrationResult {
	if clineWSLGated {
		return RegistrationResult{
			Tool: "cline-wsl", DryRun: r.opts.DryRun, Skipped: true,
			SkipReason: integration.LiveGate(clineWSLLiveCheck).Text(),
			SkipAdvice: "nothing written; this target is switched off until live check " + clineWSLLiveCheck + " passes on a real host (--force does not lift this).",
		}
	}
	return r.writeClineWSL()
}

// writeClineWSL is registerClineWSL below the gate.
func (r *Registrar) writeClineWSL() RegistrationResult {
	res := RegistrationResult{Tool: "cline-wsl", DryRun: r.opts.DryRun}
	if r.foreignAutoDetectSuppressed(r.opts.WSLClineHome) {
		res.Skipped = true
		res.SkipReason = "HomeDir was pinned by the caller and WSLClineHome does not resolve inside it, so cross-OS WSL home resolution is suppressed (incident 2026-07-31)"
		res.SkipAdvice = "nothing written; a sandboxed caller must set WSLClineHome to a home UNDER its own HomeDir to wire this target (--force does not lift this)."
		return res
	}
	home := r.detectWSLClineHome()
	if home == "" {
		res.Error = errors.New("mcp.registerClineWSL: no WSL-side Cline install detected (set WSLClineHome to \\\\wsl.localhost\\<distro>\\home\\<user>, or run on a Windows host whose one WSL user has run a current Cline)")
		return res
	}
	loc, _ := locate.ForWSLHome("cline", home)
	if r.legacyOnlyAt(loc) {
		res.ConfigPath = loc.Path
		return legacyOnlySkip(res, loc)
	}
	command, err := wslInteropCommand(r.opts.BinaryPath)
	if err != nil {
		res.Error = err
		return res
	}
	args := []string{"serve"}
	if r.opts.ConfigPath != "" {
		args = append(args, "--config", strings.ReplaceAll(r.opts.ConfigPath, `\`, "/"))
	}
	// The shared file is the cline row's declared MCP file: the writer runs
	// under the base id (its declaration and credential handling) and the
	// result carries the twin's label.
	out := r.registerJSONMCPEntry("cline", loc.Path, mcpServerEntry{Command: command, Args: args})
	out.Tool = "cline-wsl"
	return out
}

// wslInteropCommand is the interop spelling of the Windows observer.exe
// (/mnt/c/.../observer.exe): only a drive path to an .exe runs from inside
// a distro (an npm .cmd launcher is a cmd.exe script interop does not run).
func wslInteropCommand(binary string) (string, error) {
	mnt, ok := crossmount.MountPathFromWindows(binary)
	if !ok || !strings.EqualFold(filepath.Ext(mnt), ".exe") {
		return "", fmt.Errorf("mcp.registerClineWSL: the WSL twin runs the Windows observer.exe through WSL interop, so the server command must be a Windows drive path to an .exe; %q is not", binary)
	}
	return mnt, nil
}

// detectWSLClineHome resolves the WSL home cline-wsl writes under: the
// WSLClineHome override, else the one WSL home this Windows host sees
// (origin wslhost:) that is proven the operator's and has Cline installed.
func (r *Registrar) detectWSLClineHome() string {
	if r.foreignAutoDetectSuppressed(r.opts.WSLClineHome) {
		return ""
	}
	if r.opts.WSLClineHome != "" {
		return r.opts.WSLClineHome
	}
	var found []string
	for _, h := range allHomes() {
		if !crossmount.IsWSLHostHome(h) || !wslHomeOwned(h.Path) {
			continue
		}
		if loc, ok := locate.ForWSLHome("cline", h.Path); ok && r.installedAt(loc) {
			found = append(found, h.Path)
		}
	}
	if len(found) == 1 {
		return found[0]
	}
	return ""
}

// wslSuffix names a Windows to WSL twin target ("cline-wsl").
const wslSuffix = "-wsl"

// unregisterWSLTwin removes the entry of tool, the "<client>-wsl" twin of a
// client whose MCP target declares CrossOSBridge, from the client's file
// under the detected WSL home (never gated). Today cline is the one such
// client, so the home is cline-wsl's.
func (r *Registrar) unregisterWSLTwin(tool, client string) UnregistrationResult {
	home := r.detectWSLClineHome()
	if home == "" {
		return UnregistrationResult{Tool: tool, Skipped: true, DryRun: r.opts.DryRun}
	}
	loc, _ := locate.ForWSLHome(client, home)
	out := r.unregisterLocation(client, loc)
	out.Tool = tool
	return out
}

// ClineWSLDetected reports whether a WSL-side Cline install is detected
// (for the doctor, which names the gate).
func (r *Registrar) ClineWSLDetected() bool { return r.detectWSLClineHome() != "" }
