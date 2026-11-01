package hook

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// # Windows to WSL twins (surface-gap Wave 7, D7 / DEC-10)
//
// Every WSL to Windows "<tool>-windows" target (a WSL daemon writing a
// wsl.exe-bridged hook into a Windows-side config) has a twin in the other
// direction: "<tool>-wsl", a Windows-native daemon writing the hook of a
// tool that runs INSIDE a WSL distro into that distro's Linux home, reached
// as \\wsl.localhost\<distro>\home\<user>.
//
// The hook still executes in the daemon's own OS context (CLAUDE.md, "Don't
// try to bridge cross-OS hook capture at the storage layer"): the command
// written into the distro runs the Windows observer.exe through WSL interop
// (/mnt/c/.../observer.exe hook <tool> <event>), so the hook process is a
// Windows process and its writes land in the daemon's own database. That is
// the mirror of the wsl.exe bridge, which runs the Linux observer from a
// Windows host.
//
// A twin is not a new writer. It runs the tool's NATIVE writer through a
// derived registry (wslTwin) whose home is the WSL home, whose file shapes
// are Linux's (Options.GOOS), whose binary is the interop spelling of the
// Windows observer.exe, and which reads no environment variable (the
// distro's shell environment is not visible from Windows, so every file is
// the vendor default; the doctor says so). Checksums stay in the daemon's
// own hook_checksums.json.
//
// Every twin but cursor-wsl waits on live check WSL-4, so those rows are
// gated (livegate.go): built, tested, and switched off. cursor-wsl is on:
// live check WSL-5 passed on 2026-10-29 (Cursor's Remote-WSL server runs the
// WSL-side ~/.cursor/hooks.json; docs/handovers/
// surface-gap-windows-rig-run-2026-10-29.md), so its row carries no live
// check and feeds no gate (DEC-12: switching on is deleting the gate).
//
// The callers reach a switched-on twin through HomeTargetBase, as they reach
// the Xcode agent homes (FU-197, the FU-145 pattern): `observer start`, the
// dashboard's install path, `observer init` and `observer uninstall` treat it
// as a second home of its base tool, on a Windows host only (Installed lists
// a twin only for a WSL home crossmount finds there: a running distro's,
// FU-189) and only while its live gate is off.

// wslTwinRow is one Windows to WSL twin target.
type wslTwinRow struct {
	// target is the registration target ("claude-code-wsl").
	target string
	// windows is the WSL to Windows target it mirrors ("claude-code-windows").
	windows string
	// base is the native target the twin runs under the WSL home.
	base string
	// liveCheck is the pending-tracker live check the twin waits on; ""
	// once it has passed (the twin is switched on).
	liveCheck string
	// register / unregister override the base writer when the twin needs
	// more than the derived registry (codex's trust keys). nil runs the
	// base target's own writer.
	register   func(t *wslTwin) RegistrationResult
	unregister func(t *wslTwin) UnregistrationResult
}

// wslTwinRows lists every twin, in the order of the "-windows" targets they
// mirror (register_core.go hookTargetWriters / toolGateWriters).
var wslTwinRows = []wslTwinRow{
	{target: "claude-code-wsl", windows: "claude-code-windows", base: "claude-code", liveCheck: "WSL-4"},
	{target: "cursor-wsl", windows: "cursor-windows", base: "cursor"},
	{
		target: "codex-wsl", windows: "codex-windows", base: "codex", liveCheck: "WSL-4",
		register: (*wslTwin).registerCodex, unregister: (*wslTwin).unregisterCodex,
	},
	{target: "gemini-cli-wsl", windows: "gemini-cli-windows", base: "gemini-cli", liveCheck: "WSL-4"},
	{target: "qwen-code-wsl", windows: "qwen-code-windows", base: "qwen-code", liveCheck: "WSL-4"},
	{target: "droid-wsl", windows: "droid-windows", base: "droid", liveCheck: "WSL-4"},
	{target: "qoder-wsl", windows: "qoder-windows", base: "qoder", liveCheck: "WSL-4"},
	{target: "poolside-wsl", windows: "poolside-windows", base: "poolside", liveCheck: "WSL-4"},
	{target: "command-code-wsl", windows: "command-code-windows", base: "command-code", liveCheck: "WSL-4"},
	{target: "copilot-cli-wsl", windows: "copilot-cli-windows", base: "copilot-cli", liveCheck: "WSL-4"},
	{target: "ibm-bob-wsl", windows: "ibm-bob-windows", base: "ibm-bob", liveCheck: "WSL-4"},
	{target: "codebuddy-wsl", windows: "codebuddy-windows", base: "codebuddy", liveCheck: "WSL-4"},
	{target: "deepagents-code-wsl", windows: "deepagents-code-windows", base: "deepagents-code", liveCheck: "WSL-4"},
	{target: "dimcode-wsl", windows: "dimcode-windows", base: "dimcode", liveCheck: "WSL-4"},
	{target: "dirac-wsl", windows: "dirac-windows", base: "dirac", liveCheck: "WSL-4"},
	{target: "vtcode-wsl", windows: "vtcode-windows", base: "vtcode", liveCheck: "WSL-4"},
	// The twins of this lane's own new "-windows" targets
	// (register_crossos_ide.go), so the mirror stays complete.
	{target: "devin-wsl", windows: "devin-windows", base: "devin", liveCheck: "WSL-4"},
	{target: "antigravity-cli-wsl", windows: "antigravity-cli-windows", base: "antigravity-cli", liveCheck: "WSL-4"},
}

// wslTwinFor returns the twin row of target.
func wslTwinFor(target string) (wslTwinRow, bool) {
	for _, row := range wslTwinRows {
		if row.target == target {
			return row, true
		}
	}
	return wslTwinRow{}, false
}

// WSLTwinBase returns the native tool a "<tool>-wsl" twin target registers
// (its adapter and capability), false for any other target.
func WSLTwinBase(target string) (string, bool) {
	row, ok := wslTwinFor(target)
	return row.base, ok
}

// WSLTwinsFor returns the "-wsl" twin targets of the native tool base, in
// table order (gated ones included; LiveCheckGate says which are switched
// off).
func WSLTwinsFor(base string) []string {
	var out []string
	for _, row := range wslTwinRows {
		if row.base == base {
			out = append(out, row.target)
		}
	}
	return out
}

// HomeTargetBase returns the native tool a target registers in another home
// of the same tool, false for any other target: an Xcode agent home
// (XcodeTargetBase, FU-145) or, on a Windows host, a WSL distro's Linux home
// (WSLTwinBase, FU-197). The callers (observer start, init, the dashboard,
// uninstall) resolve such a target's capability, adapter and selection
// through its base; whether it is switched on is LiveCheckGate's answer, and
// whether its home exists here is Installed's (an Xcode folder on macOS, a
// running distro's home crossmount finds from Windows, FU-189).
func HomeTargetBase(target string) (string, bool) {
	if base, ok := XcodeTargetBase(target); ok {
		return base, true
	}
	return WSLTwinBase(target)
}

// HomeTargetsFor returns every other-home target of the native tool base
// (its Xcode agent homes, then its WSL twins), gated ones included.
func HomeTargetsFor(base string) []string {
	return append(XcodeTargetsFor(base), WSLTwinsFor(base)...)
}

// wslTwinGateRows feeds the twins that still wait on a live check into the
// live-check gate; a twin with no live check is switched on.
func wslTwinGateRows() []liveGateRow {
	out := make([]liveGateRow, 0, len(wslTwinRows))
	for _, row := range wslTwinRows {
		if row.liveCheck == "" {
			continue
		}
		out = append(out, liveGateRow{target: row.target, liveChecks: []string{row.liveCheck}})
	}
	return out
}

// wslTwin is the derived registry a twin writes through.
type wslTwin struct {
	row  wslTwinRow
	reg  *Registry
	home string
}

// wslInteropBinary is the spelling of the Windows observer binary a process
// inside a WSL distro runs through interop (/mnt/c/.../observer.exe). Only
// a Windows drive path to an .exe can be run that way: an npm or pip
// launcher (.cmd / .bat) is a cmd.exe script that interop does not run, and
// a POSIX binary path means this daemon is not a Windows observer.
func wslInteropBinary(binary string) (string, error) {
	mnt, ok := crossmount.MountPathFromWindows(binary)
	if !ok {
		return "", safeErrorf("the WSL twin runs the Windows observer.exe through WSL interop, so the hook binary must be a Windows drive path; %q is not", binary)
	}
	if !strings.EqualFold(filepath.Ext(mnt), ".exe") {
		return "", safeErrorf("the WSL twin runs the Windows observer.exe through WSL interop, which does not run a %s launcher; register from the observer.exe itself (%q)", filepath.Ext(mnt), binary)
	}
	if strings.Contains(mnt, "'") {
		return "", safeErrorf("the observer binary path %q contains a single quote, which the WSL hook shell cannot quote safely", binary)
	}
	return mnt, nil
}

// wslInteropConfig is the --config argument a twin writes: the daemon's
// Windows config path with forward slashes. observer.exe reads C:/x like
// C:\x, and the forward-slash spelling carries no character a POSIX hook
// shell escapes, so every native writer's quoter (POSIX, or the path-shape
// one that double-quotes a drive path with spaces) yields a command the
// distro's /bin/sh passes through unchanged. A path holding a character
// that some quoter would leave for the shell to expand is refused.
func wslInteropConfig(config string) (string, error) {
	if config == "" {
		return "", nil
	}
	if strings.ContainsAny(config, "'\"$`!") {
		return "", safeErrorf("the observer config path %q contains a quote, $, ` or !, which the WSL hook shell cannot carry safely", config)
	}
	return forwardSlashPath(config), nil
}

// wslTwinSourceBinary is the Windows binary a twin's interop command runs:
// Options.WSLTwinBinaryPath (the observer.exe a package manager's launcher
// started, FU-214), else BinaryPath. A launcher nothing resolved stays
// BinaryPath, and wslInteropBinary refuses it with its reason.
func (r *Registry) wslTwinSourceBinary() string {
	if r.opts.WSLTwinBinaryPath != "" {
		return r.opts.WSLTwinBinaryPath
	}
	return r.opts.BinaryPath
}

// newWSLTwin derives row's registry under the WSL home.
func (r *Registry) newWSLTwin(row wslTwinRow, home string) (*wslTwin, error) {
	bin, err := wslInteropBinary(r.wslTwinSourceBinary())
	if err != nil {
		return nil, err
	}
	config, err := wslInteropConfig(r.opts.ConfigPath)
	if err != nil {
		return nil, err
	}
	opts := r.opts
	opts.HomeDir = home
	opts.BinaryPath = bin
	opts.WSLTwinBinaryPath = ""
	// FU-214: the twin's entry always runs the current observer.exe. A
	// command naming another one (the path before an upgrade moved it) is
	// re-pointed, never kept as equivalent (T-725): from the Windows side
	// the interop path cannot be checked for a working binary.
	opts.KeepEquivalentHooks = false
	opts.ConfigPath = config
	opts.GOOS = crossmount.OSLinux
	opts.Getenv = crossmount.NoEnv
	opts.ChecksumsPath = r.checksumsPath()
	opts.WindowsPATH = nil
	opts.WSLDistro = ""
	opts.WSLUserHome = ""
	opts.WindowsClaudeHome, opts.WindowsCursorHome, opts.WindowsCodexHome = "", "", ""
	opts.WindowsGeminiHome, opts.WindowsQwenHome, opts.WindowsFactoryHome = "", "", ""
	opts.WindowsQoderHome, opts.WindowsPoolsideHome, opts.WindowsCommandCodeHome = "", "", ""
	opts.WindowsCopilotHome, opts.WindowsUserHome = "", ""
	// homeOverride pins the derived registry, which also switches its own
	// cross-OS detection off (crossmount.AutoDetectSuppressed).
	return &wslTwin{row: row, reg: &Registry{opts: opts, homeOverride: home, removing: r.removing, foreignOSTwin: true}, home: home}, nil
}

// linuxPath spells a path under the twin's home the way a process inside the
// distro sees it: \\wsl.localhost\<distro>\x becomes /x, and a POSIX path
// (a home a test or another mount names) is already the distro's spelling.
func (t *wslTwin) linuxPath(p string) (string, bool) {
	if lp, ok := crossmount.LinuxPathFromWSLHost(p); ok {
		return lp, true
	}
	if s := filepath.ToSlash(p); strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") {
		return s, true
	}
	return "", false
}

// registerCodex is codex-wsl: the native codex writer under the WSL home,
// with Codex's hook trust keyed by the hooks.json path the Codex inside the
// distro loads (its Linux spelling).
func (t *wslTwin) registerCodex() RegistrationResult {
	dir, err := t.reg.codexHomeDir()
	if err != nil {
		return RegistrationResult{Tool: t.row.target, DryRun: t.reg.opts.DryRun, Error: err}
	}
	return t.reg.registerCodexAt(codexHookTarget{
		tool:      t.row.target,
		dir:       dir,
		quote:     codexCmdQuoteIfNeeded,
		errPrefix: "hook.registerCodexWSL",
		matchMine: isObserverCodexEntryNative,
		trustKey:  t.linuxPath,
	})
}

// unregisterCodex removes codex-wsl's entries and trust records.
func (t *wslTwin) unregisterCodex() UnregistrationResult {
	dir, err := t.reg.codexHomeDir()
	if err != nil {
		return UnregistrationResult{Tool: t.row.target, DryRun: t.reg.opts.DryRun, Error: err}
	}
	return t.reg.unregisterCodexAt(t.row.target, dir, "hook.unregisterCodexWSL", t.linuxPath)
}

// register runs the twin's writer and labels the result with the twin
// target. A base whose hooks share a credential file is guarded by the
// base's own rule (guardCredentialRegistration keys on the tool).
func (t *wslTwin) register() RegistrationResult {
	var res RegistrationResult
	if t.row.register != nil {
		res = t.row.register(t)
	} else {
		res = t.reg.guardCredentialRegistration(t.row.base, t.reg.register(t.row.base))
	}
	res.Tool = t.row.target
	return res
}

// unregister is register's removal counterpart.
func (t *wslTwin) unregister() UnregistrationResult {
	var res UnregistrationResult
	if t.row.unregister != nil {
		res = t.row.unregister(t)
	} else {
		res = t.reg.guardCredentialUnregistration(t.row.base, t.reg.unregister(t.row.base))
	}
	res.Tool = t.row.target
	return res
}

// wslHomeOwned is the ownership seam (a package var like allHomes so a test
// can force a verdict).
var wslHomeOwned = crossmount.WSLHomeOwnedByCurrentUser

// detectWSLHome resolves the WSL Linux home row's twin writes into, or "".
//
//   - An explicit Options.WSLUserHome wins, unless the caller pinned a
//     sandbox home this override escapes (the 2026-07-31 incident rule).
//   - Otherwise the WSL homes this Windows host sees (crossmount, origin
//     wslhost:) that are proven the operator's (WSLHomeOwnedByCurrentUser)
//     and on which the base tool is installed (the base's own native
//     detection, run under that home). Exactly one wins; none or several
//     resolve to "" (no guess).
func (r *Registry) detectWSLHome(row wslTwinRow, scans wslHomeScans) string {
	if r.foreignAutoDetectSuppressed(r.opts.WSLUserHome) {
		return ""
	}
	if r.opts.WSLUserHome != "" {
		return r.opts.WSLUserHome
	}
	var found []string
	for _, h := range allHomes() {
		if !crossmount.IsWSLHostHome(h) || !wslHomeOwned(h.Path) {
			continue
		}
		if slices.Contains(r.wslHomeInstalled(row, h.Path, scans), row.base) {
			found = append(found, h.Path)
		}
	}
	if len(found) == 1 {
		return found[0]
	}
	return ""
}

// wslBaseInstalled reports whether row's base tool is installed under the
// WSL home, by the base's own native detection.
// wslHomeScans memoizes, within one detection pass, the native install
// detection of each WSL home: one derived registry and one installedAll per
// home, never per twin row (a pass over \\wsl.localhost is slow). nil means
// no memo (a single Register / Unregister).
type wslHomeScans map[string][]string

// wslHomeScanCount counts the native scans of WSL homes (test seam: pins
// the memo and that Installed spends none on gated rows).
var wslHomeScanCount atomic.Int64

// wslHomeInstalled is the native install detection under the WSL home (the
// tools the base writers would find there), from scans when it holds the
// home.
func (r *Registry) wslHomeInstalled(row wslTwinRow, home string, scans wslHomeScans) []string {
	if got, ok := scans[home]; ok {
		return got
	}
	got := r.scanWSLHome(row, home)
	if scans != nil {
		scans[home] = got
	}
	return got
}

// scanWSLHome runs the native detection under the WSL home through a
// derived registry.
func (r *Registry) scanWSLHome(row wslTwinRow, home string) []string {
	wslHomeScanCount.Add(1)
	t, err := r.newWSLTwin(row, home)
	if err != nil {
		// A binary the twin cannot run still lets detection answer: probe
		// with a placeholder, since detection never names the binary.
		probe := *r
		probe.opts.BinaryPath = `C:\observer.exe`
		if t, err = probe.newWSLTwin(row, home); err != nil {
			return nil
		}
	}
	// The derived registry pins its home, so its own cross-OS detection is
	// off: only native targets come back.
	return t.reg.installedAll(false)
}

// installedWSLTwins lists the twins whose WSL home is detected. A gated
// twin is detected only when includeGated is set (InstalledLiveGated);
// Installed, which feeds the maintain loop, init and the dashboard, never
// pays for a row it would drop. One native scan per WSL home serves every
// row of the pass.
func (r *Registry) installedWSLTwins(includeGated bool) []string {
	var out []string
	scans := wslHomeScans{}
	for _, row := range wslTwinRows {
		if _, gated := LiveCheckGate(row.target); gated && !includeGated {
			continue
		}
		if r.detectWSLHome(row, scans) != "" {
			out = append(out, row.target)
		}
	}
	return out
}

// registerWSLTwin is the dispatch of a "-wsl" target.
func (r *Registry) registerWSLTwin(row wslTwinRow) RegistrationResult {
	res := RegistrationResult{Tool: row.target, DryRun: r.opts.DryRun}
	home := r.detectWSLHome(row, nil)
	if home == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WSLUserHome) {
			r.sandboxSkipResult(&res, "WSL home", "WSLUserHome", r.opts.WSLUserHome)
			return res
		}
		res.Error = fmt.Errorf("hook.Register %s: no WSL home with %s installed was detected (set WSLUserHome to the distro home, e.g. \\\\wsl.localhost\\<distro>\\home\\<user>, or run on a Windows host whose one WSL user has %s)", row.target, row.base, row.base)
		return res
	}
	t, err := r.newWSLTwin(row, home)
	if err != nil {
		res.Error = fmt.Errorf("hook.Register %s: %w", row.target, err)
		return res
	}
	return t.register()
}

// unregisterWSLTwin removes a "-wsl" target's entries (a host with no WSL
// home is a no-op skip).
func (r *Registry) unregisterWSLTwin(row wslTwinRow) UnregistrationResult {
	home := r.detectWSLHome(row, nil)
	if home == "" {
		return UnregistrationResult{Tool: row.target, DryRun: r.opts.DryRun, Skipped: true}
	}
	t, err := r.newWSLTwin(row, home)
	if err != nil {
		return UnregistrationResult{Tool: row.target, DryRun: r.opts.DryRun, Error: fmt.Errorf("hook.Unregister %s: %w", row.target, err)}
	}
	return t.unregister()
}
