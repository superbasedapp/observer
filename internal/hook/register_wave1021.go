package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// Hook writers for the 2026-10-21 wave (contracts: docs/guard.md "Live
// grounding: 2026-10-21 wave"). Four are rows of the table-driven JSON
// writer (register_jsonhooks.go): IBM Bob, CodeBuddy, Deep Agents, DimCode.
// Four need a writer of their own: Dirac (one script per event), Kimchi's
// bash pre-gate (one script), Autohand (an ARRAY of entries inside a
// credential-bearing config.json) and VT Code (TOML arrays of tables edited
// line by line). Every writer keeps the common guarantees: the settings
// lock, the pinned write target, round trip of everything Observer does not
// own, the checksum record, the --force conflict guard, dry-run and a
// symmetric unregister. The event lists are the registry rows' Registered
// bindings (eventsOr).

// waveHookTimeoutSeconds is the timeout Observer registers where a vendor
// takes one in seconds and its default is shorter than a process spawn plus
// a guard evaluation, or fails the call closed on a timeout.
const waveHookTimeoutSeconds = 30

// codeBuddyHookTimeoutSeconds is CodeBuddy's own default, written
// explicitly: a CodeBuddy hook TIMEOUT blocks the call, so the registered
// timeout stays well above Observer's own gate budget.
const codeBuddyHookTimeoutSeconds = 60

// autohandHookTimeoutMs is the per-entry timeout (milliseconds) Observer
// writes for Autohand, whose 5 s default plus a fail-closed pre-tool would
// block a call on a cold start.
const autohandHookTimeoutMs = 30000

// envDir returns the absolute directory an environment override names, or
// "" (no Getenv, unset, or not absolute).
func (r *Registry) envDir(key string) string {
	if r.opts.Getenv == nil {
		return ""
	}
	if v := strings.TrimSpace(r.opts.Getenv(key)); v != "" && filepath.IsAbs(v) {
		return v
	}
	return ""
}

// hostGOOS is the OS whose file shapes a native registration writes (the
// running OS; tests pin it).
func (r *Registry) hostGOOS() string {
	if r.opts.GOOS != "" {
		return r.opts.GOOS
	}
	return runtime.GOOS
}

// wslBridge is the cross-OS prefix for a host whose hook shell is cmd.exe
// (no MSYS path conversion there, and an env assignment would be read as a
// program name).
func wslBridge(distro string) string {
	return "wsl.exe -d " + cmdQuoteIfNeeded(distro) + " -- "
}

// --- IBM Bob ------------------------------------------------------------

// ibmBobHooksTarget: Bob reads Claude-shaped matcher groups under "hooks" in
// ~/.bob/settings/settings.json (user hooks need no folder trust). Hooks run
// through Node's child_process.exec: /bin/sh on Linux, cmd.exe on Windows.
func ibmBobHooksTarget(home, wrapper, label string) jsonHooksTarget {
	return jsonHooksTarget{
		tool: "ibm-bob", label: label, wrapper: wrapper,
		dir: filepath.Join(home, ".bob", "settings"), file: "settings.json",
		eventsPath: []string{"hooks"}, events: eventsOr("ibm-bob", "PreToolUse", "UserPromptSubmit"),
		grouped: true, handler: commandHandler("timeout", waveHookTimeoutSeconds), commandKey: "command",
		quote: codexCmdQuoteIfNeeded, skip: ibmBobSkip, errPrefix: "hook.registerIBMBob", restore: true,
	}
}

// ibmBobSkip honours Bob's disableGlobalHooks: a user who switched global
// hooks off gets nothing written (Bob would not run it).
func ibmBobSkip(raw []byte, removing bool) string {
	if removing || len(bytes.TrimSpace(raw)) == 0 {
		return ""
	}
	var top struct {
		DisableGlobalHooks bool `json:"disableGlobalHooks"`
	}
	if json.Unmarshal(raw, &top) == nil && top.DisableGlobalHooks {
		return "IBM Bob's settings.json sets disableGlobalHooks: true, so Bob would not run a user-level hook; Observer leaves the switch as you set it and writes nothing"
	}
	return ""
}

// --- CodeBuddy ---------------------------------------------------------

// codeBuddyHooksTarget: CodeBuddy reads Claude-shaped matcher groups under
// "hooks" in ~/.codebuddy/settings.json; Windows runs the command under Git
// Bash, so the POSIX forward-slash form is right on both OSes. bridgeDistro
// is the WSL distro of the "-windows" bridge target ("" for a native one),
// written in the portable bridge form (portableBridgeCommand, AP-119). dir
// is the .codebuddy directory itself.
func codeBuddyHooksTarget(dir, bridgeDistro, label string) jsonHooksTarget {
	return jsonHooksTarget{
		tool: "codebuddy", label: label, portableDistro: bridgeDistro,
		dir: dir, file: "settings.json",
		eventsPath: []string{"hooks"}, events: eventsOr("codebuddy", "PreToolUse", "UserPromptSubmit"),
		grouped: true, handler: commandHandler("timeout", codeBuddyHookTimeoutSeconds), commandKey: "command",
		errPrefix: "hook.registerCodeBuddy", restore: true,
	}
}

// --- Deep Agents Code ---------------------------------------------------

// deepAgentsHooksTarget: dcode reads ~/.deepagents/hooks.json
// ($DEEPAGENTS_HOME) at user level with no trust step. Hooks run through
// create_subprocess_shell: /bin/sh, or cmd.exe on Windows.
func deepAgentsHooksTarget(dir, wrapper, label string) jsonHooksTarget {
	return jsonHooksTarget{
		tool: "deepagents-code", label: label, wrapper: wrapper,
		dir: dir, file: "hooks.json",
		eventsPath: []string{"hooks"}, events: eventsOr("deepagents-code", "PreToolUse", "UserPromptSubmit"),
		grouped: true, handler: commandHandler("timeout", waveHookTimeoutSeconds), commandKey: "command",
		quote: codexCmdQuoteIfNeeded, skip: deepAgentsSkip, errPrefix: "hook.registerDeepAgents", restore: true,
	}
}

// deepAgentsSkip leaves a legacy LIST-shaped hooks.json alone: dcode
// migrates or removes it itself, so Observer neither rewrites it nor reads
// it as its own.
func deepAgentsSkip(raw []byte, _ bool) string {
	if t := bytes.TrimSpace(bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})); len(t) > 0 && t[0] == '[' {
		return "~/.deepagents/hooks.json is in the legacy list shape that dcode migrates on its next run; Observer leaves it and writes nothing (run observer init again after dcode has started once)"
	}
	return ""
}

// deepAgentsHome is the native Deep Agents home: the
// deepagents-code/user-hooks artifact's directory, so $DEEPAGENTS_HOME moves
// it, a leading ~/ included (FU-50; the old envDir dropped a ~/ value).
func (r *Registry) deepAgentsHome() (string, error) {
	return r.artifactDir("deepagents-code/user-hooks")
}

// --- DimCode -----------------------------------------------------------

// dimCodeHooksTarget: DimCode reads <home>/hooks.json, where <home> is
// ~/.dimcode/v2, or $DIMCODE_HOME (with v2 appended unless the value already
// ends in v2, see dimCodeHome). Only supported event names may appear
// (an unknown one makes the whole file unloadable); there is no trust step.
// Hooks run through spawn(shell:true): /bin/sh, or cmd.exe on Windows.
func dimCodeHooksTarget(dir, wrapper, label string) jsonHooksTarget {
	return jsonHooksTarget{
		tool: "dimcode", label: label, wrapper: wrapper,
		dir: dir, file: "hooks.json",
		eventsPath: []string{"hooks"}, events: eventsOr("dimcode", "PreToolUse", "UserPromptSubmit"),
		grouped: true, handler: commandHandler("timeout", waveHookTimeoutSeconds), commandKey: "command",
		quote: codexCmdQuoteIfNeeded, errPrefix: "hook.registerDimCode", restore: true,
	}
}

// dimCodeHome is the native DimCode hooks directory. With DIMCODE_HOME set,
// it follows the vendor binary's resolveCliHomeDirFromEnv (the same rule
// internal/adapter/dimcode/store.go rootFromEnv reads the store by): a value
// whose last segment is already v2 is the home as-is, anything else gets v2
// appended. Appending unconditionally targeted .../v2/v2 (S-17). Since FU-18
// the rule is the dimcode/user-hooks artifact's DIMCODE_HOME relocation
// (RelocAppendIfMissing), not a copy here.
func (r *Registry) dimCodeHome() (string, error) {
	return r.artifactDir("dimcode/user-hooks")
}

// --- owned scripts (Dirac, Kimchi) --------------------------------------

// ownedScript is one hook file Observer owns outright: its path, its bytes,
// its mode and how to recognise a file Observer wrote.
type ownedScript struct {
	event string
	path  string
	data  []byte
	mode  os.FileMode
	ours  func([]byte) bool
	// pruneDirs is how many parent directories an unregister removes when
	// they are left empty (directories the writer creates that the vendor
	// does not ship); os.Remove never deletes a non-empty one.
	pruneDirs int
}

// registerOwnedScripts writes each script (a file Observer owns by name and
// marker). A file at the path that is not Observer's is a conflict unless
// --force.
func (r *Registry) registerOwnedScripts(label, errPrefix string, scripts []ownedScript) RegistrationResult {
	res := RegistrationResult{Tool: label, DryRun: r.opts.DryRun}
	for _, s := range scripts {
		if res.ConfigPath == "" {
			res.ConfigPath = s.path
		}
		if r.skipEvent(strings.TrimSuffix(label, "-windows"), s.event) {
			continue
		}
		if err := r.registerOwnedScript(&res, errPrefix, strings.TrimSuffix(label, "-windows"), s); err != nil {
			res.Error = err
			return res
		}
	}
	return res
}

func (r *Registry) registerOwnedScript(res *RegistrationResult, errPrefix, tool string, s ownedScript) error {
	unlock, err := r.lockSettings(s.path)
	if err != nil {
		return fmt.Errorf("%s: %w", errPrefix, err)
	}
	defer unlock()
	have, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return fmt.Errorf("%s: read %s: %w", errPrefix, s.path, err)
	case bytes.Equal(have, s.data) && scriptModeOK(s.path, s.mode):
		res.AlreadySet = append(res.AlreadySet, s.event)
		return nil
	case !s.ours(have) && r.refuses(s.path, identityContent):
		return hookConflictError(errPrefix, s.event)
	case r.refusesForeignBinary(res, errPrefix, s.path, identityContent, shapedHooksInText(have, tool)):
		// FU-192: a script in Observer's shape running another binary is
		// kept.
		return res.Error
	}
	res.HooksAdded = append(res.HooksAdded, s.event)
	if r.opts.DryRun {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("%s: %w", errPrefix, err)
	}
	pinned := pinWriteTarget(s.path)
	if err := atomicWriteFileMode(pinned, s.data, s.mode); err != nil {
		return fmt.Errorf("%s: write %s: %w", errPrefix, s.path, err)
	}
	if err := os.Chmod(pinned.target, s.mode); err != nil {
		return fmt.Errorf("%s: chmod: %w", errPrefix, err)
	}
	return r.recordChecksum(strings.TrimSuffix(res.Tool, "-windows"), s.path)
}

// scriptModeOK reports whether an executable script keeps its owner execute
// bit (a hook file the host runs as a program is no hook without it).
func scriptModeOK(path string, mode os.FileMode) bool {
	if mode&0o100 == 0 || runtime.GOOS == "windows" {
		// Windows keeps no execute bit to check.
		return true
	}
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().Perm()&0o100 != 0
}

// unregisterOwnedScripts removes each script Observer wrote, never a file it
// did not.
func (r *Registry) unregisterOwnedScripts(label, errPrefix string, scripts []ownedScript) UnregistrationResult {
	res := UnregistrationResult{Tool: label, DryRun: r.opts.DryRun}
	for _, s := range scripts {
		if res.ConfigPath == "" {
			res.ConfigPath = s.path
		}
		have, err := os.ReadFile(s.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			res.Error = fmt.Errorf("%s: read %s: %w", errPrefix, s.path, err)
			return res
		}
		if !s.ours(have) {
			res.HooksKept = append(res.HooksKept, s.event)
			continue
		}
		// FU-203: Observer's script running another binary is kept.
		if r.keepsForeignBinary(shapedHooksInText(have, strings.TrimSuffix(label, "-windows"))) {
			res.HooksKept = append(res.HooksKept, s.event)
			noteKeptForeign(&res, s.event)
			continue
		}
		res.HooksRemoved = append(res.HooksRemoved, s.event)
		if r.opts.DryRun {
			continue
		}
		unlock, err := r.lockSettings(s.path)
		if err != nil {
			res.Error = fmt.Errorf("%s: %w", errPrefix, err)
			return res
		}
		err = removeEmptyConfigFile(s.path, have)
		unlock()
		if err != nil {
			res.Error = fmt.Errorf("%s: %w", errPrefix, err)
			return res
		}
		_ = r.removeChecksum(s.path)
		dir := filepath.Dir(s.path)
		for i := 0; i < s.pruneDirs && os.Remove(dir) == nil; i++ {
			dir = filepath.Dir(dir)
		}
	}
	return res
}

// markerOwned returns an ownership test: the file carries marker as a whole
// line.
func markerOwned(marker string) func([]byte) bool {
	return func(data []byte) bool {
		for _, l := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
			if l == marker {
				return true
			}
		}
		return false
	}
}

// --- Dirac -------------------------------------------------------------

// diracHookMarker is the marker line of Observer's Dirac hook file for event.
func diracHookMarker(event string) string {
	return "# superbased-observer: Dirac " + event + " guard (observer init writes this file; observer uninstall removes it)"
}

// diracHooksDir is the native Dirac global hooks directory, ~/.dirac/Hooks,
// whatever DIRAC_DIR says. Vendor source builds it on the OS home alone:
// getDiracHomePath() is path.join(os.homedir(), ".dirac")
// (src/core/storage/paths.ts) and ensureHooksDirectoryExists is
// ensureDiracSubdir("Hooks") on it (src/core/storage/directoryEnsurers.ts);
// DIRAC_DIR is read only by the CLI's data and log paths
// (cli/src/utils/path.ts). That a run with DIRAC_DIR set still scans
// ~/.dirac/Hooks is source-grounded, not live-verified (live check 32), so a
// registration under a relocated DIRAC_DIR says so (diracRelocationWarnings).
// Only a script under a path matching .dirac/Hooks or Dirac/Hooks runs from
// the CLI without the extension-granted trust.
//
// Since FU-18 the path is the dirac/global-hooks artifact, whose DIRAC_DIR
// rule is RelocDoesNotMoveArtifact, so the catalogue and the writer say the
// same thing.
func (r *Registry) diracHooksDir() string {
	return r.artifactDirOr("dirac/global-hooks", filepath.Join(r.opts.HomeDir, ".dirac", "Hooks"))
}

// diracRelocatedHooksDir is $DIRAC_DIR/Hooks when DIRAC_DIR names a directory
// other than ~/.dirac: where builds before the S-17 fix wrote the scripts.
// "" when DIRAC_DIR is unset, not absolute, or ~/.dirac itself.
func (r *Registry) diracRelocatedHooksDir() string {
	d := r.envDir("DIRAC_DIR")
	if d == "" {
		return ""
	}
	alt := filepath.Join(d, "Hooks")
	if samePathOn(r.hostGOOS(), alt, r.diracHooksDir()) {
		return ""
	}
	return alt
}

// samePathOn compares two paths the way goos's file system does: Windows
// paths are case-insensitive.
func samePathOn(goos, a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if goos == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// diracRelocationWarnings are the non-fatal notes for a registration made
// while DIRAC_DIR is relocated: the scripts go to ~/.dirac/Hooks, whether
// the runtime scans that folder under DIRAC_DIR is unverified, and any
// Observer scripts an earlier build wrote under $DIRAC_DIR/Hooks are left in
// place (removing either copy before live check 32 would be a guess about
// which folder Dirac scans) until `observer uninstall`, which removes both.
func diracRelocationWarnings(scanned, legacy []ownedScript) []string {
	if len(scanned) == 0 || len(legacy) == 0 {
		return nil
	}
	alt := filepath.Dir(legacy[0].path)
	out := []string{"DIRAC_DIR is set: Observer's Dirac hook scripts are in " + filepath.Dir(scanned[0].path) +
		", the global Hooks folder Dirac's source scans whatever DIRAC_DIR says, not in " + alt +
		"; that a Dirac run with DIRAC_DIR set scans it is unverified (live check 32)"}
	var stale []string
	for _, s := range legacy {
		if have, err := os.ReadFile(s.path); err == nil && s.ours(have) {
			stale = append(stale, filepath.Base(s.path))
		}
	}
	if len(stale) > 0 {
		out = append(out, "Observer hook scripts an earlier build wrote remain in "+alt+" ("+strings.Join(stale, ", ")+
			"); they stay until live check 32 settles which folder Dirac scans, and `observer uninstall` removes them")
	}
	return out
}

// diracScripts are Observer's hook files in dir: an executable sh script per
// event on Linux / macOS, <Event>.ps1 on Windows (Dirac runs those with
// PowerShell -File). bridge is the cross-OS distro ("" for a native
// observer).
func (r *Registry) diracScripts(dir string, windows bool, distro string) []ownedScript {
	var out []ownedScript
	for _, event := range eventsOr("dirac", "PreToolUse", "UserPromptSubmit") {
		marker := diracHookMarker(event)
		s := ownedScript{event: event, ours: markerOwned(marker)}
		if windows {
			s.path = filepath.Join(dir, event+".ps1")
			s.mode = 0o644
			s.data = r.diracPowerShellScript(marker, event, distro)
		} else {
			s.path = filepath.Join(dir, event)
			s.mode = 0o755
			s.data = []byte("#!/bin/sh\n" + marker + "\nexec " + shellQuoteIfNeeded(r.opts.BinaryPath) +
				" hook dirac " + event + r.configFlagSuffix() + "\n")
		}
		out = append(out, s)
	}
	return out
}

// diracPowerShellScript is the Windows hook file: PowerShell 5.1 reads the
// payload as raw bytes, runs Observer (or the wsl.exe bridge) with the bytes
// on stdin, and copies its stdout / stderr bytes and exit code back, so no
// console code page ever re-encodes the JSON.
func (r *Registry) diracPowerShellScript(marker, event, distro string) []byte {
	exe, args := r.opts.BinaryPath, []string{"hook", "dirac", event}
	if r.opts.ConfigPath != "" {
		args = append(args, "--config", r.opts.ConfigPath)
	}
	if distro != "" {
		exe, args = "wsl.exe", append([]string{"-d", distro, "--", shellQuoteIfNeeded(r.opts.BinaryPath)}, posixArgs(args)...)
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = winArg(a)
	}
	lines := []string{
		marker,
		"$ErrorActionPreference = 'Stop'",
		"$payload = New-Object System.IO.MemoryStream",
		"[Console]::OpenStandardInput().CopyTo($payload)",
		"$psi = New-Object System.Diagnostics.ProcessStartInfo",
		"$psi.FileName = " + psQuote(exe),
		"$psi.Arguments = " + psQuote(strings.Join(quoted, " ")),
		"$psi.UseShellExecute = $false",
		"$psi.CreateNoWindow = $true",
		"$psi.RedirectStandardInput = $true",
		"$psi.RedirectStandardOutput = $true",
		"$psi.RedirectStandardError = $true",
		"$psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8",
		"$p = [System.Diagnostics.Process]::Start($psi)",
		"$err = $p.StandardError.ReadToEndAsync()",
		"$in = $payload.ToArray()",
		"$p.StandardInput.BaseStream.Write($in, 0, $in.Length)",
		"$p.StandardInput.Close()",
		"$out = New-Object System.IO.MemoryStream",
		"$p.StandardOutput.BaseStream.CopyTo($out)",
		"$p.WaitForExit()",
		"$o = $out.ToArray()",
		"$so = [Console]::OpenStandardOutput(); $so.Write($o, 0, $o.Length); $so.Flush()",
		"$e = [System.Text.Encoding]::UTF8.GetBytes($err.Result)",
		"$se = [Console]::OpenStandardError(); $se.Write($e, 0, $e.Length); $se.Flush()",
		"exit $p.ExitCode",
	}
	return []byte(strings.Join(lines, "\r\n") + "\r\n")
}

// posixArgs quotes args for the shell wsl.exe hands the command line to.
func posixArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = shellQuoteIfNeeded(a)
	}
	return out
}

// winArg quotes one argument for a Windows command line (CommandLineToArgv
// rules: a value with a space, a tab or a quote is double-quoted, inner
// quotes and the backslashes before them escaped).
func winArg(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for _, c := range s {
		switch c {
		case '\\':
			slashes++
			continue
		case '"':
			b.WriteString(strings.Repeat(`\`, 2*slashes+1))
		default:
			b.WriteString(strings.Repeat(`\`, slashes))
		}
		slashes = 0
		b.WriteRune(c)
	}
	b.WriteString(strings.Repeat(`\`, 2*slashes))
	b.WriteByte('"')
	return b.String()
}

// psQuote is a PowerShell single-quoted literal.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func (r *Registry) registerDirac() RegistrationResult {
	windows := r.hostGOOS() == "windows"
	scripts := r.diracScripts(r.diracHooksDir(), windows, "")
	res := r.registerOwnedScripts("dirac", "hook.registerDirac", scripts)
	if alt := r.diracRelocatedHooksDir(); alt != "" {
		res.Warnings = append(res.Warnings, diracRelocationWarnings(scripts, r.diracScripts(alt, windows, ""))...)
	}
	return res
}

// unregisterDirac removes Observer's scripts from ~/.dirac/Hooks and, when
// DIRAC_DIR is relocated, from $DIRAC_DIR/Hooks too (where earlier builds
// wrote them). A file Observer did not write is never touched.
func (r *Registry) unregisterDirac() UnregistrationResult {
	windows := r.hostGOOS() == "windows"
	res := r.unregisterOwnedScripts("dirac", "hook.unregisterDirac", r.diracScripts(r.diracHooksDir(), windows, ""))
	alt := r.diracRelocatedHooksDir()
	if res.Error != nil || alt == "" {
		return res
	}
	legacy := r.unregisterOwnedScripts("dirac", "hook.unregisterDirac", r.diracScripts(alt, windows, ""))
	res.Error = legacy.Error
	res.HooksRemoved = appendMissing(res.HooksRemoved, legacy.HooksRemoved)
	res.HooksKept = appendMissing(res.HooksKept, legacy.HooksKept)
	return res
}

// appendMissing appends each value of add that dst does not hold yet.
func appendMissing(dst, add []string) []string {
	for _, v := range add {
		if !slices.Contains(dst, v) {
			dst = append(dst, v)
		}
	}
	return dst
}

// --- Kimchi bash pre-gate ----------------------------------------------

// kimchiBashHookMarker is the marker line of Observer's bash pre-gate.
const kimchiBashHookMarker = "# superbased-observer: Kimchi bash pre-gate (observer init writes this file; observer uninstall removes it)"

// kimchiBashHookDir is ~/.config/kimchi/harness/hooks/bash, the
// kimchi/harness-bash-hooks artifact. Kimchi's entry.ts sets
// KIMCHI_CODING_AGENT_DIR (and PI_CODING_AGENT_DIR) to the harness dir
// unconditionally, so a value the user exports never moves it; following
// that value wrote a gate Kimchi never ran (S-17, FU-50).
func (r *Registry) kimchiBashHookDir() string {
	return r.artifactDirOr("kimchi/harness-bash-hooks", filepath.Join(r.opts.HomeDir, ".config", "kimchi", "harness", "hooks", "bash"))
}

// kimchiBashScripts is Observer's one bash pre-gate script (Kimchi runs every
// *.sh in the directory as `bash <file>` before the bash tool).
func (r *Registry) kimchiBashScripts() []ownedScript {
	var out []ownedScript
	for _, event := range eventsOr("kimchi", "tool_call") {
		out = append(out, ownedScript{
			// hooks/ and hooks/bash/ do not ship with Kimchi: the writer
			// creates them, so an unregister removes them when empty.
			event: event, path: filepath.Join(r.kimchiBashHookDir(), "superbased-observer.sh"), mode: 0o755, pruneDirs: 2,
			ours: markerOwned(kimchiBashHookMarker),
			data: []byte("#!/usr/bin/env bash\n" + kimchiBashHookMarker + "\nexec " + shellQuoteIfNeeded(r.opts.BinaryPath) +
				" hook kimchi " + event + r.configFlagSuffix() + "\n"),
		})
	}
	return out
}

func (r *Registry) registerKimchi() RegistrationResult {
	if r.hostGOOS() == "windows" {
		return RegistrationResult{
			Tool: "kimchi", DryRun: r.opts.DryRun, Skipped: true, SkipKind: SkipNotApplicable,
			SkipReason: "Kimchi runs its bash pre-gate scripts with whatever bash is first on PATH, which on Windows is often the WSL launcher; the gate is written on Linux and macOS only",
		}
	}
	return r.registerOwnedScripts("kimchi", "hook.registerKimchi", r.kimchiBashScripts())
}

func (r *Registry) unregisterKimchi() UnregistrationResult {
	return r.unregisterOwnedScripts("kimchi", "hook.unregisterKimchi", r.kimchiBashScripts())
}

// --- native JSON targets -----------------------------------------------

// registerIBMBob stands down for the events the node's Bob administrator
// policy already runs through EnforcedHooks (ibmbob_policy.go), so a
// managed node does not fire every hook twice.
func (r *Registry) registerIBMBob() RegistrationResult {
	t := ibmBobHooksTarget(r.opts.HomeDir, "", "")
	res, done, warnings := r.ibmBobPolicyStandDown(&t)
	if done {
		return res
	}
	res = r.registerJSONHooks(t)
	res.Warnings = append(res.Warnings, warnings...)
	return res
}

func (r *Registry) unregisterIBMBob() UnregistrationResult {
	return r.unregisterJSONHooks(ibmBobHooksTarget(r.opts.HomeDir, "", ""))
}

// codeBuddyNativeTarget is the native CodeBuddy target: the
// codebuddy/user-settings artifact's directory, so CODEBUDDY_CONFIG_DIR
// moves it (W-4, FU-50).
func (r *Registry) codeBuddyNativeTarget() jsonHooksTarget {
	dir, err := r.artifactDir("codebuddy/user-settings")
	t := codeBuddyHooksTarget(dir, "", "")
	t.dirErr = err
	return t
}

func (r *Registry) registerCodeBuddy() RegistrationResult {
	return r.registerJSONHooks(r.codeBuddyNativeTarget())
}

func (r *Registry) unregisterCodeBuddy() UnregistrationResult {
	return r.unregisterJSONHooks(r.codeBuddyNativeTarget())
}

// deepAgentsNativeTarget is the native Deep Agents target.
func (r *Registry) deepAgentsNativeTarget() jsonHooksTarget {
	dir, err := r.deepAgentsHome()
	t := deepAgentsHooksTarget(dir, "", "")
	t.dirErr = err
	return t
}

func (r *Registry) registerDeepAgents() RegistrationResult {
	return r.registerJSONHooks(r.deepAgentsNativeTarget())
}

func (r *Registry) unregisterDeepAgents() UnregistrationResult {
	return r.unregisterJSONHooks(r.deepAgentsNativeTarget())
}

// dimCodeNativeTarget is the native DimCode target.
func (r *Registry) dimCodeNativeTarget() jsonHooksTarget {
	dir, err := r.dimCodeHome()
	t := dimCodeHooksTarget(dir, "", "")
	t.dirErr = err
	return t
}

func (r *Registry) registerDimCode() RegistrationResult {
	return r.registerJSONHooks(r.dimCodeNativeTarget())
}

func (r *Registry) unregisterDimCode() UnregistrationResult {
	return r.unregisterJSONHooks(r.dimCodeNativeTarget())
}

// --- cross-OS bridge targets ---------------------------------------------

// waveCrossOSTarget is one 2026-10-21 tool's "-windows" target: the
// directory under a Windows USER home its config sits in, and the
// register / unregister pair for that directory (distro "" on unregister).
type waveCrossOSTarget struct {
	tool       string
	winSubdir  string
	register   func(r *Registry, dir, distro string) RegistrationResult
	unregister func(r *Registry, dir string) UnregistrationResult
}

// waveCrossOSTargets lists the targets, keyed by base tool. The bridge
// prefix follows the shell each Windows host runs its hook command in:
// cmd.exe (IBM Bob, Deep Agents, DimCode) takes a plain wsl.exe prefix, Git
// Bash (CodeBuddy, VT Code) takes the portable bridge form
// (portableBridgeCommand: `//` paths and a `; exit $LASTEXITCODE` trailer,
// AP-119; it replaced the MSYS_NO_PATHCONV=1 prefix and is valid in Git
// Bash, Git sh, PowerShell and cmd.exe), and Dirac's .ps1 runs wsl.exe
// itself.
var waveCrossOSTargets = []waveCrossOSTarget{
	{
		tool: "ibm-bob", winSubdir: ".bob",
		register: func(r *Registry, dir, distro string) RegistrationResult {
			return r.registerJSONHooks(ibmBobHooksTarget(filepath.Dir(dir), wslBridge(distro), "ibm-bob-windows"))
		},
		unregister: func(r *Registry, dir string) UnregistrationResult {
			return r.unregisterJSONHooks(ibmBobHooksTarget(filepath.Dir(dir), "", "ibm-bob-windows"))
		},
	},
	{
		tool: "codebuddy", winSubdir: ".codebuddy",
		register: func(r *Registry, dir, distro string) RegistrationResult {
			return r.registerJSONHooks(codeBuddyHooksTarget(dir, distro, "codebuddy-windows"))
		},
		unregister: func(r *Registry, dir string) UnregistrationResult {
			return r.unregisterJSONHooks(codeBuddyHooksTarget(dir, "", "codebuddy-windows"))
		},
	},
	{
		tool: "deepagents-code", winSubdir: ".deepagents",
		register: func(r *Registry, dir, distro string) RegistrationResult {
			return r.registerJSONHooks(deepAgentsHooksTarget(dir, wslBridge(distro), "deepagents-code-windows"))
		},
		unregister: func(r *Registry, dir string) UnregistrationResult {
			return r.unregisterJSONHooks(deepAgentsHooksTarget(dir, "", "deepagents-code-windows"))
		},
	},
	{
		tool: "dimcode", winSubdir: ".dimcode",
		register: func(r *Registry, dir, distro string) RegistrationResult {
			return r.registerJSONHooks(dimCodeHooksTarget(filepath.Join(dir, "v2"), wslBridge(distro), "dimcode-windows"))
		},
		unregister: func(r *Registry, dir string) UnregistrationResult {
			return r.unregisterJSONHooks(dimCodeHooksTarget(filepath.Join(dir, "v2"), "", "dimcode-windows"))
		},
	},
	{
		tool: "dirac", winSubdir: ".dirac",
		register: func(r *Registry, dir, distro string) RegistrationResult {
			return r.registerOwnedScripts("dirac-windows", "hook.registerDiracWindows", r.diracScripts(filepath.Join(dir, "Hooks"), true, distro))
		},
		unregister: func(r *Registry, dir string) UnregistrationResult {
			return r.unregisterOwnedScripts("dirac-windows", "hook.unregisterDiracWindows", r.diracScripts(filepath.Join(dir, "Hooks"), true, "-"))
		},
	},
	{
		tool: "vtcode", winSubdir: filepath.Join("AppData", "Roaming", "vinhnx", "vtcode", "config"),
		register: func(r *Registry, dir, distro string) RegistrationResult {
			return r.registerVTCodeAt("vtcode-windows", filepath.Join(dir, "vtcode.toml"), distro)
		},
		unregister: func(r *Registry, dir string) UnregistrationResult {
			return r.unregisterVTCodeAt("vtcode-windows", filepath.Join(dir, "vtcode.toml"))
		},
	},
}

// waveCrossOSFor returns the cross-OS target of tool.
func waveCrossOSFor(tool string) (waveCrossOSTarget, bool) {
	for _, t := range waveCrossOSTargets {
		if t.tool == tool {
			return t, true
		}
	}
	return waveCrossOSTarget{}, false
}

// detectWindowsWaveDir resolves t's Windows-side directory (Options.
// WindowsUserHome, else the one owned Windows home crossmount sees).
func (r *Registry) detectWindowsWaveDir(t waveCrossOSTarget) string {
	return r.detectWindowsHome(r.opts.WindowsUserHome, t.winSubdir)
}

// registerWaveWindows registers tool's "-windows" bridge target.
func (r *Registry) registerWaveWindows(tool string) RegistrationResult {
	label := tool + "-windows"
	res := RegistrationResult{Tool: label, DryRun: r.opts.DryRun}
	t, ok := waveCrossOSFor(tool)
	if !ok {
		res.Error = fmt.Errorf("hook.Register: no cross-OS target for %s", tool)
		return res
	}
	dir := r.detectWindowsWaveDir(t)
	if dir == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsUserHome) {
			r.sandboxSkipResult(&res, t.winSubdir, "WindowsUserHome", r.opts.WindowsUserHome)
			return res
		}
		res.Error = fmt.Errorf("hook.Register %s: no Windows-side %s detected (set WindowsUserHome explicitly or run on a host where crossmount sees /mnt/c/Users/<u>/%s)", label, filepath.ToSlash(t.winSubdir), filepath.ToSlash(t.winSubdir))
		return res
	}
	distro, err := r.resolveWSLDistro("hook.Register " + label)
	if err != nil {
		res.Error = err
		return res
	}
	return t.register(r, dir, distro)
}

// unregisterWaveWindows removes tool's "-windows" bridge target (a host with
// no Windows-side directory is a no-op skip).
func (r *Registry) unregisterWaveWindows(tool string) UnregistrationResult {
	label := tool + "-windows"
	t, ok := waveCrossOSFor(tool)
	if !ok {
		return UnregistrationResult{Tool: label, DryRun: r.opts.DryRun, Skipped: true}
	}
	dir := r.detectWindowsWaveDir(t)
	if dir == "" {
		return UnregistrationResult{Tool: label, DryRun: r.opts.DryRun, Skipped: true}
	}
	return t.unregister(r, dir)
}

// installedWaveWindows lists the detected "-windows" targets.
func (r *Registry) installedWaveWindows() []string {
	var out []string
	for _, t := range waveCrossOSTargets {
		if r.detectWindowsWaveDir(t) != "" {
			out = append(out, t.tool+"-windows")
		}
	}
	return out
}
