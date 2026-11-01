package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/claudeplugin"
	"github.com/marmutapp/superbased-observer/internal/hook/commandcodemod"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// allHomes and homeOwnedByCurrentWindowsUser are the crossmount seams (package
// vars, mirroring internal/proxyroute) so tests can inject a fixed multi-home
// layout AND a deterministic ownership verdict without a real /mnt/c mount or
// a cmd.exe interop shell (restore them in a defer).
var (
	allHomes                      = crossmount.AllHomes
	homeOwnedByCurrentWindowsUser = crossmount.HomeOwnedByCurrentWindowsUser
)

// detectWindowsClaudeHome returns the resolved Windows-side .claude
// directory used by the claude-code-windows registration target, or
// "" if none. Honors Options.WindowsClaudeHome when set; otherwise
// accepts an auto-detected OS=windows home that has a `.claude/`
// subdirectory ONLY when crossmount can prove it belongs to the current
// Windows user. Mirrors detectWindowsCursorHome and the proxy-route
// side's resolveWindowsHome R1 guard.
func (r *Registry) detectWindowsClaudeHome() string {
	return r.detectWindowsHome(r.opts.WindowsClaudeHome, ".claude")
}

// WindowsClaudeDir exposes the resolved Windows-side .claude directory
// the claude-code-windows registration target writes into, or "" when
// there is none. Exported so `observer doctor` can inspect the SAME
// directory this registrar would write to, instead of re-deriving the
// crossmount + ownership rules and drifting from them (one owner). Its
// argument mirrors Options.WindowsClaudeHome: an explicit Windows USER
// home override, or "" to auto-detect.
func WindowsClaudeDir(override string) string {
	r := &Registry{opts: Options{WindowsClaudeHome: override}}
	return r.detectWindowsClaudeHome()
}

// detectWindowsCursorHome returns the resolved Windows-side .cursor
// directory used by the cursor-windows registration target, or "" if
// none. Honors Options.WindowsCursorHome when set; otherwise accepts an
// auto-detected OS=windows home carrying `.cursor/` only when
// crossmount-ownership-verified.
func (r *Registry) detectWindowsCursorHome() string {
	return r.detectWindowsHome(r.opts.WindowsCursorHome, ".cursor")
}

// detectWindowsCodexHome returns the resolved Windows-side .codex
// directory used by the codex-windows registration target, or "" if
// none. Honors Options.WindowsCodexHome when set; otherwise accepts an
// auto-detected OS=windows home carrying `.codex/` only when
// crossmount-ownership-verified. Same contract as
// detectWindowsClaudeHome / detectWindowsCursorHome.
func (r *Registry) detectWindowsCodexHome() string {
	return r.detectWindowsHome(r.opts.WindowsCodexHome, ".codex")
}

// detectWindowsGeminiHome / detectWindowsQwenHome / detectWindowsFactoryHome
// / detectWindowsQoderHome / detectWindowsPoolsideHome /
// detectWindowsCommandCodeHome resolve the Windows-side config directory
// for each of the six Part B item 1/2 long-tail vendors' own cross-OS
// bridge target, or "" if none. Same contract as detectWindowsClaudeHome
// / detectWindowsCursorHome / detectWindowsCodexHome — honors the
// matching Options override when set, otherwise an auto-detected
// OS=windows home carrying the subdir ONLY when crossmount proves it
// belongs to the current Windows user.
func (r *Registry) detectWindowsGeminiHome() string {
	return r.detectWindowsHome(r.opts.WindowsGeminiHome, ".gemini")
}

func (r *Registry) detectWindowsQwenHome() string {
	return r.detectWindowsHome(r.opts.WindowsQwenHome, ".qwen")
}

func (r *Registry) detectWindowsFactoryHome() string {
	return r.detectWindowsHome(r.opts.WindowsFactoryHome, ".factory")
}

func (r *Registry) detectWindowsQoderHome() string {
	return r.detectWindowsHome(r.opts.WindowsQoderHome, ".qoder")
}

func (r *Registry) detectWindowsPoolsideHome() string {
	return r.detectWindowsHome(r.opts.WindowsPoolsideHome, filepath.Join(".config", "poolside"))
}

func (r *Registry) detectWindowsCommandCodeHome() string {
	return r.detectWindowsHome(r.opts.WindowsCommandCodeHome, ".commandcode")
}

func (r *Registry) detectWindowsCopilotHome() string {
	return r.detectWindowsHome(r.opts.WindowsCopilotHome, ".copilot")
}

// detectWindowsHome resolves the Windows-side <subdir> directory for a
// cross-OS registration target. Ownership discipline mirrors the proxy-route
// writer's resolveWindowsHome (security finding R1/F1): a WSL daemon must NOT
// install hooks into another Windows user's config just because theirs is the
// only `.claude`/`.cursor` mounted.
//
//   - An explicit override wins unconditionally — the operator named the home,
//     so ownership verification is moot; returned even if the dir doesn't exist
//     yet (the registrar mkdir's on first install).
//   - Otherwise an auto-detected OS=windows home carrying <subdir> is accepted
//     ONLY when crossmount proves it belongs to the current Windows user
//     (base name matches %USERNAME%). Zero owned homes — or an ambiguous
//     several — resolve to "" so the virtual target simply doesn't surface in
//     Installed() (the honest floor: no behaviour change on a single-user
//     machine where the name matches; a refusal to guess otherwise).
func (r *Registry) detectWindowsHome(override, subdir string) string {
	// Sandbox gate FIRST — before the override branch, because an override
	// that points OUTSIDE the pinned home is exactly the escape hatch that
	// re-opened this hole. See crossmount.AutoDetectSuppressed (incident
	// 2026-07-31). Production never pins HomeDir, so this is false on every
	// real path and a bare override still wins unconditionally.
	if r.foreignAutoDetectSuppressed(override) {
		return ""
	}
	if override != "" {
		return filepath.Join(override, subdir)
	}
	var owned []string
	for _, h := range allHomes() {
		if h.OS != crossmount.OSWindows {
			continue
		}
		dir := filepath.Join(h.Path, subdir)
		if !r.dirExists(dir) {
			continue
		}
		if homeOwnedByCurrentWindowsUser(h.Path) {
			owned = append(owned, dir)
		}
	}
	if len(owned) == 1 {
		return owned[0]
	}
	return ""
}

// foreignAutoDetectSuppressed reports whether this registry's caller pinned
// HomeDir (a sandbox) without naming the Windows-side home for the target
// being resolved. See crossmount.AutoDetectSuppressed for the rule and the
// 2026-07-31 incident it exists to make structurally impossible.
func (r *Registry) foreignAutoDetectSuppressed(override string) bool {
	return crossmount.AutoDetectSuppressed(r.homeOverride, override)
}

// sandboxSkipResult fills res as a deliberate no-write for a cross-OS target
// the sandbox gate suppressed. It is a SKIP, not an error: nothing is wrong
// with the host — the caller pinned a home and either never said which
// Windows-side home it wanted, or named one OUTSIDE that sandbox, so there is
// no path this registry is allowed to touch. optionName is the Options field
// that unlocks the target; its value must resolve INSIDE the pinned home.
func (r *Registry) sandboxSkipResult(res *RegistrationResult, subdir, optionName, override string) {
	res.Skipped = true
	res.SkipKind = SkipNotApplicable
	if override == "" {
		res.SkipReason = fmt.Sprintf(
			"HomeDir was pinned by the caller but no %s was given, so cross-OS %s/ resolution is suppressed (incident 2026-07-31)",
			optionName, subdir,
		)
	} else {
		res.SkipReason = fmt.Sprintf(
			"%s (%s) resolves OUTSIDE the pinned HomeDir (%s), so cross-OS %s/ resolution is suppressed (incident 2026-07-31)",
			optionName, override, r.homeOverride, subdir,
		)
	}
	res.SkipAdvice = fmt.Sprintf(
		"nothing written; a sandboxed caller must set %s to a home UNDER its own HomeDir to wire this target (--force does not lift this).",
		optionName,
	)
}

// registerClaudeCodeWindows installs Claude Code hooks into a Windows-
// side `.claude/settings.json` (typically
// `/mnt/c/Users/<u>/.claude/settings.json`) with each command wrapped
// in the portable bridge form (portableBridgeCommand):
//
//	wsl.exe -d <distro> -- //<linux-bin> hook claude-code <event>
//	[--config '//<wsl-path>']; exit $LASTEXITCODE
//
// One settings.json is read by several hosts that run its hook commands
// through different shells, and this one string has to work in all of
// them (AP-119):
//
//   - Claude Code on Windows runs a hook through Git Bash (`bash -c`, or
//     `sh -c` when CLAUDE_CODE_GIT_BASH_PATH names sh.exe), and through
//     `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass
//     -Command` for a hook entry that sets "shell": "powershell" (read
//     from the 2.1.288 binary, 2026-10-22).
//   - Snowflake Cortex Code merges ~/.claude/settings.json and runs every
//     hook through `powershell.exe -NoProfile -Command`.
//
// Git Bash's MSYS layer rewrites a bare `/home/...` argument into
// `C:/Program Files/Git/home/...` before it reaches wsl.exe (the inner
// binary is then not found and every hook exits 127 — confirmed on Claude
// Desktop v2.1.138, 2026-05-20). The old fix was a `MSYS_NO_PATHCONV=1`
// env prefix, but PowerShell (and cmd.exe) cannot parse a `VAR=value cmd`
// prefix at all, so under Cortex every hook failed. A leading `//` is the
// other MSYS escape: MSYS passes the argument through untouched, and Linux
// resolves `//home/...` exactly like `/home/...`. PowerShell also turns a
// native exit code 2 (how a gate blocks) into 1 unless the command ends
// with `exit $LASTEXITCODE`; in bash that variable is unset, so `exit`
// returns the last command's status. Verified 2026-10-22 under Git Bash,
// Git sh, PowerShell 5.1 (both host spawn shapes) and cmd.exe: exit 0/1/2,
// stdin and stderr pass through unchanged.
//
// The old MSYS-prefixed form stays recognised as Observer-owned
// (isObserverWindowsClaudeEntry), so re-registration replaces it and
// uninstall removes it; the equivalence table's bridge-form row forces
// the rewrite even under KeepEquivalentHooks.
//
// Distro lookup: Options.WSLDistro → $WSL_DISTRO_NAME. Empty distro
// is an error; the command would be ambiguous on a host with multiple
// distros. Same contract as registerCursorWindows.
func (r *Registry) registerClaudeCodeWindows() RegistrationResult {
	res := RegistrationResult{Tool: "claude-code-windows", DryRun: r.opts.DryRun}
	claudeDir, distro, ok := r.claudeCodeWindowsTarget(&res)
	if !ok {
		return res
	}

	unlock, err := r.lockSettings(res.ConfigPath)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerClaudeCodeWindows: %w", err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(res.ConfigPath)

	raw, err := readSettingsFile(res.ConfigPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Error = fmt.Errorf("hook.registerClaudeCodeWindows: read: %w", err)
		return res
	}
	settings := map[string]json.RawMessage{}
	if len(raw) > 0 {
		settings, err = decodeSettingsObject(res.ConfigPath, raw)
		if err != nil {
			res.Error = fmt.Errorf("hook.registerClaudeCodeWindows: %w", err)
			return res
		}
	}
	var hooks map[string][]claudeHookGroup
	if existing, ok := settings["hooks"]; ok {
		if err := json.Unmarshal(existing, &hooks); err != nil {
			res.Error = fmt.Errorf("hook.registerClaudeCodeWindows: parse hooks: %w", err)
			return res
		}
	}
	if hooks == nil {
		hooks = map[string][]claudeHookGroup{}
	}
	// FU-192: an entry in Observer's shape running another binary is kept.
	if r.refusesForeignBinary(&res, "hook.registerClaudeCodeWindows", res.ConfigPath, identityContent, shapedHooksInText(settings["hooks"], "claude-code")) {
		return res
	}
	shapeDrift := shapeDriftEvents(settings["hooks"], claudeShapedGroups(isObserverWindowsClaudeEntry))

	for _, event := range claudeCodeEvents {
		cmd := r.gateBridgeCommand("claude-code", filepath.Dir(claudeDir), distro, event, hookEventArg(event),
			portableBridgeCommand(distro, r.opts.BinaryPath, "claude-code", hookEventArg(event), r.opts.ConfigPath))
		groups := hooks[event]
		// T-847: a narrowed matcher or an extra entry field is not "already
		// set" (see registerClaudeCode and hook_shape.go).
		groups, idx := dropShapeDriftedTyped(&res, event, cmd, groups, shapeDrift[event],
			findClaudeGroupWithObserverWindows, isObserverWindowsClaudeEntry)
		if idx >= 0 {
			if observerCmdMatches(groups[idx], cmd) {
				res.AlreadySet = append(res.AlreadySet, event)
				continue
			}
			// Refresh-on-drift: binary path or config flag changed but
			// the wsl-wrapped shape is still ours. Under
			// KeepEquivalentHooks an equivalent entry stays (T-725);
			// a native entry, another distro, a missing binary or
			// another config is still rewritten. Drop the stale group
			// and fall through to append the current one.
			if r.keepOrRewrite(&res, event, observerCommandInGroup(groups[idx], isObserverWindowsClaudeEntry), cmd) {
				res.AlreadySet = append(res.AlreadySet, event)
				continue
			}
			groups = append(groups[:idx], groups[idx+1:]...)
		}
		if r.refuses(res.ConfigPath, identityContent) && hasConflictingClaudeHookWindows(groups) {
			res.Error = hookConflictError("hook.registerClaudeCodeWindows", event)
			return res
		}
		groups = append(groups, claudeHookGroup{
			Matcher: "*",
			Hooks:   []claudeHookCommand{{Type: "command", Command: cmd}},
		})
		hooks[event] = groups
		res.HooksAdded = append(res.HooksAdded, event)
	}

	// Nothing added (every event exact or kept as equivalent): never
	// re-encode the typed groups, so the file stays byte-identical
	// (T-725; the typed decode would otherwise drop a sibling entry's
	// unknown fields on a no-op pass).
	if len(res.HooksAdded) == 0 && len(raw) > 0 {
		if r.opts.DryRun {
			return res
		}
		if err := r.recordHookChecksum("claude-code-windows", res.ConfigPath); err != nil {
			res.Error = err
		}
		return res
	}

	patched, err := json.Marshal(hooks)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerClaudeCodeWindows: marshal hooks: %w", err)
		return res
	}
	settings["hooks"] = patched

	if r.opts.DryRun {
		return res
	}
	if err := r.writeHookSettingsJSON("claude-code-windows", claudeDir, pinned, raw, settings); err != nil {
		res.Error = err
		return res
	}
	if err := r.recordHookChecksum("claude-code-windows", res.ConfigPath); err != nil {
		res.Error = err
		return res
	}
	return res
}

// claudeCodeWindowsTarget resolves the Windows-side .claude directory and
// the WSL distro registerClaudeCodeWindows writes the bridge for, filling
// res (config path, skip, error) on the way. ok is false when res is final.
func (r *Registry) claudeCodeWindowsTarget(res *RegistrationResult) (claudeDir, distro string, ok bool) {
	claudeDir = r.detectWindowsClaudeHome()
	if claudeDir == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsClaudeHome) {
			r.sandboxSkipResult(res, ".claude", "WindowsClaudeHome", r.opts.WindowsClaudeHome)
			return "", "", false
		}
		res.Error = errors.New("hook.registerClaudeCodeWindows: no Windows-side .claude/ detected (set WindowsClaudeHome explicitly or run on a host where crossmount sees /mnt/c/Users/<u>/.claude/)")
		return "", "", false
	}
	res.ConfigPath = filepath.Join(claudeDir, "settings.json")

	// Same double-wiring guard as the native registrar, applied to the
	// Windows-side .claude the cross-OS bridge writes into: that install
	// keeps its own plugin state there. Same fail-open-to-wiring rule.
	pdWin := claudeplugin.DetectInClaudeDir(claudeDir)
	if pdWin.Active && !r.opts.Force {
		res.Skipped = true
		res.SkipKind = SkipCovered
		res.SkipReason = pdWin.Reason()
		return "", "", false
	}
	res.ProbeWarning = pdWin.Warning()

	distro = r.opts.WSLDistro
	if distro == "" {
		distro = os.Getenv("WSL_DISTRO_NAME")
	}
	if distro == "" {
		res.Error = safeErrorf("hook.registerClaudeCodeWindows: WSL distro unknown: set Options.WSLDistro or run inside WSL (so $WSL_DISTRO_NAME is set)")
		return "", "", false
	}
	// The portable bridge form (AP-119): see the docstring for why it
	// replaced the MSYS_NO_PATHCONV=1 prefix.
	if err := portableBridgePathError("hook.registerClaudeCodeWindows", r.opts.BinaryPath, r.opts.ConfigPath); err != nil {
		res.Error = err
		return "", "", false
	}

	return claudeDir, distro, true
}

// isObserverWindowsClaudeEntry recognises a hook command in the
// Windows-side settings.json as observer-owned, in EITHER shape:
//
//   - the cross-OS bridge this registrar writes — a `wsl.exe `
//     invocation (the current portable form, the legacy
//     MSYS_NO_PATHCONV=1-prefixed form of v1.6.22 to AP-119, or the
//     prefix-free form before it) that ultimately calls
//     `<bin> hook claude-code <event>`. Matching every generation lets
//     refresh-on-drift rewrite an older entry and uninstall remove it;
//   - a NATIVE `<...>\observer.exe hook claude-code <event>` entry
//     written by an earlier Windows-native npm `observer init`
//     (isObserverAnyHookEntry — class C2 / audit IDE-11).
//
// The native half is what lets the bridge REPLACE a stale native
// registration without --force. Without it the native entry read as a
// third-party hook, registration errored, and the stale entry kept
// writing the stranded Windows DB.
//
// Note the deliberate asymmetry with isObserverClaudeEntry, the
// native-target predicate, which still REJECTS wsl.exe shapes: the two
// targets must not fight over a settings.json that carries both, and
// only the Windows target is allowed to convert one shape into the
// other (native → bridge, never the reverse).
func isObserverWindowsClaudeEntry(cmd string) bool {
	if isHookBridgeEntry(cmd, "claude-code") {
		return true
	}
	if strings.Contains(cmd, " hook claude-code ") {
		if strings.HasPrefix(cmd, "wsl.exe ") {
			return true
		}
		if strings.HasPrefix(cmd, "MSYS_NO_PATHCONV=1 wsl.exe ") {
			return true
		}
	}
	return isObserverAnyHookEntry(cmd, "claude-code")
}

// findClaudeGroupWithObserverWindows returns the index of a group
// whose single hook command is a wsl-wrapped observer claude-code
// invocation, or -1.
func findClaudeGroupWithObserverWindows(groups []claudeHookGroup) int {
	for i, g := range groups {
		for _, h := range g.Hooks {
			if h.Type == "command" && isObserverWindowsClaudeEntry(h.Command) {
				return i
			}
		}
	}
	return -1
}

// observerCommandInGroup returns the command of the first entry in group
// that ours recognises as observer-owned, or "" when there is none.
func observerCommandInGroup(group claudeHookGroup, ours func(string) bool) string {
	for _, h := range group.Hooks {
		if h.Type == "command" && ours(h.Command) {
			return h.Command
		}
	}
	return ""
}

// hasConflictingClaudeHookWindows reports whether any group contains a
// non-observer command. Used by the Windows registrar's --force-less
// path to refuse silent overwrite of user-authored hooks.
func hasConflictingClaudeHookWindows(groups []claudeHookGroup) bool {
	for _, g := range groups {
		for _, h := range g.Hooks {
			if h.Type != "command" {
				continue
			}
			if !isObserverWindowsClaudeEntry(h.Command) {
				return true
			}
		}
	}
	return false
}

// registerCursorWindows installs Cursor hooks into a Windows-side
// .cursor/hooks.json (typically `/mnt/c/Users/<u>/.cursor/hooks.json`)
// with each command wrapped in `wsl.exe -d <distro> -- <linux-bin>
// hook cursor <event> [--config <wsl-path>]`. The Windows-Cursor
// process spawns wsl.exe; wsl.exe routes stdin/stdout to the WSL-side
// observer binary; the binary processes the hook payload exactly as
// it would on a native Linux install. Uses double-dash (`--`)
// separator so wsl.exe stops parsing its own flags before the linux
// binary path; this keeps any future wsl.exe flags additions from
// silently consuming an arg meant for observer.
//
// The WSL distro name comes from Options.WSLDistro, falling back to
// $WSL_DISTRO_NAME at registration time. Empty distro is an error —
// without it, the registered command would be ambiguous on a host
// with multiple WSL distros.
func (r *Registry) registerCursorWindows() RegistrationResult {
	res := RegistrationResult{Tool: "cursor-windows", DryRun: r.opts.DryRun}

	cursorDir := r.detectWindowsCursorHome()
	if cursorDir == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsCursorHome) {
			r.sandboxSkipResult(&res, ".cursor", "WindowsCursorHome", r.opts.WindowsCursorHome)
			return res
		}
		res.Error = errors.New("hook.registerCursorWindows: no Windows-side .cursor/ detected (set WindowsCursorHome explicitly or run on a host where crossmount sees /mnt/c/Users/<u>/.cursor/)")
		return res
	}
	res.ConfigPath = filepath.Join(cursorDir, "hooks.json")

	distro := r.opts.WSLDistro
	if distro == "" {
		distro = os.Getenv("WSL_DISTRO_NAME")
	}
	if distro == "" {
		res.Error = safeErrorf("hook.registerCursorWindows: WSL distro unknown: set Options.WSLDistro or run inside WSL (so $WSL_DISTRO_NAME is set)")
		return res
	}

	unlock, err := r.lockSettings(res.ConfigPath)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerCursorWindows: %w", err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(res.ConfigPath)

	raw, err := readSettingsFile(res.ConfigPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Error = fmt.Errorf("hook.registerCursorWindows: read: %w", err)
		return res
	}
	settings := map[string]json.RawMessage{}
	if len(raw) > 0 {
		settings, err = decodeSettingsObject(res.ConfigPath, raw)
		if err != nil {
			res.Error = fmt.Errorf("hook.registerCursorWindows: %w", err)
			return res
		}
	}
	hooks := map[string][]cursorHookEntry{}
	if existing, ok := settings["hooks"]; ok {
		_ = json.Unmarshal(existing, &hooks)
	}

	// NO MSYS_NO_PATHCONV=1 prefix here: Cursor executes hook commands via
	// PowerShell on Windows (it runs `Get-Content <payload> -Raw | & {
	// $input | <command> }`), where a bash-style `VAR=value cmd` env-prefix
	// is not a command — PowerShell fails with "The term
	// 'MSYS_NO_PATHCONV=1' is not recognized" and the hook never fires
	// (live-confirmed against Cursor 3.9.16, session 77fefbb3). PowerShell
	// (and cmd.exe) pass the /home/... arg to wsl.exe verbatim — they don't
	// do MSYS path translation — so the prefix that Git Bash needs is both
	// unnecessary AND fatal here. The v1.6.22 MSYS prefix targeted an older
	// Cursor that ran hooks through /bin/bash (Git Bash); the current
	// surface is PowerShell. isObserverWindowsCursorEntry still recognises
	// the legacy MSYS-prefixed shape, so refresh-on-drift replaces it.
	// (claude-code's Windows bridge cannot drop the MSYS protection: its
	// settings.json is run by Git Bash AND by PowerShell hosts, so it uses
	// portableBridgeCommand's `//` paths instead — AP-119.)
	wrapperPrefix := fmt.Sprintf("wsl.exe -d %s -- ", shellQuoteIfNeeded(distro))
	// FU-192: an entry in Observer's shape running another binary is kept.
	if r.refusesForeignBinary(&res, "hook.registerCursorWindows", res.ConfigPath, identityContent, shapedHooksInText(settings["hooks"], "cursor")) {
		return res
	}
	shapeDrift := shapeDriftEvents(settings["hooks"], flatCommandEntries(isObserverWindowsCursorEntry))
	for _, event := range cursorEvents {
		cmd := wrapperPrefix + shellQuoteIfNeeded(r.opts.BinaryPath) + " hook cursor " + event + r.configFlagSuffix()
		if shapeDrift[event] {
			// T-847: an Observer entry with a field Observer never writes
			// is rewritten (the typed decode below would drop it silently).
			shapeRewrite(&res, event, cmd, cmd)
			hooks[event] = dropCursorEntries(hooks[event], isObserverWindowsCursorEntry)
		}
		if slicesContainsCommand(hooks[event], cmd) {
			res.AlreadySet = append(res.AlreadySet, event)
			continue
		}
		// Stale-observer-entry case: any command starting with `wsl.exe`
		// that contains ` hook cursor ` was clearly written by a prior
		// observer install — we own it regardless of which observer
		// binary path it points at. This matters across upgrades,
		// distro changes, or smoke-test artifacts: the binary path
		// changes but the entry is still ours and should be refreshed,
		// not treated as a foreign conflict. filterStaleObserverWindowsCursorEntries
		// ALSO drops dangling one-off observer debug shims (see
		// isDanglingObserverWindowsCursorShim) that never carried the
		// canonical " hook cursor " signature.
		hooks[event] = filterStaleObserverWindowsCursorEntries(hooks[event], cmd, event, r.opts.ConfigPath)
		if r.refuses(res.ConfigPath, identityContent) && hasNonObserverWindowsCursorEntry(hooks[event]) {
			res.Error = fmt.Errorf("hook.registerCursorWindows: event %s already has a non-observer hook; pass --force to overwrite", event)
			return res
		}
		hooks[event] = append(hooks[event], cursorHookEntry{Command: cmd})
		res.HooksAdded = append(res.HooksAdded, event)
	}

	settings["version"] = json.RawMessage("1")
	hookJSON, err := json.Marshal(hooks)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerCursorWindows: marshal hooks: %w", err)
		return res
	}
	settings["hooks"] = hookJSON

	if r.opts.DryRun {
		return res
	}
	if err := writeJSONIndented(cursorDir, pinned, settings); err != nil {
		res.Error = err
		return res
	}
	if err := r.recordChecksum(res.Tool, res.ConfigPath); err != nil {
		res.Error = err
		return res
	}
	return res
}

// isObserverWindowsCursorEntry recognises an entry in the Windows-side
// hooks.json as observer-owned, in EITHER shape:
//
//   - the cross-OS bridge this registrar writes — a `wsl.exe ...`
//     invocation (with or without the legacy MSYS_NO_PATHCONV=1 env
//     prefix) that ultimately calls `<bin> hook cursor <event> ...`;
//   - a NATIVE `C:\...\observer.exe hook cursor <event>` entry written
//     by an earlier Windows-native npm `observer init`
//     (isObserverAnyHookEntry — class C2 / audit IDE-11, which found
//     exactly this in a live ~/.cursor/hooks.json);
//   - the orphaned observer HTTP-hook shape
//     (IsOrphanedObserverCursorHTTPHook) left by the lost 2026-09-08
//     build — recognised so refresh-on-drift heals it without --force.
//
// Recognising the native half is what lets refresh-on-drift REPLACE a
// stale native registration with the bridge command without --force,
// instead of erroring and leaving the native entry writing the
// stranded Windows DB. Anything else is foreign and still treated as a
// user-authored conflict.
func isObserverWindowsCursorEntry(cmd string) bool {
	if strings.Contains(cmd, " hook cursor ") {
		if strings.HasPrefix(cmd, "wsl.exe ") {
			return true
		}
		if strings.HasPrefix(cmd, "MSYS_NO_PATHCONV=1 wsl.exe ") {
			return true
		}
	}
	if IsOrphanedObserverCursorHTTPHook(cmd) {
		return true
	}
	return isObserverAnyHookEntry(cmd, "cursor")
}

// isDanglingObserverWindowsCursorShim recognises a stale
// observer-authored debug artifact for the Windows-Cursor bridge
// that does NOT carry the canonical " hook cursor " signature
// isObserverWindowsCursorEntry looks for — e.g. a one-off tee/debug
// wrapper (`wsl.exe -d <distro> -- /tmp/cursor-tee-shim.sh <event>
// --config '<ours>'`) left behind by a prior observer debugging
// session. It is recognised as ours ONLY when ALL three hold, so a
// genuinely user-authored PowerShell/cmd.exe hook is never
// misclassified as stale and silently dropped:
//
//   - cmd invokes via the wsl.exe cross-OS bridge shape (with or
//     without the legacy MSYS_NO_PATHCONV=1 prefix);
//   - cmd's --config argument points at THIS registrar's own config
//     file (configPath, threaded from Options.ConfigPath) — an empty
//     configPath never matches anything, since without it we can't
//     attribute authorship at all;
//   - cmd names event as a bare argument token.
//
// See docs/audits/cursor-windows-capture-diagnosis-2026-08-07.md §4
// F2: a dead /tmp/cursor-tee-shim.sh entry (the shim itself long
// gone — /tmp is cleared on WSL restart) permanently blocked
// auto-register by tripping hasNonObserverWindowsCursorEntry on
// every `observer start`, because it started with `wsl.exe ` but
// never contained ` hook cursor `.
func isDanglingObserverWindowsCursorShim(cmd, event, configPath string) bool {
	if configPath == "" {
		return false
	}
	if !strings.HasPrefix(cmd, "wsl.exe ") && !strings.HasPrefix(cmd, "MSYS_NO_PATHCONV=1 wsl.exe ") {
		return false
	}
	if !strings.Contains(cmd, "--config "+shellQuote(configPath)) {
		return false
	}
	return commandArgsInclude(cmd, event)
}

// filterStaleObserverWindowsCursorEntries drops any
// observer-recognised stale entry that doesn't match `want`,
// including dangling debug shims for this event
// (isDanglingObserverWindowsCursorShim). Used by the cursor-windows
// registrar to clear prior registrations before appending the
// canonical command. Non-observer entries pass through untouched so
// the conflict check below can flag them.
func filterStaleObserverWindowsCursorEntries(entries []cursorHookEntry, want, event, configPath string) []cursorHookEntry {
	out := make([]cursorHookEntry, 0, len(entries))
	for _, e := range entries {
		isOurs := isObserverWindowsCursorEntry(e.Command) || isDanglingObserverWindowsCursorShim(e.Command, event, configPath)
		if isOurs && e.Command != want {
			continue
		}
		out = append(out, e)
	}
	return out
}

// hasNonObserverWindowsCursorEntry reports whether the slice has any
// entry we don't recognise as observer-authored. Anything not
// matching the wsl.exe + `hook cursor` shape counts as foreign.
func hasNonObserverWindowsCursorEntry(entries []cursorHookEntry) bool {
	for _, e := range entries {
		if !isObserverWindowsCursorEntry(e.Command) {
			return true
		}
	}
	return false
}

// isWindowsPath returns true if s looks Windows-shaped (contains a
// backslash separator). Used by the codex registrar to pick a
// cmd.exe-safe quoter on Windows paths and the POSIX single-quote
// quoter on Linux/macOS paths. Path-shape rather than runtime.GOOS
// so cross-platform tests can exercise both shapes without OS
// mocking — and so a Linux host writing hooks for a Windows-side
// codex (via shared mounts, hypothetical) would also pick up the
// right quoting.
func isWindowsPath(s string) bool {
	return strings.Contains(s, `\`)
}

// forwardSlashPath converts a Windows-shaped path (backslash
// separators) into the forward-slash equivalent, leaving non-
// Windows-shaped paths untouched. Used by registerClaudeCode +
// registerCursor — both write hook commands that Claude Code on
// Windows invokes through Git Bash (per code.claude.com/docs/en/hooks:
// "Git Bash on Windows") OR through whatever inner shell the harness
// uses to wrap a single Bash-tool call (which may strip the
// single-quote wrapping the registrar applies). With backslash paths,
// every layer that loses the single quotes turns the unquoted
// backslashes into shell escape sequences and strips them —
// `D:\programsx\...` collapses to `D:programsx...` and bash exits 127
// "command not found". Forward-slash paths survive every shell
// wrapping intact: Git Bash, PowerShell, and cmd.exe all accept
// `D:/programsx/...` as a Windows file path, and forward slashes are
// never escape characters in any of those shells, so the path is
// untouched even when an upstream wrapper strips the registrar's
// quoting. This is the v1.8.2+ evolution of the v1.6.25 single-quote
// fix (see TestRegisterClaudeCodeQuotesWindowsBinaryPath for the
// original symptom); the single-quote fix worked when Claude Code
// ran the hook command directly in Git Bash but the harness's
// per-tool-call Bash wrapper would still strip the outer single
// quotes on intermittent invocation patterns (operator-reported
// 2026-06-06 across `wsl.exe`-style Bash-tool calls). Forward-slash
// normalization is the bulletproof fix because it removes the only
// character that any shell layer interprets specially.
func forwardSlashPath(s string) string {
	if !isWindowsPath(s) {
		return s
	}
	return strings.ReplaceAll(s, `\`, `/`)
}

// cmdQuoteIfNeeded wraps s in DOUBLE quotes when it contains
// cmd.exe-meaningful characters, otherwise returns it verbatim.
// Used by the codex registrar for Windows-shaped paths because
// Codex 0.133+ on Windows spawns hooks through cmd.exe, which only
// understands `"..."` quoting — `'...'` is interpreted literally
// as part of the argument (operator-reported 2026-05-23: codex
// hook fires exit 1 with `'C:\\...\\observer.exe'` because cmd
// can't find a binary whose name starts with a literal `'`).
//
// cmd.exe doesn't have backslash-as-escape inside `"..."`, so
// Windows paths round-trip cleanly without further escaping.
// Windows file names disallow `"` (NTFS-enforced), so we don't
// need to escape embedded quotes either.
//
// Trade-off vs shellQuoteIfNeeded: double-quote allows `$VAR`
// expansion in POSIX shells. Not a concern here — codex's
// codexCmdQuoteIfNeeded only routes to this when the path is
// Windows-shaped (the path will be evaluated by cmd.exe, not by
// /bin/sh).
func cmdQuoteIfNeeded(s string) string {
	if s == "" {
		return `""`
	}
	for _, r := range s {
		if r == ' ' || r == '"' || r == '&' || r == '<' || r == '>' || r == '|' || r == '^' || r == '(' || r == ')' || r == '%' {
			return `"` + s + `"`
		}
	}
	return s
}

// codexCmdQuoteIfNeeded picks between POSIX single-quote and
// cmd.exe double-quote based on the path shape. Used only by the
// codex registrar — claudecode + cursor stay on shellQuoteIfNeeded
// because Claude Code on Windows always uses Git Bash (POSIX) and
// cursor's hook execution shell on Windows-native is unverified
// (operator can re-target it if a regression appears there too).
//
// Path-shape detection rather than runtime.GOOS so cross-platform
// tests can pin both shapes without OS mocking.
func codexCmdQuoteIfNeeded(s string) string {
	if isWindowsPath(s) {
		return cmdQuoteIfNeeded(s)
	}
	return shellQuoteIfNeeded(s)
}

// unregisterClaudeCodeWindows removes hook entries this registrar
// previously wrote into the Windows-side .claude/settings.json. Mirrors
// unregisterClaudeCode but matches on the wsl.exe-wrapped signature
// rather than a binary-path prefix, so user-authored hooks (and stale
// observer entries from a different distro / binary path) are still
// recognised as ours. The user's non-observer entries are preserved.
func (r *Registry) unregisterClaudeCodeWindows() UnregistrationResult {
	res := UnregistrationResult{Tool: "claude-code-windows", DryRun: r.opts.DryRun}

	claudeDir := r.detectWindowsClaudeHome()
	if claudeDir == "" {
		res.Skipped = true
		return res
	}
	res.ConfigPath = filepath.Join(claudeDir, "settings.json")

	unlock, err := r.lockSettings(res.ConfigPath)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterClaudeCodeWindows: %w", err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(res.ConfigPath)

	raw, err := readSettingsFile(res.ConfigPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			res.Skipped = true
			return res
		}
		res.Error = fmt.Errorf("hook.unregisterClaudeCodeWindows: read: %w", err)
		return res
	}

	settings, err := decodeSettingsObject(res.ConfigPath, raw)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterClaudeCodeWindows: %w", err)
		return res
	}
	hooks := map[string][]claudeHookGroup{}
	if existing, ok := settings["hooks"]; ok {
		if err := json.Unmarshal(existing, &hooks); err != nil {
			res.Error = fmt.Errorf("hook.unregisterClaudeCodeWindows: parse hooks: %w", err)
			return res
		}
	}

	for event, groups := range hooks {
		foreign := false
		newGroups, removed, kept := filterClaudeGroupsWindows(groups, r.removableEntry("claude-code", isObserverWindowsClaudeEntry, &foreign))
		if foreign {
			noteKeptForeign(&res, event)
		}
		if removed > 0 {
			res.HooksRemoved = append(res.HooksRemoved, event)
		}
		if kept > 0 {
			res.HooksKept = append(res.HooksKept, event)
		}
		if len(newGroups) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = newGroups
		}
	}
	sort.Strings(res.HooksRemoved)
	sort.Strings(res.HooksKept)

	if len(res.HooksRemoved) == 0 {
		res.Skipped = true
		return res
	}

	match, err := r.checksumMatches(res.ConfigPath, raw)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterClaudeCodeWindows: checksum: %w", err)
		return res
	}
	res.ChecksumMatch = match
	if !match && !r.opts.Force {
		res.Error = safeErrorf("hook.unregisterClaudeCodeWindows: %s has been modified since install (checksum mismatch); pass --force to remove anyway", res.ConfigPath)
		return res
	}

	if len(hooks) == 0 {
		delete(settings, "hooks")
	} else {
		patched, err := json.Marshal(hooks)
		if err != nil {
			res.Error = fmt.Errorf("hook.unregisterClaudeCodeWindows: marshal hooks: %w", err)
			return res
		}
		settings["hooks"] = patched
	}

	if r.opts.DryRun {
		return res
	}

	if len(settings) == 0 {
		if err := removeEmptyConfigFile(res.ConfigPath, raw); err != nil {
			res.Error = fmt.Errorf("hook.unregisterClaudeCodeWindows: remove empty %s: %w", res.ConfigPath, err)
			return res
		}
	} else {
		if err := r.writeHookSettingsJSON("claude-code-windows", claudeDir, pinned, raw, settings); err != nil {
			res.Error = err
			return res
		}
	}
	if err := r.removeChecksum(res.ConfigPath); err != nil {
		res.Error = err
		return res
	}
	return res
}

// filterClaudeGroupsWindows walks groups, drops any command
// isObserverWindowsClaudeEntry recognises as ours — the wsl.exe-wrapped
// bridge invocation this registrar writes AND a native
// `observer.exe hook claude-code …` entry from an earlier
// Windows-native npm install (class C2) — and discards groups left
// empty. Removing the native shape too is deliberate: `observer
// uninstall` must not leave behind the very entry that was writing the
// stranded Windows DB. Returns the survivors plus removed / kept counts
// so the caller can decide whether to touch the file at all.
//
// mine is the uninstall's recogniser (isObserverWindowsClaudeEntry under the
// FU-203 judgement, removableEntry).
func filterClaudeGroupsWindows(groups []claudeHookGroup, mine func(string) bool) (out []claudeHookGroup, removed, kept int) {
	for _, g := range groups {
		var survivors []claudeHookCommand
		for _, h := range g.Hooks {
			if h.Type == "command" && mine(h.Command) {
				removed++
				continue
			}
			survivors = append(survivors, h)
		}
		if len(survivors) == 0 {
			continue
		}
		kept += len(survivors)
		out = append(out, claudeHookGroup{Matcher: g.Matcher, Hooks: survivors})
	}
	return out, removed, kept
}

// unregisterCursorWindows is unregisterCursor's cross-OS-bridge
// counterpart — mirrors unregisterClaudeCodeWindows's shape (FIX
// cluster, item 7b): `Register`'s switch has had a "cursor-windows"
// case (registerCursorWindows) since the bridge was built, but
// `Unregister`'s switch never got the matching case, and no
// unregisterCursorWindows function existed at all — so `observer
// uninstall --cursor` (or any direct Unregister("cursor-windows")
// call) could never remove a cursor-windows bridge entry it had
// written. Same checksum-guard discipline as unregisterClaudeCodeWindows/
// unregisterCodexWindows, and the same cross-OS home resolution
// (r.detectWindowsCursorHome/r.opts.WindowsCursorHome) registerCursorWindows
// already uses.
func (r *Registry) unregisterCursorWindows() UnregistrationResult {
	res := UnregistrationResult{Tool: "cursor-windows", DryRun: r.opts.DryRun}

	cursorDir := r.detectWindowsCursorHome()
	if cursorDir == "" {
		res.Skipped = true
		return res
	}
	path := filepath.Join(cursorDir, "hooks.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterCursorWindows: %w", err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(path)

	raw, err := readSettingsFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			res.Skipped = true
			return res
		}
		res.Error = fmt.Errorf("hook.unregisterCursorWindows: read: %w", err)
		return res
	}

	settings, err := decodeSettingsObject(path, raw)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterCursorWindows: %w", err)
		return res
	}
	hooks := map[string][]cursorHookEntry{}
	if existing, ok := settings["hooks"]; ok {
		_ = json.Unmarshal(existing, &hooks)
	}

	for event, entries := range hooks {
		var survivors []cursorHookEntry
		removed := 0
		foreign := false
		mine := r.removableEntry("cursor", isObserverWindowsCursorEntry, &foreign)
		for _, e := range entries {
			// isObserverWindowsCursorEntry recognises BOTH the wsl.exe
			// cross-OS bridge shape this registrar writes AND a native
			// observer.exe entry from an earlier Windows-native install
			// — mirrors filterClaudeGroupsWindows's own native+bridge
			// removal so `observer uninstall` never leaves behind the
			// entry that was writing the stranded Windows DB.
			if mine(e.Command) {
				removed++
				continue
			}
			survivors = append(survivors, e)
		}
		if foreign {
			noteKeptForeign(&res, event)
		}
		if removed > 0 {
			res.HooksRemoved = append(res.HooksRemoved, event)
		}
		if len(survivors) > 0 {
			res.HooksKept = append(res.HooksKept, event)
		}
		if len(survivors) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = survivors
		}
	}
	sort.Strings(res.HooksRemoved)
	sort.Strings(res.HooksKept)

	if len(res.HooksRemoved) == 0 {
		res.Skipped = true
		return res
	}

	match, err := r.checksumMatches(path, raw)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterCursorWindows: checksum: %w", err)
		return res
	}
	res.ChecksumMatch = match
	if !match && !r.opts.Force {
		res.Error = fmt.Errorf("hook.unregisterCursorWindows: %s has been modified since install (checksum mismatch); pass --force to remove anyway", path)
		return res
	}

	if len(hooks) == 0 {
		delete(settings, "hooks")
	} else {
		hookJSON, err := json.Marshal(hooks)
		if err != nil {
			res.Error = fmt.Errorf("hook.unregisterCursorWindows: marshal hooks: %w", err)
			return res
		}
		settings["hooks"] = hookJSON
	}

	if r.opts.DryRun {
		return res
	}

	// If the only surviving keys are the "version" registerCursorWindows
	// manufactured at install time, remove the file entirely so
	// uninstall leaves no trace — mirrors unregisterCursor's own
	// version-only cleanup.
	if len(settings) == 1 {
		if _, onlyVersion := settings["version"]; onlyVersion {
			delete(settings, "version")
		}
	}
	if len(settings) == 0 {
		if err := removeEmptyConfigFile(path, raw); err != nil {
			res.Error = fmt.Errorf("hook.unregisterCursorWindows: remove %s: %w", path, err)
			return res
		}
	} else {
		if err := writeJSONIndented(cursorDir, pinned, settings); err != nil {
			res.Error = err
			return res
		}
	}
	if err := r.removeChecksum(path); err != nil {
		res.Error = err
		return res
	}
	return res
}

// registerCodexWindows installs Codex hooks into a Windows-side
// `.codex/hooks.json` (typically `/mnt/c/Users/<u>/.codex/hooks.json`)
// with each command wrapped in
//
//	wsl.exe -d <distro> -- <linux-bin> hook codex <Event> [--config <wsl-path>]
//
// so a Windows-native Codex can fire hooks that EXECUTE inside the WSL
// daemon's OS-context and whose db.Open therefore resolves the daemon's
// own DB natively. This is the registration-layer cross-OS bridge
// CLAUDE.md's "Don't try to bridge cross-OS hook capture at the storage
// layer" prescribes; codex previously had no Windows hook target at all
// (only the identically-named codex-windows PROXY-ROUTE label in
// internal/proxyroute — a different subsystem writing config.toml's
// base_url).
//
// Quoting: cmd.exe double-quote-when-needed (cmdQuoteIfNeeded), NOT the
// POSIX single-quote the claude-code/cursor bridges use. Codex on
// Windows spawns hooks through cmd.exe, which treats `'...'` as literal
// argument text (the v1.6.25 → 2026-05-23 regression codexCmdQuoteIfNeeded
// exists for). For the same reason there is NO `MSYS_NO_PATHCONV=1`
// prefix: that is a bash-ism, and cmd.exe would try to run it as a
// program. The Linux-side paths inside the WSL command normally contain
// no cmd.exe-meaningful character, so in practice nothing is quoted at
// all and the arguments reach wsl.exe verbatim.
//
// Distro lookup: Options.WSLDistro → $WSL_DISTRO_NAME. Empty distro is
// an error; the command would be ambiguous on a host with multiple
// distros. Same contract as registerCursorWindows /
// registerClaudeCodeWindows.
//
// Like registerCodex it also ensures `[features].hooks = true` in the
// WINDOWS-side config.toml — codex reads hooks.json but never dispatches
// without that flag, and the Windows install has its own config.toml.
func (r *Registry) registerCodexWindows() RegistrationResult {
	res := RegistrationResult{Tool: "codex-windows", DryRun: r.opts.DryRun}

	codexDir := r.detectWindowsCodexHome()
	if codexDir == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsCodexHome) {
			r.sandboxSkipResult(&res, ".codex", "WindowsCodexHome", r.opts.WindowsCodexHome)
			return res
		}
		res.Error = errors.New("hook.registerCodexWindows: no Windows-side .codex/ detected (set WindowsCodexHome explicitly or run on a host where crossmount sees /mnt/c/Users/<u>/.codex/)")
		return res
	}

	distro := r.opts.WSLDistro
	if distro == "" {
		distro = os.Getenv("WSL_DISTRO_NAME")
	}
	if distro == "" {
		res.Error = safeErrorf("hook.registerCodexWindows: WSL distro unknown: set Options.WSLDistro or run inside WSL (so $WSL_DISTRO_NAME is set)")
		return res
	}

	if err := codexWindowsBridgePathError("hook.registerCodexWindows", distro, r.opts.BinaryPath, r.opts.ConfigPath); err != nil {
		res.Error = err
		return res
	}

	return r.registerCodexAt(codexHookTarget{
		tool:      "codex-windows",
		dir:       codexDir,
		wrapper:   "wsl.exe -d " + cmdQuoteIfNeeded(distro) + " -- ",
		quote:     cmdQuoteIfNeeded,
		errPrefix: "hook.registerCodexWindows",
		matchMine: isObserverCodexEntry,
		trustKey:  crossmount.WindowsPathFromMount,
		commandFor: func(event, legacy string) string {
			return r.gateBridgeCommand("codex", filepath.Dir(codexDir), distro, event, event, legacy)
		},
	})
}

// codexWindowsBridgeUnsafe are the characters a codex-windows bridge command
// cannot carry in its distro, binary or config path (FU-162). Codex on
// Windows runs the command through `powershell.exe -NoProfile -Command`, and
// wsl.exe hands everything after `--` to the distro's shell, so $, a
// backtick, a quote, ;, &, |, <, >, ( and ) are re-read by PowerShell or by
// that shell whatever quoting the entry carries: probed live on Windows
// PowerShell 5.1 and wsl.exe (2026-10-29), each of $, a backtick, ', ;, &
// and ( broke the call. A space and % pass: the double quotes
// cmdQuoteIfNeeded writes reach the Linux shell.
const codexWindowsBridgeUnsafe = "$`'\";&|<>()\r\n"

// codexWindowsBridgePathError refuses a codex-windows distro, binary or
// config path that holds a codexWindowsBridgeUnsafe character: such an entry
// would fail on every call, and Codex reads a failed hook as non-blocking.
func codexWindowsBridgePathError(errPrefix string, fields ...string) error {
	for _, f := range fields {
		if i := strings.IndexAny(f, codexWindowsBridgeUnsafe); i >= 0 {
			return safeErrorf("%s: %q holds %q, which Codex's PowerShell wrapper or the Linux shell behind wsl.exe would re-read; install observer under a path without it", errPrefix, f, f[i:i+1])
		}
	}
	return nil
}

// unregisterCodexWindows removes the hook entries the codex-windows
// bridge wrote from the Windows-side .codex/hooks.json. Mirrors
// unregisterCodex against the detected Windows home; a host with no
// Windows-side .codex is a no-op Skip, not an error (there is nothing
// to clean). isObserverCodexEntry recognises the native and the
// wsl.exe-bridge shapes alike, so a stale native
// `observer.exe hook codex …` entry is cleaned up too (class C2).
func (r *Registry) unregisterCodexWindows() UnregistrationResult {
	codexDir := r.detectWindowsCodexHome()
	if codexDir == "" {
		return UnregistrationResult{Tool: "codex-windows", DryRun: r.opts.DryRun, Skipped: true}
	}
	return r.unregisterCodexAt("codex-windows", codexDir, "hook.unregisterCodexWindows", crossmount.WindowsPathFromMount)
}

// --- Part B item 1/2 cross-OS bridges -----------------------------------
//
// The six long-tail vendors' own "<tool>-windows" registration targets:
// a WSL daemon writing a wsl.exe-bridged hook command into a Windows-side
// config file, mirroring registerClaudeCodeWindows / registerCursorWindows
// / registerCodexWindows (see CLAUDE.md's "Don't try to bridge cross-OS
// hook capture at the storage layer"). Devin Desktop's bridge,
// devin-windows, lives with the other Wave 7 IDE targets in
// register_crossos_ide.go (surface-gap IDE-6).

// resolveWSLDistro returns the WSL distribution the cross-OS bridge
// registrars invoke via `wsl.exe -d <distro>`, honoring Options.WSLDistro
// before falling back to $WSL_DISTRO_NAME. errPrefix names the calling
// registrar in the wrapped error when neither is set — the command would
// be ambiguous on a host with multiple distros. Same contract as the
// inline distro resolution registerClaudeCodeWindows / registerCursorWindows
// / registerCodexWindows each already duplicate.
func (r *Registry) resolveWSLDistro(errPrefix string) (string, error) {
	distro := r.opts.WSLDistro
	if distro == "" {
		distro = os.Getenv("WSL_DISTRO_NAME")
	}
	if distro == "" {
		return "", safeErrorf("%s: WSL distro unknown: set Options.WSLDistro or run inside WSL (so $WSL_DISTRO_NAME is set)", errPrefix)
	}
	return distro, nil
}

// gitBashWrapper returns the "MSYS_NO_PATHCONV=1 wsl.exe -d <distro> -- "
// prefix every settings.json/hooks.json/settings.yaml *-windows bridge in
// this section wraps its command with — same convention
// registerClaudeCodeWindows / registerCursorWindows already established
// (these tools spawn hooks through Git Bash on Windows; see
// registerClaudeCodeWindows's doc comment for the MSYS_NO_PATHCONV
// rationale), NOT codex's cmd.exe convention.
func gitBashWrapper(distro string) string {
	return "MSYS_NO_PATHCONV=1 wsl.exe -d " + shellQuoteIfNeeded(distro) + " -- "
}

// bridgeExitTrailer ends every portable bridge command. PowerShell
// reports a native command's exit 2 as 1 unless the script exits with
// $LASTEXITCODE; Git Bash leaves the variable unset, so `exit` alone
// returns the last command's status there (AP-119).
const bridgeExitTrailer = "; exit $LASTEXITCODE"

// msysLiteralPath doubles the leading slash of an absolute POSIX path so
// Git Bash's MSYS argument conversion leaves it alone; Linux resolves
// `//home/...` exactly like `/home/...`. Any other value is returned as
// is. unMSYSLiteralPath is its inverse.
func msysLiteralPath(p string) string {
	if strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") {
		return "/" + p
	}
	return p
}

// unMSYSLiteralPath undoes msysLiteralPath: `//x` becomes `/x`; `/x`,
// `///x` and every other value is returned as is.
func unMSYSLiteralPath(p string) string {
	if strings.HasPrefix(p, "//") && !strings.HasPrefix(p, "///") {
		return p[1:]
	}
	return p
}

// portableBridgeCommand builds the wsl.exe bridge command that runs the
// same way under Git Bash (and Git's sh), PowerShell 5.1 and cmd.exe
// (AP-119; see registerClaudeCodeWindows for the per-shell findings):
//
//	wsl.exe -d <distro> -- //<bin> hook <tool> <event> [--config '//<cfg>']; exit $LASTEXITCODE
//
// Only POSIX single quotes are used, which mean the same literal in bash
// and PowerShell; portableBridgePathError refuses the one character they
// escape differently.
func portableBridgeCommand(distro, binary, tool, event, configPath string) string {
	cmd := "wsl.exe -d " + shellQuoteIfNeeded(distro) + " -- " +
		shellQuoteIfNeeded(msysLiteralPath(binary)) + " hook " + tool + " " + event
	if configPath != "" {
		cmd += " --config " + shellQuote(msysLiteralPath(configPath))
	}
	return cmd + bridgeExitTrailer
}

// portableBridgePathError refuses a binary or config path that no
// portable bridge command can quote: inside single quotes bash escapes a
// quote as quote-backslash-quote-quote and PowerShell as a doubled quote,
// so no one spelling works in both.
func portableBridgePathError(errPrefix string, paths ...string) error {
	for _, p := range paths {
		if strings.Contains(p, "'") {
			return safeErrorf("%s: path %q contains a single quote, which cannot be quoted for both Git Bash and PowerShell; install observer under a path without one", errPrefix, p)
		}
	}
	return nil
}

// trimBridgeExitTrailer removes the portable bridge's trailing
// `; exit $LASTEXITCODE` so the tokenizers see only the observer
// invocation. ok reports whether the trailer was present.
func trimBridgeExitTrailer(cmd string) (body string, ok bool) {
	trimmed := strings.TrimRight(cmd, " \t")
	if body, found := strings.CutSuffix(trimmed, bridgeExitTrailer); found {
		return strings.TrimRight(body, " \t"), true
	}
	return cmd, false
}

// registerGeminiCLIWindows installs the prompt-submit hook into a
// Windows-side .gemini/settings.json (typically
// /mnt/c/Users/<u>/.gemini/settings.json) with the command wrapped in
// the wsl.exe bridge (gitBashWrapper) so a Windows-native Gemini CLI can
// fire a hook that executes inside the WSL daemon's own OS-context.
func (r *Registry) registerGeminiCLIWindows() RegistrationResult {
	res := RegistrationResult{Tool: "gemini-cli-windows", DryRun: r.opts.DryRun}
	dir := r.detectWindowsGeminiHome()
	if dir == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsGeminiHome) {
			r.sandboxSkipResult(&res, ".gemini", "WindowsGeminiHome", r.opts.WindowsGeminiHome)
			return res
		}
		res.Error = errors.New("hook.registerGeminiCLIWindows: no Windows-side .gemini/ detected (set WindowsGeminiHome explicitly or run on a host where crossmount sees /mnt/c/Users/<u>/.gemini/)")
		return res
	}
	distro, err := r.resolveWSLDistro("hook.registerGeminiCLIWindows")
	if err != nil {
		res.Error = err
		return res
	}
	return r.registerGenericSettingsHooks(genericSettingsHookTarget{
		tool:       "gemini-cli",
		resultTool: "gemini-cli-windows",
		dir:        dir,
		event:      "BeforeAgent",
		errPrefix:  "hook.registerGeminiCLIWindows",
		wrapper:    gitBashWrapper(distro),
	})
}

// unregisterGeminiCLIWindows removes the hook entry the
// gemini-cli-windows bridge wrote from the Windows-side
// .gemini/settings.json. A host with no Windows-side .gemini is a no-op
// Skip, not an error.
func (r *Registry) unregisterGeminiCLIWindows() UnregistrationResult {
	dir := r.detectWindowsGeminiHome()
	if dir == "" {
		return UnregistrationResult{Tool: "gemini-cli-windows", DryRun: r.opts.DryRun, Skipped: true}
	}
	return r.unregisterGenericSettingsHooks(genericSettingsHookTarget{
		tool: "gemini-cli", resultTool: "gemini-cli-windows",
		dir: dir, event: "BeforeAgent", errPrefix: "hook.unregisterGeminiCLIWindows",
	})
}

// registerQwenCodeWindows is registerGeminiCLIWindows's Qwen Code
// counterpart: a Windows-side .qwen/settings.json, single event
// UserPromptSubmit.
func (r *Registry) registerQwenCodeWindows() RegistrationResult {
	res := RegistrationResult{Tool: "qwen-code-windows", DryRun: r.opts.DryRun}
	dir := r.detectWindowsQwenHome()
	if dir == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsQwenHome) {
			r.sandboxSkipResult(&res, ".qwen", "WindowsQwenHome", r.opts.WindowsQwenHome)
			return res
		}
		res.Error = errors.New("hook.registerQwenCodeWindows: no Windows-side .qwen/ detected (set WindowsQwenHome explicitly or run on a host where crossmount sees /mnt/c/Users/<u>/.qwen/)")
		return res
	}
	distro, err := r.resolveWSLDistro("hook.registerQwenCodeWindows")
	if err != nil {
		res.Error = err
		return res
	}
	return r.registerGenericSettingsHooks(genericSettingsHookTarget{
		tool:       "qwen-code",
		resultTool: "qwen-code-windows",
		dir:        dir,
		event:      "UserPromptSubmit",
		errPrefix:  "hook.registerQwenCodeWindows",
		wrapper:    gitBashWrapper(distro),
	})
}

// unregisterQwenCodeWindows is unregisterGeminiCLIWindows's Qwen Code
// counterpart.
func (r *Registry) unregisterQwenCodeWindows() UnregistrationResult {
	dir := r.detectWindowsQwenHome()
	if dir == "" {
		return UnregistrationResult{Tool: "qwen-code-windows", DryRun: r.opts.DryRun, Skipped: true}
	}
	return r.unregisterGenericSettingsHooks(genericSettingsHookTarget{
		tool: "qwen-code", resultTool: "qwen-code-windows",
		dir: dir, event: "UserPromptSubmit", errPrefix: "hook.unregisterQwenCodeWindows",
	})
}

// registerQoderWindows is registerGeminiCLIWindows's Qoder counterpart:
// a Windows-side .qoder/settings.json, single event UserPromptSubmit.
func (r *Registry) registerQoderWindows() RegistrationResult {
	res := RegistrationResult{Tool: "qoder-windows", DryRun: r.opts.DryRun}
	dir := r.detectWindowsQoderHome()
	if dir == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsQoderHome) {
			r.sandboxSkipResult(&res, ".qoder", "WindowsQoderHome", r.opts.WindowsQoderHome)
			return res
		}
		res.Error = errors.New("hook.registerQoderWindows: no Windows-side .qoder/ detected (set WindowsQoderHome explicitly or run on a host where crossmount sees /mnt/c/Users/<u>/.qoder/)")
		return res
	}
	distro, err := r.resolveWSLDistro("hook.registerQoderWindows")
	if err != nil {
		res.Error = err
		return res
	}
	return r.registerGenericSettingsHooks(genericSettingsHookTarget{
		tool:       "qoder",
		resultTool: "qoder-windows",
		dir:        dir,
		event:      "UserPromptSubmit",
		errPrefix:  "hook.registerQoderWindows",
		wrapper:    gitBashWrapper(distro),
	})
}

// unregisterQoderWindows is unregisterGeminiCLIWindows's Qoder
// counterpart.
func (r *Registry) unregisterQoderWindows() UnregistrationResult {
	dir := r.detectWindowsQoderHome()
	if dir == "" {
		return UnregistrationResult{Tool: "qoder-windows", DryRun: r.opts.DryRun, Skipped: true}
	}
	return r.unregisterGenericSettingsHooks(genericSettingsHookTarget{
		tool: "qoder", resultTool: "qoder-windows",
		dir: dir, event: "UserPromptSubmit", errPrefix: "hook.unregisterQoderWindows",
	})
}

// registerFactoryDroidWindows installs the prompt-submit hook into a
// Windows-side .factory/hooks.json with the command wsl.exe-bridged
// (gitBashWrapper). Single event: UserPromptSubmit.
func (r *Registry) registerFactoryDroidWindows() RegistrationResult {
	res := RegistrationResult{Tool: "droid-windows", DryRun: r.opts.DryRun}
	dir := r.detectWindowsFactoryHome()
	if dir == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsFactoryHome) {
			r.sandboxSkipResult(&res, ".factory", "WindowsFactoryHome", r.opts.WindowsFactoryHome)
			return res
		}
		res.Error = errors.New("hook.registerFactoryDroidWindows: no Windows-side .factory/ detected (set WindowsFactoryHome explicitly or run on a host where crossmount sees /mnt/c/Users/<u>/.factory/)")
		return res
	}
	distro, err := r.resolveWSLDistro("hook.registerFactoryDroidWindows")
	if err != nil {
		res.Error = err
		return res
	}
	return r.registerFactoryDroidAt(droidHookTarget{
		tool:      "droid-windows",
		dir:       dir,
		wrapper:   gitBashWrapper(distro),
		errPrefix: "hook.registerFactoryDroidWindows",
	})
}

// unregisterFactoryDroidWindows removes the hook group the
// droid-windows bridge wrote from the Windows-side .factory/hooks.json.
func (r *Registry) unregisterFactoryDroidWindows() UnregistrationResult {
	dir := r.detectWindowsFactoryHome()
	if dir == "" {
		return UnregistrationResult{Tool: "droid-windows", DryRun: r.opts.DryRun, Skipped: true}
	}
	return r.unregisterFactoryDroidAt("droid-windows", dir, "hook.unregisterFactoryDroidWindows")
}

// registerPoolsideWindows installs the prompt-submit hook into a
// Windows-side .config/poolside/settings.yaml with the command
// wsl.exe-bridged (gitBashWrapper). Single event: UserPromptSubmit.
func (r *Registry) registerPoolsideWindows() RegistrationResult {
	res := RegistrationResult{Tool: "poolside-windows", DryRun: r.opts.DryRun}
	dir := r.detectWindowsPoolsideHome()
	if dir == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsPoolsideHome) {
			r.sandboxSkipResult(&res, filepath.Join(".config", "poolside"), "WindowsPoolsideHome", r.opts.WindowsPoolsideHome)
			return res
		}
		res.Error = errors.New("hook.registerPoolsideWindows: no Windows-side .config/poolside/ detected (set WindowsPoolsideHome explicitly or run on a host where crossmount sees /mnt/c/Users/<u>/.config/poolside/)")
		return res
	}
	distro, err := r.resolveWSLDistro("hook.registerPoolsideWindows")
	if err != nil {
		res.Error = err
		return res
	}
	return r.registerPoolsideAt(poolsideHookTarget{
		tool:      "poolside-windows",
		dir:       dir,
		wrapper:   gitBashWrapper(distro),
		errPrefix: "hook.registerPoolsideWindows",
	})
}

// unregisterPoolsideWindows removes the hook entry the
// poolside-windows bridge wrote from the Windows-side settings.yaml.
func (r *Registry) unregisterPoolsideWindows() UnregistrationResult {
	dir := r.detectWindowsPoolsideHome()
	if dir == "" {
		return UnregistrationResult{Tool: "poolside-windows", DryRun: r.opts.DryRun, Skipped: true}
	}
	return r.unregisterPoolsideAt("poolside-windows", dir, "hook.unregisterPoolsideWindows")
}

// registerCommandCodeWindows installs commandcode's Mods SDK bridge into
// a Windows-side .commandcode/mods/observer-guard.ts (typically
// /mnt/c/Users/<u>/.commandcode/mods/observer-guard.ts), baking in the
// WSL distro + the Linux-side observer binary path so the mod's OWN
// runtime (observer-guard.ts's resolveExec()) shells out through
// wsl.exe when it detects it is running on win32 — see
// commandcodemod.WritePluginBridge. Unlike every hooks.json/
// settings.json/settings.yaml *-windows writer above, there is no
// wrapper string built HERE: the wsl.exe bridge decision is made at
// RUNTIME inside the TS mod (commandcode's own Node process is the one
// that knows its own platform at hook-fire time), not baked into a
// static shell command the way a JSON/YAML hooks entry is.
func (r *Registry) registerCommandCodeWindows() RegistrationResult {
	res := RegistrationResult{Tool: "command-code-windows", DryRun: r.opts.DryRun}
	winHome := r.detectWindowsCommandCodeHome()
	if winHome == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsCommandCodeHome) {
			r.sandboxSkipResult(&res, ".commandcode", "WindowsCommandCodeHome", r.opts.WindowsCommandCodeHome)
			return res
		}
		res.Error = errors.New("hook.registerCommandCodeWindows: no Windows-side .commandcode/ detected (set WindowsCommandCodeHome explicitly or run on a host where crossmount sees /mnt/c/Users/<u>/.commandcode/)")
		return res
	}
	distro, err := r.resolveWSLDistro("hook.registerCommandCodeWindows")
	if err != nil {
		res.Error = err
		return res
	}
	dir := filepath.Join(winHome, "mods")
	path := filepath.Join(dir, commandcodemod.ModFileName)
	res.ConfigPath = path

	events := commandcodemod.EventsExcept(func(e string) bool { return r.skipEvent("command-code-windows", e) })
	names := commandcodemod.NamesOf(events)
	// Byte-exact currency, as registerCommandCode (T-847).
	want, err := commandcodemod.RenderPluginBridgeEvents(r.opts.BinaryPath, distro, r.opts.ConfigPath, events)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerCommandCodeWindows: %w", err)
		return res
	}
	existing, readErr := os.ReadFile(path)
	// The same guard as registerCommandCode (FU-207): a file that does not
	// read as Observer's mod is refused without --force, a neutralised mod
	// on a managed repair pass is rewritten (T-872), and a mod whose PROFILE
	// runs a binary that is not judged an Observer binary is kept (FU-192).
	var foreign, repair bool
	if readErr == nil {
		foreign, repair, err = r.occupiedOwnedFile("hook.registerCommandCodeWindows", path, commandcodemod.LooksLikeObserverPlugin(existing), shapedHooksInPluginProfile(existing))
		if err != nil {
			res.Error = err
			return res
		}
	}
	current := readErr == nil && !foreign && bytes.Equal(existing, want)
	if r.opts.DryRun {
		if current {
			res.AlreadySet = names
		} else {
			res.HooksAdded = names
		}
		return res
	}
	if foreign {
		if err := keepReplacedBytes(&res, path, existing, repair); err != nil {
			res.Error = fmt.Errorf("hook.registerCommandCodeWindows: %w", err)
			return res
		}
	}
	if err := commandcodemod.WritePluginBridgeEvents(dir, r.opts.BinaryPath, distro, r.opts.ConfigPath, events); err != nil {
		res.Error = fmt.Errorf("hook.registerCommandCodeWindows: %w", err)
		return res
	}
	// The checksum the native writer records, so the managed-integrity
	// probe can tell this file's tamper from a clean install (T-847).
	if err := r.recordChecksum(res.Tool, path); err != nil {
		res.Error = fmt.Errorf("hook.registerCommandCodeWindows: %w", err)
		return res
	}
	if current {
		res.AlreadySet = names
	} else {
		res.HooksAdded = names
	}
	if repair {
		noteOwnedRepair(&res, path, names)
	}
	return res
}

// unregisterCommandCodeWindows removes the observer-guard.ts mod file
// from the Windows-side .commandcode/mods/. A host with no Windows-side
// .commandcode is a no-op Skip, not an error.
func (r *Registry) unregisterCommandCodeWindows() UnregistrationResult {
	winHome := r.detectWindowsCommandCodeHome()
	if winHome == "" {
		return UnregistrationResult{Tool: "command-code-windows", DryRun: r.opts.DryRun, Skipped: true}
	}
	dir := filepath.Join(winHome, "mods")
	res := UnregistrationResult{
		Tool:       "command-code-windows",
		DryRun:     r.opts.DryRun,
		ConfigPath: filepath.Join(dir, commandcodemod.ModFileName),
	}
	raw, err := os.ReadFile(res.ConfigPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			res.Error = fmt.Errorf("hook.unregisterCommandCodeWindows: read: %w", err)
		}
		return res
	}
	// FU-203: a mod whose PROFILE runs a binary that is not judged an
	// Observer binary is kept, with or without --force; so is a file that
	// is not Observer's mod (FU-212, the native mod's and the plugin
	// shim's rule), reported in FilesKeptForeign.
	if r.keepsForeignBinary(shapedHooksInPluginProfile(raw)) {
		res.HooksKept = commandcodemod.EventNames()
		noteKeptForeign(&res, res.HooksKept...)
		return res
	}
	if !commandcodemod.LooksLikeObserverPlugin(raw) {
		noteKeptForeignFile(&res, res.ConfigPath)
		return res
	}
	if r.opts.DryRun {
		res.HooksRemoved = commandcodemod.EventNames()
		return res
	}
	if err := removeEmptyConfigFile(res.ConfigPath, raw); err != nil {
		res.Error = fmt.Errorf("hook.unregisterCommandCodeWindows: %w", err)
		return res
	}
	res.HooksRemoved = commandcodemod.EventNames()
	return res
}
