package hook

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// --- Statusline registration (docs/plans/observer-statusline-plan-2026-07-30.md §5.1) ---
//
// This is a NEW, independent registration surface — a sibling of the hook
// registration above, not a variant of it. It patches a different
// top-level key ("statusLine") in the exact same ~/.claude/settings.json
// file that registerClaudeCode patches ("hooks"), using the identical
// read-preserve-write map[string]json.RawMessage shape so unknown keys
// (and the "hooks" key itself) survive byte-for-byte. registerClaudeCode
// and every other existing function in this file are NOT modified by
// this addition — only new sibling functions are added below, and the
// entry points (RegisterClaudeCodeStatusline / UnregisterClaudeCodeStatusline)
// are deliberately NOT wired into the tool-name-dispatched Register/
// Unregister switches above, so those two functions also stay untouched.
//
// v1 scope is claude-code (native OS) ONLY — see
// runStatuslineInit's doc comment in cmd/observer/init.go for the
// cross-OS (WSL bridge) decision: a Windows-side Claude Code reached
// only via crossmount is deliberately NOT bridged here (unlike hooks,
// a statusLine command runs on every render tick, and a wsl.exe
// subprocess spawn per tick risks the plan's <100ms budget); the
// caller WARNs instead of silently doing nothing.

// claudeStatuslineEntry is the shape written into settings.json's
// top-level "statusLine" key: `{"type":"command","command":"<bin>
// statusline","padding":0}`. Distinct from claudeHookGroup/
// claudeHookCommand — the "statusLine" key is never merged with
// "hooks" (CLAUDE.md #4: one owner per piece of state; this struct
// owns exactly the "statusLine" value, nothing else in the file).
type claudeStatuslineEntry struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Padding int    `json:"padding"`
}

// isObserverStatuslineEntry recognises a "statusLine" command as one
// previously written by ANY observer registrar. Unlike
// isObserverClaudeEntry — whose ` hook claude-code ` signature is
// observer-internal syntax nobody else writes — "statusline" is a
// GENERIC word other statusline tools use as a subcommand, so a bare
// substring test is not a safe ownership signal: `node /opt/acme
// statusline --theme compact` would have been silently overwritten by
// register (or uninstalled by unregister) as if it were ours.
//
// Ownership therefore requires BOTH halves of the command shape we
// actually write (`<quoted-bin-path> statusline`):
//
//  1. the executable token's basename is an observer binary
//     (isObserverBinaryToken), and
//  2. the very next argument is exactly "statusline".
//
// Anything else — a foreign executable, "statusline" appearing only as
// a later flag value, an unparseable command — is FOREIGN, which means
// register blocks without --force and unregister leaves it alone.
// Trailing arguments after "statusline" are tolerated so a future
// flag-carrying variant of our own command still refreshes rather than
// tripping the conflict guard.
func isObserverStatuslineEntry(cmd string) bool {
	toks := splitCommandTokens(cmd)
	if len(toks) < 2 || toks[1] != "statusline" {
		return false
	}
	return isObserverBinaryToken(toks[0])
}

// isObserverBinaryToken reports whether an executable token names an
// observer binary, by basename. Accepts the plain names (`observer`,
// `superbased`, with or without a `.exe` tail) plus the
// `observer-<something>` / `superbased-<something>` family, because
// real installs DO carry suffixed names (`observer-v1.8.3` from a
// versioned download, `observer-hermes.exe`, a `/tmp/observer-A` A/B
// build) and a path-shape-strict test would misclassify our own
// earlier registration as foreign — the exact failure mode
// isObserverClaudeEntry's content-heuristic exists to avoid (a stale
// entry that can no longer be refreshed without --force).
// Case-insensitive: Windows paths are.
func isObserverBinaryToken(tok string) bool {
	base := strings.ToLower(commandBaseName(tok))
	base = strings.TrimSuffix(base, ".exe")
	if base == "observer" || base == "superbased" {
		return true
	}
	return strings.HasPrefix(base, "observer-") || strings.HasPrefix(base, "superbased-")
}

// commandBaseName returns the final path element of an executable
// token, splitting on EITHER separator — the token may be a
// forward-slash-normalized Windows path (see forwardSlashPath) or a
// native backslash one, and filepath.Base only knows the host's
// separator.
func commandBaseName(tok string) string {
	if i := strings.LastIndexAny(tok, `/\`); i >= 0 {
		return tok[i+1:]
	}
	return tok
}

// registerClaudeCodeStatusline installs (or refreshes) the
// "statusLine" top-level key in ~/.claude/settings.json, wired to
// `<binary> statusline`. Conflict discipline mirrors
// hasConflictingClaudeHook: a foreign (non-observer) existing value
// blocks without --force — more conservative here than for hooks,
// because "statusLine" is a single, visible UI slot (unlike hooks,
// which fan out across many named events with no single-slot
// contention), so clobbering a user's own statusline silently would
// be a materially worse experience than clobbering one hook event.
// An observer-recognised entry (by isObserverStatuslineEntry)
// refreshes silently on drift (binary path moved, quoting changed).
// An entry that already matches byte-for-byte is reported via
// AlreadySet and the file is NOT rewritten at all (idempotent
// re-run — no needless mtime/checksum churn), mirroring how
// registerClaudeCode's observerCmdMatches short-circuits per event.
func (r *Registry) registerClaudeCodeStatusline() RegistrationResult {
	res := RegistrationResult{Tool: "claude-code-statusline", DryRun: r.opts.DryRun}
	settingsDir, err := r.claudeConfigDir()
	if err != nil {
		res.Error = err
		return res
	}
	path := filepath.Join(settingsDir, "settings.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerClaudeCodeStatusline: %w", err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(path)

	raw, err := readSettingsFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Error = fmt.Errorf("hook.registerClaudeCodeStatusline: read: %w", err)
		return res
	}
	// Preserve unknown top-level fields (including "hooks") via
	// map[string]json.RawMessage — identical shape to registerClaudeCode.
	settings := map[string]json.RawMessage{}
	if len(raw) > 0 {
		settings, err = decodeSettingsObject(path, raw)
		if err != nil {
			res.Error = fmt.Errorf("hook.registerClaudeCodeStatusline: %w", err)
			return res
		}
	}

	// Same forward-slash + shell-quote binary-path handling the hook
	// registrars use — see forwardSlashPath's docstring for the Git
	// Bash / harness-wrapper rationale.
	binPath := forwardSlashPath(r.opts.BinaryPath)
	desired := claudeStatuslineEntry{
		Type:    "command",
		Command: shellQuoteIfNeeded(binPath) + " statusline",
		Padding: 0,
	}

	if existing, ok := settings["statusLine"]; ok {
		var cur claudeStatuslineEntry
		parsed := json.Unmarshal(existing, &cur) == nil
		switch {
		case parsed && cur == desired:
			res.AlreadySet = append(res.AlreadySet, "statusLine")
			return res
		case parsed && isObserverStatuslineEntry(cur.Command):
			// Observer-owned but stale (binary path/quoting drifted) —
			// silently refresh; fall through to overwrite below.
		case r.opts.Force:
			// Foreign (or unparseable) value, but the operator passed
			// --force — fall through to overwrite below.
		default:
			// The foreign command is a value read from settings.json, a
			// credential-bearing file (D-268): it is not echoed back.
			res.Error = safeErrorf("hook.registerClaudeCodeStatusline: %s already has a non-observer \"statusLine\" command; pass --force to overwrite", path)
			return res
		}
	}

	patched, err := json.Marshal(desired)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerClaudeCodeStatusline: marshal: %w", err)
		return res
	}
	settings["statusLine"] = patched
	res.HooksAdded = append(res.HooksAdded, "statusLine")

	if r.opts.DryRun {
		return res
	}
	// No hook_checksums.json write: settings.json's entry is the HOOK
	// writer's (a digest of the "hooks" subtree for this credential-
	// bearing file, D-268), which this writer never touches. Recording it
	// here would re-baseline the hook drift guard over a hooks edit the
	// user made after the hook install. Ownership of "statusLine" is read
	// from the command itself, the --statusline-tools writer's rule.
	if err := r.writeHookSettingsJSON("claude-code", settingsDir, pinned, raw, settings); err != nil {
		res.Error = err
		return res
	}
	return res
}

// unregisterClaudeCodeStatusline removes the "statusLine" top-level
// key from ~/.claude/settings.json ENTIRELY (not blanked) — so a user
// who opts out gets Claude Code's own default statusline back, not an
// empty one. Only an entry recognised as observer-written (via
// isObserverStatuslineEntry) is ever removed; a foreign/user-authored
// "statusLine" is left untouched and reported via HooksKept, mirroring
// how unregisterClaudeCode preserves non-observer hook entries.
//
// It neither consults nor removes the file's hook_checksums.json entry:
// that entry is the hook writer's (see registerClaudeCodeStatusline).
// Removing it stranded the hook uninstall's drift guard (a later
// `observer init --uninstall` refused without --force), and requiring it
// made this uninstall refuse after the hook uninstall had removed it.
// The write itself preserves every other member under the settings lock,
// so there is no other-key edit for a guard to protect.
func (r *Registry) unregisterClaudeCodeStatusline() UnregistrationResult {
	res := UnregistrationResult{Tool: "claude-code-statusline", DryRun: r.opts.DryRun}
	settingsDir, err := r.claudeConfigDir()
	if err != nil {
		res.Error = err
		return res
	}
	path := filepath.Join(settingsDir, "settings.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterClaudeCodeStatusline: %w", err)
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
		res.Error = fmt.Errorf("hook.unregisterClaudeCodeStatusline: read: %w", err)
		return res
	}

	settings, err := decodeSettingsObject(path, raw)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterClaudeCodeStatusline: %w", err)
		return res
	}

	existing, ok := settings["statusLine"]
	if !ok {
		res.Skipped = true
		return res
	}
	var cur claudeStatuslineEntry
	if err := json.Unmarshal(existing, &cur); err != nil || !isObserverStatuslineEntry(cur.Command) {
		// Foreign (or unparseable) "statusLine" — a user-authored
		// statusline (or another tool's). Never removed by uninstall,
		// with or without --force, mirroring the hook unregistrars'
		// HooksKept posture.
		res.HooksKept = append(res.HooksKept, "statusLine")
		res.Skipped = true
		return res
	}

	delete(settings, "statusLine")
	res.HooksRemoved = append(res.HooksRemoved, "statusLine")

	if r.opts.DryRun {
		return res
	}

	if len(settings) == 0 {
		if err := removeEmptyConfigFile(path, raw); err != nil {
			res.Error = fmt.Errorf("hook.unregisterClaudeCodeStatusline: remove empty %s: %w", path, err)
			return res
		}
	} else {
		if err := r.writeHookSettingsJSON("claude-code", settingsDir, pinned, raw, settings); err != nil {
			res.Error = err
			return res
		}
	}
	return res
}

// RegisterClaudeCodeStatusline is the exported entry point for the
// statusline registration path. Deliberately NOT reached through the
// tool-name-dispatched Register(tool string) switch above (adding a
// case there would touch an existing function this WP must leave
// byte-identical) — callers (cmd/observer/init.go's `observer init
// --statusline`) call this directly instead. Opt-in only: never
// called by `observer start`'s hook auto-register path, matching the
// MCP/proxy-route precedent (CLAUDE.md's `observer start` invariant).
func (r *Registry) RegisterClaudeCodeStatusline() RegistrationResult {
	return r.guardCredentialRegistration("claude-code", r.registerClaudeCodeStatusline())
}

// UnregisterClaudeCodeStatusline is the exported entry point for
// removing the statusline registration — the `observer init
// --statusline --uninstall` path. See RegisterClaudeCodeStatusline's
// doc comment for why this is a direct call rather than a Unregister
// switch case.
func (r *Registry) UnregisterClaudeCodeStatusline() UnregistrationResult {
	return r.guardCredentialUnregistration("claude-code", r.unregisterClaudeCodeStatusline())
}
