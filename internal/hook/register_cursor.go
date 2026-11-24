package hook

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// cursorEvents is the set of Cursor hook events we register for. The first
// 5 are the original Tier 1 set (shell, MCP, file edits, prompt submit,
// stop). Tier 2 (v1.4.45) extends coverage to file reads (closing audit
// C2), tool failures, session-lifecycle markers, sub-agent fan-out, and
// pre-compact dispatch. Tier 3 (v1.4.45) adds the universal preToolUse
// to fill the long-tail-tool gap (Glob/Grep/Search/Write/etc. — tools
// the per-tool before* hooks miss) plus three paired-after observers
// registered no-row pending update-in-place: postToolUse,
// afterShellExecution, afterMCPExecution. Tier 4 (v1.6.18) adds
// afterAgentThought + afterAgentResponse: on Cursor 3.4.20-3.9.16 (the
// versions live-confirmed at the time) agent-transcripts/*.jsonl writing
// had stopped, so the JSONL walker BuildStopTranscriptEvents relied on
// as a fallback for finalized assistant prose was believed dead-code;
// live-captured payloads on those versions confirmed the events fire
// once-per-finalized-block (not per-token-delta as the v1.4.45
// docstring claimed). CORRECTION (2026-08-07, see
// docs/audits/cursor-windows-capture-diagnosis-2026-08-07.md): on
// Cursor 3.14.27 agent-transcripts/*.jsonl writing is back — it is
// currently the ONLY thing capturing Windows-IDE Cursor activity, so
// the JSONL walker is live again, not dead-code, on that version.
// Whether 3.14.27 still fires afterAgentResponse with usage fields is
// unverified (see that audit's probe P2/P3). See
// internal/adapter/cursor/adapter.go for the full rationale. Tab
// events (beforeTabFileRead, afterTabFileEdit) remain out of scope.
var cursorEvents = []string{
	"beforeSubmitPrompt", "beforeShellExecution", "afterFileEdit", "beforeMCPExecution", "stop",
	"beforeReadFile", "postToolUseFailure", "sessionStart", "sessionEnd",
	"subagentStart", "subagentStop", "preCompact",
	"preToolUse", "postToolUse", "afterShellExecution", "afterMCPExecution",
	"afterAgentThought", "afterAgentResponse",
}

// CursorEvents exposes the Cursor hook events this registrar manages, for
// callers outside this package that need to check coverage (e.g.
// internal/diag's `cursor.hooks` doctor check) without duplicating or
// drifting from cursorEvents, the one owner of that list. Returns a copy
// so a caller mutating the slice can't affect registration.
func CursorEvents() []string {
	return append([]string(nil), cursorEvents...)
}

// cursorHookEntry is Observer's own flat Cursor hook entry, as Observer
// writes it. A registrar never decodes ~/.cursor/hooks.json into it: a
// developer's entries carry fields it does not model (timeout, matcher,
// type), so they stay raw (hookentries.go, NEW-06).
type cursorHookEntry struct {
	Command string `json:"command"`
}

// cursorHooksPath is the user hooks file the cursor registration writes
// (~/.cursor/hooks.json under the registry's home), the one owner of that
// path for the registrar and the own-registration reader
// (cursorObserverEvents).
func (r *Registry) cursorHooksPath() string {
	return filepath.Join(r.opts.HomeDir, ".cursor", "hooks.json")
}

func (r *Registry) registerCursor() RegistrationResult {
	res := RegistrationResult{Tool: "cursor", DryRun: r.opts.DryRun}
	path := r.cursorHooksPath()
	cursorDir := filepath.Dir(path)
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerCursor: %w", err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(path)

	raw, err := readSettingsFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Error = fmt.Errorf("hook.registerCursor: read: %w", err)
		return res
	}
	settings := map[string]json.RawMessage{}
	if len(raw) > 0 {
		settings, err = decodeSettingsObject(path, raw)
		if err != nil {
			res.Error = fmt.Errorf("hook.registerCursor: %w", err)
			return res
		}
	}
	// NEW-06: every entry stays raw, so a field Observer does not write (a
	// developer's timeout, matcher or type) survives the rewrite, and a
	// hooks member Observer cannot read is refused, never overwritten.
	hooks, err := decodeHookEvents(settings["hooks"], flatHookEntries)
	if err != nil {
		res.Error = refuseHookShape("hook.registerCursor", path, err)
		return res
	}
	// FU-192: an entry in Observer's shape running another binary is kept.
	if r.refusesForeignBinary(&res, "hook.registerCursor", path, identityContent, shapedHooksInText(settings["hooks"], "cursor")) {
		return res
	}
	shapeDrift := shapeDriftEvents(settings["hooks"], flatCommandEntries(isObserverCursorEntry))

	// IDE-5: Cursor merges its enterprise hooks.json with this file, so an
	// event the administrator file already runs Observer's hook for is not
	// registered here a second time, and Observer's own earlier per-node
	// entry for it is removed (a non-Observer entry stays).
	plan := r.managedHooksPlanFor("cursor", cursorEvents)
	res.Warnings = append(res.Warnings, plan.warnings...)
	for _, ev := range plan.drop {
		kept, removed, _, err := flatHookEntries.removeHandlers(hooks.entries(ev), isObserverCursorEntry)
		if err != nil {
			res.Error = fmt.Errorf("hook.registerCursor: %w", err)
			return res
		}
		if removed == 0 {
			continue
		}
		res.HooksDropped = append(res.HooksDropped, ev)
		hooks.set(ev, kept)
	}
	if plan.complete && len(res.HooksDropped) == 0 {
		return plan.finish(res)
	}
	events := plan.register

	for _, event := range events {
		// Forward-slash-normalize the binary + config path before
		// quoting — see registerClaudeCode for the full rationale
		// (the harness can strip the single quotes upstream, leaving
		// unquoted-Windows-path backslashes for Git Bash to escape-
		// strip). Forward slashes survive any shell wrapping.
		binPath := forwardSlashPath(r.opts.BinaryPath)
		cmd := shellQuoteIfNeeded(binPath) + " hook cursor " + event + r.configFlagSuffixForwardSlash()
		// Stale-observer-args case: an existing command recognised as
		// observer-written (by content-heuristic, see
		// isObserverCursorEntry) but with different args. Covers
		// same-binary arg drift (e.g. missing --config after we add a
		// new flag) AND cross-binary upgrade (e.g. an npm-bundled
		// observer in node_modules being replaced by a fresh local
		// build). Silently refreshed; non-observer entries are still
		// treated as conflicts. T-847: an Observer entry with a field
		// Observer never writes (a matcher, a timeout) is rewritten,
		// never "already set".
		added, err := r.putObserverEntry(&res, hooks, flatEntryRule{
			errPrefix: "hook.registerCursor", path: res.ConfigPath, event: event, cmd: cmd,
			ours: isObserverCursorEntry, drift: shapeDrift[event],
		})
		if err != nil {
			res.Error = err
			return res
		}
		if added {
			res.HooksAdded = append(res.HooksAdded, event)
		}
	}

	settings, err = cursorSettingsWith(settings, hooks)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerCursor: %w", err)
		return res
	}

	if r.opts.DryRun {
		return plan.finish(res)
	}
	if err := writeJSONIndented(cursorDir, pinned, settings); err != nil {
		res.Error = err
		return res
	}
	if err := r.recordChecksum(res.Tool, path); err != nil {
		res.Error = err
		return res
	}
	return plan.finish(res)
}

// flatEntryRule is one event of a flat (Cursor-shaped) hooks file to put
// Observer's entry into: the command to write, the recogniser of
// Observer's entries, whether its entry drifted from the canonical shape
// (T-847), and stale, which also drops entries Observer owns that ours
// does not recognise (a dangling debug shim, cursor-windows); nil drops
// none.
type flatEntryRule struct {
	errPrefix, path, event, cmd string
	ours                        func(string) bool
	stale                       func(string) bool
	drift                       bool
}

// putObserverEntry is the per-event write the flat Cursor registrars share
// (native and the wsl.exe bridge): already set when Observer's exact
// command is there in its canonical shape; otherwise Observer's stale
// entries are dropped (every other entry keeps its data and order, NEW-06),
// a developer's own entry blocks without --force, and Observer's entry is
// appended. added reports a new entry.
func (r *Registry) putObserverEntry(res *RegistrationResult, hooks *hookEvents, rule flatEntryRule) (added bool, err error) {
	entries := hooks.entries(rule.event)
	if rule.drift {
		shapeRewrite(res, rule.event, rule.cmd, rule.cmd)
		if entries, _, _, err = flatHookEntries.removeHandlers(entries, rule.ours); err != nil {
			return false, fmt.Errorf("%s: %w", rule.errPrefix, err)
		}
	}
	if flatHookEntries.hasCommand(entries, rule.cmd) {
		res.AlreadySet = append(res.AlreadySet, rule.event)
		return false, nil
	}
	if entries, _, _, err = flatHookEntries.removeHandlers(entries, func(c string) bool {
		return c != rule.cmd && (rule.ours(c) || (rule.stale != nil && rule.stale(c)))
	}); err != nil {
		return false, fmt.Errorf("%s: %w", rule.errPrefix, err)
	}
	if r.refuses(rule.path, identityContent) && flatHookEntries.hasForeign(entries, rule.ours) {
		return false, fmt.Errorf("%s: event %s already has a non-observer hook; pass --force to overwrite", rule.errPrefix, rule.event)
	}
	entry, err := observerFlatEntry(rule.cmd)
	if err != nil {
		return false, fmt.Errorf("%s: marshal entry: %w", rule.errPrefix, err)
	}
	hooks.set(rule.event, append(entries, entry))
	return true, nil
}

// cursorSettingsWith returns settings carrying hooks (re-encoded only when
// an event changed, so an unchanged member is left as read) and Cursor's
// required "version": 1 when the file names no version (a version the file
// already states is the developer's and stays).
func cursorSettingsWith(settings map[string]json.RawMessage, hooks *hookEvents) (map[string]json.RawMessage, error) {
	if _, ok := settings["version"]; !ok {
		settings["version"] = json.RawMessage("1")
	}
	if len(hooks.dirty) == 0 {
		return settings, nil
	}
	b, err := hooks.encode()
	if err != nil {
		return nil, fmt.Errorf("encode hooks: %w", err)
	}
	settings["hooks"] = b
	return settings, nil
}

// IsOrphanedObserverCursorHTTPHook reports whether cmd is a stale
// observer-authored Cursor hook entry from a LOST, never-committed
// 2026-09-08 build that POSTed hook payloads over loopback HTTP instead
// of invoking the CLI directly — e.g.
//
//	curl.exe -sS --max-time 3 -X POST -H "Content-Type: application/json" \
//	  -H "X-Observer-Token: <64 hex>" --data-binary '@-' \
//	  http://127.0.0.1:8081/api/cursor/hook/<event>
//
// This build serves no such route (it was never committed): the dashboard's SPA
// fallback answers every such POST with a 200 text/html, so a hooks.json
// carrying this shape silently drops every Cursor event with no visible
// error. Because it doesn't match the canonical ` hook cursor `
// signature isObserverWindowsCursorEntry/isObserverCursorEntry look for,
// it used to be classified foreign — auto-register refused to heal it
// without --force, and the daemon logged "already has a non-observer
// hook" on every `observer start`.
//
// Recognition requires ALL three to hold, so a user's own curl-based
// hook is never mistaken for this artifact and silently removed:
//
//   - the command invokes curl (`curl.exe` or `curl` as argv[0], via
//     the same quote-aware tokenizer splitCommandTokens uses elsewhere
//     in this file);
//   - one of its arguments is a plain-http URL whose host is LOOPBACK
//     (127.0.0.1, localhost, or [::1] — including any other IP that
//     resolves loopback) and whose path is EXACTLY
//     "/api/cursor/hook/<event>" for one of the Cursor events this
//     registrar manages (no further segments, query or fragment);
//   - the command carries an "X-Observer-Token:" header whose value is
//     a 64-hex-digit token (the lost build's grammar).
//
// A curl hook to a non-loopback host, a different path, or without the
// observer token header stays foreign — see
// TestIsOrphanedObserverCursorHTTPHook for the recognised/rejected
// table.
func IsOrphanedObserverCursorHTTPHook(cmd string) bool {
	toks := splitCommandTokens(cmd)
	if len(toks) == 0 {
		return false
	}
	base := strings.ToLower(strings.TrimSuffix(commandBaseName(toks[0]), ".exe"))
	if base != "curl" {
		return false
	}
	if !orphanHookTokenHeader.MatchString(cmd) {
		return false
	}
	for _, t := range toks[1:] {
		if !strings.Contains(t, "://") {
			continue
		}
		u, err := url.Parse(t)
		if err != nil || u.Scheme != "http" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			continue
		}
		event, ok := strings.CutPrefix(u.Path, "/api/cursor/hook/")
		if isLoopbackHookHost(u.Hostname()) && ok && slices.Contains(cursorEvents, event) {
			return true
		}
	}
	return false
}

// orphanHookTokenHeader is the lost build's exact header grammar: the
// X-Observer-Token header carrying a 64-hex-digit token.
var orphanHookTokenHeader = regexp.MustCompile(`X-Observer-Token: ?[0-9a-fA-F]{64}(?:["'\s]|$)`)

// isLoopbackHookHost reports whether host names the local machine —
// the literal forms "localhost"/"127.0.0.1"/"[::1]" (net/url strips
// brackets from Hostname()) or any other IP literal that resolves
// loopback. Used only by IsOrphanedObserverCursorHTTPHook to keep its
// recognition narrow to a hook that could only ever have been talking
// to this same host's daemon.
func isLoopbackHookHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// commandArgsInclude reports whether cmd contains token as a bare,
// whitespace-delimited argument (optionally single- or
// double-quoted). Splitting on whitespace is safe here: it is only
// ever called with cursorEvents members (identifiers with no
// internal whitespace), so a quoted value elsewhere in cmd (e.g. a
// --config path) can never be mistaken for a match.
func commandArgsInclude(cmd, token string) bool {
	for _, f := range strings.Fields(cmd) {
		if strings.Trim(f, `'"`) == token {
			return true
		}
	}
	return false
}

// isObserverCursorEntry recognises a hook command as one previously
// written by ANY observer cursor (Linux/default) registrar. The
// ` hook cursor ` token sequence is the stable signature, regardless
// of which observer binary path prefixes it. Same content-heuristic
// rationale as isObserverClaudeEntry — lets refresh-on-drift upgrade
// entries left behind by a differently-installed observer (npm
// bundle in node_modules, cross-binary upgrade, renamed $HOME)
// without --force. See isObserverClaudeEntry for the full trade-off
// discussion; the cursor entry shape uses the same observer-internal
// syntax so the collision risk is equally negligible.
//
// Excludes wsl.exe-wrapped commands so this and
// isObserverWindowsCursorEntry match disjoint shapes — see
// isObserverClaudeEntry's docstring for the same rationale.
//
// Also recognises the orphaned observer HTTP-hook shape
// (IsOrphanedObserverCursorHTTPHook) a native install could carry for
// the same reason the Windows side can — see that predicate's
// docstring. It never starts with `wsl.exe`, so it doesn't disturb the
// disjointness this function's wsl.exe exclusion exists for.
func isObserverCursorEntry(cmd string) bool {
	if IsOrphanedObserverCursorHTTPHook(cmd) {
		return true
	}
	if !strings.Contains(cmd, " hook cursor ") {
		return false
	}
	if strings.HasPrefix(cmd, "wsl.exe ") || strings.HasPrefix(cmd, "MSYS_NO_PATHCONV=1 wsl.exe ") {
		return false
	}
	return true
}

func (r *Registry) unregisterCursor() UnregistrationResult {
	res := UnregistrationResult{Tool: "cursor", DryRun: r.opts.DryRun}
	path := r.cursorHooksPath()
	cursorDir := filepath.Dir(path)
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterCursor: %w", err)
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
		res.Error = fmt.Errorf("hook.unregisterCursor: read: %w", err)
		return res
	}

	settings, err := decodeSettingsObject(path, raw)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterCursor: %w", err)
		return res
	}
	hooks, err := decodeHookEvents(settings["hooks"], flatHookEntries)
	if err != nil {
		res.Error = refuseHookShape("hook.unregisterCursor", path, err)
		return res
	}
	// Content-heuristic so cross-binary installs (npm bundle, renamed
	// $HOME, prior worktree binary) get cleaned up when uninstalling from
	// a different observer build. Mirrors the register-side
	// isObserverCursorEntry usage; without it a byte-exact prefix match
	// would leave orphaned entries behind on `observer uninstall cursor`.
	if err := r.removeObserverHandlers(&res, hooks, flatHookEntries, "cursor", isObserverCursorEntry); err != nil {
		res.Error = fmt.Errorf("hook.unregisterCursor: %w", err)
		return res
	}
	if len(res.HooksRemoved) == 0 {
		res.Skipped = true
		return res
	}

	match, err := r.checksumMatches(path, raw)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterCursor: checksum: %w", err)
		return res
	}
	res.ChecksumMatch = match
	if !match && !r.opts.Force {
		res.Error = fmt.Errorf("hook.unregisterCursor: %s has been modified since install (checksum mismatch); pass --force to remove anyway", path)
		return res
	}

	if err := setHooksMember(settings, "hooks", hooks, true); err != nil {
		res.Error = fmt.Errorf("hook.unregisterCursor: %w", err)
		return res
	}

	if r.opts.DryRun {
		return res
	}

	// If the only surviving keys are the "version" we manufactured at
	// install time, remove the file entirely so uninstall leaves no trace.
	if len(settings) == 1 {
		if _, onlyVersion := settings["version"]; onlyVersion {
			delete(settings, "version")
		}
	}
	if len(settings) == 0 {
		if err := removeEmptyConfigFile(path, raw); err != nil {
			res.Error = fmt.Errorf("hook.unregisterCursor: remove %s: %w", path, err)
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
