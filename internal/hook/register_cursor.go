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
	"sort"
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
	hooks := map[string][]cursorHookEntry{}
	if existing, ok := settings["hooks"]; ok {
		_ = json.Unmarshal(existing, &hooks)
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
		kept := dropCursorEntries(hooks[ev], isObserverCursorEntry)
		if len(kept) == len(hooks[ev]) {
			continue
		}
		res.HooksDropped = append(res.HooksDropped, ev)
		if len(kept) == 0 {
			delete(hooks, ev)
		} else {
			hooks[ev] = kept
		}
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
		if shapeDrift[event] {
			// T-847: an Observer entry with a field Observer never writes
			// (a matcher, a timeout) is rewritten, never "already set";
			// the typed decode above would otherwise drop the field without
			// anyone hearing about it.
			shapeRewrite(&res, event, cmd, cmd)
			hooks[event] = dropCursorEntries(hooks[event], isObserverCursorEntry)
		}
		if slicesContainsCommand(hooks[event], cmd) {
			res.AlreadySet = append(res.AlreadySet, event)
			continue
		}
		// Stale-observer-args case: existing command is recognised as
		// observer-written (by content-heuristic — see
		// isObserverCursorEntry) but has different args. Covers
		// same-binary arg drift (e.g. missing --config after we add a
		// new flag) AND cross-binary upgrade (e.g. an npm-bundled
		// observer in node_modules being replaced by a fresh local
		// build). Silently refresh; non-observer entries are still
		// treated as conflicts via hasCursorConflict below.
		if hasStaleObserverEntry(hooks[event], cmd) {
			hooks[event] = filterStaleObserverEntries(hooks[event], cmd)
		}
		if r.refuses(res.ConfigPath, identityContent) && hasCursorConflict(hooks[event]) {
			res.Error = fmt.Errorf("hook.registerCursor: event %s already has a non-observer hook; pass --force to overwrite", event)
			return res
		}
		hooks[event] = append(hooks[event], cursorHookEntry{Command: cmd})
		res.HooksAdded = append(res.HooksAdded, event)
	}

	settings["version"] = json.RawMessage("1")
	hookJSON, err := json.Marshal(hooks)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerCursor: marshal hooks: %w", err)
		return res
	}
	settings["hooks"] = hookJSON

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

// hasCursorConflict reports whether any entry carries a command
// that isn't recognised as observer-shaped. Used by the force-less
// path to refuse silent overwrite of user-authored hooks.
// Content-heuristic via isObserverCursorEntry so entries from a
// different observer install path (npm bundle, cross-binary upgrade)
// fall through to the refresh path rather than being flagged as
// foreign.
func hasCursorConflict(entries []cursorHookEntry) bool {
	for _, e := range entries {
		if !isObserverCursorEntry(e.Command) {
			return true
		}
	}
	return false
}

// slicesContainsCommand reports whether entries holds a hook with
// Command == want.
// dropCursorEntries removes every entry whose command ours recognises.
func dropCursorEntries(entries []cursorHookEntry, ours func(string) bool) []cursorHookEntry {
	out := entries[:0:0]
	for _, e := range entries {
		if !ours(e.Command) {
			out = append(out, e)
		}
	}
	return out
}

func slicesContainsCommand(entries []cursorHookEntry, want string) bool {
	for _, e := range entries {
		if e.Command == want {
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

// hasStaleObserverEntry reports whether entries holds an observer-
// recognised hook command that doesn't match want (i.e. an old
// registration — possibly from a different observer binary — that
// needs refreshing). Different from a non-observer conflict — those
// go through hasCursorConflict.
func hasStaleObserverEntry(entries []cursorHookEntry, want string) bool {
	for _, e := range entries {
		if isObserverCursorEntry(e.Command) && e.Command != want {
			return true
		}
	}
	return false
}

// filterStaleObserverEntries drops entries recognised as observer-
// written that don't match the canonical want. Used by the refresh
// path to clear a previous registration (including ones from a
// different observer binary path) before appending the fresh one.
// Non-observer entries (other tools the user wired in by hand) pass
// through untouched.
func filterStaleObserverEntries(entries []cursorHookEntry, want string) []cursorHookEntry {
	out := make([]cursorHookEntry, 0, len(entries))
	for _, e := range entries {
		if isObserverCursorEntry(e.Command) && e.Command != want {
			continue
		}
		out = append(out, e)
	}
	return out
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
	hooks := map[string][]cursorHookEntry{}
	if existing, ok := settings["hooks"]; ok {
		_ = json.Unmarshal(existing, &hooks)
	}

	for event, entries := range hooks {
		var survivors []cursorHookEntry
		removed := 0
		foreign := false
		mine := r.removableEntry("cursor", isObserverCursorEntry, &foreign)
		for _, e := range entries {
			// Content-heuristic so cross-binary installs (npm bundle,
			// renamed $HOME, prior worktree binary) get cleaned up
			// when uninstalling from a different observer build.
			// Mirrors the register-side isObserverCursorEntry usage —
			// without this, byte-exact prefix-match would leave
			// orphaned entries behind on `observer uninstall cursor`.
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
		res.Error = fmt.Errorf("hook.unregisterCursor: checksum: %w", err)
		return res
	}
	res.ChecksumMatch = match
	if !match && !r.opts.Force {
		res.Error = fmt.Errorf("hook.unregisterCursor: %s has been modified since install (checksum mismatch); pass --force to remove anyway", path)
		return res
	}

	if len(hooks) == 0 {
		delete(settings, "hooks")
	} else {
		hookJSON, err := json.Marshal(hooks)
		if err != nil {
			res.Error = fmt.Errorf("hook.unregisterCursor: marshal hooks: %w", err)
			return res
		}
		settings["hooks"] = hookJSON
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
