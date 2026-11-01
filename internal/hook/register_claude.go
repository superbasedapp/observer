package hook

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/claudeplugin"
)

// claudeCodeEvents is the set of events we register for. The matcher "*"
// catches every tool; downstream handlers filter by tool_name.
//
// Tier 1 additions (2026-05): SessionEnd, UserPromptSubmit,
// PostToolUseFailure, StopFailure, SubagentStart, SubagentStop,
// Notification, CwdChanged. Each maps to a row in the actions table
// via cmd/observer/hook.go::handleClaudeCodeHook so dashboards can
// surface failures, sub-agent fan-out, lifecycle exit reasons, host
// notifications and cwd changes that the JSONL transcript either
// doesn't carry or carries less directly.
//
// Tier 2/3 additions (2026-05-11): Setup, UserPromptExpansion,
// PostToolBatch, PermissionRequest, PermissionDenied, InstructionsLoaded,
// ConfigChange. Shapes verified against
// docs.claude.com/docs/en/hooks. FileChanged deferred — its matcher
// takes literal filenames (split on `|`), not the wildcard `*` shape
// all other events use, so it needs a separate per-project config
// surface before registration.
var claudeCodeEvents = []string{
	"SessionStart",
	"SessionEnd",
	"Setup",
	"UserPromptSubmit",
	"UserPromptExpansion",
	"PreToolUse",
	"PostToolUse",
	"PostToolUseFailure",
	"PostToolBatch",
	"PermissionRequest",
	"PermissionDenied",
	"Stop",
	"StopFailure",
	"PreCompact",
	"PostCompact",
	"SubagentStart",
	"SubagentStop",
	"Notification",
	"CwdChanged",
	"InstructionsLoaded",
	"ConfigChange",
	// WorktreeRemove is non-blocking (logging only) so it's safe to
	// register by default. WorktreeCreate (its blocking pair) is NOT
	// in this list — see docs/claude-worktree-hook.md for the opt-in
	// procedure. Wiring it as a default hook without a verified
	// path-echo contract risks breaking every Agent spawn with
	// isolation: "worktree".
	"WorktreeRemove",
	// TaskCreated / TaskCompleted: capture only (the receiver always
	// approves, so the vendor's exit-2 rollback is never taken).
	// Live-grounded on demo node 1 (Claude Code 2.1.288, 2026-10-04):
	// both events fired for TaskCreate / TaskUpdate(status completed) and
	// landed task_event rows.
	"TaskCreated",
	"TaskCompleted",
}

type claudeHookGroup struct {
	Matcher string              `json:"matcher,omitempty"`
	Hooks   []claudeHookCommand `json:"hooks"`
}

type claudeHookCommand struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

// claudeHookGroupRaw mirrors claudeHookGroup's JSON shape
// (`{"matcher":...,"hooks":[...]}`) but keeps each entry in Hooks as
// raw JSON rather than decoding it into claudeHookCommand (B5). A
// group observer appends to may already hold a SIBLING entry this
// repo doesn't own — another tool's own hook, or one the user
// hand-authored — that carries fields claudeHookCommand doesn't model
// (Claude Code's documented per-entry `timeout`, for one). Decoding
// that entry into claudeHookCommand and re-encoding it would silently
// drop those fields the moment observer registers/refreshes/removes
// its own neighboring entry in the same list. Only observer's OWN
// entry is ever constructed directly (via claudeHookCommand, then
// marshaled) since observer fully controls and knows that shape;
// every other entry round-trips as opaque json.RawMessage.
type claudeHookGroupRaw struct {
	Matcher string            `json:"matcher,omitempty"`
	Hooks   []json.RawMessage `json:"hooks"`
}

// claudeHookCommandProbe decodes just the two fields
// isObserverClaudeEntry/isObserverWindowsClaudeEntry need to recognise
// an entry as observer's own, from an otherwise-opaque raw hook entry.
// Used instead of the full claudeHookCommand so a sibling entry's
// unknown fields are never routed through — and so truncated by — a
// typed decode/re-encode round-trip.
type claudeHookCommandProbe struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

// findClaudeGroupWithObserverRaw is findClaudeGroupWithObserver's
// raw-entry counterpart (B5): it probes each entry's `type`/`command`
// fields without decoding (and thereby truncating) any other field
// the entry carries.
func findClaudeGroupWithObserverRaw(groups []claudeHookGroupRaw) int {
	for i, g := range groups {
		for _, raw := range g.Hooks {
			var probe claudeHookCommandProbe
			if err := json.Unmarshal(raw, &probe); err != nil {
				continue
			}
			if probe.Type == "command" && isObserverClaudeEntry(probe.Command) {
				return i
			}
		}
	}
	return -1
}

// observerCommandInGroupRaw returns the command of the first entry in group
// that ours recognises as observer-owned, or "" when there is none.
func observerCommandInGroupRaw(group claudeHookGroupRaw, ours func(string) bool) string {
	for _, raw := range group.Hooks {
		var probe claudeHookCommandProbe
		if err := json.Unmarshal(raw, &probe); err != nil {
			continue
		}
		if probe.Type == "command" && ours(probe.Command) {
			return probe.Command
		}
	}
	return ""
}

// hasConflictingClaudeHookRaw is hasConflictingClaudeHook's raw-entry
// counterpart (B5) — see findClaudeGroupWithObserverRaw.
func hasConflictingClaudeHookRaw(groups []claudeHookGroupRaw) bool {
	for _, g := range groups {
		if g.Matcher != "" && g.Matcher != "*" {
			continue
		}
		for _, raw := range g.Hooks {
			var probe claudeHookCommandProbe
			if err := json.Unmarshal(raw, &probe); err != nil {
				continue
			}
			if probe.Type != "command" {
				continue
			}
			if !isObserverClaudeEntry(probe.Command) {
				return true
			}
		}
	}
	return false
}

// observerCmdMatchesRaw is observerCmdMatches's raw-entry counterpart
// (B5) — see findClaudeGroupWithObserverRaw.
func observerCmdMatchesRaw(group claudeHookGroupRaw, want string) bool {
	if len(group.Hooks) != 1 {
		return false
	}
	var probe claudeHookCommandProbe
	if err := json.Unmarshal(group.Hooks[0], &probe); err != nil {
		return false
	}
	return probe.Type == "command" && probe.Command == want
}

// filterClaudeGroupsRaw is filterClaudeGroups's raw-entry counterpart
// (B5): it drops observer-owned entries by probing just their
// `type`/`command` fields, and keeps every surviving entry as the
// exact json.RawMessage bytes it was read as — so a sibling entry's
// undocumented-to-us fields (e.g. `timeout`) survive byte-identical
// even when observer's own entry in the SAME group is removed
// alongside it.
//
// mine is the uninstall's recogniser (isObserverClaudeEntry under the FU-203
// judgement, removableEntry).
func filterClaudeGroupsRaw(groups []claudeHookGroupRaw, mine func(string) bool) (out []claudeHookGroupRaw, removed, kept int) {
	for _, g := range groups {
		var survivors []json.RawMessage
		for _, raw := range g.Hooks {
			var probe claudeHookCommandProbe
			if err := json.Unmarshal(raw, &probe); err == nil && probe.Type == "command" && mine(probe.Command) {
				removed++
				continue
			}
			survivors = append(survivors, raw)
		}
		if len(survivors) == 0 {
			continue
		}
		kept += len(survivors)
		out = append(out, claudeHookGroupRaw{Matcher: g.Matcher, Hooks: survivors})
	}
	return out, removed, kept
}

// readClaudeHookSettings reads path for registerClaudeCode: the raw bytes
// (nil when the file does not exist), the top-level object with unknown
// fields preserved via map[string]json.RawMessage, and the per-event hooks
// map (never nil). The per-event value is kept as json.RawMessage (B5) so
// an event the register loop never touches, and within an event it DOES
// touch a sibling entry it doesn't own, round-trips byte-for-byte instead
// of being decoded into (and truncated by) a typed struct.
func readClaudeHookSettings(path string) ([]byte, map[string]json.RawMessage, map[string]json.RawMessage, error) {
	raw, err := readSettingsFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil, fmt.Errorf("hook.registerClaudeCode: read: %w", err)
	}
	settings := map[string]json.RawMessage{}
	if len(raw) > 0 {
		settings, err = decodeSettingsObject(path, raw)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("hook.registerClaudeCode: %w", err)
		}
	}
	var hooksRaw map[string]json.RawMessage
	if existing, ok := settings["hooks"]; ok {
		if err := json.Unmarshal(existing, &hooksRaw); err != nil {
			return nil, nil, nil, fmt.Errorf("hook.registerClaudeCode: parse hooks: %w", err)
		}
	}
	if hooksRaw == nil {
		hooksRaw = map[string]json.RawMessage{}
	}
	return raw, settings, hooksRaw, nil
}

func (r *Registry) registerClaudeCode() RegistrationResult {
	settingsDir, err := r.claudeConfigDir()
	if err != nil {
		return RegistrationResult{Tool: "claude-code", DryRun: r.opts.DryRun, Error: err}
	}
	return r.registerClaudeCodeAt("claude-code", settingsDir, "hook.registerClaudeCode")
}

// registerClaudeCodeAt is the settings.json hook writer behind
// registerClaudeCode, for the Claude Code config home settingsDir. tool is
// the target label (the result's Tool and the checksum key; "claude-code",
// or "claude-code-xcode" for the home Xcode gives its bundled Claude,
// register_xcode.go); every entry is the same native `observer hook
// claude-code <event>` command, so isObserverClaudeEntry owns it in either
// home. errPrefix names the calling registrar in wrapped errors.
func (r *Registry) registerClaudeCodeAt(tool, settingsDir, errPrefix string) RegistrationResult {
	res := RegistrationResult{Tool: tool, DryRun: r.opts.DryRun}
	path := filepath.Join(settingsDir, "settings.json")
	res.ConfigPath = path

	// Double-wiring guard: the Claude Code plugin declares exactly the
	// events below, and Claude Code merges hook config from every source,
	// so registering on top of an installed plugin fires each event
	// twice. Skip instead. --force still writes, for the operator who
	// wants both (e.g. mid-migration off the plugin).
	//
	// A skip needs AFFIRMATIVE evidence. When the probe could not read
	// settings.json it reports Uncertain and we fall through to register:
	// losing capture because a config file was corrupt would be a far
	// worse failure than a doubled event. The read below hits the same
	// file and surfaces the underlying error through res.Error.
	pd := claudeplugin.DetectInClaudeDir(settingsDir)
	if pd.Active && !r.opts.Force {
		res.Skipped = true
		res.SkipKind = SkipCovered
		res.SkipReason = pd.Reason()
		return res
	}
	res.ProbeWarning = pd.Warning()

	// Serialize observer's own writers of this file, THEN read — the
	// snapshot we mutate has to be taken after the lock, or a
	// concurrent observer's committed write is lost.
	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf(errPrefix+": %w", err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(path)

	raw, settings, hooksRaw, err := readClaudeHookSettings(path)
	if err != nil {
		res.Error = err
		return res
	}

	// T-847: events whose Observer entry is ours but not in the shape this
	// writer emits (hook_shape.go).
	// FU-192: an entry in Observer's shape running another binary is kept.
	if r.refusesForeignBinary(&res, errPrefix, path, identityContent, shapedHooksInText(settings["hooks"], "claude-code")) {
		return res
	}
	shapeDrift := shapeDriftEvents(settings["hooks"], claudeShapedGroups(isObserverClaudeEntry))

	for _, event := range claudeCodeEvents {
		// Normalize Windows-shaped paths to forward slashes so the
		// hook command survives any shell wrapping the harness applies.
		// Background: the v1.6.25 fix at this site single-quoted the
		// backslash path (`'D:\programsx\...\observer.exe'`) so Git
		// Bash on Windows wouldn't strip backslashes as escape
		// sequences. That worked when Claude Code spawned the hook
		// directly. But the harness's per-tool-call Bash wrapper can
		// strip the single quotes on intermittent invocation patterns
		// (operator-reported 2026-06-06; reliably reproduces on
		// `wsl.exe`-shaped Bash-tool calls), leaving the unquoted
		// backslash path for bash to escape-strip — symptom is the
		// canonical `D:programsxsuperbased-observerbinobserver-hermes.exe:
		// command not found` 127 exit. Forward-slash normalization is
		// a stronger guarantee than single-quoting: `D:/programsx/...`
		// has no character any shell layer interprets specially, so
		// the path arrives at the exec syscall unmodified regardless
		// of how many wrappers stripped or re-quoted it. Same effect
		// for the --config path (see configFlagSuffixForwardSlash).
		// shellQuoteIfNeeded is still called for the safety of paths
		// with spaces (`C:\Program Files\...`); forward-slash variants
		// of those still need quoting, just with whatever quote style
		// survives without escape interpretation.
		binPath := forwardSlashPath(r.opts.BinaryPath)
		cmd := shellQuoteIfNeeded(binPath) + " hook claude-code " + hookEventArg(event) + r.configFlagSuffixForwardSlash()
		var groups []claudeHookGroupRaw
		if raw, ok := hooksRaw[event]; ok && len(raw) > 0 {
			if err := json.Unmarshal(raw, &groups); err != nil {
				res.Error = fmt.Errorf(errPrefix+": parse hooks[%s]: %w", event, err)
				return res
			}
		}
		groups, idx := dropShapeDriftedClaudeEntry(&res, event, cmd, groups, shapeDrift[event])
		if idx >= 0 {
			if observerCmdMatchesRaw(groups[idx], cmd) {
				res.AlreadySet = append(res.AlreadySet, event)
				continue
			}
			// Args drifted but the entry is already ours (recognised
			// by content-heuristic, see isObserverClaudeEntry). An
			// EQUIVALENT entry stays as it is under KeepEquivalentHooks
			// (T-725: `observer start` from another binary path must
			// not rewrite the user's file); otherwise refresh, which
			// covers a broken entry (binary gone), a different config,
			// and the consented `observer init` refresh to this binary.
			// Drop the stale group and fall through to append the
			// up-to-date one.
			if r.keepOrRewrite(&res, event, observerCommandInGroupRaw(groups[idx], isObserverClaudeEntry), cmd) {
				res.AlreadySet = append(res.AlreadySet, event)
				continue
			}
			groups = append(groups[:idx], groups[idx+1:]...)
		}
		// Conflict check: a non-observer hook command on "*" matcher
		// counts as an unmanaged entry.
		if r.refuses(res.ConfigPath, identityContent) && hasConflictingClaudeHookRaw(groups) {
			res.Error = hookConflictError(errPrefix, event)
			return res
		}
		entryJSON, err := json.Marshal(claudeHookCommand{Type: "command", Command: cmd})
		if err != nil {
			res.Error = fmt.Errorf(errPrefix+": marshal entry: %w", err)
			return res
		}
		groups = append(groups, claudeHookGroupRaw{
			Matcher: "*",
			Hooks:   []json.RawMessage{entryJSON},
		})
		groupsJSON, err := json.Marshal(groups)
		if err != nil {
			res.Error = fmt.Errorf(errPrefix+": marshal hooks[%s]: %w", event, err)
			return res
		}
		hooksRaw[event] = groupsJSON
		res.HooksAdded = append(res.HooksAdded, event)
	}

	// Nothing added (every event exact or kept as equivalent): never
	// re-encode the file, so it stays byte-identical (T-407, T-725).
	if len(res.HooksAdded) == 0 && len(raw) > 0 {
		if r.opts.DryRun {
			return res
		}
		if err := r.recordHookChecksum(tool, path); err != nil {
			res.Error = err
		}
		return res
	}

	patched, err := json.Marshal(hooksRaw)
	if err != nil {
		res.Error = fmt.Errorf(errPrefix+": marshal hooks: %w", err)
		return res
	}
	settings["hooks"] = patched

	if r.opts.DryRun {
		return res
	}
	if err := r.writeHookSettingsJSON(tool, settingsDir, pinned, raw, settings); err != nil {
		res.Error = err
		return res
	}
	if err := r.recordHookChecksum(tool, path); err != nil {
		res.Error = err
		return res
	}
	return res
}

// shapeRewriteRule / shapeRewriteReason name the T-847 rewrite of an
// Observer entry whose command may be current but whose surrounding shape
// (matcher, extra fields) is not the canonical registration.
const (
	shapeRewriteRule   = "hook-shape"
	shapeRewriteReason = "the entry's matcher or fields differ from the canonical registration"
)

// claudeMatcherCanonical reports whether a group matcher is the match-all
// Observer writes ("*"; an absent matcher also matches every tool).
func claudeMatcherCanonical(m string) bool { return m == "" || m == "*" }

// dropObserverEntriesRaw removes Observer's entries from groups[idx], keeping
// any sibling entry (and its matcher) in place; a group left empty is dropped.
func dropObserverEntriesRaw(groups []claudeHookGroupRaw, idx int, ours func(string) bool) []claudeHookGroupRaw {
	var survivors []json.RawMessage
	for _, raw := range groups[idx].Hooks {
		var probe claudeHookCommandProbe
		if json.Unmarshal(raw, &probe) == nil && probe.Type == "command" && ours(probe.Command) {
			continue
		}
		survivors = append(survivors, raw)
	}
	if len(survivors) == 0 {
		return append(groups[:idx:idx], groups[idx+1:]...)
	}
	groups[idx].Hooks = survivors
	return groups
}

// dropShapeDriftedClaudeEntry finds Observer's group for event and, when the
// entry is ours but no longer the shape Observer writes (drift: a narrowed
// matcher, an added field such as a short timeout), records the T-847 shape
// rewrite and drops only Observer's entry (a sibling keeps its group), so the
// caller appends the canonical one. The command alone never made such an
// entry "already set": that let `observer start` re-record a weakened file as
// the new baseline. It returns the groups and Observer's group index (-1 when
// there is none, or it was dropped).
func dropShapeDriftedClaudeEntry(res *RegistrationResult, event, cmd string, groups []claudeHookGroupRaw, drift bool) ([]claudeHookGroupRaw, int) {
	idx := findClaudeGroupWithObserverRaw(groups)
	if idx < 0 || !drift {
		return groups, idx
	}
	shapeRewrite(res, event, observerCommandInGroupRaw(groups[idx], isObserverClaudeEntry), cmd)
	return dropObserverEntriesRaw(groups, idx, isObserverClaudeEntry), -1
}

// dropShapeDriftedTyped is dropShapeDriftedClaudeEntry for typed groups:
// find locates Observer's group, ours recognises its entry.
func dropShapeDriftedTyped(res *RegistrationResult, event, cmd string, groups []claudeHookGroup, drift bool,
	find func([]claudeHookGroup) int, ours func(string) bool,
) ([]claudeHookGroup, int) {
	idx := find(groups)
	if idx < 0 || !drift {
		return groups, idx
	}
	shapeRewrite(res, event, observerCommandInGroup(groups[idx], ours), cmd)
	return dropObserverEntriesTyped(groups, idx, ours), -1
}

// dropObserverEntriesTyped is dropObserverEntriesRaw for typed groups.
func dropObserverEntriesTyped(groups []claudeHookGroup, idx int, ours func(string) bool) []claudeHookGroup {
	var survivors []claudeHookCommand
	for _, h := range groups[idx].Hooks {
		if h.Type == "command" && ours(h.Command) {
			continue
		}
		survivors = append(survivors, h)
	}
	if len(survivors) == 0 {
		return append(groups[:idx:idx], groups[idx+1:]...)
	}
	groups[idx].Hooks = survivors
	return groups
}

// isObserverClaudeEntry recognises a hook command as one previously
// written by ANY observer claude-code (Linux/default) registrar.
// The ` hook claude-code ` token sequence is the stable signature,
// regardless of which observer binary path prefixes it.
// Content-heuristic rather than binary-path-prefix so a hook left
// behind by a differently-installed observer (e.g. an npm-bundled
// binary in node_modules, an upgrade that moved the install root,
// a Linux build with a renamed `$HOME`) is still recognised as ours
// and silently refreshed on the next `observer start` auto-register
// pass. Without this, the conflict guard would mis-classify those
// stale-but-ours entries as foreign third-party hooks and refuse to
// touch them without `--force`, leaving Claude Code firing the OLD
// observer binary forever — exactly the bug class that caused the
// v1.6.22 claude-code effort sidecar to silently stay empty for
// users who had a node_modules-bundled observer registered before
// upgrading to a local build.
//
// The Windows registrar's isObserverWindowsClaudeEntry is the same
// idea with an additional wsl.exe-wrapper guard; this is its
// Linux/default counterpart. To keep the two heuristics matching
// disjoint shapes (so the Linux/default registrar doesn't rewrite
// wsl-bridge entries into native-shape on hosts that have both
// configurations registered against the same settings.json), this
// helper EXCLUDES wsl.exe-wrapped commands. Any cmd that
// isObserverWindowsClaudeEntry would accept is rejected here.
//
// Trade-off: a third-party command containing the literal
// ` hook claude-code ` substring would be misclassified as observer
// and silently rewritten. The risk is acceptable — the syntax is
// distinctive enough that an accidental collision is essentially
// impossible, and the same trade-off the Windows registrar already
// accepts in production since v1.6.22.
func isObserverClaudeEntry(cmd string) bool {
	if !strings.Contains(cmd, " hook claude-code ") {
		return false
	}
	if strings.HasPrefix(cmd, "wsl.exe ") || strings.HasPrefix(cmd, "MSYS_NO_PATHCONV=1 wsl.exe ") {
		return false
	}
	return true
}

// IsObserverClaudeCodeHookCommand reports whether cmd is an observer
// `hook claude-code <event>` invocation, in either the native shape or
// the wsl.exe cross-OS bridge shape this package writes.
//
// This is the STRICT counterpart of isObserverClaudeEntry. The two exist
// for opposite reasons and must not be merged:
//
//   - isObserverClaudeEntry is deliberately loose (a bare
//     ` hook claude-code ` substring test) because the REGISTRAR has to
//     recognise its own stale entries in order to refresh them; a
//     false negative there strands a user on an old binary forever.
//   - this one is for REPORTING (the `claude-code.plugin` doctor probe),
//     where a false POSITIVE is the harm: a third-party command such as
//     `/opt/acme hook claude-code audit` would otherwise raise a
//     double-wiring warning naming wiring observer never wrote.
//
// So this tokenizes and checks an allow-list: after stripping any
// leading environment assignments and the `wsl.exe -d <distro> --`
// bridge prefix, argv[0] must NAME an observer binary
// (isObserverBinaryToken — basename `observer`/`superbased`, optional
// `.exe`, optional `-suffix`) and be followed by exactly the tokens
// `hook` `claude-code`.
func IsObserverClaudeCodeHookCommand(cmd string) bool {
	return isObserverAnyHookEntry(cmd, "claude-code")
}

// ClaudeCodeEventArg returns the `observer hook claude-code <arg>` spelling
// Observer registers for the Claude Code native event (lower-kebab, e.g.
// PreToolUse -> pre-tool); an event without a mapping is returned as is.
// cmd/observer uses it to resolve an invocation's argv back to its
// registry binding.
func ClaudeCodeEventArg(event string) string { return hookEventArg(event) }

func hookEventArg(event string) string {
	// Claude Code event names are CamelCase; we use lower-kebab on the CLI.
	switch event {
	case "SessionStart":
		return "session-start"
	case "SessionEnd":
		return "session-end"
	case "UserPromptSubmit":
		return "user-prompt-submit"
	case "PreToolUse":
		return "pre-tool"
	case "PostToolUse":
		return "post-tool"
	case "PostToolUseFailure":
		return "post-tool-failure"
	case "Stop":
		return "stop"
	case "StopFailure":
		return "stop-failure"
	case "PreCompact":
		return "pre-compact"
	case "PostCompact":
		return "post-compact"
	case "SubagentStart":
		return "subagent-start"
	case "SubagentStop":
		return "subagent-stop"
	case "Notification":
		return "notification"
	case "CwdChanged":
		return "cwd-changed"
	case "Setup":
		return "setup"
	case "UserPromptExpansion":
		return "user-prompt-expansion"
	case "PostToolBatch":
		return "post-tool-batch"
	case "PermissionRequest":
		return "permission-request"
	case "PermissionDenied":
		return "permission-denied"
	case "InstructionsLoaded":
		return "instructions-loaded"
	case "ConfigChange":
		return "config-change"
	case "WorktreeCreate":
		return "worktree-create"
	case "WorktreeRemove":
		return "worktree-remove"
	case "TaskCreated":
		return "task-created"
	case "TaskCompleted":
		return "task-completed"
	}
	return event
}

// observerCmdMatches reports whether group has exactly one hook command
// equal to want. Anything else (different command, multiple hooks,
// non-command type) returns false.
func observerCmdMatches(group claudeHookGroup, want string) bool {
	if len(group.Hooks) != 1 {
		return false
	}
	h := group.Hooks[0]
	return h.Type == "command" && h.Command == want
}

func (r *Registry) unregisterClaudeCode() UnregistrationResult {
	settingsDir, err := r.claudeConfigDir()
	if err != nil {
		return UnregistrationResult{Tool: "claude-code", DryRun: r.opts.DryRun, Error: err}
	}
	return r.unregisterClaudeCodeAt("claude-code", settingsDir, "hook.unregisterClaudeCode")
}

// unregisterClaudeCodeAt is registerClaudeCodeAt's cleaner: it removes the
// entries isObserverClaudeEntry owns from settingsDir's settings.json.
func (r *Registry) unregisterClaudeCodeAt(tool, settingsDir, errPrefix string) UnregistrationResult {
	res := UnregistrationResult{Tool: tool, DryRun: r.opts.DryRun}
	path := filepath.Join(settingsDir, "settings.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf(errPrefix+": %w", err)
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
		res.Error = fmt.Errorf(errPrefix+": read: %w", err)
		return res
	}

	settings, err := decodeSettingsObject(path, raw)
	if err != nil {
		res.Error = fmt.Errorf(errPrefix+": %w", err)
		return res
	}
	// Kept as json.RawMessage per event (B5) — see registerClaudeCode's
	// hooksRaw for the rationale; filterClaudeGroupsRaw preserves every
	// surviving sibling entry's unknown fields byte-for-byte.
	hooksRaw := map[string]json.RawMessage{}
	if existing, ok := settings["hooks"]; ok {
		if err := json.Unmarshal(existing, &hooksRaw); err != nil {
			res.Error = fmt.Errorf(errPrefix+": parse hooks: %w", err)
			return res
		}
	}

	for event, raw := range hooksRaw {
		var groups []claudeHookGroupRaw
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &groups); err != nil {
				res.Error = fmt.Errorf(errPrefix+": parse hooks[%s]: %w", event, err)
				return res
			}
		}
		foreign := false
		newGroups, removed, kept := filterClaudeGroupsRaw(groups, r.removableEntry("claude-code", isObserverClaudeEntry, &foreign))
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
			delete(hooksRaw, event)
			continue
		}
		newGroupsJSON, err := json.Marshal(newGroups)
		if err != nil {
			res.Error = fmt.Errorf(errPrefix+": marshal hooks[%s]: %w", event, err)
			return res
		}
		hooksRaw[event] = newGroupsJSON
	}
	sort.Strings(res.HooksRemoved)
	sort.Strings(res.HooksKept)
	sort.Strings(res.HooksKeptForeign)

	// No observer entries to remove — skip the checksum guard entirely
	// and treat this as a no-op regardless of file drift.
	if len(res.HooksRemoved) == 0 {
		res.Skipped = true
		return res
	}

	// There is real work to do — now verify the file hasn't drifted since
	// we installed, so we don't clobber user edits. Passing --force
	// bypasses the guard.
	match, err := r.checksumMatches(path, raw)
	if err != nil {
		res.Error = fmt.Errorf(errPrefix+": checksum: %w", err)
		return res
	}
	res.ChecksumMatch = match
	if !match && !r.opts.Force {
		res.Error = safeErrorf(errPrefix+": %s has been modified since install (checksum mismatch); pass --force to remove anyway", path)
		return res
	}

	if len(hooksRaw) == 0 {
		delete(settings, "hooks")
	} else {
		patched, err := json.Marshal(hooksRaw)
		if err != nil {
			res.Error = fmt.Errorf(errPrefix+": marshal hooks: %w", err)
			return res
		}
		settings["hooks"] = patched
	}

	if r.opts.DryRun {
		return res
	}

	if len(settings) == 0 {
		if err := removeEmptyConfigFile(path, raw); err != nil {
			res.Error = fmt.Errorf(errPrefix+": remove empty %s: %w", path, err)
			return res
		}
	} else {
		if err := r.writeHookSettingsJSON(tool, settingsDir, pinned, raw, settings); err != nil {
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
