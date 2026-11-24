package hook

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// claudeHookGroup is Observer's own Claude-shaped hook group as Observer
// writes it (one command handler), the shape the tests build fixtures
// with. No writer decodes or encodes a file through it: every writer,
// the hosted box seed included, keeps every field raw and writes its own
// group with observerGroupEntry (hookentries.go, NEW-06).
type claudeHookGroup struct {
	Matcher string              `json:"matcher,omitempty"`
	Hooks   []claudeHookCommand `json:"hooks"`
}

// claudeHookCommand is one command handler in Observer's own group.
type claudeHookCommand struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

// readClaudeHookSettings reads path for registerClaudeCode: the raw bytes
// (nil when the file does not exist), the top-level object with unknown
// fields preserved via map[string]json.RawMessage, and the event map with
// every group and handler kept as its raw JSON (B5, NEW-06), so an event
// the register loop never touches, and within an event it DOES touch every
// group member and sibling handler it doesn't own, round-trips instead of
// being decoded into (and truncated by) a typed struct. A hooks member
// Observer cannot read is refused (refuseHookShape), never overwritten.
func readClaudeHookSettings(path, errPrefix string) ([]byte, map[string]json.RawMessage, *hookEvents, error) {
	raw, err := readSettingsFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil, fmt.Errorf(errPrefix+": read: %w", err)
	}
	settings := map[string]json.RawMessage{}
	if len(raw) > 0 {
		settings, err = decodeSettingsObject(path, raw)
		if err != nil {
			return nil, nil, nil, fmt.Errorf(errPrefix+": %w", err)
		}
	}
	hooks, err := decodeHookEvents(settings["hooks"], groupedHookEntries)
	if err != nil {
		return nil, nil, nil, refuseHookShape(errPrefix, path, err)
	}
	return raw, settings, hooks, nil
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

	raw, settings, hooks, err := readClaudeHookSettings(path, errPrefix)
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
		cmd := claudeCodeHookCommand(binPath, event, r.configFlagSuffixForwardSlash())
		// Args drifted but the entry is already ours (recognised by
		// content-heuristic, see isObserverClaudeEntry): an EQUIVALENT
		// entry stays as it is under KeepEquivalentHooks (T-725: `observer
		// start` from another binary path must not rewrite the user's
		// file); otherwise refresh, which covers a broken entry (binary
		// gone), a different config, and the consented `observer init`
		// refresh to this binary. A non-observer hook command on the "*"
		// matcher counts as an unmanaged entry (the conflict check).
		added, err := r.putObserverGroup(&res, hooks, groupEntryRule{
			errPrefix: errPrefix, path: res.ConfigPath, event: event, cmd: cmd,
			matcher: "*", ours: isObserverClaudeEntry, drift: shapeDrift[event], keepEquivalent: true,
			conflictScope: claudeMatcherCanonical,
		})
		if err != nil {
			res.Error = err
			return res
		}
		if added {
			res.HooksAdded = append(res.HooksAdded, event)
		}
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

	if err := setHooksMember(settings, "hooks", hooks, false); err != nil {
		res.Error = fmt.Errorf(errPrefix+": %w", err)
		return res
	}

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
	// Every group and handler stays raw (B5, NEW-06): only Observer's
	// handlers go, and a developer's handler in the same group keeps its
	// group and every field.
	hooks, err := decodeHookEvents(settings["hooks"], groupedHookEntries)
	if err != nil {
		res.Error = refuseHookShape(errPrefix, path, err)
		return res
	}
	if err := r.removeObserverHandlers(&res, hooks, groupedHookEntries, "claude-code", isObserverClaudeEntry); err != nil {
		res.Error = fmt.Errorf(errPrefix+": %w", err)
		return res
	}

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

	if err := setHooksMember(settings, "hooks", hooks, true); err != nil {
		res.Error = fmt.Errorf(errPrefix+": %w", err)
		return res
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
