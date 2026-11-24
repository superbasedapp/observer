package hook

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// genericSettingsHookTarget parameterizes registerGenericSettingsHooks
// (Part B item 1, docs/plans/prompt-submit-intervention-exploration-2026-09-07.md
// §6.7): a single-event, Claude-Code-shaped
// {"hooks":{<event>:[{"hooks":[{"type":"command","command":…}]}]}}
// settings.json writer — generalized from registerClaudeCode's own
// body via the ALREADY tool-parameterized isObserverAnyHookEntry
// (the C2/IDE-11 cross-OS-ownership fix). Reused for every tool whose
// registration file matches this exact shape and needs only ONE event
// registered — Gemini CLI (BeforeAgent) and Qwen Code (UserPromptSubmit)
// today. Unlike registerClaudeCode's 21-event lifecycle registration,
// these two tools have no OTHER hook this repo captures, so a single
// event is the complete, honest scope — not a partial implementation
// of a larger one.
type genericSettingsHookTarget struct {
	// tool is the hookReceivers/`hook <tool>` dispatch token embedded in
	// the registered command — the BASE tool name (e.g. "gemini-cli"),
	// never a "-windows" suffix, because the hook receiver on the far
	// end (cmd/observer/hook.go's hookReceivers map) is keyed by base
	// tool name regardless of which config file wrote the command.
	tool string
	// resultTool is the RegistrationResult.Tool label. Empty means
	// "same as tool" (the native target); the cross-OS bridge targets
	// set this to the "-windows" name so callers can tell which config
	// file a result came from while the wire command still names the
	// base tool.
	resultTool string
	// dir is the settings directory (e.g. ~/.gemini, ~/.qwen).
	dir string
	// dirErr, when set, is why dir could not be resolved (a relocation
	// variable with a relative value, register_homes.go): nothing is
	// written and the error is reported.
	dirErr error
	// event is the tool's prompt-submit event: the fallback event list
	// when the registry row declares no registered bindings. The writer
	// registers every event the row's bindings mark Registered (events):
	// the prompt-submit event, the tool gate where the vendor offers one on
	// the same file (hook-parity Lane A3) and the lifecycle events Lane C
	// grounded.
	event string
	// errPrefix names the calling registrar in wrapped errors.
	errPrefix string
	// hostTarget, when set, is the host-home Registry target this writer
	// serves (gemini-cli-xcode, register_xcode.go): the credential-file
	// rules and the checksum entry answer for it, and an Unregister that
	// leaves no hook drops the hooks member (and a file left empty) rather
	// than leaving an empty block in the host's file. Empty for the native
	// and "-windows" targets, which answer for tool.
	hostTarget string
	// wrapper prefixes every registered command; "" for the native
	// target, `MSYS_NO_PATHCONV=1 wsl.exe -d <distro> -- ` for the
	// cross-OS bridge — same convention as registerClaudeCodeWindows /
	// registerCursorWindows (these tools spawn hooks through Git Bash
	// on Windows too, per the same vendor-doc precedent those two
	// registrars already established), NOT codex's cmd.exe convention.
	wrapper string
}

// label returns t.resultTool when set, else t.tool — the
// RegistrationResult.Tool value for both registerGenericSettingsHooks
// and unregisterGenericSettingsHooks.
func (t genericSettingsHookTarget) label() string {
	if t.resultTool != "" {
		return t.resultTool
	}
	return t.tool
}

// rulesTool is the target the credential-file rules and the checksum entry
// answer for: hostTarget when set, else tool.
func (t genericSettingsHookTarget) rulesTool() string {
	if t.hostTarget != "" {
		return t.hostTarget
	}
	return t.tool
}

// registerGenericSettingsHooks is the shared writer behind
// registerGeminiCLI, registerQwenCode and registerQoder. Conflict/refresh
// discipline mirrors registerClaudeCode exactly, per event in t.events():
// an entry isObserverAnyHookEntry recognises as ours is refreshed silently
// on drift; anything else blocks without --force.
func (r *Registry) registerGenericSettingsHooks(t genericSettingsHookTarget) RegistrationResult {
	res := RegistrationResult{Tool: t.label(), DryRun: r.opts.DryRun}
	if t.dirErr != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, t.dirErr)
		return res
	}
	path := filepath.Join(t.dir, "settings.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(path)

	raw, err := readSettingsFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Error = fmt.Errorf("%s: read: %w", t.errPrefix, err)
		return res
	}
	// Preserve unknown top-level fields (model config, MCP servers, …)
	// via map[string]json.RawMessage — same discipline as
	// registerClaudeCode.
	settings := map[string]json.RawMessage{}
	if len(raw) > 0 {
		settings, err = decodeSettingsObject(path, raw)
		if err != nil {
			res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
			return res
		}
	}
	// NEW-06: every group and handler stays raw, so a field Observer does
	// not write survives the rewrite.
	hooks, err := decodeHookEvents(settings["hooks"], groupedHookEntries)
	if err != nil {
		res.Error = refuseHookShape(t.errPrefix, path, err)
		return res
	}
	ours := func(c string) bool { return isObserverAnyHookEntry(c, t.tool) }

	// FU-192: an entry in Observer's shape running another binary is kept.
	if r.refusesForeignBinary(&res, t.errPrefix, path, identityContent, shapedHooksInText(settings["hooks"], t.tool)) {
		return res
	}
	binPath := forwardSlashPath(r.opts.BinaryPath)
	// T-847: a matcher or an extra field on Observer's entry is never
	// "already set" (hook_shape.go).
	shapeDrift := shapeDriftEvents(settings["hooks"], claudeShapedGroups(ours))
	for _, event := range r.registeredEventsFor(t.tool, t.event) {
		if r.skipEvent(t.tool, event) {
			continue
		}
		cmd := t.wrapper + genericSettingsHookCommand(binPath, t.tool, event, r.configFlagSuffixForwardSlash())
		// Stale-observer-args / cross-binary refresh: Observer's stale
		// handler is replaced where it sits (refreshObserverGroup).
		added, err := r.putObserverGroup(&res, hooks, groupEntryRule{
			errPrefix: t.errPrefix, path: res.ConfigPath, event: event, cmd: cmd,
			ours: ours, drift: shapeDrift[event],
		})
		if err != nil {
			res.Error = err
			return res
		}
		if added {
			res.HooksAdded = append(res.HooksAdded, event)
		}
	}
	// An opt-in event whose component is not selected loses the entry
	// Observer wrote for it (Options.Selected, lane sec-h); nothing else in
	// the file changes.
	removed, err := removeObserverEvents(hooks, r.optInEventsOff(t.tool), ours)
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
		return res
	}
	if len(res.HooksAdded) == 0 && len(removed) == 0 {
		return res
	}
	if err := setHooksMember(settings, "hooks", hooks, false); err != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
		return res
	}

	if r.opts.DryRun {
		return res
	}
	if err := r.writeHookSettingsJSON(t.rulesTool(), t.dir, pinned, raw, settings); err != nil {
		res.Error = err
		return res
	}
	if err := r.recordHookChecksum(t.rulesTool(), path); err != nil {
		res.Error = err
		return res
	}
	return res
}

// removeObserverEvents drops Observer's handlers (ours) from each of
// events, keeping every other group and handler with its data and order, and
// returns the events it changed.
func removeObserverEvents(hooks *hookEvents, events []string, ours func(string) bool) ([]string, error) {
	var changed []string
	for _, event := range events {
		kept, removed, _, err := groupedHookEntries.removeHandlers(hooks.entries(event), ours)
		if err != nil {
			return nil, err
		}
		if removed == 0 {
			continue
		}
		hooks.set(event, kept)
		changed = append(changed, event)
	}
	return changed, nil
}

// registerGeminiCLI installs the prompt-submit hook into
// ~/.gemini/settings.json's "hooks" block (contract §6.7: new
// HookGeminiSettings mechanism), plus the BeforeTool tool gate
// (every Registered binding of the row, t.events()).
func (r *Registry) registerGeminiCLI() RegistrationResult {
	return r.registerGenericSettingsHooks(r.nativeSettingsTarget("gemini-cli", "gemini-cli/user-settings", "BeforeAgent", "hook.registerGeminiCLI"))
}

// registerQwenCode installs the prompt-submit hook into
// ~/.qwen/settings.json's "hooks" block (contract §6.7: new
// HookQwenSettings mechanism), plus the PreToolUse tool gate and the
// grounded lifecycle events (every Registered binding of the row).
func (r *Registry) registerQwenCode() RegistrationResult {
	return r.registerGenericSettingsHooks(r.nativeSettingsTarget("qwen-code", "qwen-code/user-settings", "UserPromptSubmit", "hook.registerQwenCode"))
}

// registerQoder installs the prompt-submit hook into
// ~/.qoder/settings.json's "hooks" block (Part B item 2, phase-3a:
// new HookQoderJSON mechanism). Live-fetched 2026-09-07
// (docs.qoder.com/en/cli/hooks): Qoder's settings.json hooks schema
// ({"hooks":{"UserPromptSubmit":[{"matcher":…,"hooks":[{"type":
// "command","command":…,"timeout":…}]}]}}) is byte-identical to
// Claude Code's own — the same shape registerGenericSettingsHooks
// already generalizes for Gemini CLI/Qwen Code. Events: UserPromptSubmit
// and the PreToolUse tool gate plus the grounded lifecycle events (every
// Registered binding of the row; NIT, phase-3a review:
// re-counted 2026-09-07 — Qoder's own Event Reference overview table
// lists 23 distinct hook event names, not 24 as an earlier pass here
// miscounted).
func (r *Registry) registerQoder() RegistrationResult {
	return r.registerGenericSettingsHooks(r.nativeSettingsTarget("qoder", "qoder/user-settings", "UserPromptSubmit", "hook.registerQoder"))
}

// unregisterGenericSettingsHooks removes ONLY the observer-owned hook
// groups for t.events() from the settings.json's "hooks" block, leaving
// every other key (and every other event) untouched. Symmetric
// counterpart of registerGenericSettingsHooks.
func (r *Registry) unregisterGenericSettingsHooks(t genericSettingsHookTarget) UnregistrationResult {
	res := UnregistrationResult{Tool: t.label(), DryRun: r.opts.DryRun}
	if t.dirErr != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, t.dirErr)
		return res
	}
	path := filepath.Join(t.dir, "settings.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(path)

	raw, err := readSettingsFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return res
		}
		res.Error = fmt.Errorf("%s: read: %w", t.errPrefix, err)
		return res
	}
	settings, err := decodeSettingsObject(path, raw)
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
		return res
	}
	existing, ok := settings["hooks"]
	if !ok {
		return res
	}
	hooks, err := decodeHookEvents(existing, groupedHookEntries)
	if err != nil {
		res.Error = refuseHookShape(t.errPrefix, path, err)
		return res
	}
	ours := func(c string) bool { return isObserverAnyHookEntry(c, t.tool) }
	// FU-203: the strict recogniser never takes an entry in Observer's
	// shape that runs another binary; it is reported kept.
	for _, ev := range allEventsFor(t.tool, t.event) {
		for _, g := range hooks.entries(ev) {
			for _, c := range groupedHookEntries.commands(g) {
				if r.keepsForeignBinary(shapedHooksInText([]byte(c), t.tool)) {
					noteKeptForeign(&res, ev)
				}
			}
		}
	}
	res.HooksRemoved, err = removeObserverEvents(hooks, allEventsFor(t.tool, t.event), ours)
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
		return res
	}
	if len(res.HooksRemoved) == 0 {
		return res
	}
	if hooks.empty() && t.hostTarget != "" {
		delete(settings, "hooks")
	} else if len(hooks.dirty) > 0 {
		patched, err := hooks.encode()
		if err != nil {
			res.Error = fmt.Errorf("%s: encode hooks: %w", t.errPrefix, err)
			return res
		}
		settings["hooks"] = patched
	}

	if r.opts.DryRun {
		return res
	}
	if len(settings) == 0 && t.hostTarget != "" {
		if err := removeEmptyConfigFile(path, raw); err != nil {
			res.Error = fmt.Errorf("%s: remove empty %s: %w", t.errPrefix, path, err)
			return res
		}
	} else if err := r.writeHookSettingsJSON(t.rulesTool(), t.dir, pinned, raw, settings); err != nil {
		res.Error = err
		return res
	}
	if err := r.removeChecksum(path); err != nil {
		res.Error = err
		return res
	}
	return res
}

func (r *Registry) unregisterGeminiCLI() UnregistrationResult {
	return r.unregisterGenericSettingsHooks(r.nativeSettingsTarget("gemini-cli", "gemini-cli/user-settings", "BeforeAgent", "hook.unregisterGeminiCLI"))
}

func (r *Registry) unregisterQwenCode() UnregistrationResult {
	return r.unregisterGenericSettingsHooks(r.nativeSettingsTarget("qwen-code", "qwen-code/user-settings", "UserPromptSubmit", "hook.unregisterQwenCode"))
}

func (r *Registry) unregisterQoder() UnregistrationResult {
	return r.unregisterGenericSettingsHooks(r.nativeSettingsTarget("qoder", "qoder/user-settings", "UserPromptSubmit", "hook.unregisterQoder"))
}

// nativeSettingsTarget is the native settings.json target of tool, whose
// directory is that of the catalogued artifact (gemini-cli/user-settings,
// qwen-code/user-settings, qoder/user-settings), so the vendor's own home
// variable (GEMINI_CLI_HOME, QWEN_HOME, QODER_CONFIG_DIR) moves the write
// with the route writer and the detector (S-17).
func (r *Registry) nativeSettingsTarget(tool, artifact, event, errPrefix string) genericSettingsHookTarget {
	dir, err := r.artifactDir(artifact)
	return genericSettingsHookTarget{tool: tool, dir: dir, dirErr: err, event: event, errPrefix: errPrefix}
}
