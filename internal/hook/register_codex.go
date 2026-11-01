package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// droidHookTarget parameterizes registerFactoryDroidAt for its two
// registration targets: the native `~/.factory` on the daemon's own OS,
// and the cross-OS Windows-side `.factory` the droid-windows bridge
// writes. Mirrors codexHookTarget — one shared writer (CLAUDE.md #4),
// differing only in where it writes and whether the command carries the
// wsl.exe bridge wrapper. The dispatch vocabulary embedded in the
// command is always the literal "droid" (hardcoded in
// registerFactoryDroidAt), never "droid-windows" — the hook receiver on
// the far end is keyed by base tool name.
type droidHookTarget struct {
	// tool is the RegistrationResult.Tool label ("droid" / "droid-windows").
	tool string
	// dir is the .factory directory holding hooks.json.
	dir string
	// wrapper prefixes every registered command; "" for the native
	// target, `MSYS_NO_PATHCONV=1 wsl.exe -d <distro> -- ` for the
	// cross-OS bridge.
	wrapper string
	// errPrefix names the calling registrar in wrapped errors.
	errPrefix string
}

// registerFactoryDroid installs the prompt-submit hook and the tool gate
// into ~/.factory/hooks.json (contract §6.7: HookFactoryJSON mechanism).
// Droid's hooks.json is a DEDICATED hooks-only file whose event map sits
// at the ROOT of the object (readDroidHooks / writeDroidHooks in
// register_droid_hooksjson.go), unlike Codex's {"hooks":{...}} file.
func (r *Registry) registerFactoryDroid() RegistrationResult {
	return r.registerFactoryDroidAt(droidHookTarget{
		tool:      "droid",
		dir:       filepath.Join(r.opts.HomeDir, ".factory"),
		errPrefix: "hook.registerFactoryDroid",
	})
}

// droidEvents is the event list the droid writer registers: the registry
// row's Registered bindings (hook-parity audit section 5.4): the
// prompt-submit event (Part B) and the pre-tool gate (hook-parity Lane A3).
func droidEvents() []string { return eventsOr("droid", "UserPromptSubmit") }

// registerFactoryDroidAt is the shared ~/.factory/hooks.json writer
// behind registerFactoryDroid and registerFactoryDroidWindows.
// Conflict/refresh discipline mirrors registerCodexAt, per event in
// droidEvents(): an entry isObserverAnyHookEntry recognises as ours is
// refreshed silently on drift; anything else blocks without --force.
func (r *Registry) registerFactoryDroidAt(t droidHookTarget) RegistrationResult {
	res := RegistrationResult{Tool: t.tool, DryRun: r.opts.DryRun}
	path := filepath.Join(t.dir, "hooks.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
		return res
	}
	defer unlock()

	pinned := pinWriteTarget(path)

	// Lift only Observer's own wrapped groups, and only for the events this
	// run writes (reviews M2-10 / M2-15).
	doc, lifted, err := readDroidHooks(path, func(event string) bool {
		return slices.Contains(droidEvents(), event) && !r.skipEvent("droid", event)
	})
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
		return res
	}
	// FU-192: an entry in Observer's shape running another binary is kept.
	if r.refusesForeignBinaryInFile(&res, t.errPrefix, path, "droid", identityContent) {
		return res
	}

	for _, event := range droidEvents() {
		if r.skipEvent("droid", event) {
			continue
		}
		cmd := t.wrapper + shellQuoteIfNeeded(forwardSlashPath(r.opts.BinaryPath)) + " hook droid " + event + r.configFlagSuffixForwardSlash()
		groups, err := doc.groups(event)
		if err != nil {
			res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
			return res
		}
		idx := droidObserverGroupIndex(groups)
		if idx >= 0 && groupShapeDrift(groups[idx], claudeShapedGroups(droidOurs)) {
			// T-847: a narrowed matcher or an extra field on Observer's
			// entry is never "already set" (hook_shape.go).
			shapeRewrite(&res, event, cmd, cmd)
			groups = append(groups[:idx:idx], groups[idx+1:]...)
			idx = -1
		}
		if idx >= 0 {
			hs := droidGroupCommands(groups[idx])
			// T-725, as the Claude Code writer: an Observer entry that is not
			// byte-equal but still EQUIVALENT (another install path of the
			// observer binary, or a --config naming the default file) stays
			// as written under KeepEquivalentHooks, and counts as set. The
			// doctor / `observer guard prompt status` probe registers in this
			// mode, so before this an equivalent UserPromptSubmit entry that
			// `observer start` does not refresh (a binding still owed its
			// live test) read as NOT REGISTERED. A lifted entry was not
			// firing, so it is never kept.
			if len(hs) == 1 && hs[0].Command != cmd && !lifted[event] &&
				r.keepOrRewrite(&res, event, hs[0].Command, cmd) {
				res.AlreadySet = append(res.AlreadySet, event)
				continue
			}
			if len(hs) == 1 && hs[0].Command == cmd {
				// A current entry lifted out of the legacy wrapper was NOT
				// firing (droid ignores the wrapper): it is added by this
				// write, never "already set" (currency, as M2-07).
				if lifted[event] {
					res.HooksAdded = append(res.HooksAdded, event)
				} else {
					res.AlreadySet = append(res.AlreadySet, event)
				}
				continue
			}
			groups = append(groups[:idx], groups[idx+1:]...)
		}
		if r.refuses(res.ConfigPath, identityContent) {
			for _, g := range groups {
				for _, h := range droidGroupCommands(g) {
					if h.Type == "command" && !isObserverAnyHookEntry(h.Command, "droid") {
						res.Error = hookConflictError(t.errPrefix, event)
						return res
					}
				}
			}
		}
		own, err := marshalDroidJSON(codexHookGroup{
			Matcher: "*",
			Hooks:   []claudeHookCommand{{Type: "command", Command: cmd}},
		})
		if err != nil {
			res.Error = fmt.Errorf("%s: encode %s: %w", t.errPrefix, event, err)
			return res
		}
		if err := doc.setGroups(event, append(groups, own)); err != nil {
			res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
			return res
		}
		res.HooksAdded = append(res.HooksAdded, event)
	}
	// A file whose Observer groups sat in the legacy {"hooks":{...}}
	// wrapper is rewritten: droid ignores the wrapper, so leaving it means
	// no hook fires (live 2026-10-04).
	if len(res.HooksAdded) == 0 && len(lifted) == 0 {
		return res
	}

	if r.opts.DryRun {
		return res
	}
	if err := writeDroidHooks(t.dir, pinned, doc); err != nil {
		res.Error = err
		return res
	}
	if err := r.recordChecksum(res.Tool, path); err != nil {
		res.Error = err
		return res
	}
	return res
}

// droidOurs recognises an Observer droid hook command.
func droidOurs(cmd string) bool { return isObserverAnyHookEntry(cmd, "droid") }

// droidObserverGroupIndex returns the index of the LAST matcher group that
// holds an Observer droid hook entry, -1 when none does.
func droidObserverGroupIndex(groups []json.RawMessage) int {
	idx := -1
	for i, g := range groups {
		for _, h := range droidGroupCommands(g) {
			if h.Type == "command" && isObserverAnyHookEntry(h.Command, "droid") {
				idx = i
			}
		}
	}
	return idx
}

// unregisterFactoryDroid removes ONLY the observer-owned groups
// (droidEvents()) from ~/.factory/hooks.json.
func (r *Registry) unregisterFactoryDroid() UnregistrationResult {
	return r.unregisterFactoryDroidAt("droid", filepath.Join(r.opts.HomeDir, ".factory"), "hook.unregisterFactoryDroid")
}

// unregisterFactoryDroidAt is the shared hooks.json cleaner behind
// unregisterFactoryDroid and unregisterFactoryDroidWindows.
func (r *Registry) unregisterFactoryDroidAt(tool, dir, errPrefix string) UnregistrationResult {
	res := UnregistrationResult{Tool: tool, DryRun: r.opts.DryRun}
	path := filepath.Join(dir, "hooks.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", errPrefix, err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(path)

	// Lift Observer's own wrapped groups of the events Observer registers,
	// so they are removed too; a user's wrapped group stays put.
	doc, _, err := readDroidHooks(path, func(event string) bool { return slices.Contains(droidEvents(), event) })
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", errPrefix, err)
		return res
	}
	for _, event := range droidEvents() {
		groups, err := doc.groups(event)
		if err != nil {
			res.Error = fmt.Errorf("%s: %w", errPrefix, err)
			return res
		}
		kept := groups[:0]
		removed := false
		for _, g := range groups {
			hs := droidGroupCommands(g)
			isOurs := len(hs) > 0
			for _, h := range hs {
				if h.Type != "command" || !isObserverAnyHookEntry(h.Command, "droid") {
					isOurs = false
				}
			}
			if isOurs {
				removed = true
				continue
			}
			kept = append(kept, g)
		}
		if !removed {
			continue
		}
		if err := doc.setGroups(event, kept); err != nil {
			res.Error = fmt.Errorf("%s: %w", errPrefix, err)
			return res
		}
		res.HooksRemoved = append(res.HooksRemoved, event)
	}
	if len(res.HooksRemoved) == 0 {
		return res
	}

	if r.opts.DryRun {
		return res
	}
	if err := writeDroidHooks(dir, pinned, doc); err != nil {
		res.Error = err
		return res
	}
	if err := r.removeChecksum(path); err != nil {
		res.Error = err
		return res
	}
	return res
}

// codexEvents is the set of Codex hook events we register for. Codex's
// hook event names are CamelCase identical to Claude Code's, but codex
// fires its own subset (no Pre/Post compact, no SubagentStart/Stop, etc.).
// Per developers.openai.com/codex/hooks (snapshot 2026-05-09), codex
// exposes 6 events; we register all 6 so observer's hook handler is the
// single point of capture / dispatch.
//
// Since hook-parity Lane C the list is the registry row's Registered
// bindings (audit section 5.4), in binding order; the six events above are
// its fallback.
var codexEvents = eventsOr("codex",
	"SessionStart",
	"UserPromptSubmit",
	"PreToolUse",
	"PermissionRequest",
	"PostToolUse",
	"Stop",
)

// codexHooksFile is the per-event-list config; we keep hooks in
// ~/.codex/hooks.json (codex also accepts [hooks.<Event>] inside
// config.toml but the JSON file path is canonical and the diff stays
// scoped to a single file). codex 0.129.0 requires
// `[features].hooks = true` in config.toml separately to actually
// dispatch hooks — registerCodex sets both. See
// ensureCodexHooksFeatureFlag for the verified flag-name history.
const codexHooksFile = "hooks.json"

// codexHookGroup mirrors claudeHookGroup — codex inherited Claude Code's
// hooks-config schema verbatim (top-level `hooks` map → event-name
// arrays → group with matcher + nested hooks list).
type codexHookGroup struct {
	Matcher string              `json:"matcher,omitempty"`
	Hooks   []claudeHookCommand `json:"hooks"`
}

// codexHooksFile body is `{"hooks": {<event>: [<group>...]}}`.
type codexHooksConfig struct {
	Hooks map[string][]codexHookGroup `json:"hooks"`
}

// registerCodex installs observer hooks into ~/.codex/hooks.json AND
// ensures `[features].hooks = true` in ~/.codex/config.toml so codex
// actually dispatches them. Idempotent — re-running with the same
// binary path returns AlreadySet.
//
// Trust caveat: codex requires per-hook user trust approval the first
// time each entry is seen (security feature). The user must run codex
// once after registration and use `/hooks` to mark our entries trusted;
// there is no documented programmatic shortcut as of codex 0.129.0
// (the trust hash algorithm is opaque and not exposed via any
// `codex` subcommand). The CLI prints a hint after registration.
func (r *Registry) registerCodex() RegistrationResult {
	// codexHookQuoteIfNeeded picks the quoter by path shape: POSIX
	// single quotes for a Linux/macOS path (codex spawns hooks via
	// /bin/sh there), a PowerShell literal for a Windows path, and the
	// call operator in front of a quoted Windows binary (codexHookExe).
	// Codex on Windows runs every hook command as `powershell.exe
	// -NoProfile -Command "<command>"` (FU-162, Windows rig run A8);
	// the earlier cmd.exe double quotes (operator report 2026-05-23,
	// codex 0.133) made a quoted binary a PowerShell string expression.
	// A path that needs no quoting is written as before, which both
	// shells run.
	dir, err := r.codexHomeDir()
	if err != nil {
		return RegistrationResult{Tool: "codex", DryRun: r.opts.DryRun, Error: err}
	}
	return r.registerCodexAt(codexHookTarget{
		tool:      "codex",
		dir:       dir,
		quote:     codexHookQuoteIfNeeded,
		quoteExe:  codexHookExe,
		errPrefix: "hook.registerCodex",
		matchMine: isObserverCodexEntryNative,
		trustKey:  nativeCodexTrustKey,
	})
}

// nativeCodexTrustKey: a Codex on the daemon's own OS keys trust with the
// hooks.json path it loaded, which is the path Observer wrote.
func nativeCodexTrustKey(hooksPath string) (string, bool) { return hooksPath, true }

// codexHookQuoteIfNeeded quotes one argument of a native Codex hook command
// for the shell Codex runs it through: a Windows-shaped path becomes a
// PowerShell single-quoted literal when it holds a character PowerShell
// reads (a space, $, a backtick, ;, &, quotes and the rest of
// psQuoteIfNeeded's set), because Codex on Windows starts every hook as
// `powershell.exe -NoProfile -Command "<command>"` (FU-162); any other path
// is POSIX-quoted for /bin/sh (shellQuoteIfNeeded). Path shape, not
// runtime.GOOS, so both spellings are pinned on any test host.
func codexHookQuoteIfNeeded(s string) string {
	if isWindowsPath(s) {
		return psQuoteIfNeeded(s)
	}
	return shellQuoteIfNeeded(s)
}

// codexHookExe is the first word of a native Codex hook command: the
// quoted binary, behind PowerShell's call operator when it is a quoted
// Windows path (PowerShell reads a command that starts with a quoted string
// as a string expression, not a program to run). An unquoted path stays
// bare, so the command is byte-identical to the earlier writer's.
func codexHookExe(s string) string {
	q := codexHookQuoteIfNeeded(s)
	if isWindowsPath(s) && strings.HasPrefix(q, "'") {
		return "& " + q
	}
	return q
}

// codexHookTarget parameterizes registerCodexAt for its two
// registration targets: the native `~/.codex` on the daemon's own OS,
// and the cross-OS Windows-side `.codex` the codex-windows bridge
// writes. Both produce the same hooks.json shape through ONE writer
// (CLAUDE.md #4: one owner per piece of state) — they differ only in
// where they write, how they quote, whether the command carries the
// wsl.exe bridge wrapper, and (B4 fix) which shape they'll accept as
// "already ours".
type codexHookTarget struct {
	// tool is the RegistrationResult.Tool label ("codex" /
	// "codex-windows").
	tool string
	// dir is the .codex directory holding hooks.json + config.toml.
	dir string
	// wrapper prefixes every registered command; "" for the native
	// target, `wsl.exe -d <distro> -- ` for the cross-OS bridge.
	wrapper string
	// quote quotes the binary path and the --config argument for the
	// shell codex spawns hooks through on that target.
	quote func(string) string
	// quoteExe, when set, renders the binary as the command's first word
	// (the native target puts PowerShell's call operator before a quoted
	// Windows binary); nil uses quote.
	quoteExe func(string) string
	// errPrefix names the calling registrar in wrapped errors so a
	// failure still points at the target the operator asked for.
	errPrefix string
	// matchMine recognises an existing hook command as belonging to
	// THIS target (used for both the "already set, don't touch" check
	// and the conflict guard). registerCodex passes the STRICT
	// isObserverCodexEntryNative (excludes the wsl.exe bridge shape);
	// registerCodexWindows passes the permissive isObserverCodexEntry
	// (matches native OR bridge). B4 fix: before this field existed,
	// registerCodexAt always used the permissive isObserverCodexEntry
	// for BOTH targets, so a native `Register("codex")` re-run against
	// a hooks.json that already held a codex-windows bridge entry (the
	// two targets DO write the identical file when WindowsCodexHome
	// resolves to the same directory HomeDir does — see
	// TestRegisterCodexNativeDoesNotClobberBridgeEntry) recognised the
	// bridge command as "already ours", found it didn't string-match
	// the NATIVE command it was about to write, and silently rewrote
	// it into native form with NO --force — exactly the flip-flop
	// isObserverWindowsClaudeEntry/isObserverWindowsCursorEntry's split
	// from their native counterparts already prevents for the other
	// two tools. Mirrors that asymmetry: the Windows target MAY still
	// convert a stale native entry into bridge form (registerCodexAt's
	// existing drift-refresh behaviour, unchanged), but the native
	// target must now treat an existing bridge entry as a foreign
	// conflict requiring --force, never the reverse.
	matchMine func(string) bool
	// trustKey spells hooks.json's path the way the Codex that loads it
	// keys [hooks.state] trust (the native path, or C:\... for the
	// Windows Codex a WSL daemon reaches through /mnt/c). ok=false means
	// the spelling is unknown and no trust is recorded.
	trustKey func(hooksPath string) (string, bool)
	// commandFor, when set, may replace the command written for one event
	// (the codex-windows fail-closed hook bridge, AW-37); nil writes the
	// default command for every event.
	commandFor func(event, cmd string) string
}

// registerCodexAt is the shared codex hooks.json writer behind
// registerCodex and registerCodexWindows. Conflict / refresh discipline
// is identical on both targets modulo t.matchMine (see its doc
// comment): an entry t.matchMine recognises as ours is refreshed
// silently, anything else blocks without --force.
func (r *Registry) registerCodexAt(t codexHookTarget) RegistrationResult {
	res := RegistrationResult{Tool: t.tool, DryRun: r.opts.DryRun}
	hooksPath := filepath.Join(t.dir, codexHooksFile)
	res.ConfigPath = hooksPath

	// Serialize observer's own writers of this file, THEN read — same
	// contract as registerClaudeCode/registerCursor (see lockSettings).
	// Codex's hooks.json previously took NO lock at all here.
	unlock, err := r.lockSettings(hooksPath)
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(hooksPath)

	cfg, err := readCodexHooks(hooksPath)
	if err != nil {
		res.Error = err
		return res
	}

	// T-847: the typed decode cannot see a field Observer never writes on
	// its own entry; read the raw shape once (hook_shape.go).
	hooksRaw := fileHooksRaw(hooksPath)
	// FU-192: an entry in Observer's shape running another binary is kept.
	if r.refusesForeignBinary(&res, t.errPrefix, hooksPath, identityContent, shapedHooksInText(hooksRaw, "codex")) {
		return res
	}
	shapeDrift := shapeDriftEvents(hooksRaw, claudeShapedGroups(t.matchMine))

	for _, event := range codexEvents {
		exe := t.quote
		if t.quoteExe != nil {
			exe = t.quoteExe
		}
		cmd := t.wrapper + exe(r.opts.BinaryPath) + " hook codex " + event + r.configFlagSuffixWith(t.quote)
		if t.commandFor != nil {
			cmd = t.commandFor(event, cmd)
		}
		groups := cfg.Hooks[event]
		idx := findCodexGroupWithObserver(groups, t.matchMine)
		if idx >= 0 && shapeDrift[event] {
			shapeRewrite(&res, event, cmd, cmd)
		}
		if idx >= 0 {
			if observerCodexCmdMatches(groups[idx], cmd) && !shapeDrift[event] {
				res.AlreadySet = append(res.AlreadySet, event)
				continue
			}
			// Stale-observer-args / cross-binary refresh — recognised
			// as ours via t.matchMine's content-heuristic. Drop the
			// stale group; the fresh append below restores.
			groups = append(groups[:idx], groups[idx+1:]...)
		}
		if r.refuses(res.ConfigPath, identityContent) && hasConflictingCodexHook(groups, t.matchMine) {
			if onlyCodexBridgeConflicts(groups, t.matchMine) {
				res.Error = codexBridgeConflictError(t.errPrefix, event)
				return res
			}
			res.Error = hookConflictError(t.errPrefix, event)
			return res
		}
		groups = append(groups, codexHookGroup{
			Matcher: "*",
			Hooks:   []claudeHookCommand{{Type: "command", Command: cmd}},
		})
		cfg.Hooks[event] = groups
		res.HooksAdded = append(res.HooksAdded, event)
	}

	if r.opts.DryRun {
		// Still report whether the feature flag would be flipped.
		return res
	}

	if err := writeCodexHooks(t.dir, pinned, cfg); err != nil {
		res.Error = err
		return res
	}
	if err := r.recordChecksum(res.Tool, hooksPath); err != nil {
		res.Error = err
		return res
	}
	if err := r.ensureCodexHooksFeatureFlag(t.dir); err != nil {
		res.Error = err
		return res
	}
	r.recordCodexTrust(&res, t)
	return res
}

func (r *Registry) unregisterCodex() UnregistrationResult {
	dir, err := r.codexHomeDir()
	if err != nil {
		return UnregistrationResult{Tool: "codex", DryRun: r.opts.DryRun, Error: err}
	}
	return r.unregisterCodexAt("codex", dir, "hook.unregisterCodex", nativeCodexTrustKey)
}

// unregisterCodexAt is the shared codex hooks.json cleaner behind
// unregisterCodex and unregisterCodexWindows. dir is the .codex
// directory; errPrefix names the calling registrar in wrapped errors;
// trustKey is the target's codexHookTarget.trustKey, used to remove the
// trust records Observer wrote for the entries it removes.
func (r *Registry) unregisterCodexAt(tool, dir, errPrefix string, trustKey func(string) (string, bool)) UnregistrationResult {
	res := UnregistrationResult{Tool: tool, DryRun: r.opts.DryRun}
	hooksPath := filepath.Join(dir, codexHooksFile)
	res.ConfigPath = hooksPath

	unlock, err := r.lockSettings(hooksPath)
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", errPrefix, err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(hooksPath)

	raw, err := os.ReadFile(hooksPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			res.Skipped = true
			return res
		}
		res.Error = fmt.Errorf("%s: read: %w", errPrefix, err)
		return res
	}
	var cfg codexHooksConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		res.Error = fmt.Errorf("%s: parse %s: %w", errPrefix, hooksPath, err)
		return res
	}
	if cfg.Hooks == nil {
		cfg.Hooks = map[string][]codexHookGroup{}
	}

	for event, groups := range cfg.Hooks {
		foreign := false
		newGroups, removed, kept := filterCodexGroups(groups, r.removableEntry("codex", isObserverCodexEntry, &foreign))
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
			delete(cfg.Hooks, event)
		} else {
			cfg.Hooks[event] = newGroups
		}
	}
	sort.Strings(res.HooksRemoved)
	sort.Strings(res.HooksKept)

	if len(res.HooksRemoved) == 0 {
		res.Skipped = true
		return res
	}

	match, err := r.checksumMatches(hooksPath, raw)
	if err != nil {
		res.Error = fmt.Errorf("%s: checksum: %w", errPrefix, err)
		return res
	}
	if !match && !r.opts.Force {
		res.Error = fmt.Errorf("%s: %s changed since install; pass --force to overwrite", errPrefix, hooksPath)
		return res
	}

	if r.opts.DryRun {
		return res
	}
	// When no entries remain we still write an empty `{"hooks":{}}` rather
	// than removing the file entirely; codex tolerates the empty object and
	// the user may have added their own entries we don't know about
	// (kept-rows above already short-circuit if any non-observer entries
	// remain).
	if err := writeCodexHooks(dir, pinned, cfg); err != nil {
		res.Error = err
		return res
	}
	if err := r.removeChecksum(hooksPath); err != nil {
		res.Error = err
		return res
	}
	// Note: we DO NOT flip [features].hooks = false on uninstall —
	// the user may have other hooks registered through that flag.
	r.removeCodexTrust(&res, dir, raw, trustKey)
	return res
}

// readCodexHooks loads ~/.codex/hooks.json, returning an empty config
// when the file doesn't exist.
func readCodexHooks(path string) (codexHooksConfig, error) {
	cfg := codexHooksConfig{Hooks: map[string][]codexHookGroup{}}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("hook.readCodexHooks: read: %w", err)
	}
	if len(raw) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("hook.readCodexHooks: parse %s: %w", path, err)
	}
	if cfg.Hooks == nil {
		cfg.Hooks = map[string][]codexHookGroup{}
	}
	return cfg, nil
}

// writeCodexHooks marshals cfg as 2-space-indented JSON with stable
// event ordering. Creates the parent dir if missing. Callers own the
// advisory lock (see lockSettings) — this function must never take it
// itself, matching writeJSONIndented's contract.
//
// pinned must have been produced by pinWriteTarget against the hooks
// file, right after the lock was acquired and before it was first
// read — see pinnedTarget's doc comment for why (F6).
func writeCodexHooks(dir string, pinned pinnedTarget, cfg codexHooksConfig) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("hook.writeCodexHooks: mkdir: %w", err)
	}
	// Emit with sorted event keys so JSON diffs stay clean across
	// re-registrations.
	keys := make([]string, 0, len(cfg.Hooks))
	for k := range cfg.Hooks {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteString("{\n  \"hooks\": {")
	for i, k := range keys {
		if i > 0 {
			buf.WriteString(",")
		}
		buf.WriteString("\n    ")
		ke, _ := json.Marshal(k)
		buf.Write(ke)
		buf.WriteString(": ")
		ge, err := json.MarshalIndent(cfg.Hooks[k], "    ", "  ")
		if err != nil {
			return fmt.Errorf("hook.writeCodexHooks: encode %s: %w", k, err)
		}
		buf.Write(ge)
	}
	if len(keys) > 0 {
		buf.WriteString("\n  ")
	}
	buf.WriteString("}\n}\n")

	if err := atomicWriteFile(pinned, buf.Bytes()); err != nil {
		return fmt.Errorf("hook.writeCodexHooks: %w", err)
	}
	return nil
}

// isObserverCodexEntry recognises a hook command as one previously
// written by ANY observer codex registrar, NATIVE OR the wsl.exe
// cross-OS bridge alike. Same content-heuristic rationale as
// isObserverClaudeEntry/isObserverWindowsClaudeEntry and
// isObserverCursorEntry/isObserverWindowsCursorEntry — the
// ` hook codex ` token sequence is the stable signature regardless of
// which observer binary path (or bridge wrapper) prefixes it. Lets
// refresh-on-drift upgrade entries left behind by a differently-
// installed observer (npm bundle in node_modules, cross-binary
// upgrade, renamed $HOME) without --force.
//
// This is the PERMISSIVE half of codex's native/bridge predicate pair
// (B4 fix) — the counterpart to the STRICT isObserverCodexEntryNative.
// Used for: registerCodexWindows's own "already ours" check (so the
// bridge target may still silently convert a stale NATIVE entry into
// bridge form — the same one-directional asymmetry
// isObserverWindowsClaudeEntry documents), and BOTH unregister paths
// (uninstall must clean up either shape regardless of which target is
// asked to do it). It must NEVER be used for registerCodex's (native)
// own "already ours"/conflict check — that uses
// isObserverCodexEntryNative instead, or a native re-register would
// silently overwrite an existing bridge entry with no --force. See
// codexHookTarget.matchMine's doc comment for the incident this
// predicate split fixes.
func isObserverCodexEntry(cmd string) bool {
	return strings.Contains(cmd, " hook codex ") || isHookBridgeEntry(cmd, "codex")
}

// IsObserverCodexHookCommand reports whether a Codex hooks.json command is
// Observer's, in every shape Observer writes: the native and wsl.exe-bridge
// `observer hook codex <event>` and the fail-closed `observer hook-bridge
// ... --tool codex` entry (AW-37). The dashboard's Codex trust status and
// the doctor's trust row use it, so they see the same entries the
// registrar owns.
func IsObserverCodexHookCommand(cmd string) bool { return isObserverCodexEntry(cmd) }

// isObserverCodexEntryNative is the STRICT, native-only half of
// codex's predicate pair (B4 fix): it recognises the same
// ` hook codex ` signature as isObserverCodexEntry but EXCLUDES the
// wsl.exe cross-OS bridge shape registerCodexWindows writes — the
// exact split isObserverClaudeEntry/isObserverCursorEntry already
// apply for their own tools (see isObserverClaudeEntry's doc comment
// for the full "must not merge" rationale). Used ONLY by registerCodex
// (via codexHookTarget.matchMine) so a native re-register never
// mistakes an existing bridge entry for "already ours" and silently
// rewrites it into native form — that flip would need --force, exactly
// like a native claude-code/cursor register already refuses to
// overwrite an existing bridge entry without it.
func isObserverCodexEntryNative(cmd string) bool {
	if !strings.Contains(cmd, " hook codex ") {
		return false
	}
	if strings.HasPrefix(cmd, "wsl.exe ") || strings.HasPrefix(cmd, "MSYS_NO_PATHCONV=1 wsl.exe ") {
		return false
	}
	return true
}

// findCodexGroupWithObserver returns the index of a codex hook
// group whose single entry is recognised as observer-written by
// matchMine (t.matchMine — either isObserverCodexEntry or
// isObserverCodexEntryNative, see codexHookTarget's doc comment), or
// -1. Content-heuristic so cross-binary stale entries are still
// detected as ours and refreshed.
func findCodexGroupWithObserver(groups []codexHookGroup, matchMine func(string) bool) int {
	for i, g := range groups {
		for _, h := range g.Hooks {
			if h.Type == "command" && matchMine(h.Command) {
				return i
			}
		}
	}
	return -1
}

// observerCodexCmdMatches reports whether g already encodes the observer
// hook entry shape we'd write — same matcher ("*"), single command of
// type "command", same command body. Drift in any of these fields means
// the entry is stale and registerCodex should refresh it.
func observerCodexCmdMatches(g codexHookGroup, cmd string) bool {
	if g.Matcher != "*" {
		return false
	}
	if len(g.Hooks) != 1 {
		return false
	}
	h := g.Hooks[0]
	return h.Type == "command" && h.Command == cmd
}

// hasConflictingCodexHook reports whether any group carries a
// command that isn't observer-shaped per matchMine (t.matchMine —
// see codexHookTarget's doc comment). Force-less guard against
// silently overwriting user-authored hooks (or, for the native
// target, an existing bridge entry — see isObserverCodexEntryNative).
// Content-heuristic — cross-binary stale entries fall through to the
// refresh path.
func hasConflictingCodexHook(groups []codexHookGroup, matchMine func(string) bool) bool {
	for _, g := range groups {
		for _, h := range g.Hooks {
			if h.Type != "command" {
				continue
			}
			if !matchMine(h.Command) {
				return true
			}
		}
	}
	return false
}

// onlyCodexBridgeConflicts reports whether every command matchMine does
// not own is Observer's own wsl.exe bridge entry (the codex-windows shape
// a WSL daemon writes). The native target still refuses those (B4: a
// native register must never silently replace the bridge, and adding
// beside it would capture every event twice); this only picks the
// refusal's wording (live proof 2026-10-21, where the generic
// "non-observer hook" read as if a foreign tool owned them).
func onlyCodexBridgeConflicts(groups []codexHookGroup, matchMine func(string) bool) bool {
	found := false
	for _, g := range groups {
		for _, h := range g.Hooks {
			if h.Type != "command" || matchMine(h.Command) {
				continue
			}
			if !isObserverCodexEntry(h.Command) || isObserverCodexEntryNative(h.Command) {
				return false
			}
			found = true
		}
	}
	return found
}

// codexBridgeConflictCommand is the removal a native `observer init
// --codex` names when Observer's WSL bridge entries hold the file: only
// Observer's hook entries go (MCP and the proxy route stay), and --force
// because the native install never recorded the checksum the WSL daemon
// did.
const codexBridgeConflictCommand = "observer uninstall --codex --skip-mcp --skip-proxy-route --force"

// codexBridgeConflictError is the refusal when the only entries in the way
// are Observer's own WSL bridge hooks.
func codexBridgeConflictError(prefix, event string) error {
	return safeErrorf("%s: event %s has Observer hooks that run through WSL (wsl.exe bridge, written by an Observer daemon in WSL); remove them first with `%s` (removes only Observer's hook entries) and re-run, or keep the WSL daemon, which already captures this Codex",
		prefix, event, codexBridgeConflictCommand)
}

// filterCodexGroups returns groups with all observer-owned entries
// (recognised via isObserverCodexEntry) stripped, plus counts
// (removed, kept) for the result struct. Content-heuristic so
// cross-binary stale entries are also cleaned up on uninstall —
// mirrors the register-side findCodexGroupWithObserver /
// hasConflictingCodexHook usage.
//
// mine is the uninstall's recogniser (isObserverCodexEntry under the FU-203
// judgement, removableEntry).
func filterCodexGroups(groups []codexHookGroup, mine func(string) bool) ([]codexHookGroup, int, int) {
	var out []codexHookGroup
	var removed, kept int
	for _, g := range groups {
		var keepHooks []claudeHookCommand
		for _, h := range g.Hooks {
			if h.Type == "command" && mine(h.Command) {
				removed++
				continue
			}
			keepHooks = append(keepHooks, h)
		}
		if len(keepHooks) == 0 {
			continue
		}
		kept += len(keepHooks)
		g.Hooks = keepHooks
		out = append(out, g)
	}
	return out, removed, kept
}

// ensureCodexHooksFeatureFlag patches `[features].hooks = true` into
// ~/.codex/config.toml if not already set. Codex gates the hook
// dispatcher behind this flag — without it, hooks.json is read but
// never invoked.
//
// **Verified flag name (2026-05-11):** codex 0.129.0 prints
// "`[features].codex_hooks` is deprecated. Use `[features].hooks`
// instead." when it sees the longer form. So `hooks = true` is the
// canonical name despite some published docs (e.g. the local
// reference at tmp/codex-hooks.md) showing `codex_hooks`. Observer's
// long-standing choice of `hooks = true` is correct.
//
// **Tool-context hook coverage caveat:** even with this flag set,
// codex's `PreToolUse` / `PostToolUse` hooks only intercept "simple
// Bash calls, apply_patch edits, and MCP tool calls" (per
// docs.codex.com hooks reference). Modern codex shell calls route
// through `unified_exec` which is NOT intercepted yet. Result:
// tool-using prompts produce JSONL rows but rarely emit hook rows.
// This is a codex design limitation, not an observer bug. See
// docs/codex-hook-capture.md for the maintainer's 2026-05-11
// dogfood notes.
// A method (not a free function) so it can take its own advisory lock
// on config.toml — a DIFFERENT file than the hooks.json lock
// registerCodex already holds for the rest of its body, so this is a
// second, independent lockSettings/unlock pair, not a re-entrant one.
func (r *Registry) ensureCodexHooksFeatureFlag(dir string) error {
	path := filepath.Join(dir, "config.toml")

	// Serialize observer's own writers of this file, THEN read — same
	// contract as every other settings/config writer since WP9
	// (lockSettings' docstring). config.toml previously took no lock
	// and wrote through a FIXED `<path>.tmp`, so two concurrent
	// `observer init --codex` runs could splice a torn config.toml.
	unlock, err := r.lockSettings(path)
	if err != nil {
		return fmt.Errorf("hook.ensureCodexHooksFeatureFlag: %w", err)
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6).
	pinned := pinWriteTarget(path)

	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("hook.ensureCodexHooksFeatureFlag: read: %w", err)
	}
	root := map[string]any{}
	if len(raw) > 0 {
		if err := toml.Unmarshal(raw, &root); err != nil {
			return fmt.Errorf("hook.ensureCodexHooksFeatureFlag: parse %s: %w", path, err)
		}
	}
	// D-268: config.toml can hold a literal bearer token, so for a row
	// carrying the credential-file exception the flag is set by a line
	// edit that keeps every other byte, verified, with the mode kept.
	if hooksShareCredentialFile("codex") {
		if v, ok := root["features"].(map[string]any); ok {
			if on, ok := v["hooks"].(bool); ok && on {
				return nil
			}
		}
		body, err := setTOMLFeaturesHooks(raw, root)
		if err != nil {
			return err
		}
		if err := atomicWriteFileMode(pinned, body, fileModeOr(pinned.target, 0o600)); err != nil {
			return fmt.Errorf("hook.ensureCodexHooksFeatureFlag: %w", err)
		}
		return nil
	}
	features, _ := root["features"].(map[string]any)
	if features == nil {
		features = map[string]any{}
	}
	if v, ok := features["hooks"].(bool); ok && v {
		return nil
	}
	features["hooks"] = true
	root["features"] = features

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(root); err != nil {
		return fmt.Errorf("hook.ensureCodexHooksFeatureFlag: encode: %w", err)
	}
	if err := atomicWriteFile(pinned, buf.Bytes()); err != nil {
		return fmt.Errorf("hook.ensureCodexHooksFeatureFlag: %w", err)
	}
	return nil
}

// CodexHookEvents returns the events the codex writer registers, in order:
// the list Codex asks the user to trust one by one via /hooks (U8, lane
// FIX-UPGRADE). Callers derive the trust count from it instead of a
// hard-coded number.
func CodexHookEvents() []string {
	return append([]string(nil), codexEvents...)
}
