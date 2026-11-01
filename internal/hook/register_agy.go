package hook

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Antigravity (`agy` CLI, the desktop app and the IDE) hook registration
// (HookAntigravityJSON). Grounding: the hooks reference embedded in agy
// 1.2.16 (read on demo node 1, 2026-10-03) and antigravity.google/docs/hooks
// (fetched 2026-10-02). The global file is ~/.gemini/config/hooks.json, a
// JSON object that maps HOOK NAMES to event configurations. Tool events
// (PreToolUse, PostToolUse) take matcher groups; the other events take a
// flat handler list:
//
//	{"<name>": {"enabled": true,
//	            "PreToolUse": [{"matcher": "*",
//	                            "hooks": [{"type": "command", "command": "...", "timeout": 30}]}]}}
//
// Observer owns exactly one hook name, agyObserverHookName; every other
// top-level key round-trips byte for byte. It registers PreToolUse, the
// tool gate (hook-parity Lane A6), and PreInvocation, the pre-model-call
// prompt seam (warns, and blocks by aborting the turn since the 2026-10-15
// guard-enforcement fix). Both handlers carry a 30 s timeout; Observer's
// own hook watchdog answers below it. PreInvocation was retired on 2026-10-03 (agy 1.2.16: the transcript
// held the prompt only after the model replied) and restored by T-476: on
// agy 1.3.0 (demo node 1, 2026-10-06) the payload's transcript already
// holds the USER_INPUT step at invocationNum 0, and the injected
// ephemeralMessage reached the model's first agent request.

// agyObserverHookName is the hooks.json key observer owns.
const agyObserverHookName = "superbased-observer"

// agyToolGateTimeoutSeconds is the PreToolUse handler timeout (agy's
// default, stated explicitly so the binding's host timeout is the one in
// force).
const agyToolGateTimeoutSeconds = 30

// agyEvents are the events Observer registers (the registry row's
// Registered bindings, pinned by the hook-parity event_lists golden).
var agyEvents = []string{"PreToolUse", "PreInvocation"}

// agyGroupedEvents are the events whose entries are matcher groups.
var agyGroupedEvents = map[string]bool{"PreToolUse": true, "PostToolUse": true}

type agyHookHandler struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}

type agyHookGroup struct {
	Matcher string           `json:"matcher"`
	Hooks   []agyHookHandler `json:"hooks"`
}

// agyHookFileReaderDirs are the ~/.gemini data directories of the products
// that run ~/.gemini/config/hooks.json, each an install signal for the
// antigravity-cli target (Registry.Installed): the vendor's app_data_dir of
// the CLI, the Antigravity App and the Antigravity IDE
// (https://antigravity.google/docs/hooks?tab=ide, fetched 2026-10-26;
// surface-gap W-2c). The App's directory is also the antigravity adapter's
// desktop capture root. ~/.gemini/antigravity-acp (the JetBrains ACP agent)
// is not here: nothing grounds it running the file.
var agyHookFileReaderDirs = []string{"antigravity-cli", "antigravity", "antigravity-ide"}

// agyHooksDirUnder is the directory of .gemini/config/hooks.json under home
// for goos, from the catalogue (antigravity-cli/user-hooks).
func agyHooksDirUnder(home, goos string) string {
	return filepath.Join(home, artifactSubdir("antigravity-cli/user-hooks", goos))
}

// agyGeminiSubdir is the Gemini home under a user home for goos (the hooks
// file's grandparent), "" when the artifact does not resolve.
func agyGeminiSubdir(goos string) string {
	sub := artifactSubdir("antigravity-cli/user-hooks", goos)
	if sub == "" {
		return ""
	}
	return filepath.Dir(sub)
}

// readAgyHooksFile reads the hooks.json top-level object; a missing or
// empty file is an empty object.
func readAgyHooksFile(path string) (map[string]json.RawMessage, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]json.RawMessage{}, nil
		}
		return nil, fmt.Errorf("hook.readAgyHooksFile: read: %w", err)
	}
	if len(raw) == 0 {
		return map[string]json.RawMessage{}, nil
	}
	top, err := decodeSettingsObject(path, raw)
	if err != nil {
		return nil, fmt.Errorf("hook.readAgyHooksFile: %w", err)
	}
	return top, nil
}

// agyEventHandlers returns the handlers an event value holds, grouped
// (matcher groups) or flat; ok=false for a value of neither shape.
func agyEventHandlers(event string, val json.RawMessage) ([]agyHookHandler, bool) {
	if agyGroupedEvents[event] {
		var groups []agyHookGroup
		if err := json.Unmarshal(val, &groups); err != nil {
			return nil, false
		}
		var out []agyHookHandler
		for _, g := range groups {
			out = append(out, g.Hooks...)
		}
		return out, true
	}
	var hs []agyHookHandler
	if err := json.Unmarshal(val, &hs); err != nil {
		return nil, false
	}
	return hs, true
}

// agyEntryIsObservers reports whether a hooks.json value under
// agyObserverHookName is positively observer's: an object whose only keys
// are "enabled" and event lists (matcher groups for tool events, flat
// handlers otherwise), holding at least one handler, every handler a
// command that invokes an observer binary as `hook antigravity-cli`
// (isObserverAnyHookEntry). Anything else, including an unparseable value,
// is the user's (Sol A2-09).
func agyEntryIsObservers(raw json.RawMessage) bool {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return false
	}
	handlers := 0
	for key, val := range obj {
		if key == "enabled" {
			continue
		}
		hs, ok := agyEventHandlers(key, val)
		if !ok {
			return false
		}
		for _, h := range hs {
			if h.Type != "command" || !isObserverAnyHookEntry(h.Command, "antigravity-cli") {
				return false
			}
			handlers++
		}
	}
	return handlers > 0
}

// agyTarget is one ~/.gemini/config/hooks.json Observer writes: the
// daemon OS's own, or a Windows-side one a WSL daemon bridges
// (antigravity-cli-windows, surface-gap IDE-10).
type agyTarget struct {
	label string
	// goos is the OS whose layout the hooks file follows under home.
	goos string
	// home is the user home holding .gemini/config/hooks.json.
	home string
	// command builds Observer's command for event.
	command func(event string) string
}

// nativeAgyTarget is the daemon OS's own hooks file.
func (r *Registry) nativeAgyTarget() agyTarget {
	return agyTarget{label: "antigravity-cli", home: r.opts.HomeDir, goos: r.hostGOOS(), command: r.nativeAgyCommand}
}

// nativeAgyCommand is the daemon-OS command for event.
func (r *Registry) nativeAgyCommand(event string) string {
	return shellQuoteIfNeeded(forwardSlashPath(r.opts.BinaryPath)) + " hook antigravity-cli " + event + r.configFlagSuffixForwardSlash()
}

// agyObserverDefWith is the value Observer writes under agyObserverHookName
// for the events it registers (skip filters events `observer start` holds
// back), each handler running command(event).
func agyObserverDefWith(skip func(string) bool, command func(string) string) (map[string]any, []string) {
	def := map[string]any{"enabled": true}
	var events []string
	for _, event := range agyEvents {
		if skip(event) {
			continue
		}
		cmd := command(event)
		h := agyHookHandler{Type: "command", Command: cmd, Timeout: agyToolGateTimeoutSeconds}
		if agyGroupedEvents[event] {
			def[event] = []agyHookGroup{{Matcher: "*", Hooks: []agyHookHandler{h}}}
		} else {
			def[event] = []agyHookHandler{h}
		}
		events = append(events, event)
	}
	return def, events
}

// registerAntigravityCLI installs observer's hook name into
// ~/.gemini/config/hooks.json.
func (r *Registry) registerAntigravityCLI() RegistrationResult {
	return r.registerAgyAt(r.nativeAgyTarget())
}

// registerAgyAt installs observer's hook name into t's hooks.json.
func (r *Registry) registerAgyAt(t agyTarget) RegistrationResult {
	res := RegistrationResult{Tool: t.label, DryRun: r.opts.DryRun}
	dir := agyHooksDirUnder(t.home, t.goos)
	path := filepath.Join(dir, "hooks.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerAntigravityCLI: %w", err)
		return res
	}
	defer unlock()
	pinned := pinWriteTarget(path)

	top, err := readAgyHooksFile(path)
	if err != nil {
		res.Error = err
		return res
	}
	// FU-192: an entry in Observer's shape running another binary is kept
	// (the entry name is Observer's own).
	if r.refusesForeignBinaryInFile(&res, "hook.registerAntigravityCLI", path, "antigravity-cli", identityOwnedName) {
		return res
	}
	want, events := agyObserverDefWith(func(e string) bool { return r.skipEvent(t.label, e) }, t.command)
	if len(events) == 0 {
		return res
	}
	defJSON, err := json.Marshal(want)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerAntigravityCLI: marshal: %w", err)
		return res
	}
	foreign, repair := false, false
	if cur, ok := top[agyObserverHookName]; ok {
		if jsonEqual(cur, defJSON) {
			res.AlreadySet = append(res.AlreadySet, events...)
			return res
		}
		// Sol A2-09: the key is occupied by something other than the
		// exact desired entry. Refresh it only when it is positively
		// observer's own (a stale command or timeout, or the retired
		// PreInvocation entry); anything else is a conflict without
		// --force, except on a managed repair pass when Observer installed
		// this hook name before (T-872: the name is Observer's own,
		// identityOwnedName, so a stubbed entry under it is a neutralised
		// Observer hook, not the user's).
		if !agyEntryIsObservers(cur) {
			switch r.resolveConflict(path, identityOwnedName) {
			case conflictRefuse:
				res.Error = fmt.Errorf("hook.registerAntigravityCLI: %s already has a non-observer hook named %q; pass --force to overwrite", path, agyObserverHookName)
				return res
			case conflictRepair:
				repair = true
			}
			foreign = true
		}
	}
	top[agyObserverHookName] = defJSON
	res.HooksAdded = append(res.HooksAdded, events...)
	if r.opts.DryRun {
		return res
	}
	if foreign {
		// --force over a user's entry, or a managed repair of Observer's
		// neutralised one: keep the pre-overwrite file recoverable (the
		// writeYAMLMap / Command Code takeover discipline; a repair keeps
		// a displaced copy, T-884).
		if raw, rerr := os.ReadFile(path); rerr == nil {
			if err := keepReplacedBytes(&res, path, raw, repair); err != nil {
				res.Error = fmt.Errorf("hook.registerAntigravityCLI: %w", err)
				return res
			}
		}
	}
	if err := writeJSONIndented(dir, pinned, top); err != nil {
		res.Error = err
		return res
	}
	if err := r.recordChecksum(res.Tool, path); err != nil {
		res.Error = err
		return res
	}
	if repair {
		noteOwnedRepair(&res, path, events)
	}
	return res
}

// unregisterAntigravityCLI removes ONLY observer's hook name from
// ~/.gemini/config/hooks.json.
func (r *Registry) unregisterAntigravityCLI() UnregistrationResult {
	return r.unregisterAgyAt("antigravity-cli", r.opts.HomeDir, r.hostGOOS())
}

// unregisterAgyAt removes observer's hook name from home's hooks.json (the
// layout of goos).
func (r *Registry) unregisterAgyAt(label, home, goos string) UnregistrationResult {
	res := UnregistrationResult{Tool: label, DryRun: r.opts.DryRun}
	dir := agyHooksDirUnder(home, goos)
	path := filepath.Join(dir, "hooks.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterAntigravityCLI: %w", err)
		return res
	}
	defer unlock()
	pinned := pinWriteTarget(path)

	top, err := readAgyHooksFile(path)
	if err != nil {
		res.Error = err
		return res
	}
	cur, ok := top[agyObserverHookName]
	if !ok {
		return res
	}
	events := agyEntryEvents(cur)
	if !agyEntryIsObservers(cur) {
		// Sol A2-09: a user's entry under the same name is never ours to
		// delete.
		res.HooksKept = append(res.HooksKept, events...)
		return res
	}
	delete(top, agyObserverHookName)
	res.HooksRemoved = append(res.HooksRemoved, events...)
	if r.opts.DryRun {
		return res
	}
	if err := writeJSONIndented(dir, pinned, top); err != nil {
		res.Error = err
		return res
	}
	if err := r.removeChecksum(path); err != nil {
		res.Error = err
	}
	return res
}

// agyEntryEvents lists the event keys of a hook-name value, sorted.
func agyEntryEvents(raw json.RawMessage) []string {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return nil
	}
	var events []string
	for _, e := range []string{"PreToolUse", "PostToolUse", "PreInvocation", "PostInvocation", "Stop"} {
		if _, ok := obj[e]; ok {
			events = append(events, e)
		}
	}
	return events
}

// agyInstalled reports the install signals of the shared Antigravity hooks
// file: a data directory of a product that reads it (agyHookFileReaderDirs)
// or the file's own directory, resolved from the catalogued artifact so a
// pinned home and the vendor's relocation hold (WINNODE2 item 5b).
func (r *Registry) agyInstalled() bool {
	return r.anyGeminiDirExists(agyHookFileReaderDirs) || r.homeArtifactExists("antigravity-cli")
}
