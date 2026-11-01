package hook

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// cascadeHookEntry is one entry of Windsurf/Devin Desktop Cascade's
// hooks.json "pre_user_prompt" list (Part B item 2, phase-3a;
// live-fetched 2026-09-07, docs.devin.ai/desktop/cascade/hooks):
//
//	{"hooks":{"pre_user_prompt":[{"command":"…","powershell":"…"}]}}
//
// No matcher, no "type" field — a flat command list, the vendor's OWN
// shape distinct from every other hooks.json this repo writes.
// PowerShell is left empty in the native per-node user file; the
// devin-windows bridge (register_crossos_ide.go, surface-gap IDE-6) writes
// its portable command into both fields, and the administrator system file
// (managedhooks.go) carries a powershell command for Windows.
//
// B5: this type is now used ONLY to construct observer's OWN entry.
// A sibling entry already in the list — one this repo doesn't own,
// which may carry a documented field this struct doesn't model (e.g.
// a per-entry `timeout`) — is never decoded into it; see
// cascadeEntryProbe and readCascadeHooksFile below.
type cascadeHookEntry struct {
	Command    string `json:"command,omitempty"`
	PowerShell string `json:"powershell,omitempty"`
}

// cascadeHooksConfig describes hooks.json's body shape
// (`{"hooks": {<event>: [<entry>...]}}`) for callers (tests) that want
// a typed READ of the file this package wrote. It is never used to
// decode a file this package is about to re-write — see
// readCascadeHooksFile.
type cascadeHooksConfig struct {
	Hooks map[string][]cascadeHookEntry `json:"hooks"`
}

// cascadeEntryProbe decodes just the "command" field from an
// otherwise-opaque raw Cascade hook entry — enough for
// isObserverAnyHookEntry to tell whether the entry is observer's own,
// without decoding (and thereby truncating) any other field the entry
// carries.
type cascadeEntryProbe struct {
	Command string `json:"command"`
}

// readCascadeHooksFile reads hooks.json's top-level object and its
// "hooks" subtree with the RawMessage boundary pushed one level deeper
// than a single map[string]json.RawMessage (B5): top holds every
// top-level key verbatim (so a key beside "hooks" that Cascade itself
// — or a human — wrote round-trips byte-for-byte), and hooksByEvent
// holds, per event, the list of RAW hook entries (so an event beside
// "pre_user_prompt", and any entry within an event's list this repo
// doesn't own, both round-trip byte-for-byte too — decodePoolsideHooksRaw
// and registerClaudeCode's hooksRaw use the identical shape of fix for
// their own file formats). A missing or empty file yields empty maps
// and no error, matching every other readSettingsFile-style helper in
// this package.
func readCascadeHooksFile(path string) (map[string]json.RawMessage, map[string][]json.RawMessage, error) {
	hooksByEvent := map[string][]json.RawMessage{}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]json.RawMessage{}, hooksByEvent, nil
		}
		return nil, nil, fmt.Errorf("hook.readCascadeHooksFile: read: %w", err)
	}
	if len(raw) == 0 {
		return map[string]json.RawMessage{}, hooksByEvent, nil
	}
	top, err := decodeSettingsObject(path, raw)
	if err != nil {
		return nil, nil, fmt.Errorf("hook.readCascadeHooksFile: %w", err)
	}
	if hRaw, ok := top["hooks"]; ok && len(hRaw) > 0 {
		if err := json.Unmarshal(hRaw, &hooksByEvent); err != nil {
			return nil, nil, fmt.Errorf("hook.readCascadeHooksFile: parse hooks: %w", err)
		}
		if hooksByEvent == nil {
			hooksByEvent = map[string][]json.RawMessage{}
		}
	}
	return top, hooksByEvent, nil
}

// cascadeEvents are the events Observer registers in Cascade's hooks.json:
// the prompt gate (Part B) and the four per-action pre hooks that make up
// the tool gate (hook-parity Lane A5; exit code 2 blocks, stderr is the
// reason shown to the developer). Equal to the registry row's Registered
// bindings (event_lists golden).
var cascadeEvents = []string{"pre_user_prompt", "pre_run_command", "pre_write_code", "pre_read_code", "pre_mcp_tool_use"}

// cascadeTarget is one Cascade hooks.json Observer writes: the native
// Devin Desktop file, the JetBrains plugin's file (devin-jetbrains) or the
// Windows-side Devin Desktop file a WSL daemon bridges (devin-windows).
type cascadeTarget struct {
	// label is the RegistrationResult.Tool.
	label string
	// dir holds hooks.json.
	dir string
	// command builds Observer's command for event.
	command func(event string) string
	// powershell also writes the command as the entry's "powershell" field
	// (a Windows host; the portable bridge runs under PowerShell too).
	powershell bool
	// managed applies this host's administrator hooks file (the native
	// Devin Desktop file only: the system file is merged with that one).
	managed bool
	// errPrefix names the registrar in wrapped errors.
	errPrefix string
}

// nativeCascadeTarget is ~/.codeium/windsurf/hooks.json on the daemon's OS.
func (r *Registry) nativeCascadeTarget() cascadeTarget {
	return cascadeTarget{
		label: "devin", dir: filepath.Join(r.opts.HomeDir, ".codeium", "windsurf"),
		command:   r.nativeCascadeCommand,
		managed:   true,
		errPrefix: "hook.registerCascade",
	}
}

// nativeCascadeCommand is the daemon-OS command for event.
func (r *Registry) nativeCascadeCommand(event string) string {
	return shellQuoteIfNeeded(forwardSlashPath(r.opts.BinaryPath)) + " hook devin " + event + r.configFlagSuffixForwardSlash()
}

// registerCascade installs Observer's hooks into
// ~/.codeium/windsurf/hooks.json, one entry per cascadeEvents event (Part B
// item 2, phase-3a: the HookCascadeJSON mechanism).
func (r *Registry) registerCascade() RegistrationResult {
	return r.registerCascadeAt(r.nativeCascadeTarget())
}

// registerCascadeAt writes Observer's entries into t's hooks.json.
func (r *Registry) registerCascadeAt(t cascadeTarget) RegistrationResult {
	res := RegistrationResult{Tool: t.label, DryRun: r.opts.DryRun}
	dir := t.dir
	path := filepath.Join(dir, "hooks.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
		return res
	}
	defer unlock()

	pinned := pinWriteTarget(path)

	top, hooksByEvent, err := readCascadeHooksFile(path)
	if err != nil {
		res.Error = err
		return res
	}
	// FU-192: an entry in Observer's shape running another binary is kept.
	if r.refusesForeignBinaryInFile(&res, t.errPrefix, path, "devin", identityContent) {
		return res
	}

	// IDE-6 managed row: Cascade merges the system hooks.json with this
	// file, so an event the administrator file already runs Observer's hook
	// for is not registered here a second time, and Observer's own earlier
	// per-node entry for it is removed (a non-Observer entry stays).
	plan := managedHooksPlan{register: cascadeEvents}
	if t.managed {
		plan = r.managedHooksPlanFor("devin", cascadeEvents)
	}
	res.Warnings = append(res.Warnings, plan.warnings...)
	res.HooksDropped = dropCascadeObserverEntries(hooksByEvent, plan.drop)
	if plan.complete && len(res.HooksDropped) == 0 {
		return plan.finish(res)
	}
	events := plan.register

	for _, event := range events {
		if r.skipEvent("devin", event) {
			continue
		}
		if err := r.cascadeRegisterEvent(t, &res, hooksByEvent, event); err != nil {
			res.Error = err
			return res
		}
	}
	if len(res.HooksAdded) == 0 && len(res.HooksDropped) == 0 {
		return plan.finish(res)
	}

	hooksJSON, err := json.Marshal(hooksByEvent)
	if err != nil {
		res.Error = fmt.Errorf("%s: marshal hooks: %w", t.errPrefix, err)
		return res
	}
	top["hooks"] = hooksJSON

	if r.opts.DryRun {
		return plan.finish(res)
	}
	if err := writeJSONIndented(dir, pinned, top); err != nil {
		res.Error = err
		return res
	}
	if err := r.recordChecksum(res.Tool, path); err != nil {
		res.Error = err
		return res
	}
	return plan.finish(res)
}

// cascadePowerShellMatches reports whether entry's "powershell" field is
// what the target writes: cmd when it writes one, absent otherwise.
func cascadePowerShellMatches(entry json.RawMessage, want bool, cmd string) bool {
	var probe struct {
		PowerShell string `json:"powershell"`
	}
	if json.Unmarshal(entry, &probe) != nil {
		return false
	}
	if want {
		return probe.PowerShell == cmd
	}
	return probe.PowerShell == ""
}

// dropCascadeObserverEntries removes Observer's own entries for events from
// hooksByEvent (raw entries, so a sibling keeps every field) and returns the
// events it changed. A non-Observer entry is never removed.
func dropCascadeObserverEntries(hooksByEvent map[string][]json.RawMessage, events []string) []string {
	var dropped []string
	for _, ev := range events {
		var kept []json.RawMessage
		for _, raw := range hooksByEvent[ev] {
			var probe cascadeEntryProbe
			if json.Unmarshal(raw, &probe) == nil && isObserverAnyHookEntry(probe.Command, "devin") {
				continue
			}
			kept = append(kept, raw)
		}
		if len(kept) == len(hooksByEvent[ev]) {
			continue
		}
		dropped = append(dropped, ev)
		if len(kept) == 0 {
			delete(hooksByEvent, ev)
		} else {
			hooksByEvent[ev] = kept
		}
	}
	return dropped
}

// unregisterCascade removes ONLY the observer-owned pre_user_prompt
// entry from ~/.codeium/windsurf/hooks.json, leaving every other
// top-level key, every other event, and every sibling entry in
// pre_user_prompt's own list byte-for-byte untouched.
func (r *Registry) unregisterCascade() UnregistrationResult {
	return r.unregisterCascadeAt("devin", filepath.Join(r.opts.HomeDir, ".codeium", "windsurf"))
}

// unregisterCascadeAt removes Observer's entries from dir/hooks.json.
func (r *Registry) unregisterCascadeAt(label, dir string) UnregistrationResult {
	res := UnregistrationResult{Tool: label, DryRun: r.opts.DryRun}
	path := filepath.Join(dir, "hooks.json")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterCascade: %w", err)
		return res
	}
	defer unlock()

	pinned := pinWriteTarget(path)

	top, hooksByEvent, err := readCascadeHooksFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return res
		}
		res.Error = err
		return res
	}
	for _, event := range cascadeEvents {
		entries := hooksByEvent[event]
		var kept []json.RawMessage
		removed := false
		for _, raw := range entries {
			var probe cascadeEntryProbe
			if err := json.Unmarshal(raw, &probe); err == nil && isObserverAnyHookEntry(probe.Command, "devin") {
				removed = true
				continue
			}
			kept = append(kept, raw)
		}
		if !removed {
			continue
		}
		if len(kept) == 0 {
			delete(hooksByEvent, event)
		} else {
			hooksByEvent[event] = kept
		}
		res.HooksRemoved = append(res.HooksRemoved, event)
	}
	if len(res.HooksRemoved) == 0 {
		return res
	}

	if len(hooksByEvent) == 0 {
		delete(top, "hooks")
	} else {
		hooksJSON, err := json.Marshal(hooksByEvent)
		if err != nil {
			res.Error = fmt.Errorf("hook.unregisterCascade: marshal hooks: %w", err)
			return res
		}
		top["hooks"] = hooksJSON
	}

	if r.opts.DryRun {
		return res
	}
	if err := writeJSONIndented(dir, pinned, top); err != nil {
		res.Error = err
		return res
	}
	if err := r.removeChecksum(path); err != nil {
		res.Error = err
		return res
	}
	return res
}

// cascadeRegisterEvent adds Observer's entry for one event to hooksByEvent
// (or records it as already set), keeping every non-Observer entry. Split
// out of registerCascadeAt to keep that function's branching readable.
func (r *Registry) cascadeRegisterEvent(t cascadeTarget, res *RegistrationResult, hooksByEvent map[string][]json.RawMessage, event string) error {
	cmd := t.command(event)
	entries := hooksByEvent[event]
	idx := -1
	for i, raw := range entries {
		var probe cascadeEntryProbe
		if err := json.Unmarshal(raw, &probe); err != nil {
			continue
		}
		if isObserverAnyHookEntry(probe.Command, "devin") {
			idx = i
		}
	}
	if idx >= 0 {
		// T-847: an extra field on Observer's entry is never "already
		// set" (hook_shape.go).
		shape := flatCommandEntries(func(c string) bool { return isObserverAnyHookEntry(c, "devin") })
		if t.powershell {
			shape.handlerFields = map[string]bool{"command": true, "powershell": true}
		}
		drift := entriesShapeDrift(entries[idx:idx+1], shape)
		if drift {
			shapeRewrite(res, event, cmd, cmd)
		}
		var probe cascadeEntryProbe
		if err := json.Unmarshal(entries[idx], &probe); err == nil && probe.Command == cmd && !drift && cascadePowerShellMatches(entries[idx], t.powershell, cmd) {
			res.AlreadySet = append(res.AlreadySet, event)
			return nil
		}
		entries = append(entries[:idx:idx], entries[idx+1:]...)
	}
	if r.refuses(res.ConfigPath, identityContent) {
		for _, raw := range entries {
			var probe cascadeEntryProbe
			if err := json.Unmarshal(raw, &probe); err != nil {
				continue
			}
			if !isObserverAnyHookEntry(probe.Command, "devin") {
				return fmt.Errorf("%s: event %s already has a non-observer hook; pass --force to overwrite", t.errPrefix, event)
			}
		}
	}
	entry := cascadeHookEntry{Command: cmd}
	if t.powershell {
		entry.PowerShell = cmd
	}
	entryJSON, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("%s: marshal entry: %w", t.errPrefix, err)
	}
	hooksByEvent[event] = append(entries, entryJSON)
	res.HooksAdded = append(res.HooksAdded, event)
	return nil
}
