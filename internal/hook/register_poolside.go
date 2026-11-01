package hook

import (
	"fmt"
	"path/filepath"
)

// poolsideHookEntry is one entry of Poolside's settings.yaml "hooks"
// list (Part B item 2, phase-3a; live-fetched 2026-09-07,
// docs.poolside.ai/hooks):
//
//	hooks:
//	  UserPromptSubmit:
//	    - name: hook-name
//	      matcher: "*"
//	      command: "/path/to/script.sh"
//	      timeout: 60
//
// matcher is documented as required for every event ("Provide this
// field for every event... other events ignore it, so use
// matcher: \"*\"") even though UserPromptSubmit itself doesn't
// consult it.
//
// B5: this type is now used ONLY to construct observer's OWN entry
// when appending it to the (otherwise raw, generic
// map[string]any-decoded) entries list — see decodePoolsideHooksRaw
// and poolsideEntryCommand below. A sibling entry already in the list
// is never decoded into this struct, so an undocumented-to-us field
// on it (e.g. `timeout`) is never routed through — and truncated by —
// a typed decode/re-encode round-trip.
type poolsideHookEntry struct {
	Name    string `yaml:"name"`
	Matcher string `yaml:"matcher"`
	Command string `yaml:"command"`
}

const observerPoolsideHookName = "observer-guard"

// poolsideEvents are the events Observer registers in settings.yaml: the
// prompt gate (Part B) and the PreToolUse tool gate (hook-parity Lane A4).
// Equal to the registry row's Registered bindings (event_lists golden).
var poolsideEvents = []string{"UserPromptSubmit", "PreToolUse"}

// poolsideHookTarget parameterizes registerPoolsideAt for its two
// registration targets: the native `~/.config/poolside` on the
// daemon's own OS, and the cross-OS Windows-side directory the
// poolside-windows bridge writes. Mirrors codexHookTarget/
// droidHookTarget.
type poolsideHookTarget struct {
	// tool is the RegistrationResult.Tool label ("poolside" /
	// "poolside-windows").
	tool string
	// dir is the directory holding settings.yaml.
	dir string
	// wrapper prefixes every registered command; "" for the native
	// target, `MSYS_NO_PATHCONV=1 wsl.exe -d <distro> -- ` for the
	// cross-OS bridge.
	wrapper string
	// errPrefix names the calling registrar in wrapped errors.
	errPrefix string
}

// registerPoolside installs the prompt-submit hook into
// ~/.config/poolside/settings.yaml's "hooks" block (Part B item 2,
// phase-3a: new HookPoolsideYAML mechanism — this repo's FIRST
// YAML-format hook registration writer, distinct from every
// JSON-format settings/hooks.json writer above). Reuses the
// readYAMLMap/writeYAMLMap helpers already built for Hermes'
// config.yaml (internal/hook/hermes_mcp.go) UNCHANGED — the lock/pin/
// checksum hardening below (F8, phase-3a review) wraps the CALL SITE,
// the same way every JSON writer's own lock/pin/checksum trio wraps
// writeJSONIndented rather than living inside it.
//
// F8's second finding: this doc comment used to claim the round-trip
// preserves "everything else... untouched". That overstates what a
// generic map[string]any -> yaml.Marshal round-trip actually
// guarantees — writeYAMLMap's OWN doc comment is honest about this
// ("yaml.v3's map round-trip loses comments and key order"; that is
// why it backs up to path+".bak" first). What genuinely IS preserved
// here is every other top-level KEY'S VALUE (e.g. pool.api_url) — this
// function only mutates the "hooks" subtree before handing the whole
// map back to writeYAMLMap — but the file's original comments,
// blank-line layout, and key ORDER are NOT preserved; the operator's
// settings.yaml is re-serialized by the YAML library on every write,
// same as it always has been for Hermes' config.yaml.
func (r *Registry) registerPoolside() RegistrationResult {
	return r.registerPoolsideAt(poolsideHookTarget{
		tool:      "poolside",
		dir:       filepath.Join(r.opts.HomeDir, ".config", "poolside"),
		errPrefix: "hook.registerPoolside",
	})
}

// registerPoolsideAt is the shared settings.yaml writer behind
// registerPoolside and registerPoolsideWindows. Conflict/refresh
// discipline mirrors registerGenericSettingsHooks: an entry
// isObserverAnyHookEntry recognises as ours is refreshed silently on
// drift; anything else blocks without --force.
//
// F8 (phase-3a review): this writer was missing the three hardening
// steps every JSON settings writer above already has —
// r.lockSettings (cross-process advisory lock, serializes concurrent
// observer writers against each other), pinWriteTarget (resolves a
// symlink write target ONCE, right after the lock, before the first
// read — a TOCTOU guard against the target being retargeted mid-write;
// see pinnedTarget's doc comment), and r.recordChecksum (lets
// `observer doctor`/uninstall detect drift). writeYAMLMap itself is
// NOT modified — it takes a plain path exactly like before; this
// function now passes pinned.target (the resolved target, == path
// when not a symlink) instead of the raw path, and calls
// pinned.verifyUnmoved() immediately before the write exactly as
// writeJSONIndented's own pinned-target contract requires.
func (r *Registry) registerPoolsideAt(t poolsideHookTarget) RegistrationResult {
	res := RegistrationResult{Tool: t.tool, DryRun: r.opts.DryRun}
	path := filepath.Join(t.dir, "settings.yaml")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
		return res
	}
	defer unlock()

	// Pin the write target now, before the read — see pinnedTarget (F6),
	// and F8's doc comment above for why registerPoolsideAt needed this.
	pinned := pinWriteTarget(path)

	doc, err := readYAMLMap(pinned.target)
	if err != nil {
		res.Error = fmt.Errorf("%s: read: %w", t.errPrefix, err)
		return res
	}

	// FU-192: an entry in Observer's shape running another binary is kept.
	if r.refusesForeignBinaryInFile(&res, t.errPrefix, pinned.target, "poolside", identityContent) {
		return res
	}
	hooks := decodePoolsideHooksRaw(doc)

	binPath := forwardSlashPath(r.opts.BinaryPath)
	var repaired []string
	for _, event := range poolsideEvents {
		if r.skipEvent("poolside", event) {
			continue
		}
		cmd := t.wrapper + shellQuoteIfNeeded(binPath) + " hook poolside " + event + r.configFlagSuffixForwardSlash()
		entries := hooks[event]
		idx := -1
		for i, e := range entries {
			if isObserverAnyHookEntry(poolsideEntryCommand(e), "poolside") {
				idx = i
			}
		}
		if idx >= 0 {
			// T-847: the entry is "already set" only in the exact shape
			// this writer emits (name, a "*" matcher, the command).
			if !poolsideEntryCanonical(entries[idx]) {
				shapeRewrite(&res, event, cmd, cmd)
			} else if poolsideEntryCommand(entries[idx]) == cmd {
				res.AlreadySet = append(res.AlreadySet, event)
				continue
			}
			entries = append(entries[:idx:idx], entries[idx+1:]...)
		}
		// T-872: on a managed repair pass an entry under Observer's own
		// name that no longer runs observer is a neutralised Observer hook
		// (identityOwnedName) and is replaced; any other non-observer
		// entry is the user's (identityContent).
		if kept, dropped := r.dropNeutralisedPoolside(path, entries); dropped {
			entries = kept
			repaired = append(repaired, event)
		}
		if r.refuses(path, identityContent) {
			for _, e := range entries {
				if !isObserverAnyHookEntry(poolsideEntryCommand(e), "poolside") {
					res.Error = safeErrorf("%s: %s already has a non-observer hook; pass --force to overwrite", t.errPrefix, event)
					return res
				}
			}
		}
		hooks[event] = append(entries, poolsideHookEntry{Name: observerPoolsideHookName, Matcher: "*", Command: cmd})
		res.HooksAdded = append(res.HooksAdded, event)
	}
	if len(res.HooksAdded) == 0 {
		return res
	}
	doc["hooks"] = hooks

	if r.opts.DryRun {
		return res
	}
	if err := r.writeHookSettingsYAML(t.tool, pinned, doc); err != nil {
		res.Error = fmt.Errorf("%s: write: %w", t.errPrefix, err)
		return res
	}
	if err := r.recordHookChecksum(t.tool, path); err != nil {
		res.Error = err
		return res
	}
	noteOwnedRepair(&res, path, repaired)
	return res
}

// dropNeutralisedPoolside removes, on a managed repair pass, every entry
// under Observer's own hook name whose command is not observer's (T-872).
// dropped is false, and entries untouched, when there is none or the
// conflict rules do not repair here.
func (r *Registry) dropNeutralisedPoolside(path string, entries []any) (kept []any, dropped bool) {
	var neutralised []int
	for i, e := range entries {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if name, _ := m["name"].(string); name == observerPoolsideHookName && !isObserverAnyHookEntry(poolsideEntryCommand(e), "poolside") {
			neutralised = append(neutralised, i)
		}
	}
	if len(neutralised) == 0 || r.resolveConflict(path, identityOwnedName) != conflictRepair {
		return entries, false
	}
	kept = make([]any, 0, len(entries))
	skip := map[int]bool{}
	for _, i := range neutralised {
		skip[i] = true
	}
	for i, e := range entries {
		if !skip[i] {
			kept = append(kept, e)
		}
	}
	return kept, true
}

// unregisterPoolside removes ONLY the observer-owned UserPromptSubmit
// entry from settings.yaml's "hooks" block, leaving every other key
// and every other event's entries untouched.
func (r *Registry) unregisterPoolside() UnregistrationResult {
	return r.unregisterPoolsideAt("poolside", filepath.Join(r.opts.HomeDir, ".config", "poolside"), "hook.unregisterPoolside")
}

// unregisterPoolsideAt is the shared settings.yaml cleaner behind
// unregisterPoolside and unregisterPoolsideWindows. F8 (phase-3a
// review): carries the SAME lock/pin/checksum hardening as
// registerPoolsideAt — see that function's doc comment — mirroring
// how every JSON unregister writer (e.g. unregisterGenericSettingsHooks)
// hardens its removal path identically to its own registration path.
func (r *Registry) unregisterPoolsideAt(tool, dir, errPrefix string) UnregistrationResult {
	res := UnregistrationResult{Tool: tool, DryRun: r.opts.DryRun}
	path := filepath.Join(dir, "settings.yaml")
	res.ConfigPath = path

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", errPrefix, err)
		return res
	}
	defer unlock()

	pinned := pinWriteTarget(path)

	doc, err := readYAMLMap(pinned.target)
	if err != nil {
		res.Error = fmt.Errorf("%s: read: %w", errPrefix, err)
		return res
	}
	hooks := decodePoolsideHooksRaw(doc)
	for _, event := range poolsideEvents {
		entries := hooks[event]
		var kept []any
		removed := false
		for _, e := range entries {
			if isObserverAnyHookEntry(poolsideEntryCommand(e), "poolside") {
				removed = true
				continue
			}
			kept = append(kept, e)
		}
		if !removed {
			continue
		}
		if len(kept) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = kept
		}
		res.HooksRemoved = append(res.HooksRemoved, event)
	}
	if len(res.HooksRemoved) == 0 {
		return res
	}
	if len(hooks) == 0 {
		delete(doc, "hooks")
	} else {
		doc["hooks"] = hooks
	}

	if r.opts.DryRun {
		return res
	}
	if err := r.writeHookSettingsYAML(tool, pinned, doc); err != nil {
		res.Error = fmt.Errorf("%s: write: %w", errPrefix, err)
		return res
	}
	if err := r.removeChecksum(path); err != nil {
		res.Error = err
		return res
	}
	return res
}

// decodePoolsideHooksRaw pulls doc["hooks"] apart into per-event RAW
// entry lists (B5) — unlike the typed decodePoolsideHooks this
// replaced, entries are never routed through poolsideHookEntry, so an
// entry this repo doesn't own keeps every field it was read with
// (e.g. the vendor's documented per-entry `timeout`) instead of being
// silently truncated to {name, matcher, command} on the next write.
// readYAMLMap already decoded the whole document generically (every
// map as map[string]any, every sequence as []any), so doc["hooks"] is
// already exactly that shape — no re-marshal/re-decode round-trip is
// needed to get raw per-entry values the way readCascadeHooksFile's
// JSON equivalent needs json.RawMessage. An event whose value isn't a
// []any (a malformed document) is skipped rather than erroring, same
// leniency the typed version had via its own best-effort YAML decode.
func decodePoolsideHooksRaw(doc map[string]any) map[string][]any {
	hooks := map[string][]any{}
	raw, ok := doc["hooks"]
	if !ok {
		return hooks
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return hooks
	}
	for event, v := range m {
		if list, ok := v.([]any); ok {
			hooks[event] = list
		}
	}
	return hooks
}

// poolsideEntryCanonical reports whether an Observer poolside entry has the
// exact shape registerPoolsideAt writes: the observer-guard name, a "*"
// matcher and the command, nothing else (T-847).
func poolsideEntryCanonical(e any) bool {
	switch v := e.(type) {
	case poolsideHookEntry:
		return v.Name == observerPoolsideHookName && v.Matcher == "*"
	case map[string]any:
		for k := range v {
			if k != "name" && k != "matcher" && k != "command" {
				return false
			}
		}
		name, _ := v["name"].(string)
		matcher, _ := v["matcher"].(string)
		return name == observerPoolsideHookName && matcher == "*"
	default:
		return false
	}
}

// poolsideEntryCommand extracts the "command" field from an
// otherwise-opaque raw Poolside hook entry (a generic
// map[string]any, as readYAMLMap/decodePoolsideHooksRaw decode it, OR
// the poolsideHookEntry struct observer's own freshly-appended entry
// still is at this point in the same slice) — enough for
// isObserverAnyHookEntry to tell whether the entry is observer's own,
// without decoding (and thereby truncating) any other field.
func poolsideEntryCommand(e any) string {
	switch v := e.(type) {
	case map[string]any:
		cmd, _ := v["command"].(string)
		return cmd
	case poolsideHookEntry:
		return v.Command
	default:
		return ""
	}
}
