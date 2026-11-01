package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/regularfile"
)

// One JSON hooks-file writer for the hook-parity Lane A6 vendors whose
// config is a JSON object holding an event map (data: jsonHooksTarget),
// instead of one hand-written writer per vendor. Every target keeps the
// writers' common guarantees: the settings lock, the pinned write target,
// raw round-trip of every key and sibling entry Observer does not own (B5),
// the checksum record, the --force conflict guard, dry-run and a symmetric
// unregister. A vendor is a row: where the file is, where its event map
// sits, whether entries are matcher groups or flat handlers, and the
// handler shape.

// jsonSetting is a value Observer ensures at a dotted path of the file (a
// vendor enable switch such as zcode's hooks.enabled, or a format version
// such as Copilot CLI's version: 1).
type jsonSetting struct {
	path  []string
	value any
}

// jsonHooksTarget is one vendor's JSON hooks file.
type jsonHooksTarget struct {
	// tool is the `observer hook <tool>` token and the result label.
	tool string
	// label overrides the result label (a "-windows" bridge target).
	label string
	// wrapper prefixes every command (the cross-OS `wsl.exe -d <distro> --`
	// bridge); "" for a native target.
	wrapper string
	// portableDistro, when non-empty, makes the command the AP-119 portable
	// wsl.exe bridge for that WSL distro (portableBridgeCommand) instead of
	// wrapper + the native command: for a Windows host whose hook shell is
	// Git Bash and which may also be run through another shell. It is
	// mutually exclusive with wrapper and quote (the bridge quotes its own
	// Linux paths).
	portableDistro string
	// dir / file locate the hooks file.
	dir, file string
	// eventsPath is the key path from the top-level object to the event
	// map ({"hooks": {...}} is ["hooks"]; zcode's is ["hooks", "events"]).
	eventsPath []string
	// events are the native events registered, in order.
	events []string
	// grouped is true when an event's entries are matcher groups
	// ({"matcher": ..., "hooks": [handler]}); false for a flat list of
	// handlers.
	grouped bool
	// matcher is the group matcher Observer writes (grouped only; "" omits
	// the key).
	matcher string
	// handler builds Observer's handler object for cmd.
	handler func(cmd string) map[string]any
	// eventHandler, when non-nil, replaces handler for a vendor whose entry
	// shape differs per event (Kiro: a tool matcher on preToolUse only).
	eventHandler func(event, cmd string) map[string]any
	// coexist is true when Observer's entry sits beside the user's own
	// entries for the same event by design (Kiro: every agent JSON the user
	// owns), so an existing foreign entry is never a conflict.
	coexist bool
	// commandKey is the handler key that carries the command ("command",
	// or Copilot CLI's "bash").
	commandKey string
	// settings are ensured on register (never removed on unregister: a
	// vendor switch another hook may rely on is the user's after that).
	settings []jsonSetting
	// dedicated is true when the file is Observer's own (a hooks
	// directory where every file is one hook set): unregister deletes it
	// once it holds no hook entry.
	dedicated bool
	// entryName is the "name" Observer gives its own handler inside a
	// shared file (Crush), "" when the handler has none. With dedicated it
	// is how this target owns an entry by name (T-872, ownership.go).
	entryName string
	// extraFiles are written beside the hooks file on register and removed
	// on unregister (Goose's plugin manifest), keyed by path relative to
	// dir.
	extraFiles map[string][]byte
	// errPrefix names the registrar in wrapped errors.
	errPrefix string
	// quote, when non-nil, quotes the binary and --config paths for a host
	// whose hook shell is cmd.exe (Windows-shaped paths double-quoted, kept
	// with their backslashes); nil keeps the POSIX forward-slash form every
	// sh / Git Bash host reads.
	quote func(string) string
	// skip, when non-nil, inspects the file's raw bytes (nil when absent)
	// before anything is parsed and returns a reason to write nothing: a
	// vendor switch the user set that turns these hooks off (register only:
	// removing is always allowed), or a legacy shape the vendor migrates
	// itself.
	skip func(raw []byte, removing bool) string
	// restore, when true, writes only the changed top-level member (the
	// credential-file splice, every other member keeps its bytes) and, on
	// unregister, drops an events object left empty and a file left
	// holding nothing, so a removal gives back the file Observer found
	// when that file carried no hooks of the user's own.
	restore bool
	// dirErr, when set, is why dir could not be resolved (a relocation
	// variable with a relative value, register_homes.go): register writes
	// nothing and reports it; unregister reports it too.
	dirErr error
}

// writeJSONHooksTarget is the one settings write of the table-driven JSON
// writer: a restore target is spliced, any other goes through
// writeHookSettingsJSON (splice for a credential-flagged tool, whole-file
// otherwise).
func (r *Registry) writeJSONHooksTarget(t jsonHooksTarget, pinned pinnedTarget, raw []byte, top map[string]json.RawMessage) error {
	dir := filepath.Dir(pinned.target)
	if !t.restore || hooksShareCredentialFile(t.tool) {
		return r.writeHookSettingsJSON(t.tool, dir, pinned, raw, top)
	}
	body, err := spliceTopLevelJSON(raw, top)
	if err != nil {
		return err
	}
	if len(raw) > 0 && bytes.Equal(body, raw) {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("hook.write: mkdir: %w", err)
	}
	return atomicWriteFileMode(pinned, body, fileModeOr(pinned.target, 0o644))
}

// dropEmptyHooksMember removes a one-level events object left empty by an
// unregister (restore targets) and reports whether the file is left holding
// nothing at all.
func dropEmptyHooksMember(t jsonHooksTarget, top map[string]json.RawMessage) (empty bool) {
	if len(t.eventsPath) == 1 {
		if obj, err := jsonObject(top[t.eventsPath[0]]); err == nil && len(obj) == 0 {
			delete(top, t.eventsPath[0])
		}
	}
	return len(top) == 0
}

// command is Observer's command for event.
func (r *Registry) jsonHooksCommand(t jsonHooksTarget, event string) string {
	if t.portableDistro != "" {
		return portableBridgeCommand(t.portableDistro, r.opts.BinaryPath, t.tool, event, r.opts.ConfigPath)
	}
	if t.quote != nil {
		return t.wrapper + t.quote(r.opts.BinaryPath) + " hook " + t.tool + " " + event + r.configFlagSuffixWith(t.quote)
	}
	return t.wrapper + shellQuoteIfNeeded(forwardSlashPath(r.opts.BinaryPath)) + " hook " + t.tool + " " + event + r.configFlagSuffixForwardSlash()
}

// jsonHooksSkip runs t.skip over the file at path (under the caller's lock).
func jsonHooksSkip(t jsonHooksTarget, path string, removing bool) string {
	if t.skip == nil {
		return ""
	}
	raw, err := readSettingsFile(path)
	if err != nil {
		raw = nil
	}
	return t.skip(raw, removing)
}

// entry is Observer's entry for event, as JSON.
func (r *Registry) jsonHooksEntry(t jsonHooksTarget, event string) (json.RawMessage, error) {
	var h map[string]any
	if t.eventHandler != nil {
		h = t.eventHandler(event, r.jsonHooksCommand(t, event))
	} else {
		h = t.handler(r.jsonHooksCommand(t, event))
	}
	if !t.grouped {
		return json.Marshal(h)
	}
	g := map[string]any{"hooks": []any{h}}
	if t.matcher != "" {
		g["matcher"] = t.matcher
	}
	return json.Marshal(g)
}

// jsonHooksEntryIsObservers reports whether a raw entry is positively
// Observer's: every handler it holds names an observer `hook <tool>`
// invocation under commandKey, and it holds at least one.
func jsonHooksEntryIsObservers(t jsonHooksTarget, raw json.RawMessage) bool {
	handlers := []json.RawMessage{raw}
	if t.grouped {
		var g struct {
			Hooks []json.RawMessage `json:"hooks"`
		}
		if json.Unmarshal(raw, &g) != nil || len(g.Hooks) == 0 {
			return false
		}
		handlers = g.Hooks
	}
	for _, h := range handlers {
		var m map[string]any
		if json.Unmarshal(h, &m) != nil {
			return false
		}
		cmd, _ := m[t.commandKey].(string)
		if !isObserverAnyHookEntry(cmd, t.tool) {
			return false
		}
	}
	return true
}

// jsonObject decodes raw as a JSON object of raw values (nil/empty raw is an
// empty object).
func jsonObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	m := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(raw)) == 0 {
		return m, nil
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]json.RawMessage{}
	}
	return m, nil
}

// readJSONHooksFile reads the file's top-level object and its event map.
func readJSONHooksFile(t jsonHooksTarget, path string) (top map[string]json.RawMessage, raw []byte, eventMap map[string][]json.RawMessage, err error) {
	raw, err = readSettingsFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil, fmt.Errorf("%s: read: %w", t.errPrefix, err)
	}
	return decodeJSONHooksFile(t, path, raw)
}

// decodeJSONHooksFile decodes an already read file body (nil or empty is an
// empty file) into its top-level object and its event map.
func decodeJSONHooksFile(t jsonHooksTarget, path string, raw []byte) (top map[string]json.RawMessage, _ []byte, eventMap map[string][]json.RawMessage, err error) {
	top = map[string]json.RawMessage{}
	if len(bytes.TrimSpace(raw)) > 0 {
		if top, err = decodeSettingsObject(path, raw); err != nil {
			return nil, nil, nil, fmt.Errorf("%s: %w", t.errPrefix, err)
		}
	}
	cur := top
	for i, k := range t.eventsPath {
		next, err := jsonObject(cur[k])
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%s: parse %v: %w", t.errPrefix, t.eventsPath[:i+1], err)
		}
		if i == len(t.eventsPath)-1 {
			eventMap = map[string][]json.RawMessage{}
			for ev, v := range next {
				var list []json.RawMessage
				if err := json.Unmarshal(v, &list); err != nil {
					return nil, nil, nil, fmt.Errorf("%s: parse event %s: %w", t.errPrefix, ev, err)
				}
				eventMap[ev] = list
			}
		}
		cur = next
	}
	return top, raw, eventMap, nil
}

// setJSONPath writes value at path under top, creating intermediate objects
// and keeping every sibling key raw.
func setJSONPath(top map[string]json.RawMessage, path []string, value json.RawMessage) error {
	if len(path) == 1 {
		top[path[0]] = value
		return nil
	}
	child, err := jsonObject(top[path[0]])
	if err != nil {
		return err
	}
	if err := setJSONPath(child, path[1:], value); err != nil {
		return err
	}
	b, err := json.Marshal(child)
	if err != nil {
		return err
	}
	top[path[0]] = b
	return nil
}

// storeEventMap writes eventMap back under t.eventsPath (an empty event is
// dropped).
func storeEventMap(t jsonHooksTarget, top map[string]json.RawMessage, eventMap map[string][]json.RawMessage) error {
	parent := t.eventsPath[:len(t.eventsPath)-1]
	cur := top
	for _, k := range parent {
		next, err := jsonObject(cur[k])
		if err != nil {
			return err
		}
		cur = next
	}
	existing, err := jsonObject(cur[t.eventsPath[len(t.eventsPath)-1]])
	if err != nil {
		return err
	}
	for ev, list := range eventMap {
		if len(list) == 0 {
			delete(existing, ev)
			continue
		}
		b, err := json.Marshal(list)
		if err != nil {
			return err
		}
		existing[ev] = b
	}
	b, err := json.Marshal(existing)
	if err != nil {
		return err
	}
	return setJSONPath(top, t.eventsPath, b)
}

// registerJSONHooks installs Observer's entry for every t.events event.
func (r *Registry) registerJSONHooks(t jsonHooksTarget) RegistrationResult {
	res := RegistrationResult{Tool: t.resultLabel(), DryRun: r.opts.DryRun}
	if t.dirErr != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, t.dirErr)
		return res
	}
	path := filepath.Join(t.dir, t.file)
	res.ConfigPath = path

	if t.portableDistro != "" {
		if err := portableBridgePathError(t.errPrefix, r.opts.BinaryPath, r.opts.ConfigPath); err != nil {
			res.Error = err
			return res
		}
	}
	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
		return res
	}
	defer unlock()
	pinned := pinWriteTarget(path)
	if why := jsonHooksSkip(t, path, false); why != "" {
		res.Skipped, res.SkipKind, res.SkipReason = true, SkipNotApplicable, why
		return res
	}

	top, raw, eventMap, err := readJSONHooksFile(t, path)
	if err != nil {
		res.Error = err
		return res
	}
	// FU-192: an entry in Observer's shape running another binary is kept.
	id := identityContent
	if t.dedicated {
		id = identityOwnedName
	}
	if r.refusesForeignBinary(&res, t.errPrefix, path, id, shapedHooksInText(raw, t.tool)) {
		return res
	}
	// FU-207: an extra file (Goose's plugin.json) that is not Observer's is
	// kept without --force, like every file Observer owns by name.
	replaced, err := r.occupiedJSONHooksExtras(t)
	if err != nil {
		res.Error = err
		return res
	}
	changed := false
	var repaired []string
	for _, event := range t.events {
		if r.skipEvent(t.tool, event) {
			continue
		}
		added, wasRepaired, err := r.jsonHooksRegisterEvent(t, &res, path, eventMap, event)
		if err != nil {
			res.Error = err
			return res
		}
		if wasRepaired {
			repaired = append(repaired, event)
		}
		changed = changed || added
	}
	settingsChanged, err := applyJSONHooksSettings(t, top)
	if err != nil {
		res.Error = err
		return res
	}
	changed = changed || settingsChanged
	if !changed && r.jsonHooksExtrasPresent(t) {
		return res
	}
	if err := storeEventMap(t, top, eventMap); err != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
		return res
	}
	if r.opts.DryRun {
		return res
	}
	for _, x := range replaced {
		if err := keepReplacedBytes(&res, x.path, x.data, x.repair); err != nil {
			res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
			return res
		}
	}
	if err := writeJSONHooksExtras(t); err != nil {
		res.Error = err
		return res
	}
	if len(repaired) > 0 && !hooksShareCredentialFile(t.tool) {
		// Keep the pre-repair file recoverable (a credential-bearing file
		// is never copied: its writer splices only the hooks subtree).
		if err := keepRepairCopyOf(&res, pinned.target); err != nil {
			res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
			return res
		}
	}
	if err := r.writeJSONHooksTarget(t, pinned, raw, top); err != nil {
		res.Error = err
		return res
	}
	if err := r.recordHookChecksum(t.tool, path); err != nil {
		res.Error = err
		return res
	}
	noteOwnedRepair(&res, path, repaired)
	return res
}

// jsonHooksRegisterEvent puts Observer's entry for one event into eventMap
// (or records it as already set). added reports a new entry; repaired that
// a neutralised Observer entry was replaced (T-872). Split out of
// registerJSONHooks to keep that function's branching readable.
func (r *Registry) jsonHooksRegisterEvent(t jsonHooksTarget, res *RegistrationResult, path string, eventMap map[string][]json.RawMessage, event string) (added, repaired bool, err error) {
	want, err := r.jsonHooksEntry(t, event)
	if err != nil {
		return false, false, fmt.Errorf("%s: marshal: %w", t.errPrefix, err)
	}
	entries := eventMap[event]
	idx := -1
	for i, e := range entries {
		if jsonHooksEntryIsObservers(t, e) {
			idx = i
		}
	}
	if idx >= 0 {
		if jsonEqual(entries[idx], want) {
			res.AlreadySet = append(res.AlreadySet, event)
			return false, false, nil
		}
		entries = append(entries[:idx:idx], entries[idx+1:]...)
	}
	// T-872: on a managed repair pass an entry Observer owns by name
	// (any entry of Observer's own dedicated file, or one under
	// Observer's entry name) that no longer runs observer is a
	// neutralised Observer hook and is replaced.
	if kept, dropped := r.dropNeutralisedJSONHooks(t, path, entries); dropped {
		entries = kept
		repaired = true
	}
	if !t.coexist && len(entries) > 0 && r.refuses(path, identityContent) {
		return false, repaired, hookConflictError(t.errPrefix, event)
	}
	eventMap[event] = append(entries, want)
	res.HooksAdded = append(res.HooksAdded, event)
	return true, repaired, nil
}

// applyJSONHooksSettings sets each of t.settings in top and reports whether
// any value changed.
func applyJSONHooksSettings(t jsonHooksTarget, top map[string]json.RawMessage) (changed bool, err error) {
	for _, s := range t.settings {
		b, _ := json.Marshal(s.value)
		if cur, ok := lookupJSONPath(top, s.path); ok && jsonEqual(cur, b) {
			continue
		}
		if err := setJSONPath(top, s.path, b); err != nil {
			return changed, fmt.Errorf("%s: set %v: %w", t.errPrefix, s.path, err)
		}
		changed = true
	}
	return changed, nil
}

// writeJSONHooksExtras writes t.extraFiles (Observer's own companion files)
// under t.dir.
func writeJSONHooksExtras(t jsonHooksTarget) error {
	for rel, data := range t.extraFiles {
		p := filepath.Join(t.dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return fmt.Errorf("%s: %w", t.errPrefix, err)
		}
		if err := atomicWriteFile(pinWriteTarget(p), data); err != nil {
			return fmt.Errorf("%s: write %s: %w", t.errPrefix, rel, err)
		}
	}
	return nil
}

// dropNeutralisedJSONHooks removes, on a managed repair pass, the entries of
// one event that Observer owns by name but that no longer run observer: every
// such entry of a dedicated file (the file itself is Observer's), or one whose
// handler carries Observer's entry name (t.entryName). dropped is false, and
// entries untouched, when there is none or the conflict rules do not repair
// here (T-872).
func (r *Registry) dropNeutralisedJSONHooks(t jsonHooksTarget, path string, entries []json.RawMessage) (kept []json.RawMessage, dropped bool) {
	owned := func(e json.RawMessage) bool {
		if jsonHooksEntryIsObservers(t, e) {
			return false
		}
		return t.dedicated || (t.entryName != "" && jsonHooksEntryNamed(t, e, t.entryName))
	}
	n := 0
	for _, e := range entries {
		if owned(e) {
			n++
		}
	}
	if n == 0 || r.resolveConflict(path, identityOwnedName) != conflictRepair {
		return entries, false
	}
	kept = make([]json.RawMessage, 0, len(entries)-n)
	for _, e := range entries {
		if !owned(e) {
			kept = append(kept, e)
		}
	}
	return kept, true
}

// jsonHooksEntryNamed reports whether a raw entry (or, for a grouped target,
// any handler in it) carries "name": name.
func jsonHooksEntryNamed(t jsonHooksTarget, raw json.RawMessage, name string) bool {
	handlers := []json.RawMessage{raw}
	if t.grouped {
		var g struct {
			Hooks []json.RawMessage `json:"hooks"`
		}
		if json.Unmarshal(raw, &g) != nil {
			return false
		}
		handlers = g.Hooks
	}
	for _, h := range handlers {
		var m map[string]any
		if json.Unmarshal(h, &m) != nil {
			continue
		}
		if n, _ := m["name"].(string); n == name {
			return true
		}
	}
	return false
}

// replacedExtra is an extra file whose bytes a registration replaces: the
// operator's --force takeover or a managed repair (ownership.go).
type replacedExtra struct {
	path   string
	data   []byte
	repair bool
}

// occupiedJSONHooksExtras runs occupiedOwnedFile over every extra file that
// exists and does not read as Observer's (extraFileIsObservers). It returns
// the refusal, or the files whose bytes the write replaces.
func (r *Registry) occupiedJSONHooksExtras(t jsonHooksTarget) ([]replacedExtra, error) {
	rels := make([]string, 0, len(t.extraFiles))
	for rel := range t.extraFiles {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	var out []replacedExtra
	for _, rel := range rels {
		p := filepath.Join(t.dir, rel)
		have, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%s: read %s: %w", t.errPrefix, p, err)
		}
		// The extras live in the directory Observer owns with the hooks
		// file, whose install record decides a managed repair.
		foreign, repair, err := r.occupiedOwnedFileIn(t.errPrefix, p, filepath.Join(t.dir, t.file), extraFileIsObservers(t.extraFiles[rel], have), nil)
		if err != nil {
			return nil, err
		}
		if foreign {
			out = append(out, replacedExtra{path: p, data: have, repair: repair})
		}
	}
	return out, nil
}

// extraFileIsObservers reports whether have, the file at an extra file's
// path, is Observer's: the bytes Observer writes, or a JSON object with the
// same non-empty "name" (an older manifest Observer wrote).
func extraFileIsObservers(want, have []byte) bool {
	if bytes.Equal(want, have) {
		return true
	}
	var w, h struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(want, &w) != nil || json.Unmarshal(have, &h) != nil {
		return false
	}
	return w.Name != "" && w.Name == h.Name
}

// jsonHooksExtrasPresent reports whether every extra file already holds its
// exact content.
func (r *Registry) jsonHooksExtrasPresent(t jsonHooksTarget) bool {
	for rel, data := range t.extraFiles {
		have, err := os.ReadFile(filepath.Join(t.dir, rel))
		if err != nil || !bytes.Equal(have, data) {
			return false
		}
	}
	return true
}

// unregisterJSONHooks removes ONLY Observer's entries for t.events.
func (r *Registry) unregisterJSONHooks(t jsonHooksTarget) UnregistrationResult {
	res := UnregistrationResult{Tool: t.resultLabel(), DryRun: r.opts.DryRun}
	if t.dirErr != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, t.dirErr)
		return res
	}
	path := filepath.Join(t.dir, t.file)
	res.ConfigPath = path

	// A target with extra files owns its directory (a plugin dir): once
	// its files are gone, the directory goes too. This runs AFTER the
	// lock is released (the lock sentinel sits beside the file), and
	// os.Remove never deletes a directory that still holds anything.
	removeOwnedDir := false
	defer func() {
		if removeOwnedDir {
			_ = os.Remove(filepath.Dir(path))
			_ = os.Remove(t.dir)
		}
	}()
	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
		return res
	}
	defer unlock()
	pinned := pinWriteTarget(path)
	if why := jsonHooksSkip(t, path, true); why != "" {
		res.Skipped = true
		return res
	}

	top, raw, eventMap, err := readJSONHooksFile(t, path)
	if err != nil {
		res.Error = err
		return res
	}
	// FU-203: jsonHooksEntryIsObservers's token-strict recogniser never
	// takes an entry in Observer's shape that runs another binary; it is
	// reported kept.
	for _, event := range t.events {
		for _, e := range eventMap[event] {
			if r.keepsForeignBinary(shapedHooksInText(e, t.tool)) {
				noteKeptForeign(&res, event)
			}
		}
	}
	for _, event := range t.events {
		entries := eventMap[event]
		kept := make([]json.RawMessage, 0, len(entries))
		removed := false
		for _, e := range entries {
			if jsonHooksEntryIsObservers(t, e) {
				removed = true
				continue
			}
			kept = append(kept, e)
		}
		if removed {
			eventMap[event] = kept
			res.HooksRemoved = append(res.HooksRemoved, event)
		}
	}
	if len(res.HooksRemoved) == 0 {
		return res
	}
	if err := storeEventMap(t, top, eventMap); err != nil {
		res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
		return res
	}
	// FU-212: a dedicated file is deleted only when what is left in it is
	// Observer's (dedicatedFileLeftObservers); anything else of the user's
	// in it keeps the file, written back without Observer's entries.
	deleteFile := (t.dedicated && jsonHooksEmpty(eventMap) && dedicatedFileLeftObservers(t, top)) ||
		(t.restore && dropEmptyHooksMember(t, top))
	// The extras go with the hooks file they serve, only once that file is
	// gone, and only those that read as Observer's; a kept hooks file (or
	// a failed delete of it) keeps them all.
	if r.opts.DryRun {
		if deleteFile && t.dedicated {
			r.removeJSONHooksExtras(t, &res)
		}
		return res
	}
	if deleteFile {
		if err := removeEmptyConfigFile(path, raw); err != nil {
			res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
			return res
		}
		_ = r.removeChecksum(path)
		if t.dedicated {
			r.removeJSONHooksExtras(t, &res)
		}
		removeOwnedDir = len(t.extraFiles) > 0
		return res
	}
	if err := r.writeJSONHooksTarget(t, pinned, raw, top); err != nil {
		res.Error = err
		return res
	}
	if err := r.removeChecksum(path); err != nil {
		res.Error = err
	}
	return res
}

// removeJSONHooksExtras deletes each of t.extraFiles that reads as
// Observer's (extraFileIsObservers, the recogniser the writer's guard uses),
// comparing the bytes again before the delete. A file that does not is kept
// byte for byte, with or without --force, and named in
// res.FilesKeptForeign (FU-212). A dry run deletes nothing and reports the
// same.
func (r *Registry) removeJSONHooksExtras(t jsonHooksTarget, res *UnregistrationResult) {
	rels := make([]string, 0, len(t.extraFiles))
	for rel := range t.extraFiles {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		p := filepath.Join(t.dir, rel)
		have, err := regularfile.Read(p, maxSettingsFileBytes)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !extraFileIsObservers(t.extraFiles[rel], have) {
			noteKeptForeignFile(res, p)
			continue
		}
		if r.opts.DryRun {
			continue
		}
		if err := removeEmptyConfigFile(p, have); err != nil && res.Error == nil {
			res.Error = fmt.Errorf("%s: %w", t.errPrefix, err)
		}
	}
}

// dedicatedFileLeftObservers reports whether a dedicated hooks file, with
// Observer's entries cut (top), holds nothing but Observer's own: the
// events object (empty by then) and the members t.settings writes, with
// Observer's value for a "name" member (the recogniser
// extraFileIsObservers uses). Any other member (a user's own key in
// Observer's Kiro agent, say) means the file is not only Observer's and is
// written back instead of deleted (FU-212).
func dedicatedFileLeftObservers(t jsonHooksTarget, top map[string]json.RawMessage) bool {
	owned := map[string]json.RawMessage{t.eventsPath[0]: nil}
	for _, s := range t.settings {
		b, _ := json.Marshal(s.value)
		owned[s.path[0]] = b
	}
	for k, v := range top {
		want, ok := owned[k]
		if !ok {
			return false
		}
		if k == "name" && !jsonEqual(v, want) {
			return false
		}
	}
	return true
}

// jsonHooksEmpty reports whether no event holds an entry.
func jsonHooksEmpty(eventMap map[string][]json.RawMessage) bool {
	for _, l := range eventMap {
		if len(l) > 0 {
			return false
		}
	}
	return true
}

// lookupJSONPath returns the raw value at path.
func lookupJSONPath(top map[string]json.RawMessage, path []string) (json.RawMessage, bool) {
	cur := top
	for i, k := range path {
		v, ok := cur[k]
		if !ok {
			return nil, false
		}
		if i == len(path)-1 {
			return v, true
		}
		next, err := jsonObject(v)
		if err != nil {
			return nil, false
		}
		cur = next
	}
	return nil, false
}

// jsonEqual compares two JSON values semantically (key order and spacing
// ignored).
func jsonEqual(a, b json.RawMessage) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	xb, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	return bytes.Equal(xb, yb)
}

// resultLabel is the RegistrationResult.Tool label.
func (t jsonHooksTarget) resultLabel() string {
	if t.label != "" {
		return t.label
	}
	return t.tool
}
