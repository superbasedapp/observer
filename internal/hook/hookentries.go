package hook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/credfile"
)

// hookentries.go - NEW-06: the one raw round-trip of a hook event map.
//
// Several registrars used to decode their hooks member into typed structs
// that held only the fields Observer itself writes (Cursor's {command}, the
// Claude-shaped {matcher, hooks: [{type, command}]}, Codex's whole
// {"hooks": ...} file). Every rewrite re-encoded those structs, so a
// developer's own entry lost every field the struct did not model (a
// timeout, a matcher, a type, an env, a statusMessage, a group's own keys)
// and Codex's hooks.json lost every top-level key beside "hooks", silently,
// on every `observer start`. Cursor also swallowed a decode error and then
// wrote its own entries over whatever the file held.
//
// hookEvents keeps every event's entries as their raw JSON. The only fields
// Observer reads are a handler's "type" and its command, through a probe;
// the only entries it changes are its own handlers; an event it does not
// change keeps its data and its place in the member; and a member it
// cannot read without guessing is refused, so the file stays untouched.
//
// "Keeps its data" is not "keeps its bytes": once the member changes, the
// file writer re-indents the whole member (encodeSettingsJSON, and the
// credential splice, credfile.SpliceObject, both run json.Indent over a
// changed member), so whitespace inside an untouched event can change.
// Every value, key, number literal and order survives; only an unchanged
// member, or an unchanged file, keeps its exact bytes.

// hookEntryLayout says where the handlers of one hook entry sit. It is data,
// one value per format family, never a tool branch.
type hookEntryLayout struct {
	// grouped is true when an event's entries are matcher groups
	// ({"matcher": ..., "hooks": [handler...]}); false when each entry is
	// itself a handler (Cursor's flat {"command": ...} list).
	grouped bool
	// commandKey is the handler member that carries the command.
	commandKey string
	// typed is true when a handler runs a command only when its "type" is
	// "command" (the Claude-shaped family; another type, a prompt or an
	// agent hook, is never a command and never Observer's).
	typed bool
}

// flatHookEntries is the flat handler list (Cursor's hooks.json).
var flatHookEntries = hookEntryLayout{commandKey: "command"}

// groupedHookEntries is the Claude-shaped matcher-group family (Claude Code,
// Codex, Gemini CLI, Qwen Code, Qoder).
var groupedHookEntries = hookEntryLayout{grouped: true, commandKey: "command", typed: true}

// hookEvents is a decoded event map: event name -> entries, every entry raw.
type hookEvents struct {
	// orig is the member as read (nil when absent, empty or null).
	orig json.RawMessage
	// origEvents is orig's members, each event's value as read.
	origEvents map[string]json.RawMessage
	// lists holds every event's entries.
	lists map[string][]json.RawMessage
	// dirty names the events set since the decode.
	dirty map[string]bool
}

// hookShapeError is a decode refusal: what is wrong, composed only from
// event names and positions (never a value read from the file), so it can
// be shown for a credential-bearing file too.
type hookShapeError struct{ msg string }

func (e *hookShapeError) Error() string { return e.msg }

// refuseHookShape wraps a decode refusal with the registrar and the path as
// a safe message (paths, event and key names only), telling the developer
// that nothing was written.
func refuseHookShape(errPrefix, path string, err error) error {
	return safeErrorf("%s: %s: %v; refusing to modify it (nothing was written; fix the file by hand, then re-run)", errPrefix, path, err)
}

// decodeHookEvents decodes the event map member of a hooks file. An absent,
// empty or null member is an empty map. Anything Observer cannot edit
// without guessing is refused: a member that is not an
// object, an event whose value is not a list, an entry that is not an
// object, and in a grouped layout a group whose "hooks" is not a list of
// objects. A refusal (a hookShapeError) leaves the caller nothing to write.
func decodeHookEvents(member json.RawMessage, l hookEntryLayout) (*hookEvents, error) {
	h := &hookEvents{origEvents: map[string]json.RawMessage{}, lists: map[string][]json.RawMessage{}, dirty: map[string]bool{}}
	trimmed := bytes.TrimSpace(member)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return h, nil
	}
	if trimmed[0] != '{' || json.Unmarshal(trimmed, &h.origEvents) != nil || h.origEvents == nil {
		return nil, &hookShapeError{"the hooks member is not an object of event lists"}
	}
	if key, dup := duplicateTopLevelKey(trimmed); dup {
		return nil, &hookShapeError{"the hooks member lists event " + key + " twice"}
	}
	h.orig = trimmed
	for event, v := range h.origEvents {
		list, err := decodeHookEntryList(event, v, l)
		if err != nil {
			return nil, err
		}
		h.lists[event] = list
	}
	return h, nil
}

// decodeHookEntryList decodes one event's value into its raw entries,
// checking each against l (see decodeHookEvents).
func decodeHookEntryList(event string, v json.RawMessage, l hookEntryLayout) ([]json.RawMessage, error) {
	tv := bytes.TrimSpace(v)
	if bytes.Equal(tv, []byte("null")) {
		return nil, nil
	}
	var list []json.RawMessage
	if len(tv) == 0 || tv[0] != '[' || json.Unmarshal(tv, &list) != nil {
		return nil, &hookShapeError{"hooks." + event + " is not a list of hook entries"}
	}
	for i, e := range list {
		if !isJSONObject(e) {
			return nil, &hookShapeError{"hooks." + event + " entry " + strconv.Itoa(i+1) + " is not an object"}
		}
		if !l.grouped {
			continue
		}
		var g map[string]json.RawMessage
		_ = json.Unmarshal(e, &g)
		hv, ok := g["hooks"]
		if !ok || bytes.Equal(bytes.TrimSpace(hv), []byte("null")) {
			continue
		}
		var handlers []json.RawMessage
		if !bytes.HasPrefix(bytes.TrimSpace(hv), []byte("[")) || json.Unmarshal(hv, &handlers) != nil {
			return nil, &hookShapeError{"hooks." + event + " group " + strconv.Itoa(i+1) + " has a hooks member that is not a list"}
		}
		for _, hd := range handlers {
			if !isJSONObject(hd) {
				return nil, &hookShapeError{"hooks." + event + " group " + strconv.Itoa(i+1) + " holds a handler that is not an object"}
			}
		}
	}
	return list, nil
}

// isJSONObject reports whether raw is a JSON object.
func isJSONObject(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || t[0] != '{' {
		return false
	}
	var m map[string]json.RawMessage
	return json.Unmarshal(t, &m) == nil && m != nil
}

// entries returns event's entries (nil when absent).
func (h *hookEvents) entries(event string) []json.RawMessage { return h.lists[event] }

// set replaces event's entries; an empty list removes the event.
func (h *hookEvents) set(event string, entries []json.RawMessage) {
	h.lists[event] = entries
	h.dirty[event] = true
}

// names returns every event the map holds entries for, sorted.
func (h *hookEvents) names() []string {
	out := make([]string, 0, len(h.lists))
	for ev, l := range h.lists {
		if len(l) > 0 {
			out = append(out, ev)
		}
	}
	sort.Strings(out)
	return out
}

// empty reports whether no event holds an entry and the member holds
// nothing else either (so a caller may drop the member).
func (h *hookEvents) empty() bool {
	for ev, l := range h.lists {
		if len(l) > 0 {
			return false
		}
		if !h.dirty[ev] {
			// An untouched event the file lists with no entry (null or
			// []) is the developer's; keep the member for it.
			return false
		}
	}
	return true
}

// encode renders the member back: an event set since the decode is
// re-encoded (removed when it holds no entry), every other event is spliced
// back as read, in its place (credfile.SpliceObject), and a new event is
// appended. Re-encoding never HTML-escapes, so a command holding && keeps
// its text. What survives the file write is the data and the order, not the
// bytes: the writer re-indents a changed member as a whole (see the note at
// the top of this file), untouched events included.
func (h *hookEvents) encode() (json.RawMessage, error) {
	next := make(map[string]json.RawMessage, len(h.origEvents)+len(h.dirty))
	for ev, v := range h.origEvents {
		next[ev] = v
	}
	for ev := range h.dirty {
		list := h.lists[ev]
		if len(list) == 0 {
			delete(next, ev)
			continue
		}
		b, err := marshalHookJSON(list)
		if err != nil {
			return nil, err
		}
		next[ev] = b
	}
	out, err := credfile.SpliceObject(h.orig, next)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(out), nil
}

// marshalHookJSON encodes v compactly without HTML escaping, so a command
// holding && or a redirect keeps its text.
func marshalHookJSON(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return json.RawMessage(bytes.TrimRight(buf.Bytes(), "\n")), nil
}

// handlers returns entry's handlers, raw: a grouped entry's "hooks" list
// (nil when it has none), or the entry itself.
func (l hookEntryLayout) handlers(entry json.RawMessage) []json.RawMessage {
	if !l.grouped {
		return []json.RawMessage{entry}
	}
	var g struct {
		Hooks []json.RawMessage `json:"hooks"`
	}
	if json.Unmarshal(entry, &g) != nil {
		return nil
	}
	return g.Hooks
}

// command returns a handler's command and whether it is a command handler.
// A typed layout's handler is one only when its "type" is "command"; a flat
// handler always is (a missing or non-string command reads as "", which no
// recogniser owns).
func (l hookEntryLayout) command(handler json.RawMessage) (string, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(handler, &m) != nil {
		return "", !l.typed
	}
	if l.typed {
		var typ string
		if json.Unmarshal(m["type"], &typ) != nil || typ != "command" {
			return "", false
		}
	}
	var cmd string
	_ = json.Unmarshal(m[l.commandKey], &cmd)
	return cmd, true
}

// commands returns the command of every command handler entry holds.
func (l hookEntryLayout) commands(entry json.RawMessage) []string {
	var out []string
	for _, h := range l.handlers(entry) {
		if cmd, ok := l.command(h); ok {
			out = append(out, cmd)
		}
	}
	return out
}

// observerIndex returns the index of the first entry holding a command
// handler ours recognises, -1 when there is none.
func (l hookEntryLayout) observerIndex(entries []json.RawMessage, ours func(string) bool) int {
	for i, e := range entries {
		if l.observerCommand(e, ours) != "" {
			return i
		}
	}
	return -1
}

// observerCommand returns the command of the first command handler in entry
// that ours recognises, "" when there is none.
func (l hookEntryLayout) observerCommand(entry json.RawMessage, ours func(string) bool) string {
	for _, cmd := range l.commands(entry) {
		if ours(cmd) {
			return cmd
		}
	}
	return ""
}

// hasCommand reports whether a command handler in entries runs exactly cmd.
func (l hookEntryLayout) hasCommand(entries []json.RawMessage, cmd string) bool {
	for _, e := range entries {
		for _, c := range l.commands(e) {
			if c == cmd {
				return true
			}
		}
	}
	return false
}

// hasForeign reports whether a command handler in entries is not one ours
// recognises.
func (l hookEntryLayout) hasForeign(entries []json.RawMessage, ours func(string) bool) bool {
	for _, e := range entries {
		for _, c := range l.commands(e) {
			if !ours(c) {
				return true
			}
		}
	}
	return false
}

// soleObserverCommand reports whether entry holds exactly one command
// handler ours recognises and it runs cmd. A developer's own handler beside
// it in the same group does not change the answer: it is theirs, and
// Observer's entry is the one this writer emits.
func (l hookEntryLayout) soleObserverCommand(entry json.RawMessage, ours func(string) bool, cmd string) bool {
	n, match := 0, false
	for _, c := range l.commands(entry) {
		if ours(c) {
			n++
			match = c == cmd
		}
	}
	return n == 1 && match
}

// matcher returns a group's matcher ("" when absent or not a string).
func (l hookEntryLayout) matcher(entry json.RawMessage) string {
	var g struct {
		Matcher json.RawMessage `json:"matcher"`
	}
	if json.Unmarshal(entry, &g) != nil {
		return ""
	}
	var m string
	_ = json.Unmarshal(g.Matcher, &m)
	return m
}

// removeHandlers drops every command handler drop recognises from entries.
// A flat entry goes whole. A group loses only those handlers and keeps every
// other member and handler, with its data and order; a group left holding
// no handler is dropped. removed counts the handlers dropped, kept the
// handlers left in entries. The entries are never decoded into a typed
// shape, so nothing Observer does not own is lost.
func (l hookEntryLayout) removeHandlers(entries []json.RawMessage, drop func(string) bool) (out []json.RawMessage, removed, kept int, err error) {
	for _, e := range entries {
		hs := l.handlers(e)
		var survivors []json.RawMessage
		n := 0
		for _, h := range hs {
			if cmd, ok := l.command(h); ok && drop(cmd) {
				n++
				continue
			}
			survivors = append(survivors, h)
		}
		removed += n
		switch {
		case n == 0:
			out = append(out, e)
			kept += len(hs)
		case !l.grouped || len(survivors) == 0:
			// The whole entry was Observer's handler(s).
		default:
			list, merr := marshalHookJSON(survivors)
			if merr != nil {
				return nil, 0, 0, merr
			}
			g, serr := credfile.SetObjectMember(e, "hooks", list, true)
			if serr != nil {
				return nil, 0, 0, serr
			}
			out = append(out, json.RawMessage(bytes.TrimSpace(g)))
			kept += len(survivors)
		}
	}
	return out, removed, kept, nil
}

// observerGroupHandler is the one command handler Observer writes into a
// matcher group.
type observerGroupHandler struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

// observerHandler is Observer's own command handler for cmd.
func observerHandler(cmd string) (json.RawMessage, error) {
	return marshalHookJSON(observerGroupHandler{"command", cmd})
}

// observerGroupEntry is Observer's own matcher group for cmd: matcher
// ("" omits the member) and one command handler.
func observerGroupEntry(matcher, cmd string) (json.RawMessage, error) {
	if matcher == "" {
		return marshalHookJSON(struct {
			Hooks []observerGroupHandler `json:"hooks"`
		}{[]observerGroupHandler{{"command", cmd}}})
	}
	return marshalHookJSON(struct {
		Matcher string                 `json:"matcher"`
		Hooks   []observerGroupHandler `json:"hooks"`
	}{matcher, []observerGroupHandler{{"command", cmd}}})
}

// observerFlatEntry is Observer's own flat handler for cmd.
func observerFlatEntry(cmd string) (json.RawMessage, error) {
	return marshalHookJSON(cursorHookEntry{Command: cmd})
}

// removeObserverHandlers is the uninstall walk the raw-entry writers share:
// for every event, the handlers recognise owns (judged by removableEntry,
// so one in Observer's shape running another binary is kept and reported,
// FU-203) are dropped, every other entry and field keeps its data and
// order, and the result names the events removed from and those still
// holding a handler.
func (r *Registry) removeObserverHandlers(res *UnregistrationResult, hooks *hookEvents, l hookEntryLayout, tool string, recognise func(string) bool) error {
	for _, event := range hooks.names() {
		foreign := false
		kept, removed, left, err := l.removeHandlers(hooks.entries(event), r.removableEntry(tool, recognise, &foreign))
		if err != nil {
			return err
		}
		if foreign {
			noteKeptForeign(res, event)
		}
		if removed > 0 {
			res.HooksRemoved = append(res.HooksRemoved, event)
			hooks.set(event, kept)
		}
		if left > 0 {
			res.HooksKept = append(res.HooksKept, event)
		}
	}
	return nil
}

// setHooksMember writes hooks back as settings[key]: removed when dropEmpty
// is set (an uninstall) and no event holds an entry any more, re-encoded
// when an event changed, and left as read otherwise.
func setHooksMember(settings map[string]json.RawMessage, key string, hooks *hookEvents, dropEmpty bool) error {
	if dropEmpty && hooks.empty() {
		delete(settings, key)
		return nil
	}
	if len(hooks.dirty) == 0 {
		return nil
	}
	b, err := hooks.encode()
	if err != nil {
		return fmt.Errorf("encode %s: %w", key, err)
	}
	settings[key] = b
	return nil
}

// groupEntryRule is one event of a Claude-shaped (matcher group) hooks
// file to put Observer's entry into. The writers differ only in data, so
// each is a value of this, never a branch on the tool.
type groupEntryRule struct {
	errPrefix, path, event, cmd string
	// matcher is the matcher of the group Observer writes ("" omits it).
	matcher string
	// exactMatcher: Observer's entry is already set only when its group's
	// matcher is exactly matcher (Codex: a group with no matcher is
	// rewritten to "*"); otherwise the T-847 shape check judges it.
	exactMatcher bool
	// ours recognises Observer's handlers for this target.
	ours func(string) bool
	// conflictScope, when set, limits the --force conflict check to the
	// groups whose matcher it accepts (native Claude Code: a developer's
	// hook on a narrower matcher never blocks); nil checks every group.
	conflictScope func(matcher string) bool
	// conflictErr, when set, words the --force refusal for the event's
	// groups (Codex names Observer's own wsl.exe bridge entries); nil uses
	// hookConflictError.
	conflictErr func(groups []json.RawMessage) error
	// drift is true when Observer's entry for event is not in the shape
	// this writer emits (T-847, shapeDriftEvents).
	drift bool
	// keepEquivalent runs the T-725 judgement (keepOrRewrite) on a stale
	// Observer entry: kept as set under KeepEquivalentHooks, and every
	// rewrite recorded with its reason.
	keepEquivalent bool
}

// putObserverGroup is the per-event write every Claude-shaped registrar
// shares (Claude Code and its Windows bridge, Gemini CLI, Qwen Code, Qoder,
// Codex). Observer's entry is already set when its group holds exactly one
// Observer handler, running the command this writer emits, in the shape it
// emits. Otherwise a developer's hook elsewhere on the event blocks without
// --force, and Observer's entry is written: appended when the event had
// none, and on a refresh put where the stale one was (refreshObserverGroup),
// so every other group and handler keeps its data and its position
// (NEW-06). added reports a new entry.
//
// On a refresh, two kinds of developer hook never block, because each
// already sat beside Observer's entry and the refresh does not touch it: a
// handler inside Observer's own group, and a group on Observer's own matcher
// (observerMatcher). The second covers the group a split left behind: an
// earlier refresh that moved Observer's handler out of a shared group left
// the developer's handler there as a group of its own, and that group must
// not stop every later refresh (and with it `observer start`) for the tool.
func (r *Registry) putObserverGroup(res *RegistrationResult, hooks *hookEvents, rule groupEntryRule) (added bool, err error) {
	l := groupedHookEntries
	groups := hooks.entries(rule.event)
	idx := l.observerIndex(groups, rule.ours)
	others := groups
	if idx >= 0 {
		have := l.observerCommand(groups[idx], rule.ours)
		switch {
		case rule.drift:
			shapeRewrite(res, rule.event, have, rule.cmd)
		case rule.observerGroupCurrent(groups[idx]):
			res.AlreadySet = append(res.AlreadySet, rule.event)
			return false, nil
		case rule.keepEquivalent && r.keepOrRewrite(res, rule.event, have, rule.cmd):
			res.AlreadySet = append(res.AlreadySet, rule.event)
			return false, nil
		}
		others = nil
		for i, g := range groups {
			if i != idx && !rule.observerMatcher(l.matcher(g)) {
				others = append(others, g)
			}
		}
	}
	if r.refuses(rule.path, identityContent) && l.hasForeign(scopedGroups(others, rule.conflictScope), rule.ours) {
		if rule.conflictErr != nil {
			return false, rule.conflictErr(others)
		}
		return false, hookConflictError(rule.errPrefix, rule.event)
	}
	if idx >= 0 {
		next, err := refreshObserverGroup(groups, idx, rule)
		if err != nil {
			return false, fmt.Errorf("%s: %w", rule.errPrefix, err)
		}
		hooks.set(rule.event, next)
		return true, nil
	}
	entry, err := observerGroupEntry(rule.matcher, rule.cmd)
	if err != nil {
		return false, fmt.Errorf("%s: marshal entry: %w", rule.errPrefix, err)
	}
	hooks.set(rule.event, append(groups, entry))
	return true, nil
}

// mergeObserverGroup puts Observer's entry for rule.event into hooks with
// no --force conflict rule and no T-725 equivalence: the write of the hosted
// box seed (RenderBoxHooks), whose file is Observer's to seed and where a
// developer's hook is kept beside Observer's, never refused. An entry
// already current is left alone; a stale one is refreshed where it sits
// (refreshObserverGroup); any Observer handler in a later group is dropped
// (a group left with none goes), so a stale one never runs beside the
// current one; and an event with no Observer entry gets Observer's group
// appended. rule's errPrefix, path, conflict and equivalence fields are
// not read.
func mergeObserverGroup(hooks *hookEvents, rule groupEntryRule) error {
	l := groupedHookEntries
	groups := hooks.entries(rule.event)
	idx := l.observerIndex(groups, rule.ours)
	if idx < 0 {
		entry, err := observerGroupEntry(rule.matcher, rule.cmd)
		if err != nil {
			return fmt.Errorf("marshal entry: %w", err)
		}
		hooks.set(rule.event, append(groups, entry))
		return nil
	}
	tail, strays, _, err := l.removeHandlers(groups[idx+1:], rule.ours)
	if err != nil {
		return err
	}
	next := append(append([]json.RawMessage{}, groups[:idx+1]...), tail...)
	if !rule.observerGroupCurrent(groups[idx]) {
		if next, err = refreshObserverGroup(next, idx, rule); err != nil {
			return err
		}
	} else if strays == 0 {
		return nil
	}
	hooks.set(rule.event, next)
	return nil
}

// observerGroupCurrent reports whether group, Observer's group on the
// event, already holds exactly the entry this writer emits: not drifted
// (T-847), one Observer handler, running rule.cmd, on a matcher rule keeps.
// A developer's handler beside it does not change the answer.
func (rule groupEntryRule) observerGroupCurrent(group json.RawMessage) bool {
	return !rule.drift && groupedHookEntries.soleObserverCommand(group, rule.ours, rule.cmd) && rule.matcherKept(group)
}

// matcherKept reports whether group's matcher is one this writer keeps for
// its own entry: any (the T-847 shape check judges it) unless exactMatcher,
// which keeps only rule.matcher itself (Codex rewrites a group with no
// matcher to "*").
func (rule groupEntryRule) matcherKept(group json.RawMessage) bool {
	return !rule.exactMatcher || groupedHookEntries.matcher(group) == rule.matcher
}

// observerMatcher reports whether a group on matcher m selects the same
// tools as the group Observer writes: the same matcher, or both match-all
// ("*" and an absent matcher, claudeMatcherCanonical).
func (rule groupEntryRule) observerMatcher(m string) bool {
	return m == rule.matcher || (claudeMatcherCanonical(m) && claudeMatcherCanonical(rule.matcher))
}

// refreshObserverGroup returns groups with Observer's stale entry in
// groups[idx] replaced by its current one, keeping every position on the
// event it can. Codex trusts a handler by its position
// ("<path>:<event>:<group>:<handler>", internal/codextrust), so a developer's
// handler that moved would silently stop running there.
//
//   - Observer's group still in the shape this writer emits (not drifted,
//     and on a matcher rule keeps): only Observer's handler is replaced, in
//     its own place in the group; a developer's handler beside it keeps its
//     group and handler position.
//   - Otherwise (T-847 drift, or Codex's group not on "*") the group's own
//     matcher or members are not Observer's to keep, so Observer's handlers
//     leave it. A group left with no handler is replaced by Observer's fresh
//     group at the same index; a group still holding a developer's handler
//     stays where it is, and Observer's fresh group is appended after the
//     event's last group, so no other group moves.
func refreshObserverGroup(groups []json.RawMessage, idx int, rule groupEntryRule) ([]json.RawMessage, error) {
	l := groupedHookEntries
	next := append([]json.RawMessage{}, groups...)
	if !rule.drift && rule.matcherKept(groups[idx]) {
		g, err := l.replaceObserverHandler(groups[idx], rule.ours, rule.cmd)
		if err != nil {
			return nil, err
		}
		next[idx] = g
		return next, nil
	}
	entry, err := observerGroupEntry(rule.matcher, rule.cmd)
	if err != nil {
		return nil, fmt.Errorf("marshal entry: %w", err)
	}
	rest, _, _, err := l.removeHandlers(groups[idx:idx+1], rule.ours)
	if err != nil {
		return nil, err
	}
	if len(rest) == 0 {
		next[idx] = entry
		return next, nil
	}
	next[idx] = rest[0]
	return append(next, entry), nil
}

// replaceObserverHandler returns the matcher group entry with the first
// command handler ours recognises replaced, in its place, by Observer's
// handler for cmd, and any further one ours recognises dropped. Every other
// member and handler keeps its data and its place.
func (l hookEntryLayout) replaceObserverHandler(entry json.RawMessage, ours func(string) bool, cmd string) (json.RawMessage, error) {
	fresh, err := observerHandler(cmd)
	if err != nil {
		return nil, fmt.Errorf("marshal entry: %w", err)
	}
	hs := l.handlers(entry)
	out := make([]json.RawMessage, 0, len(hs))
	placed := false
	for _, h := range hs {
		if c, ok := l.command(h); ok && ours(c) {
			if !placed {
				out = append(out, fresh)
				placed = true
			}
			continue
		}
		out = append(out, h)
	}
	list, err := marshalHookJSON(out)
	if err != nil {
		return nil, err
	}
	g, err := credfile.SetObjectMember(entry, "hooks", list, true)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(bytes.TrimSpace(g)), nil
}

// scopedGroups returns the groups whose matcher scope accepts (every group
// when scope is nil).
func scopedGroups(groups []json.RawMessage, scope func(string) bool) []json.RawMessage {
	if scope == nil {
		return groups
	}
	var out []json.RawMessage
	for _, g := range groups {
		if scope(groupedHookEntries.matcher(g)) {
			out = append(out, g)
		}
	}
	return out
}
