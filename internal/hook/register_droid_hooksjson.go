package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
)

// Factory Droid's hooks.json keeps its event map at the ROOT of the
// object: {"PreToolUse":[{"matcher":"*","hooks":[...]}],...}. Only
// settings.json wraps the same map under a "hooks" key
// (docs.factory.com/reference/hooks-reference, "JSON Structure").
//
// Observer's writer used to reuse Codex's {"hooks":{...}} shape here. Live
// on demo node 1 (droid 0.233.0, 2026-10-04) droid logged "Ignoring unknown
// hook event keys" with keys ["hooks"] for both the user-level file and a
// project-level file Observer had written, and no Observer hook ever
// fired. readDroidHooks lifts Observer's own groups out of that legacy
// wrapper to the root, so the next registration (`observer init`, or the
// `observer start` auto-register for the events it writes) repairs an
// existing install; a group Observer did not write stays wrapped.

// droidHooksDoc is a decoded droid hooks.json. Each root value stays raw so
// a group Observer does not own (with droid fields such as commandRegex or
// a per-hook timeout) survives a rewrite unchanged.
type droidHooksDoc map[string]json.RawMessage

// readDroidHooks reads path. A missing or empty file is an empty document.
//
// When the file carries the legacy {"hooks":{...}} wrapper, only groups
// OBSERVER wrote (every command in the group is an Observer droid entry) of
// an event lift(event) admits are moved to the root (appended after any
// root groups for the same event); lifted names those events. Every other
// wrapped group stays in the wrapper exactly as it was (review M2-15):
// droid ignores the wrapper, so a user's group there has never run, and
// lifting it would start running a command the user never saw fire. Nor is
// an Observer group lifted for an event the caller will not write (an
// `observer start` event that still owes its live test, review M2-10). The
// wrapper is dropped once nothing is left in it.
func readDroidHooks(path string, lift func(event string) bool) (droidHooksDoc, map[string]bool, error) {
	doc := droidHooksDoc{}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return doc, nil, nil
		}
		return nil, nil, fmt.Errorf("readDroidHooks: read: %w", err)
	}
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
	if len(bytes.TrimSpace(raw)) == 0 {
		return doc, nil, nil
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, fmt.Errorf("readDroidHooks: parse %s: %w", path, err)
	}
	if doc == nil {
		return droidHooksDoc{}, nil, nil
	}
	wrapped, ok := doc["hooks"]
	if !ok {
		return doc, nil, nil
	}
	var inner map[string][]json.RawMessage
	if json.Unmarshal(wrapped, &inner) != nil {
		// Not the legacy event map: an unknown "hooks" value is kept as is.
		return doc, nil, nil
	}
	events := make([]string, 0, len(inner))
	for event := range inner {
		events = append(events, event)
	}
	sort.Strings(events)
	lifted := map[string]bool{}
	for _, event := range events {
		var move, keep []json.RawMessage
		for _, g := range inner[event] {
			if lift != nil && lift(event) && droidGroupIsObservers(g) {
				move = append(move, g)
			} else {
				keep = append(keep, g)
			}
		}
		if len(keep) == 0 {
			delete(inner, event)
		} else {
			inner[event] = keep
		}
		if len(move) == 0 {
			continue
		}
		cur, err := doc.groups(event)
		if err != nil {
			return nil, nil, fmt.Errorf("readDroidHooks: %s: %w", path, err)
		}
		if err := doc.setGroups(event, append(cur, move...)); err != nil {
			return nil, nil, fmt.Errorf("readDroidHooks: %s: %w", path, err)
		}
		lifted[event] = true
	}
	if len(lifted) == 0 {
		return doc, nil, nil
	}
	if len(inner) == 0 {
		delete(doc, "hooks")
	} else {
		b, err := marshalHookJSON(inner)
		if err != nil {
			return nil, nil, fmt.Errorf("readDroidHooks: %s: %w", path, err)
		}
		doc["hooks"] = b
	}
	return doc, lifted, nil
}

// droidGroupIsObservers reports whether a matcher group holds only
// Observer's own droid hook entries (at least one).
func droidGroupIsObservers(g json.RawMessage) bool {
	hs := droidGroupCommands(g)
	if len(hs) == 0 {
		return false
	}
	for _, h := range hs {
		if h.Type != "command" || !isObserverAnyHookEntry(h.Command, "droid") {
			return false
		}
	}
	return true
}

// groups returns event's matcher groups (nil when absent or null).
func (d droidHooksDoc) groups(event string) ([]json.RawMessage, error) {
	raw, ok := d[event]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var gs []json.RawMessage
	if err := json.Unmarshal(raw, &gs); err != nil {
		return nil, fmt.Errorf("event %s is not a list of matcher groups: %w", event, err)
	}
	return gs, nil
}

// setGroups stores event's groups; an empty list removes the event.
func (d droidHooksDoc) setGroups(event string, gs []json.RawMessage) error {
	if len(gs) == 0 {
		delete(d, event)
		return nil
	}
	b, err := marshalHookJSON(gs)
	if err != nil {
		return fmt.Errorf("encode %s: %w", event, err)
	}
	d[event] = b
	return nil
}

// droidGroupCommands decodes a matcher group's hook entries for the
// ownership checks; a group that does not decode has none.
func droidGroupCommands(g json.RawMessage) []claudeHookCommand {
	var cg codexHookGroup
	if err := json.Unmarshal(g, &cg); err != nil {
		return nil
	}
	return cg.Hooks
}

// writeDroidHooks writes doc as 2-space-indented JSON with sorted root
// keys. Callers own the advisory lock and pass the target pinned before
// the read (pinnedTarget, F6), exactly as for writeCodexHooksFile.
func writeDroidHooks(dir string, pinned pinnedTarget, doc droidHooksDoc) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("hook.writeDroidHooks: mkdir: %w", err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(map[string]json.RawMessage(doc)); err != nil {
		return fmt.Errorf("hook.writeDroidHooks: encode: %w", err)
	}
	if err := atomicWriteFile(pinned, buf.Bytes()); err != nil {
		return fmt.Errorf("hook.writeDroidHooks: %w", err)
	}
	return nil
}
