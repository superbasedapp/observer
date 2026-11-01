package hook

import (
	"encoding/json"
	"os"
)

// hook_shape.go - T-847: an Observer hook entry is "already set" only in the
// exact shape its writer emits.
//
// Every registrar used to decide "already set" from the entry's COMMAND
// alone. A developer could keep the command and weaken what surrounds it (a
// narrowed matcher so the gate only sees one tool, a tiny timeout so the host
// gives up before the gate answers), and `observer start` then re-recorded
// the weakened file in hook_checksums.json as the new baseline. Several
// writers decode entries into typed structs that cannot even see an extra
// field. This file is the one raw-JSON shape check those writers share: it
// names the events whose Observer entry differs in shape, and each writer
// sends those events down its existing rewrite path (so the rewrite is a
// reported add, and a repair when the event had been registered before).

// entryShape describes the canonical shape of Observer's entry in one hook
// format. It is data, one value per format family, never a tool branch.
type entryShape struct {
	// grouped is true when an event's entries are matcher groups
	// ({"matcher": ..., "hooks": [handler]}); false for a flat handler list.
	grouped bool
	// ours recognises an Observer command for this target.
	ours func(cmd string) bool
	// commandKey is the handler field carrying the command ("command").
	commandKey string
	// handlerFields are the only fields Observer's handler carries.
	handlerFields map[string]bool
	// matcherOK accepts the group matcher Observer writes (grouped only).
	matcherOK func(string) bool
}

// claudeShapedGroups is the Claude-Code-shaped matcher-group family
// (Claude Code on Windows, Codex, Factory Droid, Gemini CLI, Qwen Code,
// Qoder): {"matcher": "*"|absent, "hooks": [{"type","command"}]}.
func claudeShapedGroups(ours func(string) bool) entryShape {
	return entryShape{
		grouped:       true,
		ours:          ours,
		commandKey:    "command",
		handlerFields: map[string]bool{"type": true, "command": true},
		matcherOK:     claudeMatcherCanonical,
	}
}

// flatCommandEntries is the flat {"command": ...} family (Cursor, Windsurf
// Cascade): Observer's entry carries nothing but the command.
func flatCommandEntries(ours func(string) bool) entryShape {
	return entryShape{
		ours:          ours,
		commandKey:    "command",
		handlerFields: map[string]bool{"command": true},
	}
}

// shapeDriftEvents returns the events in hooksRaw (a JSON object mapping an
// event name to its entry list) whose Observer entry is not in s's canonical
// shape. Unparseable input yields no events: the writer's own parse reports
// it.
func shapeDriftEvents(hooksRaw json.RawMessage, s entryShape) map[string]bool {
	out := map[string]bool{}
	if len(hooksRaw) == 0 {
		return out
	}
	var byEvent map[string][]json.RawMessage
	if json.Unmarshal(hooksRaw, &byEvent) != nil {
		return out
	}
	for event, entries := range byEvent {
		if entriesShapeDrift(entries, s) {
			out[event] = true
		}
	}
	return out
}

// entriesShapeDrift reports whether any Observer entry in entries (one
// event's list) is not in s's canonical shape.
func entriesShapeDrift(entries []json.RawMessage, s entryShape) bool {
	for _, raw := range entries {
		if s.grouped {
			if groupShapeDrift(raw, s) {
				return true
			}
			continue
		}
		if ours, canonical := handlerShape(raw, s); ours && !canonical {
			return true
		}
	}
	return false
}

// groupShapeDrift reports whether a matcher group that holds an Observer
// handler has a non-canonical matcher, an extra group field, or a
// non-canonical Observer handler.
func groupShapeDrift(raw json.RawMessage, s entryShape) bool {
	var g map[string]json.RawMessage
	if json.Unmarshal(raw, &g) != nil {
		return false
	}
	var handlers []json.RawMessage
	if json.Unmarshal(g["hooks"], &handlers) != nil {
		return false
	}
	holdsOurs, drift := false, false
	for _, h := range handlers {
		ours, canonical := handlerShape(h, s)
		if ours {
			holdsOurs = true
			drift = drift || !canonical
		}
	}
	if !holdsOurs {
		return false
	}
	for k := range g {
		if k != "matcher" && k != "hooks" {
			return true
		}
	}
	var matcher string
	if m, ok := g["matcher"]; ok && json.Unmarshal(m, &matcher) != nil {
		return true
	}
	if s.matcherOK != nil && !s.matcherOK(matcher) {
		return true
	}
	return drift
}

// handlerShape reports whether raw is an Observer handler and, if so,
// whether it carries only the fields Observer writes.
func handlerShape(raw json.RawMessage, s entryShape) (ours, canonical bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return false, false
	}
	var cmd string
	if json.Unmarshal(m[s.commandKey], &cmd) != nil || !s.ours(cmd) {
		return false, false
	}
	for k := range m {
		if !s.handlerFields[k] {
			return true, false
		}
	}
	return true, true
}

// fileHooksRaw returns the top-level "hooks" member of the JSON file at path
// (nil when absent or unreadable).
func fileHooksRaw(path string) json.RawMessage {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil {
		return nil
	}
	return top["hooks"]
}

// shapeRewrite records the T-847 shape rewrite of event on res.
func shapeRewrite(res *RegistrationResult, event, from, to string) {
	res.Rewrites = append(res.Rewrites, Rewrite{
		Event: event, Rule: shapeRewriteRule, Reason: shapeRewriteReason, From: from, To: to,
	})
}
