package cloudsession

import (
	"errors"
	"fmt"
	"strings"
)

// hooks.go renders the two JSON hook files: the shared .claude/settings.json
// (merged, Observer's groups appended) and the dedicated Copilot hooks file.
// Both are edited through the order-preserving tree in jsonedit.go, and both
// recognise Observer's entries by OwnerTag, so init is idempotent (it strips
// its own entries before adding them again) and remove takes out exactly
// what init added.

// copilotDefaultTimeout is the timeoutSec written on a Copilot capture hook
// (the value internal/hook writes for the local Copilot CLI hooks file).
const copilotDefaultTimeout = 30

// errNotObject reports a JSON file whose expected object is something else.
var errNotObject = errors.New("is not a JSON object")

// loadEditable parses an existing JSON file for editing. A missing or blank
// file starts as an empty object written with a trailing newline.
func loadEditable(before string, existed bool, reformat bool) (jsonDoc, string, error) {
	if !existed || strings.TrimSpace(before) == "" {
		return jsonDoc{root: jObj(), trailingNewline: true, roundTrips: true}, "", nil
	}
	doc, err := loadJSONDoc(before)
	if err != nil {
		return jsonDoc{}, "", fmt.Errorf("not valid JSON (%w); fix it first", err)
	}
	if doc.root.kind != jObject {
		return jsonDoc{}, "", fmt.Errorf("the top level %w", errNotObject)
	}
	if !doc.roundTrips {
		if !reformat {
			return jsonDoc{}, "", fmt.Errorf("the file is not in two-space JSON layout, so Observer could not later remove its entries byte-for-byte; reformat it (or pass --reformat to let init rewrite it in that layout)")
		}
		return doc, "reformatted to two-space JSON layout (--reformat)", nil
	}
	return doc, "", nil
}

// childObject returns parent[key] as an object, creating it when absent.
func childObject(parent *jnode, key string) (*jnode, error) {
	n := parent.get(key)
	if n == nil {
		n = jObj()
		parent.set(key, n)
		return n, nil
	}
	if n.kind != jObject {
		return nil, fmt.Errorf("%q %w", key, errNotObject)
	}
	return n, nil
}

// childArray returns parent[key] as an array, creating it when absent.
func childArray(parent *jnode, key string) (*jnode, error) {
	n := parent.get(key)
	if n == nil {
		n = &jnode{kind: jArray}
		parent.set(key, n)
		return n, nil
	}
	if n.kind != jArray {
		return nil, fmt.Errorf("%q is not a JSON array", key)
	}
	return n, nil
}

// ownedEntry reports whether an entry object's command field (commandKey)
// is an Observer cloud-session command.
func ownedEntry(n *jnode, commandKey string) bool {
	s, ok := n.get(commandKey).stringValue()
	return ok && isOwnedCommand(s)
}

// stripOwnedEntries removes owned entries from arr (in place) and reports
// how many it removed.
func stripOwnedEntries(arr *jnode, commandKey string) int {
	if arr == nil || arr.kind != jArray {
		return 0
	}
	kept := arr.items[:0:0]
	removed := 0
	for _, it := range arr.items {
		if it.kind == jObject && ownedEntry(it, commandKey) {
			removed++
			continue
		}
		kept = append(kept, it)
	}
	arr.items = kept
	return removed
}

// stripEventMap removes Observer's entries from a hooks map whose values are
// arrays. grouped: each array item is a {matcher, hooks:[...]} group (Claude
// Code); otherwise the items are the entries themselves (Copilot). An event
// key, group or the map itself is dropped only when Observer's removal is
// what emptied it, so a container the team left empty stays.
func stripEventMap(hooks *jnode, grouped bool, commandKey string) int {
	if hooks == nil || hooks.kind != jObject {
		return 0
	}
	total := 0
	for _, event := range append([]string(nil), hooks.keys...) {
		arr := hooks.get(event)
		if arr == nil || arr.kind != jArray {
			continue
		}
		removed := 0
		if grouped {
			kept := arr.items[:0:0]
			for _, g := range arr.items {
				inner := g.get("hooks")
				n := stripOwnedEntries(inner, commandKey)
				removed += n
				if n > 0 && inner != nil && len(inner.items) == 0 {
					continue // Observer's own group
				}
				kept = append(kept, g)
			}
			arr.items = kept
		} else {
			removed = stripOwnedEntries(arr, commandKey)
		}
		total += removed
		if removed > 0 && len(arr.items) == 0 {
			hooks.del(event)
		}
	}
	return total
}

// commandEntry builds one {type: command, <commandKey>: cmd, <timeoutKey>: n}.
func commandEntry(commandKey, cmd, timeoutKey string, timeout int) *jnode {
	n := jObj("type", jString("command"), commandKey, jString(cmd))
	if timeoutKey != "" && timeout > 0 {
		n.set(timeoutKey, jInt(timeout))
	}
	return n
}

// insertClaudeSettings merges the agent's hook groups into
// .claude/settings.json: one group per binding, appended after the team's own.
func insertClaudeSettings(a Agent, opts PlanOptions, before string, existed bool) (string, string, []string, error) {
	doc, note, err := loadEditable(before, existed, opts.Reformat)
	if err != nil {
		return "", "", nil, err
	}
	if hooks := doc.root.get("hooks"); hooks != nil {
		n := stripEventMap(hooks, true, "command")
		if n > 0 && len(hooks.keys) == 0 {
			doc.root.del("hooks")
		}
	}
	hooks, err := childObject(doc.root, "hooks")
	if err != nil {
		return "", "", nil, err
	}
	for _, b := range a.Hooks {
		if !opts.enabled(b.Feature) {
			continue
		}
		cmd, err := hookCommand(a, b, opts)
		if err != nil {
			return "", "", nil, err
		}
		arr, err := childArray(hooks, b.Event)
		if err != nil {
			return "", "", nil, err
		}
		inner := &jnode{kind: jArray, items: []*jnode{commandEntry("command", cmd, "timeout", bindingTimeout(b))}}
		group := jObj("hooks", inner)
		if b.Matcher != "" {
			group = jObj("matcher", jString(b.Matcher), "hooks", inner)
		}
		arr.items = append(arr.items, group)
	}
	return doc.render(), note, nil, nil
}

// removeClaudeSettings takes Observer's groups back out. When nothing but
// Observer's hooks was ever in the file, the file is deleted.
func removeClaudeSettings(_ Agent, before string) (string, bool, string, error) {
	doc, err := loadJSONDoc(before)
	if err != nil || doc.root.kind != jObject {
		return before, false, "kept: not a JSON object, remove Observer's entries by hand", nil
	}
	hooks := doc.root.get("hooks")
	n := stripEventMap(hooks, true, "command")
	if n == 0 {
		return before, false, "", nil
	}
	if len(hooks.keys) == 0 {
		doc.root.del("hooks")
	}
	if len(doc.root.keys) == 0 {
		return "", true, "", nil
	}
	note := ""
	if !doc.roundTrips {
		note = "the file was not in two-space JSON layout; it is rewritten in that layout"
	}
	return doc.render(), false, note, nil
}

// insertCopilotHooks writes Observer's dedicated Copilot hooks file. A file
// the team since added its own entries to keeps them.
func insertCopilotHooks(a Agent, opts PlanOptions, before string, existed bool) (string, string, []string, error) {
	doc, note, err := loadEditable(before, existed, opts.Reformat)
	if err != nil {
		return "", "", nil, err
	}
	if hooks := doc.root.get("hooks"); hooks != nil {
		stripEventMap(hooks, false, "bash")
	}
	if doc.root.get("version") == nil {
		// version leads the file the way the vendor docs write it.
		doc.root.keys = append([]string{"version"}, doc.root.keys...)
		doc.root.vals = append([]*jnode{jInt(1)}, doc.root.vals...)
	}
	hooks, err := childObject(doc.root, "hooks")
	if err != nil {
		return "", "", nil, err
	}
	for _, b := range a.Hooks {
		if !opts.enabled(b.Feature) {
			continue
		}
		cmd, err := hookCommand(a, b, opts)
		if err != nil {
			return "", "", nil, err
		}
		arr, err := childArray(hooks, b.Event)
		if err != nil {
			return "", "", nil, err
		}
		timeout := bindingTimeout(b)
		if timeout == 0 {
			timeout = copilotDefaultTimeout
		}
		arr.items = append(arr.items, commandEntry("bash", cmd, "timeoutSec", timeout))
	}
	return doc.render(), note, nil, nil
}

// removeCopilotHooks deletes the dedicated file when only Observer's entries
// were in it, and otherwise takes just those entries out.
func removeCopilotHooks(_ Agent, before string) (string, bool, string, error) {
	doc, err := loadJSONDoc(before)
	if err != nil || doc.root.kind != jObject {
		return before, false, "kept: not a JSON object, remove it by hand", nil
	}
	hooks := doc.root.get("hooks")
	if stripEventMap(hooks, false, "bash") == 0 {
		return before, false, "", nil
	}
	onlyOurs := hooks != nil && len(hooks.keys) == 0
	for _, k := range doc.root.keys {
		if k != "version" && k != "hooks" {
			onlyOurs = false
		}
	}
	if onlyOurs {
		return "", true, "", nil
	}
	return doc.render(), false, "", nil
}
