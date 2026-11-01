package hook

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/jsonv1compat"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Proposed content of a write or edit tool call (T-910), carried on the
// policy event so the R-162 rows can judge what a write puts into a
// hook-bearing settings file instead of the path alone. Field spellings are
// data, shared by every pre-tool payload (Claude Code's Write / Edit /
// MultiEdit and the Claude-shaped and vendor-shaped families the tool gate
// reads), never keyed on a tool name. The spellings are the ones the line
// counter (internal/loc/extract.go) and the adapters already ground.

// isWriteAction reports whether an action verb writes its file target (the
// write and edit verbs of the models taxonomy).
func isWriteAction(actionType string) bool {
	return actionType == models.ActionWriteFile || actionType == models.ActionEditFile
}

// toolInputMap decodes a Claude-shaped payload's tool input (tool_input or
// toolInput, an object or a JSON-encoded string) into a map; empty when it
// has none.
func toolInputMap(body []byte) map[string]any {
	var p struct {
		ToolInput      json.RawMessage `json:"tool_input"`
		ToolInputCamel json.RawMessage `json:"toolInput"`
	}
	if json.Unmarshal(bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF}), &p) != nil {
		return nil
	}
	raw := p.ToolInput
	if len(raw) == 0 {
		raw = p.ToolInputCamel
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		raw = []byte(s)
	}
	m := map[string]any{}
	// Go 1.26 result for an out-of-range number (internal/jsonv1compat).
	_ = jsonv1compat.UnmarshalObject(raw, &m)
	return m
}

// editPairFields are the (old, new) field pairs of a replace-style edit.
var editPairFields = [][2]string{
	{"old_string", "new_string"},
	{"oldString", "newString"},
	{"old_str", "new_str"},
	{"old_text", "new_text"},
	{"oldText", "newText"},
}

// wholeContentFields carry a write's whole new file content.
var wholeContentFields = []string{"content", "file_text", "contents", "fileText"}

// replaceAllFields carry an edit's replace-every-occurrence flag.
var replaceAllFields = []string{"replace_all", "replaceAll"}

// editListFields carry a list of edits applied in order (MultiEdit).
var editListFields = []string{"edits"}

// proposedEditsIn reads the proposed content of a write or edit from its
// tool input: an edit list first, then a single replace pair, then a whole
// content field. Nil when the input carries none of them.
func proposedEditsIn(input map[string]any) []policy.ProposedEdit {
	for _, f := range editListFields {
		list, ok := input[f].([]any)
		if !ok {
			continue
		}
		var out []policy.ProposedEdit
		for _, item := range list {
			if m, ok := item.(map[string]any); ok {
				if e, ok := replaceEditIn(m); ok {
					out = append(out, e)
				}
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	if e, ok := replaceEditIn(input); ok {
		return []policy.ProposedEdit{e}
	}
	for _, f := range wholeContentFields {
		if s, ok := input[f].(string); ok {
			return []policy.ProposedEdit{{Kind: policy.EditWhole, New: s}}
		}
	}
	return nil
}

// replaceEditIn reads one replace-style edit (any spelling pair).
func replaceEditIn(m map[string]any) (policy.ProposedEdit, bool) {
	for _, p := range editPairFields {
		newText, ok := m[p[1]].(string)
		if !ok {
			continue
		}
		oldText, _ := m[p[0]].(string)
		e := policy.ProposedEdit{Kind: policy.EditReplace, Old: oldText, New: newText}
		for _, f := range replaceAllFields {
			if b, ok := m[f].(bool); ok && b {
				e.All = true
			}
		}
		return e, true
	}
	return policy.ProposedEdit{}, false
}

// patchEditsFor reads the part of an apply_patch envelope (any string input
// field holding one) that touches target: an added file is its whole
// content, an updated file is a fragment of the lines it removes and adds
// (hunks cannot be replayed onto the file without their context).
func patchEditsFor(input map[string]any, target string) []policy.ProposedEdit {
	keys := make([]string, 0, len(input))
	for k := range input {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s, ok := input[k].(string)
		if !ok || !strings.Contains(s, "*** Begin Patch") {
			continue
		}
		if e, ok := patchSectionEdit(s, target); ok {
			return []policy.ProposedEdit{e}
		}
	}
	return nil
}

// patchSectionEdit collects the added and removed lines of target's
// section(s) of one patch envelope.
func patchSectionEdit(patch, target string) (policy.ProposedEdit, bool) {
	var added, removed []string
	in, adding, found := false, false, false
	for _, line := range strings.Split(patch, "\n") {
		trimmed := strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(trimmed, "*** "); ok {
			in = false
			for _, h := range []string{"Add File:", "Update File:"} {
				if p, ok := strings.CutPrefix(rest, h); ok && strings.TrimSpace(p) == target {
					in, adding, found = true, h == "Add File:", true
				}
			}
			continue
		}
		if !in {
			continue
		}
		switch {
		case strings.HasPrefix(line, "+"):
			added = append(added, line[1:])
		case strings.HasPrefix(line, "-"):
			removed = append(removed, line[1:])
		}
	}
	if !found {
		return policy.ProposedEdit{}, false
	}
	if adding && len(removed) == 0 {
		return policy.ProposedEdit{Kind: policy.EditWhole, New: strings.Join(added, "\n")}, true
	}
	return policy.ProposedEdit{Kind: policy.EditFragment, Old: strings.Join(removed, "\n"), New: strings.Join(added, "\n")}, true
}
