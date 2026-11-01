package secfeedback

import (
	"bytes"
	"encoding/json"
	"strings"
)

// The feedback dialect ids: the Dialect of each post-phase context_inject
// hook binding in internal/integration (spelled again here because that
// package's ids are unexported; TestEveryPostContextBindingHasAWriter keeps
// the two in step).
const (
	DialectClaude = "feedback-claude"
	DialectCodex  = "feedback-codex"
	DialectGemini = "feedback-gemini"
	DialectCline  = "feedback-cline"
	DialectPlugin = "feedback-plugin"
	DialectCursor = "feedback-cursor"
)

// PluginContextField is the field of the plugin shim's reply whose text the
// shim appends to the tool's output (observer-shim.ts tool.execute.after).
const PluginContextField = "context"

// writer is one reply shape: where the text goes, the event name a
// hookSpecificOutput envelope names when the caller gives none, and the
// largest text the host is sent.
type writer struct {
	// nested puts the text in hookSpecificOutput.additionalContext beside
	// hookEventName; otherwise it is the top-level field.
	nested bool
	field  string
	// defaultEvent is hookEventName when the caller passes no event.
	defaultEvent string
	// maxBytes caps the joined text; whole lines are dropped from the end
	// until it fits.
	maxBytes int
}

// writers is the reply-writer table, one row per dialect (security pillar
// plan section 4.7, JSP-6 "What the plans should change" and its live
// half). Caps are the host's documented limit where one exists, else a
// conservative bound well above three lines.
var writers = map[string]writer{
	// Claude Code and Qoder: hookSpecificOutput.additionalContext next to
	// the kept "decision":"approve"; Claude Code spills over 10,000
	// characters to a file.
	DialectClaude: {nested: true, field: "additionalContext", defaultEvent: "PostToolUse", maxBytes: 10000},
	// Codex: a separate developer message; its default cap is 2,500
	// tokens, so 8,000 bytes stays under it.
	DialectCodex: {nested: true, field: "additionalContext", defaultEvent: "PostToolUse", maxBytes: 8000},
	// Gemini CLI (AfterTool) and Qwen Code (PostToolUse): appended to the
	// tool result.
	DialectGemini: {nested: true, field: "additionalContext", defaultEvent: "AfterTool", maxBytes: 8000},
	// Cline file hooks: contextModification, truncated at 50 KB by the
	// extension.
	DialectCline: {field: "contextModification", maxBytes: 8000},
	// OpenCode and Kilo: the shim appends the context to output.output.
	DialectPlugin: {field: PluginContextField, maxBytes: 8000},
	// Cursor: additional_context on postToolUse, size-capped by the host
	// (the limit is not documented), so the bound is the smallest.
	DialectCursor: {field: "additional_context", maxBytes: 1000},
}

// Dialects returns the dialect ids that have a writer.
func Dialects() []string {
	out := make([]string, 0, len(writers))
	for d := range writers {
		out = append(out, d)
	}
	return out
}

// Supported reports whether dialect has a writer.
func Supported(dialect string) bool {
	_, ok := writers[dialect]
	return ok
}

// MaxBytes returns the dialect's text cap (0 for an unknown dialect).
func MaxBytes(dialect string) int { return writers[dialect].maxBytes }

// Text joins lines (one per line) within the dialect's cap, dropping whole
// lines from the end until it fits; "" when nothing fits or the dialect is
// unknown.
func Text(dialect string, lines []string) string {
	w, ok := writers[dialect]
	if !ok {
		return ""
	}
	if len(lines) > MaxLines {
		lines = lines[:MaxLines]
	}
	for n := len(lines); n > 0; n-- {
		t := strings.Join(lines[:n], "\n")
		if len(t) <= w.maxBytes {
			return t
		}
	}
	return ""
}

// Write merges lines into reply, the JSON object the host's post-tool
// receiver writes, and reports whether it changed anything. event names
// the host event for a hookSpecificOutput envelope ("" uses the dialect's
// default). An empty reply is read as {} (a host whose allow is an empty
// stdout). The reply is returned unchanged (and false) for an unknown
// dialect, no lines, a reply that is not one JSON object, or an envelope
// whose hookEventName names another event. A context the reply already
// carries is kept, and the feedback is appended after it on a new line.
// Every other field of the reply is kept byte for byte.
func Write(dialect, event string, reply []byte, lines []string) ([]byte, bool) {
	w, ok := writers[dialect]
	if !ok {
		return reply, false
	}
	text := Text(dialect, lines)
	if text == "" {
		return reply, false
	}
	trimmed := bytes.TrimSpace(reply)
	obj := map[string]json.RawMessage{}
	if len(trimmed) > 0 {
		if trimmed[0] != '{' || json.Unmarshal(trimmed, &obj) != nil || obj == nil {
			return reply, false
		}
	}
	if w.nested {
		if event == "" {
			event = w.defaultEvent
		}
		inner := map[string]json.RawMessage{}
		if raw, has := obj["hookSpecificOutput"]; has {
			if json.Unmarshal(raw, &inner) != nil || inner == nil {
				return reply, false
			}
			if n, has := inner["hookEventName"]; has {
				var name string
				if json.Unmarshal(n, &name) != nil || name != event {
					return reply, false
				}
			}
		}
		inner["hookEventName"] = mustString(event)
		merged, ok := appendText(inner[w.field], text)
		if !ok {
			return reply, false
		}
		inner[w.field] = merged
		raw, err := json.Marshal(inner)
		if err != nil {
			return reply, false
		}
		obj["hookSpecificOutput"] = raw
	} else {
		merged, ok := appendText(obj[w.field], text)
		if !ok {
			return reply, false
		}
		obj[w.field] = merged
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return reply, false
	}
	return append(out, '\n'), true
}

// appendText returns text as a JSON string, after the string prev already
// holds (on a new line). A prev that is not a string refuses.
func appendText(prev json.RawMessage, text string) (json.RawMessage, bool) {
	if len(prev) > 0 {
		var s string
		if json.Unmarshal(prev, &s) != nil {
			return nil, false
		}
		if s != "" {
			text = s + "\n" + text
		}
	}
	return mustString(text), true
}

func mustString(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}
