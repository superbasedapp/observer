package vtcode

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"
)

// archiveFile is the decoded subset of a global session archive
// (`<state dir>/sessions/<session-id>.json`), written by VT Code when a
// session starts and rewritten at its end.
//
// Grounded live (0.180.2, 18 archives across WSL + Windows): top-level
// metadata, started_at, ended_at, total_messages, distinct_tools,
// transcript, messages and (TUI only) progress. `messages` is the
// provider-shaped conversation: role User / Assistant / Tool / System,
// content (a string, or an array of {text} parts), Assistant tool_calls
// [{id, function{name, arguments}}] whose ids equal events.jsonl's
// tool_call_id, Tool rows keyed by tool_call_id, and the model's own
// reasoning on Assistant rows (`reasoning`, plus `reasoning_details`).
// Under operator rulings 2 and 4 (2026-10-21) the adapter reads
// messages for the model reasoning column, the transcript reader, and
// the archive-only parse of a session whose workspace event log is gone.
// `transcript` (the rendered TUI scrollback) and `progress` are never
// decoded.
type archiveFile struct {
	Metadata  archiveMeta      `json:"metadata"`
	StartedAt string           `json:"started_at"`
	EndedAt   string           `json:"ended_at"`
	Messages  []archiveMessage `json:"messages"`
}

// archiveMessage is one entry of an archive's `messages` array.
type archiveMessage struct {
	Role             string            `json:"role"`
	Content          json.RawMessage   `json:"content"`
	ToolCalls        []archiveToolCall `json:"tool_calls"`
	ToolCallID       string            `json:"tool_call_id"`
	Reasoning        string            `json:"reasoning"`
	ReasoningDetails []json.RawMessage `json:"reasoning_details"`
	Phase            string            `json:"phase"`
	OriginTool       string            `json:"origin_tool"`
	Metadata         *struct {
		// Timestamp is Unix SECONDS (live: 1792573484 for a 09:04:44Z
		// prompt). Only TUI user messages carry it.
		Timestamp int64  `json:"timestamp"`
		Source    string `json:"source"`
	} `json:"metadata"`
}

// archiveToolCall is one Assistant tool call; Arguments is the JSON text
// the model produced.
type archiveToolCall struct {
	ID       string `json:"id"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// Archive roles (VT Code serializes its MessageRole enum in Pascal case).
const (
	roleUser      = "user"
	roleAssistant = "assistant"
	roleTool      = "tool"
)

// role returns the message role lower-cased.
func (m *archiveMessage) role() string { return strings.ToLower(strings.TrimSpace(m.Role)) }

// text flattens the content: a JSON string, or the concatenated `text`
// of an array of parts (the exec-mode shape).
func (m *archiveMessage) text() string {
	return contentText(m.Content)
}

// contentText flattens an archive `content` value.
func contentText(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) == nil {
		var b strings.Builder
		for _, p := range parts {
			if p.Text == "" {
				continue
			}
			if b.Len() > 0 {
				b.WriteString("\n")
			}
			b.WriteString(p.Text)
		}
		return b.String()
	}
	return ""
}

// reasoningText returns the message's model reasoning: the `reasoning`
// string, else the concatenated text of `reasoning_details` entries
// (each an object, or a JSON string encoding one).
func (m *archiveMessage) reasoningText() string {
	if r := strings.TrimSpace(m.Reasoning); r != "" {
		return r
	}
	var b strings.Builder
	for _, raw := range m.ReasoningDetails {
		var d struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(raw, &d) != nil {
			var s string
			if json.Unmarshal(raw, &s) != nil || json.Unmarshal([]byte(s), &d) != nil {
				continue
			}
		}
		b.WriteString(d.Text)
	}
	return strings.TrimSpace(b.String())
}

// isRealPrompt reports whether a User message is operator input. TUI
// prompts carry metadata.source "user_input"; harness-injected user rows
// carry another source ("synthetic": task-tracker nudges, grounded live)
// and are not prompts. exec-mode archives mark the task itself not at
// all: when no message is marked user_input, the FIRST User message is
// the task and later unmarked ones are harness instructions.
func (m *archiveMessage) isRealPrompt(anyUserInput, firstUser bool) bool {
	if m.Metadata != nil && m.Metadata.Source != "" {
		return m.Metadata.Source == "user_input"
	}
	return !anyUserInput && firstUser
}

// hasUserInput reports whether any User message is marked user_input.
func hasUserInput(msgs []archiveMessage) bool {
	for i := range msgs {
		if msgs[i].role() == roleUser && msgs[i].Metadata != nil && msgs[i].Metadata.Source == "user_input" {
			return true
		}
	}
	return false
}

// archiveDoc is a decoded archive plus the derived reasoning lookups.
type archiveDoc struct {
	file archiveFile
	// reasoningByCall maps a tool_call id to the reasoning of the
	// Assistant message that issued it. Consumed-once per message: the
	// message's FIRST call carries it (the reasoning preceded that
	// message, not each call in it).
	reasoningByCall map[string]string
	// reasoningByText maps an Assistant message's trimmed text to its
	// reasoning, for a text-only message (no tool calls).
	reasoningByText map[string]string
}

// newArchiveDoc derives the lookups from a decoded archive.
func newArchiveDoc(f archiveFile) *archiveDoc {
	d := &archiveDoc{file: f, reasoningByCall: map[string]string{}, reasoningByText: map[string]string{}}
	for i := range f.Messages {
		m := &f.Messages[i]
		if m.role() != roleAssistant {
			continue
		}
		r := m.reasoningText()
		if r == "" {
			continue
		}
		if len(m.ToolCalls) > 0 {
			if id := m.ToolCalls[0].ID; id != "" {
				d.reasoningByCall[id] = r
			}
			continue
		}
		if t := strings.TrimSpace(m.text()); t != "" {
			d.reasoningByText[t] = r
		}
	}
	return d
}

// archiveCache memoizes decoded archives keyed on size + mtime, so a live
// events.jsonl tick costs no archive re-read until the archive changes.
type archiveCache struct {
	mu    sync.Mutex
	files map[string]cachedArchive
}

type cachedArchive struct {
	size  int64
	mtime time.Time
	doc   *archiveDoc
}

// load returns the decoded archive at path, or nil when it is missing or
// malformed.
func (c *archiveCache) load(path string) *archiveDoc {
	fi, err := os.Stat(path) //nolint:gosec // G703: stat of vtcode's per-user session archive, read only
	if err != nil || fi.IsDir() {
		return nil
	}
	c.mu.Lock()
	if c.files == nil {
		c.files = map[string]cachedArchive{}
	}
	if f, ok := c.files[path]; ok && f.size == fi.Size() && f.mtime.Equal(fi.ModTime()) {
		c.mu.Unlock()
		return f.doc
	}
	c.mu.Unlock()

	b, err := os.ReadFile(path) //nolint:gosec // archive JSON under a watch root
	if err != nil {
		return nil
	}
	var f archiveFile
	if json.Unmarshal(b, &f) != nil {
		return nil
	}
	doc := newArchiveDoc(f)
	c.mu.Lock()
	c.files[path] = cachedArchive{size: fi.Size(), mtime: fi.ModTime(), doc: doc}
	c.mu.Unlock()
	return doc
}
