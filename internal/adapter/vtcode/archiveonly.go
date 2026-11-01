package vtcode

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// parseArchiveOnly captures a session whose workspace event log no longer
// exists (a deleted scratch workspace, an unmounted drive) from the global
// archive's `messages` alone. Grounded 2026-10-21: the hook-probe
// workspaces on both OSes were deleted after the probe, leaving 16
// archives whose messages still hold every prompt, tool call (ids equal
// to events.jsonl's tool_call_id), tool result and the model reasoning.
//
// What this mode CANNOT recover, honestly absent: tokens (no usage in
// messages), the per-turn served model (the session-start metadata.model
// is used), turn ids, tool durations, and real timestamps for anything
// but TUI prompts (metadata.timestamp, Unix seconds). Other rows get a
// synthesized time — the preceding anchor plus one millisecond per
// message — so their ORDER is right and their clock is approximate.
//
// Rows are attributed to the would-be events.jsonl path (the
// CursorNoActions contract of the archive trigger) and reuse the events
// mode's ids where the archive carries the same key — session_start,
// session_end and `tool:<call id>` — so a re-parse in the other mode
// dedupes those. Prompt and assistant-text ids are content-derived here
// (the archive has no turn / item ids).
func (a *Adapter) parseArchiveOnly(ctx context.Context, archivePath, eventsPath, ws, sid string, doc *archiveDoc) adapter.ParseResult {
	var res adapter.ParseResult
	p := &parser{
		a:         a,
		path:      eventsPath,
		sessionID: sid,
		threadID:  sid,
		meta:      doc.file.Metadata,
		doc:       doc,
	}
	p.resolveProject(ws)

	start := parseTime(doc.file.StartedAt)
	clock := start
	tick := func() time.Time {
		if !clock.IsZero() {
			clock = clock.Add(time.Millisecond)
		}
		return clock
	}

	if !start.IsZero() {
		ev := p.base("session_start:"+sid, start, models.ActionSessionStart)
		ev.Target = "startup"
		ev.RawToolName = models.ToolVTCode + ".session_start"
		res.ToolEvents = append(res.ToolEvents, ev)
	}

	msgs := doc.file.Messages
	anyMarked := hasUserInput(msgs)

	type pendingCall struct {
		call      archiveToolCall
		ts        time.Time
		reasoning string
	}
	pending := map[string]*pendingCall{}
	var order []string
	seen := map[string]int{}
	contentID := func(kind, key string) string {
		seen[kind+key]++
		return fmt.Sprintf("%s:archive:%s", kind, hashID(fmt.Sprintf("%s#%d", key, seen[kind+key])))
	}
	model := strings.TrimSpace(p.meta.Model)
	firstUser := true

	for i := range msgs {
		if i%256 == 0 && ctx.Err() != nil {
			break
		}
		m := &msgs[i]
		switch m.role() {
		case roleUser:
			isFirst := firstUser
			firstUser = false
			ts := tick()
			if m.Metadata != nil && m.Metadata.Timestamp > 0 {
				ts = time.Unix(m.Metadata.Timestamp, 0).UTC()
				clock = ts
			}
			text := m.text()
			if strings.TrimSpace(text) == "" || !m.isRealPrompt(anyMarked, isFirst) {
				continue
			}
			scrubbed := a.scrubber.String(text)
			te := p.base(contentID("prompt", text+"|"+ts.Format(time.RFC3339)), ts, models.ActionUserPrompt)
			te.Target = truncate(scrubbed, 200)
			te.RawToolName = models.ToolVTCode + ".user_prompt"
			te.RawToolInput = scrubbed
			te.Model = model
			if effort := strings.TrimSpace(p.meta.ReasoningEffort); effort != "" {
				te.Metadata = &models.ActionMetadata{EffortLevel: effort}
			}
			res.ToolEvents = append(res.ToolEvents, te)
		case roleAssistant:
			ts := tick()
			reasoning := p.scrubReasoning(m.reasoningText())
			if text := m.text(); strings.TrimSpace(text) != "" {
				scrubbed := a.scrubber.String(text)
				te := p.base(contentID("assistant", strings.TrimSpace(text)), ts, models.ActionAssistantMessage)
				te.Model = model
				te.Target = truncate(scrubbed, 200)
				te.RawToolName = models.ToolVTCode + ".assistant_text"
				te.ToolOutput = a.scrubber.String(contentcap.Cap(text, contentcap.DefaultMaxBytes))
				if len(m.ToolCalls) == 0 {
					te.PrecedingReasoning = reasoning
				}
				res.ToolEvents = append(res.ToolEvents, te)
			}
			for j, c := range m.ToolCalls {
				if c.ID == "" || pending[c.ID] != nil {
					continue
				}
				pc := &pendingCall{call: c, ts: ts}
				if j == 0 {
					pc.reasoning = reasoning
				}
				pending[c.ID] = pc
				order = append(order, c.ID)
			}
		case roleTool:
			tick()
			pc := pending[m.ToolCallID]
			if pc == nil {
				continue
			}
			delete(pending, m.ToolCallID)
			res.ToolEvents = append(res.ToolEvents, p.archiveCall(pc.call, pc.ts, pc.reasoning, model, m.text(), true))
		default:
			tick()
		}
	}
	for _, id := range order {
		if pc := pending[id]; pc != nil {
			res.ToolEvents = append(res.ToolEvents, p.archiveCall(pc.call, pc.ts, pc.reasoning, model, "", false))
		}
	}

	if end := parseTime(doc.file.EndedAt); !end.IsZero() {
		te := p.base("session_end:"+sid, end, models.ActionSessionEnd)
		te.Target = "completed"
		te.RawToolName = models.ToolVTCode + ".session_end"
		res.ToolEvents = append(res.ToolEvents, te)
	}

	a.sessionFacts(&res, sid, "", ws, "", filepath.Dir(archivePath))
	adapter.ApplyProjectIdentity(&res, p.identity)
	return res
}

// archiveCall builds the action row of one archived tool call. resolved
// is false when no Tool message answered it.
func (p *parser) archiveCall(c archiveToolCall, ts time.Time, reasoning, model, output string, resolved bool) models.ToolEvent {
	raw := json.RawMessage(c.Function.Arguments)
	if !json.Valid(raw) {
		b, _ := json.Marshal(c.Function.Arguments)
		raw = b
	}
	m := argsMap(raw)
	name := c.Function.Name
	te := p.base("tool:"+c.ID, ts, mapVTCodeTool(name))
	te.Model = model
	te.RawToolName = name
	te.Target = p.a.scrubber.String(toolTarget(name, raw, m))
	te.RawToolInput = p.rawToolInput(name, raw, m)
	if te.ActionType == models.ActionEditFile {
		te.ContentBytes = patchAddedBytes(patchText(raw, m))
	}
	te.PrecedingReasoning = reasoning
	if !resolved {
		te.Success = false
		te.ErrorMessage = "no tool result recorded"
		return te
	}
	ok, errMsg := toolResultOutcome(output)
	te.Success = ok
	if output != "" {
		te.ToolOutput = p.a.scrubber.String(contentcap.Cap(output, contentcap.DefaultMaxBytes))
	}
	if !ok {
		te.ErrorMessage = truncate(p.a.scrubber.String(firstNonEmpty(errMsg, output, "failed")), 500)
	}
	return te
}

// toolResultOutcome classifies an archived Tool message body. Grounded
// shapes: `{"success":true,"output":...}`, `{"output":...,"exit_code":N}`
// and `{"error":{"tool_name":...,"error_type":"PolicyViolation",
// "message":...}}`. A non-JSON body is a success (plain output).
func toolResultOutcome(body string) (bool, string) {
	var r struct {
		Success  *bool           `json:"success"`
		ExitCode *int            `json:"exit_code"`
		Error    json.RawMessage `json:"error"`
	}
	if json.Unmarshal([]byte(body), &r) != nil {
		// Not (complete) JSON: plain output, unless it is visibly an
		// error envelope cut short.
		trimmed := strings.TrimSpace(body)
		if strings.HasPrefix(trimmed, `{"error"`) {
			return false, ""
		}
		if strings.HasPrefix(trimmed, "{") && strings.Contains(trimmed, `"success":false`) {
			return false, ""
		}
		return true, ""
	}
	if len(r.Error) > 0 && string(r.Error) != "null" {
		var e struct {
			Message   string `json:"message"`
			ErrorType string `json:"error_type"`
		}
		if json.Unmarshal(r.Error, &e) == nil {
			return false, firstNonEmpty(e.Message, e.ErrorType)
		}
		var s string
		_ = json.Unmarshal(r.Error, &s)
		return false, s
	}
	if r.Success != nil && !*r.Success {
		return false, ""
	}
	if r.ExitCode != nil && *r.ExitCode != 0 {
		return false, fmt.Sprintf("exit code %d", *r.ExitCode)
	}
	return true, ""
}
