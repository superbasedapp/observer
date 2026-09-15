package copilot

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// parseModern parses a modern Copilot Chat session file (chatSessions/<id>.jsonl
// or globalStorage/emptyWindowChatSessions/<id>.jsonl), produced by VS Code
// Copilot Chat ≥0.45.
//
// Format: each line is one JSON object with a "kind" discriminator.
//
//   - kind=0: a full session snapshot (`v` is the entire session state).
//     A file may contain multiple snapshots — VS Code rewrites the snapshot
//     when reopening a session. We only ever parse the LAST snapshot; earlier
//     ones are subsumed.
//   - kind=1: an incremental patch. `k` is a JSON-pointer-style array of
//     keys/indices into the session; `v` is the new value at that path. We
//     apply only patches whose path begins with "requests" — patches under
//     "inputState" carry transient UI state (selections, attachments, etc.)
//     and may contain multi-MB inline image payloads we never want to ingest.
//
// fromOffset is intentionally ignored: the snapshot+patches model has no
// meaningful resumption point, so we always reparse the whole file. The
// store layer's (source_file, source_event_id) UNIQUE constraint dedupes
// re-emitted turns; the watcher's stat-only short-circuit (v1.4.26) keeps
// steady-state cost bounded.
func (a *Adapter) parseModern(ctx context.Context, path string) (adapter.ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("copilot.parseModern: open %s: %w", path, err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("copilot.parseModern: stat: %w", err)
	}

	res := adapter.ParseResult{NewOffset: stat.Size()}

	scanner := bufio.NewScanner(f)
	const maxLine = 16 * 1024 * 1024
	scanner.Buffer(make([]byte, 64*1024), maxLine)

	var session map[string]any
	// pendingPatch buffers a kind=1 (replace) or kind=2 (insert/append)
	// patch until we've finished scanning the file — earlier patches are
	// thrown away if a later kind=0 snapshot subsumes them.
	type pendingPatch struct {
		kind int
		k    []any
		i    int
		hasI bool
		v    json.RawMessage
	}
	var patches []pendingPatch

	lineNum := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		raw := scanner.Bytes()
		lineNum++
		if len(raw) == 0 {
			continue
		}

		var head struct {
			Kind int             `json:"kind"`
			K    json.RawMessage `json:"k"`
			V    json.RawMessage `json:"v"`
			I    *int            `json:"i"`
		}
		if err := json.Unmarshal(raw, &head); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: malformed JSON: %v", lineNum, err))
			continue
		}

		switch head.Kind {
		case 0:
			// New snapshot — discard any patches accumulated against the
			// previous snapshot; they are subsumed by this one.
			var v map[string]any
			if err := json.Unmarshal(head.V, &v); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: snapshot decode: %v", lineNum, err))
				continue
			}
			session = v
			patches = patches[:0]
		case 1, 2:
			// kind=1 replaces the value at path k; kind=2 inserts the
			// elements of v[*] into the array at k, at index i (append
			// when i is omitted). In both cases we filter on k[0] so
			// inputState/selections/attachments patches drop without
			// materializing v (the 14.8 MB attachment line is one of
			// these).
			var k []any
			if err := json.Unmarshal(head.K, &k); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: patch path decode: %v", lineNum, err))
				continue
			}
			if len(k) == 0 {
				continue
			}
			head0, _ := k[0].(string)
			if head0 != "requests" {
				continue
			}
			pp := pendingPatch{kind: head.Kind, k: k, v: head.V}
			if head.I != nil {
				pp.i = *head.I
				pp.hasI = true
			}
			patches = append(patches, pp)
		default:
			// Forward-compat: unknown kind values are ignored.
		}
	}
	if err := scanner.Err(); err != nil {
		return res, fmt.Errorf("copilot.parseModern: scan: %w", err)
	}

	if session == nil {
		// No snapshot line: nothing to emit, but the session still
		// exists and is still an IDE chat.
		a.finishModern(path, nil, &res)
		return res, nil
	}

	// Apply queued patches against the last snapshot.
	for _, p := range patches {
		var v any
		if err := json.Unmarshal(p.v, &v); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("patch %v: value decode: %v", p.k, err))
			continue
		}
		switch p.kind {
		case 1:
			if err := applyPatch(session, p.k, v); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("patch %v: %v", p.k, err))
			}
		case 2:
			elems, ok := v.([]any)
			if !ok {
				res.Warnings = append(res.Warnings, fmt.Sprintf("patch %v: kind=2 v is %T, not array", p.k, v))
				continue
			}
			if err := applyInsert(session, p.k, p.i, p.hasI, elems); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("patch %v: %v", p.k, err))
			}
		}
	}

	a.finishModern(path, session, &res)
	return res, nil
}

// parseModernDocument parses the `.json` empty-window session DOCUMENT
// (`<globalStorage>/emptyWindowChatSessions/<sessId>.json`). The whole file
// IS the session state — byte-for-byte the same object a `.jsonl` log
// carries as a kind=0 snapshot's `v` payload (`version`,
// `requesterUsername`, `responderUsername`, `initialLocation`, `requests[]`,
// `sessionId`, `creationDate`, `isImported`, `lastMessageDate`) — so it
// decodes straight into the same map the snapshot+patches path assembles
// and runs through the same emitter (audit finding IDE-10). There are no
// patches to apply and no snapshot to pick.
//
// fromOffset is ignored for the same reason parseModern ignores it: VS Code
// REWRITES this document in place, so a byte cursor has no meaning. The
// store's (source_file, source_event_id) UNIQUE constraint dedupes
// re-emitted turns, and NewOffset is the file size so the watcher's
// stat-only short-circuit still keeps steady-state cost bounded.
//
// DOUBLE-INGEST GUARD (C1). That UNIQUE constraint is keyed on
// (source_file, source_event_id), and SourceEventID here is derived from
// the request id — the SAME value the `.jsonl` path derives. So the two
// shapes of one session id collide on the event id but NOT on the source
// file (they differ by extension), which means a session that somehow had
// both a `<sid>.json` and a `<sid>.jsonl` on disk would be ingested TWICE:
// double actions, double tokens.
//
// VS Code's writer is not documented either way, and no live install here
// has been observed producing both, so the honest posture is to defend
// against it rather than assert it cannot happen: when a `.jsonl` log
// exists for this session id, the log WINS and the document emits nothing
// but its watermark. The log is the strictly better source — it is
// append-structured, so it carries the session's history across rewrites
// that the in-place document only ever shows the latest state of. Same
// shape as cursor's stateDBAlreadyCaptured / cursorSiblingExists gate.
func (a *Adapter) parseModernDocument(ctx context.Context, path string) (adapter.ParseResult, error) {
	body, err := os.ReadFile(path) //nolint:gosec // watched session file
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("copilot.parseModernDocument: read %s: %w", path, err)
	}
	if err := ctx.Err(); err != nil {
		return adapter.ParseResult{}, err
	}

	if a.modernLogSiblingExists(sessionIDFromPath(path), path) {
		// Cursor advances so the watcher does not re-read the file every
		// tick; the surface stamp is still emitted (it is idempotent and
		// says the same thing the log's stamp would).
		res := adapter.ParseResult{NewOffset: int64(len(body))}
		appendSessionSurface(&res, sessionIDFromPath(path), path)
		return res, nil
	}

	res := adapter.ParseResult{NewOffset: int64(len(body))}
	var session map[string]any
	if err := json.Unmarshal(body, &session); err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("document decode: %v", err))
		a.finishModern(path, nil, &res)
		return res, nil
	}
	a.finishModern(path, session, &res)
	return res, nil
}

// finishModern is the single emission tail shared by both modern shapes:
// it resolves the session context from the path, emits the snapshot's
// requests (when there is one), and stamps the session's capture surface.
// Keeping it in one place is what makes the `.json` document and the
// `.jsonl` snapshot produce identical rows for identical content.
func (a *Adapter) finishModern(path string, session map[string]any, res *adapter.ParseResult) {
	state := sessionContext{
		SessionID:   sessionIDFromPath(path),
		ProjectRoot: projectRootFromPath(path),
	}
	if session != nil {
		a.emitModernEvents(path, session, &state, res)
	}
	appendSessionSurface(res, state.SessionID, path)
}

// applyPatch writes v into session at the location named by the JSON-pointer
// array k. Numeric indices in k may arrive as float64 (json.Unmarshal default)
// or string; both are handled. Returns an error when the path can't be
// followed; callers log and continue.
func applyPatch(session map[string]any, k []any, v any) error {
	if len(k) == 0 {
		return fmt.Errorf("empty path")
	}
	if len(k) == 1 {
		key, ok := k[0].(string)
		if !ok {
			return fmt.Errorf("top-level key must be string, got %T", k[0])
		}
		session[key] = v
		return nil
	}
	cur := any(session)
	for i := 0; i < len(k)-1; i++ {
		next, ok := descend(cur, k[i])
		if !ok {
			return fmt.Errorf("path miss at index %d (%v)", i, k[i])
		}
		cur = next
	}
	return assign(cur, k[len(k)-1], v)
}

// applyInsert handles kind=2 patches: insert elems[*] into the array at
// session[k...] starting at index i. When hasI is false (the JSON omitted
// `i`), the elements are appended.
func applyInsert(session map[string]any, k []any, i int, hasI bool, elems []any) error {
	if len(k) == 0 {
		return fmt.Errorf("empty path")
	}
	// Walk to the parent of the array we want to mutate, then merge at
	// the leaf. We need parent + final key (rather than the array value
	// itself) because slice header reassignment after a grow only sticks
	// when written back through the parent.
	parent := any(session)
	for j := 0; j < len(k)-1; j++ {
		next, ok := descend(parent, k[j])
		if !ok {
			return fmt.Errorf("path miss at index %d (%v)", j, k[j])
		}
		parent = next
	}
	last := k[len(k)-1]
	switch p := parent.(type) {
	case map[string]any:
		s, ok := last.(string)
		if !ok {
			return fmt.Errorf("string key required, got %T", last)
		}
		existing, _ := p[s].([]any)
		p[s] = mergeInsert(existing, i, hasI, elems)
		return nil
	case []any:
		idx, ok := toIndex(last)
		if !ok {
			return fmt.Errorf("integer index required, got %T", last)
		}
		if idx < 0 || idx >= len(p) {
			return fmt.Errorf("index %d out of range %d", idx, len(p))
		}
		existing, _ := p[idx].([]any)
		p[idx] = mergeInsert(existing, i, hasI, elems)
		return nil
	}
	return fmt.Errorf("cannot insert into %T", parent)
}

func mergeInsert(existing []any, i int, hasI bool, elems []any) []any {
	if !hasI || i < 0 || i > len(existing) {
		return append(append([]any{}, existing...), elems...)
	}
	merged := make([]any, 0, len(existing)+len(elems))
	merged = append(merged, existing[:i]...)
	merged = append(merged, elems...)
	merged = append(merged, existing[i:]...)
	return merged
}

func descend(x any, key any) (any, bool) {
	switch m := x.(type) {
	case map[string]any:
		s, ok := key.(string)
		if !ok {
			return nil, false
		}
		val, exists := m[s]
		return val, exists
	case []any:
		idx, ok := toIndex(key)
		if !ok || idx < 0 || idx >= len(m) {
			return nil, false
		}
		return m[idx], true
	}
	return nil, false
}

func assign(x any, key any, v any) error {
	switch m := x.(type) {
	case map[string]any:
		s, ok := key.(string)
		if !ok {
			return fmt.Errorf("string key required, got %T", key)
		}
		m[s] = v
		return nil
	case []any:
		idx, ok := toIndex(key)
		if !ok {
			return fmt.Errorf("integer index required, got %T", key)
		}
		if idx < 0 || idx >= len(m) {
			return fmt.Errorf("index %d out of range %d", idx, len(m))
		}
		m[idx] = v
		return nil
	}
	return fmt.Errorf("cannot assign into %T", x)
}

func toIndex(key any) (int, bool) {
	switch v := key.(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case int64:
		return int(v), true
	case string:
		// rare but tolerated
		var i int
		if _, err := fmt.Sscanf(v, "%d", &i); err == nil {
			return i, true
		}
	}
	return 0, false
}

// emitModernEvents walks the assembled snapshot's requests[] and emits one
// user_prompt + N tool-call ToolEvents + 1 task_complete + 1 TokenEvent per
// turn. Turn idempotence is keyed on requestId, which is stable across
// snapshot rewrites within a file.
func (a *Adapter) emitModernEvents(sourceFile string, session map[string]any, state *sessionContext, res *adapter.ParseResult) {
	if model := topLevelModel(session); model != "" {
		state.Model = model
	}

	requests, _ := session["requests"].([]any)
	for _, ri := range requests {
		req, ok := ri.(map[string]any)
		if !ok {
			continue
		}
		a.emitModernTurn(sourceFile, req, state, res)
	}
}

// topLevelModel returns the session's selectedModel.identifier from
// inputState, when present. Per-turn modelId on a request takes priority,
// but this fallback covers turns that don't echo it.
func topLevelModel(session map[string]any) string {
	is, _ := session["inputState"].(map[string]any)
	if is == nil {
		return ""
	}
	sm, _ := is["selectedModel"].(map[string]any)
	if sm == nil {
		return ""
	}
	id, _ := sm["identifier"].(string)
	return id
}

func (a *Adapter) emitModernTurn(sourceFile string, req map[string]any, state *sessionContext, res *adapter.ParseResult) {
	requestID, _ := req["requestId"].(string)
	if requestID == "" {
		// Without a stable id we can't dedupe; skip rather than emit
		// rows that re-duplicate every reparse.
		res.Warnings = append(res.Warnings, "modern turn missing requestId")
		return
	}
	ts := millisToTime(asInt64(req["timestamp"]))
	// Model resolution: prefer result.metadata.resolvedModel (the actual
	// upstream model that processed the turn — e.g. claude-haiku-4-5-20251001
	// or grok-code-fast-1), fall back to requests[].modelId (the user-facing
	// routing pick — typically copilot/auto when the user hasn't picked a
	// specific model). resolvedModel is what cost analytics wants when it
	// names a public model.
	//
	// `capi-*` exception (v1.6.16 audit F1): Copilot sometimes returns
	// internal routing identifiers like
	// `capi-cus-ptuc-h100-oswe-vscode-prime` in resolvedModel. These are
	// not in pricing.go and would silently bill $0. Fall back to modelId
	// (`copilot/auto`) so the row joins the rest of the copilot/auto
	// activity rather than appearing as a one-off unpriced bucket. The
	// underlying pricing question (what `copilot/auto` should bill at)
	// is separate from the attribution coherence this fix achieves.
	rm := resolvedModel(req)
	modelID, _ := req["modelId"].(string)
	switch {
	case rm != "" && !strings.HasPrefix(rm, "capi-"):
		state.Model = rm
	case modelID != "":
		state.Model = modelID
	case rm != "":
		// rm is `capi-*` and modelId is empty — fall through to
		// using the routing ID. Should never happen in observed
		// data (modelId is always populated when resolvedModel is),
		// but keeps state.Model non-empty.
		state.Model = rm
	}
	agent, _ := req["agent"].(map[string]any)
	agentID, _ := agent["id"].(string)
	messageID := "assistant:" + requestID

	// User prompt event.
	if msg, _ := req["message"].(map[string]any); msg != nil {
		if text, _ := msg["text"].(string); strings.TrimSpace(text) != "" {
			res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
				SourceFile:         sourceFile,
				SourceEventID:      requestID + ":user",
				SessionID:          state.SessionID,
				MessageID:          "user:" + requestID,
				ProjectRoot:        state.ProjectRoot,
				Timestamp:          ts,
				Model:              state.Model,
				Tool:               models.ToolCopilot,
				ActionType:         models.ActionUserPrompt,
				Target:             truncate(text, 200),
				Success:            true,
				PrecedingReasoning: truncate(text, 200),
				RawToolName:        "user_message",
				RawToolInput:       a.scrubber.String(text),
			})
		}
	}

	// Tool calls — taken from result.metadata.toolCallRounds[].toolCalls[].
	// This is the canonical source; the parallel response[] array has only
	// references to tool invocations, not arguments.
	//
	// v1.6.16 audit F2: Copilot's response[] carries `kind="thinking"`
	// entries with reasoning prose between user prompt and tool calls.
	// Collect them so each tool call's PrecedingReasoning surfaces the
	// most-recent thinking text (mirrors the claudecode adapter's
	// lastReasoning window). The reasoning *token count* is captured
	// separately via result.metadata.toolCallRounds[*].thinking.tokens
	// (turnReasoningTokens below); this F2 path captures the text.
	rounds := pickRounds(req)
	results := pickResults(req)
	thinkingTexts := collectThinkingTexts(req)
	thinkingIdx := 0
	advanceThinking := func() string {
		if thinkingIdx < len(thinkingTexts) {
			t := thinkingTexts[thinkingIdx]
			thinkingIdx++
			return t
		}
		if len(thinkingTexts) == 0 {
			return ""
		}
		return thinkingTexts[len(thinkingTexts)-1]
	}
	for ri, round := range rounds {
		toolCalls, _ := round["toolCalls"].([]any)
		roundTS := millisToTime(asInt64(round["timestamp"]))
		if roundTS.IsZero() {
			roundTS = ts
		}
		// One thinking block typically precedes each round of tool calls;
		// when counts diverge the helper sticks at the last available
		// entry rather than wrapping or erroring.
		precedingReasoning := truncate(advanceThinking(), 1000)
		for ci, ti := range toolCalls {
			tc, _ := ti.(map[string]any)
			if tc == nil {
				continue
			}
			name, _ := tc["name"].(string)
			args, _ := tc["arguments"].(string)
			callID, _ := tc["id"].(string)
			target, rawInput := parseToolArgs(args, name)
			eventID := fmt.Sprintf("%s:tool:%s", requestID, firstNonEmpty(callID, fmt.Sprintf("r%d-c%d", ri, ci)))
			ev := models.ToolEvent{
				SourceFile:         sourceFile,
				SourceEventID:      eventID,
				SessionID:          state.SessionID,
				MessageID:          messageID,
				ProjectRoot:        state.ProjectRoot,
				Timestamp:          roundTS,
				Model:              state.Model,
				Tool:               models.ToolCopilot,
				ActionType:         mapToolName(name),
				Target:             truncate(target, 200),
				Success:            true,
				PrecedingReasoning: precedingReasoning,
				RawToolName:        name,
				RawToolInput:       a.scrubber.String(rawInput),
			}
			if outExcerpt := toolResultExcerpt(results, callID); outExcerpt != "" {
				ev.ToolOutput = a.scrubber.String(outExcerpt)
			}
			res.ToolEvents = append(res.ToolEvents, ev)
		}
	}

	// Final assistant response (task_complete).
	respText := assistantResponseText(req)
	complete, _ := req["isComplete"].(bool)
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      requestID + ":complete",
		SessionID:          state.SessionID,
		MessageID:          messageID,
		ProjectRoot:        state.ProjectRoot,
		Timestamp:          ts,
		Model:              state.Model,
		Tool:               models.ToolCopilot,
		ActionType:         models.ActionTaskComplete,
		Target:             "agent_response",
		Success:            complete,
		DurationMs:         asInt64(req["elapsedMs"]),
		PrecedingReasoning: truncate(agentID, 200),
		RawToolName:        "agent_response",
		ToolOutput:         a.scrubber.String(respText),
	})

	// Token usage. Modern Copilot exposes:
	//   - input:  result.metadata.promptTokens
	//   - output: completionTokens (preferred) / result.metadata.outputTokens
	//   - reasoning: sum of result.metadata.toolCallRounds[].thinking.tokens
	// Cache token counts are NOT exposed (only cacheType:"ephemeral" markers
	// on rendered context blocks, no count). See Adapter doc-comment.
	in, out := turnTokens(req)
	reasoning := turnReasoningTokens(req)
	if in > 0 || out > 0 || reasoning > 0 {
		res.TokenEvents = append(res.TokenEvents, models.TokenEvent{
			SourceFile:      sourceFile,
			SourceEventID:   requestID + ":usage",
			SessionID:       state.SessionID,
			MessageID:       messageID,
			ProjectRoot:     state.ProjectRoot,
			Timestamp:       ts,
			Tool:            models.ToolCopilot,
			Model:           state.Model,
			InputTokens:     in,
			OutputTokens:    out,
			ReasoningTokens: reasoning,
			Source:          models.TokenSourceJSONL,
			Reliability:     models.ReliabilityApproximate,
		})
	}
}

// resolvedModel returns the actual upstream model that processed this turn,
// from result.metadata.resolvedModel. Empty when missing (e.g. the snapshot
// was written before the result patch landed).
func resolvedModel(req map[string]any) string {
	result, _ := req["result"].(map[string]any)
	meta, _ := result["metadata"].(map[string]any)
	rm, _ := meta["resolvedModel"].(string)
	return rm
}

// turnReasoningTokens sums result.metadata.toolCallRounds[*].thinking.tokens
// across all rounds for one turn. Modern Copilot has the field but writes
// 0 in observed data; the field exists for forward-compat with thinking-
// model variants.
func turnReasoningTokens(req map[string]any) int64 {
	result, _ := req["result"].(map[string]any)
	meta, _ := result["metadata"].(map[string]any)
	rounds, _ := meta["toolCallRounds"].([]any)
	var total int64
	for _, r := range rounds {
		rd, _ := r.(map[string]any)
		thinking, _ := rd["thinking"].(map[string]any)
		total += asInt64(thinking["tokens"])
	}
	return total
}

func pickRounds(req map[string]any) []map[string]any {
	result, _ := req["result"].(map[string]any)
	meta, _ := result["metadata"].(map[string]any)
	rawRounds, _ := meta["toolCallRounds"].([]any)
	out := make([]map[string]any, 0, len(rawRounds))
	for _, r := range rawRounds {
		if m, ok := r.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func pickResults(req map[string]any) map[string]any {
	result, _ := req["result"].(map[string]any)
	meta, _ := result["metadata"].(map[string]any)
	tcr, _ := meta["toolCallResults"].(map[string]any)
	return tcr
}

// toolResultExcerpt returns a short, scrubbable string describing the tool's
// output. It NEVER returns inline image bytes or large value blobs — only
// structural metadata or a truncated text excerpt.
func toolResultExcerpt(results map[string]any, callID string) string {
	if results == nil || callID == "" {
		return ""
	}
	r, _ := results[callID].(map[string]any)
	if r == nil {
		return ""
	}
	content, _ := r["content"].([]any)
	if len(content) == 0 {
		return ""
	}
	// Prefer text content. Image/binary content is summarized as a marker.
	for _, ci := range content {
		c, _ := ci.(map[string]any)
		if c == nil {
			continue
		}
		if mt, _ := c["mimeType"].(string); strings.HasPrefix(mt, "image/") {
			return "<image:" + mt + ">"
		}
		if v, ok := c["value"].(map[string]any); ok {
			if t, _ := v["text"].(string); t != "" {
				return truncate(t, 400)
			}
		}
		if t, _ := c["text"].(string); t != "" {
			return truncate(t, 400)
		}
	}
	return fmt.Sprintf("<%d content items>", len(content))
}

// collectThinkingTexts pulls the model's reasoning prose out of
// req.response[] entries with `kind="thinking"`. Each entry has a
// `value` string holding the reasoning block. Order is preserved so
// callers can pair each block with the round of tool calls it
// precedes (the round-thinking-tool-thinking-tool emit pattern in
// Copilot's response stream). Empty when the source carries no
// thinking entries — the field exists for forward-compat with
// thinking-capable models but is empty for non-thinking variants.
func collectThinkingTexts(req map[string]any) []string {
	resp, _ := req["response"].([]any)
	var out []string
	for _, ri := range resp {
		r, _ := ri.(map[string]any)
		if r == nil {
			continue
		}
		kind, _ := r["kind"].(string)
		if kind != "thinking" {
			continue
		}
		v, _ := r["value"].(string)
		if strings.TrimSpace(v) == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

// assistantResponseText pulls the model's textual reply out of req.response[].
// Modern Copilot interleaves multiple kinds with the assistant's prose:
//
//   - kind="toolInvocationSerialized" — tool invocation reference (skip;
//     the canonical source is result.metadata.toolCallRounds[])
//   - kind="thinking" — reasoning prose (skip; surfaced via
//     [[collectThinkingTexts]] as PrecedingReasoning on tool rows)
//   - kind="inlineReference" / "mcpServersStarting" /
//     "progressTaskSerialized" — observability envelopes, no prose
//   - entries with no `kind` and a `value` string — the assistant's
//     visible response text
func assistantResponseText(req map[string]any) string {
	resp, _ := req["response"].([]any)
	var b strings.Builder
	for _, ri := range resp {
		r, _ := ri.(map[string]any)
		if r == nil {
			continue
		}
		// Any kind-tagged envelope is skipped — thinking, tool
		// invocations, MCP setup markers, etc. The assistant's
		// prose lands as kind-less entries with a `value` string.
		if _, hasKind := r["kind"].(string); hasKind {
			continue
		}
		if v, ok := r["value"].(string); ok && v != "" {
			if b.Len() > 0 {
				b.WriteString("\n")
			}
			b.WriteString(v)
		}
	}
	return strings.TrimSpace(b.String())
}

// turnTokens extracts (input, output) tokens from a request. Output tokens
// prefer the top-level `completionTokens` (canonical) over the echo at
// result.metadata.outputTokens; input always comes from result.metadata.promptTokens.
func turnTokens(req map[string]any) (int64, int64) {
	out := asInt64(req["completionTokens"])
	result, _ := req["result"].(map[string]any)
	meta, _ := result["metadata"].(map[string]any)
	in := asInt64(meta["promptTokens"])
	if out == 0 {
		out = asInt64(meta["outputTokens"])
	}
	return in, out
}

func asInt64(x any) int64 {
	switch v := x.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case json.Number:
		i, _ := v.Int64()
		return i
	}
	return 0
}

// dispatchParse is the shared entry point that routes between the three
// on-disk shapes: the legacy debug-log scanner, the modern
// snapshot+patches log, and the modern empty-window `.json` document.
// Dispatch is on the file's SHAPE, never on a tool/source identity
// (CLAUDE.md Module Boundaries #3).
func (a *Adapter) dispatchParse(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	switch {
	case isEmptyWindowDocumentPath(path):
		return a.parseModernDocument(ctx, path)
	case isModernSessionPath(path):
		return a.parseModern(ctx, path)
	default:
		return a.parseLegacy(ctx, path, fromOffset)
	}
}

// parseLegacy preserves the existing forward-only debug-log scanner as a
// named entrypoint so the dispatcher can call it explicitly.
func (a *Adapter) parseLegacy(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("copilot.parseLegacy: open %s: %w", path, err)
	}
	defer f.Close()
	if fromOffset > 0 {
		if _, err := f.Seek(fromOffset, io.SeekStart); err != nil {
			return adapter.ParseResult{}, fmt.Errorf("copilot.parseLegacy: seek: %w", err)
		}
	}
	res := adapter.ParseResult{NewOffset: fromOffset}
	state := sessionContext{
		SessionID:   sessionIDFromPath(path),
		ProjectRoot: projectRootFromPath(path),
	}
	scanner := bufio.NewScanner(f)
	const maxLine = 16 * 1024 * 1024
	scanner.Buffer(make([]byte, 64*1024), maxLine)
	var bytesRead int64 = fromOffset
	lineNum := 0
	for scanner.Scan() {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		raw := scanner.Bytes()
		bytesRead += int64(len(raw) + 1)
		lineNum++
		if len(raw) == 0 {
			continue
		}
		var line rawLine
		if err := json.Unmarshal(raw, &line); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: malformed JSON: %v", lineNum, err))
			res.NewOffset = bytesRead
			continue
		}
		res.NewOffset = bytesRead
		a.parseLine(path, line, lineNum, &state, &res)
	}
	if err := scanner.Err(); err != nil {
		return res, fmt.Errorf("copilot.parseLegacy: scan: %w", err)
	}
	// The debug-log's own `sid` overrides the path-derived id when the
	// stream carried one, so stamp after the scan, not before.
	appendSessionSurface(&res, state.SessionID, path)
	return res, nil
}

// guard against accidental imports being elided.
var _ = time.Time{}
