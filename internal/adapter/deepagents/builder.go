package deepagents

import (
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// threadShared is the per-thread context every namespace's builder reads.
type threadShared struct {
	a       *Adapter
	dbPath  string
	session string
	root    string
	remote  string
	tc      threadCheckpoints
	// starts is the `_last_model_request_at` request-start time per
	// producing task (writeKey).
	starts map[string]time.Time
}

// spawnLink ties a parent `task` tool call to the sub-agent run it started.
type spawnLink struct {
	ns      string
	agentID string
	// result is the parent's ToolMessage for the `task` call (the
	// sub-agent's returned answer).
	result *rawMessage
}

// threadBuilder accumulates one namespace's events in message order. The
// thread's own graph and every sub-agent run each get one; a sub-agent's
// builder is flagged sidechain so its rows land on the PARENT session marked
// is_sidechain with the sub-agent identity (the Claude Code inline-sidechain
// model the session sub-agents view reads).
type threadBuilder struct {
	*threadShared
	results map[string]*rawMessage
	// calls is the tool calls each task's AI-message write carried (the
	// approval pairing input); hitl the namespace's approval requests.
	calls map[string][]rawToolCall
	hitl  []hitlRequest
	cache *cacheobs.Accumulator

	// sidechain marks a sub-agent namespace; agentID / agentType identify
	// it (the `tools:<task id>` suffix and the checkpoint lc_agent_name).
	sidechain bool
	agentID   string
	agentType string
	// spawns maps a parent `task` tool_call_id to its sub-agent run (root
	// builder only).
	spawns map[string]spawnLink

	tools    []models.ToolEvent
	tokens   []models.TokenEvent
	cacheObs []models.CacheTurnObservation

	// turnID is the dcode turn id of the most recent human prompt; model is
	// the most recent model an AI message named (rows without their own
	// model — prompts, tool results — are not stamped, only AI-side rows).
	turnID string
	model  string
	// pendingPrompt is the newest human prompt that has not yet received
	// an AI message (a second prompt arriving first means it was aborted).
	pendingPrompt *rawMessage

	// resolved lists the tool calls that have a result, in order, for the
	// late-outcome window.
	resolved []resolvedCall
}

type resolvedCall struct {
	sourceEventID string
	success       bool
	errMsg        string
	output        string
}

// newBuilder prepares a builder for one namespace's folded messages.
func newBuilder(shared *threadShared, msgs []*rawMessage, calls map[string][]rawToolCall, hitl []hitlRequest) *threadBuilder {
	b := &threadBuilder{
		threadShared: shared,
		results:      map[string]*rawMessage{},
		calls:        calls,
		hitl:         hitl,
		cache:        newCache(),
	}
	for _, m := range msgs {
		if m.Role == "tool" && m.ToolCallID != "" {
			b.results[m.ToolCallID] = m
		}
	}
	return b
}

// run converts the namespace's messages, then its approval requests.
func (b *threadBuilder) run(msgs []*rawMessage) {
	for _, m := range msgs {
		b.add(m)
	}
	b.addPermissions()
}

// metaFor returns the metadata of the checkpoint a message hung off.
func (b *threadBuilder) metaFor(m *rawMessage) checkpointMeta {
	return b.metaAt(m.CheckpointID)
}

func (b *threadBuilder) metaAt(checkpointID string) checkpointMeta {
	if meta, ok := b.tc.byID[checkpointID]; ok {
		return meta
	}
	return b.tc.latest
}

// baseAt returns a ToolEvent carrying the thread-level fields for a row
// anchored at a checkpoint.
func (b *threadBuilder) baseAt(checkpointID string, ts time.Time) models.ToolEvent {
	meta := b.metaAt(checkpointID)
	ev := models.ToolEvent{
		SourceFile:  b.dbPath,
		SessionID:   b.session,
		ProjectRoot: b.root,
		GitRemote:   b.remote,
		GitBranch:   meta.GitBranch,
		Timestamp:   ts,
		TurnIndex:   meta.TurnNumber,
		Tool:        models.ToolDeepAgentsCode,
		Success:     true,
		IsSidechain: b.sidechain,
	}
	if meta.ApprovalMode != "" || b.sidechain {
		ev.Metadata = &models.ActionMetadata{PermissionMode: meta.ApprovalMode}
		if b.sidechain {
			ev.Metadata.AgentID = b.agentID
			ev.Metadata.IsSubagent = true
		}
	}
	return ev
}

// base returns the row base for a message.
func (b *threadBuilder) base(m *rawMessage) models.ToolEvent {
	return b.baseAt(m.CheckpointID, msgTime(m))
}

// add converts one message to events (and feeds the Tier-2 cache
// accumulator), in conversation order.
func (b *threadBuilder) add(m *rawMessage) {
	switch m.Role {
	case "human":
		b.addHuman(m)
	case "ai":
		b.pendingPrompt = nil
		b.addAI(m)
	case "tool":
		b.cacheToolResult(m)
	}
}

// addHuman emits a user_prompt (or a prompt_context row for a harness-
// injected `[SYSTEM]` message, the same discriminator the vendor's own
// thread inspector uses; and for a sub-agent's delegated task, which the
// parent model wrote, not the user).
func (b *threadBuilder) addHuman(m *rawMessage) {
	literal, promptTurn := promptMeta(*m)
	text := cleanPromptText(contentText(m.Content))
	shown := text
	if l := cleanPromptText(literal); l != "" {
		shown = l
	}
	attachments := userAttachments(m.Content)
	if shown == "" && len(attachments) == 0 {
		return
	}
	system := strings.HasPrefix(text, "[SYSTEM]")
	if !system && !b.sidechain {
		b.turnID = firstNonEmpty(promptTurn, b.metaFor(m).TurnID)
		if b.pendingPrompt != nil {
			b.addAborted(b.pendingPrompt)
		}
		b.pendingPrompt = m
	}
	preview := b.a.scrub(truncate(shown, 500))
	ev := b.base(m)
	ev.SourceEventID = "prompt:" + m.ID
	ev.Target = truncate(preview, 200)
	ev.MessageID = m.ID
	ev.UserAttachments = attachments
	switch {
	case system:
		ev.ActionType = models.ActionPromptContext
		ev.RawToolName = models.ToolDeepAgentsCode + ".system_message"
		ev.UserAttachments = nil
	case b.sidechain:
		ev.ActionType = models.ActionPromptContext
		ev.RawToolName = models.ToolDeepAgentsCode + ".subagent_prompt"
		ev.RawToolInput = preview
	default:
		ev.ActionType = models.ActionUserPrompt
		ev.RawToolName = models.ToolDeepAgentsCode + ".user_prompt"
		ev.RawToolInput = preview
	}
	b.tools = append(b.tools, ev)
	if text != "" {
		accumulateTextCache(b.cache, b.a.scrub(text), "user")
	}
}

// addAborted emits turn_aborted for a prompt the user superseded before the
// model answered (dcode's TUI lets a prompt be interrupted; the next prompt
// then follows with no AI message in between). Timestamped at the prompt's
// turn's last checkpoint when known.
func (b *threadBuilder) addAborted(p *rawMessage) {
	ts := msgTime(p)
	if last := b.tc.turnLast[b.metaFor(p).TurnID]; last != "" {
		if t, ok := uuidTime(last); ok {
			ts = t
		}
	}
	ev := b.baseAt(p.CheckpointID, ts)
	ev.SourceEventID = "aborted:" + p.ID
	ev.ActionType = models.ActionTurnAborted
	ev.Target = "interrupted before a reply"
	ev.RawToolName = models.ToolDeepAgentsCode + ".turn_aborted"
	ev.MessageID = p.ID
	b.tools = append(b.tools, ev)
}

// addAI emits the assistant text, one row per tool call, the terminal-stop
// marker, the token row and the Tier-2 cache observation of one model call.
func (b *threadBuilder) addAI(m *rawMessage) {
	model := firstString(m.ResponseMetadata, "model_name", "model")
	if model != "" {
		b.model = model
	} else {
		model = b.model
	}
	callID := firstString(m.ResponseMetadata, "id")
	if callID == "" {
		callID = m.ID
	}
	reasoning := b.a.scrub(truncate(reasoningText(*m), maxReasoningBytes))
	text := strings.TrimSpace(contentText(m.Content))
	finish := firstString(m.ResponseMetadata, "finish_reason", "stop_reason")

	if text != "" {
		scrubbed := b.a.scrub(contentcap.Cap(text, contentcap.DefaultMaxBytes))
		ev := b.base(m)
		ev.SourceEventID = "text:" + m.ID
		ev.ActionType = models.ActionAssistantMessage
		ev.Model = model
		ev.Target = truncate(b.a.scrub(truncate(text, 200)), 200)
		ev.RawToolName = models.ToolDeepAgentsCode + ".assistant_text"
		ev.ToolOutput = scrubbed
		ev.PrecedingReasoning = reasoning
		ev.MessageID = callID
		if finish != "" {
			if ev.Metadata == nil {
				ev.Metadata = &models.ActionMetadata{}
			}
			ev.Metadata.StopReason = finish
		}
		b.tools = append(b.tools, ev)
		accumulateTextCache(b.cache, scrubbed, "assistant")
		reasoning = "" // attach once
	}

	for i, tc := range m.ToolCalls {
		b.addToolCall(m, tc, i, model, callID, reasoning)
		reasoning = ""
	}

	// A sub-agent's final answer is not the session's turn ending; its end
	// is the subagent_stop bracket instead.
	if finish == "stop" && len(m.ToolCalls) == 0 && !b.sidechain {
		ev := b.base(m)
		ev.SourceEventID = "complete:" + m.ID
		ev.ActionType = models.ActionTaskComplete
		ev.Model = model
		ev.Target = finish
		ev.RawToolName = models.ToolDeepAgentsCode + ".finish"
		ev.MessageID = callID
		b.tools = append(b.tools, ev)
	}

	b.addUsage(m, model, callID)
}

// addToolCall emits one tool_call row, paired with its ToolMessage result
// when the namespace has one.
func (b *threadBuilder) addToolCall(m *rawMessage, tc rawToolCall, idx int, model, callID, reasoning string) {
	action, target := mapTool(tc.Name, tc.Args)
	raw := jsonArgs(tc.Args)

	ev := b.base(m)
	ev.SourceEventID = "tool:" + tc.ID
	if tc.ID == "" {
		ev.SourceEventID = fmt.Sprintf("tool:%s:%d:%s", m.ID, idx, tc.Name)
	}
	ev.ActionType = action
	ev.Model = model
	ev.Target = truncate(b.a.scrub(target), 200)
	ev.RawToolName = tc.Name
	ev.RawToolInput = b.a.scrubRaw([]byte(raw))
	ev.ContentBytes = authoredBytes(tc.Name, tc.Args)
	ev.PrecedingReasoning = reasoning
	ev.MessageID = callID
	if link, ok := b.spawns[tc.ID]; ok && tc.ID != "" {
		// The parent's spawn row names the sub-agent run it started (the
		// session sub-agents view labels the window from it) and carries
		// the child run's wall-clock span.
		if ev.Metadata == nil {
			ev.Metadata = &models.ActionMetadata{}
		}
		ev.Metadata.AgentID = link.agentID
		sp := b.tc.spans[link.ns]
		ev.DurationMs = clockMs(sp[0], sp[1])
	}

	accumulateToolCallCache(b.cache, tc.Name, ev.RawToolInput)

	if res, ok := b.results[tc.ID]; ok && tc.ID != "" {
		success, errMsg := resultOutcome(res)
		out := contentText(res.Content)
		ev.Success = success
		ev.ToolOutput = b.a.scrub(contentcap.Cap(out, contentcap.DefaultMaxBytes))
		if !success {
			ev.ErrorMessage = b.a.scrub(truncate(errMsg, 500))
		}
		b.resolved = append(b.resolved, resolvedCall{
			sourceEventID: ev.SourceEventID,
			success:       success,
			errMsg:        ev.ErrorMessage,
			output:        ev.ToolOutput,
		})
	} else {
		// No result yet (the call is awaiting approval or still running):
		// persisted optimistically, flipped later via OutcomeUpdates.
		ev.OutcomePending = true
	}
	b.tools = append(b.tools, ev)
}

// cacheToolResult feeds a tool result into the Tier-2 accumulator.
func (b *threadBuilder) cacheToolResult(m *rawMessage) {
	if text := contentText(m.Content); text != "" {
		accumulateToolResultCache(b.cache, b.a.scrub(contentcap.Cap(text, contentcap.DefaultMaxBytes)))
	}
}

// addUsage emits the token row (and cache observation) of an AI message from
// its usage_metadata.
//
// LangChain's usage_metadata is normalized across providers: input_tokens is
// the SUM of every input class (cache reads and cache writes included) and
// output_tokens the sum of every output class (reasoning included), with the
// classes broken out in input_token_details / output_token_details.
// Observer's TokenBundle is NET: input = input − cache_read − cache_creation
// and output = output − reasoning, with reasoning carried separately so it is
// billed once at the output rate (grounded 2026-10-21: input 14510 with
// cache_read 14359 → net 151).
//
// GenMs is native: the model task's `_last_model_request_at` (request sent)
// to the checkpoint LangGraph saved when that task's step finished
// (grounded: request 12:11:59.718, next checkpoint 12:12:03.381 → 3663 ms).
// It is absent for a sub-agent call (the channel is not written in a child
// namespace) and for the newest call before its step's checkpoint exists.
func (b *threadBuilder) addUsage(m *rawMessage, model, callID string) {
	u := m.UsageMetadata
	if u == nil {
		return
	}
	in := asInt64(u["input_tokens"])
	out := asInt64(u["output_tokens"])
	idet := asMap(u["input_token_details"])
	odet := asMap(u["output_token_details"])
	cacheRead := asInt64(idet["cache_read"])
	cacheWrite := asInt64(idet["cache_creation"])
	cache1h := asInt64(idet["ephemeral_1h_input_tokens"])
	if cache1h > cacheWrite {
		cache1h = cacheWrite
	}
	reasoning := asInt64(odet["reasoning"])
	if in == 0 && out == 0 && cacheRead == 0 && cacheWrite == 0 {
		return
	}
	netIn := in - cacheRead - cacheWrite
	if netIn < 0 {
		netIn = 0
	}
	netOut := out - reasoning
	if netOut < 0 {
		netOut = 0
	}
	ts := msgTime(m)
	meta := b.metaFor(m)
	tok := models.TokenEvent{
		SourceFile:            b.dbPath,
		SourceEventID:         "tokens:" + m.ID,
		SessionID:             b.session,
		ProjectRoot:           b.root,
		GitRemote:             b.remote,
		GitBranch:             meta.GitBranch,
		Timestamp:             ts,
		Tool:                  models.ToolDeepAgentsCode,
		Model:                 model,
		InputTokens:           netIn,
		OutputTokens:          netOut,
		CacheReadTokens:       cacheRead,
		CacheCreationTokens:   cacheWrite,
		CacheCreation1hTokens: cache1h,
		ReasoningTokens:       reasoning,
		EstimatedCostUSD:      asFloat(m.ResponseMetadata["cost"]),
		Source:                models.TokenSourceJSONL,
		Reliability:           models.ReliabilityApproximate,
		MessageID:             callID,
		TurnID:                firstNonEmpty(b.turnID, meta.TurnID),
		IsSidechain:           b.sidechain,
	}
	if start, ok := b.starts[writeKey(m.CheckpointID, m.TaskID)]; ok {
		if end, ok := uuidTime(b.tc.next[m.CheckpointID]); ok && end.After(start) {
			tok.GenMs = end.Sub(start).Milliseconds()
			tok.GenBasis = models.GenBasisNative
			tok.GenTimingV = genTimingV
		}
	}
	b.tokens = append(b.tokens, tok)

	if b.sidechain {
		// A sub-agent runs a separate prompt prefix; interleaving its calls
		// into the parent session's cache chain would corrupt the engine's
		// per-session prediction, so its calls feed no Tier-2 observation.
		return
	}
	usage := models.CacheUsage{
		NetInputTokens:        netIn,
		OutputTokens:          netOut,
		CacheReadTokens:       cacheRead,
		CacheCreationTokens:   cacheWrite,
		CacheCreation1hTokens: cache1h,
	}
	if cacheobs.IsZeroUsage(usage) {
		return
	}
	obs := b.cache.Emit(b.dbPath, b.session, callID, model, ts, usage, false)
	obs = cacheobs.ApplyImplicitCacheOverlay(obs, firstString(m.ResponseMetadata, "model_provider"), model)
	b.cacheObs = append(b.cacheObs, obs)
}

// addPermissions emits one permission_request per human-in-the-loop approval
// request of the namespace and, for a rejected one, a permission_denied row.
// The request row is anchored at the paused checkpoint; the denial at the
// checkpoint saved after the answer was applied.
func (b *threadBuilder) addPermissions() {
	claimed := map[string]bool{}
	for _, r := range b.hitl {
		callID := matchCall(r, b.calls[writeKey(r.CheckpointID, r.TaskID)], claimed)
		asked, _ := uuidTime(r.CheckpointID)
		input := b.a.scrubRaw(argsJSON(r.Args))
		ev := b.baseAt(r.CheckpointID, asked)
		ev.SourceEventID = permissionEventID(r, callID)
		ev.ActionType = models.ActionPermissionRequest
		ev.Target = r.Name
		ev.RawToolName = r.Name
		ev.RawToolInput = input
		if r.Decision != "" && r.Decision != "approve" {
			if ev.Metadata == nil {
				ev.Metadata = &models.ActionMetadata{}
			}
			ev.Metadata.PermissionApprovalKind = r.Decision
		}
		b.tools = append(b.tools, ev)
		if r.Decision != "reject" {
			continue
		}
		answered := asked
		if t, ok := uuidTime(b.tc.next[r.CheckpointID]); ok {
			answered = t
		}
		deny := b.baseAt(r.CheckpointID, answered)
		deny.SourceEventID = "permdeny:" + strings.TrimPrefix(ev.SourceEventID, "perm:")
		deny.ActionType = models.ActionPermissionDenied
		deny.Target = r.Name
		deny.RawToolName = r.Name
		deny.RawToolInput = input
		deny.Success = false
		deny.ErrorMessage = b.a.scrub(truncate(firstNonEmpty(r.Message, "rejected by the user"), 500))
		b.tools = append(b.tools, deny)
	}
}

// spawnFor returns the parent spawn link of a sub-agent run.
func (b *threadBuilder) spawnFor(agentID string) (spawnLink, bool) {
	for _, l := range b.spawns {
		if l.agentID == agentID {
			return l, true
		}
	}
	return spawnLink{}, false
}

// addSubagentStop closes a finished sub-agent run with a subagent_stop
// bracket at its namespace's last checkpoint. It is emitted only once the
// parent holds the `task` result (the run returned), and carries that
// result as the stop's output.
func (b *threadBuilder) addSubagentStop(ns string, link spawnLink) {
	sp := b.tc.spans[ns]
	end, ok := uuidTime(sp[1])
	if !ok || link.result == nil {
		return
	}
	ev := b.baseAt(sp[1], end)
	ev.SourceEventID = "substop:" + b.agentID
	ev.ActionType = models.ActionSubagentStop
	ev.Target = firstNonEmpty(b.agentType, "subagent")
	ev.RawToolName = models.ToolDeepAgentsCode + ".subagent_stop"
	ev.DurationMs = clockMs(sp[0], sp[1])
	success, errMsg := resultOutcome(link.result)
	ev.Success = success
	ev.ToolOutput = b.a.scrub(contentcap.Cap(contentText(link.result.Content), contentcap.DefaultMaxBytes))
	if !success {
		ev.ErrorMessage = b.a.scrub(truncate(errMsg, 500))
	}
	b.tools = append(b.tools, ev)
}

// sideCostEvent turns the thread's out-of-graph spend (thread naming and
// `/btw` questions) into one cumulative token row. The subtotal grows
// monotonically, so re-emitting it under the stable id "btw:<thread>" relies
// on the store's MAX-upgrade. dcode records no model for it; thread naming
// runs on the conversation's own model (thread_titles.py), so the thread's
// most recent model is the best attribution — an approximation, documented
// in docs/deepagents-adapter.md. Gross input / output are netted exactly as
// for a graph call.
func (b *threadBuilder) sideCostEvent(sc sideCost, latestCheckpoint string) models.TokenEvent {
	netIn := sc.Input - sc.CacheRead - sc.CacheCreation
	if netIn < 0 {
		netIn = 0
	}
	netOut := sc.Output - sc.Reasoning
	if netOut < 0 {
		netOut = 0
	}
	ts, _ := uuidTime(latestCheckpoint)
	return models.TokenEvent{
		SourceFile:          b.dbPath,
		SourceEventID:       "btw:" + b.session,
		SessionID:           b.session,
		ProjectRoot:         b.root,
		GitRemote:           b.remote,
		GitBranch:           b.tc.latest.GitBranch,
		Timestamp:           ts,
		Tool:                models.ToolDeepAgentsCode,
		Model:               b.model,
		InputTokens:         netIn,
		OutputTokens:        netOut,
		CacheReadTokens:     sc.CacheRead,
		CacheCreationTokens: sc.CacheCreation,
		ReasoningTokens:     sc.Reasoning,
		EstimatedCostUSD:    sc.CostUSD,
		Source:              models.TokenSourceJSONL,
		Reliability:         models.ReliabilityApproximate,
		MessageID:           "btw:" + b.session,
	}
}

// recentOutcomes turns the newest resolved calls into late OutcomeUpdates.
func (b *threadBuilder) recentOutcomes() []models.ActionOutcomeUpdate {
	start := 0
	if len(b.resolved) > outcomeWindow {
		start = len(b.resolved) - outcomeWindow
	}
	var out []models.ActionOutcomeUpdate
	for _, r := range b.resolved[start:] {
		out = append(out, models.ActionOutcomeUpdate{
			SourceFile:    b.dbPath,
			SourceEventID: r.sourceEventID,
			SuccessKnown:  true,
			Success:       r.success,
			ErrorMessage:  r.errMsg,
			ToolOutput:    r.output,
		})
	}
	return out
}
