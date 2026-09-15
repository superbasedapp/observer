package junie

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// MaxBlocksPerSession caps the per-session Tier-2 accumulator's running
// block count. Matches the claudecode template's cap (same memory
// budget, same OOM guard).
const MaxBlocksPerSession = cacheobs.DefaultMaxBlocksPerSession

// accumulatePromptCache feeds a UserPromptEvent's verbatim (scrubbed)
// prompt text into acc, as a single "user" text block. UserPromptEvent
// records are one-shot (a prompt's requestId never recurs mid-file), so no
// once-only guard is needed here — unlike the block kinds below, which
// the rebroadcast finding requires one.
func accumulatePromptCache(acc *cacheobs.Accumulator, text string) {
	canon, ok := marshalTextBlock(text)
	if !ok {
		return
	}
	acc.ObserveBlocks([]models.CacheBlockMeta{{
		LevelLabel:     "message", // R1: transcripts never expose tools/system
		Kind:           "text",
		CanonicalBytes: canon,
		Role:           "user",
	}})
}

// accumulateThoughtCache feeds an AgentThoughtBlockUpdatedEvent's
// (already-scrubbed) narration into acc, once per stepId. Thought blocks
// were never observed to rebroadcast in the Phase-0 capture (unlike
// Terminal/FileChanges/Result, which do — see the package doc), but the
// guard costs nothing and keeps the contract explicit rather than relying
// on that never recurring.
func accumulateThoughtCache(acc *cacheobs.Accumulator, cacheDone map[string]bool, key, text string) {
	if key != "" && cacheDone[key] {
		return
	}
	canon, ok := marshalTextBlock(text)
	if !ok {
		return
	}
	if key != "" {
		cacheDone[key] = true
	}
	acc.ObserveBlocks([]models.CacheBlockMeta{{
		LevelLabel:     "message",
		Kind:           "thinking",
		CanonicalBytes: canon,
		Role:           "assistant",
	}})
}

// accumulateTerminalCache feeds a Terminal block's command+output into acc
// exactly once, at the point the block FIRST reaches a terminal status
// (COMPLETED/FAILED). The IN_PROGRESS occurrence carries no Output yet,
// and the later completion-rebroadcast (see the package doc's
// rebroadcast-after-terminal finding) repeats the SAME terminal-status
// content byte-for-byte — accumulating on that first terminal transition
// captures the block's full content exactly once, never double-counted.
// Confirmed against the testdata/junie fixture: every TerminalBlock's
// IN_PROGRESS occurrence carries Output="", and its COMPLETED/FAILED
// occurrence is repeated byte-identical at the enclosing task's
// completion rebroadcast.
func accumulateTerminalCache(acc *cacheobs.Accumulator, cacheDone map[string]bool, key string, ae *agentEventRaw) {
	if cacheDone[key] {
		return
	}
	if ae.Status != blockStatusCompleted && ae.Status != blockStatusFailed {
		return
	}
	canon, ok := marshalTerminalBlock(ae)
	if !ok {
		return
	}
	cacheDone[key] = true
	acc.ObserveBlocks([]models.CacheBlockMeta{{
		LevelLabel:     "message",
		Kind:           "tool_result",
		CanonicalBytes: canon,
		Role:           "tool",
	}})
}

// accumulateFileChangesCache feeds a FileChanges block's diff+details into
// acc exactly once, at the point the block first reaches COMPLETED/FAILED
// — mirroring accumulateTerminalCache's reasoning. Unlike a Terminal
// block, a FileChanges block's `changes` are already populated at
// IN_PROGRESS; only `details` (the natural-language summary) is added at
// the terminal transition, so waiting for that transition still captures
// strictly more content, never less.
func accumulateFileChangesCache(acc *cacheobs.Accumulator, cacheDone map[string]bool, key string, ae *agentEventRaw) {
	if cacheDone[key] {
		return
	}
	if ae.Status != blockStatusCompleted && ae.Status != blockStatusFailed {
		return
	}
	canon, ok := marshalFileChangesBlock(ae)
	if !ok {
		return
	}
	cacheDone[key] = true
	acc.ObserveBlocks([]models.CacheBlockMeta{{
		LevelLabel:     "message",
		Kind:           "tool_result",
		CanonicalBytes: canon,
		Role:           "tool",
	}})
}

// accumulateMCPCache feeds an MCP block's tool name + arguments +
// outcome summary into acc exactly once, at the point the block first
// reaches a terminal status — mirroring accumulateTerminalCache's
// reasoning exactly. Grounded on the 2026-09-03 IDE/MCP capture: an MCP
// block's `details` MIRRORS its `input` while IN_PROGRESS and only
// becomes the outcome summary at the terminal transition, and every one
// of the 8 observed steps is then repeated byte-identical at the
// enclosing task's completion rebroadcast — so gating on the first
// terminal transition captures the block's full content exactly once.
func accumulateMCPCache(acc *cacheobs.Accumulator, cacheDone map[string]bool, key string, ae *agentEventRaw) {
	if cacheDone[key] {
		return
	}
	if ae.Status != blockStatusCompleted && ae.Status != blockStatusFailed {
		return
	}
	canon, ok := marshalMCPBlock(ae)
	if !ok {
		return
	}
	cacheDone[key] = true
	acc.ObserveBlocks([]models.CacheBlockMeta{{
		LevelLabel:     "message",
		Kind:           "tool_result",
		CanonicalBytes: canon,
		Role:           "tool",
	}})
}

// marshalMCPBlock produces the canonical form of an MCP block's tool
// name + input + outcome summary.
func marshalMCPBlock(ae *agentEventRaw) ([]byte, bool) {
	if ae.ToolName == "" && ae.Input == "" && ae.Details == "" {
		return nil, false
	}
	payload := struct {
		Type    string `json:"type"`
		Tool    string `json:"tool,omitempty"`
		Input   string `json:"input,omitempty"`
		Details string `json:"details,omitempty"`
		Status  string `json:"status,omitempty"`
	}{Type: "mcp", Tool: ae.ToolName, Input: ae.Input, Details: ae.Details, Status: ae.Status}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, false
	}
	return buf, true
}

// accumulateResultCache feeds a Result block's title+result into acc,
// once per stepId — on the block's FIRST occurrence only, unconditionally
// (no terminal-status gate, unlike Terminal/FileChanges). Confirmed
// against the testdata/junie fixture: a Result block's agentEvent payload
// is byte-identical across its IN_PROGRESS-envelope and
// COMPLETED-envelope occurrences (only the OUTER envelope.event.state
// differs, never agentEvent itself) — so the first occurrence already
// carries the block's full and final content, and calling this from the
// creation branch alone (see emitResultBlock) is sufficient; calling it
// again from the update-in-place branch would double-count.
func accumulateResultCache(acc *cacheobs.Accumulator, ae *agentEventRaw) {
	canon, ok := marshalResultBlock(ae)
	if !ok {
		return
	}
	acc.ObserveBlocks([]models.CacheBlockMeta{{
		LevelLabel:     "message",
		Kind:           "text",
		CanonicalBytes: canon,
		Role:           "assistant",
	}})
}

// marshalTextBlock produces the deterministic JSON canonical form of a
// plain text block (a user prompt or an agent thought). Each payload is an
// explicit STRUCT (never a map) so encoding/json's deterministic field
// order preserves the R3 byte-stability invariant.
func marshalTextBlock(text string) ([]byte, bool) {
	if text == "" {
		return nil, false
	}
	payload := struct {
		Type string `json:"type"`
		Text string `json:"text,omitempty"`
	}{Type: "text", Text: text}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, false
	}
	return buf, true
}

// marshalTerminalBlock produces the canonical form of a Terminal block's
// command + output + status.
func marshalTerminalBlock(ae *agentEventRaw) ([]byte, bool) {
	if ae.Command == "" && ae.Output == "" {
		return nil, false
	}
	payload := struct {
		Type    string `json:"type"`
		Command string `json:"command,omitempty"`
		Output  string `json:"output,omitempty"`
		Status  string `json:"status,omitempty"`
	}{Type: "terminal", Command: ae.Command, Output: ae.Output, Status: ae.Status}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, false
	}
	return buf, true
}

// marshalFileChangesBlock produces the canonical form of a FileChanges
// block's diff (path + after-content, the FIRST change entry — mirroring
// applyFileChangesFields' own "first entry" convention) plus its
// natural-language details.
func marshalFileChangesBlock(ae *agentEventRaw) ([]byte, bool) {
	if len(ae.Changes) == 0 && ae.Details == "" {
		return nil, false
	}
	var path, afterText string
	if len(ae.Changes) > 0 {
		c := ae.Changes[0]
		path = c.AfterRelativePath
		if path == "" {
			path = c.BeforeRelativePath
		}
		if c.AfterContent != nil {
			afterText = c.AfterContent.Text
		}
	}
	payload := struct {
		Type    string `json:"type"`
		Path    string `json:"path,omitempty"`
		After   string `json:"after,omitempty"`
		Details string `json:"details,omitempty"`
	}{Type: "file_changes", Path: path, After: afterText, Details: ae.Details}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, false
	}
	return buf, true
}

// marshalResultBlock produces the canonical form of a Result block's
// title + result text.
func marshalResultBlock(ae *agentEventRaw) ([]byte, bool) {
	if ae.Title == "" && ae.Result == "" {
		return nil, false
	}
	payload := struct {
		Type   string `json:"type"`
		Title  string `json:"title,omitempty"`
		Result string `json:"result,omitempty"`
	}{Type: "result", Title: ae.Title, Result: ae.Result}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, false
	}
	return buf, true
}

// emitCacheObservations drains cacheAcc's pending content-block delta into
// one CacheTurnObservation per non-zero modelUsage entry, in the SAME
// order and using the IDENTICAL "llm:<lineStart>:<i>" message-id shape
// emitTokens builds its sibling TokenEvents with — mirroring cowork's
// multi-model-per-turn convention: only the first non-zero entry receives
// the accumulated block delta, since Accumulator.Emit drains it; every
// subsequent model in the same record gets a delta-drained (zero
// BlockHashes) observation.
//
// A block accumulated after the LAST LlmResponseMetadataEvent in a given
// parse window (a Terminal/FileChanges/Result block that completes but is
// never followed by another LLM call before this poll's EOF) is not drained
// here and, because Junie is parsed incrementally forward from a persisted
// byte offset rather than whole-file-rescanned, is never re-read on a
// later call either — an inherent limitation shared with every other
// incrementally-parsed Tier-2 producer (cline, cowork), not unique to
// Junie: the cache-chain is a best-effort observation, never a guaranteed
// complete one.
func emitCacheObservations(acc *cacheobs.Accumulator, path, sessionID string, lineStart int64, ts time.Time, modelUsage []modelUsageRaw) []models.CacheTurnObservation {
	var out []models.CacheTurnObservation
	for i, m := range modelUsage {
		if m.isZero() {
			continue
		}
		usage := models.CacheUsage{
			NetInputTokens:      m.InputTokens,
			OutputTokens:        m.OutputTokens,
			CacheReadTokens:     m.CacheInputTokens,
			CacheCreationTokens: m.CacheCreateTokens,
		}
		if cacheobs.IsZeroUsage(usage) {
			continue
		}
		messageID := fmt.Sprintf("llm:%d:%d", lineStart, i)
		obs := acc.Emit(path, sessionID, messageID, m.Model, ts, usage, false)
		// §15.3 boundary: Junie never records which upstream provider
		// served a given model (its LlmResponseMetadataEvent carries only
		// a model string), so provider is always "" here and
		// IsImplicitCacheProvider short-circuits to false — this call is
		// a no-op today, kept only for consistency with every other
		// Tier-2 producer's identical three-line overlay.
		obs = cacheobs.ApplyImplicitCacheOverlay(obs, "", m.Model)
		out = append(out, obs)
	}
	return out
}
