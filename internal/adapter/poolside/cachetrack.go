package poolside

import (
	"encoding/json"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// MaxBlocksPerSession caps the per-session Tier-2 accumulator's running
// block count. Matches the claudecode/muse template's cap (same memory
// budget, same OOM guard).
const MaxBlocksPerSession = cacheobs.DefaultMaxBlocksPerSession

// accumulateTextCache feeds an already-scrubbed plain-text block (a user
// prompt or an assistant message) into acc under the given role.
func accumulateTextCache(acc *cacheobs.Accumulator, text, role string) {
	canon, ok := marshalCacheTextBlock(text)
	if !ok {
		return
	}
	acc.ObserveBlocks([]models.CacheBlockMeta{{
		LevelLabel:     "message", // R1: transcripts never expose tools/system
		Kind:           "text",
		CanonicalBytes: canon,
		Role:           role,
	}})
}

// accumulateToolCallCache feeds one tool_call.parsed's name + (already
// scrubbed) serialized input into acc.
func accumulateToolCallCache(acc *cacheobs.Accumulator, name, scrubbedInput string) {
	canon, ok := marshalCacheToolUseBlock(name, scrubbedInput)
	if !ok {
		return
	}
	acc.ObserveBlocks([]models.CacheBlockMeta{{
		LevelLabel:     "message",
		Kind:           "tool_use",
		CanonicalBytes: canon,
		Role:           "assistant",
	}})
}

// accumulateToolResultCache feeds one tool_call.result's (already
// scrubbed) observation text into acc.
func accumulateToolResultCache(acc *cacheobs.Accumulator, scrubbedText string) {
	canon, ok := marshalCacheToolResultBlock(scrubbedText)
	if !ok {
		return
	}
	acc.ObserveBlocks([]models.CacheBlockMeta{{
		LevelLabel:     "message",
		Kind:           "tool_result",
		CanonicalBytes: canon,
		Role:           "tool",
	}})
}

// marshalCacheTextBlock produces the deterministic JSON canonical form of
// a plain text block. Each payload is an explicit STRUCT (never a map) so
// encoding/json's deterministic field order preserves the R3
// byte-stability invariant.
func marshalCacheTextBlock(text string) ([]byte, bool) {
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

// marshalCacheToolUseBlock produces the canonical form of one tool call.
func marshalCacheToolUseBlock(name, input string) ([]byte, bool) {
	if name == "" && input == "" {
		return nil, false
	}
	payload := struct {
		Type  string `json:"type"`
		Name  string `json:"name,omitempty"`
		Input string `json:"input,omitempty"`
	}{Type: "tool_use", Name: name, Input: input}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, false
	}
	return buf, true
}

// marshalCacheToolResultBlock produces the canonical form of one tool
// result's flattened text.
func marshalCacheToolResultBlock(text string) ([]byte, bool) {
	if text == "" {
		return nil, false
	}
	payload := struct {
		Type string `json:"type"`
		Text string `json:"text,omitempty"`
	}{Type: "tool_result", Text: text}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, false
	}
	return buf, true
}

// emitCacheObservation drains acc's pending content-block delta into one
// CacheTurnObservation for a tool_call.inference.end record's usage, when
// tp carries anything worth persisting.
func emitCacheObservation(acc *cacheobs.Accumulator, path, sessionID, messageID, model string, ts time.Time, tp tokenParts) *models.CacheTurnObservation {
	usage := models.CacheUsage{
		NetInputTokens:      tp.inputNet,
		OutputTokens:        tp.outputNet,
		CacheReadTokens:     tp.cacheRead,
		CacheCreationTokens: tp.cacheWrit,
	}
	if cacheobs.IsZeroUsage(usage) {
		return nil
	}
	obs := acc.Emit(path, sessionID, messageID, model, ts, usage, false)
	// Poolside's tool_call.inference.end never states which upstream
	// provider served the model, so provider is always "" — a no-op
	// today, kept for consistency with every other Tier-2 producer's
	// identical overlay call.
	obs = cacheobs.ApplyImplicitCacheOverlay(obs, "", model)
	return &obs
}
