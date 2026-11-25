package kirocli

import (
	"encoding/json"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// MaxBlocksPerSession caps the per-conversation Tier-2 accumulator's
// running block count: the shared cacheobs default (same memory budget,
// same OOM guard as every other Tier-2 producer).
const MaxBlocksPerSession = cacheobs.DefaultMaxBlocksPerSession

// accumulateTurnCache feeds one conversations_v2 history entry's user
// and assistant content into acc, in wire order: the user's prompt or
// tool-use-results, then the assistant's tool_use calls or text
// response. Text blocks use the shared cacheobs form; the tool blocks
// keep kiro-cli's own fields (id, status, result_text). Only the SQLite (conversations_v2) path calls this — the
// flat-bundle path's turn metadata carries no cache fields at all (see
// flatTurnMeta in flat.go), so there is nothing to accumulate there.
func accumulateTurnCache(acc *cacheobs.Accumulator, h sqliteHistory) {
	var blocks []models.CacheBlockMeta
	if h.User.Content.Prompt != nil {
		if canon, ok := cacheobs.MarshalTextBlock(h.User.Content.Prompt.Prompt); ok {
			blocks = append(blocks, models.CacheBlockMeta{
				LevelLabel:     "message", // R1: transcripts never expose tools/system
				Kind:           "text",
				CanonicalBytes: canon,
				Role:           "user",
			})
		}
	}
	if h.User.Content.ToolUseResults != nil {
		for _, r := range h.User.Content.ToolUseResults.ToolUseResults {
			if canon, ok := marshalCacheToolResultBlock(r); ok {
				blocks = append(blocks, models.CacheBlockMeta{
					LevelLabel:     "message",
					Kind:           "tool_result",
					CanonicalBytes: canon,
					Role:           "tool",
				})
			}
		}
	}
	if h.Assistant.ToolUse != nil {
		for _, tu := range h.Assistant.ToolUse.ToolUses {
			if canon, ok := marshalCacheToolUseBlock(tu); ok {
				blocks = append(blocks, models.CacheBlockMeta{
					LevelLabel:     "message",
					Kind:           "tool_use",
					CanonicalBytes: canon,
					Role:           "assistant",
				})
			}
		}
	}
	if h.Assistant.Response != nil {
		if canon, ok := cacheobs.MarshalTextBlock(h.Assistant.Response.Content); ok {
			blocks = append(blocks, models.CacheBlockMeta{
				LevelLabel:     "message",
				Kind:           "text",
				CanonicalBytes: canon,
				Role:           "assistant",
			})
		}
	}
	if len(blocks) > 0 {
		acc.ObserveBlocks(blocks)
	}
}

// marshalCacheToolUseBlock produces the canonical form of one assistant
// tool_use call.
func marshalCacheToolUseBlock(tu sqliteToolUseItem) ([]byte, bool) {
	if tu.Name == "" && len(tu.Args) == 0 {
		return nil, false
	}
	payload := struct {
		Type string          `json:"type"`
		ID   string          `json:"id,omitempty"`
		Name string          `json:"name,omitempty"`
		Args json.RawMessage `json:"args,omitempty"`
	}{Type: "tool_use", ID: tu.ID, Name: tu.Name, Args: tu.Args}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, false
	}
	return buf, true
}

// marshalCacheToolResultBlock produces the canonical form of one user
// tool_use_results entry, reusing the same toolResultText flattening
// the normal event path uses.
func marshalCacheToolResultBlock(r sqliteToolResult) ([]byte, bool) {
	text := toolResultText(r.Content)
	if r.ToolUseID == "" && text == "" {
		return nil, false
	}
	payload := struct {
		Type       string `json:"type"`
		ToolUseID  string `json:"tool_use_id,omitempty"`
		Status     string `json:"status,omitempty"`
		ResultText string `json:"result_text,omitempty"`
	}{Type: "tool_result", ToolUseID: r.ToolUseID, Status: r.Status, ResultText: text}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, false
	}
	return buf, true
}

// emitCacheObservation drains acc's pending content-block delta into
// one CacheTurnObservation for a history entry's request_metadata, when
// that metadata carries anything worth persisting. Returns nil (no
// observation) when every token field is null or the derived
// CacheUsage is all-zero.
//
// uncached_input_tokens is already NET of the cache-read tokens (the
// field name is explicit — see sqliteReqMeta's doc comment in
// statedb.go), so no gross→net subtraction is needed here, matching
// tokenEvent's own handling of the same field.
func emitCacheObservation(acc *cacheobs.Accumulator, path, sessionID, messageID, model string, ts time.Time, m sqliteReqMeta) *models.CacheTurnObservation {
	if m.UncachedInputTokens == nil && m.OutputTokens == nil &&
		m.CacheReadInputTokens == nil && m.CacheWriteInputTokens == nil {
		return nil
	}
	usage := models.CacheUsage{
		NetInputTokens:      deref(m.UncachedInputTokens),
		OutputTokens:        deref(m.OutputTokens),
		CacheReadTokens:     deref(m.CacheReadInputTokens),
		CacheCreationTokens: deref(m.CacheWriteInputTokens),
	}
	// §15.3 boundary: Kiro CLI's SigV4 endpoint never surfaces which
	// upstream provider served a model (model_id is often the literal
	// string "auto"), so provider is always "" here — a no-op today,
	// kept for consistency with every other Tier-2 producer's identical
	// overlay.
	return acc.EmitTurn(path, sessionID, messageID, model, "", ts, usage)
}
