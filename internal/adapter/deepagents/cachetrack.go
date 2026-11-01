package deepagents

import (
	"encoding/json"

	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// MaxBlocksPerSession caps the per-thread Tier-2 accumulator's running block
// count (same memory budget and OOM guard as the claudecode template).
const MaxBlocksPerSession = cacheobs.DefaultMaxBlocksPerSession

// accumulateTextCache feeds one already-scrubbed text block into acc, tagged
// by the message role.
func accumulateTextCache(acc *cacheobs.Accumulator, text, role string) {
	canon, ok := marshalCacheBlock("text", text)
	if !ok {
		return
	}
	acc.ObserveBlocks([]models.CacheBlockMeta{{
		LevelLabel:     "message", // transcripts never expose tools/system
		Kind:           "text",
		CanonicalBytes: canon,
		Role:           role,
	}})
}

// accumulateToolResultCache feeds one already-scrubbed, flattened tool result
// into acc.
func accumulateToolResultCache(acc *cacheobs.Accumulator, scrubbedText string) {
	canon, ok := marshalCacheBlock("tool_result", scrubbedText)
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

// accumulateToolCallCache feeds one assistant tool call (name plus the
// already-scrubbed argument JSON) into acc.
func accumulateToolCallCache(acc *cacheobs.Accumulator, name, scrubbedInput string) {
	if name == "" && scrubbedInput == "" {
		return
	}
	// An explicit struct (never a map) keeps encoding/json's field order
	// deterministic: the engine's rolling chain hash needs byte-stable
	// canonical forms.
	payload := struct {
		Type  string `json:"type"`
		Name  string `json:"name,omitempty"`
		Input string `json:"input,omitempty"`
	}{Type: "tool_use", Name: name, Input: scrubbedInput}
	canon, err := json.Marshal(payload)
	if err != nil {
		return
	}
	acc.ObserveBlocks([]models.CacheBlockMeta{{
		LevelLabel:     "message",
		Kind:           "tool_use",
		CanonicalBytes: canon,
		Role:           "assistant",
	}})
}

// marshalCacheBlock produces the deterministic canonical form of a
// {type, text} block.
func marshalCacheBlock(typ, text string) ([]byte, bool) {
	if text == "" {
		return nil, false
	}
	payload := struct {
		Type string `json:"type"`
		Text string `json:"text,omitempty"`
	}{Type: typ, Text: text}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, false
	}
	return buf, true
}
