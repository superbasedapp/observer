package kimchi

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// MaxBlocksPerSession caps the per-parse Tier-2 accumulator's running
// block count (the shared cacheobs default, same OOM guard as every other
// Tier-2 producer).
const MaxBlocksPerSession = cacheobs.DefaultMaxBlocksPerSession

// apiCacheFamily resolves a record's pi-mono `api` wire name into the
// provider family cachetrack's implicit-cache table understands. Kimchi's
// `provider` field names an ACCOUNT lane (`kimchi-dev`, `openai-codex`)
// that the table does not know, while `api` names the wire protocol the
// call actually spoke — which is what decides whether the upstream caches
// implicitly (OpenAI-shape) or by explicit breakpoints (Anthropic-shape).
// Ordered prefix table, first match wins; no match = "" (cachetrack's
// conservative Anthropic default).
var apiCacheFamily = []struct {
	prefix string
	family string
}{
	// grounded live: "openai-completions" (kimchi-dev gateway) and
	// "openai-codex-responses" (ChatGPT sign-in lane).
	{prefix: "openai-", family: "openai"},
	// pi-mono's Anthropic Messages lane (not observed in the operator's
	// sessions; named so it never falls into the OpenAI bucket).
	{prefix: "anthropic-", family: "anthropic"},
}

// cacheFamilyForAPI walks apiCacheFamily.
func cacheFamilyForAPI(api string) string {
	a := strings.ToLower(strings.TrimSpace(api))
	for _, r := range apiCacheFamily {
		if strings.HasPrefix(a, r.prefix) {
			return r.family
		}
	}
	return ""
}

// observeText feeds one (already scrubbed) text block into acc.
func observeText(acc *cacheobs.Accumulator, text, role string) {
	canon, ok := marshalCacheBlock(struct {
		Type string `json:"type"`
		Text string `json:"text,omitempty"`
	}{Type: "text", Text: text}, text == "")
	if !ok {
		return
	}
	acc.ObserveBlocks([]models.CacheBlockMeta{{
		LevelLabel: "message", Kind: "text", CanonicalBytes: canon, Role: role,
	}})
}

// observeToolCall feeds one tool call's name + (already scrubbed) input.
func observeToolCall(acc *cacheobs.Accumulator, name, input string) {
	canon, ok := marshalCacheBlock(struct {
		Type  string `json:"type"`
		Name  string `json:"name,omitempty"`
		Input string `json:"input,omitempty"`
	}{Type: "tool_use", Name: name, Input: input}, name == "" && input == "")
	if !ok {
		return
	}
	acc.ObserveBlocks([]models.CacheBlockMeta{{
		LevelLabel: "message", Kind: "tool_use", CanonicalBytes: canon, Role: "assistant",
	}})
}

// observeToolResult feeds one tool result's (already scrubbed) text.
func observeToolResult(acc *cacheobs.Accumulator, text string) {
	canon, ok := marshalCacheBlock(struct {
		Type string `json:"type"`
		Text string `json:"text,omitempty"`
	}{Type: "tool_result", Text: text}, text == "")
	if !ok {
		return
	}
	acc.ObserveBlocks([]models.CacheBlockMeta{{
		LevelLabel: "message", Kind: "tool_result", CanonicalBytes: canon, Role: "tool",
	}})
}

// marshalCacheBlock produces the deterministic canonical JSON of one block
// (an explicit struct, never a map, so field order is byte-stable). skip
// short-circuits empty blocks.
func marshalCacheBlock(payload any, skip bool) ([]byte, bool) {
	if skip {
		return nil, false
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, false
	}
	return buf, true
}

// emitCacheObservation drains acc's pending block delta into one
// observation for a record's usage envelope. input is already NET (see
// usage), so it maps onto NetInputTokens unchanged; output is the
// reasoning-free half of the split. Returns nil on an all-zero envelope.
func emitCacheObservation(acc *cacheobs.Accumulator, path, sessionID, messageID, model, api string, ts time.Time, u *usage) *models.CacheTurnObservation {
	output, _ := u.split()
	cu := models.CacheUsage{
		NetInputTokens:      u.Input,
		OutputTokens:        output,
		CacheReadTokens:     u.CacheRead,
		CacheCreationTokens: u.CacheWrite,
	}
	if cacheobs.IsZeroUsage(cu) {
		return nil
	}
	obs := acc.Emit(path, sessionID, messageID, model, ts, cu, false)
	obs = cacheobs.ApplyImplicitCacheOverlay(obs, cacheFamilyForAPI(api), model)
	return &obs
}
