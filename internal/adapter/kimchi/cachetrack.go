package kimchi

import (
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

// The canonical block forms live in cacheobs (message.go), so kimchi's
// chain bytes cannot drift from the other Tier-2 producers'. The wrappers
// below keep the parse loop's call sites unchanged.

// observeText feeds one (already scrubbed) text block into acc.
func observeText(acc *cacheobs.Accumulator, text, role string) {
	acc.ObserveText(text, role)
}

// observeToolCall feeds one tool call's name + (already scrubbed) input.
func observeToolCall(acc *cacheobs.Accumulator, name, input string) {
	acc.ObserveToolUse(name, input)
}

// observeToolResult feeds one tool result's (already scrubbed) text.
func observeToolResult(acc *cacheobs.Accumulator, text string) {
	acc.ObserveToolResult(text)
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
	return acc.EmitTurn(path, sessionID, messageID, model, cacheFamilyForAPI(api), ts, cu)
}
