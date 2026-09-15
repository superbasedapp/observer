package aigateway

import (
	"regexp"
	"strconv"
)

// usageFieldRe matches a `"field": <int>` pair for the token-count field names
// both supported provider families emit. It is deliberately tolerant: it scans
// the concatenated SSE (or a single JSON body) and takes the MAX value seen per
// field, which is correct because both providers report cumulative counts in a
// stream's tail — the final event carries the largest value.
var usageFieldRe = regexp.MustCompile(`"(input_tokens|output_tokens|cache_read_input_tokens|cache_creation_input_tokens|prompt_tokens|completion_tokens|cached_tokens)"\s*:\s*(\d+)`)

// ExtractUsage pulls authoritative token usage from a provider response body
// (streamed SSE concatenation or a single JSON object). It maps both the
// Anthropic field names (input_tokens / output_tokens / cache_read_input_tokens
// / cache_creation_input_tokens) and the OpenAI names (prompt_tokens /
// completion_tokens / cached_tokens) onto the normalized Usage. kind selects
// which mapping wins when both families' names appear (they never should in one
// response, but the kind keeps the mapping unambiguous).
//
// It is best-effort by design: tokens are AUTHORITATIVE when present, and an
// absent count is zero rather than an error — the audit row still records the
// turn, and the dollar figure derived from a zero count is simply zero.
func ExtractUsage(kind ProviderKind, body []byte) Usage {
	max := map[string]int{}
	for _, m := range usageFieldRe.FindAllSubmatch(body, -1) {
		n, err := strconv.Atoi(string(m[2]))
		if err != nil {
			continue
		}
		field := string(m[1])
		if n > max[field] {
			max[field] = n
		}
	}
	var u Usage
	if _, ok := ParserForKind(kind); ok && kind == KindAnthropic {
		u.InputTokens = max["input_tokens"]
		u.OutputTokens = max["output_tokens"]
		u.CacheReadTokens = max["cache_read_input_tokens"]
		u.CacheWriteTokens = max["cache_creation_input_tokens"]
		return u
	}
	// OpenAI-compatible family (default). prompt_tokens is GROSS (includes
	// cached); the caller's rate card treats cached separately if it carries a
	// cache rate, so keep the raw split here.
	u.InputTokens = max["prompt_tokens"]
	u.OutputTokens = max["completion_tokens"]
	u.CacheReadTokens = max["cached_tokens"]
	// Fall back to Anthropic names if the OpenAI names were absent but the
	// Anthropic ones appeared (a custom upstream mislabeled its kind).
	if u.InputTokens == 0 && max["input_tokens"] > 0 {
		u.InputTokens = max["input_tokens"]
	}
	if u.OutputTokens == 0 && max["output_tokens"] > 0 {
		u.OutputTokens = max["output_tokens"]
	}
	return u
}
