package modelfamily

import "strings"

// FamilyMapVersion is the version of the model_family normalizer's mapping.
// Because remapping a model id to a different family later changes
// longitudinal results, the mapping is versioned and the version travels with
// every submission - folded into the envelope's cost_method_version (design
// §3.3, Open Q12). Bump this whenever a Family rule changes.
const FamilyMapVersion = "1"

// The closed model_family vocabulary (design §3.2/§3.3). Family always returns
// exactly one of these; an unrecognized model id collapses to FamilyOther so
// no long-tail / exotic model string can ever reach the wire. This is the
// k-anonymity-by-construction lever.
const (
	FamilyClaudeOpus   = "claude-opus"
	FamilyClaudeSonnet = "claude-sonnet"
	FamilyClaudeHaiku  = "claude-haiku"
	FamilyGPT5         = "gpt-5"
	FamilyGPT5Mini     = "gpt-5-mini"
	FamilyGeminiPro    = "gemini-pro"
	FamilyGeminiFlash  = "gemini-flash"
	FamilyGrok         = "grok"
	FamilyOpenWeight   = "open-weight"
	FamilyOther        = "other"
)

// Families is the complete closed set Family can return. Used by the coverage
// invariant test to assert totality.
var Families = []string{
	FamilyClaudeOpus,
	FamilyClaudeSonnet,
	FamilyClaudeHaiku,
	FamilyGPT5,
	FamilyGPT5Mini,
	FamilyGeminiPro,
	FamilyGeminiFlash,
	FamilyGrok,
	FamilyOpenWeight,
	FamilyOther,
}

// familyRule is one row of the table-driven normalizer: every substring in
// all must be present (after the model string is lowercased and its
// provider-prefix / OpenRouter tail stripped) for the rule to match. Rules are
// walked top-down, first match wins (design/CLAUDE.md rule #5 - ordered rule
// table, not an if/else ladder).
type familyRule struct {
	all    []string
	family string
}

// familyRules is ordered: the more specific tiers (mini/nano before the base
// gpt-5 tier; opus/sonnet/haiku before anything else) come first.
var familyRules = []familyRule{
	// Anthropic tiers - the token appears in every id form
	// (claude-opus-4-8, claude-3-opus, stealth/claude-sonnet-4.6, …).
	{all: []string{"opus"}, family: FamilyClaudeOpus},
	{all: []string{"fable"}, family: FamilyClaudeOpus}, // claude-fable-* is Opus-class
	{all: []string{"sonnet"}, family: FamilyClaudeSonnet},
	{all: []string{"haiku"}, family: FamilyClaudeHaiku},

	// OpenAI gpt-5 family: small tier (mini/nano) before the base tier so
	// gpt-5-mini / gpt-5.4-nano / gpt-5.1-codex-mini bucket as small.
	{all: []string{"gpt-5", "nano"}, family: FamilyGPT5Mini},
	{all: []string{"gpt-5", "mini"}, family: FamilyGPT5Mini},
	{all: []string{"gpt-5"}, family: FamilyGPT5},

	// Gemini: flash before pro is irrelevant (an id carries one or the
	// other), but pro-lite variants still match "pro" → gemini-pro is the
	// coarser bucket the report wants.
	{all: []string{"gemini", "flash"}, family: FamilyGeminiFlash},
	{all: []string{"gemini", "pro"}, family: FamilyGeminiPro},

	// xAI Grok.
	{all: []string{"grok"}, family: FamilyGrok},

	// Open-weight / self-hostable families collapse to one bucket - the
	// report treats them as a single "open-weight" category and their exact
	// SKU is not the moat-differentiated angle.
	{all: []string{"gpt-oss"}, family: FamilyOpenWeight},
	{all: []string{"nemotron"}, family: FamilyOpenWeight},
	{all: []string{"hermes"}, family: FamilyOpenWeight},
	{all: []string{"qwen"}, family: FamilyOpenWeight},
	{all: []string{"glm"}, family: FamilyOpenWeight},
	{all: []string{"mistral"}, family: FamilyOpenWeight},
	{all: []string{"minimax"}, family: FamilyOpenWeight},
	{all: []string{"kimi"}, family: FamilyOpenWeight},
	{all: []string{"deepseek"}, family: FamilyOpenWeight},
	{all: []string{"llama"}, family: FamilyOpenWeight},
	{all: []string{"ollama"}, family: FamilyOpenWeight},
}

// Family maps any model id to one of the fixed, closed Families. The mapping
// is pure and total: anything unrecognized (including "", "<unknown>", and any
// long-tail or exotic model string) returns FamilyOther - never the raw
// string. Provider prefixes ("openai/…", "x-ai/…", "stealth/…") and OpenRouter
// suffix tails (":free", ":nitro") are stripped before matching so the same
// model routed through different gateways normalizes identically.
func Family(modelID string) string {
	s := strings.ToLower(strings.TrimSpace(modelID))
	if s == "" {
		return FamilyOther
	}
	// Strip provider prefix: "openai/gpt-oss-120b" → "gpt-oss-120b",
	// "stealth/claude-sonnet-4.6" → "claude-sonnet-4.6".
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	// Strip an OpenRouter-style ":suffix" tail (":free", ":nitro").
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	for _, r := range familyRules {
		if matchesAll(s, r.all) {
			return r.family
		}
	}
	return FamilyOther
}

func matchesAll(s string, subs []string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

// StripRouterPrefix is the last-resort model-id reducer the pricing and
// routing lookups retry once after every other match has missed. It strips a
// router prefix (capi:, sweagent-capi:) and ALL leading provider path
// segments (openrouter/anthropic/foo -> foo) that a family-prefix ladder
// can't see past. It deliberately leaves the "auto" router sentinel and an
// empty string alone: neither names a real model, so both stay a miss.
// Returns "" when nothing was stripped.
func StripRouterPrefix(model string) string {
	out := model
	switch {
	case strings.HasPrefix(out, "capi:"):
		out = strings.TrimPrefix(out, "capi:")
	case strings.HasPrefix(out, "sweagent-capi:"):
		out = strings.TrimPrefix(out, "sweagent-capi:")
	}
	if i := strings.LastIndex(out, "/"); i >= 0 {
		out = out[i+1:] // drop ALL leading provider segments (a/b/c/model -> model)
	}
	if out == model || out == "" {
		return ""
	}
	return out
}
