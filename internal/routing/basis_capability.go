package routing

import "strings"

// capabilityBasis is the always-on filter (§R6.2): it denies illegal
// switches — provider shape, context-window fit, tool-use support,
// entitlement class (§R11.2, §R11.3) — BEFORE ranking, so an illegal
// move is never discovered as an upstream 4xx. It runs first in every
// pipeline whether or not the policy lists it.
type capabilityBasis struct{}

var capabilityBasisSingleton Basis = capabilityBasis{}

// basisRegistry maps basis names to implementations. The framework
// commit registers capability; the bases commit fills the rest. An
// unregistered name resolves to nothing (fail-open; lint reports
// vocabulary misses).
var basisRegistry = map[string]Basis{
	BasisCapability: capabilityBasisSingleton,
}

func (capabilityBasis) Name() string      { return BasisCapability }
func (capabilityBasis) Class() BasisClass { return ClassFilter }

// Allow implements FilterBasis.
func (capabilityBasis) Allow(c ModelCandidate, bin BasisInput) (bool, ReasonCode) {
	// The incumbent is never capability-denied: it is what the client
	// already chose; routing must not make it illegal (G7).
	if c.Model == bin.In.Shape.Model {
		return true, ""
	}
	origShape := ShapeForModel(bin.In.Shape.Model)
	// Same-provider-shape only until cross-provider translation ships
	// (§R11.4); unknown shapes are never candidates.
	if c.Shape == ShapeUnknown || origShape == ShapeUnknown || c.Shape != origShape {
		return false, ReasonCapabilityHold
	}
	// Context-window fit (§R11.2): a candidate whose window the prompt
	// already exceeds would 4xx upstream.
	if bin.In.Shape.PromptTokens > 0 && bin.In.Shape.PromptTokens > contextWindowTokens(c.Model) {
		return false, ReasonCapabilityHold
	}
	// Tool-use support: requests carrying tool definitions can only
	// move to tool-capable candidates.
	if bin.In.Shape.ToolUseCount > 0 && !supportsTools(c.Model) {
		return false, ReasonCapabilityHold
	}
	// Entitlement guard (§R11.3): API-key traffic accepts any legal
	// rewrite; subscription (or unknown — treated restrictively)
	// traffic stays within the plan's native first-party set: the
	// original shape's own models, never router-prefixed slugs.
	if bin.In.Entitlement != EntitlementAPIKey && strings.Contains(c.Model, "/") {
		return false, ReasonEntitlementHold
	}
	return true, ""
}

// contextWindowTokens resolves a model's context window from the seed
// table by longest-prefix match. Unknown models get the conservative
// 200K default — the lowest common window among the families the
// engine routes between, so a fit check never passes on optimism.
func contextWindowTokens(model string) int64 {
	m := strings.ToLower(model)
	if norm := normalizeUnplacedModel(m); norm != "" {
		m = norm
	}
	best := ""
	var win int64
	for prefix, w := range seedContextWindows {
		if strings.HasPrefix(m, prefix) && len(prefix) > len(best) {
			best, win = prefix, w
		}
	}
	if best == "" {
		return defaultContextWindowTokens
	}
	return win
}

// defaultContextWindowTokens is the conservative unknown-model window.
const defaultContextWindowTokens int64 = 200_000

// seedContextWindows maps family prefixes to context windows (input
// tokens), per published provider limits as of 2026-06. Longest prefix
// wins. Values deliberately conservative: standard-tier windows, not
// beta/preview extensions.
var seedContextWindows = map[string]int64{
	"claude":          200_000,
	"claude-sonnet-4": 1_000_000, // 1M GA on Sonnet 4.x
	// Claude Sonnet 5.5: 1M context per Anthropic's models overview
	// (captured 2026-09-28).
	"claude-sonnet-5-5": 1_000_000,
	"gpt-5":             272_000,
	"gpt-4.1":           1_000_000,
	"gpt-4o":            128_000,
	"o1":                200_000,
	"o3":                200_000,
	"o4":                200_000,
	"gemini":            1_000_000,
	"deepseek":          128_000,
	"kimi":              256_000,
	"grok":              256_000,
	"qwen":              262_000,
	"glm":               200_000,
	"mistral":           128_000,
	"hermes":            128_000,
	"gpt-oss":           131_000,
	"nemotron":          131_000,
	"minimax":           1_000_000,
	"composer":          262_000,
	"kilo-auto/free":    262_000,
	"kilo-auto/small":   262_000,
	"ollama":            128_000,
}

// supportsTools reports tool-use capability. Every seed-table model
// supports tools today; the deny set exists so a future no-tools SKU
// is a one-line addition, not a new mechanism.
func supportsTools(model string) bool {
	m := strings.ToLower(model)
	for prefix := range noToolSupportPrefixes {
		if strings.HasPrefix(m, prefix) {
			return false
		}
	}
	return true
}

var noToolSupportPrefixes = map[string]struct{}{}
