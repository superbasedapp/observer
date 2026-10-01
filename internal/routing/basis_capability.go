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
	// Context-window fit (§R11.2): a candidate whose KNOWN window the
	// prompt already exceeds would 4xx upstream. An unknown window is
	// unknown — never a reason to exclude, never a default size
	// (Decide annotates such a switch with ReasonContextWindowUnknown).
	if win, known := contextWindow(bin.Snap, c.Model); known && bin.In.Shape.PromptTokens > win {
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

// contextWindow resolves a model's context window through the snapshot's
// injected resolver (Tokenomics data, resolved at the boundary). A nil
// snapshot or resolver, or a model the resolver does not know, reports
// known=false: this package holds no window table and assumes no default.
func contextWindow(snap *Snapshot, model string) (int64, bool) {
	if snap == nil || snap.ContextWindow == nil {
		return 0, false
	}
	win, known := snap.ContextWindow(model)
	if !known || win <= 0 {
		return 0, false
	}
	return win, true
}

// contextWindowUnverified reports whether a decision that switched models
// moved onto a candidate whose window fit could not be checked: the prompt
// size is known but the candidate's window is not.
func contextWindowUnverified(snap *Snapshot, in DecisionInput, d Decision) bool {
	if !d.Changed || in.Shape.PromptTokens <= 0 {
		return false
	}
	_, known := contextWindow(snap, d.SelectedModel)
	return !known
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
