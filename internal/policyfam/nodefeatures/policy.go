package nodefeatures

import (
	"fmt"
	"strings"
)

// Feature names — the CLOSED set of node-local capabilities this family
// can govern. New features are appended, never renamed/removed (an
// already-published body's keys must keep meaning what they meant).
const (
	FeatureTerminals     = "terminals"
	FeatureRemote        = "remote"
	FeatureRoutingApply  = "routing_apply"
	FeaturePatternsWrite = "patterns_write"
)

// AllFeatures lists every governable feature in a stable order — used by
// the lint/validation test and by callers that want to render every row
// (e.g. the web2 authoring form) without hardcoding the set twice.
var AllFeatures = []string{FeatureTerminals, FeatureRemote, FeatureRoutingApply, FeaturePatternsWrite}

// FeatureRule is a compiled per-feature governance decision. Governed is
// false when the published body did not mention this feature at all — in
// which case the feature stays ungoverned (fail-open) regardless of
// Enabled's zero value, which is why the two are kept separate rather than
// collapsing to a single bool.
type FeatureRule struct {
	Governed bool
	Enabled  bool
}

// TerminalsRule extends FeatureRule with the two terminal-specific limits
// the org can additionally set once terminals are governed.
type TerminalsRule struct {
	FeatureRule
	// MaxConcurrent caps concurrently-running embedded terminals for this
	// node when > 0. Zero means the org body did not set a limit (no
	// additional cap beyond the node's own [terminal.launch] config).
	//
	// NOTE (deviation, reported): MaxConcurrent is compiled and carried on
	// the spec so an org can author it and see it round-trip, but no
	// enforcement seam currently reads it — the dashboard has no existing
	// "how many terminals are running right now" query it can consult
	// without new plumbing this wave did not add. See the wave report.
	MaxConcurrent int
	// SandboxRequired, when true and the feature is enabled, additionally
	// requires every fresh terminal launch to run inside the B9 sandbox.
	SandboxRequired bool
}

// ToolsRule governs which integration-registry tools (adapters) this node
// may launch or route, as a disallow list — the P7 gateway-arc node-side
// honor path for the "org_disallow" enforcement bucket
// (docs/plans/plane-b-gateway-implementation-tracker-2026-08-29.md Phase
// P7 item 4). Like the other rules in this family, Governed=false means
// the org body never mentioned a tools stanza at all, which fails open
// exactly like an absent Terminals/Remote/RoutingApply/PatternsWrite
// stanza — an org can also publish a governed EMPTY disallow list as a
// positive "nothing is disallowed" assertion, distinct from never having
// opined.
type ToolsRule struct {
	Governed bool
	// Disallow holds lower-cased, trimmed integration-registry tool names
	// (Capability.Tool, e.g. "codex", "opencode") that this node must
	// refuse to launch or route.
	Disallow map[string]bool
}

// PolicySpec is the compiled, ready-to-evaluate node.features policy: one
// rule per governed feature, plus the content hash used by policy_state to
// report which body is currently effective. A feature absent from the
// published body compiles to a zero-value FeatureRule (Governed=false),
// which Allowed/TerminalDecision treat as fail-open.
type PolicySpec struct {
	Terminals     TerminalsRule
	Remote        FeatureRule
	RoutingApply  FeatureRule
	PatternsWrite FeatureRule
	Tools         ToolsRule
	Hash          string
}

// Decision is the outcome of evaluating one feature against a PolicySpec.
// Reason is a human-readable, user-facing string — set only when Allowed is
// false — so every enforcement seam can surface it verbatim without
// composing its own denial copy (keeping the wording consistent across the
// four seams, per the wave's requirement).
type Decision struct {
	Allowed bool
	Reason  string
}

// denyReason is the exact wording the org-parity W5.1 task specifies for a
// policy-denied action, shared by every feature so the copy never drifts
// between seams.
const denyReason = "disabled by organization policy — request access via 'observer org request'"

// sandboxDenyReason is the terminals-specific denial when the feature is
// enabled but the org additionally requires sandboxing and the caller did
// not request one.
const sandboxDenyReason = "organization policy requires a sandboxed terminal for this feature — retry with sandbox enabled"

// toolDenyReason names the specific disallowed tool so the operator sees
// exactly what is blocked, rather than the generic denyReason.
func toolDenyReason(tool string) string {
	return fmt.Sprintf("organization policy disallows launching %q — request access via 'observer org request'", tool)
}

// allowOpen is the shared fail-open Decision: no policy installed, or the
// installed policy doesn't opine on this feature.
var allowOpen = Decision{Allowed: true}

// FeatureDecision evaluates one of the three simple (enabled-only) governed
// features: remote, routing_apply, patterns_write. spec == nil (no
// node.features policy accepted on this node — no org enrolment, or an
// enrolled org that never published this family) fails OPEN, matching
// every other individual/ungoverned-node behavior in this codebase.
// FeatureTerminals is NOT handled here — use TerminalDecision, which also
// carries the sandbox_required limit.
func FeatureDecision(spec *PolicySpec, feature string) Decision {
	if spec == nil {
		return allowOpen
	}
	rule, ok := ruleFor(spec, feature)
	if !ok {
		// Unknown feature name is a caller bug, not an org decision to
		// enforce — fail open rather than let a typo silently brick an
		// unrelated capability.
		return allowOpen
	}
	if !rule.Governed || rule.Enabled {
		return allowOpen
	}
	return Decision{Allowed: false, Reason: denyReason}
}

// TerminalDecision evaluates the terminals feature, which additionally
// carries the sandbox_required limit (max_concurrent is compiled but not
// enforced here — see TerminalsRule.MaxConcurrent's doc comment).
// requestedSandbox is the caller's own Sandbox request for this launch.
func TerminalDecision(spec *PolicySpec, requestedSandbox bool) Decision {
	if spec == nil {
		return allowOpen
	}
	rule := spec.Terminals
	if !rule.Governed {
		return allowOpen
	}
	if !rule.Enabled {
		return Decision{Allowed: false, Reason: denyReason}
	}
	if rule.SandboxRequired && !requestedSandbox {
		return Decision{Allowed: false, Reason: sandboxDenyReason}
	}
	return allowOpen
}

// ToolDecision evaluates the tools feature — the P7 gateway-arc
// org_disallow honor path. tool is matched case-insensitively (and
// trimmed) against the published disallow list. spec == nil or an
// ungoverned Tools stanza fails OPEN, matching every other
// individual/ungoverned-node decision in this family; this function never
// reaches out anywhere — the node enforces the decision locally at its own
// launch seam.
func ToolDecision(spec *PolicySpec, tool string) Decision {
	if spec == nil || !spec.Tools.Governed {
		return allowOpen
	}
	key := strings.ToLower(strings.TrimSpace(tool))
	if spec.Tools.Disallow[key] {
		return Decision{Allowed: false, Reason: toolDenyReason(tool)}
	}
	return allowOpen
}

// ruleFor resolves the plain FeatureRule for the three simple features.
func ruleFor(spec *PolicySpec, feature string) (FeatureRule, bool) {
	switch feature {
	case FeatureRemote:
		return spec.Remote, true
	case FeatureRoutingApply:
		return spec.RoutingApply, true
	case FeaturePatternsWrite:
		return spec.PatternsWrite, true
	default:
		return FeatureRule{}, false
	}
}
