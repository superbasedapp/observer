package policy

import "fmt"

// Decision is the outcome class of a policy evaluation. Decisions are
// ordered by strictness — DecisionAllow < DecisionFlag < DecisionAsk <
// DecisionDeny — and that ordering is load-bearing: verdict-winner
// selection (engine.go) and the §4.6 one-way layering merge (G3) both
// compare decisions, and a layer may only ever escalate, never relax.
type Decision int

// Decision values in strictness order.
const (
	// DecisionAllow lets the action proceed silently.
	DecisionAllow Decision = iota
	// DecisionFlag records and alerts but lets the action proceed.
	DecisionFlag
	// DecisionAsk defers to a human (client-native prompt where the
	// client supports it; otherwise the §6.2 degradation applies at
	// the emission seam, never here).
	DecisionAsk
	// DecisionDeny blocks the action with an LLM-readable reason.
	DecisionDeny
)

// String returns the stable lowercase form used in config files,
// guard_events rows and JSON surfaces: "allow", "flag", "ask", "deny".
func (d Decision) String() string {
	switch d {
	case DecisionAllow:
		return "allow"
	case DecisionFlag:
		return "flag"
	case DecisionAsk:
		return "ask"
	case DecisionDeny:
		return "deny"
	default:
		return fmt.Sprintf("decision(%d)", int(d))
	}
}

// ParseDecision converts a stable string form back into a Decision.
// It is the inverse of Decision.String and exists for the TOML policy
// loader (G3) and CLI surfaces (G5); unknown strings are an error so
// a typo in a policy file is loud, never silently weaker.
func ParseDecision(s string) (Decision, error) {
	switch s {
	case "allow":
		return DecisionAllow, nil
	case "flag":
		return DecisionFlag, nil
	case "ask":
		return DecisionAsk, nil
	case "deny":
		return DecisionDeny, nil
	default:
		return DecisionAllow, fmt.Errorf("policy.ParseDecision: unknown decision %q", s)
	}
}

// StricterOf returns the stricter of two decisions per the Decision
// ordering. It is the primitive the §4.6 layering merge builds on.
func StricterOf(a, b Decision) Decision {
	if a > b {
		return a
	}
	return b
}

// Severity grades how serious a rule hit is, independent of the
// Decision taken on it (an observe-mode verdict can be
// flag/critical). Ordered: SeverityInfo < SeverityWarn < SeverityHigh
// < SeverityCritical.
type Severity int

// Severity values in ascending order of seriousness.
const (
	// SeverityInfo is informational only.
	SeverityInfo Severity = iota
	// SeverityWarn is worth surfacing but routine.
	SeverityWarn
	// SeverityHigh is a likely-unintended or risky action.
	SeverityHigh
	// SeverityCritical is an action with irreversible or
	// security-sensitive consequences.
	SeverityCritical
)

// String returns the stable lowercase form used in config files,
// guard_events rows and JSON surfaces: "info", "warn", "high",
// "critical".
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarn:
		return "warn"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return fmt.Sprintf("severity(%d)", int(s))
	}
}

// ParseSeverity converts a stable string form back into a Severity.
// Inverse of Severity.String; for the G3 loader and G5 CLI. Unknown
// strings are an error.
func ParseSeverity(s string) (Severity, error) {
	switch s {
	case "info":
		return SeverityInfo, nil
	case "warn":
		return SeverityWarn, nil
	case "high":
		return SeverityHigh, nil
	case "critical":
		return SeverityCritical, nil
	default:
		return SeverityInfo, fmt.Errorf("policy.ParseSeverity: unknown severity %q", s)
	}
}

// SourceBuiltin marks a verdict produced by a built-in rule table.
// Later layers add "user", "project", "org" and "llm_judge" (spec
// §3.4); G1 only ever emits builtin.
const SourceBuiltin = "builtin"

// Verdict is the result of evaluating one Event against the effective
// policy — the only type (besides Event and Capabilities) that crosses
// the seam back to hot paths. Field semantics follow spec §3.4
// exactly.
type Verdict struct {
	// Decision is the outcome class, already adjusted for the
	// engine's mode (a rule's observe-mode and enforce-mode
	// decisions can differ — spec §5 catalog columns).
	Decision Decision
	// RuleID is the stable public ID of the winning rule ("R-101").
	// Empty when no rule hit (the allow verdict).
	RuleID string
	// Severity is the winning rule's severity grade.
	Severity Severity
	// Reason is written FOR THE AGENT (spec §4.2): one sentence of
	// what was matched and why it matters. Agents read this and
	// self-correct.
	Reason string
	// Advice is the optional remediation hint ("Use
	// --force-with-lease ..."), appended to Reason by emission
	// surfaces that only carry one string.
	Advice string
	// Source identifies the policy layer that produced the verdict:
	// "builtin" | "user" | "project" | "org" | "llm_judge". G1 emits
	// only SourceBuiltin.
	Source string
	// Overridable carries Rule.Overridable onto the verdict: the
	// organization published a bundle that lets a developer override
	// THIS rule on their own node. It is read by the emission seam
	// (an overridable deny presents as an ask where the channel can
	// prompt) and by the §6.3 approvals register (a grant for a
	// non-overridable rule under an org bundle is inert). False on
	// every individual node — nothing consults it there.
	Overridable bool
}
