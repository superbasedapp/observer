package egress

import "slices"

// Action is the primary egress verb a rule resolves to (exactly one per rule,
// lint-enforced). The zero value ActionNone is "no egress action".
type Action string

const (
	// ActionNone is the zero value — no egress directive.
	ActionNone Action = ""
	// ActionRouteUpstream selects an alternate declared upstream (the
	// operator's "another resource").
	ActionRouteUpstream Action = "route_upstream"
	// ActionRouteModel swaps to a same-shape model (an explicit cheaper model
	// in v1).
	ActionRouteModel Action = "route_model"
	// ActionSetEffort degrades effort — best-effort, provider-compatible only.
	ActionSetEffort Action = "set_effort"
	// ActionDeny is a terminal refusal (fail-closed data-locality).
	ActionDeny Action = "deny"
)

// ProviderShape is the incoming wire shape. v1 is anthropic|openai only —
// Gemini is excluded (design finding 17): when this was written, admission's
// extractor sent non-OpenAI providers through the Anthropic parser, so a
// Gemini body yielded no text and skipped the gate. Admission now reads the
// shared promptturn.AdmissionView, which knows Gemini; egress is unchanged.
type ProviderShape string

const (
	ShapeAnthropic ProviderShape = "anthropic"
	ShapeOpenAI    ProviderShape = "openai"
)

// validShape reports whether s is a v1-supported provider shape.
func validShape(s string) bool {
	return s == string(ShapeAnthropic) || s == string(ShapeOpenAI)
}

// Effort is the Plane-A effort-degrade vocabulary, mirroring the routing effort
// names as a local enum (no internal/routing import).
type Effort string

const (
	EffortMinimal Effort = "minimal"
	EffortLow     Effort = "low"
	EffortMedium  Effort = "medium"
	EffortHigh    Effort = "high"
)

// validEffort reports whether s is a known effort level.
func validEffort(s string) bool {
	switch Effort(s) {
	case EffortMinimal, EffortLow, EffortMedium, EffortHigh:
		return true
	default:
		return false
	}
}

// OnUnavailable is the per-rule fail posture when a routed target is
// unavailable at runtime. The proxy owns the runtime enforcement (design §3.6 /
// finding 1); obs only expresses the intent.
const (
	OnUnavailableFailOpen = "fail_open"
	OnUnavailableDeny     = "deny"
)

// ReasonCode is the closed Plane-A reason vocabulary recorded on every egress
// decision row — never free text (design §4).
type ReasonCode string

const (
	ReasonFlaggedLocal       ReasonCode = "egress_flagged_local"
	ReasonBudgetBand         ReasonCode = "egress_budget_band"
	ReasonCohortUpstream     ReasonCode = "egress_cohort_upstream"
	ReasonOverloadDegrade    ReasonCode = "egress_overload_degrade"
	ReasonSensitiveLocalOnly ReasonCode = "egress_sensitive_local_only"
	ReasonDenyUnavailable    ReasonCode = "egress_deny_unavailable"
	ReasonFailOpen           ReasonCode = "egress_fail_open"
	ReasonNoRoute            ReasonCode = "egress_no_route"
	ReasonSwitchHeld         ReasonCode = "egress_switch_held"
	ReasonEffortNoop         ReasonCode = "egress_effort_noop"
)

// reasonCodes is the closed reason vocabulary in declaration order: the one
// list validReasonCode checks and ReasonCodes hands out. The dashboards'
// reason-code pickers read its TypeScript mirror, shared/lib/
// egressReasonCodes.ts, which reasoncodes_mirror_test.go pins to it (FRONT-02).
var reasonCodes = []ReasonCode{
	ReasonFlaggedLocal, ReasonBudgetBand, ReasonCohortUpstream,
	ReasonOverloadDegrade, ReasonSensitiveLocalOnly, ReasonDenyUnavailable,
	ReasonFailOpen, ReasonNoRoute, ReasonSwitchHeld, ReasonEffortNoop,
}

// ReasonCodes returns the closed reason vocabulary, in declaration order. The
// slice is a copy.
func ReasonCodes() []ReasonCode { return slices.Clone(reasonCodes) }

// validReasonCode reports whether s is a member of the closed reason enum.
func validReasonCode(s string) bool { return slices.Contains(reasonCodes, ReasonCode(s)) }

// Target is a typed upstream target: an id, its URL, and its declared wire
// shape. A shape is REQUIRED for any enforce-mode route_to_upstream (design
// finding 6) — [proxy.upstreams] entries are bare URLs with no shape, which
// cannot safely authorize a body/model rewrite.
type Target struct {
	ID    string
	URL   string
	Shape ProviderShape
}

// DecisionRank orders the admission decision vocabulary so verdict_at_least
// can match "this decision or stricter". An unknown/empty decision ranks as
// allow. Exported (unlike its previous obs/egress-local, unexported form) so
// internal/obs/egress's evaluation engine — which stays outside this
// package — can alias it without duplicating the table (single owner,
// CLAUDE.md #4).
var DecisionRank = map[string]int{
	"allow": 0,
	"flag":  1,
	"ask":   2,
	"deny":  3,
}

// SeverityRank orders the admission severity vocabulary for severity_at_least.
var SeverityRank = map[string]int{
	"info":     0,
	"warn":     1,
	"high":     2,
	"critical": 3,
}

// IsHardSwitch reports whether a rule is a hard governance rule (verdict /
// criterion / severity driven) whose model switch must not be held by the
// session pin/cooldown. Exported (moved here with CompiledRule, unlike its
// previous obs/egress-local, unexported form) because a Go method can only
// be declared in the package that defines its receiver type.
func (r CompiledRule) IsHardSwitch() bool {
	return r.When.VerdictAtLeast != "" || r.When.Criterion != "" || r.When.SeverityAtLeast != ""
}
