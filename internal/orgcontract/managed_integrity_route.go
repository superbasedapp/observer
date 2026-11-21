package orgcontract

import (
	"sort"
	"strings"
)

// managed_integrity_route.go carries the per-surface route observation of the
// managed-integrity report (surface-gap arc Wave 1, finding OBS-6;
// docs/audits/surface-settings-precedence-gap-review-2026-10-25.md section 4):
// the closed "tool/surface_kind" label vocabulary of UnroutedSurfaces, its
// normalization, and the overall-health rule table that reads it beside the
// older sibling / route-drift State() and the capture checks.

// unroutedSurfaceTools is the CLOSED tool half of the UnroutedSurfaces
// vocabulary: the registry tools that declare per-surface route facts
// (integration Capability.RouteSurfaces), the only ones whose surfaces the
// node can judge as an observed bypass. It lives here, not in the
// integration registry, for the same reason as driftedToolLabels: the org
// server validates against the wire vocabulary without linking the node's
// registry. routeattest.TestRouteSurfaceToolsAreWireLabels fails when a
// registry tool gains route surfaces this table does not name.
//
// Adding a row is safe in both directions: NormalizeLabels runs on both
// sides, so an older server drops a label it does not know and an older node
// never sends one.
var unroutedSurfaceTools = map[string]bool{
	"aider":         true,
	"claude-code":   true,
	"cline-cli":     true,
	"codex":         true,
	"copilot-cli":   true,
	"crush":         true,
	"gemini-cli":    true,
	"goose":         true,
	"grok":          true,
	"hermes":        true,
	"kilo-code-cli": true,
	"kimi-code":     true,
	"opencode":      true,
	"pi":            true,
	"prime-agent":   true,
	"qwen-code":     true,
}

// unroutedSurfaceKinds is the CLOSED surface-kind half: the models.Surface*
// kinds (models.KnownSurface). An unstamped session ("") has no label of its
// own: a single-surface tool's unstamped group is judged, and labelled, as
// the surface its registry row names (its CLI); any other unstamped group
// is never a bypass. TestUnroutedSurfaceKindsMatchModels pins it.
var unroutedSurfaceKinds = map[string]bool{
	"cli":     true,
	"desktop": true,
	"ide":     true,
	"mobile":  true,
	"sdk":     true,
	"web":     true,
}

// UnroutedSurfaceLabel renders one UnroutedSurfaces label, "tool/kind", and
// reports whether both halves are in the closed vocabulary. A label it
// refuses never crosses the wire.
func UnroutedSurfaceLabel(tool, kind string) (string, bool) {
	label := tool + "/" + kind
	return label, validUnroutedSurfaceLabel(label)
}

// validUnroutedSurfaceLabel reports whether label is a closed
// "tool/surface_kind" pair.
func validUnroutedSurfaceLabel(label string) bool {
	tool, kind, ok := strings.Cut(label, "/")
	return ok && unroutedSurfaceTools[tool] && unroutedSurfaceKinds[kind]
}

// UnroutedSurfaceTools returns the closed tool half of the UnroutedSurfaces
// vocabulary, sorted, for the registry pin test.
func UnroutedSurfaceTools() []string { return sortedSet(unroutedSurfaceTools) }

// UnroutedSurfaceKinds returns the closed surface-kind half, sorted.
func UnroutedSurfaceKinds() []string { return sortedSet(unroutedSurfaceKinds) }

func sortedSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// normalizeRouteObservation reduces the route observation to the wire
// vocabulary: an unsupported version (an older node's absent key, or a
// future one this binary cannot read) is not reported and carries no
// surfaces; a supported one keeps only closed labels.
func (r ManagedIntegrityReport) normalizeRouteObservation() ManagedIntegrityReport {
	if r.RouteObservationVersion != ManagedRouteObservationVersion {
		r.RouteObservationVersion = 0
		r.UnroutedSurfaces = nil
		return r
	}
	r.UnroutedSurfaces = normalizeManagedLabels(r.UnroutedSurfaces, validUnroutedSurfaceLabel)
	if len(r.UnroutedSurfaces) == 0 {
		r.UnroutedSurfaces = nil
	}
	return r
}

// derivedCaptureRisk is one capture-risk label NormalizeLabels derives from
// a normalized list of the report rather than taking it from the node.
type derivedCaptureRisk struct {
	label   string
	present func(r ManagedIntegrityReport) bool
}

// derivedCaptureRisks is the table of derived labels (CLAUDE.md #5, one test
// row each in TestDerivedCaptureRisks). Each label is present exactly when
// its list is, so the label and the list never disagree whichever side built
// the report, and a custom client cannot send one without the other.
var derivedCaptureRisks = []derivedCaptureRisk{
	{CaptureRiskRouteBypassObserved, func(r ManagedIntegrityReport) bool { return len(r.UnroutedSurfaces) > 0 }},
	{CaptureRiskRouteInactiveProvider, func(r ManagedIntegrityReport) bool { return len(r.InactiveProviderTools) > 0 }},
	{CaptureRiskHookSwitchedOff, func(r ManagedIntegrityReport) bool { return len(r.HookDisabledTools) > 0 }},
	{CaptureRiskConfigLayerOverride, func(r ManagedIntegrityReport) bool { return len(r.ConfigLayerRisks) > 0 }},
}

// syncDerivedRisks returns labels with every derivedCaptureRisks label made
// present exactly when its list holds on r. r's lists must already be
// normalized. The result stays sorted; nil when empty.
func (r ManagedIntegrityReport) syncDerivedRisks(labels []string) []string {
	derived := make(map[string]bool, len(derivedCaptureRisks))
	for _, d := range derivedCaptureRisks {
		derived[d.label] = true
	}
	out := make([]string, 0, len(labels)+len(derivedCaptureRisks))
	for _, l := range labels {
		if !derived[l] {
			out = append(out, l)
		}
	}
	for _, d := range derivedCaptureRisks {
		if d.present(r) {
			out = append(out, d.label)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// The closed overall-health vocabulary (ManagedIntegrityHealthVerdict.Health).
// The Control Center shows ok only when every check family reported and
// none found a risk; a family that did not report is not clean.
const (
	ManagedHealthOK          = "ok"
	ManagedHealthAtRisk      = "at_risk"
	ManagedHealthIncomplete  = "incomplete"
	ManagedHealthNotReported = "not_reported"
)

// The closed overall-health reasons, one per rule of managedHealthRules.
// The legacy-state rule reports State() itself ("sibling_observer",
// "route_drift" or "both") as its reason.
const (
	ManagedHealthReasonNoReport            = "no_report"
	ManagedHealthReasonRouteBypass         = "route_bypass_observed" //nolint:gosec // G101: an enum value, not a credential
	ManagedHealthReasonCaptureRisk         = "capture_risk"
	ManagedHealthReasonCaptureNotReported  = "capture_check_not_reported"
	ManagedHealthReasonRouteNotReported    = "route_observation_not_reported"
	ManagedHealthReasonConfigNotReported   = "config_layer_not_reported"
	ManagedHealthReasonCaptureCheckUnknown = "capture_check_unknown"
	ManagedHealthReasonClear               = "clear"
)

// ManagedIntegrityHealthFacts is what the overall-health rule reads: the
// legacy sibling / route-drift State() ("" when no report exists), and per
// check family whether it reported and what it found. A caller folding
// several machines sets a Reported flag only when every machine reported.
type ManagedIntegrityHealthFacts struct {
	State                    string
	CaptureChecksReported    bool
	CaptureRisks             int
	UnknownChecks            int
	RouteObservationReported bool
	UnroutedSurfaces         int
	// ConfigLayerReported: the settings-layer reading (DEC-7) was reported.
	// Its risks reach the rules as derived capture-risk labels.
	ConfigLayerReported bool
}

// ManagedIntegrityHealthVerdict is the overall health and the rule that
// decided it.
type ManagedIntegrityHealthVerdict struct {
	Health string `json:"health"`
	Reason string `json:"reason"`
}

// managedHealthRule is one row of managedHealthRules: the first row whose
// when holds decides the verdict.
type managedHealthRule struct {
	health string
	when   func(f ManagedIntegrityHealthFacts) bool
	reason func(f ManagedIntegrityHealthFacts) string
}

func fixedReason(r string) func(ManagedIntegrityHealthFacts) string {
	return func(ManagedIntegrityHealthFacts) string { return r }
}

// managedHealthRules is the ordered overall-health table (CLAUDE.md #5, one
// test row per rule). Positive evidence outranks a missing report, so a
// machine that reported a bypass is at risk even if its capture checks are
// old; a missing report outranks an inconclusive check.
var managedHealthRules = []managedHealthRule{
	{ManagedHealthNotReported, func(f ManagedIntegrityHealthFacts) bool { return f.State == "" }, fixedReason(ManagedHealthReasonNoReport)},
	{ManagedHealthAtRisk, func(f ManagedIntegrityHealthFacts) bool { return f.State != ManagedIntegrityOK }, func(f ManagedIntegrityHealthFacts) string { return f.State }},
	{ManagedHealthAtRisk, func(f ManagedIntegrityHealthFacts) bool { return f.UnroutedSurfaces > 0 }, fixedReason(ManagedHealthReasonRouteBypass)},
	{ManagedHealthAtRisk, func(f ManagedIntegrityHealthFacts) bool { return f.CaptureRisks > 0 }, fixedReason(ManagedHealthReasonCaptureRisk)},
	{ManagedHealthNotReported, func(f ManagedIntegrityHealthFacts) bool { return !f.CaptureChecksReported }, fixedReason(ManagedHealthReasonCaptureNotReported)},
	{ManagedHealthNotReported, func(f ManagedIntegrityHealthFacts) bool { return !f.RouteObservationReported }, fixedReason(ManagedHealthReasonRouteNotReported)},
	{ManagedHealthNotReported, func(f ManagedIntegrityHealthFacts) bool { return !f.ConfigLayerReported }, fixedReason(ManagedHealthReasonConfigNotReported)},
	{ManagedHealthIncomplete, func(f ManagedIntegrityHealthFacts) bool { return f.UnknownChecks > 0 }, fixedReason(ManagedHealthReasonCaptureCheckUnknown)},
	{ManagedHealthOK, func(ManagedIntegrityHealthFacts) bool { return true }, fixedReason(ManagedHealthReasonClear)},
}

// DeriveManagedIntegrityHealth walks managedHealthRules top-down.
func DeriveManagedIntegrityHealth(f ManagedIntegrityHealthFacts) ManagedIntegrityHealthVerdict {
	for _, rule := range managedHealthRules {
		if rule.when(f) {
			return ManagedIntegrityHealthVerdict{Health: rule.health, Reason: rule.reason(f)}
		}
	}
	return ManagedIntegrityHealthVerdict{Health: ManagedHealthNotReported, Reason: ManagedHealthReasonNoReport}
}

// HealthFacts reads one normalized report (or stored detail fields) as
// overall-health facts.
func (r ManagedIntegrityReport) HealthFacts() ManagedIntegrityHealthFacts {
	return ManagedIntegrityHealthFacts{
		State:                    r.State(),
		CaptureChecksReported:    r.CaptureCheckVersion == ManagedCaptureCheckVersion,
		CaptureRisks:             len(r.CaptureRisks),
		UnknownChecks:            len(r.UnknownChecks),
		RouteObservationReported: r.RouteObservationVersion == ManagedRouteObservationVersion,
		UnroutedSurfaces:         len(r.UnroutedSurfaces),
		ConfigLayerReported:      r.ConfigLayerVersion == ManagedConfigLayerVersion,
	}
}

// OverallHealth is the report's overall health: ok only when State() is ok
// and every check family reported without a risk.
func (r ManagedIntegrityReport) OverallHealth() ManagedIntegrityHealthVerdict {
	return DeriveManagedIntegrityHealth(r.HealthFacts())
}
