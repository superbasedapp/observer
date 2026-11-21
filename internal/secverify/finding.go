package secverify

import (
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// The finding vocabularies are the security pillar's closed ones (the
// sec-a type contract: internal/policy owns them, internal/secfinding
// re-exports them for the finding model). Verify only names the values
// its detectors emit.

// Category is a finding's closed category (security plan 4.5).
type Category = secfinding.Category

// The categories verify's detectors emit.
const (
	CategoryAgentConfig   = policy.FindingAgentConfig
	CategoryRepoTrust     = policy.FindingRepoTrust
	CategorySecret        = policy.FindingSecret
	CategoryCIConfig      = policy.FindingCIConfig
	CategoryTestTampering = policy.FindingTestTampering
	CategoryMalicious     = policy.FindingMaliciousPackage
	CategoryIaC           = policy.FindingIaC
)

// Severity is the closed severity scale.
type Severity = secfinding.Severity

// The closed severity scale.
const (
	SeverityInfo     = policy.FindingSeverityInfo
	SeverityLow      = policy.FindingSeverityLow
	SeverityMedium   = policy.FindingSeverityMedium
	SeverityHigh     = policy.FindingSeverityHigh
	SeverityCritical = policy.FindingSeverityCritical
)

// Confidence is the closed confidence scale.
type Confidence = secfinding.Confidence

// The closed confidence scale.
const (
	ConfidenceLow    = policy.FindingConfidenceLow
	ConfidenceMedium = policy.FindingConfidenceMedium
	ConfidenceHigh   = policy.FindingConfidenceHigh
)

// Action is what the policy makes of a finding in CI. There is no ask in
// CI: nobody is there to answer.
type Action string

// The closed action vocabulary.
const (
	ActionDeny Action = "deny"
	ActionFlag Action = "flag"
	ActionOff  Action = "off"
)

// DriverName is the engine name verify's native detectors report in the
// normalized finding model.
const DriverName = "observer-verify"

// Finding is one CI result: the normalized finding's fields verify fills,
// plus the CI-only ones (detector, policy action, fingerprint). Every text
// field is built from templates and closed tables; no field holds
// repository text except Path, which is confined and capped (uri.go), and
// no field ever holds a secret value.
type Finding struct {
	// RuleID is the finding rule id (detector-scoped, never a guard rule
	// id): "secret/aws_access_key", "agent-config/hooks".
	RuleID     string
	Detector   string
	Category   Category
	Severity   Severity
	Confidence Confidence
	// Path is project-relative with forward slashes; Line is 1-based, 0
	// when the finding is about the file as a whole.
	Path string
	Line int
	// Message is rendered from the detector's template.
	Message string
	// Fingerprint is a stable hex id for code scanning's dedupe, built from
	// the rule, the path and the occurrence index, never from a matched
	// value (a hash of a secret would be a test oracle for it).
	Fingerprint string
	// DefaultAction is the detector's own judgement; Action is it after the
	// policy (detector override, fixture paths).
	DefaultAction Action
	Action        Action
	// Lowered names why the policy lowered the action ("fixture_path"),
	// empty otherwise.
	Lowered string
}

// Normalized converts a CI result into the pillar's finding model (scope
// ci, status open). The baseline is new: verify judges only what the
// change adds over its base commit (security plan 4.5.2, a signed CI
// result is a baseline reference). Node-local ids, keys and lineage stay
// empty: CI has no node, session or org dedupe key.
func (f Finding) Normalized(version string) secfinding.Finding {
	return secfinding.Finding{
		Location:   secfinding.Location{RelPath: f.Path, StartLine: f.Line, EndLine: f.Line},
		Rule:       secfinding.Rule{ID: f.RuleID},
		Engine:     secfinding.Engine{Driver: DriverName + "/" + f.Detector, DriverVersion: version},
		Category:   f.Category,
		Severity:   f.Severity,
		Confidence: f.Confidence,
		Scope:      policy.FindingScopeCI,
		Message:    f.Message,
		Baseline:   policy.FindingBaselineNew,
		Status:     policy.FindingStatusOpen,
	}
}
