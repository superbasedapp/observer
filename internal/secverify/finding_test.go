package secverify

import (
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestVocabulariesAreTheContracts: every category, severity and confidence
// verify emits is a value of the pillar's closed vocabularies.
func TestVocabulariesAreTheContracts(t *testing.T) {
	for _, d := range Detectors() {
		if !slices.Contains(policy.FindingCategories(), d.Category) {
			t.Errorf("detector %s category %q is not in the contract", d.ID, d.Category)
		}
	}
	for name, r := range secretRules {
		if !slices.Contains(policy.FindingSeverities(), r.Severity) || !slices.Contains(policy.FindingConfidences(), r.Confidence) {
			t.Errorf("secret rule %s: %q/%q outside the contract", name, r.Severity, r.Confidence)
		}
	}
	for kind, c := range agentConfigKinds {
		if !slices.Contains(policy.FindingSeverities(), c.Severity) || !slices.Contains(policy.FindingConfidences(), c.Confidence) {
			t.Errorf("agent config kind %s: %q/%q outside the contract", kind, c.Severity, c.Confidence)
		}
	}
}

func TestNormalized(t *testing.T) {
	f := Finding{
		RuleID: "secret/aws_access_key", Detector: "secrets", Category: CategorySecret, Severity: SeverityCritical,
		Confidence: ConfidenceHigh, Path: "a/b.py", Line: 3, Message: "m", Fingerprint: "fp", DefaultAction: ActionDeny, Action: ActionDeny,
	}
	n := f.Normalized("v1.40.0")
	if n.Rule.ID != f.RuleID || n.Location.RelPath != "a/b.py" || n.Location.StartLine != 3 || n.Scope != policy.FindingScopeCI ||
		n.Baseline != policy.FindingBaselineNew || n.Status != policy.FindingStatusOpen || n.Engine.Driver != "observer-verify/secrets" ||
		n.Engine.DriverVersion != "v1.40.0" || n.Category != CategorySecret || n.EvidenceRedacted != "" || n.LocalKey != "" {
		t.Errorf("normalized = %+v", n)
	}
}
