package seciac

import (
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// SkipNoLocation is the skip reason of a result with no file: an IaC
// finding is always at a file and a line (the P-115 location rule), so a
// result without one is left out and counted.
const SkipNoLocation = "no_location"

// SeverityRow is one row of an engine's severity mapping, as the SARIF it
// writes states it: a rule's numeric security-severity (Trivy writes 9.5
// for CRITICAL, 8.0 for HIGH, 5.5 for MEDIUM, 2.0 for LOW) or a result
// level (KICS writes error for CRITICAL and HIGH, warning for MEDIUM, note
// for LOW and INFO). secscan's adapter rows "trivy" and "kics" apply them;
// one test per row pins each.
type SeverityRow struct {
	Engine           EngineID
	SecuritySeverity string
	Level            string
	Want             secfinding.Severity
}

// SeverityTable is the mapping table.
var SeverityTable = []SeverityRow{
	{Engine: Trivy, SecuritySeverity: "9.5", Level: "error", Want: policy.FindingSeverityCritical},
	{Engine: Trivy, SecuritySeverity: "8.0", Level: "error", Want: policy.FindingSeverityHigh},
	{Engine: Trivy, SecuritySeverity: "5.5", Level: "warning", Want: policy.FindingSeverityMedium},
	{Engine: Trivy, SecuritySeverity: "2.0", Level: "note", Want: policy.FindingSeverityLow},
	{Engine: Trivy, Level: "note", Want: policy.FindingSeverityLow},
	{Engine: KICS, Level: "error", Want: policy.FindingSeverityHigh},
	{Engine: KICS, Level: "warning", Want: policy.FindingSeverityMedium},
	{Engine: KICS, Level: "note", Want: policy.FindingSeverityLow},
	{Engine: KICS, Level: "none", Want: policy.FindingSeverityInfo},
}

// MapFindings applies the IaC rules to adapted findings: category iac,
// confidence never high (flag only: nothing an IaC engine reports changes
// a verdict in this release), and every kept finding at a file and a line
// (a result with no file is dropped and counted; a missing start line is
// line 1). A run left with nothing after a drop is unknown, never clean.
func MapFindings(fs []secfinding.Finding, cov secscan.Coverage) ([]secfinding.Finding, secscan.Coverage) {
	kept := make([]secfinding.Finding, 0, len(fs))
	dropped := 0
	for _, f := range fs {
		if f.Location.RelPath == "" {
			dropped++
			cov.Skipped = append(cov.Skipped, secscan.Skip{Reason: SkipNoLocation})
			continue
		}
		if f.Location.StartLine <= 0 {
			f.Location.StartLine = 1
		}
		if f.Location.EndLine < f.Location.StartLine {
			f.Location.EndLine = f.Location.StartLine
		}
		f.Category = policy.FindingIaC
		if f.Confidence == policy.FindingConfidenceHigh {
			f.Confidence = policy.FindingConfidenceMedium
		}
		kept = append(kept, f)
	}
	if dropped > 0 && len(kept) == 0 && cov.Outcome != secscan.OutcomeFailed && cov.Outcome != secscan.OutcomeNotScanned {
		cov.Outcome, cov.Reason = secscan.OutcomeUnknown, "results_refused"
	}
	return kept, cov
}
