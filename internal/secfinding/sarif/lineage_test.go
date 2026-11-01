package sarif

import (
	"encoding/json"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// lineageFindings are one finding with a line and one file-level finding.
func lineageFindings() []secfinding.Finding {
	return []secfinding.Finding{
		{
			LocalKey: "k1", Rule: secfinding.Rule{ID: "secret.aws_access_key"}, Category: policy.FindingSecret,
			Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh, Baseline: policy.FindingBaselineNew,
			Message: "AWS key", EvidenceHash: "abc123",
			Location: secfinding.Location{RelPath: "cfg.py", StartLine: 12, EndLine: 12},
			Lineage:  secfinding.Lineage{SessionID: "s1", Model: "m1", Tool: "claude-code", PromptActionID: "p9"},
		},
		{
			LocalKey: "k2", Rule: secfinding.Rule{ID: "trust.hooks"}, Category: policy.FindingAgentConfig,
			Severity: policy.FindingSeverityMedium, Confidence: policy.FindingConfidenceMedium, Baseline: policy.FindingBaselineNew,
			Message: "hook", Location: secfinding.Location{RelPath: ".claude/settings.json"},
			Lineage: secfinding.Lineage{SessionID: "s2"},
		},
	}
}

// TestSARIFLineLineage (lane LEFT-SEC milestone 3): a finding with a line
// carries its lineage on its region as well as on the result, a file-level
// finding on the result alone, and each result says which. Rule ids,
// levels and fingerprints are unchanged (golden), and every result keeps a
// physical location the P-115 rule accepts.
func TestSARIFLineLineage(t *testing.T) {
	data, err := Encode(lineageFindings(), ToolInfo{Name: "SuperBased Observer", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if p := LocationProblems(data); len(p) != 0 {
		t.Fatalf("location problems: %v", p)
	}
	var lg outLog
	if err := json.Unmarshal(data, &lg); err != nil {
		t.Fatal(err)
	}
	rs := lg.Runs[0].Results
	if len(rs) != 2 {
		t.Fatalf("%d results", len(rs))
	}
	// Golden: what an export said before line lineage.
	golden := []struct {
		rule, level, fp string
		start, end      int
	}{
		{"secret.aws_access_key", "error", "abc123", 12, 12},
		{"trust.hooks", "warning", "", 1, 0},
	}
	for i, g := range golden {
		r := rs[i]
		if r.RuleID != g.rule || r.Level != g.level || r.PartialFingerprints["superbased/evidence/v1"] != g.fp {
			t.Errorf("result %d: %s %s %v, want %s %s %s", i, r.RuleID, r.Level, r.PartialFingerprints, g.rule, g.level, g.fp)
		}
		reg := r.Locations[0].Physical.Region
		if reg.StartLine != g.start || reg.EndLine != g.end {
			t.Errorf("result %d region %+v", i, reg)
		}
	}
	line := rs[0]
	if line.Properties[PropLineageScope] != LineageRegion || line.Properties[PropSession] != "s1" {
		t.Errorf("line result properties %v", line.Properties)
	}
	rp := line.Locations[0].Physical.Region.Properties
	if rp[PropSession] != "s1" || rp[PropModel] != "m1" || rp[PropTool] != "claude-code" || rp[PropPrompt] != "p9" || rp[PropTaint] != "false" {
		t.Errorf("region lineage %v", rp)
	}
	file := rs[1]
	if file.Properties[PropLineageScope] != LineageResult || file.Locations[0].Physical.Region.Properties != nil || file.Properties[PropSession] != "s2" {
		t.Errorf("file-level result %v region %v", file.Properties, file.Locations[0].Physical.Region.Properties)
	}
}

// TestLocationProblems names a result GitHub would reject.
func TestLocationProblems(t *testing.T) {
	bad := `{"version":"2.1.0","runs":[{"results":[
		{"ruleId":"a","locations":[{"physicalLocation":{"artifactLocation":{"uri":"x"},"region":{"startLine":3}}}]},
		{"ruleId":"b","locations":[{"logicalLocations":[{"fullyQualifiedName":"commit/1"}]}]},
		{"ruleId":"c"},
		{"ruleId":"d","locations":[{"physicalLocation":{"artifactLocation":{"uri":"x"},"region":{"startLine":0}}}]}
	]}]}`
	if p := LocationProblems([]byte(bad)); len(p) != 3 {
		t.Fatalf("problems %v, want b, c and d", p)
	}
	if p := LocationProblems([]byte("{")); len(p) != 1 {
		t.Fatalf("unparsable: %v", p)
	}
}
