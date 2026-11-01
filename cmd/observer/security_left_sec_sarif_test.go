//go:build !sbo_omit_security

package main

import (
	"bytes"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secchange"
	"github.com/marmutapp/superbased-observer/internal/secfinding/sarif"
	"github.com/marmutapp/superbased-observer/internal/secverify"
)

// TestCISARIFPassesTheLocationRule (lane LEFT-SEC milestone 3, decision log
// P-115): the CI template's SARIF (secverify.WriteSARIF) gives every result
// a physical location with a file and a start line, a file-level finding
// and a provenance result for a commit that changes no file included, so
// GitHub code scanning never drops the whole upload. The CI SARIF carries
// no per-finding lineage (verify reads the diff, not the node's sessions),
// so line lineage is the node export's (internal/secfinding/sarif).
func TestCISARIFPassesTheLocationRule(t *testing.T) {
	rep := secverify.Report{
		Verdict: secverify.Verdict("pass"),
		Findings: []secverify.Finding{
			{RuleID: "secret/aws_access_key", Category: secverify.CategorySecret, Severity: secverify.SeverityHigh, Path: "cfg.py", Line: 4, Fingerprint: "f1", Message: "m", Action: secverify.Action("deny")},
			{RuleID: "agent-config/hooks", Category: secverify.CategoryAgentConfig, Severity: secverify.SeverityMedium, Path: ".claude/settings.json", Line: 0, Fingerprint: "f2", Message: "m", Action: secverify.Action("flag")},
		},
		Provenance: secverify.ProvenanceReport{Checked: true, Commits: []secverify.ProvenanceCommitReport{
			{CommitOutcome: secchange.CommitOutcome{SHA: "0123456789abcdef0123456789abcdef01234567", Provenance: secchange.ProvenanceUnknown, Reason: "no_record"}},
		}},
	}
	var b bytes.Buffer
	if err := secverify.WriteSARIF(&b, rep, "/repo", "test"); err != nil {
		t.Fatal(err)
	}
	if p := sarif.LocationProblems(b.Bytes()); len(p) != 0 {
		t.Fatalf("the CI SARIF fails the location rule: %v", p)
	}
}
