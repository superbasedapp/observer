//go:build !sbo_omit_security

package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdockerfile"
	"github.com/marmutapp/superbased-observer/internal/secquickscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestSecurityContainerFinding (OS-1): a Dockerfile rule hit lands as an
// iac finding of the security.code pack under container.<rule>, at the
// hit's severity (flag only is low), medium confidence, with the rule's
// fixed text and the end-of-life words.
func TestSecurityContainerFinding(t *testing.T) {
	cases := []struct {
		in  secquickscan.ContainerFinding
		sev policy.FindingSeverity
	}{
		{secquickscan.ContainerFinding{Path: "Dockerfile", RuleID: "S-752", Line: 1, Severity: secdockerfile.SeverityHigh, Detail: "debian 10 (buster), end of life since 2024-06-30"}, policy.FindingSeverityHigh},
		{secquickscan.ContainerFinding{Path: "Dockerfile", RuleID: "S-755", Line: 3, Severity: secdockerfile.SeverityMedium}, policy.FindingSeverityMedium},
		{secquickscan.ContainerFinding{Path: "Dockerfile", RuleID: "S-753", Line: 2, Severity: secdockerfile.SeverityLow, FlagOnly: true}, policy.FindingSeverityLow},
	}
	for _, c := range cases {
		f := securityContainerFinding("roothash", "", c.in)
		if f.Rule.ID != "container."+strings.ToLower(c.in.RuleID) || f.Rule.Pack != securityCodePack || f.Category != policy.FindingIaC {
			t.Errorf("%s: rule %+v category %s", c.in.RuleID, f.Rule, f.Category)
		}
		if f.Severity != c.sev || f.Confidence != policy.FindingConfidenceMedium {
			t.Errorf("%s: severity %s confidence %s", c.in.RuleID, f.Severity, f.Confidence)
		}
		r, _ := secdockerfile.RuleByID(c.in.RuleID)
		if !strings.HasPrefix(f.Message, c.in.RuleID+": "+r.Message) || (c.in.Detail != "" && !strings.Contains(f.Message, c.in.Detail)) {
			t.Errorf("%s: message %q", c.in.RuleID, f.Message)
		}
	}
}

// TestDockerfileRescanAndFeedback: an open container.* sighting is
// rechecked as a Dockerfile, the rescan classes ask for it, and the
// feedback table names the rule.
func TestDockerfileRescanAndFeedback(t *testing.T) {
	o := store.SecOpenSighting{RulePack: securityCodePack, RuleID: "container.s-751", Path: "Dockerfile"}
	if rescanKindFor(o) != rescanDockerfile {
		t.Fatalf("kind %v", rescanKindFor(o))
	}
	found := false
	for _, c := range rescanClasses(true) {
		for _, p := range c.RulePrefixes {
			if c.Pack == securityCodePack && p == securityContainerRulePrefix {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("rescan classes do not ask for container.* rows")
	}
	for _, r := range secdockerfile.Rules {
		if !feedbackCodeRule("container." + strings.ToLower(r.ID)) {
			t.Errorf("feedback does not know %s", r.ID)
		}
	}
	if feedbackCodeRule("container.s-999") {
		t.Error("feedback knows an unknown container rule")
	}
}
