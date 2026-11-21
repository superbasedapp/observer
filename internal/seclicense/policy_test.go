package seclicense

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

func TestPolicyActive(t *testing.T) {
	cases := []struct {
		p    Policy
		want bool
	}{
		{Policy{}, false},
		{Policy{Unknown: UnknownIgnore}, false},
		{Policy{Unknown: UnknownFlag}, true},
		{Policy{Deny: []string{"GPL-3.0-only"}}, true},
		{Policy{Allow: []string{"permissive"}}, true},
	}
	for _, c := range cases {
		if got := c.p.Active(); got != c.want {
			t.Errorf("%+v.Active() = %v, want %v", c.p, got, c.want)
		}
	}
}

// TestEvaluatePolicyTable walks the policy table: at least one case per
// row plus the fall-through, with expressions.
func TestEvaluatePolicyTable(t *testing.T) {
	cases := []struct {
		name string
		p    Policy
		lic  string
		want string // rule id, "" for no finding
	}{
		// Row 1: denied.
		{"denied by id", Policy{Deny: []string{"GPL-3.0-only"}}, "GPL-3.0-only", RuleDenied},
		{"denied by deprecated id", Policy{Deny: []string{"GPL-3.0"}}, "GPLv3", RuleDenied},
		{"denied by class", Policy{Deny: []string{"strong_copyleft"}}, "GPL-2.0-or-later", RuleDenied},
		{"denied class case-insensitive", Policy{Deny: []string{"Network_Copyleft"}}, "AGPL-3.0-only", RuleDenied},
		{"OR alternative avoids deny", Policy{Deny: []string{"strong_copyleft"}}, "MIT OR GPL-3.0-only", ""},
		{"AND part denied", Policy{Deny: []string{"strong_copyleft"}}, "MIT AND GPL-3.0-only", RuleDenied},
		{"WITH keeps base class for deny", Policy{Deny: []string{"strong_copyleft"}}, "GPL-2.0-only WITH Classpath-exception-2.0", RuleDenied},
		{"deny unknown class covers empty", Policy{Deny: []string{"unknown"}}, "", RuleDenied},
		{"deny before not allowed", Policy{Deny: []string{"MIT"}, Allow: []string{"ISC"}}, "MIT", RuleDenied},
		// Row 2: not allowed.
		{"allowed by class", Policy{Allow: []string{"permissive"}}, "Apache-2.0", ""},
		{"allowed by id", Policy{Allow: []string{"MPL-2.0"}}, "MPL 2.0", ""},
		{"not allowed", Policy{Allow: []string{"permissive"}}, "MPL-2.0", RuleNotAllowed},
		{"OR any alternative allowed", Policy{Allow: []string{"GPL-3.0-only"}}, "MIT OR GPL-3.0-only", ""},
		{"AND every part must be allowed", Policy{Allow: []string{"MIT"}}, "MIT AND BSD-3-Clause", RuleNotAllowed},
		{"empty licence not allowed", Policy{Allow: []string{"permissive"}}, "", RuleNotAllowed},
		{"allowed alternative that is denied is not a way out", Policy{Deny: []string{"MIT"}, Allow: []string{"MIT", "ISC"}}, "MIT OR MPL-2.0", RuleNotAllowed},
		// Row 3: unknown.
		{"unknown flagged", Policy{Unknown: UnknownFlag}, "Some Custom Licence", RuleUnknown},
		{"unknown empty flagged", Policy{Unknown: UnknownFlag}, "", RuleUnknown},
		{"unknown malformed flagged", Policy{Unknown: UnknownFlag}, "MIT OR", RuleUnknown},
		{"unknown ignored", Policy{Unknown: UnknownIgnore}, "Some Custom Licence", ""},
		{"known not flagged", Policy{Unknown: UnknownFlag}, "MIT", ""},
		{"OR with a known alternative not unknown", Policy{Unknown: UnknownFlag}, "MIT OR Custom", ""},
		// Fall-through.
		{"default policy", Policy{}, "GPL-3.0-only", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, ok := Evaluate(c.p, Entry{License: c.lic})
			got := ""
			if ok {
				got = v.RuleID
			}
			if got != c.want {
				t.Fatalf("Evaluate(%+v, %q) = %q, want %q", c.p, c.lic, got, c.want)
			}
		})
	}
}

// TestPolicyTableSeverityCapped pins every row at medium or below (plan
// section 12, finding 5).
func TestPolicyTableSeverityCapped(t *testing.T) {
	for _, r := range policyTable {
		if r.Verdict.Severity == policy.FindingSeverityHigh || r.Verdict.Severity == policy.FindingSeverityCritical {
			t.Errorf("%s: severity %q above medium", r.Verdict.RuleID, r.Verdict.Severity)
		}
		if r.Verdict.Message == "" || r.Verdict.FixHint == "" {
			t.Errorf("%s: missing message or fix hint", r.Verdict.RuleID)
		}
	}
}

func TestFindingsShape(t *testing.T) {
	now := time.Date(2026, 11, 13, 10, 0, 0, 0, time.FixedZone("x", 3600))
	p := Policy{Deny: []string{"network_copyleft", "strong_copyleft"}, Unknown: UnknownFlag}
	entries := []Entry{
		{Ecosystem: "npm", Name: "agpl-thing", Version: "1.0.0", License: "AGPL-3.0-only", Confidence: policy.FindingConfidenceHigh, Path: "package-lock.json"},
		{Ecosystem: "PyPI", Name: "mystery", Version: "0.1", License: "", Raw: "Copyright Secret Corp all rights", Confidence: policy.FindingConfidenceMedium, Path: "venv/m.dist-info/METADATA"},
		{Ecosystem: "npm", Name: "fine", Version: "1.0.0", License: "MIT", Confidence: policy.FindingConfidenceHigh, Path: "package-lock.json"},
	}
	got := Findings(p, entries, now)
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(got), got)
	}
	for _, f := range got {
		if f.Category != policy.FindingLicense {
			t.Errorf("category %q", f.Category)
		}
		if f.Baseline != policy.FindingBaselineUnknown {
			t.Errorf("baseline %q, want unknown (never new)", f.Baseline)
		}
		if f.Severity == policy.FindingSeverityHigh || f.Severity == policy.FindingSeverityCritical {
			t.Errorf("severity %q above medium", f.Severity)
		}
		if f.Status != policy.FindingStatusOpen || f.Scope != policy.FindingScopeManual {
			t.Errorf("status %q scope %q", f.Status, f.Scope)
		}
		if f.Engine.Driver != Driver || f.Rule.Pack != Driver || f.Rule.Version != Version {
			t.Errorf("engine %+v rule %+v", f.Engine, f.Rule)
		}
		if f.LocalKey == "" || f.EvidenceHash != secfinding.EvidenceHash(f.EvidenceRedacted) {
			t.Errorf("key %q evidence hash mismatch", f.LocalKey)
		}
		if !f.FirstSeen.Equal(now) || f.FirstSeen.Location() != time.UTC {
			t.Errorf("first seen %v", f.FirstSeen)
		}
	}
	if got[0].Rule.ID != RuleDenied || got[0].Severity != policy.FindingSeverityMedium || got[0].Confidence != policy.FindingConfidenceHigh {
		t.Errorf("denied finding %+v", got[0])
	}
	if got[0].EvidenceRedacted != "npm agpl-thing@1.0.0: AGPL-3.0-only" || got[0].Location.RelPath != "package-lock.json" {
		t.Errorf("evidence %q path %q", got[0].EvidenceRedacted, got[0].Location.RelPath)
	}
	if got[1].Rule.ID != RuleUnknown || got[1].Severity != policy.FindingSeverityLow || got[1].Confidence != policy.FindingConfidenceMedium {
		t.Errorf("unknown finding %+v", got[1])
	}
	if got[1].EvidenceRedacted != "PyPI mystery@0.1: (none declared)" {
		t.Errorf("raw licence text leaked into evidence: %q", got[1].EvidenceRedacted)
	}
}

func TestFindingsInactivePolicyRecordsNothing(t *testing.T) {
	got := Findings(Policy{Unknown: UnknownIgnore}, []Entry{{License: "GPL-3.0-only"}, {License: ""}}, time.Now())
	if got != nil {
		t.Fatalf("got %+v", got)
	}
}

// TestFindingsKeyStable pins the local key to ecosystem, name, version,
// path and project: the same dependency keys the same way across runs,
// and differs across projects and paths.
func TestFindingsKeyStable(t *testing.T) {
	p := Policy{Deny: []string{"MIT"}}
	e := Entry{Ecosystem: "npm", Name: "a", Version: "1", License: "MIT", Path: "package-lock.json"}
	k1 := ProjectFindings("root1", p, []Entry{e}, time.Now())[0].LocalKey
	k2 := ProjectFindings("root1", p, []Entry{e}, time.Now().Add(time.Hour))[0].LocalKey
	k3 := ProjectFindings("root2", p, []Entry{e}, time.Now())[0].LocalKey
	e.Path = "web/package-lock.json"
	k4 := ProjectFindings("root1", p, []Entry{e}, time.Now())[0].LocalKey
	if k1 != k2 || k1 == k3 || k1 == k4 {
		t.Fatalf("keys %s %s %s %s", k1, k2, k3, k4)
	}
}
