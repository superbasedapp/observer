package guard

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestRuleListingIncludesOrgProjectRules (round-3 finding): the rule listing
// every surface reads carries the org's project-scoped rules, each labelled
// with its org project, beside the rules in force everywhere; a project rule
// the org-wide layer already defines is left out, as the project fold drops
// it.
func TestRuleListingIncludesOrgProjectRules(t *testing.T) {
	orgWide := orgFloor + `
[[rule]]
id = "ORG-901"
category = "exfil"
severity = "high"
decision = "deny"
match.command_base = "scp"
`
	projZ := `
[[rule]]
id = "ORG-901"
category = "exfil"
severity = "high"
decision = "ask"
match.command_base = "rsync"
`
	f := newOrgProjectFixture(t, orgWide, map[string]string{"X": projX, "Y": projY, "Z": projZ})
	rows := f.guard(false).RuleListing()

	type key struct{ id, project string }
	got := map[key]policy.RuleInfo{}
	for _, r := range rows {
		got[key{r.ID, r.Project}] = r
	}
	cases := []struct {
		name    string
		id      string
		project string
		present bool
	}{
		{"an org-wide custom rule, scope all", "ORG-901", "", true},
		{"a built-in", "R-110", "", true},
		{"project X's rule, scoped to X", "PRJ-X1", "X", true},
		{"project Y's rule, scoped to Y", "PRJ-Y1", "Y", true},
		{"project X's rule is not listed org-wide", "PRJ-X1", "", false},
		{"a project redefinition of an org-wide id is left out", "ORG-901", "Z", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, ok := got[key{tc.id, tc.project}]
			if ok != tc.present {
				t.Fatalf("(%s, project %q) listed = %v, want %v; rows %+v", tc.id, tc.project, ok, tc.present, rows)
			}
			if ok && tc.id != "R-110" && r.Source != policy.SourceOrg {
				t.Errorf("(%s, %q) source = %q, want org", tc.id, tc.project, r.Source)
			}
		})
	}
}

// TestRuleListingWithoutProjectAudience: with no project-scoped org bundle the
// listing is exactly the effective rules.
func TestRuleListingWithoutProjectAudience(t *testing.T) {
	g, err := New(Options{Config: guardCfgOrg(), Home: "/home/u", ReadFile: fsMap(map[string]string{})})
	if err != nil {
		t.Fatal(err)
	}
	listing, eff := g.RuleListing(), g.EffectiveRules()
	if len(listing) != len(eff) {
		t.Fatalf("listing has %d rows, effective %d", len(listing), len(eff))
	}
	for _, r := range listing {
		if r.Project != "" {
			t.Errorf("%s scoped to %q with no project audience", r.ID, r.Project)
		}
	}
}
