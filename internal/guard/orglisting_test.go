package guard

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestOrgLayerRuleListing pins what the org server's effective preview reads:
// the whole catalog a node can evaluate, with the bundle's own rows marked
// "org" and every other row at its catalog source and decision. One case per
// row of the bundle shapes an admin can publish.
func TestOrgLayerRuleListing(t *testing.T) {
	type want struct {
		source           string
		observe, enforce policy.Decision
		enforced         bool
	}
	catalogIDs := map[string]bool{}
	for _, r := range OrgRuleCatalog() {
		catalogIDs[r.ID] = true
	}
	cases := []struct {
		name   string
		bundle string
		rows   map[string]want
		extra  []string // ids beyond the catalog
	}{
		{
			name:   "no bundle: the catalog at its own decisions",
			bundle: "",
			rows: map[string]want{
				"R-121": {policy.SourceBuiltin, policy.DecisionFlag, policy.DecisionAsk, false},
				"R-110": {policy.SourceBuiltin, policy.DecisionFlag, policy.DecisionDeny, false},
			},
		},
		{
			name:   "an override tightens a built-in and marks it org",
			bundle: "[[override]]\nrule = 'R-121'\ndecision = 'deny'\nenforce = true\n",
			rows: map[string]want{
				"R-121": {policy.SourceOrg, policy.DecisionDeny, policy.DecisionDeny, true},
				"R-122": {policy.SourceBuiltin, policy.DecisionFlag, policy.DecisionAsk, false},
			},
		},
		{
			name:   "an enforce-only override keeps the decisions and marks it org",
			bundle: "[[override]]\nrule = 'R-110'\nenforce = true\n",
			rows: map[string]want{
				"R-110": {policy.SourceOrg, policy.DecisionFlag, policy.DecisionDeny, true},
			},
		},
		{
			name:   "a relaxing override is dropped, as on the node",
			bundle: "[[override]]\nrule = 'R-110'\ndecision = 'flag'\n",
			rows: map[string]want{
				"R-110": {policy.SourceBuiltin, policy.DecisionFlag, policy.DecisionDeny, false},
			},
		},
		{
			name:   "an org custom rule joins the list",
			bundle: "[[rule]]\nid = 'ORG-1'\ncategory = 'boundary'\ndecision = 'deny'\nmatch.command_base = 'terraform'\n",
			rows: map[string]want{
				// A rule's decision is its enforce-mode stance; an observing
				// machine flags it unless the rule sets enforce = true.
				"ORG-1": {policy.SourceOrg, policy.DecisionFlag, policy.DecisionDeny, false},
			},
			extra: []string{"ORG-1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := OrgLayerRuleListing(tc.bundle)
			if err != nil {
				t.Fatalf("OrgLayerRuleListing: %v", err)
			}
			ids := map[string]policy.RuleInfo{}
			for _, r := range got {
				if _, seen := ids[r.ID]; !seen {
					ids[r.ID] = r
				}
			}
			if len(ids) != len(catalogIDs)+len(tc.extra) {
				t.Fatalf("listed %d ids, want %d (catalog) + %d", len(ids), len(catalogIDs), len(tc.extra))
			}
			for id := range catalogIDs {
				if _, ok := ids[id]; !ok {
					t.Errorf("catalog id %s missing from the listing", id)
				}
			}
			for id, w := range tc.rows {
				r, ok := ids[id]
				if !ok {
					t.Fatalf("%s not listed", id)
				}
				if r.Source != w.source || r.Observe != w.observe || r.Enforce != w.enforce || r.Enforced != w.enforced {
					t.Errorf("%s = source %q observe %s enforce %s enforced %v; want %q %s %s %v",
						id, r.Source, r.Observe, r.Enforce, r.Enforced, w.source, w.observe, w.enforce, w.enforced)
				}
			}
		})
	}
}

// TestOrgLayerRuleListingWithProjects (review finding 11, 2026-11-12): a
// project section folds into the org layer escalate-only, as the node folds
// it: a stricter project override wins and reads Source org, a weaker one is
// dropped, and a project rule joins the list.
func TestOrgLayerRuleListingWithProjects(t *testing.T) {
	const org = "[[override]]\nrule = 'R-104'\ndecision = 'deny'\n"
	for _, tc := range []struct {
		name     string
		projects []string
		id       string
		source   string
		enforce  policy.Decision
	}{
		{"no project section", nil, "R-102", policy.SourceBuiltin, policy.DecisionAsk},
		{"a project section raises a rule", []string{"[[override]]\nrule = 'R-102'\ndecision = 'deny'\n"}, "R-102", policy.SourceOrg, policy.DecisionDeny},
		{"a project section cannot lower the org's rule", []string{"[[override]]\nrule = 'R-104'\ndecision = 'flag'\n"}, "R-104", policy.SourceOrg, policy.DecisionDeny},
		{"a project rule joins the list", []string{"[[rule]]\nid = 'PRJ-1'\ncategory = 'boundary'\ndecision = 'deny'\nmatch.command_base = 'terraform'\n"}, "PRJ-1", policy.SourceOrg, policy.DecisionDeny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := OrgLayerRuleListingWithProjects(org, tc.projects)
			if err != nil {
				t.Fatalf("OrgLayerRuleListingWithProjects: %v", err)
			}
			for _, r := range got {
				if r.ID != tc.id {
					continue
				}
				if r.Source != tc.source || r.Enforce != tc.enforce {
					t.Fatalf("%s = source %q enforce %s, want %q %s", tc.id, r.Source, r.Enforce, tc.source, tc.enforce)
				}
				return
			}
			t.Fatalf("%s not listed", tc.id)
		})
	}
	if _, err := OrgLayerRuleListingWithProjects(org, []string{"[[override]\n"}); err == nil {
		t.Fatal("an unparseable project section must be an error")
	}
}

// TestOrgLayerRuleListingRefusesUnparseableBundle: a bundle that does not
// parse is an error, never the bare catalog.
func TestOrgLayerRuleListingRefusesUnparseableBundle(t *testing.T) {
	if _, err := OrgLayerRuleListing("[[override]\nrule = "); err == nil {
		t.Fatal("want an error for an unparseable bundle")
	}
}
