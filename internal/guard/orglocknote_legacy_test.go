package guard

import (
	"strings"
	"testing"
)

// TestExplainLegacyOrgLockedReason pins the read-time explanation of a
// pre-cause org-lock note (round-3 finding): the cause is rendered only where
// the row's stored source establishes it, the rest of the reason is kept,
// and every other reason is returned unchanged.
func TestExplainLegacyOrgLockedReason(t *testing.T) {
	const doc = "commit or push while the tree is dirty and the quick scan is not clean"
	legacy := func(id string) string { return doc + legacyOrgLockedNote(id) }
	cases := []struct {
		name    string
		reason  string
		rule    string
		source  string
		changed bool
		want    string // substring of the explained reason
		wantNot string
	}{
		{"a pack rule on a managed node", legacy("S-793"), "S-793", "pack:security", true, "the organization's guard bundle does not name S-793", "an org policy locks"},
		{"a built-in rule", legacy("R-101"), "R-101", "builtin", true, "does not name R-101", "an org policy locks"},
		{"an org-sourced rule", legacy("R-110"), "R-110", "org", true, "the organization's policy names R-110", "an org policy locks"},
		{"an org budget rule", legacy("B-621"), "B-621", "org_budget", true, "the organization's policy names B-621", ""},
		{"a user-sourced rule: not established", legacy("R-172"), "R-172", "user", false, "an org policy locks R-172", ""},
		{"no stored source: not established", legacy("R-101"), "R-101", "", false, "an org policy locks R-101", ""},
		{"a new row's cause note stays", doc + orgLockedNote(orgLockManaged, "S-793"), "S-793", "pack:security", false, "this node is managed by its organization", ""},
		{"no note at all", doc, "S-793", "pack:security", false, doc, "[org_locked"},
		{"a note for another rule id", legacy("R-101"), "S-793", "pack:security", false, "an org policy locks R-101", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := ExplainLegacyOrgLockedReason(tc.reason, tc.rule, tc.source)
			if changed != tc.changed {
				t.Fatalf("changed = %v, want %v (%q)", changed, tc.changed, got)
			}
			if !changed && got != tc.reason {
				t.Fatalf("an unchanged reason was altered: %q", got)
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("explained = %q, want it to contain %q", got, tc.want)
			}
			if tc.wantNot != "" && strings.Contains(got, tc.wantNot) {
				t.Errorf("explained = %q, must not contain %q", got, tc.wantNot)
			}
			if changed && (!strings.HasPrefix(got, doc) || !strings.Contains(got, " [org_locked: ")) {
				t.Errorf("explained = %q, want the rule's own text kept and the [org_locked prefix", got)
			}
		})
	}
}
