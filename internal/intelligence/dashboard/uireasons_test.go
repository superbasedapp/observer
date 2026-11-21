package dashboard

import (
	"strings"
	"testing"
)

// TestDashboardReasonsAreSentencesWithoutCLIDeadEnds pins T-374: reason
// strings the dashboard renders as prose end with a full stop, use no dash
// as a separator (neither an em / en dash nor a spaced hyphen) and point at
// a dashboard control rather than telling the user to run an `observer`
// command.
func TestDashboardReasonsAreSentencesWithoutCLIDeadEnds(t *testing.T) {
	cases := []struct{ name, text string }{
		{"session cost tab: no model", predictReasonNoModel},
		{"session cost tab: unpriced model", predictReasonUnpriced("big-pickle", false)},
		{"session cost tab: unpriced model, org-managed pricing", predictReasonUnpriced("big-pickle", true)},
		{"cloud sync: not signed in", cloudNotSignedInMessage},
		{"enrolment invite: not enrolled", notEnrolledInviteMessage},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.HasSuffix(tc.text, ".") {
				t.Errorf("%q does not end with a full stop", tc.text)
			}
			if strings.ContainsAny(tc.text, "\u2013\u2014") || strings.Contains(tc.text, " - ") {
				t.Errorf("%q uses a dash as a separator", tc.text)
			}
			if strings.Contains(tc.text, "`observer ") || strings.Contains(tc.text, "observer init") {
				t.Errorf("%q points at a CLI command instead of a dashboard control", tc.text)
			}
		})
	}
}

// TestPredictReasonUnpricedNamesWhatIsPossible pins CG-22: the unpriced-model
// reason never promises an action the node cannot take. The Pricing card has
// no free-text model, so an individual node is pointed at the config entry,
// and a node whose organization governs Pricing is pointed at the admin.
func TestPredictReasonUnpricedNamesWhatIsPossible(t *testing.T) {
	cases := []struct {
		name       string
		orgManaged bool
		want       []string
		notWant    []string
	}{
		{"individual node", false, []string{`[intelligence.pricing.models."m-1"]`, "config.toml"}, []string{"Add a price for it in Settings > Pricing", "admin"}},
		{"org-managed pricing", true, []string{"your organization", "admin"}, []string{"Settings > Pricing", "config.toml"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := predictReasonUnpriced("m-1", tc.orgManaged)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("reason %q lacks %q", got, w)
				}
			}
			for _, nw := range tc.notWant {
				if strings.Contains(got, nw) {
					t.Errorf("reason %q still says %q", got, nw)
				}
			}
		})
	}
}
