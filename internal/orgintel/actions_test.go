package orgintel

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dataauthority"
	"github.com/marmutapp/superbased-observer/internal/settingslink"
)

// TestPlanSessionAction pins the per-session action table: one case per row in
// table order (the managed and individual rows are the two "open" rows), plus
// the refusal sentence every reason renders as.
func TestPlanSessionAction(t *testing.T) {
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	terms := func(devActions bool) Inputs {
		b := req(false, 1)
		b.DeveloperActions = devActions
		return Inputs{
			Enrolled: true, Requirement: b, ConfigOptIn: true,
			Active: &Consent{RequirementVersion: 1, EvidenceLevel: "titles", Purposes: b.Purposes}, Now: now,
		}
	}
	managed := terms(true)
	managed.Managed, managed.ConfigOptIn, managed.Active = true, false, nil
	cases := []struct {
		name   string
		in     Inputs
		railOn bool
		auth   dataauthority.Authority
		want   SessionActionPlan
	}{
		{"not_org_session", terms(true), true, dataauthority.AuthorityPersonal, SessionActionPlan{Reason: "not_org_session"}},
		{"not_available", Inputs{Enrolled: true, Now: now}, true, dataauthority.AuthorityOrg, SessionActionPlan{Reason: "no_terms"}},
		{"developer_actions_off", terms(false), true, dataauthority.AuthorityOrg, SessionActionPlan{Preview: true, Reason: "developer_actions_off"}},
		{"managed", managed, true, dataauthority.AuthorityOrg, SessionActionPlan{Preview: true, Enrich: true}},
		{"individual", terms(true), true, dataauthority.AuthorityOrg, SessionActionPlan{Preview: true, Enrich: true, NeedsPreview: true}},
	}
	if len(cases) != len(SessionActionRuleNames()) {
		t.Fatalf("rows %v, cases %d", SessionActionRuleNames(), len(cases))
	}
	for i, c := range cases {
		if c.name != SessionActionRuleNames()[i] {
			t.Fatalf("case %d is %q, table row is %q", i, c.name, SessionActionRuleNames()[i])
		}
		got := PlanSessionAction(c.in, c.railOn, c.auth)
		got.Submit = SubmitPlan{}
		if got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
	// A managed machine whose rail is not raised has nothing to preview.
	if p := PlanSessionAction(managed, false, dataauthority.AuthorityOrg); p.Preview || p.Reason != "managed_rail_off" {
		t.Errorf("managed rail off: %+v", p)
	}
	for _, r := range append(SubmitRuleNames(), "not_org_session", "developer_actions_off", "purpose_not_allowed") {
		if ActionReasonText(r) == "" {
			t.Errorf("no sentence for %q", r)
		}
	}
	if ActionReasonText("") != "" {
		t.Error("an empty reason renders a sentence")
	}
}

// TestActionReasonFix is one row per refusal reason: who can lift it and
// where. Every reason the tables can produce has a row (a missing one would
// leave the dashboard with a sentence and no way forward).
func TestActionReasonFix(t *testing.T) {
	cases := []struct {
		reason string
		want   ActionFix
	}{
		{"not_enrolled", ActionFix{Place: settingslink.Account}},
		{"no_terms", ActionFix{OrgPlace: settingslink.OrgSessionEnrichment}},
		{"org_off", ActionFix{OrgPlace: settingslink.OrgSessionEnrichment}},
		{"managed_rail_off", ActionFix{OrgPlace: settingslink.OrgSessionEnrichment}},
		{"individual_not_opted_in", ActionFix{Place: settingslink.TeamSummaries}},
		{"purpose_not_allowed", ActionFix{Place: settingslink.TeamSummaries, OrgPlace: settingslink.OrgSessionEnrichment}},
		{"developer_actions_off", ActionFix{OrgPlace: settingslink.OrgSessionEnrichment}},
		{"not_org_session", ActionFix{}},
		{"unknown_reason", ActionFix{}},
	}
	for _, c := range cases {
		if got := ActionReasonFix(c.reason); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.reason, got, c.want)
		}
	}
	for _, r := range append(SubmitRuleNames(), "not_org_session", "developer_actions_off", "purpose_not_allowed") {
		if _, ok := actionReasonFix[r]; !ok {
			t.Errorf("no fix row for %q", r)
		}
		f := actionReasonFix[r]
		if f.Place != "" {
			if _, ok := settingslink.For(f.Place); !ok {
				t.Errorf("%s: unknown place %q", r, f.Place)
			}
		}
		if f.OrgPlace != "" {
			if _, ok := settingslink.OrgFor("", f.OrgPlace); !ok {
				t.Errorf("%s: unknown org place %q", r, f.OrgPlace)
			}
		}
	}
}

// TestActionReasonTextFor: a personal dashboard's org-level refusals speak
// to its only admin (no "your organization"); other reasons read the same.
func TestActionReasonTextFor(t *testing.T) {
	for r := range actionReasonTextPersonal {
		got := ActionReasonTextFor(r, true)
		if got == ActionReasonText(r) || !strings.HasPrefix(got, "Your personal dashboard") {
			t.Errorf("%s: %q", r, got)
		}
		if ActionReasonTextFor(r, false) != ActionReasonText(r) {
			t.Errorf("%s: team wording changed", r)
		}
	}
	if ActionReasonTextFor("individual_not_opted_in", true) != ActionReasonText("individual_not_opted_in") {
		t.Error("a reason with no personal row changed")
	}
}
