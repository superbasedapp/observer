package orgintel

import (
	"github.com/marmutapp/superbased-observer/internal/dataauthority"
	"github.com/marmutapp/superbased-observer/internal/settingslink"
)

// actions.go decides what a developer may do with ONE session on the org plane
// (Cloud Intelligence parity phase 3, design section 3.2): preview the exact
// evidence, and start an enrichment. Pure, table-driven (CLAUDE.md #5); the
// dashboard routes and `observer intel preview|enrich` both read it, so the
// two surfaces can never offer different actions.

// SessionActionPlan is the table's answer for one session.
type SessionActionPlan struct {
	// Preview reports the developer may build and view the org-plane evidence
	// for this session (nothing leaves the machine).
	Preview bool `json:"preview"`
	// Enrich reports the developer may start an enrichment of this session.
	Enrich bool `json:"enrich"`
	// NeedsPreview reports an Enrich must name the upload digest of a preview
	// of the current bytes (individual tenancy: the developer confirms what
	// they saw). A managed developer submits directly (a notice, no veto).
	NeedsPreview bool `json:"needs_preview"`
	// Reason names the first refusal row (empty when both actions are open).
	Reason string `json:"reason,omitempty"`
	// Submit is the level and purpose a submission is built at.
	Submit SubmitPlan `json:"-"`
}

type actionInputs struct {
	plan      SubmitPlan
	authority dataauthority.Authority
	managed   bool
	devAction bool
}

// sessionActionRules is the ordered table: the first matching row decides.
var sessionActionRules = []struct {
	name   string
	match  func(actionInputs) bool
	decide func(actionInputs) SessionActionPlan
}{
	{"not_org_session", func(a actionInputs) bool { return a.authority != dataauthority.AuthorityOrg }, func(actionInputs) SessionActionPlan {
		return SessionActionPlan{}
	}},
	{"not_available", func(a actionInputs) bool { return !a.plan.OK }, func(actionInputs) SessionActionPlan {
		return SessionActionPlan{}
	}},
	{"developer_actions_off", func(a actionInputs) bool { return !a.devAction }, func(actionInputs) SessionActionPlan {
		return SessionActionPlan{Preview: true}
	}},
	{"managed", func(a actionInputs) bool { return a.managed }, func(actionInputs) SessionActionPlan {
		return SessionActionPlan{Preview: true, Enrich: true}
	}},
	{"individual", func(actionInputs) bool { return true }, func(actionInputs) SessionActionPlan {
		return SessionActionPlan{Preview: true, Enrich: true, NeedsPreview: true}
	}},
}

// PlanSessionAction resolves the developer's actions for one session from the
// node's inputs, the rail gate and the session's data-authority stamp.
func PlanSessionAction(in Inputs, railOn bool, authority dataauthority.Authority) SessionActionPlan {
	plan := PlanSubmit(in, railOn)
	a := actionInputs{
		plan: plan, authority: authority, managed: in.Managed,
		devAction: in.Requirement != nil && in.Requirement.DeveloperActions,
	}
	for _, r := range sessionActionRules {
		if r.match(a) {
			out := r.decide(a)
			out.Submit = plan
			switch r.name {
			case "not_available":
				out.Reason = plan.Reason
			case "managed", "individual":
			default:
				out.Reason = r.name
			}
			return out
		}
	}
	return SessionActionPlan{Submit: plan, Reason: "unreachable"}
}

// SessionActionRuleNames lists the table's rows in order.
func SessionActionRuleNames() []string {
	out := make([]string, 0, len(sessionActionRules))
	for _, r := range sessionActionRules {
		out = append(out, r.name)
	}
	return out
}

// actionReasonText is the one sentence each refusal reads as, shared by the
// CLI and the dashboard.
var actionReasonText = map[string]string{
	"not_org_session":         "This session was not captured for your organization, so it is not part of org session enrichment.",
	"not_enrolled":            "This machine is not enrolled with an organization.",
	"no_terms":                "Your organization's server has not sent its session enrichment terms yet.",
	"org_off":                 "Your organization has not turned on session enrichment.",
	"managed_rail_off":        "Your organization has not turned on session enrichment for this machine.",
	"individual_not_opted_in": "You have not accepted your organization's session enrichment terms.",
	"purpose_not_allowed":     "Your organization does not allow a purpose your consent covers.",
	"developer_actions_off":   "Your organization runs session enrichment in the background only.",
}

// actionReasonTextPersonal words the org-level refusals for a personal
// dashboard, where the person is the only admin: no "your organization".
// A reason with no row here reads the same on both.
var actionReasonTextPersonal = map[string]string{
	"no_terms":              "Your personal dashboard has not sent its session enrichment terms yet.",
	"org_off":               "Your personal dashboard has session enrichment off.",
	"managed_rail_off":      "Your personal dashboard has session enrichment off for this machine.",
	"purpose_not_allowed":   "Your personal dashboard does not allow a purpose your consent covers.",
	"developer_actions_off": "Your personal dashboard runs session enrichment in the background only.",
}

// ActionReasonTextFor is ActionReasonText worded for the dashboard kind:
// personal reads the personal row when there is one.
func ActionReasonTextFor(reason string, personal bool) string {
	if personal {
		if t, ok := actionReasonTextPersonal[reason]; ok {
			return t
		}
	}
	return ActionReasonText(reason)
}

// ActionReasonText returns the sentence for a refusal reason ("" for none).
func ActionReasonText(reason string) string {
	if reason == "" {
		return ""
	}
	if t, ok := actionReasonText[reason]; ok {
		return t
	}
	return "Session enrichment is not available for this session (" + reason + ")."
}

// ActionFix is who can lift a refusal, and where. Place is a place in this
// machine's dashboard (the developer changes it here); OrgPlace is a place
// in the team dashboard (only the organization's admins change it; the node
// never offers a toggle for it). Both empty means no setting lifts it.
type ActionFix struct {
	Place    settingslink.Place
	OrgPlace settingslink.OrgPlace
}

// actionReasonFix is the table beside actionReasonText: one row per refusal
// reason, read by the dashboard to turn the sentence into an instruction
// with a link (internal/settingslink owns the paths).
var actionReasonFix = map[string]ActionFix{
	// The session belongs to the personal plane; nothing to change.
	"not_org_session": {},
	"not_enrolled":    {Place: settingslink.Account},
	// The org publishes its terms; they arrive on the next sync.
	"no_terms":                {OrgPlace: settingslink.OrgSessionEnrichment},
	"org_off":                 {OrgPlace: settingslink.OrgSessionEnrichment},
	"managed_rail_off":        {OrgPlace: settingslink.OrgSessionEnrichment},
	"individual_not_opted_in": {Place: settingslink.TeamSummaries},
	// The developer reviews their consent here; the admins choose the
	// purposes there.
	"purpose_not_allowed":   {Place: settingslink.TeamSummaries, OrgPlace: settingslink.OrgSessionEnrichment},
	"developer_actions_off": {OrgPlace: settingslink.OrgSessionEnrichment},
}

// ActionReasonFix returns who can lift a refusal reason and where (zero for
// none, or an unknown reason).
func ActionReasonFix(reason string) ActionFix {
	return actionReasonFix[reason]
}
