package orgcontract

// securitypurpose.go is the closed vocabulary of the org's stated purpose for
// its Code security views (security plan 7.12, lane SEC-E3) and of the org's
// visibility switches (operator ruling P-089), shared by the org server's
// settings (internal/orgserver/secorg) and the node's affected-worker notice.

// SecurityNotForEvaluationLine is the optional purpose statement (P-089): an
// org may choose to show it on its security views, its export headers and
// the node's affected-worker notice. It is off by default and never forced.
const SecurityNotForEvaluationLine = "Not for evaluating individual employees' performance"

// SecurityPurposeUnset is the push response's value while the org has not
// chosen a purpose.
const SecurityPurposeUnset = "unset"

// SecurityPurpose is one stated purpose.
type SecurityPurpose struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// SecurityPurposes is the closed vocabulary, in display order.
var SecurityPurposes = []SecurityPurpose{
	{ID: "software_security", Label: "Software security and supply-chain assurance"},
	{ID: "audit_evidence", Label: "Audit evidence"},
}

// SecurityPurposeLabel is the label of id, "" for none or an unknown id.
func SecurityPurposeLabel(id string) string {
	for _, p := range SecurityPurposes {
		if p.ID == id {
			return p.Label
		}
	}
	return ""
}

// The org's visibility switches (operator ruling P-089, 2026-10-23): on an
// org-managed node there is no developer privacy, and the admin decides what
// the Code security views show. Each switch is on by default; an org turns a
// field off by naming it in SecurityVisibility.HiddenFields.
const (
	// SecurityFieldMemberCounts is a finding's member and machine counts.
	SecurityFieldMemberCounts = "member_counts"
	// SecurityFieldAgent is the AI agent a finding was seen with.
	SecurityFieldAgent = "agent"
	// SecurityFieldModel is the model a finding was seen with.
	SecurityFieldModel = "model"
	// SecurityFieldSeen is a finding's first and last sighting.
	SecurityFieldSeen = "seen"
	// SecurityFieldDrillDown is the per-member drill-down.
	SecurityFieldDrillDown = "drill_down"
)

// SecurityVisibilityField is one visibility switch: its id, the admin's
// label and the plain sentence the node's notice uses for it.
type SecurityVisibilityField struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	// Shows completes "Your organization can see ..." on the node's notice.
	Shows string `json:"shows"`
}

// SecurityVisibilityFields is the closed switch vocabulary, in display order.
var SecurityVisibilityFields = []SecurityVisibilityField{
	{ID: SecurityFieldMemberCounts, Label: "Member and machine counts", Shows: "how many members and machines each finding was seen on"},
	{ID: SecurityFieldAgent, Label: "Agent", Shows: "the AI agent each finding is associated with"},
	{ID: SecurityFieldModel, Label: "Model", Shows: "the model each finding is associated with"},
	{ID: SecurityFieldSeen, Label: "First and last seen", Shows: "when each finding was first and last seen"},
	{ID: SecurityFieldDrillDown, Label: "Per-member drill-down", Shows: "which members and sessions each finding was seen in, so a finding can be traced to the person who has it"},
}

// SecurityVisibilityFieldKnown reports whether id is a visibility switch.
func SecurityVisibilityFieldKnown(id string) bool {
	for _, f := range SecurityVisibilityFields {
		if f.ID == id {
			return true
		}
	}
	return false
}

// SecurityVisibility is what the org's Code security views show under the
// org's current settings (P-089). The push response carries it beside the
// stated purpose so the node's affected-worker notice can state it; it is
// information, not a privacy promise, and the org may change it at any time.
type SecurityVisibility struct {
	// MinGroup is the smallest group any grouped view shows; 1 hides nothing.
	MinGroup int `json:"min_group"`
	// HiddenFields are the switches the org turned off (closed ids).
	HiddenFields []string `json:"hidden_fields"`
	// PurposeStatement is true when the org shows
	// SecurityNotForEvaluationLine on its views and exports.
	PurposeStatement bool `json:"purpose_statement"`
}
