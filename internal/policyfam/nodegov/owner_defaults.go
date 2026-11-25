package nodegov

import "slices"

// Stating the owner audience's defaults in a served body (operator ruling 3,
// 2026-11-24: "nodes older than v1.43.0 should still follow the online
// setting").
//
// The owner audience (ManagedAudienceOwner) is resolved ON THE NODE from the
// owner-managed capability its enrolment and push responses carry. A build
// older than v1.43.0 never learns that capability and applies the team
// column; v1.43.0 and v1.43.1 learn it but compiled the narrower F12 owner
// column (only the AI Apps pages, Egress, Routing and Policies visible). The
// org server knows the organization's kind, so for a managed machine of a
// personal organization it states the owner audience's levels in the
// node.governance body it serves (internal/orgserver/api
// ComposeNodeGovernance), as the ordinary explicit directives every managed
// build since v1.36.0 applies: an explicit org expose beats the managed
// default. It does so for every build, not only older ones: the served body
// then does not change when the machine upgrades (a node refuses the same
// version with different bytes) and two machines of one owner on different
// builds share one served-version row without bumping it past each other. On
// a build that resolves the owner column itself the stated levels equal its
// own defaults, so nothing it shows changes.
//
// Every team restriction any released build applies is in today's team
// column (the column only ever grew), so stating every id whose owner level
// differs from today's team level covers every older build; an id an older
// build does not know is removed by the vocabulary projection
// (ProjectServedBody) like any other.

// audienceList is one row of the statement table: which default table, which
// level, and the body list that states that level for it. Walked top-down by
// StateAudienceDefaults (CLAUDE.md #5).
type audienceList struct {
	settings bool
	level    Visibility
	list     func(s *SectionsV1) *[]string
}

func (l audienceList) rows() []ManagedDefault {
	if l.settings {
		return ManagedSettingsDefaults
	}
	return ManagedNavDefaults
}

// key is how StateAudienceDefaults names an id across both vocabularies
// (a page and a Settings section may share an id, e.g. "routing").
func (l audienceList) key(id string) string {
	if l.settings {
		return "settings:" + id
	}
	return id
}

func audienceLists() []audienceList {
	return []audienceList{
		{false, VisibilityVisible, func(s *SectionsV1) *[]string { return &s.Visible }},
		{false, VisibilityReadOnly, func(s *SectionsV1) *[]string { return &s.ReadOnly }},
		{false, VisibilityHidden, func(s *SectionsV1) *[]string { return &s.Hidden }},
		{true, VisibilityVisible, func(s *SectionsV1) *[]string { return &s.SettingsVisible }},
		{true, VisibilityReadOnly, func(s *SectionsV1) *[]string { return &s.SettingsReadOnly }},
		{true, VisibilityHidden, func(s *SectionsV1) *[]string { return &s.SettingsHidden }},
	}
}

// StateAudienceDefaults returns b with audience a's managed defaults stated as
// explicit directives wherever they differ from the team audience's, and the
// ids it added ("<id>" for a page, "settings:<id>" for a Settings section).
// An id the body already names in any of its lists keeps the body's level:
// a directive the organization published always wins, exactly as it does on
// the node. The team audience (and an audience this build does not know)
// states nothing. The lists come back sorted and the schema restamped to the
// lowest one the result needs (SchemaFor), the rule every server publisher
// follows; b itself is not modified.
func StateAudienceDefaults(b Body, a ManagedAudience) (Body, []string) {
	if a != ManagedAudienceOwner {
		return b, nil
	}
	out := b
	out.Sections = SectionsV1{
		Hidden:           slices.Clone(b.Sections.Hidden),
		ReadOnly:         slices.Clone(b.Sections.ReadOnly),
		SettingsHidden:   slices.Clone(b.Sections.SettingsHidden),
		SettingsReadOnly: slices.Clone(b.Sections.SettingsReadOnly),
		Visible:          slices.Clone(b.Sections.Visible),
		SettingsVisible:  slices.Clone(b.Sections.SettingsVisible),
	}
	named := map[string]bool{}
	for _, l := range audienceLists() {
		for _, id := range *l.list(&b.Sections) {
			named[l.key(id)] = true
		}
	}
	var added []string
	for _, l := range audienceLists() {
		for _, r := range l.rows() {
			key := l.key(r.ID)
			lvl := r.LevelFor(a)
			if named[key] || lvl != l.level || lvl == r.LevelFor(ManagedAudienceTeam) {
				continue
			}
			list := l.list(&out.Sections)
			*list = append(*list, r.ID)
			named[key] = true
			added = append(added, key)
		}
	}
	if len(added) == 0 {
		return b, nil
	}
	for _, l := range audienceLists() {
		if list := l.list(&out.Sections); len(*list) > 0 {
			slices.Sort(*list)
		}
	}
	if need := SchemaFor(out); out.Schema < need {
		out.Schema = need
	}
	return out, added
}
