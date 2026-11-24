package govern

import "github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"

// Dashboard visibility resolution (backlog item 4, managed-node visibility;
// classification of record docs/audits/managed-node-visibility-2026-10-03.md).
//
// The node dashboard asks ONE question per page and per Settings section: on
// THIS machine, is it hidden, read-only or visible? Every enforcement point
// (the dashboard API guard, GET /api/governance's visibility block and through
// it the SPA's nav, route guard, palette, tour, help and Settings rail) reads
// the answer from here, so the surfaces can never disagree with the API.
//
// The answer composes two inputs:
//
//   - the org's APPLIED node.governance directive lists (hidden / read_only /
//     visible, already intersected with the grant by Resolve), and
//   - on a MANAGED machine whose grant is live, the compiled-in default table
//     (nodegov.ManagedNavDefaults / ManagedSettingsDefaults), at the level of
//     the machine's audience (ManagedAudience: a team member's machine, or
//     one its owner manages from a personal organization of one).
//
// An individual / BYO node has no defaults: it resolves exactly as before this
// arc (visible unless its own consented body hid or locked it).

// VisibilitySource says what decided a level.
type VisibilitySource string

const (
	// VisibilitySourceFloor is the T8 floor: always visible, nothing can
	// change it.
	VisibilitySourceFloor VisibilitySource = "floor"
	// VisibilitySourceOrg is an explicit directive in the org's applied body.
	VisibilitySourceOrg VisibilitySource = "org"
	// VisibilitySourceDefault is the managed-node default table.
	VisibilitySourceDefault VisibilitySource = "default"
	// VisibilitySourceNone is an ungoverned page: visible because nothing
	// said otherwise.
	VisibilitySourceNone VisibilitySource = "none"
	// VisibilitySourceGrant is an org page-access grant (T-435): a page or
	// tab the org otherwise hides is shown READ-ONLY until the grant ends.
	VisibilitySourceGrant VisibilitySource = "grant"
)

// visibilityInput is what one id's resolution reads.
type visibilityInput struct {
	floor                     bool
	hidden, readOnly, visible bool
	// allTabsHidden is true for a tabbed page whose every tab the org hid
	// (per-tab visibility, T-132): a page with nothing left to show is hidden.
	allTabsHidden   bool
	managedDefaults bool
	managedDefault  nodegov.Visibility
}

// visibilityRule is one row of the resolution table, walked top-down, FIRST
// MATCH WINS (CLAUDE.md #5). Every row has its own test case.
type visibilityRule struct {
	name   string
	match  func(in visibilityInput) bool
	level  func(in visibilityInput) nodegov.Visibility
	source VisibilitySource
}

func constLevel(v nodegov.Visibility) func(visibilityInput) nodegov.Visibility {
	return func(visibilityInput) nodegov.Visibility { return v }
}

// visibilityTable is THE precedence order:
//
//  1. the T8 floor is always visible;
//  2. an explicit org hide;
//  3. every tab of the page hidden by the org (a page with nothing left to
//     show is hidden, even when the org exposed it);
//  4. an explicit org read-only lock;
//  5. an explicit org expose;
//  6. the managed default (managed machine, live grant), at the machine's
//     audience's level (ManagedAudience);
//  7. visible.
//
// nodegov.Compile guarantees an id appears in at most one of the three org
// lists, so rows 2, 4 and 5 never compete; their order only documents
// restrictive first.
func visibilityTable() []visibilityRule {
	return []visibilityRule{
		{
			name: "t8 floor", match: func(in visibilityInput) bool { return in.floor },
			level: constLevel(nodegov.VisibilityVisible), source: VisibilitySourceFloor,
		},
		{
			name: "org hidden", match: func(in visibilityInput) bool { return in.hidden },
			level: constLevel(nodegov.VisibilityHidden), source: VisibilitySourceOrg,
		},
		{
			name: "every tab hidden", match: func(in visibilityInput) bool { return in.allTabsHidden },
			level: constLevel(nodegov.VisibilityHidden), source: VisibilitySourceOrg,
		},
		{
			name: "org read-only", match: func(in visibilityInput) bool { return in.readOnly },
			level: constLevel(nodegov.VisibilityReadOnly), source: VisibilitySourceOrg,
		},
		{
			name: "org visible", match: func(in visibilityInput) bool { return in.visible },
			level: constLevel(nodegov.VisibilityVisible), source: VisibilitySourceOrg,
		},
		{
			name: "managed default", match: func(in visibilityInput) bool { return in.managedDefaults },
			level: func(in visibilityInput) nodegov.Visibility { return in.managedDefault }, source: VisibilitySourceDefault,
		},
		{
			name: "ungoverned", match: func(visibilityInput) bool { return true },
			level: constLevel(nodegov.VisibilityVisible), source: VisibilitySourceNone,
		},
	}
}

func resolveVisibility(in visibilityInput) (nodegov.Visibility, VisibilitySource) {
	for _, r := range visibilityTable() {
		if r.match(in) {
			return r.level(in), r.source
		}
	}
	return nodegov.VisibilityVisible, VisibilitySourceNone
}

// ManagedDefaultsApply reports whether the managed-node default table is in
// force on this machine: it enrolled under Enterprise-Managed Tenancy and its
// grant is live (not absent, expired, rebound, re-keyed or tampered). The
// defaults need no published body: a managed developer machine starts from
// them the moment it enrols.
func (e Effective) ManagedDefaultsApply() bool {
	return e.Managed && !e.GrantRefused()
}

// ManagedAudience is the audience whose managed defaults this machine applies:
// the owner audience on a managed machine whose organization is the
// developer's own (OwnerManaged), the team audience otherwise. It reads the
// capability the boundary resolved, never an org id or kind.
func (e Effective) ManagedAudience() nodegov.ManagedAudience {
	return nodegov.AudienceFor(e.Managed && e.OwnerManaged)
}

// VisibilityActive reports whether anything on this machine can change a
// page's visibility: an applied governance body, or the managed defaults. It
// is the short-circuit every enforcement point takes, so an ungoverned
// individual node's request path never changes shape.
func (e Effective) VisibilityActive() bool {
	return e.Active || e.ManagedDefaultsApply()
}

// NavVisibility resolves one nav page on this machine: the org's answer,
// then a page-access grant for the page or any of its tabs lifts a hidden
// page to read-only (liftGranted).
func (e Effective) NavVisibility(id string) (nodegov.Visibility, VisibilitySource) {
	lvl, src := e.navVisibilityBase(id)
	return liftGranted(lvl, src, e.pageGranted(id) || e.anyTabGranted(id))
}

// liftGranted is the page-access grant's one rule (T-435): it shows a HIDDEN
// page or tab read-only and changes nothing else (it never raises a
// read-only page to editable, and the floor is visible anyway).
func liftGranted(lvl nodegov.Visibility, src VisibilitySource, granted bool) (nodegov.Visibility, VisibilitySource) {
	if granted && lvl == nodegov.VisibilityHidden {
		return nodegov.VisibilityReadOnly, VisibilitySourceGrant
	}
	return lvl, src
}

// pageGranted reports an honoured page-access grant for a page or tab id.
func (e Effective) pageGranted(id string) bool { return contains(e.GrantedPages, id) }

// anyTabGranted reports a page-access grant for one of page's tabs: the page
// must then show so the tab can (its other tabs stay as the org set them).
func (e Effective) anyTabGranted(page string) bool {
	for _, t := range nodegov.NavTabsOf(page) {
		if e.pageGranted(t) {
			return true
		}
	}
	return false
}

// navVisibilityBase is the org's answer for a page before any grant.
func (e Effective) navVisibilityBase(id string) (nodegov.Visibility, VisibilitySource) {
	return resolveVisibility(visibilityInput{
		floor:           nodegov.IsUnhideableNavSection(id),
		hidden:          e.Active && contains(e.HiddenSections, id),
		allTabsHidden:   e.Active && e.everyTabHidden(id),
		readOnly:        e.Active && contains(e.ReadOnlySections, id),
		visible:         e.Active && contains(e.VisibleSections, id),
		managedDefaults: e.ManagedDefaultsApply(),
		managedDefault:  nodegov.ManagedNavDefault(id, e.ManagedAudience()),
	})
}

// everyTabHidden reports whether page has tabs and the org hid every one.
func (e Effective) everyTabHidden(page string) bool {
	tabs := nodegov.NavTabsOf(page)
	if len(tabs) == 0 {
		return false
	}
	for _, id := range tabs {
		if !contains(e.HiddenSections, id) {
			return false
		}
	}
	return true
}

// TabVisibility resolves one page tab ("<page>/<tab>", nodegov.NavTabID) on
// this machine: hidden when the org hid it explicitly, otherwise whatever its
// page resolves to (a tab of a hidden page is hidden, of a read-only page
// read-only). A tab has no managed default of its own. Anything that is not a
// known tab id is visible.
func (e Effective) TabVisibility(id string) (nodegov.Visibility, VisibilitySource) {
	page, _, ok := nodegov.SplitNavTab(id)
	if !ok {
		return nodegov.VisibilityVisible, VisibilitySourceNone
	}
	granted := e.pageGranted(id) || e.pageGranted(page)
	if e.Active && contains(e.HiddenSections, id) && !nodegov.IsUnhideableNavSection(page) {
		return liftGranted(nodegov.VisibilityHidden, VisibilitySourceOrg, granted)
	}
	// The page's own answer BEFORE grants: a grant for a sibling tab shows
	// the page, never this tab.
	lvl, src := e.navVisibilityBase(page)
	return liftGranted(lvl, src, granted)
}

// IsNavTabHidden reports whether a page tab is hidden on this machine.
func (e Effective) IsNavTabHidden(id string) bool {
	lvl, _ := e.TabVisibility(id)
	return lvl == nodegov.VisibilityHidden
}

// SettingsVisibility resolves one Settings sub-section on this machine.
func (e Effective) SettingsVisibility(id string) (nodegov.Visibility, VisibilitySource) {
	return resolveVisibility(visibilityInput{
		floor:           nodegov.IsUnhideableSettingsSectionOn(id, e.Managed),
		hidden:          e.Active && contains(e.HiddenSettings, id),
		readOnly:        e.Active && contains(e.ReadOnlySettings, id),
		visible:         e.Active && contains(e.VisibleSettings, id),
		managedDefaults: e.ManagedDefaultsApply(),
		managedDefault:  nodegov.ManagedSettingsDefault(id, e.ManagedAudience()),
	})
}

// VisibilityEntry is one id's resolved level and what decided it.
type VisibilityEntry struct {
	Level  nodegov.Visibility `json:"level"`
	Source VisibilitySource   `json:"source"`
}

// DashboardVisibility is the whole resolved surface: GET /api/governance's
// `visibility` block. The four lists are the RESOLVED hidden / read-only ids
// (org directives plus managed defaults), which is what the SPA filters on;
// Sections / Settings carry the per-id level and source for the surfaces that
// explain a decision (the Privacy card, the managed-page notice).
type DashboardVisibility struct {
	ManagedDefaults  bool                       `json:"managed_defaults"`
	HiddenSections   []string                   `json:"hidden_sections"`
	ReadOnlySections []string                   `json:"read_only_sections"`
	HiddenSettings   []string                   `json:"hidden_settings"`
	ReadOnlySettings []string                   `json:"read_only_settings"`
	Sections         map[string]VisibilityEntry `json:"sections"`
	Settings         map[string]VisibilityEntry `json:"settings"`
	// HiddenTabs lists the page tabs ("<page>/<tab>") the org hid on a page
	// that is itself NOT hidden: what the SPA drops from a tab strip. A tab
	// of a hidden page is not listed (the whole page is gone). Tabs carries
	// every tab's level and source, for the surfaces that explain it.
	HiddenTabs []string                   `json:"hidden_tabs"`
	Tabs       map[string]VisibilityEntry `json:"tabs"`
}

// DashboardVisibility resolves every page and Settings section in the closed
// vocabularies.
func (e Effective) DashboardVisibility() DashboardVisibility {
	out := DashboardVisibility{
		ManagedDefaults:  e.ManagedDefaultsApply(),
		HiddenSections:   []string{},
		ReadOnlySections: []string{},
		HiddenSettings:   []string{},
		ReadOnlySettings: []string{},
		Sections:         make(map[string]VisibilityEntry, len(nodegov.NavSectionIDs)),
		Settings:         make(map[string]VisibilityEntry, len(nodegov.SettingsSectionIDs)),
		HiddenTabs:       []string{},
		Tabs:             map[string]VisibilityEntry{},
	}
	for _, id := range nodegov.NavTabIDs() {
		lvl, src := e.TabVisibility(id)
		out.Tabs[id] = VisibilityEntry{Level: lvl, Source: src}
		page, _, _ := nodegov.SplitNavTab(id)
		if lvl == nodegov.VisibilityHidden && !e.IsNavSectionHidden(page) {
			out.HiddenTabs = append(out.HiddenTabs, id)
		}
	}
	for _, id := range nodegov.NavSectionIDs {
		lvl, src := e.NavVisibility(id)
		out.Sections[id] = VisibilityEntry{Level: lvl, Source: src}
		switch lvl {
		case nodegov.VisibilityHidden:
			out.HiddenSections = append(out.HiddenSections, id)
		case nodegov.VisibilityReadOnly:
			out.ReadOnlySections = append(out.ReadOnlySections, id)
		}
	}
	for _, id := range nodegov.SettingsSectionIDs {
		lvl, src := e.SettingsVisibility(id)
		out.Settings[id] = VisibilityEntry{Level: lvl, Source: src}
		switch lvl {
		case nodegov.VisibilityHidden:
			out.HiddenSettings = append(out.HiddenSettings, id)
		case nodegov.VisibilityReadOnly:
			out.ReadOnlySettings = append(out.ReadOnlySettings, id)
		}
	}
	return out
}
