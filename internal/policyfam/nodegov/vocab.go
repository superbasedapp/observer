package nodegov

import "strings"

// The two CLOSED vocabularies of schema 1.
//
// NavSectionIDs mirrors the `id` of every item in web/src/lib/nav.ts's
// NAV_GROUPS (the node dashboard's own page list); SettingsSectionIDs
// mirrors the `id` of every entry in web/src/pages/Settings.tsx's SECTIONS.
// vocab_source_test.go reads both SPA files and fails when either list
// drifts, so "the vocabulary is the SPA's own page list" is a checked fact
// rather than a comment.
//
// Ordering is the SPA's own order, so a rendered list of "what your
// organization hid" reads the way the sidebar does.

// NavSectionIDs is the closed set of hideable/lockable node-dashboard nav
// sections (28 today; "plans" joined with the Plans & limits page, "requests" with the request-grants design, G6,
// "agent-config" with adapter config P4/P5, "messages" with admin and
// developer messaging, T-854, and "code-security" with the security pillar's
// Code security page).
var NavSectionIDs = []string{
	"overview", "live", "sessions", "actions", "projects", "security", "code-security", "egress", "search",
	"cost", "plans", "analysis", "tools",
	"compression", "cache", "suggestions", "routing", "benchmarks", "discovery", "patterns",
	"policies", "agent-config", "privacy", "terminals", "remote", "messages", "requests", "settings",
}

// SettingsSectionIDs is the closed set of node-dashboard Settings
// sub-sections (32 today; "tasks" joined with the 2026-09-10 merge of the
// session task-tracking Settings section from origin/main, and "intel", the
// org-plane Cloud Intelligence section, with the 2026-10-03 parity arc).
var SettingsSectionIDs = []string{
	"pricing", "backfill", "tools", "health", "storage", "enrolment", "intelligence",
	"observer", "watcher", "freshness", "retention", "hooks", "proxy", "dashboard",
	"compression", "profiles", "org", "guard", "routing", "otel", "mcp", "advisor",
	"cachetrack", "observability", "secrets", "antigravity", "process", "browser",
	"terminal", "cloud", "intel", "tasks",
}

// UnhideableNavSectionIDs is threat T8's structural floor: the nav sections
// through which a developer learns what their employer configured and
// receives. An org body naming one of these in ANY list (hidden or
// read_only) is a lint error server-side and a decode failure agent-side.
//
// read_only is refused too, not just hidden: a read-only Settings page
// cannot run `unenroll`, and a governance regime that can disable its own
// exit is not revocable, which is the property §1.2 rests on.
//
// "requests" joined the floor with the request-grants design (D-089): the
// page through which a developer asks for an exception must never be hidden
// by the policy the exception is from.
//
// "messages" joined it with admin and developer messaging (D-695): the page
// where the organization writes to the developer and the developer answers
// is how a developer receives, so no policy may hide or lock it. Keeping it
// on the floor also means no org body ever names it, so an older agent that
// predates the id never meets it in a directive.
var UnhideableNavSectionIDs = []string{"settings", "privacy", "requests", "messages"}

// UnhideableSettingsSectionIDs is the same floor one level down: the
// Settings sub-sections that render the enrolment, the grant, and the org
// push posture.
var UnhideableSettingsSectionIDs = []string{"enrolment", "org"}

// IndividualUnhideableSettingsSectionIDs extends the floor on an INDIVIDUAL
// (not Enterprise-Managed) node only (T-379, review M4-07). "intel" carries
// the org-plane consent banner and Accept / Withdraw: on an individual node
// the consent is the developer's own decision (D-007, D-170, D-171), so a
// policy that hides or locks it would remove the only way to give or take it
// back. It is NOT in the static floor: on a managed node the section is a
// notice and the managed default locks it read-only, and an org body naming
// it stays valid. The node's visibility resolver applies this list
// (IsUnhideableSettingsSectionOn); the org-side lint does not.
var IndividualUnhideableSettingsSectionIDs = []string{"intel"}

func setOf(ids []string) map[string]bool {
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

var (
	navSectionSet                   = setOf(NavSectionIDs)
	settingsSectionSet              = setOf(SettingsSectionIDs)
	unhideableNavSet                = setOf(UnhideableNavSectionIDs)
	unhideableSettingsSet           = setOf(UnhideableSettingsSectionIDs)
	individualUnhideableSettingsSet = setOf(IndividualUnhideableSettingsSectionIDs)
)

// IsNavSection reports whether id is a known nav section.
func IsNavSection(id string) bool { return navSectionSet[id] }

// IsSettingsSection reports whether id is a known Settings sub-section.
func IsSettingsSection(id string) bool { return settingsSectionSet[id] }

// IsUnhideableNavSection reports whether id is structurally exempt from
// every nav visibility directive (T8).
func IsUnhideableNavSection(id string) bool { return unhideableNavSet[id] }

// IsUnhideableSettingsSection reports whether id is structurally exempt
// from every Settings visibility directive (T8).
func IsUnhideableSettingsSection(id string) bool { return unhideableSettingsSet[id] }

// IsUnhideableSettingsSectionOn is IsUnhideableSettingsSection for a node of
// known tenancy: an individual node (managed false) also exempts
// IndividualUnhideableSettingsSectionIDs.
func IsUnhideableSettingsSectionOn(id string, managed bool) bool {
	return unhideableSettingsSet[id] || (!managed && individualUnhideableSettingsSet[id])
}

// ---------------------------------------------------------------------------
// Page tabs (backlog item 4, per-tab visibility, T-132).
//
// A page tab is addressed in the EXISTING nav section lists as
// "<page>/<tab>" (NavTabID): "security/prompt-guard". It rides the nav lists
// rather than a new body key because released agents decode the body with
// DisallowUnknownFields, while an id they do not know is exactly what the
// vocabulary projection (vocablevel.go) already strips for them. A tab can
// only be HIDDEN: Compile refuses one in read_only or visible.
//
// The tab table itself (NavTabs) is GENERATED from the SPA's own tab tables
// (web/src/lib/pageTabRoutes.ts + nodePageTabs.ts) into navtabs_gen.go;
// navtabs_test.go fails when the committed file is stale.
// ---------------------------------------------------------------------------

//go:generate go run ./navtabsrc/gen -routes ../../../web/src/lib/pageTabRoutes.ts -tabs ../../../web/src/lib/nodePageTabs.ts -out navtabs_gen.go

// NavTabSep separates the page id from the tab id in a nav tab id.
const NavTabSep = "/"

// NavTab is one tab of a tabbed page: its `?tab=` id and its label.
type NavTab struct {
	ID    string
	Label string
}

// NavTabPage is one tabbed node-dashboard page and its tabs in strip order.
type NavTabPage struct {
	Page string
	Tabs []NavTab
}

var (
	navTabSet    = map[string]bool{}
	navTabLabel  = map[string]string{}
	navTabsByPg  = map[string][]string{}
	navTabIDList []string
)

func init() {
	for _, p := range NavTabs {
		for _, t := range p.Tabs {
			id := NavTabID(p.Page, t.ID)
			navTabSet[id] = true
			navTabLabel[id] = t.Label
			navTabsByPg[p.Page] = append(navTabsByPg[p.Page], id)
			navTabIDList = append(navTabIDList, id)
		}
	}
}

// NavTabID renders the nav-list id of one page tab.
func NavTabID(page, tab string) string { return page + NavTabSep + tab }

// IsNavTab reports whether id names a known tab of a known tabbed page.
func IsNavTab(id string) bool { return navTabSet[id] }

// SplitNavTab returns the page and tab of a KNOWN nav tab id; ok is false for
// anything else (a page id, an unknown tab, a malformed id).
func SplitNavTab(id string) (page, tab string, ok bool) {
	if !navTabSet[id] {
		return "", "", false
	}
	page, tab, _ = strings.Cut(id, NavTabSep)
	return page, tab, true
}

// NavTabIDs returns every nav tab id, pages in NavTabs order and tabs in strip
// order. The slice is a copy.
func NavTabIDs() []string { return append([]string(nil), navTabIDList...) }

// NavTabsOf returns the nav tab ids of one page in strip order, nil for a page
// without tabs. The slice is a copy.
func NavTabsOf(page string) []string {
	ids := navTabsByPg[page]
	if ids == nil {
		return nil
	}
	return append([]string(nil), ids...)
}

// IsNavSectionOrTab reports whether id may appear in sections.hidden: a page
// or one of its tabs.
func IsNavSectionOrTab(id string) bool { return IsNavSection(id) || IsNavTab(id) }

// isUnhideableNavID extends the T8 floor to tabs: a tab of a floor page would
// be as unhideable as the page. No floor page has tabs today
// (TestNavTabVocabulary), so this is a guard against a future one.
func isUnhideableNavID(id string) bool {
	if page, _, ok := SplitNavTab(id); ok {
		return IsUnhideableNavSection(page)
	}
	return IsUnhideableNavSection(id)
}
