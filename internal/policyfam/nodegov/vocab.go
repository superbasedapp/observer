package nodegov

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
// sections (22 today).
var NavSectionIDs = []string{
	"overview", "live", "sessions", "actions", "security", "egress", "search",
	"cost", "analysis", "tools",
	"compression", "cache", "suggestions", "routing", "benchmarks", "discovery", "patterns",
	"policies", "privacy", "terminals", "remote", "settings",
}

// SettingsSectionIDs is the closed set of node-dashboard Settings
// sub-sections (30 today; "tasks" joined with the 2026-09-10 merge of the
// session task-tracking Settings section from origin/main).
var SettingsSectionIDs = []string{
	"pricing", "backfill", "tools", "health", "storage", "enrolment", "intelligence",
	"observer", "watcher", "freshness", "retention", "hooks", "proxy", "dashboard",
	"compression", "profiles", "org", "guard", "routing", "otel", "mcp", "advisor",
	"cachetrack", "observability", "secrets", "antigravity", "process", "browser",
	"terminal", "cloud", "tasks",
}

// UnhideableNavSectionIDs is threat T8's structural floor: the nav sections
// through which a developer learns what their employer configured and
// receives. An org body naming one of these in ANY list (hidden or
// read_only) is a lint error server-side and a decode failure agent-side.
//
// read_only is refused too, not just hidden: a read-only Settings page
// cannot run `unenroll`, and a governance regime that can disable its own
// exit is not revocable, which is the property §1.2 rests on.
var UnhideableNavSectionIDs = []string{"settings", "privacy"}

// UnhideableSettingsSectionIDs is the same floor one level down: the
// Settings sub-sections that render the enrolment, the grant, and the org
// push posture.
var UnhideableSettingsSectionIDs = []string{"enrolment", "org"}

func setOf(ids []string) map[string]bool {
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

var (
	navSectionSet         = setOf(NavSectionIDs)
	settingsSectionSet    = setOf(SettingsSectionIDs)
	unhideableNavSet      = setOf(UnhideableNavSectionIDs)
	unhideableSettingsSet = setOf(UnhideableSettingsSectionIDs)
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
