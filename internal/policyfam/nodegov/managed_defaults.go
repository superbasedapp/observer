package nodegov

// The MANAGED-NODE DEFAULT visibility table (backlog item 4, operator ruling
// 2026-10-03: "our controlled or managed setup sees way too much; by default a
// lot of things have to be disabled"). Classification of record:
// docs/audits/managed-node-visibility-2026-10-03.md.
//
// ONE table per vocabulary, keyed by the same closed ids the directive lists
// use, so "what a managed developer sees when the org published nothing" and
// "what an org body may hide, lock or expose" can never disagree about which
// pages exist. It is DATA: internal/govern resolves it (Effective.
// DashboardVisibility), and every enforcement point (the node API guard, the
// SPA's nav, route guard, command palette, tour, help and Settings rail, and
// the org admin's Developer dashboards card through Vocabulary()) reads that
// one resolution.
//
// It applies ONLY on a managed node (Enterprise-Managed Tenancy) whose grant is
// live. An individual / BYO node never sees a default: every page stays
// visible unless its own consented node.governance body says otherwise.
//
// The T8 floor (UnhideableNavSectionIDs / UnhideableSettingsSectionIDs) is
// always Visible here; TestManagedDefaultsRespectTheFloor pins it.

// Visibility is one page's (or Settings section's) level on a node.
type Visibility string

// The three levels, from most to least restrictive.
const (
	// VisibilityHidden removes the page from every surface and refuses its
	// API (404 governance_hidden).
	VisibilityHidden Visibility = "hidden"
	// VisibilityReadOnly shows the page with a read-only notice and refuses
	// every write to it (409 governance_read_only).
	VisibilityReadOnly Visibility = "read_only"
	// VisibilityVisible is the page as an individual node sees it.
	VisibilityVisible Visibility = "visible"
)

// IsVisibility reports whether v is one of the three levels.
func IsVisibility(v string) bool {
	switch Visibility(v) {
	case VisibilityHidden, VisibilityReadOnly, VisibilityVisible:
		return true
	}
	return false
}

// ManagedDefault is one row of a managed-default table.
type ManagedDefault struct {
	// ID is a NavSectionIDs (or SettingsSectionIDs) entry.
	ID string
	// Level is the default on a managed node.
	Level Visibility
	// Why grounds the row in what the page does. It is surfaced to the org
	// admin in the Developer dashboards card, and the table test refuses a
	// row without one.
	Why string
}

// ManagedNavDefaults is the nav-page half, in nav order.
var ManagedNavDefaults = []ManagedDefault{
	{"overview", VisibilityVisible, "The developer's own spend, tokens and activity."},
	{"live", VisibilityVisible, "The developer's own sessions as they happen."},
	{"sessions", VisibilityVisible, "The developer's own sessions, tags, notes and resume."},
	{"actions", VisibilityVisible, "The developer's own captured tool calls."},
	{"projects", VisibilityVisible, "The developer's own per-project spend, commits and guidance files."},
	{"security", VisibilityHidden, "Guard verdicts, rule editing, approvals, prompt-guard and MCP pins: guard configuration the organization owns on a managed machine."},
	{"code-security", VisibilityHidden, "Code security findings and the commit-gate posture: hidden by default like Guard's page, which the organization may expose."},
	{"egress", VisibilityHidden, "Plane-A egress routing of a hosted app's end-user traffic: organization policy, not the developer's own usage."},
	{"search", VisibilityVisible, "Full-text search over the developer's own sessions."},
	{"cost", VisibilityVisible, "The developer's own spend (or token usage, per the organization's display policy) and budgets."},
	{"plans", VisibilityVisible, "The developer's own subscription limits and account balances, read on their machine."},
	{"analysis", VisibilityVisible, "Insights over the developer's own spending."},
	{"tools", VisibilityVisible, "The developer's own per-tool activity."},
	{"compression", VisibilityReadOnly, "The savings are the developer's; the proxy and compression configuration is the organization's."},
	{"cache", VisibilityVisible, "The developer's own prompt-cache savings and keep-warm advice."},
	{"suggestions", VisibilityVisible, "Recommendations computed from the developer's own activity."},
	{"routing", VisibilityHidden, "Model-routing policy, apply and shadow: an organization rail on a managed machine."},
	{"benchmarks", VisibilityVisible, "Results of the developer's own benchmark runs (read-only)."},
	{"discovery", VisibilityVisible, "Wasted-effort signals in the developer's own sessions."},
	{"patterns", VisibilityVisible, "Habits from the developer's own sessions, written into their own project files."},
	{"policies", VisibilityHidden, "Authoring Plane-A admission and egress policy: organization policy."},
	{"agent-config", VisibilityReadOnly, "The developer's AI tool settings and instruction files: readable, but on a managed machine the organization decides who may edit them (read-only until it grants editing, D-102)."},
	{"privacy", VisibilityVisible, "Transparency: what is captured and shared. Can never be hidden."},
	{"terminals", VisibilityVisible, "The developer's own agent terminals and launch settings."},
	{"remote", VisibilityReadOnly, "Exposing the machine remotely is a machine-security decision; the developer still sees whether it is on and who connected."},
	{"messages", VisibilityVisible, "Conversations between the developer and their organization's admins (D-695). Can never be hidden."},
	{"requests", VisibilityVisible, "Where the developer asks the organization for an exception and follows the answer (D-089). Can never be hidden."},
	{"settings", VisibilityVisible, "Carries enrolment and unenrol. Can never be hidden."},
}

// ManagedSettingsDefaults is the Settings sub-section half, in Settings order.
var ManagedSettingsDefaults = []ManagedDefault{
	{"pricing", VisibilityReadOnly, "A local rate override could re-price spend under an organization budget; the rates stay readable."},
	{"backfill", VisibilityVisible, "Maintenance of the developer's own local database."},
	{"tools", VisibilityVisible, "Read-only status of the developer's connected AI tools."},
	{"health", VisibilityVisible, "The developer's own diagnostics."},
	{"storage", VisibilityVisible, "The developer's own disk: size, vacuum, backup."},
	{"enrolment", VisibilityVisible, "The enrolment and the way out. Can never be hidden."},
	{"intelligence", VisibilityReadOnly, "Summary model, budget cap and code index: capture and spend configuration."},
	{"observer", VisibilityReadOnly, "Database path, log level and watched roots: what gets captured."},
	{"watcher", VisibilityReadOnly, "Watch paths and ignore globs: what gets captured."},
	{"freshness", VisibilityReadOnly, "Freshness classifier: capture configuration."},
	{"retention", VisibilityReadOnly, "Retention windows are a compliance decision."},
	{"hooks", VisibilityReadOnly, "Hook registration is capture integrity; managed machines register hooks automatically."},
	{"proxy", VisibilityReadOnly, "The proxy is the organization's enforcement point."},
	{"dashboard", VisibilityReadOnly, "Binding the dashboard off loopback is a machine-security decision."},
	{"compression", VisibilityReadOnly, "Proxy compression configuration."},
	{"profiles", VisibilityReadOnly, "Proxy compression profiles."},
	{"org", VisibilityVisible, "What this machine shares with the organization. Can never be hidden."},
	{"guard", VisibilityHidden, "Guard posture, rules, budgets and MCP pinning: security configuration the organization owns."},
	{"routing", VisibilityHidden, "Model-routing configuration: an organization rail."},
	{"otel", VisibilityHidden, "Exporting spans to an arbitrary collector is a data-egress decision."},
	{"mcp", VisibilityReadOnly, "The MCP retrieval tool surface and its allow/deny lists."},
	{"advisor", VisibilityVisible, "How chatty the developer's own suggestions are."},
	{"cachetrack", VisibilityReadOnly, "Cache-tracking engine: capture configuration."},
	{"observability", VisibilityHidden, "The admin-plane OTLP receiver and eval plane, not the developer's own usage."},
	{"secrets", VisibilityReadOnly, "The developer must not weaken redaction; the patterns stay readable."},
	{"antigravity", VisibilityVisible, "The developer's own Antigravity adapter setup."},
	{"process", VisibilityReadOnly, "Process capture: capture configuration the organization extracts."},
	{"browser", VisibilityReadOnly, "Browser-capture granularity ceiling: capture configuration."},
	{"terminal", VisibilityVisible, "Session attach: the developer's own terminal workflow."},
	{"cloud", VisibilityHidden, "Personal Cloud Intelligence on an organization machine: sessions captured while enrolled belong to the organization plane (the `intel` section), so the personal section is hidden by default; the admin can expose it for sessions captured before enrolment (parity design Q8)."},
	{"intel", VisibilityReadOnly, "The organization's own session enrichment: the developer sees what it runs and its evidence level; the settings are the organization's."},
	{"tasks", VisibilityReadOnly, "Task tracking engine: capture configuration."},
}

var (
	managedNavIndex      = indexDefaults(ManagedNavDefaults)
	managedSettingsIndex = indexDefaults(ManagedSettingsDefaults)
)

func indexDefaults(rows []ManagedDefault) map[string]ManagedDefault {
	m := make(map[string]ManagedDefault, len(rows))
	for _, r := range rows {
		m[r.ID] = r
	}
	return m
}

// ManagedNavDefault returns a nav page's managed default. An id outside the
// table (a newer server's page this build does not know) resolves Visible:
// a default can only ever be applied to a page this build can name.
func ManagedNavDefault(id string) Visibility {
	if r, ok := managedNavIndex[id]; ok {
		return r.Level
	}
	return VisibilityVisible
}

// ManagedSettingsDefault is ManagedNavDefault for Settings sub-sections.
func ManagedSettingsDefault(id string) Visibility {
	if r, ok := managedSettingsIndex[id]; ok {
		return r.Level
	}
	return VisibilityVisible
}

// managedDefaultWhy returns a row's reason (empty when unknown).
func managedDefaultWhy(rows map[string]ManagedDefault, id string) string {
	return rows[id].Why
}
