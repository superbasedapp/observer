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
// Each row carries one level per AUDIENCE (ManagedAudience, finding F12 of
// the v1.42.1 ship-readiness audit). A team organization's machine is managed
// by an admin who is not its developer: the row's Level. A personal
// organization of one is managed by its owner (operator ruling 2026-11-19,
// orgkind's OwnerManaged capability), whose own AI apps (Egress among them,
// operator ruling R2, 2026-11-23), routing and policy pages an organization
// has no one else to keep them from: the row's Owner
// level, which is the team Level when the row leaves it empty. The audience
// is a capability resolved at the boundary (govern.Grant.OwnerManaged, and
// the org server's orgkind row), never an org id or a kind string read here.
//
// The T8 floor (UnhideableNavSectionIDs / UnhideableSettingsSectionIDs) is
// always Visible here, for every audience; TestManagedDefaultsRespectTheFloor
// pins it.

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

// ManagedAudience is who manages a managed machine, which picks the level a
// managed-default row applies there. The zero value is the team audience, so
// a caller that states nothing gets today's (most restrictive) defaults.
type ManagedAudience string

const (
	// ManagedAudienceTeam is a team or enterprise organization's machine:
	// the admin who manages it is not its developer. The zero value.
	ManagedAudienceTeam ManagedAudience = ""
	// ManagedAudienceOwner is a machine its owner manages from a personal
	// organization of one (the org's only admin and only developer are the
	// same person; orgkind's OwnerManaged capability).
	ManagedAudienceOwner ManagedAudience = "owner"
)

// AudienceFor maps the owner-managed capability onto its audience. It is the
// one mapping every caller uses, so the node (govern) and the org server's
// vocabulary can never pick different rows for the same organization.
func AudienceFor(ownerManaged bool) ManagedAudience {
	if ownerManaged {
		return ManagedAudienceOwner
	}
	return ManagedAudienceTeam
}

// ManagedDefault is one row of a managed-default table.
type ManagedDefault struct {
	// ID is a NavSectionIDs (or SettingsSectionIDs) entry.
	ID string
	// Level is the default on a managed node of the team audience
	// (ManagedAudienceTeam).
	Level Visibility
	// Why grounds the row in what the page does. It is surfaced to the org
	// admin in the Developer dashboards card, and the table test refuses a
	// row without one.
	Why string
	// Owner is the default on a machine its owner manages
	// (ManagedAudienceOwner). Empty means the same as Level.
	Owner Visibility
	// OwnerWhy is the reason for Owner where it differs from Level; empty
	// means Why. The table test refuses an Owner level that differs from
	// Level without one.
	OwnerWhy string
}

// LevelFor returns the row's level for audience a: the Owner level for the
// owner audience when the row sets one, otherwise Level. An audience this
// build does not know resolves the team level, the most restrictive.
func (r ManagedDefault) LevelFor(a ManagedAudience) Visibility {
	if a == ManagedAudienceOwner && r.Owner != "" {
		return r.Owner
	}
	return r.Level
}

// WhyFor returns the reason that goes with LevelFor(a).
func (r ManagedDefault) WhyFor(a ManagedAudience) string {
	if a == ManagedAudienceOwner && r.Owner != "" && r.OwnerWhy != "" {
		return r.OwnerWhy
	}
	return r.Why
}

// ManagedNavDefaults is the nav-page half, in nav order.
var ManagedNavDefaults = []ManagedDefault{
	{ID: "overview", Level: VisibilityVisible, Why: "The developer's own spend, tokens and activity."},
	{ID: "live", Level: VisibilityVisible, Why: "The developer's own sessions as they happen."},
	{ID: "sessions", Level: VisibilityVisible, Why: "The developer's own sessions, tags, notes and resume."},
	{ID: "actions", Level: VisibilityVisible, Why: "The developer's own captured tool calls."},
	{ID: "projects", Level: VisibilityVisible, Why: "The developer's own per-project spend, commits and guidance files."},
	{ID: "security", Level: VisibilityHidden, Why: "Guard verdicts, rule editing, approvals, prompt-guard and MCP pins: guard configuration the organization owns on a managed machine."},
	{ID: "code-security", Level: VisibilityHidden, Why: "Code security findings and the commit-gate posture: hidden by default like Guard's page, which the organization may expose."},
	{
		ID: "egress", Level: VisibilityHidden, Why: "AI Apps egress routing of an app's end-user traffic: organization policy, not the developer's own usage.",
		Owner: VisibilityVisible, OwnerWhy: "On a machine its owner manages from a personal organization of one, the AI apps and their egress routing are the owner's own, so the page stays visible like the other Your AI apps pages (operator ruling R2, 2026-11-23).",
	},
	{ID: "search", Level: VisibilityVisible, Why: "Full-text search over the developer's own sessions."},
	{ID: "cost", Level: VisibilityVisible, Why: "The developer's own spend (or token usage, per the organization's display policy) and budgets."},
	{ID: "plans", Level: VisibilityVisible, Why: "The developer's own subscription limits and account balances, read on their machine."},
	{ID: "analysis", Level: VisibilityVisible, Why: "Insights over the developer's own spending."},
	{ID: "tools", Level: VisibilityVisible, Why: "The developer's own per-tool activity."},
	{ID: "compression", Level: VisibilityReadOnly, Why: "The savings are the developer's; the proxy and compression configuration is the organization's."},
	{ID: "cache", Level: VisibilityVisible, Why: "The developer's own prompt-cache savings and keep-warm advice."},
	{ID: "suggestions", Level: VisibilityVisible, Why: "Recommendations computed from the developer's own activity."},
	{
		ID: "routing", Level: VisibilityHidden, Why: "Model-routing policy, apply and shadow: an organization rail on a managed machine.",
		Owner: VisibilityVisible, OwnerWhy: "On a machine its owner manages from a personal organization of one, model routing is the owner's own choice, so the page stays visible.",
	},
	{ID: "benchmarks", Level: VisibilityVisible, Why: "Results of the developer's own benchmark runs (read-only)."},
	{ID: "discovery", Level: VisibilityVisible, Why: "Wasted-effort signals in the developer's own sessions."},
	{ID: "patterns", Level: VisibilityVisible, Why: "Habits from the developer's own sessions, written into their own project files."},
	{
		ID: "app-traces", Level: VisibilityHidden, Why: "Traces of the AI apps the developer builds: on a managed machine app telemetry belongs to the organization's gateway, which the organization may expose here.",
		Owner: VisibilityVisible, OwnerWhy: "On a machine its owner manages from a personal organization of one, app telemetry is the owner's own and the AI Apps SDK's score, feedback and trace-cost calls read this machine's API, so the page stays visible.",
	},
	{
		ID: "app-sessions", Level: VisibilityHidden, Why: "Sessions of the AI apps the developer builds: hidden by default like the other Your AI apps pages.",
		Owner: VisibilityVisible, OwnerWhy: "On a machine its owner manages from a personal organization of one, the AI apps are the owner's own and the AI Apps SDK's score, feedback and trace-cost calls read this machine's API, so the page stays visible.",
	},
	{
		ID: "app-analytics", Level: VisibilityHidden, Why: "Analytics of the AI apps the developer builds: hidden by default like the other Your AI apps pages.",
		Owner: VisibilityVisible, OwnerWhy: "On a machine its owner manages from a personal organization of one, the AI apps are the owner's own and the AI Apps SDK's score, feedback and trace-cost calls read this machine's API, so the page stays visible.",
	},
	{
		ID: "app-end-users", Level: VisibilityHidden, Why: "End users of the developer's AI apps (personal data): hidden by default like the other Your AI apps pages.",
		Owner: VisibilityVisible, OwnerWhy: "On a machine its owner manages from a personal organization of one, the AI apps are the owner's own and the AI Apps SDK's score, feedback and trace-cost calls read this machine's API, so the page stays visible.",
	},
	{
		ID: "app-evals", Level: VisibilityHidden, Why: "AI app eval datasets and runs: hidden by default like the other Your AI apps pages.",
		Owner: VisibilityVisible, OwnerWhy: "On a machine its owner manages from a personal organization of one, the AI apps are the owner's own and the AI Apps SDK's score, feedback and trace-cost calls read this machine's API, so the page stays visible.",
	},
	{
		ID: "app-scores", Level: VisibilityHidden, Why: "AI app scores and feedback: hidden by default like the other Your AI apps pages.",
		Owner: VisibilityVisible, OwnerWhy: "On a machine its owner manages from a personal organization of one, the AI apps are the owner's own and the AI Apps SDK's score, feedback and trace-cost calls read this machine's API, so the page stays visible.",
	},
	{
		ID: "app-prompts", Level: VisibilityHidden, Why: "The machine's AI Apps prompt registry: hidden by default like the other Your AI apps pages.",
		Owner: VisibilityVisible, OwnerWhy: "On a machine its owner manages from a personal organization of one, the AI apps are the owner's own and the AI Apps SDK's score, feedback and trace-cost calls read this machine's API, so the page stays visible.",
	},
	{
		ID: "app-alerts", Level: VisibilityHidden, Why: "Alert rules over AI app traces: hidden by default like the other Your AI apps pages.",
		Owner: VisibilityVisible, OwnerWhy: "On a machine its owner manages from a personal organization of one, the AI apps are the owner's own and the AI Apps SDK's score, feedback and trace-cost calls read this machine's API, so the page stays visible.",
	},
	{ID: "you", Level: VisibilityVisible, Why: "The developer's own identity, accounts, consents and stored credentials. Can never be hidden."},
	{
		ID: "policies", Level: VisibilityHidden, Why: "Authoring AI Apps admission and egress policy: organization policy.",
		Owner: VisibilityVisible, OwnerWhy: "On a machine its owner manages from a personal organization of one, the AI Apps admission and egress policy is for the owner's own apps, so the page stays visible.",
	},
	{ID: "agent-config", Level: VisibilityReadOnly, Why: "The developer's AI tool settings and instruction files: readable, but on a managed machine the organization decides who may edit them (read-only until it grants editing, D-102)."},
	{ID: "privacy", Level: VisibilityVisible, Why: "Transparency: what is captured and shared. Can never be hidden."},
	{ID: "terminals", Level: VisibilityVisible, Why: "The developer's own agent terminals and launch settings."},
	{ID: "remote", Level: VisibilityReadOnly, Why: "Exposing the machine remotely is a machine-security decision; the developer still sees whether it is on and who connected."},
	{ID: "messages", Level: VisibilityVisible, Why: "Conversations between the developer and their organization's admins (D-695). Can never be hidden."},
	{ID: "requests", Level: VisibilityVisible, Why: "Where the developer asks the organization for an exception and follows the answer (D-089). Can never be hidden."},
	{ID: "settings", Level: VisibilityVisible, Why: "Carries enrolment and unenrol. Can never be hidden."},
}

// ManagedSettingsDefaults is the Settings sub-section half, in Settings order.
var ManagedSettingsDefaults = []ManagedDefault{
	{ID: "general", Level: VisibilityVisible, Why: "The developer's own focus (AI coding agents, AI apps or both): which pages lead the dashboard. A view preference, not an organization setting."},
	{ID: "pricing", Level: VisibilityReadOnly, Why: "A local rate override could re-price spend under an organization budget; the rates stay readable."},
	{ID: "backfill", Level: VisibilityVisible, Why: "Maintenance of the developer's own local database."},
	{ID: "tools", Level: VisibilityVisible, Why: "Read-only status of the developer's connected AI tools."},
	{ID: "health", Level: VisibilityVisible, Why: "The developer's own diagnostics."},
	{ID: "storage", Level: VisibilityVisible, Why: "The developer's own disk: size, vacuum, backup."},
	{ID: "enrolment", Level: VisibilityVisible, Why: "The enrolment and the way out. Can never be hidden."},
	{ID: "intelligence", Level: VisibilityReadOnly, Why: "Summary model, budget cap and code index: capture and spend configuration."},
	{ID: "observer", Level: VisibilityReadOnly, Why: "Database path, log level and watched roots: what gets captured."},
	{ID: "watcher", Level: VisibilityReadOnly, Why: "Watch paths and ignore globs: what gets captured."},
	{ID: "freshness", Level: VisibilityReadOnly, Why: "Freshness classifier: capture configuration."},
	{ID: "retention", Level: VisibilityReadOnly, Why: "Retention windows are a compliance decision."},
	{ID: "hooks", Level: VisibilityReadOnly, Why: "Hook registration is capture integrity; managed machines register hooks automatically."},
	{ID: "proxy", Level: VisibilityReadOnly, Why: "The proxy is the organization's enforcement point."},
	{ID: "dashboard", Level: VisibilityReadOnly, Why: "Binding the dashboard off loopback is a machine-security decision."},
	{ID: "compression", Level: VisibilityReadOnly, Why: "Proxy compression configuration."},
	{ID: "profiles", Level: VisibilityReadOnly, Why: "Proxy compression profiles."},
	{ID: "org", Level: VisibilityVisible, Why: "What this machine shares with the organization. Can never be hidden."},
	{ID: "guard", Level: VisibilityHidden, Why: "Guard posture, rules, budgets and MCP pinning: security configuration the organization owns."},
	{
		ID: "routing", Level: VisibilityHidden, Why: "Model-routing configuration: an organization rail.",
		Owner: VisibilityVisible, OwnerWhy: "On a machine its owner manages from a personal organization of one, the model-routing configuration behind the Routing page is the owner's own, so the section stays visible.",
	},
	{ID: "otel", Level: VisibilityHidden, Why: "Exporting spans to an arbitrary collector is a data-egress decision."},
	{ID: "mcp", Level: VisibilityReadOnly, Why: "The MCP retrieval tool surface and its allow/deny lists."},
	{ID: "advisor", Level: VisibilityVisible, Why: "How chatty the developer's own suggestions are."},
	{ID: "cachetrack", Level: VisibilityReadOnly, Why: "Cache-tracking engine: capture configuration."},
	{
		ID: "observability", Level: VisibilityHidden, Why: "The admin-plane OTLP receiver and eval plane, not the developer's own usage.",
		Owner: VisibilityVisible, OwnerWhy: "On a machine its owner manages from a personal organization of one, this section configures the owner's own Your AI apps pages and the AI Apps SDK credential, so it stays visible.",
	},
	{ID: "secrets", Level: VisibilityReadOnly, Why: "The developer must not weaken redaction; the patterns stay readable."},
	{ID: "antigravity", Level: VisibilityVisible, Why: "The developer's own Antigravity adapter setup."},
	{ID: "process", Level: VisibilityReadOnly, Why: "Process capture: capture configuration the organization extracts."},
	{ID: "browser", Level: VisibilityReadOnly, Why: "Browser-capture granularity ceiling: capture configuration."},
	{ID: "terminal", Level: VisibilityVisible, Why: "Session attach: the developer's own terminal workflow."},
	{ID: "cloud", Level: VisibilityHidden, Why: "Personal Cloud Intelligence on an organization machine: sessions captured while enrolled belong to the organization plane (the `intel` section), so the personal section is hidden by default; the admin can expose it for sessions captured before enrolment (parity design Q8)."},
	{ID: "intel", Level: VisibilityReadOnly, Why: "The organization's own session enrichment: the developer sees what it runs and its evidence level; the settings are the organization's."},
	{ID: "tasks", Level: VisibilityReadOnly, Why: "Task tracking engine: capture configuration."},
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

// ManagedNavDefault returns a nav page's managed default for audience a. An
// id outside the table (a newer server's page this build does not know)
// resolves Visible: a default can only ever be applied to a page this build
// can name.
func ManagedNavDefault(id string, a ManagedAudience) Visibility {
	if r, ok := managedNavIndex[id]; ok {
		return r.LevelFor(a)
	}
	return VisibilityVisible
}

// ManagedSettingsDefault is ManagedNavDefault for Settings sub-sections.
func ManagedSettingsDefault(id string, a ManagedAudience) Visibility {
	if r, ok := managedSettingsIndex[id]; ok {
		return r.LevelFor(a)
	}
	return VisibilityVisible
}

// managedDefaultWhy returns a row's reason for audience a (empty when
// unknown).
func managedDefaultWhy(rows map[string]ManagedDefault, id string, a ManagedAudience) string {
	r, ok := rows[id]
	if !ok {
		return ""
	}
	return r.WhyFor(a)
}

// ManagedRestriction is one page or Settings section a managed machine of
// some audience starts hidden or read-only (the consent screen's list).
type ManagedRestriction struct {
	ID    string     `json:"id"`
	Label string     `json:"label"`
	Level Visibility `json:"level"`
}

// ManagedRestrictions returns, in table order, the nav pages and the Settings
// sections whose managed default for audience a is not Visible, each with its
// display label (SectionLabel). It is GENERATED from the two default tables,
// so the consent screen that lists what becomes managed can never disagree
// with what the machine applies.
func ManagedRestrictions(a ManagedAudience) (nav, settings []ManagedRestriction) {
	return restrictedRows(ManagedNavDefaults, a), restrictedRows(ManagedSettingsDefaults, a)
}

func restrictedRows(rows []ManagedDefault, a ManagedAudience) []ManagedRestriction {
	var out []ManagedRestriction
	for _, r := range rows {
		if lvl := r.LevelFor(a); lvl != VisibilityVisible {
			out = append(out, ManagedRestriction{ID: r.ID, Label: SectionLabel(r.ID), Level: lvl})
		}
	}
	return out
}
