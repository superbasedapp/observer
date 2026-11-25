package settingslink

import (
	"net/url"
	"strings"
)

// Place is a closed id for one place in the local dashboard where a setting
// is changed. A new place is one row in the places table.
type Place string

const (
	// Components is Settings > Components (every optional component's
	// switch). A single component's link comes from Component(id).
	Components Place = "components"
	// TerminalLaunchPolicy is the Fresh-agent launch policy card on the
	// Terminals page's Settings tab ([terminal.launch]: allowed tools,
	// fresh launches, guided install and uninstall).
	TerminalLaunchPolicy Place = "terminal_launch_policy"
	// SessionAttach is Settings > Session attach ([handoff], including
	// allow_dashboard_launch, the in-dashboard terminal's switch).
	SessionAttach Place = "session_attach"
	// OTelExport is Settings > OTel export ([ingest.otel], the node's OTLP
	// receiver).
	OTelExport Place = "otel_export"
	// RemoteAccess is the Remote page (arming remote dashboard access).
	RemoteAccess Place = "remote_access"
	// Account is Settings > Account (organization enrolment).
	Account Place = "account"
	// ProcessCapture is Settings > Process capture ([process], including
	// the Windows ETW feed).
	ProcessCapture Place = "process_capture"
	// TerminalSandbox is the Sandbox isolation card on the Terminals page's
	// Settings tab ([terminal.sandbox], including
	// [terminal.sandbox.setup].allow_elevated).
	TerminalSandbox Place = "terminal_sandbox"
	// TerminalSandboxHosted is the Hosted sandboxes panel inside the Sandbox
	// isolation card on the Terminals page's Settings tab
	// ([terminal.sandbox.hosted], including each provider's template).
	TerminalSandboxHosted Place = "terminal_sandbox_hosted"
	// GuardNetwork is the Network features card on the Security page's MCP
	// tab ([guard.cloud], including reputation lookups).
	GuardNetwork Place = "guard_network"
	// TeamSummaries is Settings > Team AI summaries (the org plane's
	// consent: accept, review new terms, withdraw).
	TeamSummaries Place = "team_summaries"
	// TerminalRemoteSystems is the Remote systems (SSH) card on the
	// Terminals page's Settings tab ([terminal.ssh], including enabled).
	TerminalRemoteSystems Place = "terminal_remote_systems"
	// ConnectedTools is Settings > Connected tools (each AI tool's hooks, MCP and proxy route).
	ConnectedTools Place = "connected_tools"
	// RoutingSettings is Settings > Routing ([routing]: enabled and mode).
	RoutingSettings Place = "routing_settings"
	// GuardSettings is Settings > Guard ([guard]: rules, native dialects, compile on init).
	GuardSettings Place = "guard_settings"
	// ObservabilitySettings is Settings > AI Apps ([observability], including the judge endpoint).
	ObservabilitySettings Place = "observability_settings"
	// IntelligenceSettings is Settings > Intelligence ([projects], including
	// alignment_judge, under More settings).
	IntelligenceSettings Place = "intelligence_settings"
	// SecurityMode is the Mode card on the Security page's Overview tab
	// (the guard's enforcement mode, including off).
	SecurityMode Place = "security_mode"
)

// componentsPath is the Settings > Components page. Its ?component= query
// focuses one row (web/src/pages/Components.tsx).
const componentsPath = "/settings/components"

// row is one place: the in-app path (with its query and anchor) and the
// place's plain name as the dashboard shows it.
type row struct {
	place Place
	href  string
	label string
}

// places is the table. Paths follow the SPA's routing: Settings sections are
// /settings?section=<id> (web/src/pages/Settings.tsx SECTIONS), page tabs
// are ?tab=<id> (web/src/lib/nodePageTabs.ts), and an in-page card is the
// #<element id> the page scrolls to.
var places = []row{
	{Components, componentsPath, "Settings > Components"},
	{TerminalLaunchPolicy, "/terminals?tab=settings#launch-policy", "Terminals > Settings > Fresh-agent launch policy"},
	{SessionAttach, "/settings?section=terminal", "Settings > Session attach"},
	{OTelExport, "/settings?section=otel", "Settings > OTel export"},
	{RemoteAccess, "/remote", "Remote"},
	{Account, "/settings?section=enrolment", "Settings > Account"},
	{ProcessCapture, "/settings?section=process", "Settings > Process capture"},
	{GuardNetwork, "/security?tab=mcp", "Security > MCP > Network features"},
	{TerminalSandbox, "/terminals?tab=settings#sandbox-backends", "Terminals > Settings > Sandbox isolation"},
	{TerminalSandboxHosted, "/terminals?tab=settings#hosted-sandboxes", "Terminals > Settings > Hosted sandboxes"},
	{TeamSummaries, "/settings?section=intel", "Settings > Team AI summaries"},
	{TerminalRemoteSystems, "/terminals?tab=settings#remote-systems", "Terminals > Settings > Remote systems (SSH)"},
	{ConnectedTools, "/settings?section=tools", "Settings > Connected tools"},
	{RoutingSettings, "/settings?section=routing", "Settings > Routing"},
	{GuardSettings, "/settings?section=guard", "Settings > Guard"},
	{ObservabilitySettings, "/settings?section=observability", "Settings > AI Apps"},
	{IntelligenceSettings, "/settings?section=intelligence", "Settings > Intelligence"},
	{SecurityMode, "/security?tab=overview", "Security > Overview > Mode"},
}

// Link is one place in the local dashboard: the in-app path and its name.
type Link struct {
	Href  string
	Label string
}

// For returns the link of a place, or false for an id the table does not
// carry.
func For(p Place) (Link, bool) {
	for _, r := range places {
		if r.place == p {
			return Link{Href: r.href, Label: r.label}, true
		}
	}
	return Link{}, false
}

// Places lists every place id, in table order.
func Places() []Place {
	out := make([]Place, 0, len(places))
	for _, r := range places {
		out = append(out, r.place)
	}
	return out
}

// Component returns the link that opens Settings > Components with one
// component focused. An empty id opens the page itself.
func Component(id string) Link {
	id = strings.TrimSpace(id)
	if id == "" {
		return Link{Href: componentsPath, Label: "Settings > Components"}
	}
	return Link{Href: componentsPath + "?component=" + url.QueryEscape(id), Label: "Settings > Components"}
}

// ComponentCommand is the CLI command that turns one component on: the
// same change Settings > Components makes. Without --yes the verb only
// previews.
func ComponentCommand(id string) string {
	return "observer components add " + strings.TrimSpace(id) + " --yes"
}

// OrgPlace is a closed id for one place in the TEAM dashboard (the org
// server's own dashboard, web2) where an organization's admins change a
// setting this machine cannot change itself. The node never changes it and
// never offers a toggle for it: the link only tells the person who can and
// where.
type OrgPlace string

const (
	// OrgSessionEnrichment is Intelligence > Session enrichment (the org's
	// AI summaries: on or off, its terms, developer actions).
	OrgSessionEnrichment OrgPlace = "org_session_enrichment"
	// OrgDeveloperDashboards is Settings > Developer dashboards: where an
	// organization's admins (on a personal organization, its owner) choose
	// which pages and Settings sections a developer's local dashboard
	// shows, hides or locks.
	OrgDeveloperDashboards OrgPlace = "org_developer_dashboards"
)

// orgPlaces is the team dashboard's table. Paths follow web2's routing
// (web2/src/lib/components.gen.ts routes, ?tab=<id> from
// web2/src/lib/configureTabs.ts, ?section=<id> from
// web2/src/lib/settingsSections.ts).
var orgPlaces = []row{
	{Place(OrgSessionEnrichment), "/intelligence?tab=session-enrichment", "Intelligence > Session enrichment"},
	{Place(OrgDeveloperDashboards), "/settings?section=developer-dashboards", "Settings > Developer dashboards"},
}

// OrgPlaces lists every team-dashboard place id, in table order.
func OrgPlaces() []OrgPlace {
	out := make([]OrgPlace, 0, len(orgPlaces))
	for _, r := range orgPlaces {
		out = append(out, OrgPlace(r.place))
	}
	return out
}

// OrgLink is a place in the team dashboard: its absolute URL when the
// node knows a safe org server address ("" otherwise) and its plain name.
type OrgLink struct {
	Href  string
	Label string
}

// OrgFor returns the team-dashboard link of p on the org server at
// serverURL. The URL is set only for an https address, or http on a
// loopback host, with no credentials in it; otherwise only the name is
// returned (the surface names the place in words). false for an id the
// table does not carry.
func OrgFor(serverURL string, p OrgPlace) (OrgLink, bool) {
	for _, r := range orgPlaces {
		if OrgPlace(r.place) != p {
			continue
		}
		l := OrgLink{Label: r.label}
		if base := OrgDashboardBase(serverURL); base != "" {
			l.Href = base + r.href
		}
		return l, true
	}
	return OrgLink{}, false
}

// OrgDashboardBase is the team dashboard's origin (scheme://host[:port],
// no trailing slash) for an org server address, or "" when the address is
// not one a button may open: https, or http on a loopback host, with no
// credentials.
func OrgDashboardBase(serverURL string) string {
	u, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil || u.Host == "" || u.User != nil {
		return ""
	}
	switch u.Scheme {
	case "https":
	case "http":
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
		default:
			return ""
		}
	default:
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// OrgFields are the JSON fields a body adds when only the organization's
// admins can change the setting: the team-dashboard URL (omitted when the
// node knows no safe address) and the place's plain name. A body with no
// org fix is unchanged.
type OrgFields struct {
	OrgSettings      string `json:"org_settings,omitempty"`
	OrgSettingsLabel string `json:"org_settings_label,omitempty"`
	// OrgDashboardKind is "personal" when the dashboard is the person's own
	// personal dashboard (they are its only admin, so the surface tells
	// them to turn it on rather than to ask anyone), "team" or omitted.
	OrgDashboardKind string `json:"org_dashboard_kind,omitempty"`
}

// Fields returns the org link as body fields.
func (l OrgLink) Fields() OrgFields {
	return OrgFields{OrgSettings: l.Href, OrgSettingsLabel: l.Label}
}

// Fields are the JSON fields an error body adds when its fix is a setting.
// Embed it in the body; every field is omitted when empty, so a body with no
// link is byte-identical to one written before this package existed.
//
//   - settings: the in-app path that opens the place to change it
//   - settings_label: that place's plain name ("Settings > Components")
//   - command: the CLI command that makes the same change, when there is one
type Fields struct {
	Settings      string `json:"settings,omitempty"`
	SettingsLabel string `json:"settings_label,omitempty"`
	Command       string `json:"command,omitempty"`
}

// Fields returns the link as error-body fields.
func (l Link) Fields() Fields {
	return Fields{Settings: l.Href, SettingsLabel: l.Label}
}

// WithCommand returns f with the CLI command set.
func (f Fields) WithCommand(cmd string) Fields {
	f.Command = strings.TrimSpace(cmd)
	return f
}

// Body is the JSON error body of a refusal whose fix is a setting:
// {"error": code, "message": sentence, "settings": path, "settings_label":
// name}. Error keeps whatever the route answered before (a closed code, or
// on older routes the sentence itself), so a client that reads only
// "error" is unchanged.
type Body struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	// Technical is the detail behind Message (config keys, enum values,
	// commands) that a surface may show only under a "Technical details"
	// caption; omitted when empty, so every other body is unchanged.
	Technical string `json:"technical,omitempty"`
	Fields
}

// Needs builds the body for a refusal whose fix is at place p. An unknown
// place yields a body with no link (never a guessed path).
func Needs(code, message string, p Place) Body {
	b := Body{Error: code, Message: message}
	if l, ok := For(p); ok {
		b.Fields = l.Fields()
	}
	return b
}

// NeedsComponent builds the body for a refusal whose fix is turning one
// component on, with the Components link focused on it and the CLI command.
func NeedsComponent(code, message, id string) Body {
	return Body{Error: code, Message: message, Fields: Component(id).Fields().WithCommand(ComponentCommand(id))}
}

// DashboardAddress is where the organization's own dashboard is for an
// enrolment: the online address `observer connect` recorded (a hosted
// organization's own host) when a button may open it, else the org server
// address the node pushes to. It never guesses a host: both inputs are what
// the node already holds.
func DashboardAddress(onlineURL, serverURL string) string {
	if OrgDashboardBase(onlineURL) != "" {
		return onlineURL
	}
	return serverURL
}

// orgPageRow is one local dashboard page's equivalent in the team dashboard:
// the node nav id (web/src/lib/nav.ts), the web2 path, its name as web2's
// nav shows it, and whether any signed-in member may open it (web2's route
// carries no permission guard and its nav item no permission). A page with no
// clear equivalent has no row.
type orgPageRow struct {
	nav     string
	href    string
	label   string
	members bool
}

// orgPages is the table, in the node's nav order. Paths and labels follow
// web2/src/lib/components.gen.ts and web2/src/lib/navGroups.ts;
// TestOrgPagesFollowWeb2 reads both and fails on a path web2 does not route,
// a label its nav does not show, or a members flag its guards contradict.
var orgPages = []orgPageRow{
	{"overview", "/", "Coding agents > Overview", true},
	{"sessions", "/sessions", "Coding agents > Sessions", false},
	{"projects", "/projects", "Coding agents > Projects", true},
	{"security", "/security", "Coding agents > Security", true},
	{"cost", "/cost", "Coding agents > Cost", true},
	{"tools", "/tools", "Coding agents > Tools", true},
	{"routing", "/routing", "Coding agents > Routing", false},
	{"benchmarks", "/benchmarks", "Coding agents > Benchmarks", true},
	{"patterns", "/patterns", "Coding agents > Patterns", false},
	{"app-traces", "/trajectories", "AI apps > Explorer", true},
	{"app-sessions", "/trajectories", "AI apps > Explorer", true},
	{"app-analytics", "/trajectories/analytics", "AI apps > Analytics", false},
	{"app-end-users", "/trajectories/end-users", "AI apps > End-user spend", false},
	{"app-evals", "/trajectories/evals", "AI apps > Eval health", false},
	{"app-prompts", "/trajectories/prompts", "AI apps > Prompts", false},
	{"app-alerts", "/trajectories/alerts", "AI apps > Alerts", false},
	{"policies", "/trajectories/policies", "AI apps > Policies", false},
}

// OrgPageLink is a local page's equivalent in the team dashboard: its
// absolute URL when the node knows a safe address ("" otherwise), its plain
// name, and whether any signed-in member may open it (otherwise only an admin
// whose role includes it).
type OrgPageLink struct {
	Href    string `json:"href,omitempty"`
	Label   string `json:"label"`
	Members bool   `json:"members"`
}

// OrgPageFor returns the team-dashboard equivalent of the local page navID on
// the org server at serverURL, and false for a page with none. The URL follows
// OrgFor's rule: set only for a safe address.
func OrgPageFor(serverURL, navID string) (OrgPageLink, bool) {
	for _, r := range orgPages {
		if r.nav != navID {
			continue
		}
		l := OrgPageLink{Label: r.label, Members: r.members}
		if base := OrgDashboardBase(serverURL); base != "" {
			l.Href = base + r.href
		}
		return l, true
	}
	return OrgPageLink{}, false
}

// OrgPageIDs lists the local pages that have a team-dashboard equivalent, in
// table order.
func OrgPageIDs() []string {
	out := make([]string, 0, len(orgPages))
	for _, r := range orgPages {
		out = append(out, r.nav)
	}
	return out
}
