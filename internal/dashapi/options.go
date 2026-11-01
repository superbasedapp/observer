package dashapi

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/artifactstate"
	"github.com/marmutapp/superbased-observer/internal/captureprogress"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/handoffsvc"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/intelligence/alignment"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/planlimitssvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Options configures a Server.
// ExtraRoute is one (pattern, handler) pair a separable subsystem registers
// into the dashboard's shared mux via Options.ExtraRoutes. The handler is a
// plain http.HandlerFunc so the dashboard carries no dependency on the
// subsystem (decision D4 / the obs reverse-import boundary).
type ExtraRoute struct {
	// Pattern is the mux pattern; it MAY carry a Go 1.22 method prefix
	// ("GET /api/obs/enabled") - that is the "method metadata" the plan §4.1
	// requires alongside the capability.
	Pattern string
	Handler http.HandlerFunc
	// Capability classifies the route for remote exposure (plan §4.1). It MUST
	// be set to a non-Unclassified value when the dashboard runs with a
	// RemoteController - New() rejects an unclassified ExtraRoute in that case
	// (TestExtraRoutesRejectedWithoutCapabilityMetadata). On a loopback-only
	// dashboard (the default) the zero value is tolerated (nothing is exposed).
	Capability Capability
	// Section is the node-dashboard nav section this route belongs to, for
	// the admin-controlled Plane-B governance guard (governance.go). The
	// zero value (SectionNone) means "no single page owns this route", which
	// is never hidden - the same fail-open default an unmapped built-in
	// route gets.
	Section Section
}

type Options struct {
	// DB is the observer database.
	DB *sql.DB
	// DBPath is displayed in the header; not used to open anything.
	DBPath string
	// ProcessArchive serves process capture that has moved to cold storage
	// (corpus archival Bucket B, design §4.3). Nil - the default, and the
	// state whenever [archive].enabled is false - means the process surfaces
	// behave exactly as they did before the arc: hot rows or nothing.
	ProcessArchive ProcessArchiveReader
	// CostEngine prices token summaries. Defaults to baked-in pricing.
	CostEngine *cost.Engine
	// ReadCaches turns on the production read caches (optimization review
	// 2026-09-27, docs/audits/optimization-review-2026-09-27.md):
	//   - N4: the production handler chain (guardedHandler) marks GET
	//     requests with cost.WithRowCache, so the several spend panels a page
	//     load fires at once share one read of the window's api_turns /
	//     token_usage rows (freshness contract in
	//     internal/intelligence/cost/rowcache.go);
	//   - N5: /api/health/watcher is served stale-while-revalidate
	//     (watcher_health_cache.go).
	//   - the allow-listed heavy analytics GET endpoints (/api/discover,
	//     /api/analysis/*, /api/cost, ...) are served from a response-level
	//     stale-while-revalidate cache, cleared by any successful dashboard
	//     mutation (analytics_cache.go).
	// False - the zero value, and every test's - computes every response
	// per request exactly as before.
	ReadCaches bool
	// Predict carries the [predict] tunables (Next-Message Cost & Limit
	// Predictor). Zero value → the handler falls back to built-in
	// defaults, so tests and read-only callers need not set it.
	Predict config.PredictConfig
	// Scoring carries [intelligence.scoring] so the session Quality card can
	// say whether (and after how long idle) the daemon scores a session on
	// its own. Zero value reads as "auto-scoring off", which only changes
	// the card's empty-state copy.
	Scoring config.IntelligenceScoringConfig
	// LocEditorToken is the per-install shared secret POST
	// /api/loc/editor-change verifies X-Observer-Token against. The
	// daemon resolves it in cmd (generate-on-first-start into
	// [loc].editor_token_file, or the deprecated
	// OBSERVER_LOC_EDITOR_TOKEN override) and hands the VALUE here - this
	// package never reads the file, so a test needs no filesystem.
	//
	// Empty means "no configured token", which leaves the endpoint on the
	// loopback + Origin posture it shipped with. Deliberately NOT read
	// back out anywhere: nothing in the dashboard renders it.
	LocEditorToken string
	// LocEditorTokenRequired is [loc].editor_token_required: refuse a
	// POST /api/loc/editor-change that carries no token. Default false -
	// an extension older than the token file sends none. A request that
	// DOES carry a token is verified either way (locEditorAuth).
	LocEditorTokenRequired bool
	// CacheWarm carries the [cachewarm] tunables (cache-expiry warning +
	// smart keep-warm). Zero value disables the cache-status surface
	// (Enabled=false), so tests and read-only callers need not set it.
	CacheWarm config.CacheWarmConfig
	// Tasks carries the [tasks] tunables (session-level task/todo/plan
	// checklist tracking, docs/task-tracking.md). Consumed by
	// taskflowOptions() (taskreport.go) to build the taskflow.Options
	// every LoadSessionTaskReport/LoadTaskRollup call needs - an
	// EXPLICIT argument, not read off a fresh store.New(db)'s
	// Store.TasksOptions(), which would silently return the zero value
	// here (that store instance never had SetTasksOptions called on
	// it). Zero value → match_mode/concurrent_attribution/
	// include_sidechains all read as "" / "" / false, the same
	// unconfigured behavior taskflow.Attributor's own zero value
	// already documents, so tests and read-only callers need not set
	// it.
	Tasks config.TasksConfig
	// Dashboard carries the [dashboard] tunables that the SERVER reads
	// (Addr is resolved in cmd, not here). Today that is
	// OrgAnnouncements, the node operator's opt-out for rail R3 of the
	// announcements plan. Zero value ⇒ the org rail is off, so a caller
	// that never sets it (tests, embedders) serves the release rail
	// only - the same degrade a solo install already gets.
	Dashboard config.DashboardConfig
	// Logger receives operational messages.
	Logger *slog.Logger
	// ExtraRoutes are additional (pattern, handler) pairs a separable
	// subsystem registers into the dashboard mux at the wiring point -
	// e.g. internal/obs's /api/obs/* trajectory endpoints. Generic
	// http.HandlerFunc only; this package never learns the subsystem's
	// types (decision D4). Empty/nil by default.
	ExtraRoutes []ExtraRoute
	// Governance is the admin-controlled Plane-B posture provider
	// (governance.go). NIL on every solo node and every ungoverned build,
	// in which case the governance route guard is not installed at all and
	// GET /api/governance answers with the dormant posture. Non-nil only
	// when cmd/observer wired a node.governance install seam.
	Governance GovernanceProvider
	// FeatureGate, when non-nil, answers "may this node use <feature>
	// right now" for the org-parity W5.1 node.features policy family
	// (docs/plans/org-parity-full-depth-plan-2026-08-24.md §4). feature
	// is one of the internal/policyfam/nodefeatures.Feature* constants
	// (this package never imports policyfam - the same module-boundary
	// discipline as Governance/RecognizesSessionFile: cmd/observer
	// resolves the accepted policy_resource into a plain closure).
	// Called at each of the four gated seams (terminal launch, remote
	// arm/pair, routing-apply, patterns-write) immediately before the
	// action would take effect. Returns (allowed, reason) - reason is
	// only meaningful when allowed is false, and is the exact string to
	// surface to the caller. NIL on every solo node and every node with
	// no accepted node.features policy - every seam fails OPEN in that
	// case, matching Governance's nil-safe convention.
	FeatureGate func(feature string) (bool, string)
	// TerminalFeatureGate is FeatureGate's terminals-specific sibling: the
	// terminals stanza of node.features additionally carries
	// sandbox_required, which depends on what the CALLER is requesting
	// (the launch body's own Sandbox flag) - a piece of request state
	// FeatureGate's single-string signature has no room for. requestedSandbox
	// is the launch request's own sandbox flag. NIL has the same fail-open
	// meaning as FeatureGate being nil.
	TerminalFeatureGate func(requestedSandbox bool) (bool, string)
	// MonthlyBudgetUSD surfaces on the Analysis tab as a spend-budget
	// progress tile. Zero hides the budget readout. Sourced from
	// `intelligence.monthly_budget_usd` in config.toml.
	MonthlyBudgetUSD float64
	// ConfigPath is the resolved path to config.toml - required by the
	// Settings page's GET /api/config + PUT /api/config/pricing
	// endpoints. Empty disables the Settings save path (read-only).
	ConfigPath string
	// RecognizesSessionFile, when non-nil, filters parse_cursors rows
	// in /api/health/watcher: paths NOT recognised by any current
	// adapter are tagged orphan_unmatched and excluded from the
	// "behind" count. Without this, parse_cursors entries from older
	// adapter versions (whose IsSessionFile criteria have since
	// tightened) show in the banner forever - the recovery flow
	// (Rescan / Run All) only re-walks paths a current adapter
	// matches, so it can never close those rows.
	RecognizesSessionFile func(path string) bool
	// CursorSemanticsFor, when non-nil, tells /api/health/watcher what
	// a parse_cursors row's saved cursor MEANS for that path - a byte
	// offset into an append-only log, an opaque SQLite watermark, an
	// undecodable encrypted store, or a file that yields tokens but
	// never actions. Wired alongside RecognizesSessionFile from the
	// adapter registry, and resolved to plain capability flags at that
	// boundary so this package never learns adapter types or branches
	// on tool names.
	//
	// Without it every row is treated as a byte-offset tail (the
	// pre-capability behaviour), which reports SQLite-backed adapters
	// as permanently behind AND permanently misrouted - a banner the
	// recovery flow can never close.
	CursorSemanticsFor func(path string) CursorSemantics
	// WatcherRunning reports whether this process runs the file watcher
	// (`observer start` does; a standalone `observer dashboard` does not).
	// Surfaced as /api/health/watcher's watcher_running so the sidebar's
	// "watcher" line describes the watcher itself rather than the Claude
	// Code proxy-route setup status (T-585). False is the honest zero
	// value for an embedder that does not say.
	WatcherRunning bool
	// CaptureProgress, when non-nil, reads the watcher's history-capture
	// progress model (internal/captureprogress, T-922): what the initial
	// scan and every hot-added root walk found and read. The first-run view
	// (/api/firstrun) reports it; the dashboard never re-scans to answer.
	// Nil (a standalone `observer dashboard`) reports the watcher as not
	// running in this process.
	CaptureProgress func() captureprogress.Snapshot
	// InstallSignalTools, when non-nil, lists the registry tools whose
	// install signals hold on this machine (a VS Code-family editor
	// extension, a resolved binary; cmd/observer installsignal.go). The
	// Claude Code setup snapshot reads it so a VS Code-extension-only
	// Claude Code is not reported as absent (WINNODE2 16b). Nil reports
	// none.
	InstallSignalTools func() []string
	// ProxyPort is the resolved observer-proxy port (cfg.Proxy.Port).
	// Used by /api/setup/codex to compute the desired
	// ~/.codex/config.toml base_url. Zero falls back to 8820.
	ProxyPort int
	// ProxyClientToken is the proxy client token the Setup route writers
	// write the token form with (OSH-R-009; RegisterOptions.ClientToken).
	// "" writes the plain form. Never returned by an API.
	ProxyClientToken string
	// ArenaAdmission runs immediately before each Agent Arena candidate or
	// judge process starts. Nil preserves the standalone Arena engine's
	// unconfigured behavior. cmd owns the concrete budget-policy check.
	ArenaAdmission func(context.Context, string, string) error
	// ArenaPermissionBypass answers, per Agent Arena drive, whether the
	// harness may run with its own permission checks skipped and, when not,
	// why (OSH-R-005). Nil answers no: the runner then drives every harness
	// in a mode that keeps its checks on, or refuses it. cmd composes the
	// operator's config with a managed node's org policy.
	ArenaPermissionBypass func(ctx context.Context, tool string) (allowed bool, why string)
	// ArenaPreflight checks one Agent Arena tool (a candidate's or the
	// judge's) against every launch gate in the run's project root BEFORE
	// the run makes its worktrees (ruling P-203): (ctx, tool, projectRoot).
	// A refusal names the setting. Nil skips the check.
	ArenaPreflight func(ctx context.Context, tool, projectRoot string) error
	// StashDir is the proxy-side SROD (Stash & Retrieve on Demand) stash
	// directory (cfg.Compression.Conversation.Stash.Dir). When set, the
	// /api/compression/retrieval surface reads short content snippets of
	// what was stashed so the panel shows readable previews instead of
	// opaque SHAs. Empty disables snippets (the panel degrades to counts).
	StashDir string
	// GuardEnabled / GuardMode / GuardStrict surface the [guard]
	// posture on the Security page header (guard spec §11.2).
	// Display-only - the dashboard never constructs a guard.
	GuardEnabled bool
	GuardMode    string
	GuardStrict  bool
	// GuardHookFailure answers what a failing gate hook does on this node,
	// per gate family (T-346): the same derivation `observer hook` applies
	// (the daemon's signed posture, else D-194's config + bundle fallback).
	// Nil = not wired; the Security page then does not claim a mode.
	GuardHookFailure func() GuardHookFailure
	// GuardToolGates answers, per hook_block tool, whether its tool-gate
	// hook is registered and current on THIS node and the channel the tool
	// falls back to when not: the same node state the enforce-mode launch
	// decision uses. Nil = not wired; the Security page then shows nothing.
	GuardToolGates func() []GuardToolGate
	// OrgClient backs the /api/enrolment/* endpoints (Teams). It is non-nil
	// only when [org_client] is enabled; when nil those endpoints report
	// not-enrolled and the web UI hides the org surface - preserving the
	// byte-identical solo-local experience.
	OrgClient EnrolmentService
	// EnrolManager serves Settings > Enrolment management (enrol, consent,
	// status, grant report, push-now, leave) through the same code paths as
	// the `observer enroll` / `observer org` / `observer unenroll` commands.
	// Unlike OrgClient it is wired whether or not the node is enrolled (that is
	// the point: a node must be able to enrol from here). Nil = not wired; the
	// management routes answer 501.
	EnrolManager EnrolmentManager
	// Components serves Settings > Components and the route guard (modular
	// packaging P1, lane MP-DASH, components_manage.go): the node's component
	// state, the preview / apply of a new selection, teardown and purge,
	// through the one writer internal/componentsvc that `observer components`
	// also uses. Nil = not wired: no route is gated (every route answers as
	// before) and the management routes answer 503.
	Components ComponentsService
	// ComponentArtifacts observes the separately installed artifacts
	// (browser and VS Code extensions, plugin shims, helpers; lane MP-ART)
	// for GET /api/components (artifact_states, T-707): the same rule
	// tables `observer components artifacts` prints. Nil = not wired: the
	// report carries no artifact_states.
	ComponentArtifacts func(context.Context) []artifactstate.Status
	// BinaryInstall reports how the running observer binary was installed
	// (U12, lane FIX-UPGRADE): GET /api/components carries it as
	// binary_install. The catalog's own "binary" field is the product class
	// ("node" for the observer binary, "org" for the org server), not a path.
	// Nil = not wired: the field is omitted.
	BinaryInstall func() BinaryInstall
	// Requests backs the Requests page (/api/requests*, request-grants
	// design G6): asking the org for a budget increase, a guard exemption,
	// a tool, a model or a feature, and following the answer. Nil on a solo
	// node; the page then says requests go to an organization.
	Requests RequestService
	// Messages backs the Messages page's acts that reach the org
	// (/api/messages*, admin and developer messaging, T-854): reply, ask
	// my admin, read and acknowledge receipts. Nil on a solo node; the page
	// then reports not_enrolled.
	Messages MessageService
	// Version is the running binary's version string (e.g. "1.8.2").
	// Stamped at build time via -ldflags="-X main.version=…" and
	// surfaced on /api/status so the dashboard can compare it against
	// the latest published release. "dev" is treated as "no compare".
	Version string
	// OnConfigSaved, when non-nil, fires after every successful
	// config.toml write (section PUT, pricing PUT, backup restore).
	// The daemon wires it to consumers that can re-read config at
	// runtime - P2.5: the proxy's compression profile router, so
	// profile/assignment edits apply to NEW sessions without a
	// restart. Called synchronously after the write lands and before
	// the HTTP response; implementations must be quick and never
	// panic (mirror the CostEngine.Reload hot-path contract).
	OnConfigSaved func()
	// ToolCatalog lists every supported adapter (stable tool name +
	// canonical watch paths) for the Connected-tools panel (P4.1).
	// Injected by cmd - the same seam pattern as
	// RecognizesSessionFile, keeping adapter packages out of the
	// dashboard's import graph. Empty = the panel reports only tools
	// with DB activity.
	ToolCatalog []ToolCatalogEntry
	// ToolDoctor, when non-nil, builds the `observer doctor <tool>` report
	// for one tool (T-421 item 3): cmd/observer's buildDoctorReport, the
	// one assembly the CLI also prints, so the Connected tools "Run checks"
	// and the terminal cannot drift. Injected for the same reason as
	// ToolCatalog (the per-adapter checks need packages the dashboard must
	// not import). nil = the route answers 501 with the CLI command.
	ToolDoctor func(ctx context.Context, cfg config.Config, database *sql.DB, tool string) (diag.Report, error)
	// HookRegistryOptions, when non-nil, returns the hook.Options the
	// daemon's own hook auto-registration writes with (binary, resolved
	// --config, WSL distro, the owes-live event filter). The Connected
	// tools hooks probe dry-runs through them, so the command it expects
	// is the one `observer start` wrote: the registrars match an existing
	// entry by its exact command, and a probe built without --config read
	// every daemon-registered hook as "would register" (T-376). The probe
	// forces DryRun regardless of what this returns. Nil falls back to
	// this binary plus ConfigPath.
	HookRegistryOptions func() (hook.Options, error)
	// BuildHandoff, when non-nil, runs one session-handoff request through
	// internal/handoffsvc (docs/session-handoff.md). Injected by cmd - the
	// same seam pattern as ToolCatalog, keeping the concrete adapter set
	// out of the dashboard's import graph. Nil disables the
	// /api/session/<id>/handoff endpoints (503 with an honest message).
	BuildHandoff func(ctx context.Context, req handoffsvc.Request) (handoffsvc.Result, error)
	// DemoSeeder, when non-nil, enables demo mode (P6.7): it builds a
	// TEMPORARY database seeded from embedded synthetic fixtures and
	// returns the open handle plus a cleanup that closes it and
	// removes its directory. Injected by cmd (the same seam pattern as
	// ToolCatalog - the dashboard never imports the demo or adapter
	// packages). Nil keeps the /api/demo endpoints honest about
	// unavailability. The real observer.db is never read or written on
	// any demo path.
	DemoSeeder func(ctx context.Context) (*sql.DB, func() error, error)
	// RoutingDemotions, when non-nil, returns the live router's §R18.3
	// calibration demotion set (rule name → reason) - in-memory state
	// only the daemon process hosting the router can answer for
	// (R2.4). Injected by `observer start` from the wired router; nil
	// in a standalone `observer dashboard` process, when routing is
	// disabled, and in tests - /api/routing/status reports
	// demotions_live=false so the UI never confuses "can't see" with
	// "none demoted".
	RoutingDemotions func() map[string]string
	// LaunchManager, when non-nil, backs the embedded web-terminal launch
	// surface (POST /api/session/<id>/launch + GET /ws/launch/<handle>).
	// Injected by cmd only when [handoff].allow_dashboard_launch is true;
	// nil makes the endpoints 503 and hides the "Launch <tool> here" action
	// (a nil seam IS the disabled state - no separate flag needed). The seam
	// pattern mirrors BuildHandoff: the dashboard never imports
	// internal/termsession.
	LaunchManager LaunchManager
	// TerminalStatus, when non-nil, backs the F4 agent-status surface
	// (GET /api/terminal/<handle>/status + GET /ws/terminal/status). Nil is the
	// honest disabled state (503 / the WS closes).
	TerminalStatus TerminalStatusProvider
	// PolicyStop, when non-nil, resolves a durable explanation for a terminal
	// run the daemon's OWN node-intervention loop stopped - an org-managed
	// node's process-control policy killing a vendor process the operator
	// launched via "New Terminal" (docs/plans/... managed-node process
	// control). It is surfaced additively on the exit event and the status
	// payload; nil simply omits policy_stop everywhere (the honest "no
	// managed-node intervention wired" state, e.g. an unmanaged node).
	PolicyStop PolicyStopProvider
	// ToolPreflight, when non-nil, resolves a launchable tool NAME to its
	// binary-resolution verdict for GET /api/terminal/launch/preflight
	// (tool-binary-resolution arc). It is the dashboard's seam onto
	// internal/toolresolve - DEFINED as a plain func here so the dashboard
	// package carries no dependency on toolresolve's types (CLAUDE.md #2). A nil
	// seam is the honest disabled state (the endpoint reports 501); a returned
	// ok=false means the tool is unknown / not launchable (400). cmd wires a
	// closure that runs the resolver and fills the ToolPreflight wire shape.
	ToolPreflight func(tool string) (ToolPreflight, bool)
	// ShellWrap, when non-nil, serves the Settings -> Terminal "Command
	// wrapping" card (GET /api/shell-wrap/status, POST /api/shell-wrap/apply
	// and /disable). Nil is the honest not-wired state (501).
	ShellWrap ShellWrapService
	// WindowsHomes, when non-nil, serves the Connected tools Windows-home
	// control (GET /api/setup/windows-homes, POST /api/setup/windows-homes/
	// apply, T-421 item 4). Nil is the honest not-wired state (501).
	WindowsHomes WindowsHomeService
	// Reprice, when non-nil, serves the Settings "Re-price stored costs"
	// card (GET /api/reprice/status, POST /api/reprice/plan, /apply and
	// /revert; gap PRICE-REPRICE-1). Nil is the honest not-wired state (501).
	Reprice RepriceService
	// AllowToolInstall, when non-nil, reports whether the guided install
	// endpoint (POST /api/terminal/install) is enabled - a LIVE read of the
	// [terminal.launch].allow_install kill-switch (default true). Nil is treated
	// as DISABLED (403), so the install affordance stays off until cmd wires the
	// live-config reader.
	AllowToolInstall func() bool
	// ToolInstallHint, when non-nil, resolves a tool NAME to the server-side
	// install argv + human display string for POST /api/terminal/install. The
	// argv is a COMPILE-TIME registry constant (never request input - injection
	// surface is zero by construction); the tool name is only a registry map
	// key. Nil-able; a miss (ok=false) means no grounded install command → 400.
	ToolInstallHint func(tool string) (argv []string, display string, ok bool)
	// ToolInstallBlocked, when non-nil, returns the plain-language remedy for
	// a guided install whose grounded host prerequisites are missing (e.g.
	// "The installer needs unzip ... sudo apt-get install -y unzip"), or ""
	// when the install may run. A non-empty answer makes POST
	// /api/terminal/install refuse with 409 before anything is spawned.
	ToolInstallBlocked func(tool string) string
	// ToolInstalls, when non-nil, is the node's record of guided installs
	// this dashboard ran (agent migration 149) and the matching uninstall:
	// POST /api/terminal/install records into it, GET /api/terminal/installs
	// lists it, POST /api/terminal/uninstall and /api/terminal/installs/forget
	// act on it, and the preflight reply carries the tool's record. Nil is the
	// honest not-wired state (no record, uninstall 501).
	ToolInstalls ToolInstallLedger
	// RecentModels, when non-nil, resolves a tool NAME to its recently-used
	// models for the New Terminal model picker (B5) - the dashboard's seam
	// onto store.Store.LoadRecentModelsForTool, defined as a plain func
	// (like ToolPreflight) so the dashboard's Options struct carries no
	// hard dependency on a live *store.Store (CLAUDE.md #2; the return type
	// store.RecentToolModel is a plain data struct, not the store itself).
	// A nil seam is the honest disabled state: both
	// GET /api/terminal/launch/models and handleTerminalLaunch's model
	// membership check degrade to "unsupported" exactly like an older
	// daemon build without the store wiring - see modelSuggestionsFor.
	RecentModels func(ctx context.Context, tool string) ([]store.RecentToolModel, error)
	// ProjectRootResolver, when non-nil, backs the per-terminal project panel
	// (GET /api/terminal/project/<token>...). It resolves a live launch token
	// (LaunchInfo.ID / PTY handle) to the canonical directory the run was
	// launched into PLUS that directory's provenance (TerminalRoot), from
	// server-retained state only - the browser never sends a filesystem root.
	//
	// It returns known=false for an unknown OR exited token (→404 unknown_token)
	// and (Path="", known=true) for a live run with no local directory to browse
	// (→409 no_project_root). A default-cwd launch resolves to the run's own
	// working directory with Authorized=false rather than to an empty path
	// (operator ruling 2026-08-28): the launch allow-list governs which roots a
	// client may REQUEST, not which directory an owner-local terminal may browse.
	//
	// Injected by cmd from termsvc.Service; nil (the default) makes the panel
	// endpoints 404 (a nil seam IS the disabled state), keeping the solo-local
	// experience unchanged.
	ProjectRootResolver func(token string) (root TerminalRoot, known bool)
	// SessionResolver, when non-nil, backs the per-terminal session cockpit
	// (GET /api/terminal/session/<token>). It resolves a live launch token to
	// its run identity (run id + kind + tool) and - once the daemon has
	// correlated the run to an observer session - that session id and the
	// confidence the link was scored at. It returns known=false for an unknown
	// OR exited token (→404 unknown_token); a live-but-uncorrelated run returns
	// known=true with an empty SessionID and zero Confidence. Injected by cmd
	// from termsvc.Service (via a function field so the dashboard package never
	// imports termsvc - module discipline); nil (the default) makes the
	// endpoint 404 (a nil seam IS the disabled state), keeping the solo-local
	// experience unchanged.
	SessionResolver func(token string) (link TerminalSessionLink, known bool)
	// RestartFunc, when non-nil, restarts the daemon from the dashboard
	// (POST /api/admin/restart): it preflights the config and triggers the
	// daemon's graceful shutdown + self re-exec (cmd owns the process
	// lifecycle; see cmd/observer/reexec.go). A non-nil error is a REFUSAL
	// (e.g. config wouldn't come back) - the daemon keeps running. Nil means
	// this process mode can't self-restart (the handler reports 501).
	RestartFunc func() error
	// RestartPreflight, when non-nil, runs the refusal checks RestartFunc
	// runs (re-exec support, the config preflight) and schedules nothing.
	// The restart route runs it before it ends live sandboxed runs for an
	// "end and restart" answer, so a restart that would refuse never ends a
	// run first; an error wrapping ErrRestartUnsupported is answered 501
	// (SBX-UPD audit finding 1).
	RestartPreflight func() error
	// LiveSandboxRuns, when non-nil, makes the restart route ask before it
	// ends a live sandboxed run (livesandbox.go, SBX-UPD-1). Nil keeps the
	// route exactly as it was.
	LiveSandboxRuns LiveSandboxRuns
	// UpdateApplyFunc, when non-nil, runs an in-place binary update in the
	// DAEMON process (POST /api/update/apply) - the enterprise-update
	// management plan's §3.7 sequence.
	//
	// It is a function seam for the same reason RestartFunc is: cmd owns the
	// process lifecycle, and the drain + fork-exec-and-watch handshake are
	// only meaningful in the process that holds the listeners. The dashboard
	// package contributes a route and an authorization decision, nothing
	// else. Nil (the default) makes the endpoint 501, which is the honest
	// answer for a process mode that cannot replace its own binary.
	//
	// The route is CapabilityLocal: replacing the daemon's executable is the
	// most privileged thing this surface can be asked to do, and it must be
	// refused on any remotely-exposed bind before a principal is even
	// resolved.
	UpdateApplyFunc func(ctx context.Context, req UpdateApplyRequest) (UpdateApplyResult, error)
	// UpdateStatusFunc, when non-nil, composes the node's own update posture
	// for GET /api/update/status (W5: the Settings -> Health card and the
	// update banner). Nil returns the honest "feature off" zero value rather
	// than a 404.
	//
	// It is a READ and introduces no outbound request: everything it reports
	// was already written to this daemon by the push cycle and the apply path.
	UpdateStatusFunc func(ctx context.Context) (UpdateStatusResult, error)
	// UpdateExtensionVersionFunc, when non-nil, receives the VS Code
	// extension's own version on POST /api/update/extension-version, so the
	// org board can show editor/daemon skew (ruling R6). Nil makes the route
	// answer 501.
	//
	// It takes a plain string and returns nothing: the daemon's job is to
	// remember what the extension said, and a report that cannot be stored is
	// not worth failing an editor's activation over.
	UpdateExtensionVersionFunc func(version string)
	// MCPAccessStatus, when non-nil, backs GET /api/mcp-access/status (Agent
	// Access P10, mcpaccess.go): the node MCP relay's status, approved
	// servers, coverage matrix, effective state and org connect target, as
	// composed by cmd/observer from the SAME derivation `observer mcp status`
	// prints. A plain func returning a JSON-encodable value, so this package
	// never imports the relay. verifyChain asks it to walk the relay's
	// decision-record chain. Nil answers the honest "not available in this
	// process" body, never a 404.
	MCPAccessStatus func(ctx context.Context, verifyChain bool) (any, error)
	// Remote is the injected remote-access security substrate (plan §4).
	// Nil (the default) means loopback-only: a non-loopback bind is REFUSED
	// (§4.6 atomic-safety rule). A non-nil controller reporting Ready()
	// unlocks a remotely-exposed bind and supplies the Host allow-list,
	// per-request principal resolution, and its own /api/remote/* routes.
	// The local single-user experience is byte-identical when this is nil.
	Remote RemoteController
	// RemoteAudit, when non-nil, receives one metadata-only record per
	// remote-access decision (plan §4.8). cmd wires it to the node-local
	// remote_audit store seam; nil (the default) disables auditing. Never
	// carries a secret.
	RemoteAudit func(RemoteAuditRecord)
	// SandboxProber, when non-nil, backs the B9 sandboxed-terminal probe
	// surface: GET /api/terminal/sandbox (fail-soft, always 200 - see
	// handleTerminalSandbox) AND handleTerminalLaunch's fail-CLOSED
	// sandbox validation (a requested sandbox=true with a nil seam refuses
	// the launch with 501, never a silent unsandboxed fallback - B9 plan
	// §12 amendment A5). Injected by cmd (U5) from the daemon's real bwrap
	// probe; nil (the default) is the honest disabled state, matching the
	// LaunchManager/BuildHandoff seam pattern (CLAUDE.md #2).
	SandboxProber SandboxProber
	// SandboxInstallVersions, when non-nil, backs GET
	// /api/terminal/sandbox/install-versions (lane LEFT-SBX): the published
	// versions of one install-source tool for the Container sandboxes card's
	// version picker, read from that source's own registry hosts only when
	// the user asks. nil (the default, and every build without the
	// container driver) answers 501.
	SandboxInstallVersions func(ctx context.Context, tool string) ([]string, error)
	// SandboxSignInForbidden, when non-nil, reports whether the
	// organization's sandbox managed policy, composed onto the local
	// config as the next launch composes it, forbids sign-in seeding (lane
	// BOXSIGNIN, audit finding 3): GET /api/terminal/sandbox/config shows it
	// on the Settings card. nil (the default, and every build without the
	// sandbox) reads as not forbidden.
	SandboxSignInForbidden func() bool
	// ProjectPolicy, when non-nil, backs GET /api/terminal/project-policy
	// (lane sec-p2b): the New Terminal dialog's "project policy" line for a
	// chosen directory, read from the daemon's project match record and the
	// org-signed mapping with file reads only. nil (the default) answers
	// shown=false, the honest state of a node with no project delivery.
	ProjectPolicy func(dir string) ProjectPolicyLine
	// RefreshWatchRoots, when non-nil, is invoked fail-open after a guided
	// tool install (POST /api/terminal/install) and after a successful New
	// Terminal launch (POST /api/terminal/launch). It asks the daemon's
	// watcher to re-detect adapters, hot-add newly-existing session
	// directories into the live fsnotify set, and Scan - closing the
	// "install Muse/Prime from New Terminal then launch → session not
	// captured" gap. cmd wires a short retry schedule because the sessions
	// directory often appears a moment AFTER launch returns (the tool
	// creates it on first write). Nil (the default) is the honest disabled
	// state for `observer dashboard` without a co-located watcher.
	RefreshWatchRoots func()
	// CloudAccount is the Cloud Intelligence ACCOUNT seam (cloud_account.go):
	// the local sign-in probe + the `observer cloud <verb>` subprocess runner
	// cmd/observer injects, so this package never links the cloud network or
	// credential lane. Nil (the default) omits `sign_in` from /api/cloud/status
	// and makes the Sign in / Sign out routes answer 503 with honest copy.
	CloudAccount *CloudAccountSeams
	// OrgIntel is the ORG-PLANE Cloud Intelligence seam (orgintel_consent.go):
	// the cmd-side status / accept / withdraw functions `observer intel`
	// also runs. Nil makes /api/intel/* answer 501.
	OrgIntel OrgIntelManager
	// CustomScanners is the custom scanner service of component
	// security.scan.custom (a *seccustomsvc.Service), nil when the component
	// is inactive or compiled out. Typed as any so this package never links
	// the custom scanner packages; the dashboard's build-tagged route file
	// asserts its own interface.
	CustomScanners any
	// Plans is the Plans & limits service (internal/planlimitssvc): the
	// page model, account lifecycle, refresh and the status line feed. Nil
	// makes every /api/plans route answer 503.
	Plans *planlimitssvc.Service
	// Projects carries the [projects] tunables (Projects-page spend/ROI/
	// commit-alignment arc, docs/plans/projects-page-roi-and-commit-
	// alignment-plan-2026-09-21.md). Consumed for CommitLinkWindowDays
	// (internal/projectroi.Link's window - falls back to
	// projectroi.DefaultLinkWindow when unset/zero, so tests and
	// read-only callers need not set it).
	Projects config.ProjectsConfig
	// JudgeGrade runs one prompt-to-commit alignment through the §3.6 "J"
	// tier (the [projects].alignment_judge-configured LLM judge), bound
	// in cmd/observer/projects_wire.go over alignmentJudgeFor (W5a). Nil
	// means the tier is unavailable (disabled config, no model
	// configured, or a no_obs build) - JudgeGradeReason then carries the
	// honest reason a grade-endpoint response echoes verbatim. The
	// returned string is the model that produced the grade.
	JudgeGrade func(ctx context.Context, in alignment.Input) (alignment.Result, string, error)
	// JudgeGradeReason explains why JudgeGrade is nil. Empty when
	// JudgeGrade is non-nil.
	JudgeGradeReason string
	// CloudGradeAvailability reports whether the Cloud Intelligence
	// commit-alignment grading job (§3.6 tier C) is available right now,
	// and the honest reason when it is not - wired from
	// cmd/observer/cloud_gradecommit.go's CommitAlignmentAvailability,
	// the SAME function `observer cloud grade-commit` itself calls, so
	// the dashboard and the CLI never disagree about why grading is
	// unavailable. Nil is treated as "never available" (a standalone
	// `observer dashboard` process or a test).
	CloudGradeAvailability func() (bool, string)
	// CommitRescan scans one project's git history now (the Projects
	// page's "Rescan now", POST /api/project/{id}/commit-scan), through the
	// daemon's own commit scanner so it never overlaps a tick. Wired from
	// cmd/observer/commitscan_wire.go's commitRescanFunc, the same
	// exec/parse/store pipeline as the daemon loop and `observer backfill
	// --commits`. Nil (a test, or commit scanning off) hides the action.
	CommitRescan func(ctx context.Context, projectID int64) error
	// PackageChecks is the install gate's seam for the Code security
	// page's Package checks card (component security.deps): its status and
	// the dashboard accept of the online checks' disclosure. Nil answers
	// 404 on /api/security/deps.
	PackageChecks *PackageChecks
	// ScannerDB is the dependency scanners' OSV database download seam
	// (operator ruling PT-19 (2)): its state for the Scanners card and the
	// dashboard's one-time accept. Nil answers 404 on
	// /api/security/scanners/db.
	ScannerDB *ScannerDB
	// SARIFImport is the SARIF upload's seam (component
	// security.scan.sarif-import, lane SEC-P4): the producer picker, the
	// file cap and the import. Nil answers 404 on
	// /api/security/import-sarif.
	SARIFImport *SARIFImport
	// Opengrep is the code rules' seam (component security.scan.opengrep,
	// lane SEC-G2): the Code rules card's state and the guided install.
	// Nil answers 404 on /api/security/code/install.
	Opengrep *Opengrep
	// IaC is the IaC engines' seam (security.scan.trivy, security.scan.kics,
	// lane GATES-SEC): their Scanners card rows and the guided install. Nil
	// answers 404 on /api/security/iac/install.
	IaC *IaC
	// Provenance is the AI change records card's seam (component
	// security.provenance, lane sec-f2a); nil when the security module is
	// compiled out.
	Provenance *Provenance
	// SecuritySelected is the daemon's one opt-in rule for a security
	// child (cmd/observer/security_optin.go securitySelected): the module
	// active, and for an opt-in child also named by a [components] block.
	// Nil reads every opt-in child as not selected (fail closed).
	SecuritySelected func(snap componentstate.Snapshot, id string) bool
	// ComponentStateView is the daemon's component view with the optional
	// modules' own rules applied (cmd/observer/components_gate.go
	// componentStateView: a module root its own rule switched off, such as
	// `remove = ["terminals.sandbox"]` (plans decision log P-057), and the
	// opt-in drivers read as not active), the same view `observer
	// components status` prints. Nil serves core's snap.View(), which
	// knows no module rule.
	ComponentStateView func(snap componentstate.Snapshot) componentstate.View
	// RepoTrustOwn is the launch row's Observer-entry test for a trust
	// check root (cmd/observer/launch_trust_own.go repoTrustDashboardOwn):
	// nil for a root that is not the developer's home directory, else a
	// test over a reason's code, file, key and content that reports
	// Observer's own registered entries, which the New Terminal chip then
	// leaves out exactly as the launch does. A nil RepoTrustOwn marks
	// nothing.
	RepoTrustOwn func(root string) func(code, file, key, content string) bool
	// RepoTrustPaths is the launch row's trust path table and devcontainer
	// parser (cmd/observer/trust_conditions.go repoTrustDashboardPaths, the
	// one seam every trust surface reads): the conditional rows that hold on
	// this node, N2's initializeCommand row included, so the trust review
	// lists, and accepts, exactly what a launch decides on. Nil, or a nil
	// table, reads the default table.
	RepoTrustPaths func() ([]agentconfig.TrustPath, func(data []byte) ([]string, map[string]string, error))

	// SecurityExplain is the Code security Findings tab's Explain action
	// (component security.feedback, lane sec-h): the configured judge's
	// advisory explanation of one finding. Nil answers 404.
	SecurityExplain SecurityExplain
	// SecurityOrgShare feeds the affected-worker notice (security plan
	// 7.12, lane SEC-E3): what this node shares with its organization about
	// code security. Nil hides the notice.
	SecurityOrgShare SecurityOrgShareFunc
	// Delivery carries the [delivery] tunables (commit to PR to merge,
	// D-689): whether local landing detection runs, the provider cadence
	// the Code hosts card states, the mirror disk cap and whether "likely
	// landed" counts. The zero value reads as "local detection off".
	Delivery config.DeliveryConfig
	// DeliveryService is the delivery service seam (connect, test and
	// disconnect a code host, delete a mirror, check a project now),
	// wired from cmd/observer/delivery_wire.go over internal/deliverysvc.
	// Nil makes those write routes answer 503; every delivery read still
	// works from the local database.
	DeliveryService DeliveryService
}

// TerminalSessionLink is the resolved identity of a live terminal launch token
// for the session cockpit (GET /api/terminal/session/<token>): the run id the
// daemon minted at spawn, its kind + tool, and - once correlated - the observer
// session id and the confidence the link was scored at. SessionID is "" and
// Confidence 0 until the run is correlated (correlation is scored and
// asynchronous). Populated by Options.SessionResolver.
type TerminalSessionLink struct {
	RunID      string
	Kind       string
	Tool       string
	SessionID  string // "" until correlated
	Confidence float64
}

// ToolCatalogEntry is one supported tool in Options.ToolCatalog:
// the adapter's stable name (the `tool` column value) plus the
// canonical directories it watches - returned regardless of installed
// state, so their existence doubles as the install probe.
type ToolCatalogEntry struct {
	Tool       string
	WatchPaths []string
}

// EnrolmentService is the subset of *orgclient.Client the enrolment endpoints
// need. Keeping it an interface lets the dashboard avoid a hard dependency on
// the concrete client in tests and keeps the org surface optional.
type EnrolmentService interface {
	Status(ctx context.Context) (orgclient.EnrolmentState, error)
	Unenroll(ctx context.Context) error
	LastPayload(ctx context.Context) ([]byte, error)
	// MintInviteToken asks the enrolled org server for a one-time enrolment
	// token for a teammate (the Teams bottom-up invite loop). It is
	// user-initiated from Settings → Enrolment and adds no network posture:
	// same server, same credential the push loop already uses.
	MintInviteToken(ctx context.Context, email string, ttlDays int) (orgclient.InviteToken, error)
}

// BinaryInstall is how the running observer binary was installed (U12). It
// carries no filesystem path: GET /api/components is readable by a remote
// viewer (the same rule that strips artifact item paths); `observer
// components status` prints the path locally.
type BinaryInstall struct {
	// Channel is npm, pip or other (an archive, install.sh, a build).
	Channel string `json:"channel"`
	// Version is the binary's release version.
	Version string `json:"version"`
	// Registers is what hook and MCP entries invoke: "launcher" (the package
	// manager's launcher, which survives an upgrade) or "binary" (the real
	// path).
	Registers string `json:"registers"`
}
