package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/handoffsvc"
	"github.com/marmutapp/superbased-observer/internal/intelligence/advisor"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard/webapp"
	"github.com/marmutapp/superbased-observer/internal/intelligence/discover"
	"github.com/marmutapp/superbased-observer/internal/intelligence/learn"
	"github.com/marmutapp/superbased-observer/internal/intelligence/suggest"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/processbridge/setup"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/stash"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// Options configures a Server.
// ExtraRoute is one (pattern, handler) pair a separable subsystem registers
// into the dashboard's shared mux via Options.ExtraRoutes. The handler is a
// plain http.HandlerFunc so the dashboard carries no dependency on the
// subsystem (decision D4 / the obs reverse-import boundary).
type ExtraRoute struct {
	// Pattern is the mux pattern; it MAY carry a Go 1.22 method prefix
	// ("GET /api/obs/enabled") — that is the "method metadata" the plan §4.1
	// requires alongside the capability.
	Pattern string
	Handler http.HandlerFunc
	// Capability classifies the route for remote exposure (plan §4.1). It MUST
	// be set to a non-Unclassified value when the dashboard runs with a
	// RemoteController — New() rejects an unclassified ExtraRoute in that case
	// (TestExtraRoutesRejectedWithoutCapabilityMetadata). On a loopback-only
	// dashboard (the default) the zero value is tolerated (nothing is exposed).
	Capability Capability
	// Section is the node-dashboard nav section this route belongs to, for
	// the admin-controlled Plane-B governance guard (governance.go). The
	// zero value (SectionNone) means "no single page owns this route", which
	// is never hidden — the same fail-open default an unmapped built-in
	// route gets.
	Section Section
}

// Feature name strings passed to Options.FeatureGate / TerminalFeatureGate.
// These are duplicated, plain-string copies of
// internal/policyfam/nodefeatures.Feature* — this package never imports
// policyfam (module-boundary discipline: cmd/observer is the only thing
// that knows both the policy family's compiled types AND this package's
// closure signatures; the two sides agree only on these literal strings).
const (
	nodeFeatureTerminals     = "terminals"
	nodeFeatureRemote        = "remote"
	nodeFeatureRoutingApply  = "routing_apply"
	nodeFeaturePatternsWrite = "patterns_write"
)

type Options struct {
	// DB is the observer database.
	DB *sql.DB
	// DBPath is displayed in the header; not used to open anything.
	DBPath string
	// ProcessArchive serves process capture that has moved to cold storage
	// (corpus archival Bucket B, design §4.3). Nil — the default, and the
	// state whenever [archive].enabled is false — means the process surfaces
	// behave exactly as they did before the arc: hot rows or nothing.
	ProcessArchive ProcessArchiveReader
	// CostEngine prices token summaries. Defaults to baked-in pricing.
	CostEngine *cost.Engine
	// Predict carries the [predict] tunables (Next-Message Cost & Limit
	// Predictor). Zero value → the handler falls back to built-in
	// defaults, so tests and read-only callers need not set it.
	Predict config.PredictConfig
	// LocEditorToken is the per-install shared secret POST
	// /api/loc/editor-change verifies X-Observer-Token against. The
	// daemon resolves it in cmd (generate-on-first-start into
	// [loc].editor_token_file, or the deprecated
	// OBSERVER_LOC_EDITOR_TOKEN override) and hands the VALUE here — this
	// package never reads the file, so a test needs no filesystem.
	//
	// Empty means "no configured token", which leaves the endpoint on the
	// loopback + Origin posture it shipped with. Deliberately NOT read
	// back out anywhere: nothing in the dashboard renders it.
	LocEditorToken string
	// LocEditorTokenRequired is [loc].editor_token_required: refuse a
	// POST /api/loc/editor-change that carries no token. Default false —
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
	// every LoadSessionTaskReport/LoadTaskRollup call needs — an
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
	// only — the same degrade a solo install already gets.
	Dashboard config.DashboardConfig
	// Logger receives operational messages.
	Logger *slog.Logger
	// ExtraRoutes are additional (pattern, handler) pairs a separable
	// subsystem registers into the dashboard mux at the wiring point —
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
	// (this package never imports policyfam — the same module-boundary
	// discipline as Governance/RecognizesSessionFile: cmd/observer
	// resolves the accepted policy_resource into a plain closure).
	// Called at each of the four gated seams (terminal launch, remote
	// arm/pair, routing-apply, patterns-write) immediately before the
	// action would take effect. Returns (allowed, reason) — reason is
	// only meaningful when allowed is false, and is the exact string to
	// surface to the caller. NIL on every solo node and every node with
	// no accepted node.features policy — every seam fails OPEN in that
	// case, matching Governance's nil-safe convention.
	FeatureGate func(feature string) (bool, string)
	// TerminalFeatureGate is FeatureGate's terminals-specific sibling: the
	// terminals stanza of node.features additionally carries
	// sandbox_required, which depends on what the CALLER is requesting
	// (the launch body's own Sandbox flag) — a piece of request state
	// FeatureGate's single-string signature has no room for. requestedSandbox
	// is the launch request's own sandbox flag. NIL has the same fail-open
	// meaning as FeatureGate being nil.
	TerminalFeatureGate func(requestedSandbox bool) (bool, string)
	// MonthlyBudgetUSD surfaces on the Analysis tab as a spend-budget
	// progress tile. Zero hides the budget readout. Sourced from
	// `intelligence.monthly_budget_usd` in config.toml.
	MonthlyBudgetUSD float64
	// ConfigPath is the resolved path to config.toml — required by the
	// Settings page's GET /api/config + PUT /api/config/pricing
	// endpoints. Empty disables the Settings save path (read-only).
	ConfigPath string
	// RecognizesSessionFile, when non-nil, filters parse_cursors rows
	// in /api/health/watcher: paths NOT recognised by any current
	// adapter are tagged orphan_unmatched and excluded from the
	// "behind" count. Without this, parse_cursors entries from older
	// adapter versions (whose IsSessionFile criteria have since
	// tightened) show in the banner forever — the recovery flow
	// (Rescan / Run All) only re-walks paths a current adapter
	// matches, so it can never close those rows.
	RecognizesSessionFile func(path string) bool
	// CursorSemanticsFor, when non-nil, tells /api/health/watcher what
	// a parse_cursors row's saved cursor MEANS for that path — a byte
	// offset into an append-only log, an opaque SQLite watermark, an
	// undecodable encrypted store, or a file that yields tokens but
	// never actions. Wired alongside RecognizesSessionFile from the
	// adapter registry, and resolved to plain capability flags at that
	// boundary so this package never learns adapter types or branches
	// on tool names.
	//
	// Without it every row is treated as a byte-offset tail (the
	// pre-capability behaviour), which reports SQLite-backed adapters
	// as permanently behind AND permanently misrouted — a banner the
	// recovery flow can never close.
	CursorSemanticsFor func(path string) CursorSemantics
	// ProxyPort is the resolved observer-proxy port (cfg.Proxy.Port).
	// Used by /api/setup/codex to compute the desired
	// ~/.codex/config.toml base_url. Zero falls back to 8820.
	ProxyPort int
	// ArenaAdmission runs immediately before each Agent Arena candidate or
	// judge process starts. Nil preserves the standalone Arena engine's
	// unconfigured behavior. cmd owns the concrete budget-policy check.
	ArenaAdmission func(context.Context, string, string) error
	// StashDir is the proxy-side SROD (Stash & Retrieve on Demand) stash
	// directory (cfg.Compression.Conversation.Stash.Dir). When set, the
	// /api/compression/retrieval surface reads short content snippets of
	// what was stashed so the panel shows readable previews instead of
	// opaque SHAs. Empty disables snippets (the panel degrades to counts).
	StashDir string
	// GuardEnabled / GuardMode / GuardStrict surface the [guard]
	// posture on the Security page header (guard spec §11.2).
	// Display-only — the dashboard never constructs a guard.
	GuardEnabled bool
	GuardMode    string
	GuardStrict  bool
	// OrgClient backs the /api/enrolment/* endpoints (Teams). It is non-nil
	// only when [org_client] is enabled; when nil those endpoints report
	// not-enrolled and the web UI hides the org surface — preserving the
	// byte-identical solo-local experience.
	OrgClient EnrolmentService
	// Version is the running binary's version string (e.g. "1.8.2").
	// Stamped at build time via -ldflags="-X main.version=…" and
	// surfaced on /api/status so the dashboard can compare it against
	// the latest published release. "dev" is treated as "no compare".
	Version string
	// OnConfigSaved, when non-nil, fires after every successful
	// config.toml write (section PUT, pricing PUT, backup restore).
	// The daemon wires it to consumers that can re-read config at
	// runtime — P2.5: the proxy's compression profile router, so
	// profile/assignment edits apply to NEW sessions without a
	// restart. Called synchronously after the write lands and before
	// the HTTP response; implementations must be quick and never
	// panic (mirror the CostEngine.Reload hot-path contract).
	OnConfigSaved func()
	// ToolCatalog lists every supported adapter (stable tool name +
	// canonical watch paths) for the Connected-tools panel (P4.1).
	// Injected by cmd — the same seam pattern as
	// RecognizesSessionFile, keeping adapter packages out of the
	// dashboard's import graph. Empty = the panel reports only tools
	// with DB activity.
	ToolCatalog []ToolCatalogEntry
	// BuildHandoff, when non-nil, runs one session-handoff request through
	// internal/handoffsvc (docs/session-handoff.md). Injected by cmd — the
	// same seam pattern as ToolCatalog, keeping the concrete adapter set
	// out of the dashboard's import graph. Nil disables the
	// /api/session/<id>/handoff endpoints (503 with an honest message).
	BuildHandoff func(ctx context.Context, req handoffsvc.Request) (handoffsvc.Result, error)
	// DemoSeeder, when non-nil, enables demo mode (P6.7): it builds a
	// TEMPORARY database seeded from embedded synthetic fixtures and
	// returns the open handle plus a cleanup that closes it and
	// removes its directory. Injected by cmd (the same seam pattern as
	// ToolCatalog — the dashboard never imports the demo or adapter
	// packages). Nil keeps the /api/demo endpoints honest about
	// unavailability. The real observer.db is never read or written on
	// any demo path.
	DemoSeeder func(ctx context.Context) (*sql.DB, func() error, error)
	// RoutingDemotions, when non-nil, returns the live router's §R18.3
	// calibration demotion set (rule name → reason) — in-memory state
	// only the daemon process hosting the router can answer for
	// (R2.4). Injected by `observer start` from the wired router; nil
	// in a standalone `observer dashboard` process, when routing is
	// disabled, and in tests — /api/routing/status reports
	// demotions_live=false so the UI never confuses "can't see" with
	// "none demoted".
	RoutingDemotions func() map[string]string
	// LaunchManager, when non-nil, backs the embedded web-terminal launch
	// surface (POST /api/session/<id>/launch + GET /ws/launch/<handle>).
	// Injected by cmd only when [handoff].allow_dashboard_launch is true;
	// nil makes the endpoints 503 and hides the "Launch <tool> here" action
	// (a nil seam IS the disabled state — no separate flag needed). The seam
	// pattern mirrors BuildHandoff: the dashboard never imports
	// internal/termsession.
	LaunchManager LaunchManager
	// TerminalStatus, when non-nil, backs the F4 agent-status surface
	// (GET /api/terminal/<handle>/status + GET /ws/terminal/status). Nil is the
	// honest disabled state (503 / the WS closes).
	TerminalStatus TerminalStatusProvider
	// PolicyStop, when non-nil, resolves a durable explanation for a terminal
	// run the daemon's OWN node-intervention loop stopped — an org-managed
	// node's process-control policy killing a vendor process the operator
	// launched via "New Terminal" (docs/plans/... managed-node process
	// control). It is surfaced additively on the exit event and the status
	// payload; nil simply omits policy_stop everywhere (the honest "no
	// managed-node intervention wired" state, e.g. an unmanaged node).
	PolicyStop PolicyStopProvider
	// ToolPreflight, when non-nil, resolves a launchable tool NAME to its
	// binary-resolution verdict for GET /api/terminal/launch/preflight
	// (tool-binary-resolution arc). It is the dashboard's seam onto
	// internal/toolresolve — DEFINED as a plain func here so the dashboard
	// package carries no dependency on toolresolve's types (CLAUDE.md #2). A nil
	// seam is the honest disabled state (the endpoint reports 501); a returned
	// ok=false means the tool is unknown / not launchable (400). cmd wires a
	// closure that runs the resolver and fills the ToolPreflight wire shape.
	ToolPreflight func(tool string) (ToolPreflight, bool)
	// AllowToolInstall, when non-nil, reports whether the guided install
	// endpoint (POST /api/terminal/install) is enabled — a LIVE read of the
	// [terminal.launch].allow_install kill-switch (default true). Nil is treated
	// as DISABLED (403), so the install affordance stays off until cmd wires the
	// live-config reader.
	AllowToolInstall func() bool
	// ToolInstallHint, when non-nil, resolves a tool NAME to the server-side
	// install argv + human display string for POST /api/terminal/install. The
	// argv is a COMPILE-TIME registry constant (never request input — injection
	// surface is zero by construction); the tool name is only a registry map
	// key. Nil-able; a miss (ok=false) means no grounded install command → 400.
	ToolInstallHint func(tool string) (argv []string, display string, ok bool)
	// RecentModels, when non-nil, resolves a tool NAME to its recently-used
	// models for the New Terminal model picker (B5) — the dashboard's seam
	// onto store.Store.LoadRecentModelsForTool, defined as a plain func
	// (like ToolPreflight) so the dashboard's Options struct carries no
	// hard dependency on a live *store.Store (CLAUDE.md #2; the return type
	// store.RecentToolModel is a plain data struct, not the store itself).
	// A nil seam is the honest disabled state: both
	// GET /api/terminal/launch/models and handleTerminalLaunch's model
	// membership check degrade to "unsupported" exactly like an older
	// daemon build without the store wiring — see modelSuggestionsFor.
	RecentModels func(ctx context.Context, tool string) ([]store.RecentToolModel, error)
	// ProjectRootResolver, when non-nil, backs the per-terminal project panel
	// (GET /api/terminal/project/<token>...). It resolves a live launch token
	// (LaunchInfo.ID / PTY handle) to the canonical directory the run was
	// launched into PLUS that directory's provenance (TerminalRoot), from
	// server-retained state only — the browser never sends a filesystem root.
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
	// its run identity (run id + kind + tool) and — once the daemon has
	// correlated the run to an observer session — that session id and the
	// confidence the link was scored at. It returns known=false for an unknown
	// OR exited token (→404 unknown_token); a live-but-uncorrelated run returns
	// known=true with an empty SessionID and zero Confidence. Injected by cmd
	// from termsvc.Service (via a function field so the dashboard package never
	// imports termsvc — module discipline); nil (the default) makes the
	// endpoint 404 (a nil seam IS the disabled state), keeping the solo-local
	// experience unchanged.
	SessionResolver func(token string) (link TerminalSessionLink, known bool)
	// RestartFunc, when non-nil, restarts the daemon from the dashboard
	// (POST /api/admin/restart): it preflights the config and triggers the
	// daemon's graceful shutdown + self re-exec (cmd owns the process
	// lifecycle; see cmd/observer/reexec.go). A non-nil error is a REFUSAL
	// (e.g. config wouldn't come back) — the daemon keeps running. Nil means
	// this process mode can't self-restart (the handler reports 501).
	RestartFunc func() error
	// UpdateApplyFunc, when non-nil, runs an in-place binary update in the
	// DAEMON process (POST /api/update/apply) — the enterprise-update
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
	// surface: GET /api/terminal/sandbox (fail-soft, always 200 — see
	// handleTerminalSandbox) AND handleTerminalLaunch's fail-CLOSED
	// sandbox validation (a requested sandbox=true with a nil seam refuses
	// the launch with 501, never a silent unsandboxed fallback — B9 plan
	// §12 amendment A5). Injected by cmd (U5) from the daemon's real bwrap
	// probe; nil (the default) is the honest disabled state, matching the
	// LaunchManager/BuildHandoff seam pattern (CLAUDE.md #2).
	SandboxProber SandboxProber
	// RefreshWatchRoots, when non-nil, is invoked fail-open after a guided
	// tool install (POST /api/terminal/install) and after a successful New
	// Terminal launch (POST /api/terminal/launch). It asks the daemon's
	// watcher to re-detect adapters, hot-add newly-existing session
	// directories into the live fsnotify set, and Scan — closing the
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
}

// TerminalSessionLink is the resolved identity of a live terminal launch token
// for the session cockpit (GET /api/terminal/session/<token>): the run id the
// daemon minted at spawn, its kind + tool, and — once correlated — the observer
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
// canonical directories it watches — returned regardless of installed
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

// Server wires the /api/* endpoints and static file handler.
type Server struct {
	opts Options

	// Backfill job registry — tracks subprocesses spawned by the
	// Backfill section's Run-Now buttons. Keyed by random hex id;
	// populated in handleBackfillRun, drained by handleBackfillJob.
	// In-memory only; daemon restart drops the registry.
	backfillMu   sync.Mutex
	backfillJobs map[string]*backfillJob
	// backfillSeq hands each job a creation-ordered sequence number
	// under backfillMu — the jobs list sorts on it (StartedAt ties on
	// coarse clocks; see backfillJob.seq).
	backfillSeq int64

	// execBackfill spawns the backfill subprocess. Default points at
	// realExecBackfill which os/exec's the observer binary. Tests
	// override with a fake to avoid requiring the binary in PATH.
	execBackfill backfillExecFn

	// now returns the current UTC time. Defaults to time.Now().UTC();
	// tests override to pin date-sensitive handlers (e.g. the analysis
	// headline's prior-month-same-day window) so CI doesn't flake when
	// the wall clock crosses a calendar boundary the handler treats
	// specially.
	now func() time.Time

	// correlateMu guards lastCorrelate, the per-session timestamp of the last
	// process-correlation pass run from handleSessionProcesses. The Processes
	// drawer polls that endpoint every few seconds while open; without this the
	// correlation WRITE passes (cross-OS + action links) re-ran on every poll,
	// scaling with the unattributed-row backlog and slowing the UI. We instead
	// run them at most once per correlateMinInterval per session — the tree
	// barely changes between polls — and serve the read fresh every time.
	correlateMu   sync.Mutex
	lastCorrelate map[string]time.Time

	// configWriteMu serializes EVERY dashboard-driven config.toml write so two
	// concurrent PUTs can never lose one another's changes. Each write handler
	// does load-from-disk → patch-one-section → validate → write-full-struct;
	// without a lock, two PUTs to DIFFERENT sections both read the same base,
	// each patches only its own field, and the second write clobbers the first
	// (a classic lost update — config.WriteToml / writeBytesAtomic are atomic
	// per file but carry no cross-call serialization). Held across the whole
	// load→patch→validate→write critical section in handleConfigSection,
	// handleConfigPricing, and the handleConfigBackup restore swap — the three
	// paths that read-modify-write the file — so the class is closed, not just
	// one handler.
	//
	// It points at config.WriteLock() (the process-wide config RMW mutex, set
	// in New), NOT a Server-private lock: the daemon has OTHER in-process
	// writers of the same file that are not dashboard handlers — notably the obs
	// admission-policy persister in cmd/observer (wired via obs_wire.go, which
	// serializes its span through config.WithConfigLock). Sharing the one
	// package mutex is what makes those cross-package writers serialize against
	// these handlers instead of racing the file (CLAUDE.md #4 — one owner per
	// piece of state). The defer-style Lock/Unlock spans here are preserved
	// exactly; only the mutex's identity moved to the config package.
	configWriteMu *sync.Mutex

	// processCapabilityFn probes what OS process-capture backends can ACTUALLY
	// capture on this host (poll native enumerator by GOOS, eBPF privilege
	// probe, WSL bridge resolution) — the platform truth the enable-capture verb
	// grounds its decision in, distinct from processBackendRunnable's
	// selector-vocabulary check. Injected as a field so the enable-capture
	// handler tests exercise every GOOS-shaped capability set without needing
	// the real platform (repo injected-IO discipline). Defaults to
	// realProcessCapability in New.
	processCapabilityFn func(config.ProcessConfig) processCapability

	// etwSetupEnvFn supplies the I/O seam GET /api/process/etw/status and
	// POST /api/process/etw/register both plan
	// through (PATH lookup for schtasks.exe, the read-only `schtasks /Query`
	// probe, the Windows-binary/username resolution). Injected as a field so
	// handler tests exercise every planner outcome WITHOUT touching the real
	// Task Scheduler — the same injected-IO discipline processCapabilityFn
	// follows, and the same reason browserhost's tests inject fake registry
	// hives. nil means the production probes.
	etwSetupEnvFn func() setup.Env

	// etwProbes rate-bounds the STATUS endpoint's probes (see etwProbeTTL).
	// GET /api/process/etw/status is capability View, so a paired remote device
	// can poll it, and each applicable poll execs schtasks.exe (plus cmd.exe
	// for the Windows user name). The elevation broker does not share it.
	etwProbes etwProbeCache

	// etwRegisterOps remembers what the last elevated-ETW registration PTY was
	// actually started with, keyed by its handle. The launch manager's labelled
	// setup ops are idempotent — a second POST while one is live gets the SAME
	// handle back — so without this the response would describe the plan THIS
	// request computed rather than the command the reused PTY is running.
	etwRegisterMu  sync.Mutex
	etwRegisterOps etwRegisterRecord

	// resumeMu + resumeGates single-flight handleSessionResume PER session id
	// (R2-3): the duplicate-resume liveness check (sessionHasLiveSensitiveRun)
	// and the spawn (CreateResume) must run atomically for one session, else two
	// concurrent POSTs from separate tabs/devices could both observe no live run
	// and both spawn a tool process writing the SAME transcript. Each gate is
	// reference-counted and removed from the map when its last waiter leaves, so
	// the map cannot grow unbounded. Lazily initialized under resumeMu.
	resumeMu    sync.Mutex
	resumeGates map[string]*resumeGate

	// sensitiveViewerMu + sensitiveViewers track the LIVE remote-exposed
	// read-only viewers of a remote-sensitive (attach/resume) session that were
	// admitted under [remote].allow_terminal_view (session-attach design §3.2,
	// Phase 4). Each entry is the bridge-scoped context cancel of one such WS
	// viewer, registered when handleLaunchWS admits it and deregistered on
	// disconnect. When the owner flips allow_terminal_view→false, the management
	// handler calls closeRemoteSensitiveViewers to cancel every one NOW — so an
	// already-open remote view of a secret-bearing TUI is torn down immediately,
	// not merely blocked for future subscribes (the READ analogue of the
	// revoke-kills-open-writers invariant). Each entry also carries the viewer's
	// DEVICE fingerprint (F2) so a per-device revocation
	// (closeRemoteSensitiveViewersForDevice) can tear down exactly the revoked
	// device's open views — a revoked phone must not keep reading PTY output.
	// Keyed by a monotonic seq so deregister is O(1). Lazily initialized under
	// the mutex.
	sensitiveViewerMu  sync.Mutex
	sensitiveViewers   map[uint64]sensitiveViewer
	sensitiveViewerSeq uint64

	// statusSnap memoizes GET /api/status's diag.Snapshot for
	// statusSnapshotTTL, with singleflight semantics on a miss. The SPA
	// polls that endpoint from TWO always-mounted chrome components on a 5s
	// ticker plus the active page's own hook, and the snapshot is an
	// unfiltered COUNT(*) over a dozen tables — without this, a status scan
	// was permanently in flight against the same SQLite reader every other
	// panel queries. See status_cache.go for the full rationale; the cache
	// lives HERE, on the Server, so the endpoint has exactly one owner.
	statusSnap statusSnapshotCache

	// snapshotFn produces the /api/status snapshot. Defaults to
	// diag.Snapshot (set in New); tests override it to count how many times
	// the scan actually ran, which is the only way to observe the cache
	// without a corpus large enough for its cost to show up as latency.
	// Same injected-IO discipline as processCapabilityFn / execBackfill.
	snapshotFn func(context.Context, *sql.DB, string) (diag.StatusSnapshot, error)

	// Demo mode (P6.7). demoDB holds the seeded temp database while
	// demo mode is active — data endpoints read it through Server.db()
	// (atomic: the getter sits on every data handler's path).
	// demoCleanup closes the handle and removes the temp directory;
	// both mutate only under demoMu.
	demoMu      sync.Mutex
	demoDB      atomic.Pointer[sql.DB]
	demoCleanup func() error
}

// db returns the database the data endpoints serve from: the seeded
// demo database while demo mode is active (P6.7), the real one
// otherwise. Data handlers MUST read through this getter rather than
// s.opts.DB so demo mode swaps every data surface at one seam.
// Operational surfaces (doctor, watcher health, backfill status,
// connected tools, cowork reconcile) deliberately keep reading
// s.opts.DB — they describe THIS install, not the data.
func (s *Server) db() *sql.DB {
	if d := s.demoDB.Load(); d != nil {
		return d
	}
	return s.opts.DB
}

// New returns a Server. DB is required.
func New(opts Options) (*Server, error) {
	if opts.DB == nil {
		return nil, errors.New("dashboard.New: DB is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.CostEngine == nil {
		opts.CostEngine = cost.NewEngine(config.IntelligenceConfig{})
	}
	if opts.ProxyPort <= 0 {
		opts.ProxyPort = 8820
	}
	// Fail closed on an unclassified ExtraRoute when a RemoteController is
	// present (plan §4.1 / TestExtraRoutesRejectedWithoutCapabilityMetadata):
	// a raw pattern/handler pair may not ride the remotely-exposed mux without
	// declared capability metadata. Tolerated on a loopback-only dashboard.
	if opts.Remote != nil {
		for _, rt := range opts.ExtraRoutes {
			if rt.Pattern == "" {
				continue
			}
			if rt.Capability == CapabilityUnclassified {
				return nil, fmt.Errorf("dashboard.New: ExtraRoute %q has no capability metadata — remotely-exposed routes must be classified public/view/execute/local (plan §4.1)", rt.Pattern)
			}
			// §9.4 fail-closed: a mutation-method ExtraRoute (its pattern carries
			// an unsafe method prefix) MUST be Local unless it is on the explicit
			// remotelyExecutableExtraRoutes allowlist. Otherwise a subsystem could
			// register a config-writing POST as View and let it auto-escalate only
			// to Execute — reachable by a remote execute principal. Build-breaking.
			if patternHasUnsafeMethod(rt.Pattern) && rt.Capability != CapabilityLocal {
				if _, ok := remotelyExecutableExtraRoutes[rt.Pattern]; !ok {
					return nil, fmt.Errorf("dashboard.New: mutation-method ExtraRoute %q is classified %s — a config/machine-reaching ExtraRoute write must be CapabilityLocal, or be added to remotelyExecutableExtraRoutes with a threat-model comment (plan §9.4)", rt.Pattern, rt.Capability)
				}
			}
		}
	}
	s := &Server{
		opts:          opts,
		backfillJobs:  map[string]*backfillJob{},
		execBackfill:  realExecBackfill,
		now:           func() time.Time { return time.Now().UTC() },
		lastCorrelate: map[string]time.Time{},
		// Share the process-wide config RMW mutex so dashboard config writes
		// serialize against cmd/observer's admission-policy persister and any
		// other in-process writer (see the configWriteMu field doc).
		configWriteMu:       config.WriteLock(),
		processCapabilityFn: realProcessCapability(opts.Logger),
		snapshotFn:          diag.Snapshot,
	}
	// Wire the controller's session-revoke hook (F2): when a device logs ITSELF
	// out, close any read-only sensitive viewer that device left open — the
	// self-revocation analogue of the admin per-device revoke that
	// closeRemoteSensitiveViewersForDevice performs at the management layer. A
	// nil / non-implementing controller (loopback-only) leaves the hook unset.
	if h, ok := opts.Remote.(sessionRevokeHooker); ok {
		h.SetSessionRevokeHook(func(sessionKey string) {
			s.closeRemoteSensitiveViewersForDevice(sessionKey)
		})
	}
	return s, nil
}

// Handler returns the dashboard's http.Handler (loopback path). It registers
// every route with a capability classification but applies no remote
// authorization — the local single-user deployment trusts loopback. The
// remotely-exposed handler (remoteGuardedHandler) uses the same registry with
// the capability enforcement layered on.
func (s *Server) Handler() http.Handler {
	mux, _, sections := s.registerRoutes(nil)
	// Admin-controlled Plane B (spec §3.5): the governance route guard rides
	// HERE, on the loopback path — not beside capMap in remoteAuthz, which
	// this very function is the proof of, since it discards capMap. With a
	// nil Governance provider this returns the bare mux, so an ungoverned
	// build's handler chain is unchanged.
	return s.governanceGuard(mux, sections, mux)
}

// sessionSubRouteCapabilities is the DECLARED (documentation + test) suffix→
// Capability table for the mutating sub-routes under the dynamic
// `/api/session/<id>/…` pattern (plan §9.1).
//
// It is NOT consulted at request time. ServeMux cannot match a verb that is a
// path SUFFIX after a dynamic id segment as its own pattern, so `/api/session/`
// is registered once with a View base (its GET reads must work remotely) and
// the PRODUCTION protection for these unsafe sub-routes is the generic
// method-aware escalation in requiredCapability (remote.go): a View-classified
// route requires Execute for POST/PUT/DELETE/PATCH. That is what actually
// refuses an anonymous or view-only remote principal — pinned by
// TestRemoteAuthzMatrix (POST /api/session/<id>/resume) and, for classification,
// TestSessionTagsRemoteAuthzRefusesNonExecute.
//
// What this table buys is a REVIEW gate, not enforcement: it forces the
// intended tier of every mutating session sub-route to be written down and
// enumerated (TestSessionSubRouteCapabilities fails when a suffix is added or
// removed without a decision here), so the silent View→Execute default is a
// checked decision rather than an unexamined one. A sub-route whose intended
// tier is anything OTHER than Execute — a Local one, say — cannot be expressed
// here at all: it would need its own registered pattern, because the escalation
// this table documents can only ever produce Execute. There is none today.
var sessionSubRouteCapabilities = map[string]Capability{
	"/handoff": CapabilityExecute,
	"/launch":  CapabilityExecute,
	"/resume":  CapabilityExecute,
	// Session classification (tags / favorite / note, plan §4). Execute, not
	// Local: tagging last night's runs "junk" from a phone during remote review
	// is a primary flow, and the content written is user-authored review
	// metadata — never machine-reaching config.
	"/tags": CapabilityExecute,
}

// remotelyExecutableExtraRoutes is the explicit allowlist of mutation-method
// ExtraRoute patterns permitted to carry a non-Local capability on a
// remotely-exposed dashboard (plan §9.4). Each entry needs a threat-model
// comment justifying why a paired remote owner may drive it. Empty today:
// every shipped ExtraRoute mutation (the obs admission-policy WRITE) is Local.
// A subsystem that deliberately exposes a remote-executable mutation adds its
// exact pattern here WITH justification, or dashboard.New's fail-closed check
// rejects it.
var remotelyExecutableExtraRoutes = map[string]struct{}{}

// patternHasUnsafeMethod reports whether a mux pattern carries a Go 1.22
// method prefix for an unsafe (state-mutating) method — POST/PUT/DELETE/PATCH.
// A bare (methodless) pattern returns false: it is classified as a whole and
// its own capability governs it.
func patternHasUnsafeMethod(pattern string) bool {
	method, _, found := strings.Cut(strings.TrimSpace(pattern), " ")
	if !found {
		return false
	}
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return true
	}
	return false
}

// registerRoutes builds the dashboard mux and the parallel route-capability map
// (remote-dashboard-access plan §4.1). Every route is registered through `reg`
// with an explicit Capability, so the classification lives AT the registration
// (single source of truth, no drift) and an unclassified route is impossible
// for a built-in. On a remotely-exposed bind the capability map is consulted by
// remoteAuthz; ExtraRoutes (and the RemoteController's own routes) carry their
// own Capability and fail closed when unclassified.
//
// Capability model (method-aware, applied in requiredCapability): a
// CapabilityView route needs View for safe methods and auto-escalates to
// Execute for unsafe methods (POST/PUT/DELETE/PATCH) — so a benign read
// endpoint that also has a mutating verb is protected without a second entry.
// CapabilityExecute routes (the terminal PTY bridge) require Execute for EVERY
// method incl. the GET upgrade. CapabilityPublic routes need no auth.
func (s *Server) registerRoutes(remote RemoteController) (*http.ServeMux, map[string]Capability, map[string]Section) {
	mux := http.NewServeMux()
	capMap := map[string]Capability{}
	// sectionMap is the parallel route -> nav-section registry the
	// admin-controlled Plane-B governance guard consults (governance.go).
	// It is authored AT the registration site for exactly the reason capMap
	// is: a hand-maintained side table of 172 routes drifts, and here a
	// drifted entry silently leaks a page an organization believes it hid.
	sectionMap := map[string]Section{}
	reg := func(pattern string, cap Capability, section Section, h http.HandlerFunc) {
		mux.HandleFunc(pattern, h)
		capMap[pattern] = cap
		sectionMap[pattern] = section
	}
	// React/Vite dashboard at root (Phase 8 cutover). Returns the SPA shell for
	// any non-API path so React Router can render client-side routes. Public:
	// the shell carries no data; every data surface is a View route below.
	mux.Handle(webapp.MountPath, webapp.Handler())
	capMap[webapp.MountPath] = CapabilityPublic
	// The SPA shell itself is never a governed section: it carries no data,
	// and a governed node must still be able to LOAD the app that tells it
	// which pages its organization hid.
	sectionMap[webapp.MountPath] = SectionNone

	// Section aliases (governance.go). Every reg() call names the nav
	// section its route belongs to, or secNone for a cross-cutting route
	// that no single page owns — secNone is NEVER hidden (the D-D default).
	const (
		secNone        = SectionNone
		secLive        = SectionLive
		secSessions    = SectionSessions
		secActions     = SectionActions
		secProjects    = SectionProjects
		secSecurity    = SectionSecurity
		secSearch      = SectionSearch
		secCost        = SectionCost
		secAnalysis    = SectionAnalysis
		secTools       = SectionTools
		secCompression = SectionCompression
		secCache       = SectionCache
		secSuggestions = SectionSuggestions
		secRouting     = SectionRouting
		secBenchmarks  = SectionBenchmarks
		secDiscovery   = SectionDiscovery
		secPatterns    = SectionPatterns
		secPolicies    = SectionPolicies
		secPrivacy     = SectionPrivacy
		secTerminals   = SectionTerminals
		secRemote      = SectionRemote
		secSettings    = SectionSettings
	)

	const V = CapabilityView
	const X = CapabilityExecute
	// L = owner-local-only (dashboard-management-surface plan §9): config /
	// consent / machine-reaching mutations refused on every remote-exposed bind.
	// A dual-method route (GET read + unsafe write) is method-SPLIT so the GET
	// read stays remotely viewable while the write is Local (Go 1.22
	// method-prefixed patterns; §9.1). A pure-mutation route is whole-route L.
	const L = CapabilityLocal
	// NOTE on the classification MECHANISM (a deviation from the plan's §9.1
	// method-split, forced by this mux's shape): a dual-method route that both
	// reads (GET) and mutates config is classified WHOLE-route Local (bare
	// pattern), NOT method-split. Go 1.22 method-prefixed patterns interact
	// badly with the SPA "/" subtree catch-all here — an unregistered method on
	// a method-split path falls through to "/" and returns the 200 SPA shell
	// instead of the handler's own 405 (caught by TestSetup*_MethodNotAllowed).
	// Whole-route Local is strictly SAFER than the plan's split (the GET read is
	// also refused remotely — fail-safe) and preserves each handler's method
	// switch. Where the desired write tier is EXECUTE (not Local) — e.g. the
	// /api/launch/ DELETE and the /api/session/ sub-routes — a bare View route
	// is kept and the method-aware requirement auto-escalates the unsafe method
	// to Execute, which is the intended tier.

	reg("/api/status", V, secNone, s.handleStatus)
	reg("/api/status/scoped", V, secNone, s.handleStatusScoped)
	reg("/api/codex/support", V, secNone, s.handleCodexSupport)
	reg("/api/cowork/reconcile", V, secNone, s.handleCoworkReconcile)
	// Setup POST writes AI-client config → whole-route Local (the GET status
	// read is refused remotely too — fail-safe). codex-hooks is GET-only.
	reg("/api/setup/codex", L, secSettings, s.handleSetupCodex)
	reg("/api/setup/codex-hooks", V, secSettings, s.handleSetupCodexHooks)
	reg("/api/setup/claude", L, secSettings, s.handleSetupClaude)
	reg("/api/cost", V, secCost, s.handleCost)
	reg("/api/discover", V, secDiscovery, s.handleDiscover)
	reg("/api/suggestions", V, secSuggestions, s.handleSuggestions)
	reg("/api/suggestions/state", L, secSuggestions, s.handleSuggestionState)
	reg("/api/routing/status", V, secRouting, s.handleRoutingStatus)
	reg("/api/routing/decisions", V, secRouting, s.handleRoutingDecisions)
	reg("/api/routing/savings", V, secRouting, s.handleRoutingSavings)
	reg("/api/routing/tiers", V, secRouting, s.handleRoutingTiers)
	reg("/api/routing/health", V, secRouting, s.handleRoutingHealth)
	reg("/api/routing/shadow", V, secRouting, s.handleRoutingShadow)
	reg("/api/routing/simulate", V, secRouting, s.handleRoutingSimulate)
	// routing apply POST WRITES per-AI-tool routing config files → whole-route
	// Local (§9.3). revert is POST-only Local.
	reg("/api/routing/apply", L, secRouting, s.handleRoutingApply)
	reg("/api/routing/apply/revert", L, secRouting, s.handleRoutingApplyRevert)
	reg("/api/routing/apply/ledger", V, secRouting, s.handleRoutingApplyLedger)
	reg("/api/routing/policy", V, secRouting, s.handleRoutingPolicy)
	reg("/api/routing/policy/lint", V, secRouting, s.handleRoutingPolicyLint)
	reg("/api/verbosity/aggregate", V, secAnalysis, s.handleVerbosityAggregate)
	reg("/api/sessions", V, secSessions, s.handleSessions)
	reg("/api/sessions/calendar", V, secSessions, s.handleSessionsCalendar)
	// Session classification (plan §4). The vocabulary + per-tag rollup is a
	// pure read (View); vocabulary MANAGEMENT (rename/delete across every
	// session) is a whole-route Execute mutation — the same tier as the
	// per-session /tags sub-route, and for the same reason (user-authored
	// review metadata a paired remote owner legitimately drives).
	reg("/api/sessions/tags", V, secSessions, s.handleSessionsTags)
	reg("/api/sessions/tags/manage", X, secSessions, s.handleSessionsTagsManage)
	// Tag definitions (migration 101): the optional human-readable
	// explanation + category attached to a tag name. Same tier split as
	// the vocabulary above — GET is a pure read (View), POST is a
	// whole-route Execute mutation (method-aware requirement auto-
	// escalates it, same as /api/sessions/tags/manage).
	reg("/api/tags/definitions", V, secSessions, s.handleTagDefinitions)
	// /api/session/ keeps a View base — its many GET sub-route reads must work
	// remotely — while its mutating sub-routes resolve explicitly via
	// sessionSubRouteCapabilities (§9.1): /handoff + /launch are Execute (a
	// paired remote owner legitimately drives them), which the method-aware
	// requirement produces for their POST. No Local-class sub-route exists under
	// /api/session/; TestSessionSubRouteCapabilities enumerates and pins this.
	reg("/api/session/", V, secSessions, s.handleSessionDetail)
	// Terminal PTY bridge: the GET upgrade is View-reachable by a paired device;
	// the writer role is still gated in-band by the §4.δ execute conjunction.
	reg("/ws/launch/", V, secTerminals, s.handleLaunchWS)
	// launch admin: GET lists launched terminals (View); the DELETE terminates
	// one — a per-session op a paired owner legitimately drives (Execute).
	// Bare View + method-aware auto-escalation gives DELETE→Execute (§9.3) while
	// preserving the handler's own 405 for other methods.
	reg("/api/launch/", V, secTerminals, s.handleLaunchAdmin)
	// Terminal cockpit surface (terminal-product-exploitation plan §9).
	// Fresh-agent launch is EXECUTE (it starts a new process — the
	// privilege-expansion feature); the session list is VIEW (metadata only).
	reg("/api/terminal/launch", X, secTerminals, s.handleTerminalLaunch)
	// Pre-launch binary-resolution verdict (tool-binary-resolution arc). LOCAL —
	// resolving the binary runs a $SHELL -lc login-shell PATH capture (a
	// side-effecting local exec) AND reveals absolute binary paths + home-dir
	// layout, so a paired READ-ONLY remote principal must never drive it. Same
	// owner-local posture as /api/terminal/install (reclassified V→L in the
	// 2026-07-23 review pass). The exact pattern is MORE specific than the
	// /api/terminal/ catch-all below, so mux precedence routes it here (not to
	// handleTerminalStatus).
	reg("/api/terminal/launch/preflight", L, secTerminals, s.handleTerminalPreflight)
	// New Terminal model picker (B5). VIEW — unlike preflight (which runs a
	// local $SHELL PATH capture and reveals binary/home-dir layout), this
	// reads only token_usage history + the capability registry's Known
	// list: informational, non-sensitive, the same posture as
	// /api/terminal/sessions and /api/models. The more-specific pattern
	// takes mux precedence over /api/terminal/launch above.
	reg("/api/terminal/launch/models", V, secTerminals, s.handleTerminalLaunchModels)
	// B9 sandbox probe (plan §5). VIEW, FAIL-SOFT (always 200) — the same
	// posture as the model-picker endpoint above: informational, reads only
	// the daemon's cached probe result + the [terminal.sandbox] config, no
	// side effects. Distinct from the fail-CLOSED validation inside
	// handleTerminalLaunch, which actually refuses a launch.
	reg("/api/terminal/sandbox", V, secTerminals, s.handleTerminalSandbox)
	// SSH remote-system terminals (docs/plans/ssh-remote-profiles-plan-2026-08-27.md
	// §6.2). BOTH verbs are LOCAL-ONLY — deliberately NOT the X (execute) class
	// /api/terminal/launch carries.
	//
	//   GET  discloses the operator's configured remote hostnames, which are
	//        the same privacy class as sessions.git_branch (internal names
	//        encode clients and environments).
	//   POST opens an interactive shell on a THIRD-PARTY machine. Letting a
	//        paired phone do that is a materially different grant from letting
	//        it drive a local terminal, and it needs its own threat model
	//        before it is ever offered (plan D1).
	//
	// Expressing that as route CLASS rather than an in-handler check means a
	// future refactor cannot silently drop it. The exact pattern is more
	// specific than the /api/terminal/ catch-all below, so mux precedence
	// routes it here.
	reg("/api/terminal/ssh", L, secTerminals, s.handleTerminalSSH)
	// Instance switcher (ssh-remote-profiles plan §12 D2, partially lifted).
	// LOCAL-ONLY for the SAME two reasons /api/terminal/ssh is, plus a third:
	//
	//   GET  discloses the operator's configured remote hostnames.
	//   POST .../connect spawns an `ssh -N -L` child to a THIRD-PARTY machine.
	//   The forward it opens is reachable on THIS machine's loopback, so a
	//   remote principal able to drive it would gain a path toward the remote
	//   dashboard as well — the pivot D1 has not been threat-modelled for.
	//
	// Both patterns are registered because the mux needs the exact "/api/
	// instances" for the list and the "/api/instances/" prefix for the
	// {name}/{verb} verbs; both carry the same class, so no reachable path is
	// left unclassified.
	reg("/api/instances", L, secTerminals, s.handleInstances)
	reg("/api/instances/", L, secTerminals, s.handleInstanceVerb)
	// Sandbox config editor. LOCAL + confirm-token-gated: unlike the probe
	// above, this writes [terminal.sandbox], including authority-expanding
	// remote-clone / extra-rw-bind escape hatches.
	reg("/api/terminal/sandbox/config", L, secTerminals, s.handleTerminalSandboxConfig)
	// Guided one-click install (tool-binary-resolution arc). LOCAL + confirm-
	// token-gated, EXACTLY like the Tailscale setup handlers: it spawns a
	// grounded, compile-time-constant install command in a visible local-only
	// PTY — a machine-reaching mutation a remote principal must never drive.
	reg("/api/terminal/install", L, secTerminals, s.handleTerminalInstall)
	reg("/api/terminal/sessions", V, secTerminals, s.handleTerminalSessions)
	// Live-joinable session list (session-attach design Phase 2, "Jump in"):
	// every LIVE, non-setup daemon-owned PTY run of any valid terminal_run kind
	// (fresh/handoff/attach/resume) a dashboard tab can join as an extra seat.
	// VIEW — metadata only, no content. Same visibleSnapshot semantics as
	// /api/terminal/sessions; remote callers see attach/resume rows gated by
	// [remote].allow_terminal_view (built now), with fresh/handoff the
	// non-sensitive floor.
	reg("/api/attach/sessions", V, secTerminals, s.handleAttachSessions)
	// F4 agent status: point-in-time (GET /api/terminal/<handle>/status) via the
	// prefix route, and the multiplexed live stream — both VIEW (read-only). The
	// Per-terminal project panel (Arc A): git tree + read-only file explorer
	// rooted at the terminal's server-resolved project root. VIEW (GET-only);
	// the more-specific pattern takes mux precedence over /api/terminal/ below,
	// and its own handler re-gates remote-exposed callers on allow_terminal_view.
	reg("/api/terminal/project/", V, secTerminals, s.handleTerminalProject)
	// Per-terminal session cockpit (Session Cockpit): resolves a live launch
	// token to its run identity and, once correlated, its observer session id +
	// link confidence. VIEW (GET-only, metadata only); the more-specific prefix
	// takes mux precedence over /api/terminal/ below, and its own handler
	// re-gates remote-exposed callers on allow_terminal_view (identically for
	// known and unknown tokens — no token oracle).
	reg("/api/terminal/session/", V, secTerminals, s.handleTerminalSession)
	// exact /launch + /sessions patterns above take mux precedence.
	reg("/api/terminal/", V, secTerminals, s.handleTerminalStatus)
	reg("/ws/terminal/status", V, secTerminals, s.handleTerminalStatusWS)
	reg("/api/process/findings", V, secSecurity, s.handleProcessFindings)
	reg("/api/process/network/", V, secSecurity, s.handleProcessNetworkDetail)
	// enable-capture WRITES config.toml (turns on [observer.process] + fixes a
	// non-runnable backend) → whole-route Local, like /api/config/section/.
	reg("/api/process/enable-capture", L, secSettings, s.handleProcessEnableCapture)
	// Elevated-ETW-capturer setup DETECTION (ETW dashboard plan §E2). VIEW: it
	// reads config, runs the same read-only `schtasks /Query` probe
	// `observer init` runs, and reads the daemon's own published health record.
	// It registers nothing and spawns nothing — the elevation broker that does
	// is a separate Local + confirm-token route.
	reg("/api/process/etw/status", V, secSettings, s.handleProcessETWStatus)
	// The elevation BROKER (ETW dashboard plan §E3): spawns a fixed,
	// server-derived `powershell.exe … Start-Process schtasks.exe -Verb RunAs`
	// in a local-only setup PTY so Windows shows the operator a UAC prompt.
	// LOCAL + confirm-token-gated, exactly like the Tailscale setup POSTs and
	// /api/terminal/install — a machine-reaching mutation a remote principal
	// must never drive, and a consent dialog that can only be approved on the
	// machine itself.
	reg("/api/process/etw/register", L, secSettings, s.handleProcessETWRegister)
	reg("/api/actions", V, secActions, s.handleActions)
	reg("/api/live", V, secLive, s.handleLive)
	reg("/api/search", V, secSearch, s.handleSearch)
	reg("/api/budget", V, secCost, s.handleBudget)
	// Announcements are admin-authored banner copy (release-embedded today,
	// org-distributed later) — nothing about this install, nothing sensitive,
	// so View: a remote viewer should see the same banner the owner does.
	reg("/api/announcements", V, secNone, s.handleAnnouncements)
	// experiments POST CREATES an A/B experiment (management) → whole-route
	// Local. stop is POST-only management.
	reg("/api/experiments", L, secNone, s.handleExperiments)
	reg("/api/experiments/stop", L, secNone, s.handleExperimentStop)
	reg("/api/experiments/report", V, secNone, s.handleExperimentReport)
	// scrub-test POST computes a scrub over submitted text — no persistence, no
	// machine reach; it is a read-only compute, so View (auto-escalation is
	// harmless here, §9.3).
	reg("/api/privacy/scrub-test", V, secPrivacy, s.handlePrivacyScrubTest)
	reg("/api/demo", V, secSettings, s.handleDemo)
	// demo start/stop flip the WHOLE install into/out of demo mode — a local
	// owner-state toggle, never a remote viewer's to flip (Local, §9.3).
	reg("/api/demo/start", L, secSettings, s.handleDemoStart)
	reg("/api/demo/stop", L, secSettings, s.handleDemoStop)
	reg("/api/storage", V, secSettings, s.handleStorage)
	reg("/api/storage/vacuum", L, secSettings, s.handleStorageVacuum)
	reg("/api/storage/backup", L, secSettings, s.handleStorageBackup)
	reg("/api/report/monthly", V, secCost, s.handleReportMonthly)
	reg("/api/actions/day-counts", V, secActions, s.handleActionsDayCounts)
	reg("/api/action/", V, secActions, s.handleActionDetail)
	reg("/api/file/state", V, secActions, s.handleFileState)
	reg("/api/patterns", V, secPatterns, s.handlePatterns)
	reg("/api/patterns/timeseries", V, secPatterns, s.handlePatternsTimeseries)
	reg("/api/suggest", V, secSuggestions, s.handleSuggestPreview)
	reg("/api/suggest/write", L, secSuggestions, s.handleSuggestWrite)
	reg("/api/timeseries/cost", V, secCost, s.handleTimeseriesCost)
	reg("/api/timeseries/tokens-by-model", V, secAnalysis, s.handleTimeseriesTokensByModel)
	reg("/api/timeseries/actions", V, secAnalysis, s.handleTimeseriesActions)
	reg("/api/models", V, secNone, s.handleModels)
	reg("/api/tools", V, secTools, s.handleTools)
	reg("/api/tools/breakdown", V, secTools, s.handleToolsBreakdown)
	reg("/api/compression/events", V, secCompression, s.handleCompressionEvents)
	reg("/api/compression/timeseries", V, secCompression, s.handleCompressionTimeseries)
	reg("/api/compression/by-model", V, secCompression, s.handleCompressionByModel)
	reg("/api/compression/retrieval", V, secCompression, s.handleCompressionRetrieval)
	reg("/api/compression/rolling-cost", V, secCompression, s.handleCompressionRollingCost)
	reg("/api/compaction/events", V, secCompression, s.handleCompactionEvents)
	reg("/api/guard/summary", V, secSecurity, s.handleGuardSummary)
	reg("/api/guard/events", V, secSecurity, s.handleGuardEvents)
	reg("/api/guard/conformance", V, secSecurity, s.handleGuardConformance)
	reg("/api/guard/rules", V, secSecurity, s.handleGuardRules)
	reg("/api/guard/simulate", V, secSecurity, s.handleGuardSimulate)
	// guard approvals: the POST APPROVES a dangerous-command request — a security
	// consent, never a remote viewer's decision. Whole-route Local (§9.3). The
	// DELETE reject is Local (approvals/ subtree).
	reg("/api/guard/approvals", L, secSecurity, s.handleGuardApprovals)
	reg("/api/guard/approvals/", L, secSecurity, s.handleGuardApprovalDelete)
	reg("/api/guard/mcp", V, secSecurity, s.handleGuardMCP)
	reg("/api/guard/mcp/approve", L, secSecurity, s.handleGuardMCPApprove)
	// guard policy PUT WRITES the guard policy → whole-route Local. policy/backup
	// writes a backup to disk → Local.
	reg("/api/guard/policy", L, secPolicies, s.handleGuardPolicy)
	reg("/api/guard/policy/lint", V, secPolicies, s.handleGuardPolicyLint)
	reg("/api/guard/policy/backup", L, secPolicies, s.handleGuardPolicyBackup)
	reg("/api/guard/evidence", L, secSecurity, s.handleGuardEvidence)
	reg("/api/guard/evidence/download", V, secSecurity, s.handleGuardEvidenceDownload)
	reg("/api/guard/budget", V, secSecurity, s.handleGuardBudget)
	// Lines-of-code authorship (docs/plans/lines-of-code-tracking-plan-2026-09-07.md).
	// A View route: it serves counts over node-local file_changes rows and
	// carries no file content or path. The per-session read is a sub-route
	// of /api/session/ (see handleSessionDetail).
	reg("/api/loc/summary", V, secSessions, s.handleLOCSummary)
	// The editor-change ingest is owner-LOCAL: a loopback-only POST from
	// the developer's own editor, refused outright on any remotely-exposed
	// bind. It carries LINE COUNTS and a workspace-relative path that is
	// hashed before it reaches the database — never file content. See
	// loc_editor.go for the integrity posture the UI depends on.
	reg("/api/loc/editor-change", L, secSessions, s.handleLOCEditorChange)
	// Prompt-submit intervention (PHASE-3b-DASHBOARD, §8.2): status/
	// events/detectors are reads (View); clear + allow-revoke mutate
	// state (Local, same posture as /api/guard/approvals above); probe
	// spawns a subprocess that reads local hook config files, so it is
	// Local too (machine-reaching, not a remote viewer's decision).
	reg("/api/guard/prompt/status", V, secSecurity, s.handleGuardPromptStatus)
	reg("/api/guard/prompt/events", V, secSecurity, s.handleGuardPromptEvents)
	reg("/api/guard/prompt/detectors", V, secSecurity, s.handleGuardPromptDetectors)
	reg("/api/guard/prompt/clear", L, secSecurity, s.handleGuardPromptClear)
	reg("/api/guard/prompt/allow/", L, secSecurity, s.handleGuardPromptAllowDelete)
	reg("/api/guard/prompt/probe", L, secSecurity, s.handleGuardPromptProbe)
	reg("/api/cache/status", V, secCache, s.handleCacheStatus)
	reg("/api/cache/overview", V, secCache, s.handleCacheOverview)
	reg("/api/cache/timeseries", V, secCache, s.handleCacheTimeseries)
	reg("/api/cache/health", V, secCache, s.handleCacheHealth)
	reg("/api/cache/events", V, secCache, s.handleCacheEvents)
	reg("/api/cache/entry-states", V, secCache, s.handleCacheEntryStates)
	// Cloud Intelligence (Signed-in Free spine — plan §6 CI-P5). Read-only
	// node-local state; nothing here talks to the hosted service. Status lives
	// on the Configure/Settings page (secSettings); the per-session view drives
	// the SessionDetailPanel Cloud row (secSessions). Both View.
	reg("/api/cloud/status", V, secSettings, s.handleCloudStatus)
	reg("/api/cloud/session/", V, secSessions, s.handleCloudSession)
	// Cloud ACCOUNT actions (cloud_account.go): login / login/state / logout,
	// all Local — they spawn `observer cloud <verb>` on THIS machine.
	s.registerCloudAccountRoutes(reg)
	// /api/tasks — the Phase-2 session-level task-tracking rollup
	// (docs/task-tracking.md "Phase 2"): project/tool/window aggregate
	// over LoadSessionTaskReport. Filed under Analysis, the same
	// section the equivalent per-session cost/output-composition
	// breakdowns already live under; the per-session detail itself is
	// the /api/session/<id>/tasks sub-route above (secSessions).
	reg("/api/tasks", V, secAnalysis, s.handleTaskRollup)
	reg("/api/benchmarks", V, secBenchmarks, s.handleBenchmarks)
	reg("/api/benchmarks/", V, secBenchmarks, s.handleBenchmarkDetail)
	reg("/api/projects", V, secNone, s.handleProjects)
	// Agent-guidance inventory (internal/guidance). The inventory + roll-up
	// are metadata reads over already-persisted rows, classed like
	// /api/projects itself. The /file endpoint returns a project file's
	// SCRUBBED body, so it carries the terminal project-panel's class —
	// View-tier, secTerminals, with the same in-handler
	// [remote].allow_terminal_view gate.
	// The guidance inventory + summary are the Projects PAGE's own reads
	// (web/src/pages/Projects.tsx); /api/projects itself stays secNone because
	// the project picker is shared by the terminal launcher and others.
	reg("/api/projects/guidance", V, secProjects, s.handleProjectGuidance)
	reg("/api/projects/guidance/summary", V, secProjects, s.handleProjectGuidanceSummary)
	reg("/api/projects/guidance/file", V, secTerminals, s.handleProjectGuidanceFile)
	reg("/api/export.xlsx", V, secNone, s.handleExportXLSX)
	reg("/api/analysis/headline", V, secAnalysis, s.handleAnalysisHeadline)
	reg("/api/statusline", V, secNone, s.handleStatuslineTile)
	reg("/api/analysis/trend", V, secAnalysis, s.handleAnalysisTrend)
	reg("/api/analysis/movers", V, secAnalysis, s.handleAnalysisMovers)
	reg("/api/analysis/top-sessions", V, secAnalysis, s.handleAnalysisTopSessions)
	reg("/api/analysis/routing-suggestions", V, secAnalysis, s.handleAnalysisRoutingSuggestions)
	reg("/api/analysis/cost-by-hour", V, secAnalysis, s.handleAnalysisCostByHour)
	reg("/api/analysis/cost-by-dow-hour", V, secAnalysis, s.handleAnalysisCostByDowHour)
	reg("/api/analysis/cache-savings-trend", V, secAnalysis, s.handleAnalysisCacheSavingsTrend)
	// /api/config GET is a config READ (owner-trusted; §2A). Every config WRITE
	// is whole-route Local: pricing PUT, the generic section PUT, reload, profile
	// create, backup restore POST, profile mutate/delete. (Whole-route Local
	// rather than method-split — see the mechanism note above — so the GET
	// metadata/profile reads are refused remotely too, which is fail-safe.)
	reg("/api/config", V, secSettings, s.handleConfig)
	reg("/api/config/pricing", L, secSettings, s.handleConfigPricing)
	reg("/api/config/pricing/defaults", V, secSettings, s.handleConfigPricingDefaults)
	reg("/api/config/section/", L, secSettings, s.handleConfigSection)
	// Schema-driven settings (dashboard-config-management plan §2.2): the
	// generated schema + the generic batched dotted-key write. Both Local —
	// the schema describes the owner-local settings surface and the write is
	// a config mutation. governanceGuard has a body-aware arm for /keys.
	reg("/api/config/schema", L, secSettings, s.handleConfigSchema)
	reg("/api/config/keys", L, secSettings, s.handleConfigKeys)
	reg("/api/config/backup", L, secSettings, s.handleConfigBackup)
	reg("/api/config/reload", L, secSettings, s.handleConfigReload)
	reg("/api/config/profiles", L, secSettings, s.handleConfigProfiles)
	reg("/api/config/profiles/", L, secSettings, s.handleConfigProfile)
	reg("/api/tools/status", V, secSettings, s.handleToolsStatus)
	reg("/api/tools/launch", L, secSettings, s.handleToolsLaunch)
	reg("/api/setup/hooks", L, secSettings, s.handleSetupHooks)
	reg("/api/setup/mcp", L, secSettings, s.handleSetupMCP)
	reg("/api/health/doctor", V, secSettings, s.handleHealthDoctor)
	reg("/api/health/failures", V, secSettings, s.handleHealthFailures)
	reg("/api/mcp/value", V, secSettings, s.handleMCPValue)
	reg("/api/admin/restart", L, secNone, s.handleAdminRestart)
	// In-place binary update (enterprise-update-management plan §3.10).
	// CapabilityLocal: replacing the daemon's own executable is the most
	// privileged thing this surface can be asked to do, so it is refused on
	// any remotely-exposed bind before a principal is resolved — the same
	// posture as the restart route beside it.
	reg("/api/update/apply", L, secNone, s.handleUpdateApply)
	// W5 read side. CapabilityView, not Local: it discloses this node's own
	// version and update state to a viewer who can already see /api/status,
	// and the Settings -> Health card needs it on every bind mode.
	reg("/api/update/status", V, secSettings, s.handleUpdateStatus)
	// W5: the VS Code extension's self-report. CapabilityLocal, mirroring
	// /api/loc/editor-change above — a loopback report from an editor sharing
	// this machine, never something a remote caller writes.
	reg("/api/update/extension-version", L, secSettings, s.handleUpdateExtensionVersion)
	reg("/api/admin/antigravity-bridge.exe", V, secNone, s.handleAntigravityBridge)
	reg("/api/scan/run", L, secSettings, s.handleScanRun)
	reg("/api/backfill/status", V, secSettings, s.handleBackfillStatus)
	reg("/api/backfill/run", L, secSettings, s.handleBackfillRun)
	reg("/api/prune/run", L, secSettings, s.handlePruneRun)
	reg("/api/backfill/jobs", V, secSettings, s.handleBackfillJobsList)
	reg("/api/backfill/jobs/", V, secSettings, s.handleBackfillJob)
	reg("/api/health/watcher", V, secNone, s.handleWatcherHealth)
	reg("/api/enrolment/status", V, secSettings, s.handleEnrolmentStatus)
	reg("/api/enrolment/last-payload", V, secSettings, s.handleEnrolmentLastPayload)
	reg("/api/enrolment/unenroll", L, secSettings, s.handleEnrolmentUnenroll)
	// Mints a one-time enrolment token for a teammate through the org server
	// this node is already enrolled with. EXECUTE, not Local: it is a real
	// mutation (it creates a credential on the org server) so it must never
	// sit at plain View, but it is exactly the kind of action a paired remote
	// owner legitimately drives — the same tier as the session /tags and
	// vocabulary-management writes. It reaches the ORG server, never this
	// machine's config or filesystem, which is what separates it from the
	// Local tier.
	reg("/api/enrolment/invite", X, secSettings, s.handleEnrolmentInvite)
	// Remote-access management surface (dashboard-management-surface plan §9).
	// Reads are View (a paired remote owner may see state/audit/sessions — never
	// the secret, §11); mutations are Local (arm/disarm/rotate + session revoke
	// are owner-loopback-only, never a remote principal's to drive).
	reg("/api/remote/config", V, secRemote, s.handleRemoteConfig)
	reg("/api/remote/enable", L, secRemote, s.handleRemoteEnable)
	reg("/api/remote/disable", L, secRemote, s.handleRemoteDisable)
	reg("/api/remote/rotate", L, secRemote, s.handleRemoteRotate)
	reg("/api/remote/add-device", L, secRemote, s.handleRemoteAddDevice)
	// Flip [remote].allow_terminal on an armed controller WITHOUT rotating the
	// pairing secret or dropping paired devices (Local; owner-loopback only).
	reg("/api/remote/allow-terminal", L, secRemote, s.handleRemoteSetAllowTerminal)
	// Flip [remote].allow_terminal_view — the independent READ opt-in that lets a
	// remote paired device SEE / read-only-subscribe to a remote-sensitive
	// (attach/resume) terminal (§3.2). Strictly weaker than allow_terminal
	// (write). Local; owner-loopback only; hot-reloads the live VIEW gate.
	reg("/api/remote/allow-terminal-view", L, secRemote, s.handleRemoteSetAllowTerminalView)
	// Flip the post-authorization remote writer policy. Credential validation,
	// allow_terminal, TLS, pairing, and allow_terminal_view remain independent.
	// Local; owner-loopback only; hot-reloads for the next acquire.
	reg("/api/remote/allow-remote-takeover", L, secRemote, s.handleRemoteSetAllowRemoteTakeover)
	// Flip [remote].revoke_standing_on_takeover — the OPT-IN hardening that
	// makes a LOCAL writer takeover of a standing-credential remote writer also
	// revoke standing access (default false = seamless). Local; owner-loopback
	// only; no live gate (the takeover hook reads the persisted value).
	reg("/api/remote/standing-revoke-on-takeover", L, secRemote, s.handleRemoteSetRevokeStandingOnTakeover)
	// Terminal Workspace dock-grid layout (migration 073, node-local): READ is
	// View (a remote paired device renders the shared grid read-only); SAVE is
	// Local (arranging the grid is an owner action). Two single-purpose paths
	// per the whole-route classification rule above.
	reg("/api/terminal/workspace-layout", V, secTerminals, s.handleWorkspaceLayoutGet)
	reg("/api/terminal/workspace-layout/save", L, secTerminals, s.handleWorkspaceLayoutSave)
	// Execute-tier LOCAL approval (§4.γ/§6): mints a single-use terminal-control
	// capability + bound confirm for a target device+handle, returned in the
	// response body only. Owner-loopback-only (Local) — a remote principal can
	// never self-approve.
	reg("/api/remote/approve-execute", L, secRemote, s.handleRemoteApproveExecute)
	// Standing terminal-control secret (standing-terminal-access §B). The status
	// GET is a metadata-only View read (never the secret); mint (enable/rotate)
	// and revoke are owner-loopback-only Local mutations — the raw secret rides
	// the mint POST response body only.
	reg("/api/remote/standing-terminal", V, secRemote, s.handleStandingTerminalStatus)
	reg("/api/remote/standing-terminal/mint", L, secRemote, s.handleStandingTerminalMint)
	reg("/api/remote/standing-terminal/revoke", L, secRemote, s.handleStandingTerminalRevoke)
	reg("/api/remote/audit", V, secRemote, s.handleRemoteAudit)
	reg("/api/remote/sessions", V, secRemote, s.handleRemoteSessions)
	reg("/api/remote/sessions/revoke-all", L, secRemote, s.handleRemoteSessionsRevokeAll)
	reg("/api/remote/sessions/", L, secRemote, s.handleRemoteSessionRevoke)
	reg("/api/remote/selfcheck", V, secRemote, s.handleRemoteSelfcheck)
	// Tailnet detection + serve-command guidance (P1). Read-only View: runs
	// `tailscale status --json` via internal/tailnet and generates the
	// `tailscale serve` string — Observer never execs `tailscale up|serve`.
	reg("/api/remote/tailscale/status", V, secRemote, s.handleRemoteTailscaleStatus)
	reg("/api/remote/tailscale/serve", L, secRemote, s.handleRemoteTailscaleServe)
	// One-time Tailscale operator grant, run in the in-dashboard PTY so the
	// user types their sudo password once (dashboard-tailnet-guided-setup §B).
	// Local (owner-loopback only) + confirm-gated, like the arm verbs; the
	// spawned session is local-writer-only at the lease seam.
	reg("/api/remote/tailscale/operator-grant", L, secRemote, s.handleRemoteTailscaleOperatorGrant)
	// Interactive `tailscale up` login, run in the in-dashboard PTY so the auth
	// URL it prints is shown right there (dashboard-tailnet-guided-setup v2).
	// Local (owner-loopback only) + confirm-gated; the spawned session is
	// SpecSetup → local-writer-only. sudo-vs-not is resolved server-side.
	reg("/api/remote/tailscale/login", L, secRemote, s.handleRemoteTailscaleLogin)
	// Guided Tailscale install on Linux (official install.sh via sudo), run in
	// the in-dashboard PTY (dashboard-tailnet-guided-setup v2). Local +
	// confirm-gated; refused off-Linux or when tailscale is already present.
	reg("/api/remote/tailscale/install", L, secRemote, s.handleRemoteTailscaleInstall)
	// Terminal launch-policy management (P1). Whole-route Local (owner-loopback
	// only): the GET mints the confirm token + reads [terminal.launch], the PUT
	// writes the privilege-expanding allow_fresh_agent/allowed_tools/
	// allowed_project_roots block. The runs history is a metadata-only View read.
	reg("/api/terminal/policy", L, secTerminals, s.handleTerminalPolicy)
	reg("/api/terminal/runs", V, secTerminals, s.handleTerminalRuns)
	// Runtime bounds (max_concurrent / idle_timeout) — a Local write that
	// live-applies to the PTY manager with no restart, unlike the start-captured
	// launch policy above.
	reg("/api/terminal/limits", L, secTerminals, s.handleTerminalLimits)
	// Agent Arena (plan: agent-arena-terminal-multi-harness-2026-08-22.md).
	// Reads are View; the mutation POSTs auto-escalate to Execute via the
	// standard V-route rule AND re-check the confirm token in-handler
	// (spend + code-mutation surface).
	reg("/api/arena/runs", V, secTerminals, s.handleArenaRuns)
	reg("/api/arena/runs/{id}", V, secTerminals, func(w http.ResponseWriter, r *http.Request) {
		s.handleArenaRunDetail(w, r, r.PathValue("id"))
	})
	reg("/api/arena/runs/{id}/diff/{cid}", V, secTerminals, func(w http.ResponseWriter, r *http.Request) {
		s.handleArenaRunDiff(w, r, r.PathValue("id"), r.PathValue("cid"))
	})
	reg("/api/arena/runs/{id}/action/{cid}", V, secTerminals, func(w http.ResponseWriter, r *http.Request) {
		s.handleArenaCandidateAction(w, r, r.PathValue("id"), r.PathValue("cid"))
	})
	// ExtraRoutes lets a separable subsystem (e.g. internal/obs) register its
	// own /api/* handlers WITHOUT this package importing it (decision D4). Each
	// MUST carry a Capability; New() rejects an unclassified ExtraRoute when a
	// RemoteController is present (plan §4.1 fail-closed). Empty by default.
	// Admin-controlled Plane B: the node's own governance posture. VIEW and
	// secNone — it is registered UNCONDITIONALLY and can never be hidden,
	// because it is how the SPA learns what was hidden and by whom (T8's
	// "never a silent absence" rule, at the API level).
	reg("/api/governance", V, secNone, s.handleGovernance)
	for _, rt := range s.opts.ExtraRoutes {
		if rt.Pattern != "" && rt.Handler != nil {
			reg(rt.Pattern, rt.Capability, rt.Section, rt.Handler)
		}
	}
	// The RemoteController's own routes (/api/remote/pair, /whoami, /logout)
	// mount only on the remotely-exposed handler.
	if remote != nil {
		for _, rt := range remote.Routes() {
			if rt.Pattern != "" && rt.Handler != nil {
				// The controller's own pairing/whoami/logout routes are auth
				// plumbing, not a page: SectionNone, never hidden. Hiding the
				// Remote PAGE must not break the pairing handshake a remote
				// device needs to reach anything at all.
				reg(rt.Pattern, rt.Capability, SectionNone, rt.Handler)
			}
		}
	}
	return mux, capMap, sectionMap
}

// browserGuard defends the dashboard's loopback single-user deployment against
// two attacks that need no network access, only a web page the operator
// visits: CSRF (a malicious page drives a no-preflight POST to a state-changing
// endpoint — restart, config write, tool launch) and DNS rebinding (an attacker
// domain re-pointed at 127.0.0.1 becomes same-origin with the dashboard). It
// wraps the mux at ListenAndServe, where the bind address is known:
//   - unsafe methods (POST/PUT/DELETE/PATCH): the Origin (or Referer) header,
//     when present, must be same-host as the request Host, else 403. A
//     browser always sends Origin on a cross-origin POST, so this blocks CSRF;
//     non-browser clients (curl, the VS Code extension) send no Origin and are
//     unaffected.
//   - on a loopback bind (the default), EVERY request's Host header must name a
//     loopback host, else 403 — this defeats DNS rebinding, whose request
//     carries the attacker's own Host. A deliberately non-loopback bind can't
//     know its intended external host, so the Host allow-list is relaxed there
//     (start-up emits a WARN); the Origin/CSRF check still applies.
func browserGuard(next http.Handler, hostAllowed func(host string) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqHost := hostnameOnly(r.Host)
		// Host allow-list (DNS-rebind defense). On a loopback bind the predicate
		// admits any loopback host; on a remote bind it admits ONLY the
		// configured/trusted hosts — NEVER "allow any Host" (plan §4.5, the
		// dashboard.go:494 relaxation fix). A nil predicate (defensive) rejects.
		if hostAllowed == nil || !hostAllowed(reqHost) {
			http.Error(w, "forbidden: unrecognized Host header", http.StatusForbidden)
			return
		}
		// The Origin/CSRF check applies to unsafe methods AND to WebSocket
		// upgrades (plan §4.5 — enforce Origin on WS upgrades too, the
		// CVE-2018-14732 class), in addition to coder/websocket.Accept's own
		// cross-origin reject.
		if isUnsafeMethod(r.Method) || isWebSocketUpgrade(r) {
			// CSRF / cross-origin: the Origin (or Referer) host, when present,
			// must be an allowed host (not merely == reqHost) so a rebind can't
			// smuggle a same-Host cross-origin write. A "null" opaque origin is
			// treated as cross-origin.
			if origin := requestOriginHost(r); origin != "" &&
				!(strings.EqualFold(origin, reqHost) && hostAllowed(origin)) {
				http.Error(w, "forbidden: cross-origin request", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// isWebSocketUpgrade reports whether r is a WebSocket upgrade handshake.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

// hostAllowlistPredicate returns a Host-allow predicate for a remotely-exposed
// bind (plan §4.5): a request Host is allowed only if it case-insensitively
// matches one of the explicit allow-list entries (the configured bind address +
// [remote].trusted_hosts). Never admits an arbitrary Host.
func hostAllowlistPredicate(allowed []string) func(string) bool {
	set := make(map[string]struct{}, len(allowed))
	for _, h := range allowed {
		if hn := strings.ToLower(hostnameOnly(strings.TrimSpace(h))); hn != "" {
			set[hn] = struct{}{}
		}
	}
	return func(host string) bool {
		_, ok := set[strings.ToLower(host)]
		return ok
	}
}

// hostnameOnly strips the port (and IPv6 brackets) from a host[:port] value,
// returning the bare hostname/IP. It tolerates a missing port.
func hostnameOnly(hostport string) string {
	if hostport == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.Trim(hostport, "[]")
}

// hostIsLoopback reports whether host is a loopback name or IP (localhost,
// 127.0.0.0/8, ::1).
func hostIsLoopback(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// requestOriginHost returns the hostname of the request's Origin header, or
// its Referer host as a fallback. Empty when neither is present (a
// same-origin/non-browser request); "null" opaque origins return a non-empty
// sentinel so an unsafe method from a sandboxed context is treated as
// cross-origin.
func requestOriginHost(r *http.Request) string {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	if origin == "" {
		return ""
	}
	if origin == "null" {
		return "null"
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return "null"
	}
	return hostnameOnly(u.Host)
}

// ListenAndServe runs the dashboard on addr until ctx is cancelled.
//
// Per the plan §4.6 atomic-safety rule, a non-loopback bind FAILS CLOSED
// (returns an error, refusing to start) unless the remote-access security
// substrate is active (Options.Remote != nil && Ready()). This closes the
// historical `--addr 0.0.0.0` unauthenticated-RCE hole: pre-Phase-1 no
// controller is ever wired, so a non-loopback bind is simply refused. A
// loopback bind is unchanged.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	if err := remoteExposureAllowed(addr, s.opts.Remote); err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.guardedHandler(addr),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// processStartedAt approximates the daemon's start time — the dashboard
// server is constructed once inside `observer start` / `observer
// dashboard`, so package-init time is the serving process's start. The
// restart-pending banner compares config-save timestamps against this
// to auto-clear once the operator has restarted.
var processStartedAt = time.Now().UTC()

// handleStatus serves GET /api/status — the daemon's own state (row counts,
// schema version, last-seen-per-tool, DB size).
//
// The snapshot comes from statusSnapshot, NOT straight from diag.Snapshot:
// the scan is an unfiltered COUNT(*) over a dozen tables and the SPA polls
// this endpoint from three places at once, so it is memoized per
// statusSnapshotTTL with singleflight on a miss (status_cache.go).
//
// Version / StartedAt / UptimeSeconds are stamped AFTER cache retrieval and
// are deliberately outside the cache: they describe THIS process at THIS
// instant, and uptime in particular is the one field on this endpoint a human
// watches move. Freezing it for the TTL would be the exact dishonesty the
// cache is not allowed to introduce. The value returned by statusSnapshot is
// a copy, so stamping mutates only this request's snapshot.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	snap, err := s.statusSnapshot(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	snap.Version = s.opts.Version
	snap.StartedAt = processStartedAt
	snap.UptimeSeconds = int64(time.Since(processStartedAt).Seconds())
	writeJSON(w, snap)
}

// handleStatusScoped serves /api/status/scoped?days=&tool=&project= — the
// window/tool/project-scoped equivalent of /api/status's `counts` block.
// Drives the Overview + Analysis headline tiles that previously sourced
// from the global lifetime counts and showed the same number regardless
// of filter — a "window 30d" chip over an all-time value.
//
// Returned counts:
//   - sessions: distinct session IDs touched in the window
//   - api_turns: api_turns rows in the window (the proxy-accurate source)
//   - token_usage: token_usage rows in the window (the JSONL fallback)
//   - actions: actions rows in the window
//
// All counts honor the same `tool` + `project` filters as the rest of
// the dashboard so the surface stays internally consistent.
func (s *Server) handleStatusScoped(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")

	// since/hours/days all resolve through the shared helper; `until`
	// (when resolved) is applied as an exclusive upper bound to every
	// subquery so a bounded window (e.g. a Calendar day-click that sends
	// since+until) counts only in-window rows. `days` is still echoed
	// verbatim below.
	sinceT, untilT := windowRange(r, 30, 1, 36500)
	since := sinceT.Format(time.RFC3339Nano)
	// upper builds the "< ?" upper-bound fragment (empty when no until)
	// against the given timestamp column, appending the bound value to
	// the caller's arg slice.
	upper := func(col string, args []any) (string, []any) {
		if untilT.IsZero() {
			return "", args
		}
		return " AND " + col + " < ?", append(args, untilT.Format(time.RFC3339Nano))
	}

	// Helper: append the tool+project filter to a query whose primary
	// table is aliased `x` and has `x.session_id` + `x.project_id`
	// (api_turns) — or to one that has only `x.session_id` so we walk
	// through sessions for project (token_usage / sessions / actions).
	scoped := func(viaSession bool) (extra string, args []any) {
		if project != "" {
			// Identical whether reached via session_id or project_id: both
			// query paths expose project_id on the aliased table x.
			extra += " AND project_id IN (SELECT id FROM projects WHERE root_path = ?)"
			args = append(args, project)
		}
		if tool != "" {
			if viaSession {
				extra += " AND tool = ?"
			} else {
				extra += " AND session_id IN (SELECT id FROM sessions WHERE tool = ?)"
			}
			args = append(args, tool)
		}
		return
	}

	type counts struct {
		Days       int   `json:"days"`
		Sessions   int64 `json:"sessions"`
		APITurns   int64 `json:"api_turns"`
		TokenUsage int64 `json:"token_usage"`
		Actions    int64 `json:"actions"`
	}
	out := counts{Days: days}

	// sessions: started_at in window, session-table direct. Marker-only
	// probe sessions are excluded so this stat agrees with the Sessions list.
	sExtra, sArgs := scoped(true) // sessions has tool + project_id directly
	sUpper, sArgs := upper("started_at", sArgs)
	sQ := `SELECT COUNT(*) FROM sessions WHERE started_at >= ? AND ` +
		nonEmptySessionPredicateSessions + sExtra + sUpper
	_ = s.db().QueryRowContext(r.Context(), sQ, append([]any{since}, sArgs...)...).Scan(&out.Sessions)

	// api_turns
	atExtra, atArgs := scoped(false) // api_turns: project_id direct, tool via session
	atUpper, atArgs := upper("timestamp", atArgs)
	atQ := `SELECT COUNT(*) FROM api_turns WHERE timestamp >= ?` + atExtra + atUpper
	_ = s.db().QueryRowContext(r.Context(), atQ, append([]any{since}, atArgs...)...).Scan(&out.APITurns)

	// token_usage: no project_id column → walk through sessions for project
	tuExtra := ""
	tuArgs := []any{}
	if project != "" {
		tuExtra += " AND session_id IN (SELECT id FROM sessions WHERE project_id = (SELECT id FROM projects WHERE root_path = ?))"
		tuArgs = append(tuArgs, project)
	}
	if tool != "" {
		tuExtra += " AND session_id IN (SELECT id FROM sessions WHERE tool = ?)"
		tuArgs = append(tuArgs, tool)
	}
	tuUpper, tuArgs := upper("timestamp", tuArgs)
	tuQ := `SELECT COUNT(*) FROM token_usage WHERE timestamp >= ?` + tuExtra + tuUpper
	_ = s.db().QueryRowContext(r.Context(), tuQ, append([]any{since}, tuArgs...)...).Scan(&out.TokenUsage)

	// actions: project_id direct, tool direct
	aExtra := ""
	aArgs := []any{}
	if project != "" {
		aExtra += " AND project_id = (SELECT id FROM projects WHERE root_path = ?)"
		aArgs = append(aArgs, project)
	}
	if tool != "" {
		aExtra += " AND tool = ?"
		aArgs = append(aArgs, tool)
	}
	aUpper, aArgs := upper("timestamp", aArgs)
	aQ := `SELECT COUNT(*) FROM actions WHERE timestamp >= ?` + aExtra + aUpper
	_ = s.db().QueryRowContext(r.Context(), aQ, append([]any{since}, aArgs...)...).Scan(&out.Actions)

	writeJSON(w, out)
}

func (s *Server) handleCost(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	groupBy := r.URL.Query().Get("group_by")
	if groupBy == "" {
		groupBy = "model"
	}
	proj := r.URL.Query().Get("project")
	tool := r.URL.Query().Get("tool")
	source := r.URL.Query().Get("source")
	if source == "" {
		source = "auto"
	}
	since, until := windowRange(r, 30, 1, 36500)
	summary, err := s.opts.CostEngine.Summary(r.Context(), s.db(), cost.Options{
		Days:        days,
		Since:       since,
		Until:       until,
		GroupBy:     cost.GroupBy(groupBy),
		Source:      cost.Source(source),
		ProjectRoot: proj,
		Tool:        tool,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	// Spec §13 cost-view annotation: when the rollup keys on a
	// dimension the cache engine indexes (session_id or model),
	// attach per-row cache annotations via the shared
	// loadCacheAnnotationsByKey helper. Empty for other groupings
	// (project / tool) — cache_events doesn't carry those columns
	// natively; the /api/cache/overview endpoint serves the cross-
	// session per-project rollup operators need.
	if column := costAnnotationColumn(groupBy); column != "" {
		keys := make([]string, 0, len(summary.Rows))
		for _, row := range summary.Rows {
			keys = append(keys, row.Key)
		}
		if ann, derr := loadCacheAnnotationsByKey(r.Context(), s.db(), column, keys); derr == nil && len(ann) > 0 {
			writeJSON(w, costSummaryWithCache{Summary: summary, CacheByKey: ann})
			return
		}
	}
	writeJSON(w, summary)
}

// costSummaryWithCache wraps cost.Summary with the per-row cache
// annotation map. The embedded Summary keeps the existing JSON
// shape intact (backward-compat for clients that don't read
// cache_by_key); cache_by_key is the new field that the Cost
// page reads to render the per-row cache pill.
type costSummaryWithCache struct {
	cost.Summary
	CacheByKey map[string]*SessionCacheAnnotation `json:"cache_by_key,omitempty"`
}

// costAnnotationColumn maps cost group_by values to the
// cache_events column they correspond to. Returns "" when the
// grouping isn't directly indexable by cache_events (project /
// tool / pricing_source — for those, the Cache overview page
// serves the cross-session rollup operators need).
func costAnnotationColumn(groupBy string) string {
	switch groupBy {
	case "session":
		return "session_id"
	case "model":
		return "model"
	}
	return ""
}

func (s *Server) handleCodexSupport(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 0, 0, 36500)
	project := r.URL.Query().Get("project")
	snap, err := buildCodexSupportSnapshot(r.Context(), s.db(), days, project)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, snap)
}

// handleDiscover serves /api/discover. Paginates the stale_reads and
// repeated_commands panels independently — stale_page/stale_limit and
// repeated_page/repeated_limit query params, defaulting to 20 rows per
// page. Backend caps total results at 500 per panel (discover SQL runs
// once per request and the dashboard surfaces top-N anyway); both
// panels expose stale_total / repeated_total for the pager UI.
// handleSuggestions — GET /api/suggestions?days=N&project=R
// [&category=cost|latency|quality|hygiene][&severity=…][&detector=…]
// [&page=P&limit=L]. Computed on read by the advisor engine (spec §15.7;
// thresholds per docs/plans/advisor-calibration-2026-06-10.md). Filters
// and pagination are presentation concerns and live here, not in the
// engine; totals and the per-category rollup reflect the FILTERED set
// (pre-pagination) so the header reconciles with what the list shows.
func (s *Server) handleSuggestions(w http.ResponseWriter, r *http.Request) {
	// Max 36500 (~100y) so the global "all" window (36500 days) isn't
	// clamped to a year — matches the other dashboard endpoints' all-time.
	days := intArg(r, "days", 14, 1, 36500)
	page := intArg(r, "page", 1, 1, 1_000_000)
	limit := intArg(r, "limit", 20, 1, 200)
	proj := r.URL.Query().Get("project")
	tool := r.URL.Query().Get("tool")
	category := r.URL.Query().Get("category")
	severity := r.URL.Query().Get("severity")
	detector := r.URL.Query().Get("detector")

	// X3.1 posture inputs: effective modes from the on-disk config plus
	// the §R22 shadow signal through the one gate owner. Best-effort —
	// neither a config-load nor a shadow-read failure may take down the
	// suggestions report.
	guardMode, routingMode := "off", "off"
	var shadow *advisor.ShadowSignal
	if cfg, cerr := loadConfigForDashboard(s.opts.ConfigPath); cerr == nil {
		if cfg.Guard.Enabled {
			guardMode = cfg.Guard.Mode
		}
		if cfg.Routing.Enabled {
			routingMode = cfg.Routing.Mode
		}
		st := store.New(s.opts.DB)
		if sh, serr := st.AdviseShadowSignal(r.Context(), days, enginePriceFn(s.opts.CostEngine)); serr == nil {
			shadow = &advisor.ShadowSignal{
				AdviseDecisions: sh.AdviseDecisions,
				WouldReroute:    sh.WouldReroute,
				WouldSaveUSD:    sh.WouldSaveUSD,
				QualityFlags:    sh.QualityFlags,
				MinDecisions:    sh.MinDecisions,
				Ready:           sh.ReadyToPromote,
			}
		}
	}
	rep, err := advisor.Run(r.Context(), s.db(), advisor.Options{
		WindowDays:    days,
		ProjectRoot:   proj,
		Tool:          tool,
		CostEngine:    s.opts.CostEngine,
		GuardMode:     guardMode,
		RoutingMode:   routingMode,
		RoutingShadow: shadow,
	})
	if err != nil {
		writeErr(w, err)
		return
	}

	filtered := rep.Suggestions[:0:0]
	byCategory := map[string]float64{}
	byDetector := map[string]int{}
	var totUSD, totMin float64
	for _, sg := range rep.Suggestions {
		if (category != "" && sg.Category != category) ||
			(severity != "" && sg.Severity != severity) ||
			(detector != "" && sg.Detector != detector) {
			continue
		}
		filtered = append(filtered, sg)
		byCategory[sg.Category] += sg.SavingsUSD
		byDetector[sg.Detector]++
		totUSD += sg.SavingsUSD
		totMin += sg.SavingsMin
	}
	total := len(filtered)
	start := (page - 1) * limit
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}

	writeJSON(w, map[string]any{
		"suggestions":       filtered[start:end],
		"total_count":       total,
		"page":              page,
		"limit":             limit,
		"total_savings_usd": round2f(totUSD),
		"total_savings_min": round2f(totMin),
		"by_category":       byCategory,
		"by_detector":       byDetector,
		"window_days":       rep.WindowDays,
		"generated_at":      rep.GeneratedAt,
		"sessions_scanned":  rep.SessionsScanned,
	})
}

func round2f(v float64) float64 { return float64(int64(v*100+0.5)) / 100 }

// handleSuggestionState — POST /api/suggestions/state with JSON
// {dedup_key, status: dismissed|snoozed|acted, snooze_days?}. State is
// node-local (advisor_state, migration 039; never org-pushed).
func (s *Server) handleSuggestionState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		DedupKey   string `json:"dedup_key"`
		Status     string `json:"status"`
		SnoozeDays int    `json:"snooze_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DedupKey == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	var until time.Time
	if req.Status == advisor.StatusSnoozed {
		d := req.SnoozeDays
		if d <= 0 {
			d = 7
		}
		until = now.AddDate(0, 0, d)
	}
	if err := advisor.SetState(r.Context(), s.db(), req.DedupKey, req.Status, until, now); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	stalePage := intArg(r, "stale_page", 1, 1, 1_000_000)
	staleLimit := intArg(r, "stale_limit", 20, 1, 500)
	repeatedPage := intArg(r, "repeated_page", 1, 1, 1_000_000)
	repeatedLimit := intArg(r, "repeated_limit", 20, 1, 500)
	proj := r.URL.Query().Get("project")
	tool := r.URL.Query().Get("tool")

	// Cap the per-panel SQL limit at 500 — generous enough for realistic
	// dashboards while keeping a single discover.Run cheap.
	report, err := discover.New(s.db()).Run(r.Context(), discover.Options{
		ProjectRoot: proj, Tool: tool, Days: days, Limit: 500,
	})
	if err != nil {
		writeErr(w, err)
		return
	}

	staleTotal := len(report.StaleReads)
	staleStart := (stalePage - 1) * staleLimit
	staleEnd := staleStart + staleLimit
	if staleStart > staleTotal {
		staleStart = staleTotal
	}
	if staleEnd > staleTotal {
		staleEnd = staleTotal
	}
	staleSlice := report.StaleReads[staleStart:staleEnd]

	repTotal := len(report.RepeatedCommands)
	repStart := (repeatedPage - 1) * repeatedLimit
	repEnd := repStart + repeatedLimit
	if repStart > repTotal {
		repStart = repTotal
	}
	if repEnd > repTotal {
		repEnd = repTotal
	}
	repSlice := report.RepeatedCommands[repStart:repEnd]

	// Blended input rate — derived from the user's actual last-30d
	// api_turns (per-model prompt-token volume × per-model rate) so
	// the ~$ wasted KPI tile reflects real model mix rather than a
	// hardcoded representative rate. Falls back to the default
	// (claude-sonnet-4 input rate) when no proxy data is available.
	blendedRate, err := s.opts.CostEngine.BlendedInputRate(r.Context(), s.db(), 30)
	if err != nil {
		s.opts.Logger.Warn("discover: blended input rate", "err", err)
		blendedRate = cost.DefaultBlendedInputRate
	}

	writeJSON(w, map[string]any{
		"stale_reads":                    staleSlice,
		"stale_total":                    staleTotal,
		"stale_page":                     stalePage,
		"stale_limit":                    staleLimit,
		"repeated_commands":              repSlice,
		"repeated_total":                 repTotal,
		"repeated_page":                  repeatedPage,
		"repeated_limit":                 repeatedLimit,
		"cross_tool_files":               report.CrossToolFiles,
		"native_vs_bash":                 report.NativeVsBash,
		"summary":                        report.Summary,
		"blended_input_rate_per_million": blendedRate,
	})
}

// emptySessionMarkers are the lifecycle / meta action types that a hook
// fires for an empty Windows-CC probe session (CLAUDE.md loaded, settings
// touched, session opened then closed) WITHOUT any real work. A session
// whose only rows are these — and which has no token_usage / api_turns —
// is contentless and must not surface on the dashboard. They slip past
// store.Ingest's session_end bootstrap guard because they can legitimately
// PRECEDE a real session (instructions_loaded / config_change fire at
// session start, before the watcher parses the transcript), so dropping
// them at ingestion would strip them from real sessions too. Filtering at
// the read layer — where a session's emptiness is finally knowable — keeps
// the markers on real sessions while hiding the probes.
const emptySessionMarkers = `'instructions_loaded','config_change','session_start','session_end','setup','notification'`

// nonEmptySessionPredicate{S,Sessions} are SQL boolean expressions (no
// bound args) that are true only for sessions with real content: at least
// one substantive action, or any token_usage / api_turns row. They are
// compile-time constants (string-literal + const concat) so they fold to
// a single constant and never trip gosec's G202 SQL-concat taint check.
// Two variants because the enclosing queries use different sessions-table
// aliases: "s" for handleSessions' joined query, "sessions" for the
// unaliased overview / calendar counts.
const nonEmptySessionPredicateS = `(EXISTS (SELECT 1 FROM actions a WHERE a.session_id = s.id` +
	` AND a.action_type NOT IN (` + emptySessionMarkers + `))` +
	` OR EXISTS (SELECT 1 FROM token_usage tu WHERE tu.session_id = s.id)` +
	` OR EXISTS (SELECT 1 FROM api_turns t WHERE t.session_id = s.id))`

const nonEmptySessionPredicateSessions = `(EXISTS (SELECT 1 FROM actions a WHERE a.session_id = sessions.id` +
	` AND a.action_type NOT IN (` + emptySessionMarkers + `))` +
	` OR EXISTS (SELECT 1 FROM token_usage tu WHERE tu.session_id = sessions.id)` +
	` OR EXISTS (SELECT 1 FROM api_turns t WHERE t.session_id = sessions.id))`

// parseSessionsSortParams reads sort_by / sort_dir from the request, clamping
// sort_by to a fixed allow-list (defaulting to started_at) so the value is
// never interpolated unchecked into SQL. Direction defaults to descending; only
// the literal "asc" flips it.
func parseSessionsSortParams(r *http.Request) (sortBy string, desc bool) {
	sortBy = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sort_by")))
	switch sortBy {
	case "session", "tool", "project", "started_at", "elapsed", "actions",
		"input", "cache_r", "cache_w", "output", "cost", "quality",
		"errors", "redundancy", "favorite", "rating", "ai_code_lines":
	default:
		sortBy = "started_at"
	}
	desc = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sort_dir"))) != "asc"
	return sortBy, desc
}

// sessionsSortRequiresInMemory reports whether a sort column is computed in Go
// (elapsed) or via the cost engine (token/cost buckets) and therefore needs the
// full filtered set loaded before paging, rather than an SQL ORDER BY + LIMIT.
func sessionsSortRequiresInMemory(sortBy string) bool {
	switch sortBy {
	// ai_code_lines is a CORRELATED SUBQUERY over file_changes, not a
	// stored column. Putting it in the SQL ORDER BY would make the
	// database evaluate that subquery for every session in the corpus
	// just to page twenty rows; sorting the already-loaded filtered set
	// in Go costs the same subqueries the SELECT already ran.
	case "elapsed", "input", "cache_r", "cache_w", "output", "cost", "ai_code_lines":
		return true
	}
	return false
}

// sessionsSortRequiresCost reports whether the sort column needs the cost
// engine rollup attached before sorting (the token/cost buckets). "elapsed" is
// in-memory but does NOT need cost, so it is excluded here.
func sessionsSortRequiresCost(sortBy string) bool {
	switch sortBy {
	case "input", "cache_r", "cache_w", "output", "cost":
		return true
	}
	return false
}

// sessionsSQLOrderClause maps an allow-listed sort column to a SQL ORDER BY
// fragment (used only for the cheap, SQL-sortable columns). The sort column is
// never interpolated directly — it selects a fixed expression. A stable
// tiebreak on started_at DESC, id ASC keeps pagination deterministic.
func sessionsSQLOrderClause(sortBy string, desc bool) string {
	dir := "ASC"
	if desc {
		dir = "DESC"
	}
	expr := "s.started_at"
	switch sortBy {
	case "session":
		expr = "s.id"
	case "tool":
		expr = "s.tool"
	case "project":
		expr = "COALESCE(p.root_path, '')"
	case "actions":
		expr = "total_actions"
	case "quality":
		expr = "COALESCE(s.quality_score, -1.0)"
	case "errors":
		expr = "COALESCE(s.error_rate, -1.0)"
	case "redundancy":
		expr = "COALESCE(s.redundancy_ratio, -1.0)"
	case "favorite":
		// EXISTS rather than a LEFT JOIN so the shared FROM clause (and every
		// caller of it — data / total / scored_count) stays untouched; a
		// session with no annotation row sorts as 0. Default direction is DESC,
		// so `sort_by=favorite` alone means "starred first".
		expr = "(SELECT COUNT(*) FROM session_annotations sa" +
			" WHERE sa.session_id = s.id AND sa.favorite = 1)"
	case "rating":
		// Scalar subquery, same shape as favorite: an unrated session (no row,
		// or rating 0) sorts as 0. Default direction is DESC, so
		// `sort_by=rating` alone means "highest-rated first"; sort_dir=asc
		// surfaces the worst-rated sessions (rating 0/unrated sink to the top).
		expr = "COALESCE((SELECT sa.rating FROM session_annotations sa" +
			" WHERE sa.session_id = s.id), 0)"
	}
	return expr + " " + dir + ", s.started_at DESC, s.id ASC"
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	limit := intArg(r, "limit", 20, 1, 500)
	page := intArg(r, "page", 1, 1, 1_000_000)
	offset := (page - 1) * limit
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")
	// days=0 (or missing) means "no time filter" — preserves the prior
	// behaviour for callers that haven't been updated. Frontend always
	// passes the global window; CLI / older API consumers may not. The
	// shared windowRange helper resolves since/hours/days (and an
	// optional `until` upper bound) with the same fail-open precedence;
	// a zero `since` means "no lower bound".
	since, until := windowRange(r, 0, 0, 36500)
	// Echo the literal `days` param for response-shape compat (the
	// frontend reads it back). It stays independent of the resolved
	// window: an hours=/since= request echoes days as its default 0 —
	// the closest legacy equivalent — while the actual filtering uses
	// since/until above.
	days := intArg(r, "days", 0, 0, 36500)
	// from_date / to_date — YYYY-MM-DD prefix filter against
	// substr(s.started_at, 1, 10). Mirrors the /api/actions params so
	// the Sessions Calendar day-click can server-side scope to that
	// day's sessions instead of substring-filtering the loaded page
	// (which silently dropped any day outside the page-50 slice and
	// produced a misleading "No sessions match" empty state for any
	// day older than the loaded rows).
	fromDate := r.URL.Query().Get("from_date")
	toDate := r.URL.Query().Get("to_date")

	// Server-side sort. Cheap columns sort in SQL; columns computed in Go
	// (elapsed) or via the cost engine (token/cost buckets) need the full
	// filtered set attached + sorted before paging — otherwise the page-local
	// client sort surfaces "the most expensive of the visible 20", not the
	// most expensive session overall.
	sortBy, sortDesc := parseSessionsSortParams(r)
	inMemorySort := sessionsSortRequiresInMemory(sortBy)
	costSort := sessionsSortRequiresCost(sortBy)

	// Build optional WHERE clause over sessions + a project-id lookup.
	var where []string
	var args []any
	if tool != "" {
		where = append(where, "s.tool = ?")
		args = append(args, tool)
	}
	if project != "" {
		where = append(where, "s.project_id = (SELECT id FROM projects WHERE root_path = ?)")
		args = append(args, project)
	}
	// Session-classification filters (plan §4). `tag` is REPEATABLE with AND
	// semantics — one EXISTS subquery per tag — and `favorite=1` is an EXISTS on
	// session_annotations. Both land in the SHARED `where` slice so the data
	// query, the pagination `total`, and `scored_count` all agree on which
	// sessions exist (the coherence rule the window predicate already follows).
	// A malformed tag is a 400 rather than a silent no-match: returning the
	// unfiltered list under a filter the user asked for would lie.
	//
	// The repeatable param is DEDUPED (after normalization) and CAPPED at
	// maxSessionTagFilters: each accepted tag appends a correlated EXISTS
	// subquery to a WHERE clause that also drives the `total` COUNT and
	// scored_count, so an unbounded `?tag=` list is an authenticated
	// amplification lever (one cheap request → an arbitrarily long EXISTS
	// chain executed three times). Duplicates are dropped rather than rejected:
	// `?tag=x&tag=X` is the same filter written twice, and answering it is more
	// useful than 400-ing it.
	seenTags := make(map[string]struct{}, 4)
	for _, raw := range r.URL.Query()["tag"] {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		tag, err := store.NormalizeTag(raw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if _, dup := seenTags[tag]; dup {
			continue
		}
		if len(seenTags) >= maxSessionTagFilters {
			http.Error(w, fmt.Sprintf("too many tag filters: at most %d distinct tags per request", maxSessionTagFilters),
				http.StatusBadRequest)
			return
		}
		seenTags[tag] = struct{}{}
		where = append(where, "EXISTS (SELECT 1 FROM session_tags st WHERE st.session_id = s.id AND st.tag = ?)")
		args = append(args, tag)
	}
	if v := strings.TrimSpace(r.URL.Query().Get("favorite")); v == "1" || strings.EqualFold(v, "true") {
		where = append(where, "EXISTS (SELECT 1 FROM session_annotations sa WHERE sa.session_id = s.id AND sa.favorite = 1)")
	}
	if !since.IsZero() {
		sinceStr := since.Format(time.RFC3339Nano)
		// Reconcile the Sessions window with the cost engine. /api/cost and
		// /api/models window by turn/token TIMESTAMP (cost/summary.go), so a
		// long-running session that STARTED before the window but has RECENT
		// turns contributes there. Windowing on started_at alone would exclude
		// it here, making the Sessions tab under-count vs the Cost tab. Include
		// a session if it started in-window OR has any in-window activity
		// (action / api_turn / token_usage). The shared `where` slice carries
		// this predicate into the pagination `total` COUNT and scored_count too,
		// so the page math stays coherent. (A row dated >N days ago can thus
		// surface in an N-day view; its metadata reflects the whole session,
		// its cost is windowed — consistent with /api/cost.)
		//
		// When `until` is set, every branch is a COMPLETE [since, until)
		// test: the started_at bound and each activity EXISTS carries the
		// same exclusive upper bound, so a bounded window (e.g. a Calendar
		// day-click) can't leak a session whose only in-window activity is
		// actually AFTER `until`.
		if !until.IsZero() {
			untilStr := until.Format(time.RFC3339Nano)
			where = append(where, `((s.started_at >= ? AND s.started_at < ?)
				OR EXISTS (SELECT 1 FROM actions a2 WHERE a2.session_id = s.id AND a2.timestamp >= ? AND a2.timestamp < ?)
				OR EXISTS (SELECT 1 FROM api_turns at2 WHERE at2.session_id = s.id AND at2.timestamp >= ? AND at2.timestamp < ?)
				OR EXISTS (SELECT 1 FROM token_usage tu2 WHERE tu2.session_id = s.id AND tu2.timestamp >= ? AND tu2.timestamp < ?))`)
			args = append(args, sinceStr, untilStr, sinceStr, untilStr, sinceStr, untilStr, sinceStr, untilStr)
		} else {
			where = append(where, `(s.started_at >= ?
				OR EXISTS (SELECT 1 FROM actions a2 WHERE a2.session_id = s.id AND a2.timestamp >= ?)
				OR EXISTS (SELECT 1 FROM api_turns at2 WHERE at2.session_id = s.id AND at2.timestamp >= ?)
				OR EXISTS (SELECT 1 FROM token_usage tu2 WHERE tu2.session_id = s.id AND tu2.timestamp >= ?))`)
			args = append(args, sinceStr, sinceStr, sinceStr, sinceStr)
		}
	} else if !until.IsZero() {
		// No lower bound: window has only an upper bound. There are no
		// activity-EXISTS branches to reconcile (those exist solely to
		// pull in sessions that STARTED before `since`), so a plain
		// started_at upper bound is the complete test.
		where = append(where, "s.started_at < ?")
		args = append(args, until.Format(time.RFC3339Nano))
	}
	// from_date / to_date stay day-grained (substr) for compat, but the
	// genuinely-new sub-day params win when both are present: skip the
	// legacy lower/upper bound only if since/hours (resp. until) actually
	// RESOLVED. A present-but-malformed `until` (or `since`/`hours`) fails
	// open in windowRange, so keying suppression off resolution — not raw
	// presence — means the legacy param still applies in that case.
	// Legacy `days`+from_date keeps its historical AND behavior because
	// `days` is not one of the "new" params gated here.
	newLower, newUpper := windowBoundsResolved(r)
	if fromDate != "" && !newLower {
		where = append(where, "substr(s.started_at, 1, 10) >= ?")
		args = append(args, fromDate)
	}
	if toDate != "" && !newUpper {
		where = append(where, "substr(s.started_at, 1, 10) <= ?")
		args = append(args, toDate)
	}
	// Hide contentless probe sessions (marker-only, no tokens/turns). Added
	// to the shared `where` so the data query, the pagination `total`, and
	// the `scored_count` all agree on which sessions exist.
	where = append(where, nonEmptySessionPredicateS)
	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// Total row count for pagination. Must share the same WHERE as the
	// data query so page math stays coherent.
	var total int
	countArgs := append([]any{}, args...)
	if err := s.db().QueryRowContext(
		r.Context(),
		"SELECT COUNT(*) FROM sessions s "+whereClause, countArgs...,
	).Scan(&total); err != nil {
		writeErr(w, err)
		return
	}

	// scored_count tells the frontend whether to render the Quality /
	// Errors / Redundancy columns. None of those fields are populated
	// unless `observer score` has run — pre-fix the columns rendered
	// dashes for every row, wasting horizontal space and misleading
	// users into thinking scoring is unsupported. Same WHERE as `total`
	// so the count is consistent with the visible filter.
	var scoredCount int
	_ = s.db().QueryRowContext(
		r.Context(),
		"SELECT COUNT(*) FROM sessions s "+whereClause+
			func() string {
				if whereClause == "" {
					return "WHERE s.quality_score IS NOT NULL"
				}
				return " AND s.quality_score IS NOT NULL"
			}(),
		countArgs...,
	).Scan(&scoredCount)

	// total_actions is computed live; the sessions.total_actions stored
	// column is never advanced past 0 by any writer (UpsertSession's MAX
	// merge keeps it at whatever the first batch wrote, scoring computes
	// len(actions) only into a transient struct). Subquery is cheap at
	// LIMIT 20 and avoids a stale-column class of bug.
	dataArgs := append([]any{}, args...)
	// Cheap columns sort + page in SQL. In-memory columns (elapsed / token /
	// cost buckets) load the FULL filtered set ordered by started_at and are
	// sorted + paginated in Go below, after the per-session cost/tokens attach.
	orderAndLimit := "ORDER BY " + sessionsSQLOrderClause(sortBy, sortDesc) + " LIMIT ? OFFSET ?"
	if inMemorySort {
		orderAndLimit = "ORDER BY s.started_at DESC, s.id ASC"
	} else {
		dataArgs = append(dataArgs, limit, offset)
	}
	// last_seen falls back to MAX(actions.timestamp) when ended_at is
	// NULL (open session) so DurationSeconds is still meaningful for
	// in-flight sessions. Subqueries are cheap at LIMIT 20.
	rows, err := s.db().QueryContext(r.Context(),
		//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments, ORDER BY column from a fixed allow-list, and any IN placeholder list) is built from code constants; all values are bound via ? args.
		`SELECT s.id, s.tool, COALESCE(p.root_path, ''), s.started_at,
		        COALESCE(s.ended_at,
		                 (SELECT MAX(a.timestamp) FROM actions a WHERE a.session_id = s.id),
		                 '') AS last_seen_at,
		        (SELECT COUNT(*) FROM actions a WHERE a.session_id = s.id) AS total_actions,
		        (SELECT COUNT(*) FROM actions a WHERE a.session_id = s.id AND a.is_sidechain = 1) AS sidechain_actions,
		        -- Lines-of-code authorship (migration 103) is NOT selected
		        -- here. It is attached below from the store seam
		        -- (store.LoadSessionLOCLines), because internal/store owns
		        -- file_changes and this was the only raw read of that table
		        -- outside it. The two copies of the collapse rule drifted:
		        -- the card summed each digest group's MIN(id) representative
		        -- while this query took the group's MAX line count, so a
		        -- codex invocation/executor pair whose executor landed at
		        -- the lower id made the list and the card report different
		        -- numbers for one session. One owner, one rule.
		        s.quality_score, s.error_rate, s.redundancy_ratio,
		        s.redundancy_ratio_wasteful, s.stale_reads_wasteful, s.stale_reads_necessary
		 FROM sessions s
		 LEFT JOIN projects p ON p.id = s.project_id
		 `+whereClause+` `+orderAndLimit, dataArgs...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()
	type sessRow struct {
		ID        string `json:"id"`
		Tool      string `json:"tool"`
		Project   string `json:"project"`
		StartedAt string `json:"started_at"`
		// LastSeenAt is COALESCE(ended_at, MAX(actions.timestamp)). Drives
		// DurationSeconds for both closed and still-open sessions.
		LastSeenAt string `json:"last_seen_at,omitempty"`
		// DurationSeconds = LastSeenAt - StartedAt, computed server-side
		// so the frontend formatter doesn't need to parse timestamps.
		// Zero when LastSeenAt is empty (no actions yet) or when start
		// is unparseable. Surfaced as "Elapsed" in the Sessions table.
		DurationSeconds int64 `json:"duration_seconds"`
		TotalActions    int   `json:"total_actions"`
		// SidechainActionCount is the count of actions emitted inside
		// any sub-agent runtime spawned by this session (Claude Code's
		// `Agent` tool). Sub-agents share the parent's session_id;
		// this is the only structural marker. > 0 implies the session
		// fanned out work to sub-agents — surfaced as a "sidechain N"
		// pill on the Sessions tab.
		SidechainActionCount int `json:"sidechain_action_count"`
		// AICodeLines is the agent-authored CODE lines this session
		// touched: added + modified, comments / blanks / whitespace-only
		// reflows excluded, deduplicated across the codex
		// invocation/executor pair. Deleted lines are deliberately not in
		// it — deleting code is real work, but it is not lines written,
		// and summing the two would let a delete-heavy refactor outscore
		// a feature.
		//
		// HumanCodeLines is its editor-reported counterpart and is 0
		// unless an editor is reporting saves. The UI must NOT derive an
		// "AI share" from these two on their own: with no editor capture
		// the human side is unmeasured, not zero, and a share would read
		// as 100% AI. /api/loc/summary carries the capture flag that
		// makes a share legitimate.
		//
		// Both carry omitempty so a corpus that has never run
		// `observer backfill --loc` emits the byte-identical payload it
		// did before this feature existed (tests/invariant/golden/sessions.json).
		AICodeLines     int      `json:"ai_code_lines,omitempty"`
		HumanCodeLines  int      `json:"human_code_lines,omitempty"`
		QualityScore    *float64 `json:"quality_score,omitempty"`
		ErrorRate       *float64 `json:"error_rate,omitempty"`
		RedundancyRatio *float64 `json:"redundancy_ratio,omitempty"`
		// Spec §14.1 wasteful-subset (nil when the session has
		// no cache_events).
		RedundancyRatioWasteful *float64 `json:"redundancy_ratio_wasteful,omitempty"`
		StaleReadsWasteful      *int     `json:"stale_reads_wasteful,omitempty"`
		StaleReadsNecessary     *int     `json:"stale_reads_necessary,omitempty"`
		// Token breakdown — attached post-scan from the cost engine's
		// GroupBySession rollup so dedup (proxy preferred, JSONL
		// fallback) matches /api/cost exactly. v1.4.51 surfaces all
		// four billable buckets separately so the Sessions table can
		// show Input / Cache R / Cache W / Output as distinct columns.
		// TotalTokens is the sum for backwards compatibility with
		// older callers; the Sessions table doesn't render it as of
		// v1.4.51.
		InputTokens         int64 `json:"input_tokens"`
		OutputTokens        int64 `json:"output_tokens"`
		CacheReadTokens     int64 `json:"cache_read_tokens"`
		CacheCreationTokens int64 `json:"cache_creation_tokens"`
		// CacheCreation1hTokens is the 1h-ephemeral-tier subset of
		// CacheCreationTokens (the rest is implicitly 5m-tier).
		// Surfaced so the Sessions table's "Cache W" column can show
		// the per-row 5m/1h split as a hover tooltip — visualisation
		// of why a session billed at the higher-tier cache-write rate.
		// Anthropic-only field; non-Anthropic providers always emit 0.
		CacheCreation1hTokens int64 `json:"cache_creation_1h_tokens"`
		ReasoningTokens       int64 `json:"reasoning_tokens,omitempty"`
		WebSearchRequests     int64 `json:"web_search_requests,omitempty"`
		TotalTokens           int64 `json:"total_tokens"`
		// CostUSD is the legacy total; AICostUSD + ToolCostUSD split
		// it so the Sessions table can show "API cost vs tool cost vs
		// total" separately. CostUSD == AICostUSD + ToolCostUSD.
		CostUSD     float64 `json:"cost_usd"`
		AICostUSD   float64 `json:"ai_cost_usd"`
		ToolCostUSD float64 `json:"tool_cost_usd"`
		// CostReliability is the worst-case reliability across the
		// rows that fed this session's totals. Surfaces as a pill on
		// the Sessions table so users know which numbers to trust.
		CostReliability string `json:"cost_reliability,omitempty"`
		// Models is the distinct set of model identifiers seen across
		// this session's api_turns + token_usage rows, ordered by turn
		// count (heaviest first). Enables the Sessions table's Model(s)
		// column to render a primary chip + "+N more" affordance and
		// the Overview Recent sessions list to show which model the
		// session leaned on. Empty when no proxy/JSONL rows captured
		// a model (rare; usually means scraped fallback).
		Models []string `json:"models,omitempty"`
		// Session classification (plan §4), attached post-scan from the two
		// batched store loads (one query each per page — never per row).
		// HasNote is a flag, not the note itself: the list renders a marker and
		// the detail panel fetches the text. ALL THREE carry omitempty so an
		// unclassified corpus emits the byte-identical payload it did before
		// tags existed (the pinned tests/invariant/golden/sessions.json).
		Tags     []string `json:"tags,omitempty"`
		Favorite bool     `json:"favorite,omitempty"`
		HasNote  bool     `json:"has_note,omitempty"`
		// Rating is the 1-10 overall score (0 = unrated). omitempty for the
		// same golden-payload-stability reason as the three above.
		Rating int `json:"rating,omitempty"`
		// Title is the developer's OWN session title (migration 116) —
		// distinct from CloudTitle below (the AI-generated one) and always
		// wins over it wherever the frontend renders an "effective title".
		// omitempty for the same golden-payload-stability reason as Rating.
		Title string `json:"title,omitempty"`
		// CloudEnriched/CloudTitle surface the cloud-intelligence enrichment
		// state (node-local cloud_results, migration 097) attached
		// post-scan from the same batched-per-page pattern as the
		// classification fields above. CloudEnriched is true when a
		// non-superseded cloud_results row exists for the session;
		// CloudTitle is that row's AI-generated title, or "" when none.
		// Both carry omitempty/zero-value defaults so an unenriched corpus
		// emits the byte-identical payload it did before cloud-intelligence
		// existed.
		CloudEnriched   bool                           `json:"cloud_enriched,omitempty"`
		CloudTitle      string                         `json:"cloud_title,omitempty"`
		CloudEnrichment *store.CloudEnrichmentProgress `json:"cloud_enrichment,omitempty"`
	}
	var out []sessRow
	for rows.Next() {
		var sr sessRow
		var q, er, rr sql.NullFloat64
		var rrWasteful sql.NullFloat64
		var stWasteful, stNecessary sql.NullInt64
		if err := rows.Scan(&sr.ID, &sr.Tool, &sr.Project, &sr.StartedAt, &sr.LastSeenAt,
			&sr.TotalActions, &sr.SidechainActionCount,
			&q, &er, &rr,
			&rrWasteful, &stWasteful, &stNecessary); err != nil {
			writeErr(w, err)
			return
		}
		if sr.LastSeenAt != "" {
			start, sErr := time.Parse(time.RFC3339Nano, sr.StartedAt)
			end, eErr := time.Parse(time.RFC3339Nano, sr.LastSeenAt)
			if sErr == nil && eErr == nil && end.After(start) {
				sr.DurationSeconds = int64(end.Sub(start).Seconds())
			}
		}
		if q.Valid {
			v := q.Float64
			sr.QualityScore = &v
		}
		if er.Valid {
			v := er.Float64
			sr.ErrorRate = &v
		}
		if rr.Valid {
			v := rr.Float64
			sr.RedundancyRatio = &v
		}
		if rrWasteful.Valid {
			v := rrWasteful.Float64
			sr.RedundancyRatioWasteful = &v
		}
		if stWasteful.Valid {
			v := int(stWasteful.Int64)
			sr.StaleReadsWasteful = &v
		}
		if stNecessary.Valid {
			v := int(stNecessary.Int64)
			sr.StaleReadsNecessary = &v
		}
		out = append(out, sr)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}
	if out == nil {
		out = []sessRow{}
	}

	// Attach lines-of-code authorship through the store seam — ONE batched
	// query per 400 sessions, deduplicated by the same collapse rule the
	// session card reads through, so the two surfaces can never report
	// different numbers for one session.
	//
	// It runs HERE, before the in-memory sort, because ai_code_lines is a
	// sortable column and that sort covers the whole filtered set, not just
	// the page. A failure degrades the page to "no LOC shown" rather than
	// 500ing the list — same posture as tags/annotations/cloud below.
	if len(out) > 0 {
		locIDs := make([]string, len(out))
		for i := range out {
			locIDs[i] = out[i].ID
		}
		if locLines, lErr := store.New(s.db()).LoadSessionLOCLines(r.Context(), locIDs); lErr == nil {
			for i := range out {
				lines := locLines[out[i].ID]
				out[i].AICodeLines = lines.AICodeLines
				out[i].HumanCodeLines = lines.HumanCodeLines
			}
		} else {
			s.opts.Logger.Warn("sessions: per-session LOC load failed", "err", lErr)
		}
	}

	// Attach per-session token totals + cost from the cost engine, then (for
	// in-memory sort columns) sort the full filtered set and slice to the page.
	//
	// The window matches the days query param so the Sessions-page per-session
	// cost sum equals the Cost-page /api/models total (the v1.6.3 → v1.6.4
	// reconciliation fix). When days=0 (no time filter) the cost rollup spans
	// full history (Days=36500), keeping CLI callers correct.
	// Window the per-session cost rollup to match the list. When no
	// lower bound was requested (since zero), fall back to the all-time
	// window (costDays=36500) exactly as before; otherwise the cost
	// engine honors Since/Until (Since overrides Days when non-zero).
	costDays := 0
	if since.IsZero() {
		costDays = 36500
	}

	// attachCost rolls up per-session cost + tokens and stamps them onto rows.
	// scopeIDs limits the engine to those session_ids (the cheap page-scoped
	// path); pass nil to roll up the whole window — needed when a cost/token
	// sort column requires the full filtered set BEFORE paging, since the byID
	// map then filters the rollup back to the rows we hold.
	attachCost := func(rows []sessRow, scopeIDs []string) {
		if len(rows) == 0 {
			return
		}
		costSummary, err := s.opts.CostEngine.Summary(r.Context(), s.db(), cost.Options{
			Days:        costDays,
			Since:       since,
			Until:       until,
			GroupBy:     cost.GroupBySession,
			Source:      cost.SourceAuto,
			ProjectRoot: project,
			Tool:        tool,
			SessionIDs:  scopeIDs,
			Limit:       1_000_000,
		})
		if err != nil {
			s.opts.Logger.Warn("sessions: per-session cost rollup failed", "err", err)
			return
		}
		byID := make(map[string]cost.Row, len(costSummary.Rows))
		for _, row := range costSummary.Rows {
			byID[row.Key] = row
		}
		for i := range rows {
			row, ok := byID[rows[i].ID]
			if !ok {
				continue
			}
			rows[i].InputTokens = row.Tokens.Input
			rows[i].OutputTokens = row.Tokens.Output
			rows[i].CacheReadTokens = row.Tokens.CacheRead
			rows[i].CacheCreationTokens = row.Tokens.CacheCreation
			rows[i].CacheCreation1hTokens = row.Tokens.CacheCreation1h
			rows[i].ReasoningTokens = row.Tokens.Reasoning
			rows[i].WebSearchRequests = row.Tokens.WebSearchRequests
			rows[i].TotalTokens = row.Tokens.Input + row.Tokens.Output +
				row.Tokens.CacheRead + row.Tokens.CacheCreation
			rows[i].CostUSD = row.CostUSD
			rows[i].AICostUSD = row.AICostUSD
			rows[i].ToolCostUSD = row.ToolCostUSD
			rows[i].CostReliability = row.Reliability
		}
	}

	costAttached := false
	if inMemorySort {
		if costSort {
			// Cost/token columns: roll up the WHOLE filtered set so the sort is
			// global, not page-local.
			attachCost(out, nil)
			costAttached = true
		}
		// Sort the full filtered set in Go. Numeric key per column; stable
		// tiebreak on started_at DESC, id ASC mirrors the SQL clause so paging
		// is deterministic.
		sortKey := func(sr sessRow) float64 {
			switch sortBy {
			case "elapsed":
				return float64(sr.DurationSeconds)
			case "input":
				return float64(sr.InputTokens)
			case "cache_r":
				return float64(sr.CacheReadTokens)
			case "cache_w":
				return float64(sr.CacheCreationTokens)
			case "output":
				return float64(sr.OutputTokens)
			case "cost":
				return sr.CostUSD
			case "ai_code_lines":
				return float64(sr.AICodeLines)
			}
			return 0
		}
		sort.SliceStable(out, func(i, j int) bool {
			ki, kj := sortKey(out[i]), sortKey(out[j])
			if ki != kj {
				if sortDesc {
					return ki > kj
				}
				return ki < kj
			}
			if out[i].StartedAt != out[j].StartedAt {
				return out[i].StartedAt > out[j].StartedAt
			}
			return out[i].ID < out[j].ID
		})
		// Slice to the requested page.
		start := offset
		if start > len(out) {
			start = len(out)
		}
		end := start + limit
		if end > len(out) {
			end = len(out)
		}
		out = out[start:end]
	}

	pageIDs := make([]string, len(out))
	for i, sr := range out {
		pageIDs[i] = sr.ID
	}
	if !costAttached {
		// Cheap-SQL-sort and elapsed-sort pages: attach cost scoped to the
		// page's session_ids (no whole-window rollup needed).
		attachCost(out, pageIDs)
	}

	// Attach per-session model list for the page — one query batches across the
	// page's session IDs and unions api_turns + token_usage. Models are ordered
	// by turn count desc so out[i].Models[0] is the session's "primary" model
	// (heaviest by count). Both source tables index session_id; cheap at
	// LIMIT ≤ 500.
	if len(out) > 0 {
		ids := make([]any, 0, len(pageIDs))
		for _, id := range pageIDs {
			ids = append(ids, id)
		}
		placeholders := strings.Repeat("?,", len(ids))
		placeholders = strings.TrimRight(placeholders, ",")
		modelArgs := append(append([]any{}, ids...), ids...)
		modelRows, mErr := s.db().QueryContext(r.Context(),
			//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
			`SELECT session_id, model, SUM(c) AS turns FROM (
				SELECT session_id, COALESCE(model, '') AS model, COUNT(*) AS c
				 FROM api_turns
				 WHERE session_id IN (`+placeholders+`) AND COALESCE(model, '') != ''
				 GROUP BY session_id, model
				UNION ALL
				SELECT session_id, COALESCE(model, '') AS model, COUNT(*) AS c
				 FROM token_usage
				 WHERE session_id IN (`+placeholders+`) AND COALESCE(model, '') != ''
				 GROUP BY session_id, model
			) GROUP BY session_id, model ORDER BY session_id, turns DESC, model ASC`,
			modelArgs...)
		if mErr == nil {
			modelsBySession := make(map[string][]string, len(out))
			for modelRows.Next() {
				var sid, model string
				var turns int64
				if err := modelRows.Scan(&sid, &model, &turns); err != nil {
					continue
				}
				modelsBySession[sid] = append(modelsBySession[sid], model)
			}
			_ = modelRows.Close()
			for i, sr := range out {
				if ms, ok := modelsBySession[sr.ID]; ok {
					out[i].Models = ms
				}
			}
		} else {
			s.opts.Logger.Warn("sessions: per-session model list failed", "err", mErr)
		}
	}

	// Attach session classification for the page: exactly TWO batched store
	// queries (tags + annotations), both scoped to the page's session ids. A
	// failure degrades the page to "no classification shown" rather than 500ing
	// the whole list — tags are an annotation layer, not the data.
	if len(pageIDs) > 0 {
		st := store.New(s.db())
		if tagsBySession, tErr := st.ListSessionTags(r.Context(), pageIDs); tErr == nil {
			for i := range out {
				out[i].Tags = tagsBySession[out[i].ID]
			}
		} else {
			s.opts.Logger.Warn("sessions: per-session tag load failed", "err", tErr)
		}
		if annots, aErr := st.ListAnnotations(r.Context(), pageIDs); aErr == nil {
			for i := range out {
				a := annots[out[i].ID]
				out[i].Favorite = a.Favorite
				out[i].HasNote = a.Note != ""
				out[i].Rating = a.Rating
				out[i].Title = a.Title
			}
		} else {
			s.opts.Logger.Warn("sessions: per-session annotation load failed", "err", aErr)
		}

		progress := s.cloudListEnrichmentProgress(r.Context(), st, pageIDs)
		for i := range out {
			out[i].CloudEnrichment = progress[out[i].ID]
		}

		// Attach cloud-intelligence enrichment state: ONE batched query over
		// the page's session ids through the store seam
		// (internal/store/cloudlocal_enriched.go::LoadCloudEnrichedTitles),
		// scoped to the current (non-superseded) result per session. A
		// failure degrades to "no enrichment shown" rather than 500ing the
		// list — same posture as tags/annotations above.
		if titleBySession, cErr := st.LoadCloudEnrichedTitles(r.Context(), pageIDs); cErr == nil {
			for i := range out {
				if title, ok := titleBySession[out[i].ID]; ok {
					out[i].CloudEnriched = true
					out[i].CloudTitle = title
				}
			}
		} else {
			s.opts.Logger.Warn("sessions: per-session cloud-enrichment load failed", "err", cErr)
		}
	}

	// Page footer totals so the frontend footer reconciles with the visible
	// rows even when the global sort surfaced a different slice.
	var pageCost, pageAICost, pageToolCost float64
	for _, sr := range out {
		pageCost += sr.CostUSD
		pageAICost += sr.AICostUSD
		pageToolCost += sr.ToolCostUSD
	}
	sortDir := "asc"
	if sortDesc {
		sortDir = "desc"
	}

	writeJSON(w, map[string]any{
		"rows":               out,
		"page":               page,
		"limit":              limit,
		"total":              total,
		"scored_count":       scoredCount,
		"days":               days,
		"sort_by":            sortBy,
		"sort_dir":           sortDir,
		"page_cost_usd":      pageCost,
		"page_ai_cost_usd":   pageAICost,
		"page_tool_cost_usd": pageToolCost,
	})
}

// handleSessionsCalendar — GET /api/sessions/calendar?days=N
//
// Returns one row per day across the window: {day, session_count,
// cost_usd}. Dashboard's Calendar view consumes this so the grid
// spans the full Window with real per-day distribution instead of
// the most recent page-50 slice. Session counts come from a GROUP
// BY date(started_at) over sessions; costs come from the cost engine
// rolled up GroupByDay over the same window.
func (s *Server) handleSessionsCalendar(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 365)
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")
	since, until := windowRange(r, 30, 1, 365)

	// Session count per day.
	var where []string
	args := []any{since.Format(time.RFC3339Nano)}
	where = append(where, "started_at >= ?")
	if !until.IsZero() {
		where = append(where, "started_at < ?")
		args = append(args, until.Format(time.RFC3339Nano))
	}
	if tool != "" {
		where = append(where, "tool = ?")
		args = append(args, tool)
	}
	if project != "" {
		where = append(where, "project_id = (SELECT id FROM projects WHERE root_path = ?)")
		args = append(args, project)
	}
	rows, err := s.db().QueryContext(r.Context(),
		//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
		`SELECT substr(started_at, 1, 10) AS day, COUNT(*) AS n
		   FROM sessions
		  WHERE `+strings.Join(where, " AND ")+` AND `+nonEmptySessionPredicateSessions+`
		  GROUP BY day
		  ORDER BY day`, args...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()

	type cell struct {
		Day          string  `json:"day"`
		SessionCount int     `json:"session_count"`
		CostUSD      float64 `json:"cost_usd"`
	}
	byDay := map[string]*cell{}
	order := []string{}
	for rows.Next() {
		var day string
		var n int
		if err := rows.Scan(&day, &n); err != nil {
			writeErr(w, err)
			return
		}
		byDay[day] = &cell{Day: day, SessionCount: n}
		order = append(order, day)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}

	// Cost per day — cost.Summary with GroupByDay covers turn-date
	// bucketing across the same window, joined back onto the session
	// day map. A session that ran across midnight will have its turns
	// land on multiple days; that's expected behaviour and matches
	// the daily cost shown on /cost.
	costSummary, err := s.opts.CostEngine.Summary(r.Context(), s.db(), cost.Options{
		Days:        days,
		Since:       since, // window the cost rollup exactly like the session count above
		Until:       until, // (hours=1 must return 1h costs, not the 30d default window)
		GroupBy:     cost.GroupByDay,
		Source:      cost.SourceAuto,
		ProjectRoot: project,
		Tool:        tool, // align per-day cost with the tool-filtered session count above
		Limit:       365,
	})
	if err == nil {
		for _, row := range costSummary.Rows {
			c, ok := byDay[row.Key]
			if !ok {
				c = &cell{Day: row.Key}
				byDay[row.Key] = c
				order = append(order, row.Key)
			}
			c.CostUSD = row.CostUSD
		}
	} else {
		s.opts.Logger.Warn("sessions calendar: cost rollup failed", "err", err)
	}

	out := make([]cell, 0, len(order))
	seen := map[string]bool{}
	for _, k := range order {
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, *byDay[k])
	}
	// Stable sort by day ascending so the frontend can iterate the
	// returned slice in order regardless of insertion order.
	sort.Slice(out, func(i, j int) bool { return out[i].Day < out[j].Day })
	writeJSON(w, map[string]any{
		"days":  days,
		"cells": out,
	})
}

// loadActionExcerpts fetches the first action_excerpts.excerpt for each
// id, truncated to maxBytes when > 0. Returns map[action_id] -> excerpt.
//
// action_excerpts is an FTS5 virtual table with action_id declared
// UNINDEXED, so there's no b-tree on action_id and SQLite must fall back
// to a full virtual-table SCAN for every (action_id = ?) probe. A
// correlated subquery in the SELECT list or a LEFT JOIN therefore costs
// O(N rows × M excerpts) — empirically ~22s for 500 rows on an 81k-action
// DB, and ~136s for the 1772-action session messages view. The batch IN
// form below pays one ~50ms scan regardless of |ids|, then filters
// in-memory. The map's "first wins" semantic preserves the
// `LIMIT 1`/`COALESCE(ae.excerpt, ”)` behavior of the original queries
// (action_excerpts can hold multiple rows per action_id when the same
// action was re-indexed).
func loadActionExcerpts(ctx context.Context, db *sql.DB, ids []int64, maxBytes int) (map[int64]string, error) {
	out := make(map[int64]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	placeholders := strings.Repeat("?,", len(ids))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	var q string
	if maxBytes > 0 {
		q = fmt.Sprintf("SELECT action_id, substr(excerpt, 1, %d) FROM action_excerpts WHERE action_id IN (%s)", maxBytes, placeholders)
	} else {
		q = "SELECT action_id, excerpt FROM action_excerpts WHERE action_id IN (" + placeholders + ")"
	}
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var excerpt string
		if err := rows.Scan(&id, &excerpt); err != nil {
			return nil, err
		}
		if _, ok := out[id]; !ok {
			out[id] = excerpt
		}
	}
	return out, rows.Err()
}

func (s *Server) handleActions(w http.ResponseWriter, r *http.Request) {
	limit := intArg(r, "limit", 50, 1, 500)
	page := intArg(r, "page", 1, 1, 1_000_000)
	offset := (page - 1) * limit
	tool := r.URL.Query().Get("tool")
	sessionID := r.URL.Query().Get("session_id")
	actionType := r.URL.Query().Get("action_type")
	project := r.URL.Query().Get("project")
	// v1.4.48: metadata filters land on the migration-017 actions.metadata
	// JSON column via SQLite's json_extract (no JSON1 dependency added —
	// modernc.org/sqlite ships it). Empty params skip the filter entirely
	// so the legacy /api/actions surface is unchanged for callers that
	// don't pass them.
	effortLevel := r.URL.Query().Get("effort_level")
	permissionMode := r.URL.Query().Get("permission_mode")
	isInterrupt := r.URL.Query().Get("is_interrupt")
	// v1.4.49: assistant_text filter surfaces "what did the AI say to the
	// user?" rows from any adapter. The multi-pattern OR-chain
	// accommodates the RawToolName convention drift documented in
	// docs/handover-v1.4.49 — new wirings use `<source>.assistant_text`,
	// legacy precedents stay as-is (Pi's `message.assistant.<stopReason>`,
	// Copilot's `agent_response`, Antigravity's `structured.assistant_text`,
	// openclaw's `message.assistant.stop`).
	assistantText := r.URL.Query().Get("assistant_text")
	// Date filters — accept YYYY-MM-DD prefix matching against
	// substr(a.timestamp, 1, 10). The Timeline view passes from_date
	// = to_date when the user picks a single day from the day strip.
	fromDate := r.URL.Query().Get("from_date")
	toDate := r.URL.Query().Get("to_date")
	// Window filter — same `days` contract as /api/sessions and
	// /api/status/scoped (0 = absent = no filter, so legacy callers
	// keep the unwindowed firehose). The header's 7d/14d/… selector
	// was a no-op on this page until this landed.
	since, until := windowRange(r, 0, 0, 36500)

	var where []string
	var args []any
	if !since.IsZero() {
		where = append(where, "a.timestamp >= ?")
		args = append(args, since.Format(time.RFC3339Nano))
	}
	if !until.IsZero() {
		where = append(where, "a.timestamp < ?")
		args = append(args, until.Format(time.RFC3339Nano))
	}
	if tool != "" {
		where = append(where, "a.tool = ?")
		args = append(args, tool)
	}
	if sessionID != "" {
		where = append(where, "a.session_id = ?")
		args = append(args, sessionID)
	}
	if actionType != "" {
		where = append(where, "a.action_type = ?")
		args = append(args, actionType)
	}
	if project != "" {
		where = append(where, "a.project_id = (SELECT id FROM projects WHERE root_path = ?)")
		args = append(args, project)
	}
	// from_date / to_date stay day-grained (substr) for compat; the
	// genuinely-new sub-day params win when both are present — but only
	// when they actually RESOLVED (a malformed until/since/hours fails
	// open in windowRange, so the legacy param must still apply). Legacy
	// `days`+from_date keeps its historical AND behavior (`days` is not
	// gated here).
	newLower, newUpper := windowBoundsResolved(r)
	if fromDate != "" && !newLower {
		where = append(where, "substr(a.timestamp, 1, 10) >= ?")
		args = append(args, fromDate)
	}
	if toDate != "" && !newUpper {
		where = append(where, "substr(a.timestamp, 1, 10) <= ?")
		args = append(args, toDate)
	}
	if effortLevel != "" {
		where = append(where, "json_extract(a.metadata, '$.effort_level') = ?")
		args = append(args, effortLevel)
	}
	if permissionMode != "" {
		where = append(where, "json_extract(a.metadata, '$.permission_mode') = ?")
		args = append(args, permissionMode)
	}
	if isInterrupt == "1" {
		// SQLite's json_extract on a JSON boolean returns 1/0 (integer)
		// — compare against 1 not "true". Rows where metadata is NULL or
		// is_interrupt is absent return NULL from json_extract, which
		// fails the equality and is correctly excluded.
		where = append(where, "json_extract(a.metadata, '$.is_interrupt') = 1")
	}
	if assistantText == "1" {
		// `<source>.assistant_text` covers new wirings (codex / cline /
		// roo-code / claudecode / cursor / gemini / opencode / openclaw).
		// `structured.assistant_text` is Antigravity's pre-existing
		// RawToolName. `message.assistant.<stopReason>` is Pi.
		// `message.assistant.stop` is OpenClaw's legacy marker row.
		// `agent_response` is Copilot's pre-existing RawToolName. All
		// four legacy names are left alone per the v1.4.49 convention
		// decision to avoid SourceEventID dedup churn.
		where = append(where, `(
			a.raw_tool_name LIKE '%.assistant_text'
			OR a.raw_tool_name LIKE 'message.assistant.%'
			OR a.raw_tool_name = 'agent_response'
		)`)
	}
	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	var total int
	countArgs := append([]any{}, args...)
	if err := s.db().QueryRowContext(
		r.Context(),
		"SELECT COUNT(*) FROM actions a "+whereClause, countArgs...,
	).Scan(&total); err != nil {
		writeErr(w, err)
		return
	}

	dataArgs := append([]any{}, args...)
	dataArgs = append(dataArgs, limit, offset)
	// Excerpt is loaded in a second batch query — see loadActionExcerpts
	// for why an inline subquery is O(N×M) on the FTS5 action_excerpts
	// table.
	rows, err := s.db().QueryContext(r.Context(),
		//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
		`SELECT a.id, a.timestamp, a.tool, a.session_id,
		        COALESCE(p.root_path, ''), a.action_type,
		        COALESCE(a.raw_tool_name, ''), COALESCE(a.target, ''),
		        COALESCE(a.success, 1), COALESCE(a.error_message, ''),
		        COALESCE(a.message_id, ''),
		        COALESCE(json_extract(a.metadata, '$.permission_mode'), '') AS permission_mode,
		        COALESCE(json_extract(a.metadata, '$.effort_level'), '') AS effort_level,
		        COALESCE(json_extract(a.metadata, '$.is_interrupt'), 0) AS is_interrupt,
		        COALESCE(json_extract(a.metadata, '$.stop_reason'), '') AS stop_reason,
		        COALESCE(json_extract(a.metadata, '$.service_tier'), '') AS service_tier,
		        COALESCE(a.source_file, ''),
		        COALESCE(a.source_event_id, '')
		 FROM actions a
		 LEFT JOIN projects p ON p.id = a.project_id
		 `+whereClause+`
		 ORDER BY a.timestamp DESC, a.id DESC LIMIT ? OFFSET ?`, dataArgs...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()
	type actionRow struct {
		ID           int64  `json:"id"`
		Timestamp    string `json:"timestamp"`
		Tool         string `json:"tool"`
		SessionID    string `json:"session_id"`
		Project      string `json:"project"`
		ActionType   string `json:"action_type"`
		RawToolName  string `json:"raw_tool_name"`
		Target       string `json:"target"`
		Success      bool   `json:"success"`
		ErrorMessage string `json:"error_message,omitempty"`
		// MessageID is the upstream Anthropic msg_xxx id for the API
		// turn that produced this action (populated by the claudecode
		// adapter, the message-id backfill, and the api_error path).
		// For user_prompt rows it carries the synthesized "user:<id>"
		// form; for tool_use rows the parent assistant message's id.
		// Lets the Actions tab link a row back to the per-message
		// timeline modal via the same id surfaced on the Compression
		// events table.
		MessageID string `json:"message_id"`
		// Per-event metadata extracted from actions.metadata JSON
		// (migration 017). Empty / false when the row pre-dates
		// the migration or the source adapter didn't emit the
		// field. omitempty keeps the response payload lean.
		PermissionMode string `json:"permission_mode,omitempty"`
		EffortLevel    string `json:"effort_level,omitempty"`
		IsInterrupt    bool   `json:"is_interrupt,omitempty"`
		// StopReason — why the assistant turn ended (end_turn / max_tokens
		// / tool_use / stop_sequence / refusal). ServiceTier — the served
		// capacity tier (standard / priority / batch). Both per-message,
		// captured from the transcript (claude-code, cowork). Empty for
		// rows that pre-date capture or adapters that don't emit them.
		StopReason  string `json:"stop_reason,omitempty"`
		ServiceTier string `json:"service_tier,omitempty"`
		// SourceFile / SourceEventID — provenance for this row. Tells
		// the user which JSONL or proxy capture produced the event.
		// SourceFile may be empty for synthesized rows (e.g. hook
		// closures) where the adapter doesn't track a file origin.
		SourceFile    string `json:"source_file,omitempty"`
		SourceEventID string `json:"source_event_id,omitempty"`
		// Excerpt — first 280 chars of the action's indexed body from
		// action_excerpts. Lets the Actions table surface "what did
		// the tool actually do" inline without a row-expand click;
		// the full text remains retrievable via /api/actions/<id> when
		// that endpoint lands.
		Excerpt string `json:"excerpt,omitempty"`
	}
	var out []actionRow
	for rows.Next() {
		var ar actionRow
		var isInterrupt int
		if err := rows.Scan(&ar.ID, &ar.Timestamp, &ar.Tool, &ar.SessionID, &ar.Project,
			&ar.ActionType, &ar.RawToolName, &ar.Target, &ar.Success, &ar.ErrorMessage,
			&ar.MessageID, &ar.PermissionMode, &ar.EffortLevel, &isInterrupt,
			&ar.StopReason, &ar.ServiceTier,
			&ar.SourceFile, &ar.SourceEventID); err != nil {
			writeErr(w, err)
			return
		}
		ar.IsInterrupt = isInterrupt != 0
		out = append(out, ar)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}
	if out == nil {
		out = []actionRow{}
	}
	ids := make([]int64, len(out))
	for i, r := range out {
		ids[i] = r.ID
	}
	excerpts, err := loadActionExcerpts(r.Context(), s.db(), ids, 280)
	if err != nil {
		writeErr(w, err)
		return
	}
	for i := range out {
		out[i].Excerpt = excerpts[out[i].ID]
	}
	writeJSON(w, map[string]any{
		"rows":  out,
		"page":  page,
		"limit": limit,
		"total": total,
	})
}

// handleActionsDayCounts — GET /api/actions/day-counts?days=N
//
// fullTextInlineMax is the per-row preview cap embedded in
// /api/session/<id>/messages. Anything longer is truncated to this
// length and surfaced with full_text_elided=true so the frontend
// knows to fetch the untruncated body via /api/action/<id>/full_text
// only when the operator actually clicks copy / view. Keeps the
// timeline payload bounded regardless of how large any single row's
// raw_tool_input grows post-migration-027.
const fullTextInlineMax = 4000

// handleActionDetail handles /api/action/<id>/<sub>. The only currently
// supported sub-resource is `full_text`, which returns the untruncated
// raw_tool_input + raw_tool_output for an action so the dashboard's
// copy and view-full-text buttons can fetch on demand instead of
// embedding multi-MB blobs in every /messages response.
//
// Bounded by the adapter-side internal/contentcap.DefaultMaxBytes
// (1 MiB per column); rows that overflowed adapter capture carry the
// trailing "…(content truncated at N bytes)…" marker so the operator
// can tell the served body is itself a truncation.
func (s *Server) handleActionDetail(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/action/")
	if !strings.HasSuffix(rest, "/full_text") {
		http.Error(w, "unsupported action sub-resource", http.StatusNotFound)
		return
	}
	idStr := strings.TrimSuffix(rest, "/full_text")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "missing or invalid action id", http.StatusBadRequest)
		return
	}
	var (
		actionType string
		target     string
		rawInput   sql.NullString
		rawOutput  sql.NullString
	)
	err = s.db().QueryRowContext(
		r.Context(),
		`SELECT action_type, COALESCE(target, ''), raw_tool_input, raw_tool_output
		   FROM actions WHERE id = ?`, id,
	).Scan(&actionType, &target, &rawInput, &rawOutput)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "action not found", http.StatusNotFound)
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	fullInput := rawInput.String
	if actionType == "run_command" && fullInput != "" {
		fullInput = decodeCommandInput(fullInput)
	}
	type resp struct {
		ActionID      int64  `json:"action_id"`
		ActionType    string `json:"action_type"`
		Target        string `json:"target,omitempty"`
		RawToolInput  string `json:"raw_tool_input,omitempty"`
		RawToolOutput string `json:"raw_tool_output,omitempty"`
	}
	writeJSON(w, resp{
		ActionID:      id,
		ActionType:    actionType,
		Target:        target,
		RawToolInput:  fullInput,
		RawToolOutput: rawOutput.String,
	})
}

// Returns one row per day in the window: {day, count}. Drives the
// Actions Timeline view's day strip so every day in the configured
// Window is selectable even when it lies outside the most-recent
// page-500 slice. Honors the same tool/project filters as
// /api/actions so the strip aligns with whatever's filtered.
func (s *Server) handleActionsDayCounts(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 365)
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")
	since, until := windowRange(r, 30, 1, 365)

	where := []string{"a.timestamp >= ?"}
	args := []any{since.Format(time.RFC3339Nano)}
	if !until.IsZero() {
		where = append(where, "a.timestamp < ?")
		args = append(args, until.Format(time.RFC3339Nano))
	}
	if tool != "" {
		where = append(where, "a.tool = ?")
		args = append(args, tool)
	}
	if project != "" {
		where = append(where, "a.project_id = (SELECT id FROM projects WHERE root_path = ?)")
		args = append(args, project)
	}
	rows, err := s.db().QueryContext(r.Context(),
		//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
		`SELECT substr(a.timestamp, 1, 10) AS day, COUNT(*) AS n
		   FROM actions a
		  WHERE `+strings.Join(where, " AND ")+`
		  GROUP BY day
		  ORDER BY day`, args...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()

	type cell struct {
		Day   string `json:"day"`
		Count int    `json:"count"`
	}
	out := []cell{}
	for rows.Next() {
		var c cell
		if err := rows.Scan(&c.Day, &c.Count); err != nil {
			writeErr(w, err)
			return
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"days":  days,
		"cells": out,
	})
}

// handleSessionDetail handles /api/session/<id>. Returns session metadata
// plus aggregate roll-ups (action counts, tool breakdown, token totals,
// per-model usage). Action list is NOT inlined — the frontend should
// follow-up with /api/actions?session_id=<id>&page=… for the paginated
// stream.
func (s *Server) handleSessionDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/session/")
	// Sub-route: /api/session/<id>/messages → per-message timeline
	// (one row per upstream Anthropic message). Returns the deduped
	// per-turn breakdown with grouped tool calls. Used by the
	// session modal's Messages panel.
	if strings.HasSuffix(id, "/messages") {
		id = strings.TrimSuffix(id, "/messages")
		s.handleSessionMessages(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/cache/forecast → model-switch
	// cost forecaster (spec §14.2). Pure read-side math over the
	// existing tables — P from cache_entries, S/gaps from
	// cache_events, O/T/fast from api_turns, rates from cost.Table.
	// Returns the headline switch_cost + break_even_turns + per-
	// turn delta + closed-set warning list. Must precede the
	// /cache match below since "/cache/forecast" suffixes
	// "/cache" too.
	if strings.HasSuffix(id, "/cache/forecast") {
		id = strings.TrimSuffix(id, "/cache/forecast")
		s.handleSessionCacheForecast(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/cache → cachetrack panel
	// payload (spec §13 / C13). Tier + entries + events +
	// efficiency rollup + timeline (baseline rolled to a single
	// count entry; anomalies itemized). Drives SessionDetailPanel's
	// Cache tab.
	if strings.HasSuffix(id, "/cache") {
		id = strings.TrimSuffix(id, "/cache")
		s.handleSessionCache(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/loc → lines-of-code authorship for the
	// session (AI main vs sidechain vs editor-reported human, code vs
	// docs vs config, with the confidence and overwrite caveats attached
	// to the numbers). A read over node-local file_changes.
	if strings.HasSuffix(id, "/loc") {
		id = strings.TrimSuffix(id, "/loc")
		s.handleSessionLOC(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/processes → the Process Observability
	// session tree (docs/process-observability.md §13.1). Attributed
	// fork/exec/exit lineage with the spawning command per subtree. Empty
	// unless [observer.process] is enabled; drives the Processes drawer.
	if strings.HasSuffix(id, "/processes") {
		id = strings.TrimSuffix(id, "/processes")
		s.handleSessionProcesses(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/metrics?bucket=<duration> → the plottable
	// sibling of /processes: the same per-process metric_samples_json rings,
	// but bucketed onto a common time grid, DIFFERENTIATED (the cpu/disk
	// counters are cumulative) and aggregated across the whole attributed
	// subtree. Drives the Session Cockpit's live CPU / RSS / Disk charts.
	// Read-only — the correlation write passes stay on /processes.
	if strings.HasSuffix(id, "/metrics") {
		id = strings.TrimSuffix(id, "/metrics")
		s.handleSessionMetrics(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/network → lightweight network egress event
	// list for the session. Body excerpts are fetched explicitly through
	// /api/process/network/<event_id>.
	if strings.HasSuffix(id, "/network") {
		id = strings.TrimSuffix(id, "/network")
		s.handleSessionNetwork(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/subagents → per-sub-agent summaries for
	// sessions whose sub-agent activity rides the parent's session row
	// flagged is_sidechain (claude-code model, migration 010). Codex child
	// sessions surface through lineage instead (children[] below).
	if strings.HasSuffix(id, "/subagents") {
		id = strings.TrimSuffix(id, "/subagents")
		s.handleSessionSubagents(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/raw-events → on-demand source JSONL row
	// browser. Re-reads local source files; nothing is persisted.
	if strings.HasSuffix(id, "/raw-events") {
		id = strings.TrimSuffix(id, "/raw-events")
		s.handleSessionRawEvents(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/handoff/estimate → session-handoff
	// carry-mode price table + fork-picker boundaries (dry run, nothing
	// written). Must precede the /handoff match below.
	if strings.HasSuffix(id, "/handoff/estimate") {
		id = strings.TrimSuffix(id, "/handoff/estimate")
		s.handleSessionHandoffEstimate(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/handoff → perform the handoff (POST):
	// writes HANDOFF-<shortid>.md + one node-local handoffs row.
	if strings.HasSuffix(id, "/handoff") {
		id = strings.TrimSuffix(id, "/handoff")
		s.handleSessionHandoffCreate(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/launch → start the tool in the embedded
	// web terminal (POST). Mints an opaque session handle; the browser then
	// opens GET /ws/launch/<handle> to drive the PTY. Gated by the
	// LaunchManager seam (503 when the launcher is disabled).
	if strings.HasSuffix(id, "/launch") {
		id = strings.TrimSuffix(id, "/launch")
		s.handleSessionLaunch(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/resume → NATIVE resume (POST): spawn the
	// tool's own resume mechanism (claude `--resume <id>`, codex `resume <id>`)
	// in a fresh embedded terminal so the real prior transcript reopens
	// (session-attach design Phase 3). 409 when the tool has no grounded native
	// resume (the Continue-in… handoff-fork is the fallback). Classified Execute
	// via sessionSubRouteCapabilities, like /launch.
	if strings.HasSuffix(id, "/resume") {
		id = strings.TrimSuffix(id, "/resume")
		s.handleSessionResume(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/predict → the Next-Message Cost &
	// Limit Predictor (docs/plans/next-message-cost-predictor-plan-...).
	// Cost estimate is pure read-side math over token_usage; the limit
	// gauge is proxy-gated (Phase C capture) and renders "needs proxy"
	// until snapshots exist.
	if strings.HasSuffix(id, "/predict") {
		id = strings.TrimSuffix(id, "/predict")
		s.handleSessionPredict(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/tasks → the Phase-2 session-level
	// task/todo/plan tracking report (docs/task-tracking.md "Phase 2").
	// Per-task tokens/cost/elapsed/actions attributed via
	// taskflow.Attributor, priced through the same cost-ladder pattern
	// as live.go. Read-only; the calm empty state (has_tasks=false) is
	// the majority case.
	if strings.HasSuffix(id, "/tasks") {
		id = strings.TrimSuffix(id, "/tasks")
		s.handleSessionTasks(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/org-intel → the org-served Cloud
	// Intelligence result the node last pulled back for this session
	// (org-served-cloud-intelligence plan §3.5, W8b). A read over the
	// NODE-LOCAL org_intel_cache; the honest empty (enriched=false) is the
	// ordinary state for a node whose org has not enabled enrichment.
	if strings.HasSuffix(id, "/org-intel") {
		id = strings.TrimSuffix(id, "/org-intel")
		s.handleSessionOrgIntel(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/verbosity → the Output Composition
	// (Verbosity) card. Read-side: visible narrative/artifact bytes
	// segmented from assistant text + authored code (writes + shell
	// commands) from actions.content_bytes (migration 054).
	// Sub-route: /api/session/<id>/tags → session classification mutation
	// (POST): add/remove tags, toggle the favorite star, set the note. Execute
	// via sessionSubRouteCapabilities, like /launch and /resume.
	if strings.HasSuffix(id, "/tags") {
		id = strings.TrimSuffix(id, "/tags")
		s.handleSessionTags(w, r, id)
		return
	}
	if strings.HasSuffix(id, "/verbosity") {
		id = strings.TrimSuffix(id, "/verbosity")
		s.handleSessionVerbosity(w, r, id)
		return
	}
	if id == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	type modelBucket struct {
		Model             string  `json:"model"`
		Input             int64   `json:"input"`
		Output            int64   `json:"output"`
		CacheRead         int64   `json:"cache_read"`
		CacheCreation     int64   `json:"cache_creation"`
		Reasoning         int64   `json:"reasoning,omitempty"`
		WebSearchRequests int64   `json:"web_search_requests,omitempty"`
		TurnCount         int64   `json:"turn_count"`
		CostUSD           float64 `json:"cost_usd"`
		AICostUSD         float64 `json:"ai_cost_usd"`
		ToolCostUSD       float64 `json:"tool_cost_usd"`
		// Per-bucket AICost components (v1.6.13) — sums equal AICostUSD.
		// Feed the session-detail Models Used panel's cost-by-bucket
		// stacked bar. Zero values stay in the response so the frontend
		// can render a 4-segment bar uniformly even for cache-only models.
		InputCostUSD         float64 `json:"input_cost_usd"`
		OutputCostUSD        float64 `json:"output_cost_usd"`
		CacheReadCostUSD     float64 `json:"cache_read_cost_usd"`
		CacheCreationCostUSD float64 `json:"cache_creation_cost_usd"`
	}
	// lineageChild is one spawned (forked/subagent) session in the
	// lineage children list (migration 069; opencode included since the
	// 2026-08-21 parent_id linkage). Token/cost/action rollups let the
	// LineageBanner show what each sub-agent session cost without
	// navigating into it. Emitted as [] not null.
	type lineageChild struct {
		ID           string `json:"id"`
		ThreadSource string `json:"thread_source,omitempty"`
		StartedAt    string `json:"started_at"`
		// Rollups over the child's own rows (omitempty so a fork with no
		// usage yet renders exactly as before).
		InputTokens  int64   `json:"input_tokens,omitempty"`
		OutputTokens int64   `json:"output_tokens,omitempty"`
		CostUSD      float64 `json:"cost_usd,omitempty"`
		ActionCount  int64   `json:"action_count,omitempty"`
	}
	type sessionDetail struct {
		ID        string  `json:"id"`
		Tool      string  `json:"tool"`
		Project   string  `json:"project"`
		Model     string  `json:"model,omitempty"`
		StartedAt string  `json:"started_at"`
		EndedAt   *string `json:"ended_at,omitempty"`
		// LastActivityAt is COALESCE(ended_at, MAX(actions.timestamp)) — the
		// real end of activity for both closed and open/never-closed
		// sessions. The frontend uses it for the Elapsed figure so a session
		// that stopped without a clean ended_at (rollup never finalized)
		// shows start→last-activity instead of start→now (the 583h bug).
		// Mirrors the sessions-list endpoint's COALESCE (see the list query).
		// Empty only when the session has neither ended_at nor any action.
		LastActivityAt string `json:"last_activity_at,omitempty"`
		TotalActions   int    `json:"total_actions"`
		SuccessActions int    `json:"success_actions"`
		FailureActions int    `json:"failure_actions"`
		// SidechainActionCount is the inline sub-agent activity volume
		// (migration 010 model: sub-agents share the parent's session row,
		// flagged is_sidechain). Drives the LineageBanner's sidechain note
		// and the System tab's Sub-agents section.
		SidechainActionCount int      `json:"sidechain_action_count"`
		QualityScore         *float64 `json:"quality_score,omitempty"`
		ErrorRate            *float64 `json:"error_rate,omitempty"`
		RedundancyRatio      *float64 `json:"redundancy_ratio,omitempty"`
		// Spec §14.1 freshness/stale-read split — populated only
		// when the session has cache_events (Tier 3 / pre-backfill
		// sessions leave these nil, no fake zeros).
		StaleReadsWasteful      *int             `json:"stale_reads_wasteful,omitempty"`
		StaleReadsNecessary     *int             `json:"stale_reads_necessary,omitempty"`
		RedundancyRatioWasteful *float64         `json:"redundancy_ratio_wasteful,omitempty"`
		Tokens                  map[string]int64 `json:"tokens"`
		// TokenUsageAvailable distinguishes captured zero usage from no usage rows.
		TokenUsageAvailable bool `json:"token_usage_available"`
		// ContextBudgetTokens + TokensNote are the honest fallback for a
		// session with NO captured token usage. Hooks and native files can
		// omit usage even when an agent did real work. ContextBudgetTokens is the carried context
		// budget (the prompt_context section counts — part of a turn's input
		// but never billed on their own), surfaced as an ESTIMATE separate
		// from cost_usd; TokensNote explains why the billed figure is empty.
		// Both omitted when the session has real billed usage.
		ContextBudgetTokens int64  `json:"context_budget_tokens,omitempty"`
		TokensNote          string `json:"tokens_note,omitempty"`
		// PerModel breaks the deduped tokens + cost out by model so the
		// session detail modal shows haiku and opus separately when a
		// session uses both (Claude Code's main vs sub-agent split, etc.).
		PerModel []modelBucket `json:"per_model"`
		// CostUSD is the legacy total; AICostUSD + ToolCostUSD split
		// the same number so callers can render API spend vs tool
		// fees separately. Total == AI + Tool always.
		CostUSD       float64        `json:"cost_usd"`
		AICostUSD     float64        `json:"ai_cost_usd"`
		ToolCostUSD   float64        `json:"tool_cost_usd"`
		ToolBreakdown []actionBucket `json:"tool_breakdown"`
		// CacheSummary is the C15 cost-view cache annotation —
		// a compact glance-view of cache health for this session
		// (tier, event/hit/write/rewrite counts, token rollup,
		// ratio). Sits next to PerModel + ToolBreakdown so the
		// session detail modal shows API spend, tool spend, and
		// cache efficiency side by side. The full Cache tab
		// continues to load /api/session/<id>/cache for the
		// timeline + entries detail.
		CacheSummary *SessionCacheAnnotation `json:"cache_summary,omitempty"`
		// Codex fork/subagent lineage (migration 069). ThreadSource is
		// "subagent" for a spawned subagent, "user" for a normal/user-fork
		// session (empty/nil for non-codex tools). ForkedFromID non-empty =
		// forked/continued from that codex thread id; ParentInDB reports
		// whether a session row exists for it. Children are the sessions
		// spawned from THIS session (always [] not null so the UI can map
		// unconditionally).
		ForkedFromID   string         `json:"forked_from_id,omitempty"`
		ParentThreadID string         `json:"parent_thread_id,omitempty"`
		ThreadSource   string         `json:"thread_source,omitempty"`
		ParentInDB     bool           `json:"parent_in_db"`
		Children       []lineageChild `json:"children"`
		// Surface / SurfaceHost are the capture-surface attribution
		// (migration 107): the normalized kind (cli | ide | desktop |
		// sdk | web) + the concrete host token ("vscode", "cursor",
		// "claude-desktop", ...). Both omitted when no adapter stamped
		// one — the frontend treats absence as "unknown", never as
		// "cli". Additive; frontend rendering is a follow-up.
		Surface     string `json:"surface,omitempty"`
		SurfaceHost string `json:"surface_host,omitempty"`
		// Resume declares how a CLOSED session on this tool can be reopened
		// (session-attach design Phase 3): kind "native" (grounded
		// ResumeNative → the Resume button POSTs /resume), "handoff" (no native
		// resume but launchable → the Continue-in… fork), or "none". Derived
		// from the integration registry by capability SHAPE. Always present.
		Resume sessionResumeInfo `json:"resume"`
		// Session classification (plan §4): the tags this session carries, the
		// favorite star, and the full note text (the list endpoint ships only a
		// has_note flag). Tags is always [] not null so the frontend can map
		// unconditionally, like Children above.
		Tags     []string `json:"tags"`
		Favorite bool     `json:"favorite"`
		Note     string   `json:"note,omitempty"`
		Rating   int      `json:"rating,omitempty"`
	}

	var d sessionDetail
	d.ID = id
	var endedAt sql.NullString
	var q, er, rr sql.NullFloat64
	var rrWasteful sql.NullFloat64
	var stWasteful, stNecessary sql.NullInt64
	var model sql.NullString
	if err := s.db().QueryRowContext(
		r.Context(),
		`SELECT s.tool, COALESCE(p.root_path, ''), s.model, s.started_at,
		        s.ended_at, s.quality_score, s.error_rate, s.redundancy_ratio,
		        s.stale_reads_wasteful, s.stale_reads_necessary, s.redundancy_ratio_wasteful
		 FROM sessions s LEFT JOIN projects p ON p.id = s.project_id
		 WHERE s.id = ?`, id,
	).Scan(&d.Tool, &d.Project, &model, &d.StartedAt, &endedAt, &q, &er, &rr,
		&stWasteful, &stNecessary, &rrWasteful); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		writeErr(w, err)
		return
	}
	if model.Valid {
		d.Model = model.String
	}
	if endedAt.Valid {
		v := endedAt.String
		d.EndedAt = &v
	}
	if q.Valid {
		v := q.Float64
		d.QualityScore = &v
	}
	if er.Valid {
		v := er.Float64
		d.ErrorRate = &v
	}
	if rr.Valid {
		v := rr.Float64
		d.RedundancyRatio = &v
	}
	if stWasteful.Valid {
		v := int(stWasteful.Int64)
		d.StaleReadsWasteful = &v
	}
	if stNecessary.Valid {
		v := int(stNecessary.Int64)
		d.StaleReadsNecessary = &v
	}
	if rrWasteful.Valid {
		v := rrWasteful.Float64
		d.RedundancyRatioWasteful = &v
	}

	// Action aggregates and tool breakdown. COALESCE the SUMs: a session
	// whose actions were all pruned by retention but whose token_usage rows
	// survive (token_usage isn't pruned) has zero matching rows here, and
	// SUM over an empty set is NULL — scanning that into int fails ("NULL to
	// int is unsupported") and 500s the whole endpoint. This became routine
	// once the FK-787 retention fix let actions actually prune; the detail
	// view must still render (tokens/model/cost) for such sessions. COUNT(*)
	// is never NULL.
	var maxActionTs sql.NullString
	if err := s.db().QueryRowContext(
		r.Context(),
		`SELECT COUNT(*),
		        COALESCE(SUM(CASE WHEN success = 0 THEN 0 ELSE 1 END), 0),
		        COALESCE(SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END), 0),
		        MAX(timestamp),
		        COALESCE(SUM(CASE WHEN is_sidechain = 1 THEN 1 ELSE 0 END), 0)
		 FROM actions WHERE session_id = ?`, id,
	).Scan(&d.TotalActions, &d.SuccessActions, &d.FailureActions, &maxActionTs,
		&d.SidechainActionCount); err != nil {
		writeErr(w, err)
		return
	}
	// last_activity_at = ended_at when the session was cleanly closed, else
	// the last action's timestamp. Drives the frontend Elapsed figure so a
	// never-closed session doesn't measure start→now.
	switch {
	case endedAt.Valid && endedAt.String != "":
		d.LastActivityAt = endedAt.String
	case maxActionTs.Valid:
		d.LastActivityAt = maxActionTs.String
	}
	brRows, err := s.db().QueryContext(r.Context(),
		`SELECT action_type, COUNT(*),
		        SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END)
		 FROM actions WHERE session_id = ?
		 GROUP BY action_type
		 ORDER BY COUNT(*) DESC`, id)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer brRows.Close()
	for brRows.Next() {
		var ab actionBucket
		if err := brRows.Scan(&ab.ActionType, &ab.Count, &ab.Failures); err != nil {
			writeErr(w, err)
			return
		}
		d.ToolBreakdown = append(d.ToolBreakdown, ab)
	}
	if d.ToolBreakdown == nil {
		d.ToolBreakdown = []actionBucket{}
	}

	// C15 cache annotation. Best-effort: a query failure leaves
	// CacheSummary nil and the modal hides the cache pill row.
	// Nil-summary also when the session has no cache_events
	// (pre-cachetrack history, non-Anthropic provider).
	if summary, err := loadSessionCacheAnnotation(r.Context(), s.db(), id); err == nil && summary != nil {
		d.CacheSummary = summary
	}

	// Token totals + per-model breakdown — both come from the same
	// per-turn-deduped CTE. Pre-2026-04-29 this endpoint had the same
	// bug as the cost engine: "if api_turns has ANY row for this
	// session, drop ALL token_usage rows" — so a session where the
	// proxy intercepted only some turns would show pure-proxy totals
	// even though most of the work went direct (b9bd459d had 3% of
	// input tokens captured by the proxy; the rest came from JSONL
	// and was silently dropped). The fix mirrors the cost engine's
	// per-turn dedup (api_turns.request_id ↔ token_usage.source_event_id):
	// proxy wins for turns it intercepted, JSONL fills the gaps.
	//
	// Single SQL CTE keeps the rollup atomic and avoids two passes
	// over the same dataset. cost.Options doesn't expose a session_id
	// filter so we can't reuse cost.Engine.Summary directly here.
	//
	// Per-row pricing (no SQL GROUP BY): the cost engine's long-context
	// dispatch reprices entire turns whose prompt window exceeds a
	// threshold (Sonnet 4 / 4.5 at 200K, gpt-5.4 / 5.5 at 272K, Gemini
	// Pro at 200K). LC is a per-request property — aggregating tokens
	// across many turns first would false-positive the threshold check
	// whenever a session's summed prompt exceeded it even if no single
	// turn did. So we pull individual rows and bucket per-model in Go.
	// Per-session token aggregation has TWO dedup gates against the
	// proxy api_turns rows:
	//
	//   1. source_event_id NOT IN (api_turns.request_id) — when the
	//      JSONL adapter mirrors the upstream message id verbatim
	//      (Claude Code stores Anthropic's msg_xxx; the proxy's
	//      request_id captures the same). Per-turn exact match.
	//
	//   2. NOT EXISTS (api_turn with same model + token shape) —
	//      fallback for adapters whose source_event_id format does
	//      NOT mirror the proxy's request_id. Codex's JSONL adapter
	//      writes a synthetic "tk:<file>:L<line>" id while the proxy
	//      stores OpenAI's "resp_<hex>" id; the shape match is the
	//      only way to recognise them as the same turn. Deliberately
	//      NO minute bucket: codex's rollout flush lands ~10s after
	//      the proxy logs the request, so ~15% of turns near a minute
	//      boundary would escape a minute-bucketed match and
	//      double-count (audit F1). False-positive risk: two distinct
	//      same-session calls with byte-identical token shapes
	//      collapse — effectively impossible since cache_read grows
	//      monotonically across a session; same trade
	//      Engine.loadRows::sessionShapeKey accepts in cost/summary.go.
	const dedupedRowsCTE = `WITH proxy_turn_ids AS (
		SELECT request_id FROM api_turns
		 WHERE session_id = ? AND request_id IS NOT NULL AND request_id != ''
	),
	combined AS (
		-- api_turns has no reasoning_tokens column (proxy folds it into
		-- output_tokens at capture); pad with 0 so the UNION schema
		-- matches and cost.Compute applies its reasoning × output_rate
		-- multiplier as 0 for proxy rows. fast = the proxy row's own tier;
		-- inherited_fast = a fast JSONL twin exists for this turn (codex,
		-- where the priority flag lives only on the JSONL/config path) —
		-- audit F1.
		SELECT at.model, at.input_tokens, at.output_tokens, at.cache_read_tokens,
		       at.cache_creation_tokens, at.cache_creation_1h_tokens,
		       0 AS reasoning_tokens,
		       at.web_search_requests, at.cost_usd,
		       COALESCE(at.fast, 0) AS fast,
		       CASE WHEN EXISTS (
		           SELECT 1 FROM token_usage tw
		           WHERE tw.session_id = at.session_id AND COALESCE(tw.fast, 0) = 1
		             AND COALESCE(tw.model, '') = COALESCE(at.model, '')
		             AND COALESCE(tw.input_tokens, 0) = COALESCE(at.input_tokens, 0)
		             -- Reasoning fold: proxy output is gross (visible +
		             -- reasoning); codex's JSONL twin nets reasoning out.
		             AND COALESCE(tw.output_tokens, 0) + COALESCE(tw.reasoning_tokens, 0) = COALESCE(at.output_tokens, 0)
		             AND COALESCE(tw.cache_read_tokens, 0) = COALESCE(at.cache_read_tokens, 0)
		             AND COALESCE(tw.cache_creation_tokens, 0) = COALESCE(at.cache_creation_tokens, 0)
		       ) THEN 1 ELSE 0 END AS inherited_fast,
		       -- Row timestamp: feeds DATE-EFFECTIVE pricing (proxyAwareCost).
		       at.timestamp AS timestamp
		FROM api_turns at WHERE at.session_id = ?
		UNION ALL
		SELECT tu.model, tu.input_tokens, tu.output_tokens, tu.cache_read_tokens,
		       tu.cache_creation_tokens, tu.cache_creation_1h_tokens,
		       tu.reasoning_tokens,
		       tu.web_search_requests, tu.estimated_cost_usd,
		       COALESCE(tu.fast, 0) AS fast,
		       0 AS inherited_fast,
		       tu.timestamp AS timestamp
		FROM token_usage tu
		WHERE tu.session_id = ?
		  AND (tu.source_event_id IS NULL OR tu.source_event_id = ''
		       OR tu.source_event_id NOT IN (SELECT request_id FROM proxy_turn_ids))
		  -- F1: also drop a JSONL row that duplicates a proxy turn by
		  -- token-bundle shape when the ids don't match (codex: tk:… vs
		  -- resp_…). COALESCE because codex leaves cache_creation NULL on
		  -- one side, 0 on the other. The output comparison FOLDS the
		  -- JSONL row's reasoning back in: the proxy stores gross output
		  -- (visible + reasoning), while codex's adapter nets reasoning
		  -- out at emit time — an exact-output match missed every
		  -- reasoning turn, so both captures of the same call survived
		  -- and the timeline showed each turn twice (tk:… and resp_…).
		  -- Anthropic adapters store reasoning 0 (thinking already folded
		  -- into output on both sides), so the sum is a no-op for them.
		  AND NOT EXISTS (
		      SELECT 1 FROM api_turns ap
		      WHERE ap.session_id = tu.session_id
		        AND COALESCE(ap.model, '') = COALESCE(tu.model, '')
		        AND COALESCE(ap.input_tokens, 0) = COALESCE(tu.input_tokens, 0)
		        AND COALESCE(ap.output_tokens, 0) = COALESCE(tu.output_tokens, 0) + COALESCE(tu.reasoning_tokens, 0)
		        AND COALESCE(ap.cache_read_tokens, 0) = COALESCE(tu.cache_read_tokens, 0)
		        AND COALESCE(ap.cache_creation_tokens, 0) = COALESCE(tu.cache_creation_tokens, 0)
		  )
		  -- Copilot family (copilot, copilot-cli) emits TWO token_usage rows per
		  -- turn: a full-usage row (Tier-1 process-log [DEBUG] usage block / the
		  -- request row) and an output-only "shadow" row (Tier-3 events.jsonl
		  -- assistant.message). The adapter set MessageID on both intending a
		  -- (session_id, message_id) merge, but the store upserts on
		  -- (source_file, source_event_id), so they never merge and the output
		  -- double-counts. Drop the output-only shadow when a full-usage sibling
		  -- carries the same output in this session. Scoped to the copilot tools
		  -- (the only adapters that emit >1 token row per turn) so nothing else
		  -- is affected.
		  AND NOT (
		      tu.tool IN ('copilot', 'copilot-cli')
		      AND COALESCE(tu.input_tokens, 0) = 0
		      AND COALESCE(tu.cache_read_tokens, 0) = 0
		      AND COALESCE(tu.cache_creation_tokens, 0) = 0
		      AND COALESCE(tu.output_tokens, 0) > 0
		      AND EXISTS (
		          SELECT 1 FROM token_usage tsh
		          WHERE tsh.session_id = tu.session_id
		            AND tsh.rowid != tu.rowid
		            AND COALESCE(tsh.output_tokens, 0) = COALESCE(tu.output_tokens, 0)
		            AND (COALESCE(tsh.input_tokens, 0) > 0
		                 OR COALESCE(tsh.cache_read_tokens, 0) > 0
		                 OR COALESCE(tsh.cache_creation_tokens, 0) > 0)
		      )
		  )
	)`

	sessionModel := d.Model
	rows, err := s.db().QueryContext(r.Context(),
		dedupedRowsCTE+`
		SELECT COALESCE(NULLIF(model, ''), ?),
		       COALESCE(input_tokens, 0),
		       COALESCE(output_tokens, 0),
		       COALESCE(cache_read_tokens, 0),
		       COALESCE(cache_creation_tokens, 0),
		       COALESCE(cache_creation_1h_tokens, 0),
		       COALESCE(reasoning_tokens, 0),
		       COALESCE(web_search_requests, 0),
		       COALESCE(cost_usd, 0),
		       COALESCE(fast, 0),
		       COALESCE(inherited_fast, 0),
		       COALESCE(timestamp, '')
		FROM combined`,
		id, id, id, sessionModel)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()

	bucketByModel := map[string]*modelBucket{}
	bucketOrder := []string{}
	var totalIn, totalOut, totalCR, totalCC, totalCC1h, totalReasoning int64
	for rows.Next() {
		var modelKey string
		var bundle cost.TokenBundle
		var recorded float64
		var fastInt, inheritedFastInt int
		var tsStr string
		if err := rows.Scan(&modelKey,
			&bundle.Input, &bundle.Output,
			&bundle.CacheRead, &bundle.CacheCreation, &bundle.CacheCreation1h,
			&bundle.Reasoning,
			&bundle.WebSearchRequests,
			&recorded, &fastInt, &inheritedFastInt, &tsStr); err != nil {
			writeErr(w, err)
			return
		}
		// Row timestamp feeds date-effective pricing (see proxyAwareCost).
		// Unparseable/absent stamps stay zero → current rates.
		rowAt, _ := time.Parse(time.RFC3339Nano, tsStr)
		// Per-row cost: prefer recorded estimated_cost_usd / cost_usd
		// when non-zero (only OpenCode + Pi adapters set it today; api_turns
		// carries it for proxy rows). proxyAwareCost applies the F1 "keep
		// proxy, OR-in fast" rule — a codex proxy turn that inherited a fast
		// JSONL twin re-prices with the FastMultiplier premium (its recorded
		// cost was the standard wire tier). ComputeBreakdown returns the AI
		// vs tool split so we can show "API cost vs tool cost vs total"
		// separately; recorded costs land in AICost only (those adapters
		// don't model web_search billing). Recorded-cost rows leave the
		// per-bucket components zero so the frontend's "$ mode" stacked bar
		// renders as a single undifferentiated AI block.
		var rowCost, rowAICost, rowToolCost float64
		var rowInputCost, rowOutputCost, rowCacheReadCost, rowCacheCreationCost float64
		if cb, ok := proxyAwareCost(s.opts.CostEngine, modelKey, bundle, recorded, fastInt != 0, inheritedFastInt != 0, rowAt); ok {
			rowCost = cb.Total
			rowAICost = cb.AICost
			rowToolCost = cb.ToolCost
			rowInputCost = cb.InputCost
			rowOutputCost = cb.OutputCost
			rowCacheReadCost = cb.CacheReadCost
			rowCacheCreationCost = cb.CacheCreationCost
		}

		mb, ok := bucketByModel[modelKey]
		if !ok {
			mb = &modelBucket{Model: modelKey}
			bucketByModel[modelKey] = mb
			bucketOrder = append(bucketOrder, modelKey)
		}
		mb.Input += bundle.Input
		mb.Output += bundle.Output
		mb.CacheRead += bundle.CacheRead
		mb.CacheCreation += bundle.CacheCreation
		mb.Reasoning += bundle.Reasoning
		mb.WebSearchRequests += bundle.WebSearchRequests
		mb.TurnCount++
		mb.CostUSD += rowCost
		mb.AICostUSD += rowAICost
		mb.ToolCostUSD += rowToolCost
		mb.InputCostUSD += rowInputCost
		mb.OutputCostUSD += rowOutputCost
		mb.CacheReadCostUSD += rowCacheReadCost
		mb.CacheCreationCostUSD += rowCacheCreationCost

		d.CostUSD += rowCost
		d.AICostUSD += rowAICost
		d.ToolCostUSD += rowToolCost
		totalIn += bundle.Input
		totalOut += bundle.Output
		totalCR += bundle.CacheRead
		totalCC += bundle.CacheCreation
		totalCC1h += bundle.CacheCreation1h
		totalReasoning += bundle.Reasoning
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}
	// Order buckets by token volume DESC (matches the prior SQL ORDER BY).
	sort.SliceStable(bucketOrder, func(i, j int) bool {
		bi, bj := bucketByModel[bucketOrder[i]], bucketByModel[bucketOrder[j]]
		ti := bi.Input + bi.Output + bi.CacheRead + bi.CacheCreation
		tj := bj.Input + bj.Output + bj.CacheRead + bj.CacheCreation
		return ti > tj
	})
	perModel := make([]modelBucket, 0, len(bucketOrder))
	for _, key := range bucketOrder {
		perModel = append(perModel, *bucketByModel[key])
	}
	d.Tokens = map[string]int64{
		"input": totalIn, "output": totalOut, "cache_read": totalCR, "cache_creation": totalCC,
		// cache_creation_1h is the 1h-ephemeral-tier subset of cache_creation
		// (the rest is 5m-tier). Surfaced separately so the session-detail
		// Token Buckets panel can split "Cache Write" into "Cache Write (5m)"
		// and "Cache Write (1h)" — different bill rates.
		"cache_creation_1h": totalCC1h,
		"reasoning":         totalReasoning,
	}
	d.PerModel = perModel
	d.TokenUsageAvailable = len(perModel) > 0

	// Context occupancy cannot replace missing usage. A captured row with
	// zero counts is distinct from an absent row. Never infer cost from budget.
	if !d.TokenUsageAvailable {
		d.ContextBudgetTokens = s.sessionContextBudget(r.Context(), id)
		d.TokensNote = tokensUnbilledNote(d.Tool, d.ContextBudgetTokens)
	} else if d.Tool == "cursor" {
		d.TokensNote, _ = store.New(s.db()).CursorUsageNote(r.Context(), id)
	}

	// Headline model fallback. sessions.model is populated only when an
	// ingested event carried a model, which is unreliable across adapters:
	// it's empty for nearly all claude-code sessions and every cursor session
	// (cursor's hooks don't deliver a model, and current cursor-agent emits
	// no stop-token row — see project_cursor_model_capture_gap). When it's
	// empty, surface the dominant model from the per-turn token_usage
	// breakdown, which IS the authoritative per-turn model source. perModel
	// is already sorted by token volume DESC, so the first non-empty bucket
	// is the model the session predominantly ran on.
	if d.Model == "" {
		for _, mb := range perModel {
			if mb.Model != "" {
				d.Model = mb.Model
				break
			}
		}
	}

	// Fork/subagent lineage (migration 069; codex + opencode). Best-effort:
	// a query failure leaves the lineage fields at their zero value and the
	// modal simply hides the badge + spawned-sessions list. Children is
	// normalized to [] below so the frontend can map unconditionally.
	// Capture-surface attribution (migration 107) — best-effort read;
	// a failure leaves both fields empty (= unknown) and omitted.
	if sv, serr := store.New(s.db()).LoadSessionSurface(r.Context(), id); serr == nil {
		d.Surface = sv.Surface
		d.SurfaceHost = sv.SurfaceHost
	}
	if lin, lerr := store.New(s.db()).LoadSessionLineage(r.Context(), id); lerr == nil {
		d.ForkedFromID = lin.ForkedFromID
		d.ParentThreadID = lin.ParentThreadID
		d.ThreadSource = lin.ThreadSource
		d.ParentInDB = lin.ParentInDB
		for _, c := range lin.Children {
			d.Children = append(d.Children, lineageChild{
				ID:           c.ID,
				ThreadSource: c.ThreadSource,
				StartedAt:    c.StartedAt,
				InputTokens:  c.InputTokens,
				OutputTokens: c.OutputTokens,
				CostUSD:      c.CostUSD,
				ActionCount:  c.ActionCount,
			})
		}
	}
	if d.Children == nil {
		d.Children = []lineageChild{}
	}

	// Additive resume-capability block (session-attach design Phase 3):
	// native / handoff / none, derived from the integration registry by
	// capability shape so the frontend never branches on tool name.
	d.Resume = resumeInfoForSession(d.Tool, id)

	// Session classification (plan §4). Degrades to the unclassified state on
	// error — an annotation-layer failure must not 500 the whole detail view.
	{
		st := store.New(s.db())
		if tags, tErr := st.SessionTags(r.Context(), id); tErr == nil {
			d.Tags = tags
		} else {
			s.opts.Logger.Warn("session detail: tag load failed", "err", tErr)
		}
		if annot, aErr := st.GetSessionAnnotation(r.Context(), id); aErr == nil {
			d.Favorite = annot.Favorite
			d.Note = annot.Note
			d.Rating = annot.Rating
		} else {
			s.opts.Logger.Warn("session detail: annotation load failed", "err", aErr)
		}
	}
	if d.Tags == nil {
		d.Tags = []string{}
	}

	writeJSON(w, d)
}

// contextTokensRe extracts the token count from a cursor prompt_context
// action's target ("Rules — 15580 tokens, 61924 chars"). The format is
// adapter-controlled (cursor.promptSectionEvent) and stable.
var contextTokensRe = regexp.MustCompile(`(\d+)\s+tokens`)

// sessionContextBudget sums the carried context budget from a session's
// prompt_context actions (cursor's per-section prompt-token counts). These
// tokens are part of a turn's input but never billed on their own, so this is
// only ever surfaced as an estimate for a session with no billed usage — it
// must NOT feed cost. Returns 0 on any error or when no sections exist.
func (s *Server) sessionContextBudget(ctx context.Context, sessionID string) int64 {
	rows, err := s.db().QueryContext(ctx,
		`SELECT COALESCE(target, '') FROM actions
		  WHERE session_id = ? AND action_type = 'prompt_context'`, sessionID)
	if err != nil {
		return 0
	}
	defer rows.Close()
	var total int64
	for rows.Next() {
		var target string
		if err := rows.Scan(&target); err != nil {
			return total
		}
		if m := contextTokensRe.FindStringSubmatch(target); m != nil {
			if v, perr := strconv.ParseInt(m[1], 10, 64); perr == nil {
				total += v
			}
		}
	}
	return total
}

// tokensUnbilledNote describes missing capture without attributing it to an
// unobserved failure. The budget clause never implies billed token counts.
func tokensUnbilledNote(tool string, budget int64) string {
	if tool == "cursor" {
		n := "Token usage was not captured for this Cursor session. Cursor's stop and afterAgentResponse hooks can omit usage, and an interrupted CLI run may end before reporting totals. Input, output, cache counts and cost are unknown, not zero."
		if budget > 0 {
			n += " The context budget is an estimate of prompt size, not billed usage."
		}
		return n
	}
	return "Token usage was not captured for this session. Token counts and cost are unknown, not zero."
}

type actionBucket struct {
	ActionType string `json:"action_type"`
	Count      int    `json:"count"`
	Failures   int    `json:"failures"`
}

// proxyAwareCost computes a deduped row's cost under the audit-F1 "keep
// proxy, OR-in fast" rule (docs/audits/audit-2026-06-08.md). The effective
// fast tier is the row's own fast OR a fast JSONL twin that was deduped
// against it (inheritedFast). A recorded proxy cost_usd is authoritative
// EXCEPT when the row inherited a fast flag it didn't carry itself — codex's
// proxy wire reports the standard tier, so its insert-time cost_usd was
// priced WITHOUT the FastMultiplier premium; in that one case we re-price
// from the table so the premium lands. Returns ok=false only when the model
// is unknown AND there's no recorded cost (caller leaves the row at $0,
// matching prior behavior).
//
// `at` is the row's own timestamp, used for DATE-EFFECTIVE pricing: a
// re-priced historical row bills at the rate in force when it ran, not
// today's. Pass the zero time when no stamp is available — LookupAt then
// falls back to current rates (never to the oldest tier). Recorded costs
// are unaffected either way: they were priced at insert time, which is
// already the historically correct rate.
func proxyAwareCost(engine *cost.Engine, model string, bundle cost.TokenBundle, recorded float64, ownFast, inheritedFast bool, at time.Time) (cost.Breakdown, bool) {
	bundle.Fast = ownFast || inheritedFast
	if recorded > 0 && !(inheritedFast && !ownFast) {
		// Recorded cost already reflects this row's own tier — use as-is.
		// Recorded-cost adapters (OpenCode, Pi) don't split AI vs tool, so
		// the whole amount lands on AICost, matching the prior code path.
		return cost.Breakdown{AICost: recorded, Total: recorded}, true
	}
	if engine == nil {
		return cost.Breakdown{}, false
	}
	return engine.ComputeBreakdownAt(model, bundle, at)
}

// handleSessionMessages serves /api/session/<id>/messages — one row
// per upstream Anthropic message id. Each row carries the message's
// own token usage and cost (per-turn deduped via the same
// proxy-preferred / JSONL-fallback logic as the session detail
// endpoint), plus the contained tool_calls grouped by message_id.
//
// Includes user-prompt rows synthesized from action_type='user_prompt'
// so the timeline shows "user said X → assistant did Y" together.
// inferenceBucketIndex picks which of a turn's chronologically-ordered token
// buckets owns a transcript action stamped actionTS (all stamps RFC3339).
//
// Boundary semantics differ by capture source: a proxy bucket (api_turns) is
// stamped at request START, so it owns actions from its own timestamp until
// the next bucket begins; a transcript bucket (codex token_count) is stamped
// at inference END, so it owns actions since the PREVIOUS bucket's end (the
// first transcript bucket is unbounded below). Both reduce to one walk: each
// bucket i has a lower bound — its own stamp when isProxy[i], otherwise
// bucket i-1's stamp — and the action belongs to the LAST bucket whose lower
// bound is strictly before the action stamp, defaulting to the first bucket.
// Strictly-before keeps an action stamped exactly at a transcript bucket's
// end (same-instant fixture data) on that bucket rather than sliding to its
// successor. Returns -1 only for an empty bucket list; an unparseable
// actionTS falls back to the first bucket.
func inferenceBucketIndex(stamps []string, isProxy []bool, actionTS string) int {
	if len(stamps) == 0 || len(stamps) != len(isProxy) {
		return -1
	}
	at, err := time.Parse(time.RFC3339Nano, actionTS)
	if err != nil {
		return 0
	}
	pick := 0
	for i := range stamps {
		var boundStamp string
		switch {
		case isProxy[i]:
			boundStamp = stamps[i]
		case i == 0:
			continue // unbounded below — the default pick already covers it
		default:
			boundStamp = stamps[i-1]
		}
		bound, err := time.Parse(time.RFC3339Nano, boundStamp)
		if err != nil {
			continue
		}
		if bound.Before(at) {
			pick = i
		}
	}
	return pick
}

func (s *Server) handleSessionMessages(w http.ResponseWriter, r *http.Request, sessionID string) {
	if sessionID == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	var sessionModel, sessionTool string
	_ = s.db().QueryRowContext(
		r.Context(),
		`SELECT COALESCE(model, ''), COALESCE(tool, '') FROM sessions WHERE id = ?`, sessionID,
	).Scan(&sessionModel, &sessionTool)
	// browserSession gates the assistant_message inline-body behaviour to
	// browser-captured chat sessions (chatgpt-web / claude-web /
	// perplexity-web / gemini-web / copilot-web — every browserchat tool
	// ends in "-web"). For those sessions the response text lives in
	// actions.raw_tool_output and IS the user-facing content to render
	// inline; for coding-agent adapters assistant_message.raw_tool_output
	// is model narration already surfaced via target/excerpt, so their
	// rows stay byte-for-byte unchanged (no regression). This is a
	// capability distinction (browser chat = raw_tool_output is the
	// displayable answer), resolved once here at the boundary rather than
	// branched on tool name deeper in the scan loop.
	browserSession := strings.HasSuffix(sessionTool, "-web")
	type toolCallRow struct {
		// ActionID is the actions.id primary key. Surfaced so the
		// frontend can call /api/action/<id>/full_text to fetch the
		// untruncated raw_tool_input + raw_tool_output on demand for
		// the copy and view-full-text buttons.
		ActionID    int64  `json:"action_id"`
		ActionType  string `json:"action_type"`
		RawToolName string `json:"raw_tool_name"`
		Target      string `json:"target"`
		FullText    string `json:"full_text,omitempty"`
		// FullTextElided marks rows whose raw_tool_input exceeded the
		// per-row inline cap (fullTextInlineMax) and was truncated for
		// the timeline payload. UI fetches the untruncated body via
		// /api/action/<id>/full_text when the operator clicks copy or
		// view-full-text.
		FullTextElided bool `json:"full_text_elided,omitempty"`
		// HasFullOutput is true when actions.raw_tool_output is
		// non-empty for this row — i.e. the adapter captured a
		// tool_result body that's available via the on-demand
		// /api/action/<id>/full_text endpoint. The inline Excerpt
		// stays 2 KiB (FTS5 cap) regardless; this flag tells the UI
		// there's a fuller version to offer.
		HasFullOutput bool   `json:"has_full_output,omitempty"`
		Excerpt       string `json:"excerpt,omitempty"`
		Success       bool   `json:"success"`
		ErrorMessage  string `json:"error_message,omitempty"`
		Timestamp     string `json:"timestamp"`
		// DurationMs is the per-tool-call wall-clock duration in ms
		// (sourced from actions.duration_ms). Adapters populate this
		// where the source data carries timing — codex via the
		// function_call→output timestamp gap, claude-code via
		// tool_use→tool_result gap, copilot via elapsedMs. Zero when
		// the source provided no timing signal or the row predates
		// the v1.4.28 capture work.
		DurationMs int64 `json:"duration_ms,omitempty"`
		// Per-event metadata extracted from actions.metadata JSON
		// (migration 017 + codex JSONL extension). Empty / false when
		// the source adapter didn't emit the field. omitempty keeps
		// the response payload lean.
		PermissionMode string `json:"permission_mode,omitempty"`
		EffortLevel    string `json:"effort_level,omitempty"`
		IsInterrupt    bool   `json:"is_interrupt,omitempty"`
		// StopReason — why the assistant turn ended; ServiceTier — served
		// capacity tier. Per-message metadata from the transcript.
		StopReason  string `json:"stop_reason,omitempty"`
		ServiceTier string `json:"service_tier,omitempty"`
		// Browser-capture API-call details, extracted from
		// actions.metadata JSON on browserchat assistant_message rows
		// (request_url / id_source / granularity / prompt_tokens_est /
		// response_tokens_est). Empty / zero for every non-browser
		// adapter — omitempty keeps the payload lean so only browser
		// rows carry them. See ActionMetadata (models) + the browserchat
		// buildMetadata seam.
		RequestURL        string `json:"request_url,omitempty"`
		IDSource          string `json:"id_source,omitempty"`
		Granularity       string `json:"granularity,omitempty"`
		PromptTokensEst   int64  `json:"prompt_tokens_est,omitempty"`
		ResponseTokensEst int64  `json:"response_tokens_est,omitempty"`
	}
	type messageRow struct {
		Account models.MessageAccount `json:"account"`
		// Seq is the row's 1..N ordinal in CHRONOLOGICAL order, assigned
		// once right after the authoritative merge sort and therefore
		// stable across pagination, ?tail and any ?sort_by reordering.
		// The dashboard's "#" column renders it (a page-relative index
		// would renumber under a non-default sort), and sort_by=seq is
		// the "restore chronological order" key.
		Seq               int    `json:"seq"`
		MessageID         string `json:"message_id"`
		Timestamp         string `json:"timestamp"`
		Role              string `json:"role"`
		Model             string `json:"model,omitempty"`
		Input             int64  `json:"input"`
		Output            int64  `json:"output"`
		CacheRead         int64  `json:"cache_read"`
		CacheCreation     int64  `json:"cache_creation"`
		CacheCw1h         int64  `json:"cache_creation_1h"`
		Reasoning         int64  `json:"reasoning,omitempty"`
		WebSearchRequests int64  `json:"web_search_requests,omitempty"`
		// CostUSD is the legacy total; AICostUSD + ToolCostUSD split
		// it so the Messages table can render API / Tool / Total in
		// separate columns. CostUSD == AICostUSD + ToolCostUSD always.
		CostUSD     float64 `json:"cost_usd"`
		AICostUSD   float64 `json:"ai_cost_usd"`
		ToolCostUSD float64 `json:"tool_cost_usd"`
		// ElapsedMs is the wall-clock gap between this message's
		// timestamp and the next message's. For user rows it
		// approximates "time the assistant took to respond"; for
		// assistant rows it approximates "time the user took before
		// sending the next prompt". null on the last message in the
		// session (no successor to subtract from). Computed
		// post-sort, after pagination boundaries are decided.
		ElapsedMs *int64 `json:"elapsed_ms,omitempty"`
		// ToolDurationMs is the sum of contained tool_calls'
		// duration_ms — the assistant's tool-execution time for
		// this turn. Differs from ElapsedMs (which spans the entire
		// gap to the next message, including the model's reasoning
		// time and the user's typing time). Zero when no contained
		// tool_call carries duration_ms.
		ToolDurationMs int64 `json:"tool_duration_ms,omitempty"`
		ToolCallCount  int   `json:"tool_call_count"`
		// EffortLevel is the per-turn reasoning effort the adapter
		// captured for this message — sourced from
		// actions.metadata.$.effort_level on any action in the turn.
		// All actions in one message share the same effort_level
		// (codex collaboration_mode.settings.reasoning_effort is
		// per-turn, antigravity's effort is encoded in the SKU
		// itself — gemini-pro-agent, gemini-3.1-pro-low/medium/high
		// per [[project_antigravity_skus]]). First non-empty wins.
		// Empty when the adapter didn't emit it (Anthropic via
		// claude-code/cowork, copilot, etc. — Anthropic doesn't
		// expose a reasoning-effort knob).
		EffortLevel string `json:"effort_level,omitempty"`
		// StopReason is the assistant turn's terminal reason (end_turn /
		// max_tokens / tool_use / stop_sequence / refusal) and ServiceTier
		// the served capacity tier (standard / priority / batch), both from
		// the transcript (claude-code / cowork). Aggregated per message —
		// first non-empty among the turn's actions wins. Empty when the
		// adapter didn't emit them or the rows pre-date capture.
		StopReason  string `json:"stop_reason,omitempty"`
		ServiceTier string `json:"service_tier,omitempty"`
		// Fast is true when any token/turn row in this message bucket was
		// served in the provider's low-latency "fast" tier (Anthropic
		// Opus 4.8 speed:"fast", captured by the proxy). The timeline
		// renders a FAST badge on the row; CostUSD already reflects the
		// FastMultiplier premium. Zero/false for every standard turn.
		Fast      bool          `json:"fast,omitempty"`
		ToolCalls []toolCallRow `json:"tool_calls"`
		// TpsMs is the denominator the Tok/s column divides Output by, in
		// milliseconds — picked from the best available timing source per a
		// layered priority (see the post-merge block): (1) the proxy's
		// MEASURED total_response_ms when this bucket carries a proxy turn;
		// (2) the intra-turn generation span (MAX−MIN of a codex user-turn's
		// per-inference timestamps) when the bucket rolled up ≥2 timestamped
		// rows; (3) ElapsedMs (gap-to-next-message) for a single non-proxied
		// API call (claude-code). null when none applies (e.g. a
		// single-inference non-proxied codex turn, where gap-to-next would be
		// the meaningless inter-turn idle gap). TpsBasis names which source
		// was used, for the column's tooltip.
		TpsMs    *int64 `json:"tps_ms,omitempty"`
		TpsBasis string `json:"tps_basis,omitempty"`
		// respMs/firstT/lastT/tsCount/turnRollup are unexported per-bucket
		// accumulators feeding the TpsMs decision (set during merge,
		// resolved post-sort). Never serialized. respMs sums the proxy
		// total_response_ms of any api_turns sub-rows; firstT/lastT/tsCount
		// bound the intra-turn span; turnRollup marks a whole-turn bucket
		// (key from token_usage.turn_id — codex) so a single-inference codex
		// turn shows "—" rather than a gap-to-next rate.
		respMs     int64
		firstT     time.Time
		lastT      time.Time
		tsCount    int
		turnRollup bool
		// isProxy marks a bucket created from an api_turns row. Proxy
		// rows are stamped at request START while transcript token rows
		// are stamped at inference END — pickTurnBucket needs to know
		// which boundary semantics a bucket's Timestamp carries when
		// assigning a turn's tool calls to per-inference buckets.
		isProxy bool
	}

	// 1. Token rows joined into per-message buckets. Two modes:
	//
	//   - Default (turn rollup): bucket by
	//     COALESCE(turn_id, message_id, source_event_id). For codex
	//     (v1.7.24+) turn_id groups multiple per-inference rows back
	//     into the user-turn; for claudecode and other Anthropic
	//     adapters turn_id is NULL and message_id (= the upstream
	//     msg_xxx) is the natural per-API-call grouping.
	//
	//   - ?detail=inference: bucket by
	//     COALESCE(message_id, source_event_id). For codex this
	//     produces one row per token_count event (per model inference);
	//     for claudecode it's identical to the default mode because
	//     turn_id is NULL.
	//
	// api_turns is per-HTTP-request (proxy emits one row per upstream
	// call). Its request_id alone is NOT a usable grouping key for
	// transcript-backed adapters whose id scheme is disjoint from the
	// wire's (codex: actions + token rows key by turn_id / tk:…, the
	// proxy stores resp_…) — bucketing proxy rows by request_id strands
	// them with no tool calls and the timeline degrades into
	// "API call (no recovered text)" placeholder stubs. So each proxy
	// row first resolves its JSONL TWIN (the same turn captured from the
	// transcript — see the twin join below) and adopts the key the twin
	// would have used; request_id remains the fallback when no twin
	// exists (claude-code, where the ids already agree; or the JSONL
	// side not yet ingested).
	//nolint:gosec // G101: code-constant SQL grouping expression switched by query param. No credentials involved; gosec false-positives on the `_id` substring.
	tokenGroupExpr := `COALESCE(NULLIF(turn_id, ''), NULLIF(message_id, ''), source_event_id, '')`
	proxyKeyExpr := `COALESCE(NULLIF(tw.turn_id, ''), NULLIF(tw.message_id, ''), NULLIF(at.request_id, ''), '')` //nolint:gosec // G101: same false-positive; code-constant SQL fragment.
	if r.URL.Query().Get("detail") == "inference" {
		tokenGroupExpr = `COALESCE(NULLIF(message_id, ''), source_event_id, '')`                                            //nolint:gosec // G101: same false-positive as above; code-constant SQL fragment.
		proxyKeyExpr = `COALESCE(NULLIF(tw.message_id, ''), NULLIF(tw.source_event_id, ''), NULLIF(at.request_id, ''), '')` //nolint:gosec // G101: same false-positive; code-constant SQL fragment.
	}
	dedupedRowsCTE := `WITH proxy_turn_ids AS (
		SELECT request_id FROM api_turns
		 WHERE session_id = ? AND request_id IS NOT NULL AND request_id != ''
	),
	combined AS (
		-- api_turns has no reasoning_tokens column (proxy folds reasoning
		-- into output_tokens at capture — the cross-provider proxy
		-- convention, see parseGeminiResponse). tw is the row's JSONL
		-- TWIN: the same turn captured by the file adapter, matched by
		-- token-bundle shape WITH the reasoning fold applied (proxy
		-- output = JSONL output + reasoning; Anthropic adapters store
		-- reasoning 0 with the fold already baked into output, so the
		-- sum is a no-op there). The twin supplies what the wire capture
		-- can't know: the transcript's turn_id / per-inference
		-- message_id (so the proxy row lands in the SAME bucket the
		-- transcript's action rows key to), the reasoning split for
		-- display, and the codex priority flag (inherited_fast — audit
		-- F1; the flag lives only on the JSONL/config path). closest-
		-- timestamp LIMIT 1 disambiguates the (effectively impossible —
		-- cache_read grows monotonically) case of two same-shape turns.
		SELECT ` + proxyKeyExpr + ` AS msg_key,
		       at.model, at.timestamp,
		       at.input_tokens,
		       CASE WHEN tw.rowid IS NOT NULL
		                 AND COALESCE(at.output_tokens, 0) >= COALESCE(tw.reasoning_tokens, 0)
		            THEN COALESCE(at.output_tokens, 0) - COALESCE(tw.reasoning_tokens, 0)
		            ELSE at.output_tokens END AS output_tokens,
		       at.cache_read_tokens,
		       at.cache_creation_tokens, at.cache_creation_1h_tokens,
		       CASE WHEN tw.rowid IS NOT NULL
		                 AND COALESCE(at.output_tokens, 0) >= COALESCE(tw.reasoning_tokens, 0)
		            THEN COALESCE(tw.reasoning_tokens, 0)
		            ELSE 0 END AS reasoning_tokens,
		       at.web_search_requests, at.cost_usd,
		       COALESCE(at.fast, 0) AS fast,
		       CASE WHEN COALESCE(tw.fast, 0) = 1 THEN 1 ELSE 0 END AS inherited_fast,
		       COALESCE(tw.turn_id, '') AS turn_id,
		       COALESCE(at.total_response_ms, 0) AS total_response_ms,
		       1 AS is_proxy
		FROM api_turns at
		LEFT JOIN token_usage tw ON tw.rowid = (
		    SELECT tu.rowid FROM token_usage tu
		    WHERE tu.session_id = at.session_id
		      AND COALESCE(tu.model, '') = COALESCE(at.model, '')
		      AND COALESCE(tu.input_tokens, 0) = COALESCE(at.input_tokens, 0)
		      AND COALESCE(tu.output_tokens, 0) + COALESCE(tu.reasoning_tokens, 0) = COALESCE(at.output_tokens, 0)
		      AND COALESCE(tu.cache_read_tokens, 0) = COALESCE(at.cache_read_tokens, 0)
		      AND COALESCE(tu.cache_creation_tokens, 0) = COALESCE(at.cache_creation_tokens, 0)
		      -- SQLite (both the C library and modernc.org/sqlite) cannot
		      -- resolve a correlated outer-table reference (at.timestamp)
		      -- placed in a subquery's ORDER BY clause — only WHERE — so
		      -- "ORDER BY ABS(julianday(tu.timestamp) -
		      -- julianday(at.timestamp)) LIMIT 1" throws "no such column:
		      -- at.timestamp" at prepare time and 500s this endpoint for
		      -- EVERY session that has any api_turns row. Pick the
		      -- closest-timestamp twin via an equality against a MIN(...)
		      -- computed the same way instead — both references stay in
		      -- WHERE, where correlation works.
		      AND ABS(julianday(tu.timestamp) - julianday(at.timestamp)) = (
		          SELECT MIN(ABS(julianday(tu2.timestamp) - julianday(at.timestamp)))
		          FROM token_usage tu2
		          WHERE tu2.session_id = at.session_id
		            AND COALESCE(tu2.model, '') = COALESCE(at.model, '')
		            AND COALESCE(tu2.input_tokens, 0) = COALESCE(at.input_tokens, 0)
		            AND COALESCE(tu2.output_tokens, 0) + COALESCE(tu2.reasoning_tokens, 0) = COALESCE(at.output_tokens, 0)
		            AND COALESCE(tu2.cache_read_tokens, 0) = COALESCE(at.cache_read_tokens, 0)
		            AND COALESCE(tu2.cache_creation_tokens, 0) = COALESCE(at.cache_creation_tokens, 0)
		      )
		    LIMIT 1
		)
		WHERE at.session_id = ?
		UNION ALL
		SELECT ` + tokenGroupExpr + ` AS msg_key,
		       tu.model, tu.timestamp,
		       tu.input_tokens, tu.output_tokens, tu.cache_read_tokens,
		       tu.cache_creation_tokens, tu.cache_creation_1h_tokens,
		       tu.reasoning_tokens,
		       tu.web_search_requests, tu.estimated_cost_usd,
		       COALESCE(tu.fast, 0) AS fast,
		       0 AS inherited_fast,
		       COALESCE(tu.turn_id, '') AS turn_id,
		       0 AS total_response_ms,
		       0 AS is_proxy
		FROM token_usage tu
		WHERE tu.session_id = ?
		  AND (tu.source_event_id IS NULL OR tu.source_event_id = ''
		       OR tu.source_event_id NOT IN (SELECT request_id FROM proxy_turn_ids))
		  -- F1: also drop a JSONL row that duplicates a proxy turn by
		  -- token-bundle shape when the ids don't match (codex: tk:… vs
		  -- resp_…). COALESCE because codex leaves cache_creation NULL on
		  -- one side, 0 on the other. The output comparison FOLDS the
		  -- JSONL row's reasoning back in: the proxy stores gross output
		  -- (visible + reasoning), while codex's adapter nets reasoning
		  -- out at emit time — an exact-output match missed every
		  -- reasoning turn, so both captures of the same call survived
		  -- and the timeline showed each turn twice (tk:… and resp_…).
		  -- Anthropic adapters store reasoning 0 (thinking already folded
		  -- into output on both sides), so the sum is a no-op for them.
		  AND NOT EXISTS (
		      SELECT 1 FROM api_turns ap
		      WHERE ap.session_id = tu.session_id
		        AND COALESCE(ap.model, '') = COALESCE(tu.model, '')
		        AND COALESCE(ap.input_tokens, 0) = COALESCE(tu.input_tokens, 0)
		        AND COALESCE(ap.output_tokens, 0) = COALESCE(tu.output_tokens, 0) + COALESCE(tu.reasoning_tokens, 0)
		        AND COALESCE(ap.cache_read_tokens, 0) = COALESCE(tu.cache_read_tokens, 0)
		        AND COALESCE(ap.cache_creation_tokens, 0) = COALESCE(tu.cache_creation_tokens, 0)
		  )
		  -- Copilot family (copilot, copilot-cli) emits TWO token_usage rows per
		  -- turn: a full-usage row (Tier-1 process-log [DEBUG] usage block / the
		  -- request row) and an output-only "shadow" row (Tier-3 events.jsonl
		  -- assistant.message). The adapter set MessageID on both intending a
		  -- (session_id, message_id) merge, but the store upserts on
		  -- (source_file, source_event_id), so they never merge and the output
		  -- double-counts. Drop the output-only shadow when a full-usage sibling
		  -- carries the same output in this session. Scoped to the copilot tools
		  -- (the only adapters that emit >1 token row per turn) so nothing else
		  -- is affected.
		  AND NOT (
		      tu.tool IN ('copilot', 'copilot-cli')
		      AND COALESCE(tu.input_tokens, 0) = 0
		      AND COALESCE(tu.cache_read_tokens, 0) = 0
		      AND COALESCE(tu.cache_creation_tokens, 0) = 0
		      AND COALESCE(tu.output_tokens, 0) > 0
		      AND EXISTS (
		          SELECT 1 FROM token_usage tsh
		          WHERE tsh.session_id = tu.session_id
		            AND tsh.rowid != tu.rowid
		            AND COALESCE(tsh.output_tokens, 0) = COALESCE(tu.output_tokens, 0)
		            AND (COALESCE(tsh.input_tokens, 0) > 0
		                 OR COALESCE(tsh.cache_read_tokens, 0) > 0
		                 OR COALESCE(tsh.cache_creation_tokens, 0) > 0)
		      )
		  )
	)`
	rows, err := s.db().QueryContext(r.Context(),
		dedupedRowsCTE+`
		SELECT msg_key,
		       timestamp,
		       COALESCE(NULLIF(model, ''), ?),
		       COALESCE(input_tokens, 0),
		       COALESCE(output_tokens, 0),
		       COALESCE(cache_read_tokens, 0),
		       COALESCE(cache_creation_tokens, 0),
		       COALESCE(cache_creation_1h_tokens, 0),
		       COALESCE(reasoning_tokens, 0),
		       COALESCE(web_search_requests, 0),
		       COALESCE(cost_usd, 0),
		       COALESCE(fast, 0),
		       COALESCE(inherited_fast, 0),
		       COALESCE(turn_id, ''),
		       COALESCE(total_response_ms, 0),
		       COALESCE(is_proxy, 0)
		FROM combined
		WHERE msg_key IS NOT NULL AND msg_key != ''
		ORDER BY timestamp ASC`,
		sessionID, sessionID, sessionID, sessionModel)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()

	byKey := map[string]*messageRow{}
	out := []*messageRow{}
	// turnBuckets groups the token buckets of one transcript turn, in
	// chronological order, keyed by the turn id the ADAPTER stamps on
	// its action rows (codex actions carry message_id = the turn UUID).
	// In default (turn-rollup) mode the bucket key IS the turn id so
	// actions match byKey directly and this map is never consulted; in
	// ?detail=inference mode the buckets are per-inference (tk:… /
	// resp_… keys) and this map is the join that lets each tool call
	// land on the inference that emitted it (see pickTurnBucket) instead
	// of stranding every inference row with a synthetic
	// "API call (no recovered text)" stub.
	turnBuckets := map[string][]*messageRow{}
	for rows.Next() {
		var key, ts, model, turnID string
		var bundle cost.TokenBundle
		var recorded float64
		var fastInt, inheritedFastInt, isProxyInt int
		var respMs int64
		if err := rows.Scan(&key, &ts, &model,
			&bundle.Input, &bundle.Output,
			&bundle.CacheRead, &bundle.CacheCreation, &bundle.CacheCreation1h,
			&bundle.Reasoning,
			&bundle.WebSearchRequests,
			&recorded, &fastInt, &inheritedFastInt, &turnID, &respMs, &isProxyInt); err != nil {
			writeErr(w, err)
			return
		}
		// F1 "keep proxy, OR-in fast": effective tier is the row's own fast
		// OR a fast JSONL twin's. proxyAwareCost re-prices a codex proxy turn
		// that inherited fast (its recorded cost was the standard wire tier).
		bundle.Fast = fastInt != 0 || inheritedFastInt != 0
		var costUSD, aiCostUSD, toolCostUSD float64
		msgAt, _ := time.Parse(time.RFC3339Nano, ts)
		if cb, ok := proxyAwareCost(s.opts.CostEngine, model, bundle, recorded, fastInt != 0, inheritedFastInt != 0, msgAt); ok {
			costUSD = cb.Total
			aiCostUSD = cb.AICost
			toolCostUSD = cb.ToolCost
		}
		mr, ok := byKey[key]
		if !ok {
			mr = &messageRow{
				MessageID: key,
				Timestamp: ts,
				Role:      "assistant",
				Model:     model,
				ToolCalls: []toolCallRow{},
				isProxy:   isProxyInt != 0,
			}
			byKey[key] = mr
			out = append(out, mr)
			if turnID != "" {
				turnBuckets[turnID] = append(turnBuckets[turnID], mr)
			}
		}
		if mr.Model == "" && model != "" {
			mr.Model = model
		}
		// A turn shows the ⚡ premium badge only when it was served fast AND
		// the model actually carries a fast-mode premium
		// (Pricing.FastMultiplier > 0). Codex sends service_tier:"priority"
		// globally, but only gpt-5.5 / gpt-5.4 have a documented Fast
		// premium — so mini/codex priority turns keep the service_tier pill
		// (captured separately on the action row) without an ⚡ that implies
		// a price bump they don't incur. Anthropic Opus 4.8 (FastMultiplier
		// 2) still lights up exactly as before.
		if bundle.Fast {
			if p, ok := s.opts.CostEngine.LookupAt(model, msgAt); ok && p.FastMultiplier > 0 {
				mr.Fast = true
			}
		}
		mr.Input += bundle.Input
		mr.Output += bundle.Output
		mr.CacheRead += bundle.CacheRead
		mr.CacheCreation += bundle.CacheCreation
		mr.CacheCw1h += bundle.CacheCreation1h
		mr.Reasoning += bundle.Reasoning
		mr.WebSearchRequests += bundle.WebSearchRequests
		mr.CostUSD += costUSD
		mr.AICostUSD += aiCostUSD
		mr.ToolCostUSD += toolCostUSD
		// Per-bucket timing accumulators feeding the TpsMs decision below.
		// respMs sums any proxy total_response_ms (the measured per-call
		// wall-clock — preferred source). turnRollup marks a whole-turn
		// bucket (key from turn_id — codex). firstT/lastT/tsCount bound the
		// intra-turn generation span for a codex user-turn (many token_count
		// inference rows rolled into one bucket).
		mr.respMs += respMs
		if turnID != "" {
			mr.turnRollup = true
		}
		if t, perr := time.Parse(time.RFC3339Nano, ts); perr == nil {
			if mr.tsCount == 0 || t.Before(mr.firstT) {
				mr.firstT = t
			}
			if mr.tsCount == 0 || t.After(mr.lastT) {
				mr.lastT = t
			}
			mr.tsCount++
		}
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}

	// 2. Tool calls — grouped by message_id (or source_event_id as
	// fallback for pre-backfill rows). Append into each message's
	// ToolCalls; create synthetic message rows for actions whose
	// message_id doesn't have a token row (typically user_prompt).
	//
	// Excerpts are loaded in a second batch query — see
	// loadActionExcerpts for why an inline LEFT JOIN on
	// action_excerpts is O(N×M) on FTS5 (~136s for a 1772-action
	// session before this change).
	actRows, err := s.db().QueryContext(r.Context(),
		`SELECT a.id, COALESCE(message_id, source_event_id) AS msg_key,
		        a.action_type, COALESCE(a.raw_tool_name, ''),
		        COALESCE(a.target, ''), COALESCE(a.raw_tool_input, ''),
		        LENGTH(COALESCE(a.raw_tool_output, '')) AS raw_output_len,
		        CASE WHEN a.action_type = 'assistant_message'
		             THEN substr(COALESCE(a.raw_tool_output, ''), 1, ?)
		             ELSE '' END AS asst_body,
		        COALESCE(a.success, 1),
		        COALESCE(a.error_message, ''), a.timestamp,
		        COALESCE(a.duration_ms, 0),
		        COALESCE(json_extract(a.metadata, '$.permission_mode'), '') AS permission_mode,
		        COALESCE(json_extract(a.metadata, '$.effort_level'), '') AS effort_level,
		        COALESCE(json_extract(a.metadata, '$.is_interrupt'), 0) AS is_interrupt,
		        COALESCE(json_extract(a.metadata, '$.stop_reason'), '') AS stop_reason,
		        COALESCE(json_extract(a.metadata, '$.service_tier'), '') AS service_tier,
		        COALESCE(json_extract(a.metadata, '$.request_url'), '') AS request_url,
		        COALESCE(json_extract(a.metadata, '$.id_source'), '') AS id_source,
		        COALESCE(json_extract(a.metadata, '$.granularity'), '') AS granularity,
		        COALESCE(json_extract(a.metadata, '$.prompt_tokens_est'), 0) AS prompt_tokens_est,
		        COALESCE(json_extract(a.metadata, '$.response_tokens_est'), 0) AS response_tokens_est
		 FROM actions a
		 WHERE a.session_id = ?
		   AND a.action_type <> 'post_tool_batch'
		 ORDER BY a.timestamp ASC`, fullTextInlineMax, sessionID)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer actRows.Close()
	// pendingExcerpt records each tool-call's location so we can fill
	// its Excerpt field after the batch FTS5 lookup below. Indices into
	// mr.ToolCalls are stable once the scan loop ends.
	type pendingExcerpt struct {
		actionID int64
		mr       *messageRow
		idx      int
	}
	var pendings []pendingExcerpt
	var actionIDs []int64
	for actRows.Next() {
		var actionID int64
		var key, actionType, rawTool, target, rawInput, asstBody, errMsg, ts string
		var permMode, effortLevel, stopReason, serviceTier string
		var requestURL, idSource, granularity string
		var promptTokensEst, responseTokensEst int64
		var success, isInterrupt int
		var durationMs, rawOutputLen int64
		if err := actRows.Scan(&actionID, &key, &actionType, &rawTool, &target, &rawInput, &rawOutputLen, &asstBody, &success, &errMsg, &ts, &durationMs, &permMode, &effortLevel, &isInterrupt, &stopReason, &serviceTier, &requestURL, &idSource, &granularity, &promptTokensEst, &responseTokensEst); err != nil {
			writeErr(w, err)
			return
		}
		fullText := target
		switch actionType {
		case "user_prompt", "system_prompt", "ask_user", "run_command":
			if rawInput != "" {
				fullText = rawInput
			}
		}
		if actionType == "run_command" {
			fullText = decodeCommandInput(fullText)
		}
		// Browser chat: the assistant's on-screen answer is stored in
		// raw_tool_output (target is only a one-line preview). Surface
		// the (SQL-capped) response body as the row's inline FullText so
		// the timeline shows the actual reply; the untruncated body
		// stays available via /api/action/<id>/full_text. Gated on
		// browserSession so coding-agent assistant_message rows (model
		// narration) render exactly as before.
		if browserSession && actionType == "assistant_message" && asstBody != "" {
			fullText = asstBody
		}
		fullTextElided := false
		if len(fullText) > fullTextInlineMax {
			fullText = fullText[:fullTextInlineMax]
			fullTextElided = true
		}
		// A capped assistant body whose source was longer than the inline
		// cap is elided too (the substr already trimmed it in SQL, so the
		// len check above can't see the original length — use raw_output_len).
		if browserSession && actionType == "assistant_message" && rawOutputLen > fullTextInlineMax {
			fullTextElided = true
		}
		tc := toolCallRow{
			ActionID:          actionID,
			ActionType:        actionType,
			RawToolName:       rawTool,
			Target:            target,
			FullText:          fullText,
			FullTextElided:    fullTextElided,
			HasFullOutput:     rawOutputLen > 0,
			Success:           success != 0,
			ErrorMessage:      errMsg,
			Timestamp:         ts,
			DurationMs:        durationMs,
			PermissionMode:    permMode,
			EffortLevel:       effortLevel,
			IsInterrupt:       isInterrupt != 0,
			StopReason:        stopReason,
			ServiceTier:       serviceTier,
			RequestURL:        requestURL,
			IDSource:          idSource,
			Granularity:       granularity,
			PromptTokensEst:   promptTokensEst,
			ResponseTokensEst: responseTokensEst,
		}
		mr, ok := byKey[key]
		if !ok && actionType != "user_prompt" {
			// The action's message key is a transcript TURN id with no
			// same-key token bucket — the ?detail=inference case, where
			// the token buckets are per-inference (tk:… / resp_… keys)
			// while codex stamps every action with the turn UUID. The
			// content exists; only the join key differs in grain. Assign
			// the tool call to the inference that emitted it by
			// timestamp (inferenceBucketIndex) instead of stranding the
			// per-inference rows as "API call (no recovered text)"
			// stubs. user_prompt stays excluded: it deliberately
			// synthesizes its own role=user row below.
			if list := turnBuckets[key]; len(list) > 0 {
				stamps := make([]string, len(list))
				proxies := make([]bool, len(list))
				for i, b := range list {
					stamps[i] = b.Timestamp
					proxies[i] = b.isProxy
				}
				if idx := inferenceBucketIndex(stamps, proxies, ts); idx >= 0 {
					mr, ok = list[idx], true
				}
			}
		}
		if !ok {
			// No matching token row — this is a user_prompt or
			// other action whose parent message doesn't carry token
			// usage (user messages don't bill). Synthesize a row
			// so the timeline still shows it.
			role := "user"
			if actionType != "user_prompt" {
				role = "assistant"
			}
			// Per-turn model resolution for synthesized rows. A user
			// prompt and its assistant turn share a request_id, so the
			// assistant's token row carries the canonical per-turn
			// model (e.g. claude-haiku-4-5-20251001). Falling back to
			// sessions.model would always show the FIRST turn's model
			// for every later turn — wrong whenever a session crosses
			// upstream models (Copilot Auto routing routinely picks
			// different models per turn).
			model := sessionModel
			if role == "user" && strings.HasPrefix(key, "user:") {
				peerKey := "assistant:" + strings.TrimPrefix(key, "user:")
				if peer, ok := byKey[peerKey]; ok && peer.Model != "" {
					model = peer.Model
				}
			}
			mr = &messageRow{
				MessageID: key,
				Timestamp: ts,
				Role:      role,
				Model:     model,
				ToolCalls: []toolCallRow{},
			}
			byKey[key] = mr
			out = append(out, mr)
		}
		mr.ToolCalls = append(mr.ToolCalls, tc)
		pendings = append(pendings, pendingExcerpt{actionID: actionID, mr: mr, idx: len(mr.ToolCalls) - 1})
		actionIDs = append(actionIDs, actionID)
		mr.ToolCallCount++
		mr.ToolDurationMs += tc.DurationMs
		if mr.EffortLevel == "" && tc.EffortLevel != "" {
			mr.EffortLevel = tc.EffortLevel
		}
		if mr.StopReason == "" && tc.StopReason != "" {
			mr.StopReason = tc.StopReason
		}
		if mr.ServiceTier == "" && tc.ServiceTier != "" {
			mr.ServiceTier = tc.ServiceTier
		}
	}
	if err := actRows.Err(); err != nil {
		writeErr(w, err)
		return
	}
	// Batch-fetch excerpts for every tool call (single FTS5 scan instead
	// of N×M); see loadActionExcerpts. maxBytes=0 preserves the original
	// full-text semantics for the messages view.
	excerptByID, err := loadActionExcerpts(r.Context(), s.db(), actionIDs, 0)
	if err != nil {
		writeErr(w, err)
		return
	}
	for _, p := range pendings {
		if ex := excerptByID[p.actionID]; ex != "" {
			p.mr.ToolCalls[p.idx].Excerpt = ex
		}
	}

	// Orphan-token stub injection — for agentic sessions (gemini /
	// antigravity tool-call-loop turns) where the upstream API stores
	// no extractable content for most LLM calls, surface a synthetic
	// row carrying the per-turn token totals so the dashboard's
	// expand-row view has SOMETHING to display instead of an empty
	// Tools column. Gated on orphan ratio > 0.5 so claude sessions
	// (where every turn already has narrative or a tool call) don't
	// grow noise stubs that obscure real content.
	var assistantTotal, assistantOrphan int
	for _, mr := range out {
		if mr.Role != "assistant" {
			continue
		}
		assistantTotal++
		if len(mr.ToolCalls) == 0 {
			assistantOrphan++
		}
	}
	if assistantTotal > 0 && float64(assistantOrphan)/float64(assistantTotal) > 0.5 {
		for _, mr := range out {
			if mr.Role != "assistant" || len(mr.ToolCalls) > 0 {
				continue
			}
			target := fmt.Sprintf("API call (no recovered text): %d in + %d cache_read + %d cache_create + %d out tokens",
				mr.Input, mr.CacheRead, mr.CacheCreation, mr.Output)
			mr.ToolCalls = append(mr.ToolCalls, toolCallRow{
				ActionType:  "llm_call",
				RawToolName: "synthetic.api_call",
				Target:      target,
				Success:     true,
				Timestamp:   mr.Timestamp,
			})
			mr.ToolCallCount++
		}
	}

	// Sort the merged list chronologically — token-row pass appended
	// in time order but the actions pass may have appended synthetic
	// rows out of order. On equal timestamps, prefer the user message:
	// the proxy or adapter often stamps a synthesized user_prompt with
	// the same wall-clock as the assistant turn it triggers, and the
	// timeline reads more naturally with "user said X → assistant did Y".
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Timestamp != out[j].Timestamp {
			return out[i].Timestamp < out[j].Timestamp
		}
		return out[i].Role == "user" && out[j].Role != "user"
	})

	// Stable chronological ordinal, assigned ONCE here — before the
	// ?sort_by reorder and before pagination — so the "#" column means the
	// same thing on every page and under every sort, and so every sort has
	// a deterministic final tie-break (see messageSortOrder).
	for i := range out {
		out[i].Seq = i + 1
	}

	// Per-message wall-clock duration: gap from this message's
	// timestamp to the NEXT message's. Computed across the full sorted
	// timeline (not the paginated slice) so a row near a page boundary
	// still gets the correct successor. Null on the final message —
	// no follower to subtract from. Adapter-captured DurationMs (codex
	// task_complete, copilot elapsedMs, …) lives on the contained
	// actions/tool_calls; this field is the orthogonal "wall-clock
	// between user and assistant turns" view.
	for i := 0; i < len(out)-1; i++ {
		t1, err1 := time.Parse(time.RFC3339Nano, out[i].Timestamp)
		t2, err2 := time.Parse(time.RFC3339Nano, out[i+1].Timestamp)
		if err1 != nil || err2 != nil {
			continue
		}
		ms := t2.Sub(t1).Milliseconds()
		if ms < 0 {
			continue
		}
		out[i].ElapsedMs = &ms
	}

	// Tok/s denominator (TpsMs) — layered, best-source-first. Runs after
	// the ElapsedMs loop because the "elapsed" tier consumes it.
	//   1. "measured"   — the proxy's total_response_ms (summed across the
	//                     bucket's api_turns sub-rows): the real per-call
	//                     wall-clock. Best when the session routed through
	//                     the proxy (claude-code AND codex).
	//   2. "intra-turn" — MAX−MIN of a codex user-turn's per-inference
	//                     timestamps (≥2 rows): a real generation+tool span
	//                     for non-proxied codex. Anchored to inference
	//                     completion timestamps, so it slightly excludes the
	//                     first inference's own window (negligible on long
	//                     turns).
	//   3. "elapsed"    — ElapsedMs (gap-to-next-message): valid only for a
	//                     single non-proxied API call (claude-code), where
	//                     it approximates response time. Skipped for a
	//                     turn-rollup bucket (codex), where gap-to-next is
	//                     the meaningless inter-turn idle gap.
	// Synthesized action rows (user_prompt, etc.) match no tier → "—".
	for _, mr := range out {
		switch {
		case mr.respMs > 0:
			ms := mr.respMs
			mr.TpsMs, mr.TpsBasis = &ms, "measured"
		case mr.tsCount >= 2 && mr.lastT.Sub(mr.firstT).Milliseconds() > 0:
			ms := mr.lastT.Sub(mr.firstT).Milliseconds()
			mr.TpsMs, mr.TpsBasis = &ms, "intra-turn"
		case !mr.turnRollup && mr.ElapsedMs != nil && *mr.ElapsedMs > 0:
			ms := *mr.ElapsedMs
			mr.TpsMs, mr.TpsBasis = &ms, "elapsed"
		}
	}

	accounts, accountErr := store.New(s.db()).LoadMessageAccounts(r.Context(), sessionID, sessionTool)
	if accountErr != nil {
		http.Error(w, "account evidence unavailable", http.StatusInternalServerError)
		return
	}
	accountSummary := struct {
		Accounts  []models.ToolAccountEvidence `json:"accounts"`
		Observed  int                          `json:"observed"`
		Unknown   int                          `json:"unknown"`
		Conflicts int                          `json:"conflicts"`
	}{Accounts: []models.ToolAccountEvidence{}}
	seenAccounts := map[string]bool{}
	for _, mr := range out {
		mr.Account = accounts[mr.Role+":"+mr.MessageID]
		if mr.Account.Status == "" {
			mr.Account = models.MessageAccount{Status: "unknown", Label: "Unknown", Evidence: []models.ToolAccountEvidence{}}
		}
		switch mr.Account.Status {
		case "observed":
			accountSummary.Observed++
		case "conflict":
			accountSummary.Conflicts++
		default:
			accountSummary.Unknown++
		}
		for _, e := range mr.Account.Evidence {
			if !seenAccounts[e.Key] {
				seenAccounts[e.Key] = true
				accountSummary.Accounts = append(accountSummary.Accounts, e)
			}
		}
	}
	// ?sort_by / ?sort_dir — display ordering, applied LAST: after the
	// authoritative chronological merge, after the Seq assignment, and after
	// the ElapsedMs / TpsMs derivations (which are defined over the
	// chronological timeline and would be corrupted by a reorder), but BEFORE
	// the offset/limit slice so a sort addresses the WHOLE timeline rather
	// than the current page. Absent / unrecognised params resolve to the
	// chronological default, whose permutation is the identity — the response
	// is then byte-identical to the pre-sort handler.
	sortBy, sortDesc := parseMessagesSortParams(r)
	applySort := func(rows []*messageRow) []*messageRow {
		if messageSortIsDefault(sortBy, sortDesc) || len(rows) < 2 {
			return rows
		}
		fields := make([]messageSortField, len(rows))
		for i, mr := range rows {
			f := messageSortField{
				Seq:            mr.Seq,
				Timestamp:      mr.Timestamp,
				MessageID:      mr.MessageID,
				Role:           mr.Role,
				Model:          mr.Model,
				EffortLevel:    mr.EffortLevel,
				Account:        mr.Account.Label,
				AccountUnknown: mr.Account.Status == "unknown",
				Input:          mr.Input,
				CacheRead:      mr.CacheRead,
				CacheWrite:     mr.CacheCreation,
				Output:         mr.Output,
				ElapsedMs:      mr.ElapsedMs,
				ToolCalls:      mr.ToolCallCount,
				AICostUSD:      mr.AICostUSD,
				ToolCostUSD:    mr.ToolCostUSD,
				CostUSD:        mr.CostUSD,
			}
			// Tok/s: same arithmetic as the client's tokensPerSec() helper
			// (output ÷ tps_ms/1000, absent when either is missing) so the
			// server sorts on exactly the number the operator sees.
			if mr.Output > 0 && mr.TpsMs != nil && *mr.TpsMs > 0 {
				tps := float64(mr.Output) / (float64(*mr.TpsMs) / 1000)
				f.TokensPerSec = &tps
			}
			// Content: mirrors the Content cell, which is derived from the
			// first tool call. No tool calls → the cell renders "—" and the
			// key is the empty string.
			if len(mr.ToolCalls) > 0 {
				tc := mr.ToolCalls[0]
				f.Content = messageContentSortKey(tc.ActionType, tc.Target)
			}
			fields[i] = f
		}
		sorted := make([]*messageRow, len(rows))
		for i, p := range messageSortOrder(fields, sortBy, sortDesc) {
			sorted[i] = rows[p]
		}
		return sorted
	}

	// ?tail=N (FROZEN contract, v1.24): return the last N rows of the FULL
	// ordered timeline — NOT a re-slice of a paginated page. Because it
	// addresses the whole timeline, tail is mutually exclusive with the
	// pagination params: combined with offset/limit/locate it is an explicit
	// 400 (they would otherwise fight over which window wins, and the old
	// "tail-after-page" order silently returned the tail of page 0, not the
	// true last N). Standalone: response offset = index of the first returned
	// row (total−N, clamped ≥0); total stays the FULL count. Clamp N to 1..200
	// (>200 saturates); a <1 / non-numeric tail is ignored as absent and falls
	// through to the default pagination path below, so an absent-or-garbage
	// tail is byte-identical to the pre-tail behaviour.
	if tailStr := r.URL.Query().Get("tail"); tailStr != "" {
		if r.URL.Query().Get("offset") != "" ||
			r.URL.Query().Get("limit") != "" ||
			r.URL.Query().Get("locate") != "" {
			http.Error(w, "tail cannot be combined with offset, limit, or locate", http.StatusBadRequest)
			return
		}
		if n, err := strconv.Atoi(tailStr); err == nil && n >= 1 {
			if n > 200 {
				n = 200
			}
			total := len(out)
			offset := 0
			if total > n {
				offset = total - n
			}
			// tail keeps its frozen meaning — the last N rows
			// CHRONOLOGICALLY — and the sort then reorders just those N
			// for display. tail+sort is therefore NOT an error (unlike
			// tail+pagination, which would fight over the window).
			writeJSON(w, map[string]any{
				"session_id":      sessionID,
				"messages":        applySort(out[offset:]),
				"account_summary": accountSummary,
				"total":           total,
				"limit":           n,
				"offset":          offset,
			})
			return
		}
	}

	// Pagination — added v1.4.24 because rendering 5000+ messages in
	// one go was crashing the dashboard browser tab. Default limit is
	// 100; pass limit=0 explicitly to opt into the pre-v1.4.24 "all
	// messages" behaviour. Server-side paginates AFTER the chronological
	// sort so the page boundaries are stable across re-fetches.
	limit, offset := 100, 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	// Reorder for display BEFORE locate/offset/limit so the page window is cut
	// out of the EFFECTIVE order the caller asked for.
	out = applySort(out)
	// ?locate=<message_id>: snap offset to the page containing that message so
	// the caller (the Processes panel "jump to the message that spawned this
	// process" link) lands on the right page. Reuses this handler's own
	// effective ordering — no fragile external ordinal — so it stays correct
	// under a non-default sort_by. No-op if not found.
	if mid := r.URL.Query().Get("locate"); mid != "" && limit > 0 {
		for i := range out {
			if out[i].MessageID == mid {
				offset = (i / limit) * limit
				break
			}
		}
	}
	total := len(out)
	if offset > total {
		offset = total
	}
	page := out[offset:]
	if limit > 0 && len(page) > limit {
		page = page[:limit]
	}
	writeJSON(w, map[string]any{
		"session_id":      sessionID,
		"messages":        page,
		"account_summary": accountSummary,
		"total":           total,
		"limit":           limit,
		"offset":          offset,
	})
}

func decodeCommandInput(raw string) string {
	if raw == "" || raw[0] != '[' {
		return raw
	}
	var argv []string
	if err := json.Unmarshal([]byte(raw), &argv); err != nil || len(argv) == 0 {
		return raw
	}
	return strings.Join(argv, " ")
}

// handlePatterns serves /api/patterns?page=N&limit=M. Returns a paged
// {rows, page, limit, total} envelope mirroring /api/sessions and
// /api/actions. Patterns are ordered by confidence DESC (the user's
// "what's most reliable to act on first" view).
func (s *Server) handlePatterns(w http.ResponseWriter, r *http.Request) {
	limit := intArg(r, "limit", 20, 1, 200)
	page := intArg(r, "page", 1, 1, 1_000_000)
	offset := (page - 1) * limit
	project := r.URL.Query().Get("project")
	tool := r.URL.Query().Get("tool")

	countArgs := []any{}
	listArgs := []any{}
	where := []string{}
	if project != "" {
		where = append(where, "pp.project_id = (SELECT id FROM projects WHERE root_path = ?)")
		countArgs = append(countArgs, project)
		listArgs = append(listArgs, project)
	}
	// Patterns are mined per-project; tool-scoping restricts to projects
	// whose actions table has at least one row for the requested tool.
	// IN with a derived DISTINCT set scans actions once and hash-joins —
	// avoids the EXISTS-per-pattern quadratic risk the v1.6.2 ship hit on
	// crossToolFiles (handover §4d).
	if tool != "" {
		where = append(where, "pp.project_id IN (SELECT DISTINCT project_id FROM actions WHERE tool = ?)")
		countArgs = append(countArgs, tool)
		listArgs = append(listArgs, tool)
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + joinStrings(where, " AND ")
	}

	var total int
	if err := s.db().QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM project_patterns pp`+whereSQL, countArgs...).Scan(&total); err != nil {
		writeErr(w, err)
		return
	}
	listArgs = append(listArgs, limit, offset)
	rows, err := s.db().QueryContext(r.Context(),
		//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
		`SELECT COALESCE(p.root_path, ''), pattern_type, pattern_data,
		        COALESCE(confidence, 0), COALESCE(observation_count, 0)
		 FROM project_patterns pp
		 LEFT JOIN projects p ON p.id = pp.project_id`+whereSQL+`
		 ORDER BY confidence DESC
		 LIMIT ? OFFSET ?`, listArgs...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()
	type patternRow struct {
		Project          string  `json:"project"`
		PatternType      string  `json:"pattern_type"`
		Data             string  `json:"data"`
		Confidence       float64 `json:"confidence"`
		ObservationCount int     `json:"observation_count"`
	}
	out := []patternRow{}
	for rows.Next() {
		var pr patternRow
		if err := rows.Scan(&pr.Project, &pr.PatternType, &pr.Data, &pr.Confidence, &pr.ObservationCount); err != nil {
			writeErr(w, err)
			return
		}
		out = append(out, pr)
	}
	writeJSON(w, map[string]any{
		"rows":  out,
		"page":  page,
		"limit": limit,
		"total": total,
	})
}

// handlePatternsTimeseries serves /api/patterns/timeseries?days=N — one
// bucket per calendar day in the window with the number of patterns
// reinforced that day, split by pattern_type. Drives the "Pattern
// discovery over time" chart on the Patterns tab.
//
// Aggregation uses last_reinforced_at (the column the patterns engine
// touches on every observation). Patterns whose last_reinforced_at is
// NULL (legacy rows) skip; they'd otherwise pile onto epoch.
func (s *Server) handlePatternsTimeseries(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	project := r.URL.Query().Get("project")
	tool := r.URL.Query().Get("tool")
	since, until := windowRange(r, 30, 1, 36500)

	args := []any{since.Format(time.RFC3339Nano)}
	projClause := ""
	if !until.IsZero() {
		projClause += " AND last_reinforced_at < ?"
		args = append(args, until.Format(time.RFC3339Nano))
	}
	if project != "" {
		projClause += " AND project_id = (SELECT id FROM projects WHERE root_path = ?)"
		args = append(args, project)
	}
	if tool != "" {
		projClause += " AND project_id IN (SELECT DISTINCT project_id FROM actions WHERE tool = ?)"
		args = append(args, tool)
	}
	rows, err := s.db().QueryContext(r.Context(),
		//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
		`SELECT substr(last_reinforced_at, 1, 10) AS day, pattern_type, COUNT(*) AS c
		 FROM project_patterns
		 WHERE last_reinforced_at IS NOT NULL AND last_reinforced_at >= ?`+projClause+`
		 GROUP BY day, pattern_type
		 ORDER BY day ASC, pattern_type ASC`,
		args...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()

	type point struct {
		Day    string         `json:"day"`
		Total  int            `json:"total"`
		ByType map[string]int `json:"by_type"`
	}
	byDay := make(map[string]*point)
	for rows.Next() {
		var day, pt string
		var c int
		if err := rows.Scan(&day, &pt, &c); err != nil {
			writeErr(w, err)
			return
		}
		p, ok := byDay[day]
		if !ok {
			p = &point{Day: day, ByType: map[string]int{}}
			byDay[day] = p
		}
		p.ByType[pt] += c
		p.Total += c
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}

	// Order by day ascending; emit a stable JSON shape.
	keys := make([]string, 0, len(byDay))
	for k := range byDay {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]*point, 0, len(keys))
	for _, k := range keys {
		out = append(out, byDay[k])
	}
	writeJSON(w, map[string]any{
		"days":   days,
		"points": out,
	})
}

// handleSuggestPreview serves POST /api/suggest — given a project root
// + window, returns the rendered CLAUDE.md / AGENTS.md / .cursorrules
// bodies derived from the project's mined patterns. Does NOT write any
// files; preview only.
//
// Request body: {"project_root": string, "days": int}
// Response: {"markdown": "...", "cursorrules": "...", "input": Input}
func (s *Server) handleSuggestPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ProjectRoot string `json:"project_root"`
		Days        int    `json:"days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.ProjectRoot == "" {
		http.Error(w, "project_root required", http.StatusBadRequest)
		return
	}
	if req.Days <= 0 {
		req.Days = 30
	}
	in, err := suggest.Load(r.Context(), s.db(), suggest.Options{
		ProjectRoot: req.ProjectRoot,
		Days:        req.Days,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	now := time.Now().UTC()
	writeJSON(w, map[string]any{
		"project_root": req.ProjectRoot,
		"days":         req.Days,
		"markdown":     suggest.RenderMarkdown(in, now),
		"cursorrules":  suggest.RenderCursorRules(in, now),
		"input":        in,
	})
}

// handleSuggestWrite serves POST /api/suggest/write — same render
// pipeline as preview, then actually persists the result to a file
// in the project root. The target chooses between CLAUDE.md (default),
// AGENTS.md, and .cursorrules; the file is created if missing and
// over-written between observer-managed delimiters when present.
//
// Request body: {"project_root": string, "days": int, "target": "claude"|"agents"|"cursor"}
// Response: {"path": string, "changed": bool, "body": string}
func (s *Server) handleSuggestWrite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ProjectRoot string `json:"project_root"`
		Days        int    `json:"days"`
		Target      string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.ProjectRoot == "" {
		http.Error(w, "project_root required", http.StatusBadRequest)
		return
	}
	if req.Days <= 0 {
		req.Days = 30
	}
	target := req.Target
	if target == "" {
		target = "claude"
	}
	var (
		filename string
		body     string
	)
	in, err := suggest.Load(r.Context(), s.db(), suggest.Options{
		ProjectRoot: req.ProjectRoot,
		Days:        req.Days,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	now := time.Now().UTC()
	switch target {
	case "claude":
		filename = "CLAUDE.md"
		body = suggest.RenderMarkdown(in, now)
	case "agents":
		filename = "AGENTS.md"
		body = suggest.RenderMarkdown(in, now)
	case "cursor":
		filename = ".cursorrules"
		body = suggest.RenderCursorRules(in, now)
	default:
		http.Error(w, "target must be one of claude|agents|cursor", http.StatusBadRequest)
		return
	}
	path := req.ProjectRoot
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	path += filename
	// W5.1 org-governed feature gate: node.features.patterns_write.
	// Fail-open (nil FeatureGate, or no accepted policy) — see
	// dashboard.Options.FeatureGate.
	if s.opts.FeatureGate != nil {
		if allowed, reason := s.opts.FeatureGate(nodeFeaturePatternsWrite); !allowed {
			http.Error(w, reason, http.StatusForbidden)
			return
		}
	}
	changed, err := suggest.Apply(path, body)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"path":    path,
		"changed": changed,
		"target":  target,
		"body":    body,
	})
}

// handleTimeseriesCost serves /api/timeseries/cost?days=N&bucket=day|hour.
// Reuses the cost engine's GroupByDay aggregation; returns one point per
// bucket with token totals + cost. Bucket=hour walks api_turns directly
// since the engine doesn't support hour granularity.
// lossyEvictedBytesByDay sums, per day bucket, the original_bytes that
// lossy-eviction mechanisms (drop; see lossyEvictionMechanismList — the
// ONE owner) removed. Those bytes shrink a turn's
// compression_compressed_bytes and therefore inflate the turn-level
// SavedBytesSigned, but they are evicted content (recoverable only via
// the search_past_outputs / stash markers), not a compression saving.
// The since/until + tool/project filters mirror the cost-engine window
// so the subtraction only nets bytes attributable to the same rows.
func (s *Server) lossyEvictedBytesByDay(ctx context.Context, since, until time.Time, tool, project string) (map[string]int64, error) {
	lossy := lossyEvictionMechanismList()
	if len(lossy) == 0 {
		return map[string]int64{}, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(lossy)), ",")
	where := []string{"ce.mechanism IN (" + placeholders + ")", "ce.timestamp >= ?"}
	args := []any{"%Y-%m-%d"}
	for _, m := range lossy {
		args = append(args, m)
	}
	args = append(args, since.Format(time.RFC3339Nano))
	if !until.IsZero() {
		where = append(where, "ce.timestamp < ?")
		args = append(args, until.Format(time.RFC3339Nano))
	}
	if project != "" {
		where = append(where, "at.project_id = (SELECT id FROM projects WHERE root_path = ?)")
		args = append(args, project)
	}
	if tool != "" {
		where = append(where, "(SELECT tool FROM sessions WHERE id = at.session_id) = ?")
		args = append(args, tool)
	}
	rows, err := s.db().QueryContext(ctx,
		//nolint:gosec // G202: SQL structure (WHERE fragments + the IN placeholder list) is built from code constants; all values are bound via ? args.
		`SELECT strftime(?, ce.timestamp) AS bucket, COALESCE(SUM(ce.original_bytes), 0)
		 FROM compression_events ce
		 LEFT JOIN api_turns at ON at.id = ce.api_turn_id
		 WHERE `+strings.Join(where, " AND ")+`
		 GROUP BY bucket`,
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var bucket string
		var evicted int64
		if err := rows.Scan(&bucket, &evicted); err != nil {
			return nil, err
		}
		out[bucket] = evicted
	}
	return out, rows.Err()
}

func (s *Server) handleTimeseriesCost(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	bucket := r.URL.Query().Get("bucket")
	if bucket == "" {
		bucket = "day"
	}
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")
	since, until := windowRange(r, 30, 1, 36500)

	type point struct {
		Bucket                        string  `json:"bucket"`
		Input                         int64   `json:"input"`
		Output                        int64   `json:"output"`
		CacheRead                     int64   `json:"cache_read"`
		CacheCreation                 int64   `json:"cache_creation"`
		CostUSD                       float64 `json:"cost_usd"`
		TurnCount                     int     `json:"turn_count"`
		CompBytesSaved                int64   `json:"compression_bytes_saved"`
		CompTokensSaved               int64   `json:"compression_tokens_saved_est"`
		CompCostUSDSaved              float64 `json:"compression_cost_saved_usd_est"`
		CompCostUSDSavedInputTier     float64 `json:"compression_cost_saved_usd_est_input_tier"`
		CompCostUSDSavedCacheReadTier float64 `json:"compression_cost_saved_usd_est_cache_read_tier"`
		CompTurns                     int     `json:"compression_turns"`
		// CompEvictedBytes is the per-day byte volume that lossy-eviction
		// mechanisms removed. It has ALREADY been subtracted out of
		// CompBytesSaved / CompTokensSaved / the CompCostUSD* fields (so
		// those report genuine, retrievable compression only) and is
		// surfaced here additively so the UI can show eviction without
		// conflating it with savings.
		CompEvictedBytes int64 `json:"compression_evicted_bytes"`
	}

	if bucket == "day" {
		// Day-bucket: lean on the cost engine so pricing stays consistent
		// with /api/cost.
		summary, err := s.opts.CostEngine.Summary(r.Context(), s.db(), cost.Options{
			Days: days, Since: since, Until: until, GroupBy: cost.GroupByDay, Source: cost.SourceAuto, Limit: 365,
			Tool: tool, ProjectRoot: project,
		})
		if err != nil {
			writeErr(w, err)
			return
		}
		// Lossy-eviction bytes (drops) shrink a turn's compressed_bytes and
		// so inflate SavedBytesSigned; subtract them per-day so the cost
		// timeseries reports genuine, retrievable compression only. Same
		// window/tool/project filters as the cost summary above.
		evictedByDay, err := s.lossyEvictedBytesByDay(r.Context(), since, until, tool, project)
		if err != nil {
			writeErr(w, err)
			return
		}
		series := make([]point, 0, len(summary.Rows))
		for _, row := range summary.Rows {
			gross := row.Compression.SavedBytesSigned()
			evicted := evictedByDay[row.Key]
			bytesSaved := gross
			tokensSaved := row.Compression.TokensSavedEst
			usdSaved := row.Compression.CostSavedUSDEst
			usdInputTier := row.Compression.CostSavedUSDEstInputTier
			usdCacheTier := row.Compression.CostSavedUSDEstCacheReadTier
			if gross > 0 && evicted > 0 {
				net := gross - evicted
				if net < 0 {
					net = 0
				}
				// Tokens/USD are linear in saved bytes, so scale the
				// cost-engine estimates by the net/gross ratio rather than
				// re-deriving pricing here (keeps the cost engine the one
				// owner of the byte→token→USD conversion).
				factor := float64(net) / float64(gross)
				bytesSaved = net
				tokensSaved = int64(float64(tokensSaved) * factor)
				usdSaved *= factor
				usdInputTier *= factor
				usdCacheTier *= factor
			}
			series = append(series, point{
				Bucket:                        row.Key,
				Input:                         row.Tokens.Input,
				Output:                        row.Tokens.Output,
				CacheRead:                     row.Tokens.CacheRead,
				CacheCreation:                 row.Tokens.CacheCreation,
				CostUSD:                       row.CostUSD,
				TurnCount:                     row.TurnCount,
				CompBytesSaved:                bytesSaved,
				CompTokensSaved:               tokensSaved,
				CompCostUSDSaved:              usdSaved,
				CompCostUSDSavedInputTier:     usdInputTier,
				CompCostUSDSavedCacheReadTier: usdCacheTier,
				CompTurns:                     row.Compression.Turns,
				CompEvictedBytes:              evicted,
			})
		}
		// cost.Engine.Summary sorts rows by cost_usd DESC for the
		// /api/cost top-N use case; re-sort here so the timeseries reads
		// chronologically (oldest left, newest right) on the chart axis.
		// ISO date strings sort correctly as strings.
		sort.SliceStable(series, func(i, j int) bool {
			return series[i].Bucket < series[j].Bucket
		})
		sinceStr, untilStr := windowMeta(since, until)
		writeJSON(w, map[string]any{
			"metric": "cost",
			"bucket": "day",
			"days":   days,
			"since":  sinceStr,
			"until":  untilStr,
			"series": series,
		})
		return
	}

	// Hour-bucket fallback — query api_turns directly. JSONL token_usage
	// rows are intentionally excluded from the hour view because their
	// timestamps aren't always when the API call happened (the JSONL
	// adapter parses files on disk; rows can land minutes after the
	// originating turn). Hour resolution only makes sense for the
	// proxy-sourced stream.
	hourArgs := []any{since.Format(time.RFC3339Nano)}
	hourWhere := []string{"at.timestamp >= ?"}
	if !until.IsZero() {
		hourWhere = append(hourWhere, "at.timestamp < ?")
		hourArgs = append(hourArgs, until.Format(time.RFC3339Nano))
	}
	if project != "" {
		hourWhere = append(hourWhere, "p.root_path = ?")
		hourArgs = append(hourArgs, project)
	}
	if tool != "" {
		hourWhere = append(hourWhere, "s.tool = ?")
		hourArgs = append(hourArgs, tool)
	}
	//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
	// cost_usd is selected + scanned so the hour view matches the day
	// path field-for-field for what the cost chart consumes — without
	// it sub-day windows (bucket=hour, now requested by the SPA) render
	// $0 for every bucket. Compression-savings estimates stay zero in
	// the hour view (they require per-model pricing the day path gets
	// from the cost engine; api_turns carries raw bytes only).
	hourQ := `SELECT strftime('%Y-%m-%dT%H:00:00Z', at.timestamp) AS bucket,
	                 COALESCE(SUM(at.input_tokens), 0),
	                 COALESCE(SUM(at.output_tokens), 0),
	                 COALESCE(SUM(at.cache_read_tokens), 0),
	                 COALESCE(SUM(at.cache_creation_tokens), 0),
	                 COALESCE(SUM(at.cost_usd), 0),
	                 COUNT(*)
	          FROM api_turns at
	          LEFT JOIN projects p ON p.id = at.project_id
	          LEFT JOIN sessions s ON s.id = at.session_id
	          WHERE ` + strings.Join(hourWhere, " AND ") + `
	          GROUP BY bucket
	          ORDER BY bucket`
	rows, err := s.db().QueryContext(r.Context(), hourQ, hourArgs...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()
	series := make([]point, 0)
	for rows.Next() {
		var p point
		if err := rows.Scan(&p.Bucket, &p.Input, &p.Output, &p.CacheRead, &p.CacheCreation, &p.CostUSD, &p.TurnCount); err != nil {
			writeErr(w, err)
			return
		}
		series = append(series, p)
	}
	sinceStr, untilStr := windowMeta(since, until)
	writeJSON(w, map[string]any{
		"metric": "cost",
		"bucket": "hour",
		"days":   days,
		"since":  sinceStr,
		"until":  untilStr,
		"series": series,
	})
}

// handleTimeseriesTokensByModel serves /api/timeseries/tokens-by-model
// ?days=N&project=PATH. Returns one point per (day, model) pair so the
// Cost tab can render a stacked-bar chart of tokens per day with each
// model as its own series. Tokens, cost, and turn counts come from the
// cost engine in SourceAuto mode (proxy preferred, JSONL fallback) so
// the dedup/reliability semantics match /api/cost and
// /api/timeseries/cost exactly.
func (s *Server) handleTimeseriesTokensByModel(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	projectFilter := r.URL.Query().Get("project")
	toolFilter := r.URL.Query().Get("tool")

	type point struct {
		Bucket        string  `json:"bucket"`
		Model         string  `json:"model"`
		Input         int64   `json:"input"`
		Output        int64   `json:"output"`
		CacheRead     int64   `json:"cache_read"`
		CacheCreation int64   `json:"cache_creation"`
		TotalTokens   int64   `json:"total_tokens"`
		CostUSD       float64 `json:"cost_usd"`
		TurnCount     int     `json:"turn_count"`
	}

	since, until := windowRange(r, 30, 1, 36500)
	summary, err := s.opts.CostEngine.Summary(r.Context(), s.db(), cost.Options{
		Days:        days,
		Since:       since,
		Until:       until,
		GroupBy:     cost.GroupByDayModel,
		Source:      cost.SourceAuto,
		ProjectRoot: projectFilter,
		Tool:        toolFilter,
		// Limit large enough to cover realistic windows: 365d × ~6 models
		// per day = 2190 buckets. Keep some headroom for pathological
		// many-model accounts.
		Limit: 5000,
	})
	if err != nil {
		writeErr(w, err)
		return
	}

	series := make([]point, 0, len(summary.Rows))
	for _, row := range summary.Rows {
		day, model := cost.SplitDayModelKey(row.Key)
		series = append(series, point{
			Bucket:        day,
			Model:         model,
			Input:         row.Tokens.Input,
			Output:        row.Tokens.Output,
			CacheRead:     row.Tokens.CacheRead,
			CacheCreation: row.Tokens.CacheCreation,
			TotalTokens:   row.Tokens.Input + row.Tokens.Output + row.Tokens.CacheRead + row.Tokens.CacheCreation,
			CostUSD:       row.CostUSD,
			TurnCount:     row.TurnCount,
		})
	}
	// Engine returns rows sorted by cost_usd DESC. Re-sort chronologically
	// (then by model for a stable stacking order within a day) so the
	// chart axis reads left-to-right.
	sort.SliceStable(series, func(i, j int) bool {
		if series[i].Bucket != series[j].Bucket {
			return series[i].Bucket < series[j].Bucket
		}
		return series[i].Model < series[j].Model
	})
	sinceStr, untilStr := windowMeta(since, until)
	writeJSON(w, map[string]any{
		"metric": "tokens_by_model",
		"bucket": "day",
		"days":   days,
		"since":  sinceStr,
		"until":  untilStr,
		"series": series,
	})
}

// handleTimeseriesActions serves /api/timeseries/actions?days=N&bucket=day|hour.
// Returns one point per bucket with action counts (total, successful,
// failed) and a per-tool breakdown so charts can stack by tool.
//
// Honors ?project=<root_path> to scope to a single project (mirrors the
// filter applied to /api/sessions and /api/actions). Without the
// filter, cross-project actions are summed.
func (s *Server) handleTimeseriesActions(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	bucket := r.URL.Query().Get("bucket")
	if bucket == "" {
		bucket = "day"
	}
	fmtSpec := "%Y-%m-%d"
	if bucket == "hour" {
		fmtSpec = "%Y-%m-%dT%H:00:00Z"
	}
	since, until := windowRange(r, 30, 1, 36500)
	project := r.URL.Query().Get("project")
	tool := r.URL.Query().Get("tool")
	args := []any{fmtSpec, since.Format(time.RFC3339Nano)}
	extra := ""
	if !until.IsZero() {
		extra += " AND timestamp < ?"
		args = append(args, until.Format(time.RFC3339Nano))
	}
	if project != "" {
		extra += " AND project_id = (SELECT id FROM projects WHERE root_path = ?)"
		args = append(args, project)
	}
	if tool != "" {
		extra += " AND tool = ?"
		args = append(args, tool)
	}
	rows, err := s.db().QueryContext(r.Context(),
		//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
		`SELECT strftime(?, timestamp) AS bucket, tool,
		        COUNT(*),
		        SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END)
		 FROM actions
		 WHERE timestamp >= ?`+extra+`
		 GROUP BY bucket, tool
		 ORDER BY bucket, tool`,
		args...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()

	type point struct {
		Bucket   string         `json:"bucket"`
		Total    int            `json:"total"`
		Failures int            `json:"failures"`
		ByTool   map[string]int `json:"by_tool"`
	}
	byBucket := map[string]*point{}
	order := []string{}
	for rows.Next() {
		var b, tool string
		var n, fails int
		if err := rows.Scan(&b, &tool, &n, &fails); err != nil {
			writeErr(w, err)
			return
		}
		p, ok := byBucket[b]
		if !ok {
			p = &point{Bucket: b, ByTool: map[string]int{}}
			byBucket[b] = p
			order = append(order, b)
		}
		p.Total += n
		p.Failures += fails
		p.ByTool[tool] = n
	}
	series := make([]point, 0, len(order))
	for _, b := range order {
		series = append(series, *byBucket[b])
	}
	// Pin the contract: timeseries reads chronologically. The SQL
	// already orders by bucket ASC, but sort defensively so any future
	// upstream change can't silently flip chart axes.
	sort.SliceStable(series, func(i, j int) bool {
		return series[i].Bucket < series[j].Bucket
	})
	sinceStr, untilStr := windowMeta(since, until)
	writeJSON(w, map[string]any{
		"metric": "actions",
		"bucket": bucket,
		"days":   days,
		"since":  sinceStr,
		"until":  untilStr,
		"series": series,
	})
}

// handleModels serves /api/models?days=N — per-model breakdown over the
// window. Same shape as /api/cost but always group_by=model and JSON only.
func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")
	since, until := windowRange(r, 30, 1, 36500)
	summary, err := s.opts.CostEngine.Summary(r.Context(), s.db(), cost.Options{
		Days: days, Since: since, Until: until, GroupBy: cost.GroupByModel, Source: cost.SourceAuto, Limit: 50,
		Tool: tool, ProjectRoot: project,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	// Spec §13 cost-view annotation: attach per-model cache
	// annotations. Same shape as /api/cost?group_by=model so the
	// frontend's Cost page can render the same cache pill on
	// whichever endpoint it consumes.
	keys := make([]string, 0, len(summary.Rows))
	for _, row := range summary.Rows {
		keys = append(keys, row.Key)
	}
	if ann, derr := loadCacheAnnotationsByKey(r.Context(), s.db(), "model", keys); derr == nil && len(ann) > 0 {
		writeJSON(w, costSummaryWithCache{Summary: summary, CacheByKey: ann})
		return
	}
	writeJSON(w, summary)
}

// handleTools serves /api/tools?days=N — per-tool action volume + success
// rate over the window. Source: actions table.
func (s *Server) handleTools(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	project := r.URL.Query().Get("project")
	since, until := windowRange(r, 30, 1, 36500)
	args := []any{since.Format(time.RFC3339Nano)}
	where := []string{"timestamp >= ?"}
	if !until.IsZero() {
		where = append(where, "timestamp < ?")
		args = append(args, until.Format(time.RFC3339Nano))
	}
	if project != "" {
		where = append(where, "project_id = (SELECT id FROM projects WHERE root_path = ?)")
		args = append(args, project)
	}
	//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
	q := `SELECT tool, COUNT(*),
	             SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END),
	             COUNT(DISTINCT session_id),
	             MIN(timestamp), MAX(timestamp)
	      FROM actions
	      WHERE ` + strings.Join(where, " AND ") + `
	      GROUP BY tool
	      ORDER BY COUNT(*) DESC`
	rows, err := s.db().QueryContext(r.Context(), q, args...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()
	type toolRow struct {
		Tool         string  `json:"tool"`
		ActionCount  int     `json:"action_count"`
		FailureCount int     `json:"failure_count"`
		SuccessRate  float64 `json:"success_rate"`
		SessionCount int     `json:"session_count"`
		FirstSeen    string  `json:"first_seen"`
		LastSeen     string  `json:"last_seen"`
	}
	out := []toolRow{}
	for rows.Next() {
		var tr toolRow
		if err := rows.Scan(&tr.Tool, &tr.ActionCount, &tr.FailureCount,
			&tr.SessionCount, &tr.FirstSeen, &tr.LastSeen); err != nil {
			writeErr(w, err)
			return
		}
		if tr.ActionCount > 0 {
			tr.SuccessRate = 1 - float64(tr.FailureCount)/float64(tr.ActionCount)
		}
		out = append(out, tr)
	}
	writeJSON(w, map[string]any{
		"days":  days,
		"since": since.Format(time.RFC3339),
		"tools": out,
	})
}

// handleToolsBreakdown serves /api/tools/breakdown?days=N — per-tool
// action_type counts over the window. Powers the Tools tab's "what
// each AI client actually does" stacked bar (one row per tool, segments
// per action type). Honors ?project= and ?tool= filters.
func (s *Server) handleToolsBreakdown(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	since, until := windowRange(r, 30, 1, 36500)
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")
	args := []any{since.Format(time.RFC3339Nano)}
	where := []string{"timestamp >= ?"}
	if !until.IsZero() {
		where = append(where, "timestamp < ?")
		args = append(args, until.Format(time.RFC3339Nano))
	}
	if tool != "" {
		where = append(where, "tool = ?")
		args = append(args, tool)
	}
	if project != "" {
		where = append(where, "project_id = (SELECT id FROM projects WHERE root_path = ?)")
		args = append(args, project)
	}
	whereClause := strings.Join(where, " AND ")
	acc := newBreakdownAccumulator()

	// Two scans, both folded incrementally — nothing is retained per
	// group, so this handler's memory is bounded by the taxonomy
	// (tools × action types, tools × surfaces) and not by the corpus.
	//
	// Pass 1 is the SURFACE attribution. tooltax.Resolve needs the native
	// name (action_type alone cannot say whether a run_command came from
	// a builtin Bash tool or from an MCP server's shell), but
	// raw_tool_name is unrestricted free text, so the group count is
	// O(vocabulary) only by observation — a corpus with a unique name per
	// action would make it O(actions). The LIMIT is the actual bound; it
	// orders by COUNT(*) DESC so the mass of the corpus is what survives,
	// and whatever the cap excludes is reconciled into the `unresolved`
	// surface bucket by the accumulator's remainder (sum(by_surface) ==
	// total stays true). Native names never leave this function — the
	// response carries counts, not names.
	//
	// It runs BEFORE the totals pass so that concurrent ingest between
	// the two scans can only make the totals larger, never the surface
	// sum larger than the total.
	if err := s.foldBreakdownSurfaces(r.Context(), acc, whereClause, args); err != nil {
		writeErr(w, err)
		return
	}

	// Pass 2 is the exact, UNCAPPED totals: (tool, action_type) is
	// bounded by the taxonomy itself (~30 tools × ~50 action types), so
	// total / by_type / by_category stay exact — the pre-WP-T5 contract
	// is untouched by the cap above.
	//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
	q := `SELECT tool, action_type, COUNT(*)
	      FROM actions
	      WHERE ` + whereClause + `
	      GROUP BY tool, action_type
	      ORDER BY tool, COUNT(*) DESC`
	rows, err := s.db().QueryContext(r.Context(), q, args...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var t, atype string
		var n int
		if err := rows.Scan(&t, &atype, &n); err != nil {
			writeErr(w, err)
			return
		}
		acc.AddActionTypeCount(t, atype, n)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"days": days,
		// The canonical key spaces, so the client renders both new
		// dimensions in tooltax's display order instead of its own.
		"categories": tooltax.Categories(),
		"surfaces":   breakdownSurfaceKeys(),
		"tools":      acc.Rows(),
	})
}

// foldBreakdownSurfaces runs /api/tools/breakdown's capped native-name
// pass, streaming each (tool, raw_tool_name) group straight into the
// accumulator. It is a separate function so the cursor is closed by
// defer on every path, and so the handler reads as two passes.
func (s *Server) foldBreakdownSurfaces(ctx context.Context, acc *breakdownAccumulator, whereClause string, args []any) error {
	//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
	q := `SELECT tool, COALESCE(raw_tool_name, ''), COUNT(*)
	      FROM actions
	      WHERE ` + whereClause + `
	      GROUP BY tool, raw_tool_name
	      ORDER BY COUNT(*) DESC
	      LIMIT ?`
	qArgs := make([]any, 0, len(args)+1)
	qArgs = append(qArgs, args...)
	qArgs = append(qArgs, breakdownNativeGroupCap)
	rows, err := s.db().QueryContext(ctx, q, qArgs...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var tool, rawName string
		var n int
		if err := rows.Scan(&tool, &rawName, &n); err != nil {
			return err
		}
		acc.AddNativeCount(tool, rawName, n)
	}
	return rows.Err()
}

// handleProjects serves /api/projects — every project root the observer
// knows about, sorted by recent activity. Used by the dashboard toolbar
// to populate the project filter so users can scope Sessions / Actions /
// Cost / Discover queries to one project root.
// handleCompressionEvents serves /api/compression/events?days=N&page=&limit=
// — paginated per-event compression detail joined back to api_turns
// for model + session context. Driven by the compression_events table
// (migration 009). Mechanism is one of json/code/logs/text/diff/html
// (per-content-type compressor) or 'drop' (low-importance message
// replaced by a marker). Honors ?mechanism= and ?model= for narrowing.
func (s *Server) handleCompressionEvents(w http.ResponseWriter, r *http.Request) {
	page := intArg(r, "page", 1, 1, 1_000_000)
	limit := intArg(r, "limit", 50, 1, 500)
	offset := (page - 1) * limit
	mechanism := r.URL.Query().Get("mechanism")
	model := r.URL.Query().Get("model")
	project := r.URL.Query().Get("project")
	tool := r.URL.Query().Get("tool")
	since, until := windowRange(r, 30, 1, 36500)

	where := []string{"ce.timestamp >= ?"}
	args := []any{since.Format(time.RFC3339Nano)}
	if !until.IsZero() {
		where = append(where, "ce.timestamp < ?")
		args = append(args, until.Format(time.RFC3339Nano))
	}
	if mechanism != "" {
		where = append(where, "ce.mechanism = ?")
		args = append(args, mechanism)
	}
	if model != "" {
		where = append(where, "at.model = ?")
		args = append(args, model)
	}
	if project != "" {
		where = append(where, "at.project_id = (SELECT id FROM projects WHERE root_path = ?)")
		args = append(args, project)
	}
	if tool != "" {
		where = append(where, "(SELECT tool FROM sessions WHERE id = at.session_id) = ?")
		args = append(args, tool)
	}
	whereClause := "WHERE " + strings.Join(where, " AND ")

	var total int
	if err := s.db().QueryRowContext(
		r.Context(),
		`SELECT COUNT(*) FROM compression_events ce
		 LEFT JOIN api_turns at ON at.id = ce.api_turn_id `+whereClause,
		args...,
	).Scan(&total); err != nil {
		writeErr(w, err)
		return
	}

	// is_subagent_runtime is derived per-row by correlating against
	// actions: an api_turn whose session_id has any sidechain (Agent
	// runtime) action within ±2 minutes of the turn's timestamp is
	// almost certainly a sub-agent's API call. EXISTS subquery on the
	// indexed (session_id, timestamp, is_sidechain) columns is fast
	// enough to compute inline at query time.
	rows, err := s.db().QueryContext(r.Context(),
		//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
		`SELECT ce.id, ce.api_turn_id, ce.timestamp, ce.mechanism,
		        ce.original_bytes, ce.compressed_bytes,
		        COALESCE(ce.msg_index, -1), COALESCE(ce.importance_score, 0),
		        COALESCE(at.model, ''), COALESCE(at.session_id, ''),
		        COALESCE(at.request_id, ''),
		        EXISTS (
		          SELECT 1 FROM actions a
		          WHERE a.session_id = at.session_id
		            AND a.is_sidechain = 1
		            AND ABS(strftime('%s', a.timestamp) - strftime('%s', ce.timestamp)) <= 120
		        ) AS is_subagent
		 FROM compression_events ce
		 LEFT JOIN api_turns at ON at.id = ce.api_turn_id
		 `+whereClause+`
		 ORDER BY ce.timestamp DESC, ce.id DESC
		 LIMIT ? OFFSET ?`,
		append(args, limit, offset)...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()

	type eventRow struct {
		ID              int64  `json:"id"`
		APITurnID       int64  `json:"api_turn_id"`
		Timestamp       string `json:"timestamp"`
		Mechanism       string `json:"mechanism"`
		OriginalBytes   int64  `json:"original_bytes"`
		CompressedBytes int64  `json:"compressed_bytes"`
		SavedBytes      int64  `json:"saved_bytes"`
		// Token estimates derived from bytes via the 4 chars/token rule
		// of thumb (matches cost.CompressionStats.TokensSavedEst).
		// Same heuristic used by the cost engine's compression rollup
		// so the dashboard's per-event view stays consistent with the
		// summary numbers above the table.
		OriginalTokensEst   int64 `json:"original_tokens_est"`
		CompressedTokensEst int64 `json:"compressed_tokens_est"`
		SavedTokensEst      int64 `json:"saved_tokens_est"`
		// SavedUSDEst is saved_tokens_est × the row's model input rate.
		// Same formula as cost.Engine.Summary's per-row CostSavedUSDEst,
		// just applied per-event. Zero when the model is unrecognized.
		SavedUSDEst     float64 `json:"saved_usd_est"`
		MsgIndex        int     `json:"msg_index"`
		ImportanceScore float64 `json:"importance_score"`
		Model           string  `json:"model"`
		SessionID       string  `json:"session_id"`
		// MessageID is the upstream Anthropic msg_xxx id (sourced from
		// api_turns.request_id — same column the proxy populates). Lets
		// the UI link compression events to the same message thread on
		// the per-message timeline modal.
		MessageID string `json:"message_id"`
		// IsSubagentRuntime is true when the api_turn that produced
		// this event came from a sub-agent runtime — derived by
		// finding any sidechain action in the same session within
		// ±2 minutes of the turn's timestamp. Surfaces as a "Source"
		// pill on the events table so users can spot which mechanism
		// activity is attributable to delegated work.
		IsSubagentRuntime bool `json:"is_subagent_runtime"`
		// Lossy marks an eviction mechanism (mechanismIsLossy). For
		// these rows OriginalBytes was EVICTED, not compressed —
		// SavedBytes/SavedTokensEst/SavedUSDEst are forced to 0 and the
		// bytes surface as EvictedBytes so the UI never renders a fake
		// "100% saved" or prices evicted content as dollars saved.
		Lossy        bool  `json:"lossy"`
		EvictedBytes int64 `json:"evicted_bytes"`
	}
	out := []eventRow{}
	for rows.Next() {
		var er eventRow
		var isSubInt int
		if err := rows.Scan(&er.ID, &er.APITurnID, &er.Timestamp, &er.Mechanism,
			&er.OriginalBytes, &er.CompressedBytes,
			&er.MsgIndex, &er.ImportanceScore,
			&er.Model, &er.SessionID, &er.MessageID, &isSubInt); err != nil {
			writeErr(w, err)
			return
		}
		er.OriginalTokensEst = er.OriginalBytes / 4
		er.CompressedTokensEst = er.CompressedBytes / 4
		if mechanismIsLossy(er.Mechanism) {
			// Evicted content: report bytes as evicted, never as saved
			// and never priced. Saved* stay at their zero value.
			er.Lossy = true
			er.EvictedBytes = er.OriginalBytes
		} else {
			er.SavedBytes = er.OriginalBytes - er.CompressedBytes
			er.SavedTokensEst = er.SavedBytes / 4
			if er.Model != "" {
				if pricing, ok := s.opts.CostEngine.Lookup(er.Model); ok && pricing.Input > 0 {
					er.SavedUSDEst = float64(er.SavedTokensEst) * pricing.Input / 1_000_000
				}
			}
		}
		er.IsSubagentRuntime = isSubInt != 0
		out = append(out, er)
	}
	writeJSON(w, map[string]any{
		"rows":  out,
		"page":  page,
		"limit": limit,
		"total": total,
	})
}

// handleCompressionByModel serves /api/compression/by-model?days=N —
// per-model rollup of compression savings. One row per (model, mechanism)
// pair with event count, original/compressed bytes, saved bytes, and a
// best-effort $ estimate computed by pricing saved_bytes/4 tokens at the
// model's input rate (same convention as handleCompressionTimeseries).
//
// Drives the Compression tab's "Per-model breakdown" table (audit §3.7
// Cp11 / §4.7 dCp3). Sorted by saved_bytes DESC so the heaviest
// compressors lead.
func (s *Server) handleCompressionByModel(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	project := r.URL.Query().Get("project")
	tool := r.URL.Query().Get("tool")
	since, until := windowRange(r, 30, 1, 36500)
	where := []string{"ce.timestamp >= ?"}
	args := []any{since.Format(time.RFC3339Nano)}
	if !until.IsZero() {
		where = append(where, "ce.timestamp < ?")
		args = append(args, until.Format(time.RFC3339Nano))
	}
	if project != "" {
		where = append(where, "at.project_id = (SELECT id FROM projects WHERE root_path = ?)")
		args = append(args, project)
	}
	if tool != "" {
		where = append(where, "(SELECT tool FROM sessions WHERE id = at.session_id) = ?")
		args = append(args, tool)
	}
	rows, err := s.db().QueryContext(r.Context(),
		//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
		`SELECT COALESCE(at.model, '(unknown)') AS model,
		        ce.mechanism,
		        COUNT(*) AS events,
		        SUM(ce.original_bytes) AS orig,
		        SUM(ce.compressed_bytes) AS comp
		 FROM compression_events ce
		 LEFT JOIN api_turns at ON at.id = ce.api_turn_id
		 WHERE `+strings.Join(where, " AND ")+`
		 GROUP BY model, ce.mechanism
		 ORDER BY (SUM(ce.original_bytes) - SUM(ce.compressed_bytes)) DESC`,
		args...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()

	type row struct {
		Model           string  `json:"model"`
		Mechanism       string  `json:"mechanism"`
		Events          int     `json:"events"`
		OriginalBytes   int64   `json:"original_bytes"`
		CompressedBytes int64   `json:"compressed_bytes"`
		SavedBytes      int64   `json:"saved_bytes"`
		SavedTokensEst  int64   `json:"saved_tokens_est"`
		SavedUSDEst     float64 `json:"saved_usd_est"`
		// Lossy marks an eviction mechanism (mechanismIsLossy). For
		// these rows OriginalBytes was EVICTED, not compressed:
		// SavedBytes/SavedTokensEst/SavedUSDEst are forced to 0 and the
		// bytes surface as EvictedBytes so the UI never renders them as
		// savings (or prices them as dollars saved).
		Lossy        bool  `json:"lossy"`
		EvictedBytes int64 `json:"evicted_bytes"`
	}
	out := []row{}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.Model, &r.Mechanism, &r.Events, &r.OriginalBytes, &r.CompressedBytes); err != nil {
			writeErr(w, err)
			return
		}
		if mechanismIsLossy(r.Mechanism) {
			// Evicted content has no compressed form — report it as
			// evicted and never price it as a saving. SavedBytes,
			// SavedTokensEst and SavedUSDEst stay at their zero value.
			r.Lossy = true
			r.EvictedBytes = r.OriginalBytes
			out = append(out, r)
			continue
		}
		r.SavedBytes = r.OriginalBytes - r.CompressedBytes
		// 4 bytes/token is the same lossy conversion handleCompression
		// Timeseries uses. Good enough for "savings" framing.
		r.SavedTokensEst = r.SavedBytes / 4
		if p, ok := s.opts.CostEngine.Lookup(r.Model); ok && r.SavedTokensEst > 0 {
			r.SavedUSDEst = (float64(r.SavedTokensEst) / 1_000_000) * p.Input
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"days": days,
		"rows": out,
	})
}

// handleCompressionTimeseries serves /api/compression/timeseries?bucket=day&days=N
// — per-day savings split by mechanism for the "Savings by mechanism"
// chart. Returns one point per day with by_mechanism map of
// {mechanism: {count, original_bytes, compressed_bytes, saved_bytes,
// saved_usd_est}}.
//
// Per-mechanism $ is computed by joining compression_events back to
// api_turns for model context, looking up each model's input rate via
// the cost engine, and pricing (saved_bytes / 4) tokens at that rate.
// Models without pricing contribute to bytes/tokens but not to $ —
// matches the per-model breakdown in cost.Engine.Summary.
func (s *Server) handleCompressionTimeseries(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	project := r.URL.Query().Get("project")
	tool := r.URL.Query().Get("tool")
	// bucket=day|hour allow-list (mirrors handleTimeseriesCost /
	// handleTimeseriesActions). The SPA now sends bucket=hour for sub-day
	// windows; without this the strftime was hard-wired to daily and the
	// hour axis collapsed to one point per day.
	bucket := r.URL.Query().Get("bucket")
	if bucket == "" {
		bucket = "day"
	}
	fmtSpec := "%Y-%m-%d"
	if bucket == "hour" {
		fmtSpec = "%Y-%m-%dT%H:00:00Z"
	} else {
		bucket = "day"
	}
	since, until := windowRange(r, 30, 1, 36500)
	where := []string{"ce.timestamp >= ?"}
	args := []any{fmtSpec, since.Format(time.RFC3339Nano)}
	if !until.IsZero() {
		where = append(where, "ce.timestamp < ?")
		args = append(args, until.Format(time.RFC3339Nano))
	}
	if project != "" {
		where = append(where, "at.project_id = (SELECT id FROM projects WHERE root_path = ?)")
		args = append(args, project)
	}
	if tool != "" {
		where = append(where, "(SELECT tool FROM sessions WHERE id = at.session_id) = ?")
		args = append(args, tool)
	}
	rows, err := s.db().QueryContext(r.Context(),
		//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
		`SELECT strftime(?, ce.timestamp) AS bucket,
		        ce.mechanism,
		        COALESCE(at.model, '') AS model,
		        COUNT(*),
		        COALESCE(SUM(ce.original_bytes), 0),
		        COALESCE(SUM(ce.compressed_bytes), 0)
		 FROM compression_events ce
		 LEFT JOIN api_turns at ON at.id = ce.api_turn_id
		 WHERE `+strings.Join(where, " AND ")+`
		 GROUP BY bucket, ce.mechanism, model
		 ORDER BY bucket, ce.mechanism`,
		args...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()
	type mechStats struct {
		Count           int     `json:"count"`
		OriginalBytes   int64   `json:"original_bytes"`
		CompressedBytes int64   `json:"compressed_bytes"`
		SavedBytes      int64   `json:"saved_bytes"`
		SavedUSDEst     float64 `json:"saved_usd_est"`
		// Lossy marks an eviction mechanism (mechanismIsLossy). Its
		// bytes are reported as EvictedBytes, and SavedBytes/
		// SavedUSDEst stay 0 so the savings chart/donut and the point
		// totals never count evicted content as a saving.
		Lossy        bool  `json:"lossy"`
		EvictedBytes int64 `json:"evicted_bytes"`
	}
	type point struct {
		Bucket      string                `json:"bucket"`
		ByMechanism map[string]*mechStats `json:"by_mechanism"`
		TotalSaved  int64                 `json:"total_saved_bytes"`
		TotalUSD    float64               `json:"total_saved_usd_est"`
		TotalCount  int                   `json:"total_count"`
		// TotalEvicted is the byte volume removed by lossy-eviction
		// mechanisms in this bucket — surfaced separately so the UI can
		// show it without conflating it with total_saved_bytes.
		TotalEvicted int64 `json:"total_evicted_bytes"`
	}
	idx := map[string]*point{}
	order := []string{}
	for rows.Next() {
		var b, mech, model string
		var n int
		var orig, comp int64
		if err := rows.Scan(&b, &mech, &model, &n, &orig, &comp); err != nil {
			writeErr(w, err)
			return
		}
		p, ok := idx[b]
		if !ok {
			p = &point{Bucket: b, ByMechanism: map[string]*mechStats{}}
			idx[b] = p
			order = append(order, b)
		}
		ms, exists := p.ByMechanism[mech]
		if !exists {
			ms = &mechStats{}
			p.ByMechanism[mech] = ms
		}
		ms.Count += n
		p.TotalCount += n
		if mechanismIsLossy(mech) {
			// Evicted content: track bytes as evicted, never as saved
			// and never priced.
			ms.Lossy = true
			ms.OriginalBytes += orig
			ms.CompressedBytes += comp
			ms.EvictedBytes += orig
			p.TotalEvicted += orig
			continue
		}
		saved := orig - comp
		// Price savings at the model's input rate (matches
		// cost.Engine.Summary's CostSavedUSDEst formula). Unknown
		// models contribute 0 to $ but still show up in bytes/tokens.
		var savedUSD float64
		if model != "" {
			if pricing, ok := s.opts.CostEngine.Lookup(model); ok && pricing.Input > 0 {
				tokens := float64(saved) / 4
				savedUSD = tokens * pricing.Input / 1_000_000
			}
		}
		ms.OriginalBytes += orig
		ms.CompressedBytes += comp
		ms.SavedBytes += saved
		ms.SavedUSDEst += savedUSD
		p.TotalSaved += saved
		p.TotalUSD += savedUSD
	}
	series := make([]point, 0, len(order))
	for _, b := range order {
		series = append(series, *idx[b])
	}
	sort.SliceStable(series, func(i, j int) bool {
		return series[i].Bucket < series[j].Bucket
	})
	sinceStr, untilStr := windowMeta(since, until)
	writeJSON(w, map[string]any{
		"metric": "compression_events",
		"bucket": bucket,
		"days":   days,
		"since":  sinceStr,
		"until":  untilStr,
		"series": series,
	})
}

func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db().QueryContext(r.Context(),
		`SELECT p.root_path,
		        (SELECT COUNT(*) FROM sessions s WHERE s.project_id = p.id) AS session_count,
		        (SELECT COUNT(*) FROM actions  a WHERE a.project_id = p.id) AS action_count,
		        (SELECT MAX(a.timestamp) FROM actions a WHERE a.project_id = p.id) AS last_seen
		 FROM projects p
		 ORDER BY last_seen DESC NULLS LAST, p.id DESC`)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()
	type projectRow struct {
		RootPath     string `json:"root_path"`
		SessionCount int    `json:"session_count"`
		ActionCount  int    `json:"action_count"`
		LastSeen     string `json:"last_seen,omitempty"`
	}
	out := []projectRow{}
	for rows.Next() {
		var pr projectRow
		var lastSeen sql.NullString
		if err := rows.Scan(&pr.RootPath, &pr.SessionCount, &pr.ActionCount, &lastSeen); err != nil {
			writeErr(w, err)
			return
		}
		if lastSeen.Valid {
			pr.LastSeen = lastSeen.String
		}
		out = append(out, pr)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"rows": out})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSONStatus emits an arbitrary JSON body with an explicit status. Used
// where a handler needs a structured, machine-readable refusal ({error,
// message}) rather than writeErrStatus's single error string — the enrolment
// invite proxy maps each org-server refusal to its own code so the UI copy
// can name the real cause.
func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

// writeErrStatus emits an {"error":…} body with an explicit status (a JSON-safe
// alternative to hand-building the body when the message may contain quotes).
func writeErrStatus(w http.ResponseWriter, err error, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func intArg(r *http.Request, key string, def, lo, hi int) int {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

// parseWindowTime parses an RFC3339 or RFC3339Nano timestamp, returning
// the UTC-normalized value and ok=false on any parse failure. The
// RFC3339Nano layout accepts a plain RFC3339 string too (the fractional
// seconds are optional), so one attempt covers both; a second attempt at
// the exact RFC3339 layout is kept as a belt-and-braces fallback.
func parseWindowTime(raw string) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.UTC(), true
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}

// windowRange resolves the dashboard time-window wire contract into a
// [since, until) pair. Param precedence, highest first:
//
//  1. explicit since / until (RFC3339 or RFC3339Nano, normalized to UTC).
//     `until` is resolved independently of the lower-bound tier, so a
//     caller can pass `since` OR `hours` OR `days` alongside a bare
//     `until` upper bound.
//  2. hours (integer ≥ 1, capped at maxDays*24).
//  3. days (existing intArg semantics: default defDays, clamped
//     minDays..maxDays).
//
// A returned zero `since` means "no lower bound" (only possible when the
// days tier resolves to 0, i.e. minDays==0 and no since/hours/days param
// is present). A zero `until` means "no upper bound". Every tier is
// fail-open: a malformed value falls through to the next tier exactly
// like intArg falls back to its default, so behavior is byte-identical to
// the pre-existing `days`-only path whenever only `days` is supplied.
func windowRange(r *http.Request, defDays, minDays, maxDays int) (since, until time.Time) {
	now := time.Now().UTC()
	q := r.URL.Query()

	// Upper bound is independent of which lower-bound tier wins.
	if raw := q.Get("until"); raw != "" {
		if t, ok := parseWindowTime(raw); ok {
			until = t
		}
	}

	// Tier 1: explicit since.
	if raw := q.Get("since"); raw != "" {
		if t, ok := parseWindowTime(raw); ok {
			return t, until
		}
		// malformed → fall through to the next tier
	}

	// Tier 2: hours.
	if raw := q.Get("hours"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 {
			if maxHours := maxDays * 24; n > maxHours {
				n = maxHours
			}
			return now.Add(-time.Duration(n) * time.Hour), until
		}
		// malformed → fall through to the days tier
	}

	// Tier 3: days (existing semantics).
	days := intArg(r, "days", defDays, minDays, maxDays)
	if days <= 0 {
		return time.Time{}, until
	}
	return now.Add(-time.Duration(days) * 24 * time.Hour), until
}

// windowBoundsResolved reports whether the genuinely-NEW sub-day params
// (since / hours for the lower bound, until for the upper bound)
// actually RESOLVED to a value — as opposed to being present-but-
// malformed, which windowRange fails open on. Callers use it to decide
// whether to suppress the legacy day-grained from_date / to_date params:
// suppression must key off resolution, not raw presence, so that
// `until=garbage&to_date=X` keeps to_date (the until tier failed open)
// instead of silently dropping both bounds.
//
// The lower-bound resolution mirrors windowRange's tier walk exactly:
// `since` wins when it parses; otherwise `hours` (an integer ≥ 1) does.
// The `days` tier is intentionally NOT counted here — days-only requests
// must keep their historical AND-with-from_date behavior byte-for-byte.
func windowBoundsResolved(r *http.Request) (lowerNew, upperNew bool) {
	q := r.URL.Query()
	if raw := q.Get("since"); raw != "" {
		if _, ok := parseWindowTime(raw); ok {
			lowerNew = true
		}
	}
	if !lowerNew {
		if raw := q.Get("hours"); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n >= 1 {
				lowerNew = true
			}
		}
	}
	if raw := q.Get("until"); raw != "" {
		if _, ok := parseWindowTime(raw); ok {
			upperNew = true
		}
	}
	return
}

// windowMeta renders a resolved [since, until) window as RFC3339 strings
// (empty string when a bound is unset) for ADDITIVE inclusion in a
// timeseries response's metadata map. `days` stays echoed verbatim for
// back-compat; these fields let a response honestly report the window it
// actually served when an hours/since request was made.
func windowMeta(since, until time.Time) (sinceStr, untilStr string) {
	if !since.IsZero() {
		sinceStr = since.UTC().Format(time.RFC3339)
	}
	if !until.IsZero() {
		untilStr = until.UTC().Format(time.RFC3339)
	}
	return
}

// handleCompressionRetrieval serves /api/compression/retrieval?days=N —
// the K43 / Tier 3 self-learning feedback loop measurement: how many
// stashed bodies were actually retrieved and which shapes / actions
// the model returns to most often. Pairs with the G31 (CCR / stash)
// mechanism — `retrieve_rate` is the load-bearing dogfood metric for
// the strategic moat.
func (s *Server) handleCompressionRetrieval(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 7, 1, 365)
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")

	rep, err := learn.NewPatternMiner(s.db()).Report(r.Context(), learn.ReportOptions{
		Days: days, Tool: tool, Project: project,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("retrieval report: %v", err), http.StatusInternalServerError)
		return
	}

	// Mirror the prior shape so existing JS consumers don't break.
	// retrieve_rate can exceed 1.0 when the model retrieves the same
	// sha multiple times — we surface the raw ratio and let the UI
	// render "% retrieves per stash" so > 100% reads naturally.
	type shaCount struct {
		Sha   string `json:"sha"`
		Count int    `json:"count"`
	}
	type actionCount struct {
		ActionID int64 `json:"action_id"`
		Count    int   `json:"count"`
	}
	out := struct {
		Days               int                   `json:"days"`
		StashRetrievals    int                   `json:"stash_retrievals"`
		SearchHits         int                   `json:"search_hits"`
		TotalStashes       int                   `json:"total_stashes"`
		RetrieveRate       float64               `json:"retrieve_rate"`
		TopRetrievedShas   []shaCount            `json:"top_retrieved_shas"`
		TopSearchedActions []actionCount         `json:"top_searched_actions"`
		StashedSamples     []stashedSample       `json:"stashed_samples"`
		Hints              []learn.ThresholdHint `json:"hints"`
	}{
		Days:               days,
		StashRetrievals:    rep.StashRetrievals,
		SearchHits:         rep.SearchHits,
		TotalStashes:       rep.TotalStashes,
		RetrieveRate:       rep.RetrieveRate,
		TopRetrievedShas:   make([]shaCount, 0, len(rep.TopRetrievedShas)),
		TopSearchedActions: make([]actionCount, 0, len(rep.TopSearchedActions)),
		StashedSamples:     s.loadStashedSamples(r.Context(), days, tool, project, rep.TopRetrievedShas),
		Hints:              rep.Hints,
	}
	if out.Hints == nil {
		out.Hints = []learn.ThresholdHint{}
	}
	for _, sc := range rep.TopRetrievedShas {
		out.TopRetrievedShas = append(out.TopRetrievedShas, shaCount{Sha: sc.Sha, Count: sc.Count})
	}
	for _, ac := range rep.TopSearchedActions {
		out.TopSearchedActions = append(out.TopSearchedActions, actionCount{ActionID: ac.ActionID, Count: ac.Count})
	}
	writeJSON(w, out)
}

// stashedSample is one entry in the "what's getting stashed" preview: a short
// scrubbed snippet of a stashed body, with how many times it was stashed and
// (when applicable) retrieved. Replaces the opaque "top retrieved SHAs" list.
type stashedSample struct {
	Sha            string `json:"sha"`
	Snippet        string `json:"snippet"`
	Bytes          int64  `json:"bytes"`
	Count          int    `json:"count"`
	RetrievedCount int    `json:"retrieved_count"`
}

// loadStashedSamples returns up to 8 recent distinct stashed bodies with a
// scrubbed content snippet, so the SROD panel shows what the proxy is actually
// offloading instead of raw SHAs. body_hash on a stash compression_event IS
// the stash sha, so we read each from the stash dir (best-effort — LRU-evicted
// shas are skipped). Returns an empty slice when no stash dir is wired or
// nothing readable remains, never an error (the panel degrades to counts).
func (s *Server) loadStashedSamples(ctx context.Context, days int, tool, project string, retrieved []learn.ShaCount) []stashedSample {
	empty := []stashedSample{}
	if s.opts.StashDir == "" {
		return empty
	}
	st, err := stash.New(stash.Options{Dir: s.opts.StashDir})
	if err != nil {
		return empty
	}
	retrievedCount := make(map[string]int, len(retrieved))
	for _, x := range retrieved {
		retrievedCount[x.Sha] = x.Count
	}

	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format(time.RFC3339Nano)
	join, where := "", ""
	args := []any{cutoff}
	if tool != "" || project != "" {
		join = ` LEFT JOIN api_turns at ON at.id = ce.api_turn_id
		         LEFT JOIN sessions ss ON ss.id = at.session_id
		         LEFT JOIN projects p ON p.id = ss.project_id`
		if tool != "" {
			where += " AND ss.tool = ?"
			args = append(args, tool)
		}
		if project != "" {
			where += " AND p.root_path = ?"
			args = append(args, project)
		}
	}
	//nolint:gosec // G202: join/where are code-constant fragments; all values are bound via ? args.
	q := `SELECT ce.body_hash, COUNT(*), MAX(COALESCE(ce.original_bytes, 0))
	        FROM compression_events ce` + join + `
	       WHERE ce.mechanism = 'stash' AND ce.body_hash IS NOT NULL AND ce.body_hash != ''
	         AND ce.timestamp >= ?` + where + `
	       GROUP BY ce.body_hash
	       ORDER BY MAX(ce.timestamp) DESC
	       LIMIT 24`
	rows, err := s.db().QueryContext(ctx, q, args...)
	if err != nil {
		return empty
	}
	defer rows.Close()

	scr := scrub.New()
	samples := empty
	for rows.Next() {
		var sha string
		var count int
		var bytes int64
		if err := rows.Scan(&sha, &count, &bytes); err != nil {
			return samples
		}
		content, rerr := st.Read(sha)
		if rerr != nil {
			continue // evicted / missing / corrupt → skip
		}
		snip := makeStashSnippet(scr, content, 160)
		if snip == "" {
			continue
		}
		samples = append(samples, stashedSample{
			Sha:            sha,
			Snippet:        snip,
			Bytes:          bytes,
			Count:          count,
			RetrievedCount: retrievedCount[sha],
		})
		if len(samples) >= 8 {
			break
		}
	}
	return samples
}

// makeStashSnippet scrubs a stashed body and renders a single-line preview of
// at most n runes. The body is the model's raw (pre-scrub) tool output, so the
// scrub pass is load-bearing for display safety even on the local dashboard.
func makeStashSnippet(scr *scrub.Scrubber, body []byte, n int) string {
	s := string(body)
	if len(s) > 4096 {
		s = s[:4096] // bound scrub work — we only need the head
	}
	if scr != nil {
		s = scr.String(s)
	}
	s = strings.Join(strings.Fields(s), " ") // collapse newlines/runs to single spaces
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// handleCompactionEvents serves /api/compaction/events?days=N — the
// D23 / Tier 3 compaction-survival visibility surface. Counts
// compaction_events rows (one per /compact in the window), surfaces
// how many had post-compact recovery context injected, and lists the
// recent events with session_id + ghost-files-after count parsed out
// of the JSON snapshot.
func (s *Server) handleCompactionEvents(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 7, 1, 365)
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")
	sinceT, until := windowRange(r, 7, 1, 365)
	since := sinceT.Format(time.RFC3339Nano)

	type eventRow struct {
		ID                int64  `json:"id"`
		SessionID         string `json:"session_id"`
		Timestamp         string `json:"timestamp"`
		Tool              string `json:"tool"`
		PreActionCount    int    `json:"pre_action_count"`
		InjectedAt        string `json:"injected_at,omitempty"`
		GhostFilesAfter   int    `json:"ghost_files_after_count"`
		FileSnapshotCount int    `json:"file_snapshot_count"`
	}
	out := struct {
		Days             int        `json:"days"`
		Count            int        `json:"count"`
		SessionsAffected int        `json:"sessions_affected"`
		InjectionsFired  int        `json:"injections_fired"`
		Events           []eventRow `json:"events"`
	}{Days: days, Events: []eventRow{}}

	// compaction_events has direct tool + project_id columns — no
	// joins needed for filtering. Project lookup via projects table.
	whereExtra := ""
	args := []any{since}
	if !until.IsZero() {
		whereExtra += " AND timestamp < ?"
		args = append(args, until.Format(time.RFC3339Nano))
	}
	if tool != "" {
		whereExtra += " AND tool = ?"
		args = append(args, tool)
	}
	if project != "" {
		whereExtra += " AND project_id = (SELECT id FROM projects WHERE root_path = ?)"
		args = append(args, project)
	}

	_ = s.db().QueryRowContext(r.Context(),
		`SELECT COUNT(*), COUNT(DISTINCT session_id),
		        COALESCE(SUM(CASE WHEN injected_at IS NOT NULL THEN 1 ELSE 0 END), 0)
		 FROM compaction_events WHERE timestamp >= ?`+whereExtra,
		args...).Scan(&out.Count, &out.SessionsAffected, &out.InjectionsFired)

	rows, err := s.db().QueryContext(r.Context(),
		//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
		`SELECT id, session_id, timestamp, COALESCE(tool, ''),
		        COALESCE(pre_action_count, 0),
		        COALESCE(injected_at, ''),
		        COALESCE(ghost_files_after, ''),
		        COALESCE(file_state_snapshot, '')
		 FROM compaction_events
		 WHERE timestamp >= ?`+whereExtra+`
		 ORDER BY timestamp DESC LIMIT 50`,
		args...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var e eventRow
		var ghostsJSON, snapJSON string
		if err := rows.Scan(&e.ID, &e.SessionID, &e.Timestamp, &e.Tool,
			&e.PreActionCount, &e.InjectedAt, &ghostsJSON, &snapJSON); err != nil {
			writeErr(w, err)
			return
		}
		// Count ghost files (a JSON array of paths) without
		// unmarshalling — substring count of `","` + 1 if non-empty.
		// Cheap heuristic; defensible when the field is "[]" or empty.
		if ghostsJSON != "" && ghostsJSON != "[]" && ghostsJSON != "null" {
			var ghosts []string
			if err := json.Unmarshal([]byte(ghostsJSON), &ghosts); err == nil {
				e.GhostFilesAfter = len(ghosts)
			}
		}
		if snapJSON != "" && snapJSON != "null" {
			var snap struct {
				FileCount int `json:"file_count"`
			}
			if err := json.Unmarshal([]byte(snapJSON), &snap); err == nil {
				e.FileSnapshotCount = snap.FileCount
			}
		}
		out.Events = append(out.Events, e)
	}
	writeJSON(w, out)
}

// handleCompressionRollingCost serves /api/compression/rolling-cost?days=N
// — the D20 cost-net surface. Anthropic Haiku summary calls go directly
// to api.anthropic.com (NOT through our proxy), so api_turns doesn't
// see them. We instead read the dedicated `summary_calls` table
// populated by [messagesummary.AnthropicSummarizer] and join against
// `compression_events.mechanism = 'rolling_summary'` to estimate the
// net delta (savings on cache_creation - Haiku spend).
func (s *Server) handleCompressionRollingCost(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 7, 1, 365)
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")
	sinceT, until := windowRange(r, 7, 1, 365)
	since := sinceT.Format(time.RFC3339Nano)

	out := struct {
		Days                     int     `json:"days"`
		SummaryCalls             int     `json:"summary_calls"`
		SummaryInputTokens       int64   `json:"summary_input_tokens"`
		SummaryOutputTokens      int64   `json:"summary_output_tokens"`
		SummaryCostUSD           float64 `json:"summary_cost_usd"`
		RollingSavingsBytes      int64   `json:"rolling_savings_bytes"`
		RollingSavingsTokensEst  int64   `json:"rolling_savings_tokens_est"`
		RollingSavingsCostUSDEst float64 `json:"rolling_savings_cost_usd_est"`
		NetDeltaUSD              float64 `json:"net_delta_usd"`
	}{Days: days}

	// Build optional tool/project filter clauses for summary_calls
	// (joins through sessions → projects) and compression_events
	// (joins through api_turns → sessions → projects).
	scJoin, scWhere, scArgs := "", "", []any{since}
	if !until.IsZero() {
		scWhere += " AND sc.timestamp < ?"
		scArgs = append(scArgs, until.Format(time.RFC3339Nano))
	}
	if tool != "" || project != "" {
		scJoin = ` LEFT JOIN sessions s ON s.id = sc.session_id
		           LEFT JOIN projects p ON p.id = s.project_id`
		if tool != "" {
			scWhere += " AND s.tool = ?"
			scArgs = append(scArgs, tool)
		}
		if project != "" {
			scWhere += " AND p.root_path = ?"
			scArgs = append(scArgs, project)
		}
	}
	_ = s.db().QueryRowContext(r.Context(),
		`SELECT COUNT(*),
		        COALESCE(SUM(sc.input_tokens), 0),
		        COALESCE(SUM(sc.output_tokens), 0),
		        COALESCE(SUM(sc.cost_usd), 0)
		 FROM summary_calls sc`+scJoin+
			` WHERE sc.timestamp >= ?`+scWhere,
		scArgs...).Scan(&out.SummaryCalls, &out.SummaryInputTokens, &out.SummaryOutputTokens, &out.SummaryCostUSD)

	ceJoin, ceWhere, ceArgs := "", "", []any{since}
	if !until.IsZero() {
		ceWhere += " AND ce.timestamp < ?"
		ceArgs = append(ceArgs, until.Format(time.RFC3339Nano))
	}
	if tool != "" || project != "" {
		ceJoin = ` LEFT JOIN sessions s ON s.id = at.session_id
		           LEFT JOIN projects p ON p.id = s.project_id`
		if tool != "" {
			ceWhere += " AND s.tool = ?"
			ceArgs = append(ceArgs, tool)
		}
		if project != "" {
			ceWhere += " AND p.root_path = ?"
			ceArgs = append(ceArgs, project)
		}
	}
	rows, err := s.db().QueryContext(r.Context(),
		//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
		`SELECT COALESCE(at.model, ''),
		        COALESCE(SUM(ce.original_bytes - ce.compressed_bytes), 0)
		 FROM compression_events ce
		 LEFT JOIN api_turns at ON at.id = ce.api_turn_id`+ceJoin+
			` WHERE ce.mechanism = 'rolling_summary' AND ce.timestamp >= ?`+ceWhere+`
		 GROUP BY at.model`,
		ceArgs...)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var model string
			var saved int64
			if err := rows.Scan(&model, &saved); err != nil {
				continue
			}
			out.RollingSavingsBytes += saved
			tokens := saved / 4
			out.RollingSavingsTokensEst += tokens
			if model != "" {
				if pricing, ok := s.opts.CostEngine.Lookup(model); ok && pricing.CacheCreation > 0 {
					// rolling_summary saves bytes that would otherwise
					// be cache_creation tokens (the conversation
					// prefix would have to be re-cached on the next
					// turn without the summary). Price at the
					// CacheCreation rate, not Input.
					out.RollingSavingsCostUSDEst += float64(tokens) * pricing.CacheCreation / 1_000_000
				}
			}
		}
	}
	out.NetDeltaUSD = out.RollingSavingsCostUSDEst - out.SummaryCostUSD
	writeJSON(w, out)
}
