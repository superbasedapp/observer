package dashboard

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/firstrunstate"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard/webapp"
	"github.com/marmutapp/superbased-observer/internal/notify/feedstate"
	"github.com/marmutapp/superbased-observer/internal/secfixstate"
)

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

// Server wires the /api/* endpoints and static file handler.
type Server struct {
	opts Options

	// callerRefusals logs each refused caller path once (caller_guard.go).
	callerRefusals callerRefusalLog

	// notifyState is the notification bell's read / dismiss state seam
	// (internal/notify/feedstate), created once per server.
	notifyStateOnce sync.Once
	notifyState     *feedstate.Store

	// firstRun is the first-run view's seen state seam
	// (internal/firstrunstate, T-922), created once per server.
	firstRunOnce sync.Once
	firstRun     *firstrunstate.Store
	// apps holds the daemon's AI Apps seams (apps_enable.go, first-run plan
	// 3.8), set once by SetApps after New; nil in a process without them.
	apps atomic.Pointer[appsSeams]
	// connectFlow owns the one `observer connect --json --no-browser`
	// subprocess the Get started panel and the top bar start
	// (connect_flow.go). The zero value is ready.
	connectFlow connectFlow
	// secFix is the "Fix with an agent" attempts seam
	// (internal/secfixstate), created once per server.
	secFixOnce sync.Once
	secFix     *secfixstate.Store
	// installSignals caches Options.InstallSignalTools (setup_installsignal.go).
	installSignals installSignalCache

	// routeSections is the route -> Section registry the last
	// registerRoutes call built (the same map governanceGuard enforces).
	// handleGovernance reads it to publish the concealed read routes
	// (T-401), so the SPA skips a fetch the guard would refuse.
	routeSections atomic.Pointer[map[string]Section]
	// routeComponents is the route -> component id registry the last
	// registerRoutes call built (components_manage.go): the component each
	// registered pattern belongs to, resolved by routeComponent at the reg()
	// call. GET /api/components/state reads it to publish the routes of
	// inactive components, so the SPA skips those fetches.
	routeComponents atomic.Pointer[map[string]string]
	// comps caches the live component snapshot the route guard consults
	// (components_manage.go).
	comps componentCache
	// sandboxProbe is the one in-flight sandbox probe GET
	// /api/terminal/sandbox waits on under its deadline (sandbox.go).
	sandboxProbe sandboxProbeFlights

	// secScan is the Code security page's "Scan now" job
	// (security_scan_now.go).
	secScan securityScanJobs

	// windows caches the model context-window table the context gauge reads
	// (sessiongauge.go); refreshed at most once per windowCacheTTL.
	windows windowCache

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
	// benchDryRuns maps a benchmark dry-run job id to the digest of the
	// spec it ran (benchmark_run.go): a spend run must name a finished dry
	// run of the same spec. Guarded by backfillMu; lazily created.
	benchDryRuns map[string]string

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

	// procCapture owns the process capture read side's caches (the findings
	// count per session and the estimate endpoint's replay basis,
	// processcapture.go). Its zero value is ready.
	procCapture processCaptureState

	// orgOverride caches the org-granted per-rule override posture
	// read off the on-disk org policy bundle (guard_override.go,
	// Track B of the org guardrail control wave). Empty and inert on
	// an un-enrolled node.
	orgOverride orgOverrideCache

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

	// processObsState holds the process-observation page state (capability
	// probe, ETW setup seam, probe cache, registration record). Its fields
	// live in process_feature.go and are promoted; a -tags
	// sbo_omit_processobs build swaps in the empty process_feature_omit.go
	// (modular packaging P2, lane MP-L1B), so this file never imports the
	// process-observation packages.
	processObsState

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
	// watcherHealth memoizes /api/health/watcher (stale-while-revalidate)
	// when Options.ReadCaches is set; see watcher_health_cache.go.
	watcherHealth watcherHealthCache
	// analytics memoizes the allow-listed heavy analytics GET responses
	// (stale-while-revalidate) when Options.ReadCaches is set; see
	// analytics_cache.go.
	analytics analyticsCache

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
				return nil, fmt.Errorf("dashboard.New: ExtraRoute %q has no capability metadata - remotely-exposed routes must be classified public/view/execute/local (plan §4.1)", rt.Pattern)
			}
			// §9.4 fail-closed: a mutation-method ExtraRoute (its pattern carries
			// an unsafe method prefix) MUST be Local unless it is on the explicit
			// remotelyExecutableExtraRoutes allowlist. Otherwise a subsystem could
			// register a config-writing POST as View and let it auto-escalate only
			// to Execute — reachable by a remote execute principal. Build-breaking.
			if patternHasUnsafeMethod(rt.Pattern) && rt.Capability != CapabilityLocal {
				if _, ok := remotelyExecutableExtraRoutes[rt.Pattern]; !ok {
					return nil, fmt.Errorf("dashboard.New: mutation-method ExtraRoute %q is classified %s - a config/machine-reaching ExtraRoute write must be CapabilityLocal, or be added to remotelyExecutableExtraRoutes with a threat-model comment (plan §9.4)", rt.Pattern, rt.Capability)
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
		configWriteMu: config.WriteLock(),
		snapshotFn:    diag.Snapshot,
	}
	s.initProcessObs(opts.Logger)
	// The daemon resolves its component set once at start; record the set
	// this process started with so Settings > Components can say which
	// changes wait for a restart (components_manage.go).
	s.comps.recordStart(opts.Components)
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
	// analyticsInvalidateOnWrite clears the analytics response cache after a
	// successful mutation (identity when ReadCaches is off).
	// dbIdentityGuard refuses a CLI that names another database before any
	// route runs (db_identity_guard.go, L-125). It rides here, so every way of
	// serving the loopback handler names its database; the remote handler,
	// which does not go through Handler, gets it in guardedHandler.
	return s.dbIdentityGuard(s.analyticsInvalidateOnWrite(s.governanceGuard(mux, sections, mux)))
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
	// Session quality score (spec §15.2): POST scores the session now and
	// persists the derived metrics (no content, no config). Execute like
	// /tags - a paired remote owner re-scoring a session is a review flow.
	"/quality": CapabilityExecute,
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
	// is: a hand-maintained side table of every route drifts, and here a
	// drifted entry silently leaks a page an organization believes it hid.
	sectionMap := map[string]Section{}
	// compMap is the third parallel registry (modular packaging P1): the
	// component each route belongs to. reg resolves it from the pattern
	// (routeComponent: the catalog's route prefixes, plus command job routes
	// owned by their verb's component), records it, and wraps the handler in the component
	// guard, so a route of an inactive component answers
	// 404 component_not_installed from inside every other guard.
	compMap := map[string]string{}
	reg := func(pattern string, cap Capability, section Section, h http.HandlerFunc) {
		comp := routeComponent(pattern)
		// The analytics response cache wraps an allow-listed handler HERE,
		// inside the mux and so inside every guard (analytics_cache.go); it
		// returns h unchanged when ReadCaches is off or the route is not
		// allow-listed.
		// Lane cli-2 fixes-1: a launch route's agent write is held for a
		// human (launch_hold.go); every other route is returned unchanged.
		h = s.holdAgentLaunch(pattern, h)
		mux.HandleFunc(pattern, s.analyticsCacheWrap(pattern, s.componentGuard(comp, h)))
		capMap[pattern] = cap
		sectionMap[pattern] = section
		compMap[pattern] = comp
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

	// Every reg() call names the nav section its route belongs to
	// (governance.go), or SectionNone for a cross-cutting route that no single
	// page owns — SectionNone is NEVER hidden (the D-D default).
	//
	// CapabilityLocal is owner-local-only (dashboard-management-surface plan
	// §9): config / consent / machine-reaching mutations refused on every
	// remote-exposed bind. A dual-method route (GET read + unsafe write) is
	// method-SPLIT so the GET read stays remotely viewable while the write is
	// Local (Go 1.22 method-prefixed patterns; §9.1). A pure-mutation route is
	// whole-route Local.
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

	s.registerOverviewRoutes(reg)
	s.registerSessionRoutes(reg)
	s.registerTerminalRoutes(reg)
	s.registerProcessRoutes(reg)
	s.registerActivityRoutes(reg)
	s.registerAnalyticsRoutes(reg)
	s.registerSecurityRoutes(reg)
	s.registerGuardRoutes(reg)
	s.registerCacheAndCloudRoutes(reg)
	s.registerProjectRoutes(reg)
	s.registerAnalysisRoutes(reg)
	s.registerSettingsRoutes(reg)
	s.registerEnrolmentRoutes(reg)
	s.registerRemoteRoutes(reg)
	s.registerTerminalRunRoutes(reg)
	s.registerComponentRoutes(reg)
	// ExtraRoutes lets a separable subsystem (e.g. internal/obs) register its
	// own /api/* handlers WITHOUT this package importing it (decision D4). Each
	// MUST carry a Capability; New() rejects an unclassified ExtraRoute when a
	// RemoteController is present (plan §4.1 fail-closed). Empty by default.
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
	s.routeSections.Store(&sectionMap)
	s.routeComponents.Store(&compMap)
	return mux, capMap, sectionMap
}

// routeRegFunc is the registration closure registerRoutes builds and hands to
// each register*Routes function: it records a route's capability, nav section
// and component at the registration site and mounts the guarded handler.
type routeRegFunc func(pattern string, cap Capability, section Section, h http.HandlerFunc)

// registerOverviewRoutes registers the status reads, the You page, the Codex
// and Cowork support reads, the client setup writes, cost, plans and limits,
// cloud agents, discovery, suggestions, routing and the verbosity aggregate.
func (s *Server) registerOverviewRoutes(reg routeRegFunc) {
	reg("/api/status", CapabilityView, SectionNone, s.handleStatus)
	reg("/api/status/scoped", CapabilityView, SectionNone, s.handleStatusScoped)
	// The You page (docs/you-page.md): read-only identity routes. Owner-local:
	// they reveal vendor account emails, the machine fingerprint and which
	// keychain services exist, none of which a remote viewer should read.
	reg("/api/me/tool-accounts", CapabilityLocal, SectionYou, s.handleMeToolAccounts)
	reg("/api/me/machine", CapabilityLocal, SectionYou, s.handleMeMachine)
	reg("/api/me/credentials", CapabilityLocal, SectionYou, s.handleMeCredentials)
	reg("/api/me/aggregate-share", CapabilityLocal, SectionYou, s.handleMeAggregateShare)
	reg("/api/codex/support", CapabilityView, SectionNone, s.handleCodexSupport)
	reg("/api/cowork/reconcile", CapabilityView, SectionNone, s.handleCoworkReconcile)
	// Setup POST writes AI-client config → whole-route Local (the GET status
	// read is refused remotely too — fail-safe). codex-hooks is GET-only.
	reg("/api/setup/codex", CapabilityLocal, SectionSettings.WithSettings("hooks"), s.handleSetupCodex)
	reg("/api/setup/codex-hooks", CapabilityView, SectionSettings.WithSettings("hooks"), s.handleSetupCodexHooks)
	reg("/api/setup/claude", CapabilityLocal, SectionSettings.WithSettings("hooks"), s.handleSetupClaude)
	reg("/api/cost", CapabilityView, SectionCost, s.handleCost)
	// Plans & limits (plans.go): whole-route Local, the page manages
	// keychain credentials. The status line feed is the loopback POST from
	// `observer statusline`.
	reg("/api/plans", CapabilityLocal, SectionPlans, s.handlePlans)
	reg("/api/plans/accounts", CapabilityLocal, SectionPlans, s.handlePlanAccounts)
	reg("/api/plans/accounts/", CapabilityLocal, SectionPlans, s.handlePlanAccount)
	reg("/api/plans/optin", CapabilityLocal, SectionPlans, s.handlePlanOptIn)
	reg("/api/plans/probe", CapabilityLocal, SectionPlans, s.handlePlanProbe)
	reg("/api/plans/statusline", CapabilityLocal, SectionPlans, s.handlePlanStatusLine)
	// Cloud agents (cloudagents.go, docs/cloud-agents.md): owner-local;
	// writes carry the confirm token. Governed as Settings > tools.
	reg("/api/cloud-agents", CapabilityLocal, SectionSettings.WithSettings("tools"), s.handleCloudAgents)
	reg("/api/cloud-agents/test", CapabilityLocal, SectionSettings.WithSettings("tools"), s.handleCloudAgentsTest)
	reg("/api/cloud-agents/connect", CapabilityLocal, SectionSettings.WithSettings("tools"), s.handleCloudAgentsConnect)
	reg("/api/cloud-agents/sync", CapabilityLocal, SectionSettings.WithSettings("tools"), s.handleCloudAgentsSyncAll)
	reg("/api/cloud-agents/accounts/", CapabilityLocal, SectionSettings.WithSettings("tools"), s.handleCloudAgentsAccount)
	reg("/api/discover", CapabilityView, SectionDiscovery, s.handleDiscover)
	reg("/api/suggestions", CapabilityView, SectionSuggestions, s.handleSuggestions)
	reg("/api/suggestions/state", CapabilityLocal, SectionSuggestions, s.handleSuggestionState)
	reg("/api/routing/status", CapabilityView, SectionRouting, s.handleRoutingStatus)
	reg("/api/routing/decisions", CapabilityView, SectionRouting.WithTab("decisions"), s.handleRoutingDecisions)
	reg("/api/routing/savings", CapabilityView, SectionRouting, s.handleRoutingSavings)
	reg("/api/routing/tiers", CapabilityView, SectionRouting.WithTab("policy"), s.handleRoutingTiers)
	reg("/api/routing/health", CapabilityView, SectionRouting.WithTab("overview"), s.handleRoutingHealth)
	reg("/api/routing/shadow", CapabilityView, SectionRouting.WithTab("shadow"), s.handleRoutingShadow)
	reg("/api/routing/simulate", CapabilityView, SectionRouting.WithTab("overview"), s.handleRoutingSimulate)
	// routing apply POST WRITES per-AI-tool routing config files → whole-route
	// Local (§9.3). revert is POST-only Local.
	reg("/api/routing/apply", CapabilityLocal, SectionRouting.WithTab("shadow"), s.handleRoutingApply)
	reg("/api/routing/apply/revert", CapabilityLocal, SectionRouting.WithTab("shadow"), s.handleRoutingApplyRevert)
	reg("/api/routing/apply/ledger", CapabilityView, SectionRouting.WithTab("shadow"), s.handleRoutingApplyLedger)
	reg("/api/routing/policy", CapabilityView, SectionRouting, s.handleRoutingPolicy)
	reg("/api/routing/policy/lint", CapabilityView, SectionRouting, s.handleRoutingPolicyLint)
	reg("/api/verbosity/aggregate", CapabilityView, SectionAnalysis, s.handleVerbosityAggregate)
}

// registerSessionRoutes registers the session list and calendar, own agents,
// session tags and the per-session detail routes.
func (s *Server) registerSessionRoutes(reg routeRegFunc) {
	reg("/api/sessions", CapabilityView, SectionSessions, s.handleSessions)
	reg("/api/sessions/calendar", CapabilityView, SectionSessions, s.handleSessionsCalendar)
	// Own agents (P-228, ownagents.go): the Sessions page's Own agents view,
	// custom-agent sessions grouped by agent name. A pure read.
	reg("/api/own-agents", CapabilityView, SectionSessions, s.handleOwnAgents)
	// Session classification (plan §4). The vocabulary + per-tag rollup is a
	// pure read (View); vocabulary MANAGEMENT (rename/delete across every
	// session) is a whole-route Execute mutation — the same tier as the
	// per-session /tags sub-route, and for the same reason (user-authored
	// review metadata a paired remote owner legitimately drives).
	reg("/api/sessions/tags", CapabilityView, SectionSessions, s.handleSessionsTags)
	reg("/api/sessions/tags/manage", CapabilityExecute, SectionSessions, s.handleSessionsTagsManage)
	// Tag definitions (migration 101): the optional human-readable
	// explanation + category attached to a tag name. Same tier split as
	// the vocabulary above — GET is a pure read (View), POST is a
	// whole-route Execute mutation (method-aware requirement auto-
	// escalates it, same as /api/sessions/tags/manage).
	reg("/api/tags/definitions", CapabilityView, SectionSessions, s.handleTagDefinitions)
	// /api/session/ keeps a View base — its many GET sub-route reads must work
	// remotely — while its mutating sub-routes resolve explicitly via
	// sessionSubRouteCapabilities (§9.1): /handoff + /launch are Execute (a
	// paired remote owner legitimately drives them), which the method-aware
	// requirement produces for their POST. No Local-class sub-route exists under
	// /api/session/; TestSessionSubRouteCapabilities enumerates and pins this.
	reg("/api/session/", CapabilityView, SectionSessions, s.handleSessionDetail)
}

// registerTerminalRoutes registers terminal launch, the terminal cockpit,
// sandboxes, SSH, instances, installs and terminal sessions.
func (s *Server) registerTerminalRoutes(reg routeRegFunc) {
	// Terminal PTY bridge: the GET upgrade is View-reachable by a paired device;
	// the writer role is still gated in-band by the §4.δ execute conjunction.
	reg("/ws/launch/", CapabilityView, SectionTerminals, s.handleLaunchWS)
	// launch admin: GET lists launched terminals (View); the DELETE terminates
	// one — a per-session op a paired owner legitimately drives (Execute).
	// Bare View + method-aware auto-escalation gives DELETE→Execute (§9.3) while
	// preserving the handler's own 405 for other methods.
	reg("/api/launch/", CapabilityView, SectionTerminals, s.handleLaunchAdmin)
	// Terminal cockpit surface (terminal-product-exploitation plan §9).
	// Fresh-agent launch is EXECUTE (it starts a new process — the
	// privilege-expansion feature); the session list is VIEW (metadata only).
	reg("/api/terminal/launch", CapabilityExecute, SectionTerminals, s.handleTerminalLaunch)
	// Pre-launch binary-resolution verdict (tool-binary-resolution arc). LOCAL —
	// resolving the binary runs a $SHELL -lc login-shell PATH capture (a
	// side-effecting local exec) AND reveals absolute binary paths + home-dir
	// layout, so a paired READ-ONLY remote principal must never drive it. Same
	// owner-local posture as /api/terminal/install (reclassified V→L in the
	// 2026-07-23 review pass). The exact pattern is MORE specific than the
	// /api/terminal/ catch-all below, so mux precedence routes it here (not to
	// handleTerminalStatus).
	reg("/api/terminal/launch/preflight", CapabilityLocal, SectionTerminals, s.handleTerminalPreflight)
	// New Terminal "project policy" line (security plan 7.11, lane
	// sec-p2b). LOCAL: it takes a local directory path and says whether the
	// org's project rules apply there, which a paired remote principal has
	// no business probing. Reads the match record and mapping only.
	reg("/api/terminal/project-policy", CapabilityLocal, SectionTerminals, s.handleTerminalProjectPolicy)
	// New Terminal model picker (B5). VIEW — unlike preflight (which runs a
	// local $SHELL PATH capture and reveals binary/home-dir layout), this
	// reads only token_usage history + the capability registry's Known
	// list: informational, non-sensitive, the same posture as
	// /api/terminal/sessions and /api/models. The more-specific pattern
	// takes mux precedence over /api/terminal/launch above.
	reg("/api/terminal/launch/models", CapabilityView, SectionTerminals, s.handleTerminalLaunchModels)
	// Launches held for a human because an agent asked for them (lane
	// cli-2 fixes-1): the list, and each hold's confirm and reject.
	// Owner-local: confirming a launch is the owner's call.
	reg("/api/terminal/pending", CapabilityLocal, SectionTerminals, s.handleTerminalPending)
	reg("/api/terminal/pending/", CapabilityLocal, SectionTerminals, s.handleTerminalPending)
	// B9 sandbox probe (plan §5). VIEW, FAIL-SOFT (always 200) — the same
	// posture as the model-picker endpoint above: informational, reads only
	// the daemon's cached probe result + the [terminal.sandbox] config, no
	// side effects. Distinct from the fail-CLOSED validation inside
	// handleTerminalLaunch, which actually refuses a launch.
	reg("/api/terminal/sandbox", CapabilityView, SectionTerminals, s.handleTerminalSandbox)
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
	reg("/api/terminal/ssh", CapabilityLocal, SectionTerminals, s.handleTerminalSSH)
	// SSH remote-systems EDITOR (T-488): GET reads [terminal.ssh] with full
	// key PATHS (never key contents) + mints the confirm token, PUT replaces
	// the profile list, POST .../test probes a draft. LOCAL for the reasons
	// /api/terminal/ssh is, plus: these write the allow-list of machines this
	// daemon may shell into, which is the owner's call only. Registered on
	// exact patterns, since the /api/terminal/ catch-all below is View.
	reg("/api/terminal/ssh/profiles", CapabilityLocal, SectionTerminals.WithTab("settings"), s.handleTerminalSSHProfiles)
	reg("/api/terminal/ssh/profiles/test", CapabilityLocal, SectionTerminals.WithTab("settings"), s.handleTerminalSSHProfileTest)
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
	reg("/api/instances", CapabilityLocal, SectionTerminals, s.handleInstances)
	reg("/api/instances/", CapabilityLocal, SectionTerminals, s.handleInstanceVerb)
	// Sandbox config editor. LOCAL + confirm-token-gated: unlike the probe
	// above, this writes [terminal.sandbox], including authority-expanding
	// remote-clone / extra-rw-bind escape hatches.
	reg("/api/terminal/sandbox/config", CapabilityLocal, SectionTerminals.WithTab("settings"), s.handleTerminalSandboxConfig)
	// The strace switch (lane ptrace, PT-96): owner-local and confirm-token
	// gated, the only writer of [terminal.sandbox].seccomp_allow_seize.
	reg("/api/terminal/sandbox/ptrace-seize", CapabilityLocal, SectionTerminals.WithTab("settings"), s.handleTerminalSandboxSeize)
	// The sandbox egress refusal audit (lane N1, OpenShell plan 05 section
	// 3.1). LOCAL: the rows name the hosts a sandboxed agent tried to
	// reach and the run's project root.
	reg("/api/sandbox/refusals", CapabilityLocal, SectionTerminals, s.handleSandboxRefusals)
	// The refusal advisor (OpenShell lane N5): GET offers "allow this host"
	// per refusal, PUT applies one through the config save pipeline. LOCAL +
	// confirm-token-gated; guard rule R-167 denies an agent's PUT.
	reg("/api/sandbox/refusals/allow", CapabilityLocal, SectionTerminals, s.handleSandboxRefusalAllow)
	// The first-start install's version picker (lane LEFT-SBX). LOCAL: it
	// makes the daemon read a vendor registry, which a remote principal
	// must never drive.
	reg("/api/terminal/sandbox/install-versions", CapabilityLocal, SectionTerminals.WithTab("settings"), s.handleTerminalSandboxInstallVersions)
	// Sandbox setup (sandbox installation lifecycle plan section 3.6):
	// LOCAL. The GETs read this machine's setup (passive facts, its install
	// records); the check runs a driver probe and the run carries out one
	// server-derived step (confirm token). The subtree holds the per-backend
	// plan, check and run, and the op progress.
	reg("/api/terminal/sandbox/setup", CapabilityLocal, SectionTerminals, s.handleSandboxSetupSummary)
	reg("/api/terminal/sandbox/setup/", CapabilityLocal, SectionTerminals, s.handleSandboxSetup)
	// cli-parity L3 (plan docs/plans/dashboard-cli-parity-plan-2026-11-06.md,
	// item B-G3): "Re-attach in a terminal" runs the fixed `observer sandbox
	// readopt <run>` in a local-writer-only setup PTY. LOCAL + confirm token;
	// guard rule R-165 already denies an agent the /api/terminal/sandbox/readopt
	// prefix.
	reg("/api/terminal/sandbox/readopt/attach", CapabilityLocal, SectionTerminals, s.handleSandboxReadoptTerminal)
	// end cli-parity L3
	// Guided one-click install (tool-binary-resolution arc). LOCAL + confirm-
	// token-gated, EXACTLY like the Tailscale setup handlers: it spawns a
	// grounded, compile-time-constant install command in a visible local-only
	// PTY — a machine-reaching mutation a remote principal must never drive.
	reg("/api/terminal/install", CapabilityLocal, SectionTerminals.WithSettings("tools"), s.handleTerminalInstall)
	// Its reverse, for tools THIS dashboard installed (the node-local
	// tool_installs record): same LOCAL + confirm-token + kill-switch gates,
	// argv derived server-side from the recorded install. The record list and
	// the "forget" are LOCAL too (they name local install commands / paths).
	reg("/api/terminal/uninstall", CapabilityLocal, SectionTerminals.WithSettings("tools"), s.handleTerminalUninstall)
	reg("/api/terminal/installs", CapabilityLocal, SectionTerminals.WithSettings("tools"), s.handleTerminalInstalls)
	reg("/api/terminal/installs/forget", CapabilityLocal, SectionTerminals.WithSettings("tools"), s.handleTerminalInstallForget)
	reg("/api/terminal/sessions", CapabilityView, SectionTerminals, s.handleTerminalSessions)
	// Live-joinable session list (session-attach design Phase 2, "Jump in"):
	// every LIVE, non-setup daemon-owned PTY run of any valid terminal_run kind
	// (fresh/handoff/attach/resume) a dashboard tab can join as an extra seat.
	// VIEW — metadata only, no content. Same visibleSnapshot semantics as
	// /api/terminal/sessions; remote callers see attach/resume rows gated by
	// [remote].allow_terminal_view (built now), with fresh/handoff the
	// non-sensitive floor.
	reg("/api/attach/sessions", CapabilityView, SectionTerminals, s.handleAttachSessions)
	// F4 agent status: point-in-time (GET /api/terminal/<handle>/status) via the
	// prefix route, and the multiplexed live stream — both VIEW (read-only). The
	// Per-terminal project panel (Arc A): git tree + read-only file explorer
	// rooted at the terminal's server-resolved project root. VIEW (GET-only);
	// the more-specific pattern takes mux precedence over /api/terminal/ below,
	// and its own handler re-gates remote-exposed callers on allow_terminal_view.
	reg("/api/terminal/project/", CapabilityView, SectionTerminals, s.handleTerminalProject)
	// Per-terminal session cockpit (Session Cockpit): resolves a live launch
	// token to its run identity and, once correlated, its observer session id +
	// link confidence. VIEW (GET-only, metadata only); the more-specific prefix
	// takes mux precedence over /api/terminal/ below, and its own handler
	// re-gates remote-exposed callers on allow_terminal_view (identically for
	// known and unknown tokens — no token oracle).
	reg("/api/terminal/session/", CapabilityView, SectionTerminals, s.handleTerminalSession)
	// exact /launch + /sessions patterns above take mux precedence.
	reg("/api/terminal/", CapabilityView, SectionTerminals, s.handleTerminalStatus)
	reg("/ws/terminal/status", CapabilityView, SectionTerminals, s.handleTerminalStatusWS)
}

// registerProcessRoutes registers process observation.
func (s *Server) registerProcessRoutes(reg routeRegFunc) {
	reg("/api/process/findings", CapabilityView, SectionSecurity, s.handleProcessFindings)
	reg("/api/process/network/", CapabilityView, SectionSecurity, s.handleProcessNetworkDetail)
	// enable-capture WRITES config.toml (turns on [observer.process] + fixes a
	// non-runnable backend) → whole-route Local, like /api/config/section/.
	reg("/api/process/enable-capture", CapabilityLocal, SectionSettings.WithSettings("process"), s.handleProcessEnableCapture)
	// The capture-limits data-volume estimate (process capture budget plan
	// §9.3): a read-only replay of the node's recent stored runs through the
	// draft [observer.process.capture] values the Settings page is editing.
	// Local like the config editor it serves: it reads the saved config and
	// summarises this machine's process capture.
	reg("/api/process/capture/estimate", CapabilityLocal, SectionSettings.WithSettings("process"), s.handleProcessCaptureEstimate)
	// Elevated-ETW-capturer setup DETECTION (ETW dashboard plan §E2). VIEW: it
	// reads config, runs the same read-only `schtasks /Query` probe
	// `observer init` runs, and reads the daemon's own published health record.
	// It registers nothing and spawns nothing — the elevation broker that does
	// is a separate Local + confirm-token route.
	reg("/api/process/etw/status", CapabilityView, SectionSettings.WithSettings("process"), s.handleProcessETWStatus)
	// The elevation BROKER (ETW dashboard plan §E3): spawns a fixed,
	// server-derived `powershell.exe … Start-Process schtasks.exe -Verb RunAs`
	// in a local-only setup PTY so Windows shows the operator a UAC prompt.
	// LOCAL + confirm-token-gated, exactly like the Tailscale setup POSTs and
	// /api/terminal/install — a machine-reaching mutation a remote principal
	// must never drive, and a consent dialog that can only be approved on the
	// machine itself.
	reg("/api/process/etw/register", CapabilityLocal, SectionSettings.WithSettings("process"), s.handleProcessETWRegister)
}

// registerActivityRoutes registers actions, live, search, budget,
// announcements, notifications, first run, AI apps, messages, cost display,
// experiments, privacy, demo mode, storage, the monthly report, action detail
// and file state.
func (s *Server) registerActivityRoutes(reg routeRegFunc) {
	reg("/api/actions", CapabilityView, SectionActions, s.handleActions)
	reg("/api/live", CapabilityView, SectionLive, s.handleLive)
	reg("/api/search", CapabilityView, SectionSearch, s.handleSearch)
	reg("/api/budget", CapabilityView, SectionCost, s.handleBudget)
	// Announcements are admin-authored banner copy (release-embedded today,
	// org-distributed later) — nothing about this install, nothing sensitive,
	// so View: a remote viewer should see the same banner the owner does.
	reg("/api/announcements", CapabilityView, SectionNone, s.handleAnnouncements)
	// The notification bell (D-323): cross-cutting, so never hidden as a
	// route; the feed itself drops what a hidden section owns. Local: the
	// bell is the owner's own inbox and its state write is a node mutation.
	reg("/api/notifications", CapabilityLocal, SectionNone, s.handleNotifications)
	reg("/api/notifications/state", CapabilityLocal, SectionNone, s.handleNotificationState)
	// The first-run capture view (T-922, firstrun.go): detected AI tools and
	// the watcher's history-capture progress. Local: it names this machine's
	// session folders and project roots, and its seen write is a node
	// mutation. Never hidden as a route (it is the welcome on a fresh node).
	reg("/api/firstrun", CapabilityLocal, SectionNone, s.handleFirstRun)
	reg("/api/firstrun/seen", CapabilityLocal, SectionNone, s.handleFirstRunSeen)
	// The first-run "at a glance" card (firstrun_glance.go): 30-day spend,
	// top model, busiest project, re-reads. Local, like /api/firstrun.
	reg("/api/firstrun/glance", CapabilityLocal, SectionNone, s.handleFirstRunGlance)
	// AI Apps hot-enable (apps_enable.go, first-run plan 3.5 and 3.8): the
	// one enable seam the dashboard button, `observer apps on|off|status`
	// and the VS Code action share. Local: enable and disable write the
	// config, and the status names this machine's receiver addresses. Never
	// hidden as a route (the first-run surface depends on it).
	reg("/api/apps/status", CapabilityLocal, SectionNone, s.handleAppsStatus)
	reg("/api/apps/enable", CapabilityLocal, SectionNone, s.handleAppsEnable)
	reg("/api/apps/disable", CapabilityLocal, SectionNone, s.handleAppsDisable)
	// The local app lane (S5, hosted AI gateway plan L7; apps_lanes.go):
	// where an app's model calls and its provider key go, so owner-local.
	// Read only by Your apps > Model calls (lane L9), so it follows that
	// page's section: hiding the page hides its API.
	reg("/api/apps/lanes", CapabilityLocal, SectionAppModelCalls, s.handleAppLanes)
	reg("/api/apps/lanes/", CapabilityLocal, SectionAppModelCalls, s.handleAppLaneItem)
	// Admin and developer messaging (T-854, messages.go): the Messages
	// page's own section, which sits on the unhideable floor (D-695), so an
	// org message is never hidden from the developer it was sent to. Local:
	// the inbox is the owner's own, and its writes reach the org (a reply, a
	// receipt).
	reg("/api/messages", CapabilityLocal, SectionMessages, s.handleMessages)
	reg("/api/messages/", CapabilityLocal, SectionMessages, s.handleMessagesSub)
	// What this dashboard renders for a cost figure: dollars (default) or,
	// when the org a node is enrolled with chose it, token usage. Read by the
	// app shell once at boot. The org's own setting, already verified and
	// cached by the push loop; nothing about this install, so View.
	reg("/api/cost-display", CapabilityView, SectionNone, s.handleCostDisplay)
	// experiments POST CREATES an A/B experiment (management) → whole-route
	// Local. stop is POST-only management.
	// Section: the Compression page's experiments card (profile A/B over the
	// proxy) - governed with that page (managed-node visibility audit).
	reg("/api/experiments", CapabilityLocal, SectionCompression.WithTab("experiments"), s.handleExperiments)
	reg("/api/experiments/stop", CapabilityLocal, SectionCompression.WithTab("experiments"), s.handleExperimentStop)
	reg("/api/experiments/report", CapabilityView, SectionCompression.WithTab("experiments"), s.handleExperimentReport)
	// scrub-test POST computes a scrub over submitted text — no persistence, no
	// machine reach; it is a read-only compute, so View (auto-escalation is
	// harmless here, §9.3).
	reg("/api/privacy/scrub-test", CapabilityView, SectionPrivacy, s.handlePrivacyScrubTest)
	reg("/api/demo", CapabilityView, SectionSettings, s.handleDemo)
	// demo start/stop flip the WHOLE install into/out of demo mode — a local
	// owner-state toggle, never a remote viewer's to flip (Local, §9.3).
	reg("/api/demo/start", CapabilityLocal, SectionSettings, s.handleDemoStart)
	reg("/api/demo/stop", CapabilityLocal, SectionSettings, s.handleDemoStop)
	reg("/api/storage", CapabilityView, SectionSettings.WithSettings("storage"), s.handleStorage)
	reg("/api/storage/vacuum", CapabilityLocal, SectionSettings.WithSettings("storage"), s.handleStorageVacuum)
	reg("/api/storage/backup", CapabilityLocal, SectionSettings.WithSettings("storage"), s.handleStorageBackup)
	reg("/api/report/monthly", CapabilityView, SectionCost, s.handleReportMonthly)
	reg("/api/actions/day-counts", CapabilityView, SectionActions, s.handleActionsDayCounts)
	reg("/api/action/", CapabilityView, SectionActions, s.handleActionDetail)
	reg("/api/file/state", CapabilityView, SectionActions, s.handleFileState)
}

// registerAnalyticsRoutes registers patterns, command jobs, suggest, time
// series, models, tools, compression and requests.
func (s *Server) registerAnalyticsRoutes(reg routeRegFunc) {
	reg("/api/patterns", CapabilityView, SectionPatterns, s.handlePatterns)
	reg("/api/patterns/timeseries", CapabilityView, SectionPatterns, s.handlePatternsTimeseries)
	// Command jobs (command_jobs.go): each POST runs the matching `observer`
	// CLI command as a subprocess through the backfill job runner, so the
	// button and the terminal share one code path. Every one writes state or
	// reaches an AI client's config (or, for doctor, runs a machine probe),
	// so all are owner-Local; each carries the section of the page that
	// shows its button (the commandJobs table owns it), so a page an
	// organization hides hides its action too. The poll/list is Local and
	// cross-cutting at the route (review M3-04); it filters each job by its
	// own section and serves command jobs only (backfill jobs stay behind
	// /api/backfill/jobs/ and its Settings gate).
	for _, name := range commandJobNames() {
		reg("/api/jobs/"+name, CapabilityLocal, commandJobs[name].section, s.commandJobHandler(name))
		// A cancelable row (T-421 item 2) also gets its cancel route, with the
		// same Local class and the same section as its start route.
		if commandJobs[name].cancelable {
			reg("/api/jobs/"+name+"/cancel", CapabilityLocal, commandJobs[name].section, s.commandJobCancelHandler(name))
		}
	}
	reg("/api/jobs", CapabilityLocal, SectionNone, s.handleCommandJobs)
	reg("/api/jobs/", CapabilityLocal, SectionNone, s.handleCommandJobs)
	reg("/api/suggest", CapabilityView, SectionSuggestions, s.handleSuggestPreview)
	reg("/api/suggest/write", CapabilityLocal, SectionSuggestions, s.handleSuggestWrite)
	reg("/api/timeseries/cost", CapabilityView, SectionCost, s.handleTimeseriesCost)
	reg("/api/timeseries/tokens-by-model", CapabilityView, SectionAnalysis, s.handleTimeseriesTokensByModel)
	reg("/api/timeseries/actions", CapabilityView, SectionAnalysis, s.handleTimeseriesActions)
	reg("/api/models", CapabilityView, SectionNone, s.handleModels)
	reg("/api/tools", CapabilityView, SectionTools, s.handleTools)
	reg("/api/tools/breakdown", CapabilityView, SectionTools, s.handleToolsBreakdown)
	reg("/api/compression/events", CapabilityView, SectionCompression, s.handleCompressionEvents)
	reg("/api/compression/timeseries", CapabilityView, SectionCompression, s.handleCompressionTimeseries)
	reg("/api/compression/by-model", CapabilityView, SectionCompression, s.handleCompressionByModel)
	reg("/api/compression/retrieval", CapabilityView, SectionCompression, s.handleCompressionRetrieval)
	reg("/api/compression/rolling-cost", CapabilityView, SectionCompression, s.handleCompressionRollingCost)
	reg("/api/compaction/events", CapabilityView, SectionCompression, s.handleCompactionEvents)
	// Requests page (request-grants G6). The list is a dual-method route
	// (GET read + POST create), so whole-route Local like every other
	// read-plus-mutate route here; the sub-routes mutate (withdraw, cancel)
	// or build a draft from local guard data (prefill, preview), all Local.
	reg("/api/requests", CapabilityLocal, SectionRequests, s.handleRequests)
	reg("/api/requests/", CapabilityLocal, SectionRequests, s.handleRequestsSub)
}

// registerSecurityRoutes registers code security.
func (s *Server) registerSecurityRoutes(reg routeRegFunc) {
	// Code security (the security pillar, component `security`; security
	// pillar plan section 4.10): its own page beside Guard's, and the same
	// managed-node visibility section as its page. A route one tab reads
	// exclusively carries that tab (Findings, Exceptions, Baselines), so
	// hiding the tab blocks its API as Guard's tabs do (lane gov-tabs). The
	// findings list stays page-level: the page export reads it too
	// (web/src/lib/exportTarget.ts).
	reg("/api/security/status", CapabilityView, SectionCodeSecurity, s.handleSecurityStatus)
	reg("/api/security/findings", CapabilityView, SectionCodeSecurity, s.handleSecurityFindings)
	// The findings list's facet counts and grouped rows (redesign plan
	// section 4.4) and the Coverage read (section 4.5): read-only, the same
	// class and page-level section as the list, since the Overview reads
	// them too.
	reg("/api/security/findings/facets", CapabilityView, SectionCodeSecurity, s.handleSecurityFindingsFacets)
	reg("/api/security/findings/groups", CapabilityView, SectionCodeSecurity, s.handleSecurityFindingsGroups)
	reg("/api/security/coverage", CapabilityView, SectionCodeSecurity, s.handleSecurityCoverage)
	// The affected-worker notice (security plan 7.12, lane SEC-E3): never
	// hidden, so a page the org hides cannot hide what it is told.
	reg("/api/security/org-notice", CapabilityView, SectionNone, s.handleSecurityOrgNotice)
	// The Findings tab's Explain (security.feedback, lane sec-h): a judge
	// call that may leave the machine, so owner-local with the confirm
	// token; it changes nothing on the finding.
	reg("/api/security/findings/{id}/explain", CapabilityLocal, SectionCodeSecurity.WithTab("findings"), s.handleSecurityExplain)
	// Local finding exceptions and baselines (lane sec-c3): they lift a
	// finding, so owner-local, with the confirm token on every write. The
	// exceptions list stays page-level: its read feeds the Findings tab's
	// pickers and the Findings tab writes an exception too.
	reg("/api/security/exceptions", CapabilityLocal, SectionCodeSecurity, s.handleSecurityExceptions)
	reg("/api/security/exceptions/revoke", CapabilityLocal, SectionCodeSecurity.WithTab("exceptions"), s.handleSecurityExceptionRevoke)
	reg("/api/security/baseline", CapabilityLocal, SectionCodeSecurity.WithTab("baselines"), s.handleSecurityBaseline)
	// The VS Code extension's diagnostics feed: it resolves a directory
	// the caller names, so owner-local like /api/security/trust.
	reg("/api/security/editor", CapabilityLocal, SectionCodeSecurity, s.handleSecurityEditor)
	// The on-demand history scan: runs git and writes findings.
	reg("/api/security/scan-history", CapabilityLocal, SectionCodeSecurity.WithTab("findings"), s.handleSecurityScanHistory)
	// "Scan now" (security_scan_now.go): starts every ready scanner on one
	// project or on every active one, in the background; the GET lists the
	// scanners and the job. Runs scanners and writes findings: owner-local.
	reg("/api/security/scan", CapabilityLocal, SectionCodeSecurity, s.handleSecurityScan)
	// "Fix with an agent" (security_fix.go): the fix plan of a selection, one
	// project's task started as a fresh terminal launch (the New terminal
	// gates all apply), and the recent attempts with their findings' state.
	// Starts an agent: owner-local, the launch with the confirm token.
	reg("/api/security/fix/plan", CapabilityLocal, SectionCodeSecurity.WithTab("findings"), s.handleSecurityFixPlan)
	reg("/api/security/fix/launch", CapabilityLocal, SectionCodeSecurity.WithTab("findings"), s.handleSecurityFixLaunch)
	reg("/api/security/fix/attempts", CapabilityLocal, SectionCodeSecurity.WithTab("findings"), s.handleSecurityFixAttempts)
	// "Security assessments" (security_assess.go): the kinds and recent runs,
	// one project's plan, the launch of an agent in a dashboard terminal (the
	// New terminal gates all apply), a run's report as plain text, and the
	// developer's import of a run's findings file through the SARIF import
	// seam. Starts an agent: owner-local, the launch and the import with the
	// confirm token.
	reg("/api/security/assessments", CapabilityLocal, SectionCodeSecurity.WithTab("overview"), s.handleSecurityAssess)
	reg("/api/security/assessments/plan", CapabilityLocal, SectionCodeSecurity.WithTab("overview"), s.handleSecurityAssessPlan)
	reg("/api/security/assessments/launch", CapabilityLocal, SectionCodeSecurity.WithTab("overview"), s.handleSecurityAssessLaunch)
	reg("/api/security/assessments/report", CapabilityLocal, SectionCodeSecurity.WithTab("overview"), s.handleSecurityAssessReport)
	reg("/api/security/assessments/import", CapabilityLocal, SectionCodeSecurity.WithTab("overview"), s.handleSecurityAssessImport)
	reg("/api/security/assessments/request", CapabilityLocal, SectionCodeSecurity.WithTab("overview"), s.handleSecurityAssessRequest)
	reg("/api/security/assessments/cancel", CapabilityLocal, SectionCodeSecurity.WithTab("overview"), s.handleSecurityAssessCancel)
	reg("/api/security/assessments/stop", CapabilityLocal, SectionCodeSecurity.WithTab("overview"), s.handleSecurityAssessStop)
	reg("/api/security/assessments/delete-data", CapabilityLocal, SectionCodeSecurity.WithTab("overview"), s.handleSecurityAssessDeleteData)
	reg("/api/security/assessments/validate", CapabilityLocal, SectionCodeSecurity.WithTab("overview"), s.handleSecurityAssessValidate)
	reg("/api/security/assessments/model", CapabilityLocal, SectionCodeSecurity.WithTab("overview"), s.handleSecurityAssessModel)
	// The fix of one checked item (a write-capable agent: the POST is a launch
	// row, held and asked about) and the export of the checked copy.
	reg("/api/security/assessments/fix", CapabilityLocal, SectionCodeSecurity.WithTab("overview"), s.handleSecurityAssessFix)
	reg("/api/security/assessments/export", CapabilityLocal, SectionCodeSecurity.WithTab("overview"), s.handleSecurityAssessExport)
	// The Findings tab's drawer: one finding with its sightings, commits,
	// lifecycle events and exceptions. Read-only, no evidence.
	reg("/api/security/findings/{id}", CapabilityView, SectionCodeSecurity.WithTab("findings"), s.handleSecurityFinding)
	// The opt-in local git hooks (security.githooks): writes into a
	// repository on the developer's consent.
	reg("/api/security/githooks", CapabilityLocal, SectionCodeSecurity.WithTab("baselines"), s.handleSecurityGithooks)
	// The AI change records (security.provenance, lane sec-f2a): the key,
	// the records and the per-repository writer consent, a person's call.
	reg("/api/security/provenance", CapabilityLocal, SectionCodeSecurity.WithTab("baselines"), s.handleSecurityProvenance)
	// Dependency scanners (security.scan.scalibr and security.scan.osv,
	// Phase D2): the Scanners card; reads the database epochs file only.
	reg("/api/security/scanners", CapabilityView, SectionCodeSecurity.WithTab("scanners"), s.handleSecurityScanners)
	// The one-time accept of the scanners' OSV database download (operator
	// ruling PT-19 (2)): owner-local, consent is never a remote viewer's
	// action; the POST needs the confirm token its GET mints.
	reg("/api/security/scanners/db", CapabilityLocal, SectionCodeSecurity.WithTab("scanners"), s.handleSecurityScannersDB)
	// Trivy's database accept for the Trivy image driver (lane OS-2 T):
	// owner-local like the OSV accept; the POST needs the confirm token.
	reg("/api/security/scanners/trivydb", CapabilityLocal, SectionCodeSecurity.WithTab("scanners"), s.handleSecurityScannersTrivyDB)
	// The package lookup posture (lane RM-2, plan section 13.10): the
	// Privacy page's card and first-run choice; owner-local like the
	// accepts, the PUT needs the confirm token its GET mints.
	reg("/api/security/lookup", CapabilityLocal, SectionPrivacy, s.handleSecurityLookup)
	// The artifact folders (M3L-2 item 4, ruling 2026-11-05): a project's
	// candidate build output folders and the per-folder opt-in to scanning
	// them. Owner-local like the accepts; the PUT needs the confirm token its
	// GET mints.
	reg("/api/security/artifacts", CapabilityLocal, SectionCodeSecurity.WithTab("scanners"), s.handleSecurityArtifacts)
	// The Go source check (3b-src): a project's opt-in and its runs, which
	// run this machine's Go toolchain on the project. Owner-local; every
	// write needs the confirm token its GET mints.
	reg("/api/security/reach/go-source", CapabilityLocal, SectionCodeSecurity.WithTab("scanners"), s.handleSecurityReachSource)
	reg("/api/security/reach/go-source/run", CapabilityLocal, SectionCodeSecurity.WithTab("scanners"), s.handleSecurityReachSourceRun)
	// The code rules' card and guided install (security.scan.opengrep,
	// lane SEC-G2): owner-local, the size consent is never a remote
	// viewer's action; the POST needs the confirm token its GET mints.
	reg("/api/security/code/install", CapabilityLocal, SectionCodeSecurity.WithTab("scanners"), s.handleSecurityOpengrep)
	reg("/api/security/iac/install", CapabilityLocal, SectionCodeSecurity.WithTab("scanners"), s.handleSecurityIaCInstall)
	// The SARIF upload (security.scan.sarif-import, lane SEC-P4):
	// owner-local, a file the developer picked; the POST needs the confirm
	// token its GET mints and is capped at the CLI's own file cap.
	reg("/api/security/import-sarif", CapabilityLocal, SectionCodeSecurity.WithTab("scanners"), s.handleSecurityImportSARIF)
	// Repository trust (component security.trust): the New Terminal
	// dialog's trust chip for a chosen directory. Local-only: it reads a
	// directory the caller names. Page-level, and its READ is shared with
	// the Terminals page (sharedReadSections in governance.go): the chip
	// stays while either page is shown; the accept stays Code security's.
	reg("/api/security/trust", CapabilityLocal, SectionCodeSecurity, s.handleSecurityTrust)
	// Custom scanners (component security.scan.custom): owner-local, since a
	// scanner runs a program on this machine; writes need the confirm
	// token the GET mints.
	reg("/api/security/scanners/custom", CapabilityLocal, SectionCodeSecurity.WithTab("scanners"), s.handleSecurityCustom)
	reg("/api/security/scanners/custom/", CapabilityLocal, SectionCodeSecurity.WithTab("scanners"), s.handleSecurityCustomSub)
	// Package checks (component security.deps): the Code security page's
	// card, and the dashboard accept of the online checks' disclosure.
	// Local-only: consent is never a remote viewer's action.
	reg("/api/security/deps", CapabilityLocal, SectionCodeSecurity.WithTab("scanners"), s.handleSecurityDeps)
	// The DAST card (security.dast, security coverage gaps plan section 2):
	// its state and candidates, the accept and one run against a dev server
	// on this machine. Owner-local: the accept is never a remote viewer's
	// action and the run sends requests from this machine; every POST needs
	// the confirm token the GET mints. R-165 reserves the prefix.
	reg("/api/security/dast", CapabilityLocal, SectionCodeSecurity.WithTab("scanners"), s.handleSecurityDAST)
	reg("/api/security/dast/accept", CapabilityLocal, SectionCodeSecurity.WithTab("scanners"), s.handleSecurityDASTAccept)
	reg("/api/security/dast/run", CapabilityLocal, SectionCodeSecurity.WithTab("scanners"), s.handleSecurityDASTRun)
	// The Projects tab's "Export SBOM" (security.deps, plan section 3): a
	// download naming the project's packages, owner-local.
	reg("/api/security/sbom", CapabilityLocal, SectionCodeSecurity.WithTab("projects"), s.handleSecuritySBOM)
}

// registerGuardRoutes registers the guard, MCP access, budget status, lines
// of code and the prompt guard.
func (s *Server) registerGuardRoutes(reg routeRegFunc) {
	reg("/api/guard/summary", CapabilityView, SectionSecurity, s.handleGuardSummary)
	reg("/api/guard/events", CapabilityView, SectionSecurity, s.handleGuardEvents)
	reg("/api/guard/conformance", CapabilityView, SectionSecurity.WithTab("coverage"), s.handleGuardConformance)
	reg("/api/guard/rules", CapabilityView, SectionSecurity, s.handleGuardRules)
	reg("/api/guard/simulate", CapabilityView, SectionSecurity, s.handleGuardSimulate)
	// Guard recipes (guard_recipes.go): the catalog GET mints the confirm
	// token and lists what is applied, so it is Local like the writes; show
	// and preview are reads of the catalog and a fresh guard.
	reg("/api/guard/recipes", CapabilityLocal, SectionSecurity.WithTab("rules"), s.handleGuardRecipes)
	reg("/api/guard/recipes/show", CapabilityView, SectionSecurity.WithTab("rules"), s.handleGuardRecipeShow)
	reg("/api/guard/recipes/preview", CapabilityView, SectionSecurity.WithTab("rules"), s.handleGuardRecipePreview)
	reg("/api/guard/recipes/apply", CapabilityLocal, SectionSecurity.WithTab("rules"), s.handleGuardRecipeApply)
	reg("/api/guard/recipes/remove", CapabilityLocal, SectionSecurity.WithTab("rules"), s.handleGuardRecipeRemove)
	reg("/api/guard/recipes/user", CapabilityLocal, SectionSecurity.WithTab("rules"), s.handleGuardRecipeUser)
	reg("/api/guard/recipes/user/delete", CapabilityLocal, SectionSecurity.WithTab("rules"), s.handleGuardRecipeUserDelete)
	// Guard tools (T-154, guard_tools.go): the `guard test` dry run is a
	// read-shaped View POST; the job routes run `guard rescan | compile` and
	// `guard mcp scan | report` and are owner-local (a state-changing kind
	// also needs the confirm token their GET mints).
	reg("/api/guard/test", CapabilityView, SectionSecurity.WithTab("rules"), s.handleGuardTest)
	reg("/api/guard/jobs/policy", CapabilityLocal, SectionSecurity.WithTab("rules"), s.guardJobsHandler(guardPolicyJobs, true))
	reg("/api/guard/jobs/mcp", CapabilityLocal, SectionSecurity.WithTab("mcp"), s.guardJobsHandler(guardMCPJobs, false))
	// guard approvals: the POST APPROVES a dangerous-command request — a security
	// consent, never a remote viewer's decision. Whole-route Local (§9.3). The
	// DELETE reject is Local (approvals/ subtree).
	reg("/api/guard/approvals", CapabilityLocal, SectionSecurity, s.handleGuardApprovals)
	reg("/api/guard/approvals/", CapabilityLocal, SectionSecurity, s.handleGuardApprovalDelete)
	reg("/api/guard/mcp", CapabilityView, SectionSecurity.WithTab("mcp"), s.handleGuardMCP)
	reg("/api/guard/mcp/approve", CapabilityLocal, SectionSecurity.WithTab("mcp"), s.handleGuardMCPApprove)
	// `observer guard mcp reputation` as a dashboard control (T-496): the same
	// notify.LookupNPMReputation the CLI runs. Whole-route Local (a lookup is
	// one outbound registry request); the POST carries the confirm token.
	reg("/api/guard/mcp/reputation", CapabilityLocal, SectionSecurity.WithTab("mcp"), s.handleGuardMCPReputation)
	reg("/api/mcp-access/status", CapabilityView, SectionSecurity, s.handleMCPAccessStatus)
	// guard policy PUT WRITES the guard policy → whole-route Local. policy/backup
	// writes a backup to disk → Local.
	reg("/api/guard/policy", CapabilityLocal, SectionPolicies, s.handleGuardPolicy)
	reg("/api/guard/policy/project", CapabilityLocal, SectionPolicies, s.handleGuardProjectPolicy)
	reg("/api/guard/policy/lint", CapabilityView, SectionPolicies, s.handleGuardPolicyLint)
	reg("/api/guard/policy/backup", CapabilityLocal, SectionPolicies, s.handleGuardPolicyBackup)
	reg("/api/guard/evidence", CapabilityLocal, SectionSecurity.WithTab("coverage"), s.handleGuardEvidence)
	reg("/api/guard/evidence/download", CapabilityView, SectionSecurity.WithTab("coverage"), s.handleGuardEvidenceDownload)
	reg("/api/guard/budget", CapabilityView, SectionSecurity, s.handleGuardBudget)
	// The node's org budget warnings (budgetstatus.go): cross-cutting, never
	// hidden - the banner/toast on every page reads it.
	reg("/api/budget/status", CapabilityView, SectionNone, s.handleBudgetStatus)
	// Budget freshness P4 (T-206): the same payload pushed as server-sent
	// events when the daemon rewrites budget-status.json.
	reg("/api/budget/status/stream", CapabilityView, SectionNone, s.handleBudgetStatusStream)
	// Lines-of-code authorship (docs/plans/lines-of-code-tracking-plan-2026-09-07.md).
	// A View route: it serves counts over node-local file_changes rows and
	// carries no file content or path. The per-session read is a sub-route
	// of /api/session/ (see handleSessionDetail).
	reg("/api/loc/summary", CapabilityView, SectionSessions, s.handleLOCSummary)
	// The editor-change ingest is owner-LOCAL: a loopback-only POST from
	// the developer's own editor, refused outright on any remotely-exposed
	// bind. It carries LINE COUNTS and a workspace-relative path that is
	// hashed before it reaches the database — never file content. See
	// loc_editor.go for the integrity posture the UI depends on.
	reg("/api/loc/editor-change", CapabilityLocal, SectionSessions, s.handleLOCEditorChange)
	// Prompt-submit intervention (PHASE-3b-DASHBOARD, §8.2): status/
	// events/detectors are reads (View); clear + allow-revoke mutate
	// state (Local, same posture as /api/guard/approvals above); probe
	// spawns a subprocess that reads local hook config files, so it is
	// Local too (machine-reaching, not a remote viewer's decision).
	reg("/api/guard/prompt/status", CapabilityView, SectionSecurity.WithTab("prompt-guard"), s.handleGuardPromptStatus)
	// The organization's coding-agent prompt judge on this node (lane
	// adm-p2, promptjudge.go): read-only, the `observer guard status` facts.
	reg("/api/guard/prompt/judge", CapabilityView, SectionSecurity.WithTab("prompt-guard"), s.handlePromptJudgeStatus)
	reg("/api/guard/prompt/events", CapabilityView, SectionSecurity, s.handleGuardPromptEvents)
	reg("/api/guard/prompt/detectors", CapabilityView, SectionSecurity, s.handleGuardPromptDetectors)
	reg("/api/guard/prompt/clear", CapabilityLocal, SectionSecurity.WithTab("prompt-guard"), s.handleGuardPromptClear)
	reg("/api/guard/prompt/allow/", CapabilityLocal, SectionSecurity.WithTab("prompt-guard"), s.handleGuardPromptAllowDelete)
	reg("/api/guard/prompt/probe", CapabilityLocal, SectionSecurity.WithTab("prompt-guard"), s.handleGuardPromptProbe)
	// Hook capability coverage (hook-parity Lane G, guard_hookcoverage.go):
	// the generated matrix + posture + recorded hook failures (view), the
	// per-binding doctor (local, read-only) and the gate probe (local +
	// confirm token: it records a guard verdict).
	reg("/api/guard/hook-coverage", CapabilityView, SectionSecurity.WithTab("coverage"), s.handleGuardHookCoverage)
	reg("/api/guard/hook-doctor", CapabilityLocal, SectionSecurity.WithTab("coverage"), s.handleGuardHookDoctor)
	reg("/api/guard/hook-probe", CapabilityLocal, SectionSecurity.WithTab("coverage"), s.handleGuardHookProbe)
	// cli-parity L4 (plan docs/plans/dashboard-cli-parity-plan-2026-11-06.md):
	// the [guard.cloud] consent card (B-G5, guard_cloud.go: GET state + confirm
	// token, PUT the switches through the one save pipeline) and the audit
	// chain repair jobs (B-G8, guard_tools.go: each dry run a read, each apply
	// behind the confirm token). Both whole-route Local, and guard rule R-165
	// denies an agent's write to either (rules_selfapproval.go).
	reg("/api/guard/cloud", CapabilityLocal, SectionSecurity.WithTab("mcp"), s.handleGuardCloud)
	reg("/api/guard/jobs/chain", CapabilityLocal, SectionSecurity.WithTab("coverage"), s.guardJobsHandler(guardChainJobs, false))
	// end cli-parity L4
}

// registerCacheAndCloudRoutes registers cache, Cloud Intelligence and the
// cloud account and session routes.
func (s *Server) registerCacheAndCloudRoutes(reg routeRegFunc) {
	reg("/api/cache/status", CapabilityView, SectionCache, s.handleCacheStatus)
	reg("/api/cache/overview", CapabilityView, SectionCache, s.handleCacheOverview)
	reg("/api/cache/timeseries", CapabilityView, SectionCache, s.handleCacheTimeseries)
	reg("/api/cache/health", CapabilityView, SectionCache, s.handleCacheHealth)
	reg("/api/cache/events", CapabilityView, SectionCache.WithTab("events"), s.handleCacheEvents)
	reg("/api/cache/entry-states", CapabilityView, SectionCache.WithTab("overview"), s.handleCacheEntryStates)
	// Cloud Intelligence (Signed-in Free spine — plan §6 CI-P5). Read-only
	// node-local state; nothing here talks to the hosted service. Status lives
	// on the Configure/Settings page (SectionSettings); the per-session view drives
	// the SessionDetailPanel Cloud row (SectionSessions). Both View.
	reg("/api/cloud/status", CapabilityView, SectionSettings.WithSettings("cloud"), s.handleCloudStatus)
	// Org-plane Cloud Intelligence (parity design 2026-10-03, section 3.7):
	// the org's terms + this machine's consent (View: the pending-consent
	// banner reads it), and the interactive accept / withdraw (Local +
	// confirm token: they write config.toml and the consent record). Their
	// own Settings section, `intel`, so a managed default can differ from
	// the personal plane's `cloud`.
	reg("/api/intel/status", CapabilityView, SectionSettings.WithSettings("intel"), s.handleIntelStatus)
	reg("/api/intel/accept", CapabilityLocal, SectionSettings.WithSettings("intel"), s.handleIntelAccept)
	reg("/api/intel/withdraw", CapabilityLocal, SectionSettings.WithSettings("intel"), s.handleIntelWithdraw)
	// Parity phase 3 (design 3.2): the per-session org-plane state + cached
	// result is a View read; enrich is Local + confirm token (it queues and
	// sends one submission). The preview (the exact evidence bytes that would
	// leave) and the ledger (what was sent) are Local, like the personal
	// plane's /api/cloud/preview: evidence bytes are never remotely
	// reachable (review M3-13). The session reads
	// sit under Sessions AND the `intel` subsection, so hiding `intel` hides
	// the org-plane results on the session card as well (the role the design
	// gave a separate `intel_results` id). The ledger lives on Settings.
	reg("/api/intel/session/", CapabilityView, SectionSessions.WithSettings("intel"), s.handleIntelSession)
	reg("/api/intel/preview", CapabilityLocal, SectionSessions.WithSettings("intel"), s.handleIntelPreview)
	reg("/api/intel/enrich", CapabilityLocal, SectionSessions.WithSettings("intel"), s.handleIntelEnrich)
	reg("/api/intel/ledger", CapabilityLocal, SectionSettings.WithSettings("intel"), s.handleIntelLedger)
	// T-490: the weekly org digests of the projects this member works in, a
	// signed, audited pull from the org on the developer's behalf, so Local.
	reg("/api/intel/digests", CapabilityLocal, SectionSettings.WithSettings("intel"), s.handleIntelDigests)
	reg("/api/cloud/session/", CapabilityView, SectionSessions.WithSettings("cloud"), s.handleCloudSession)
	// Cloud ACCOUNT actions (cloud_account.go): login / login/state / logout,
	// all Local — they spawn `observer cloud <verb>` on THIS machine.
	s.registerCloudAccountRoutes(reg)
	// Cloud-session ship tokens (cloudsession_ingest.go, lane CA-B3): the
	// individual Rail S destination and its owner-local token management.
	s.registerCloudSessionRoutes(reg)
}

// registerProjectRoutes registers tasks, benchmarks, projects, delivery,
// agent config and project guidance.
func (s *Server) registerProjectRoutes(reg routeRegFunc) {
	// /api/tasks — the Phase-2 session-level task-tracking rollup
	// (docs/task-tracking.md "Phase 2"): project/tool/window aggregate
	// over LoadSessionTaskReport. Filed under Analysis, the same
	// section the equivalent per-session cost/output-composition
	// breakdowns already live under; the per-session detail itself is
	// the /api/session/<id>/tasks sub-route above (SectionSessions).
	reg("/api/tasks", CapabilityView, SectionAnalysis, s.handleTaskRollup)
	reg("/api/benchmarks", CapabilityView, SectionBenchmarks, s.handleBenchmarks)
	reg("/api/benchmarks/", CapabilityView, SectionBenchmarks, s.handleBenchmarkDetail)
	// `observer benchmark run` / `delete` (benchmark_run.go): a run spends
	// real API budget and a delete removes rows, so both are owner-Local.
	reg("/api/benchmarks/run", CapabilityLocal, SectionBenchmarks, s.handleBenchmarkRun)
	reg("/api/benchmarks/delete", CapabilityLocal, SectionBenchmarks, s.handleBenchmarkDelete)
	reg("/api/projects", CapabilityView, SectionNone, s.handleProjects)
	// Projects-page ROI + commit-alignment detail surfaces (docs/plans/
	// projects-page-roi-and-commit-alignment-plan-2026-09-21.md §3.4).
	// Unlike the list above (shared by the terminal project picker), every
	// detail read is SectionProjects — it discloses spend/commits/prompt text
	// for one specific project. The grade endpoint is POST-only but kept
	// as a bare View route (not method-split): its unsafe method
	// auto-escalates to Execute, and it never mutates config or reaches
	// another machine (SavePromptGrade is a local DB write, same class as
	// e.g. /api/guard/prompt/clear's Local siblings would be if this
	// route needed to be machine-reaching, which it does not).
	reg("/api/project/{id}", CapabilityView, SectionProjects, s.handleProjectDetail)
	reg("/api/project/{id}/commits", CapabilityView, SectionProjects, s.handleProjectCommits)
	reg("/api/project/{id}/prompts", CapabilityView, SectionProjects, s.handleProjectPrompts)
	reg("/api/project/{id}/cost", CapabilityView, SectionProjects, s.handleProjectCost)
	// Where it ran (cloud-agents lane CA-B5, cloudlane.go): the per-project
	// cloud lane on the Overview and Spend tabs. A read, like /cost.
	reg("/api/project/{id}/cloud", CapabilityView, SectionProjects, s.handleProjectCloudLane)
	reg("/api/project/{id}/skills", CapabilityView, SectionProjects, s.handleProjectSkills)
	// Quality metrics (quality.go): reads the project's coverage report
	// files under a cap and the codeintel index; writes nothing.
	reg("/api/project/{id}/quality", CapabilityView, SectionProjects, s.handleProjectQuality)
	reg("/api/project/{id}/prompts/{action_id}/grade", CapabilityView, SectionProjects, s.handleProjectGrade)
	// "Rescan now" (2026-10-15): runs git on this machine, so Local with
	// the confirm token, like the other on-demand local actions.
	reg("/api/project/{id}/commit-scan", CapabilityLocal, SectionProjects, s.handleProjectCommitScan)
	// Delivery, commit to PR to merge (D-689, delivery.go): the tab read is
	// View like the ledger; "Check now" and the mirror settings write reach
	// the network or the disk, so Local with the confirm token. The code
	// host and mirror routes live under the Projects section too (the
	// Settings card is a second door onto the same feature), so an org that
	// hides Projects hides all of it.
	reg("/api/project/{id}/delivery", CapabilityView, SectionProjects, s.handleProjectDelivery)
	reg("/api/project/{id}/delivery/check", CapabilityLocal, SectionProjects, s.handleProjectDeliveryCheck)
	reg("/api/project/{id}/delivery/settings", CapabilityLocal, SectionProjects, s.handleProjectDeliverySettings)
	reg("/api/delivery/links", CapabilityLocal, SectionProjects, s.handleDeliveryLinks)
	reg("/api/delivery/links/{id}", CapabilityLocal, SectionProjects, s.handleDeliveryLink)
	reg("/api/delivery/links/{id}/test", CapabilityLocal, SectionProjects, s.handleDeliveryLinkTest)
	reg("/api/delivery/mirrors", CapabilityView, SectionProjects, s.handleDeliveryMirrors)
	reg("/api/delivery/mirrors/{id}", CapabilityLocal, SectionProjects, s.handleDeliveryMirror)
	// Agent-guidance inventory (internal/guidance). The inventory + roll-up
	// are metadata reads over already-persisted rows, classed like
	// /api/projects itself. The /file endpoint returns a project file's
	// SCRUBBED body, so it carries the terminal project-panel's class —
	// View-tier, SectionTerminals, with the same in-handler
	// [remote].allow_terminal_view gate.
	// The guidance inventory + summary are the Projects PAGE's own reads
	// (web/src/pages/Projects.tsx); /api/projects itself stays SectionNone because
	// the project picker is shared by the terminal launcher and others.
	// AI tool settings (adapter config editor, backlog items 2 and 7;
	// agentconfig.go). The reads open the developer's own vendor files
	// (secrets masked), so they are Local like the writes; only the
	// catalogue coverage (no file read) is View. Preview POSTs are
	// read-shaped (governance.go readShapedPosts); saves need the confirm
	// token.
	reg("/api/agent-config/coverage", CapabilityView, SectionAgentConfig.WithTab("coverage"), s.handleAgentConfigCoverage)
	reg("/api/agent-config/tools", CapabilityLocal, SectionAgentConfig, s.handleAgentConfigTools)
	reg("/api/agent-config/tool", CapabilityLocal, SectionAgentConfig, s.handleAgentConfigTool)
	reg("/api/agent-config/file", CapabilityLocal, SectionAgentConfig, s.handleAgentConfigFile)
	reg("/api/agent-config/common", CapabilityLocal, SectionAgentConfig.WithTab("common"), s.handleAgentConfigCommon)
	reg("/api/agent-config/instructions", CapabilityLocal, SectionAgentConfig.WithTab("instructions"), s.handleAgentConfigInstructions)
	reg("/api/agent-config/instructions/new-path", CapabilityLocal, SectionAgentConfig.WithTab("instructions"), s.handleAgentConfigNewPath)
	reg("/api/agent-config/history", CapabilityLocal, SectionAgentConfig.WithTab("history"), s.handleAgentConfigHistory)
	reg("/api/agent-config/org", CapabilityLocal, SectionAgentConfig.WithTab("organization"), s.handleAgentConfigOrg)
	reg("/api/agent-config/org/apply", CapabilityLocal, SectionAgentConfig.WithTab("organization"), s.handleAgentConfigOrgApply)
	reg("/api/agent-config/preview", CapabilityLocal, SectionAgentConfig, s.handleAgentConfigPreview)
	reg("/api/agent-config/save", CapabilityLocal, SectionAgentConfig, s.handleAgentConfigSave)
	reg("/api/agent-config/common/preview", CapabilityLocal, SectionAgentConfig.WithTab("common"), s.handleAgentConfigCommonPreview)
	reg("/api/agent-config/common/save", CapabilityLocal, SectionAgentConfig.WithTab("common"), s.handleAgentConfigCommonSave)
	reg("/api/projects/guidance", CapabilityView, SectionProjects, s.handleProjectGuidance)
	reg("/api/projects/guidance/summary", CapabilityView, SectionProjects, s.handleProjectGuidanceSummary)
	reg("/api/projects/guidance/file", CapabilityView, SectionTerminals, s.handleProjectGuidanceFile)
}

// registerAnalysisRoutes registers the XLSX export, the analysis page and the
// status line.
func (s *Server) registerAnalysisRoutes(reg routeRegFunc) {
	reg("/api/export.xlsx", CapabilityView, SectionNone, s.handleExportXLSX)
	reg("/api/analysis/headline", CapabilityView, SectionAnalysis, s.handleAnalysisHeadline)
	reg("/api/statusline", CapabilityView, SectionNone, s.handleStatuslineTile)
	reg("/api/analysis/trend", CapabilityView, SectionAnalysis, s.handleAnalysisTrend)
	reg("/api/analysis/movers", CapabilityView, SectionAnalysis, s.handleAnalysisMovers)
	reg("/api/analysis/top-sessions", CapabilityView, SectionAnalysis, s.handleAnalysisTopSessions)
	reg("/api/analysis/routing-suggestions", CapabilityView, SectionAnalysis, s.handleAnalysisRoutingSuggestions)
	reg("/api/analysis/cost-by-hour", CapabilityView, SectionAnalysis, s.handleAnalysisCostByHour)
	reg("/api/analysis/cost-by-dow-hour", CapabilityView, SectionAnalysis, s.handleAnalysisCostByDowHour)
	reg("/api/analysis/cache-savings-trend", CapabilityView, SectionAnalysis, s.handleAnalysisCacheSavingsTrend)
}

// registerSettingsRoutes registers config, the SDK destination, tool setup
// and launch, shell wrapping, repricing, health, update, backfill and
// maintenance.
func (s *Server) registerSettingsRoutes(reg routeRegFunc) {
	// /api/config GET is a config READ (owner-trusted; §2A). Every config WRITE
	// is whole-route Local: pricing PUT, the generic section PUT, reload, profile
	// create, backup restore POST, profile mutate/delete. (Whole-route Local
	// rather than method-split — see the mechanism note above — so the GET
	// metadata/profile reads are refused remotely too, which is fail-safe.)
	reg("/api/config", CapabilityView, SectionSettings, s.handleConfig)
	reg("/api/config/pricing", CapabilityLocal, SectionSettings.WithSettings("pricing"), s.handleConfigPricing)
	reg("/api/config/pricing/defaults", CapabilityView, SectionSettings.WithSettings("pricing"), s.handleConfigPricingDefaults)
	reg("/api/config/section/", CapabilityLocal, SectionSettings, s.handleConfigSection)
	// Schema-driven settings (dashboard-config-management plan §2.2): the
	// generated schema + the generic batched dotted-key write. Both Local —
	// the schema describes the owner-local settings surface and the write is
	// a config mutation. governanceGuard has a body-aware arm for /keys.
	reg("/api/config/schema", CapabilityLocal, SectionSettings, s.handleConfigSchema)
	reg("/api/config/keys", CapabilityLocal, SectionSettings, s.handleConfigKeys)
	// Plane A lane B6 (sdk_settings.go): the SDK discovery read, SDK key
	// sign-in/out, and the settings proposals an agent filed (D19).
	// Local (review E-89): the discovery body names the org, the key id,
	// the gateway URL and the key file's path. The SDKs read it on loopback,
	// which a Local route keeps; a remote dashboard viewer does not get it.
	// No section: an org hiding a Settings section must not break the SDKs'
	// discovery.
	reg("/api/sdk/destination", CapabilityLocal, SectionNone, s.handleSDKDestination)
	// The local OTLP receiver's bind state for the AI Apps pages (E-72):
	// addresses and a bind error only, so a View read.
	reg("/api/sdk/receiver", CapabilityView, SectionNone, s.handleOTLPReceiver)
	reg("/api/sdk/credential", CapabilityLocal, SectionSettings.WithSettings("observability"), s.handleSDKCredential)
	reg("/api/sdk/credential/key", CapabilityLocal, SectionSettings.WithSettings("observability"), s.handleSDKInstallKey)
	reg("/api/config/proposals", CapabilityLocal, SectionSettings, s.handleConfigProposals)
	reg("/api/config/proposals/", CapabilityLocal, SectionSettings, s.handleConfigProposals)
	reg("/api/config/backup", CapabilityLocal, SectionSettings, s.handleConfigBackup)
	reg("/api/config/reload", CapabilityLocal, SectionSettings, s.handleConfigReload)
	reg("/api/config/profiles", CapabilityLocal, SectionSettings.WithSettings("profiles"), s.handleConfigProfiles)
	reg("/api/config/profiles/", CapabilityLocal, SectionSettings.WithSettings("profiles"), s.handleConfigProfile)
	// Per-tool profile assignment (T-369): `observer profile assign
	// tool:NAME` as a dashboard control. Same posture as the CRUD routes
	// above (whole-route Local, the profiles subsection, confirm token on
	// writes).
	reg("/api/config/profile-assignments", CapabilityLocal, SectionSettings.WithSettings("profiles"), s.handleProfileAssignments)
	// Per-project profile assignment (T-421 item 1): `observer config set
	// --project <root> profiles.*` as a dashboard control. Same posture as
	// the per-tool route above; writes are preview-first (an apply must
	// echo its preview's base_sha) and only for a root this node knows.
	reg("/api/config/project-profiles", CapabilityLocal, SectionSettings.WithSettings("profiles"), s.handleProjectProfiles)
	reg("/api/tools/status", CapabilityView, SectionSettings.WithSettings("tools"), s.handleToolsStatus)
	reg("/api/tools/launch", CapabilityLocal, SectionSettings.WithSettings("tools"), s.handleToolsLaunch)
	// Command wrapping (backlog item 7): shims + a marked PATH block in the
	// operator's shell start-up files. Whole-route Local - it names and
	// writes files in the operator's home; the writes also need the confirm
	// token.
	reg("/api/shell-wrap/status", CapabilityLocal, SectionSettings.WithSettings("terminal"), s.handleShellWrapStatus)
	reg("/api/shell-wrap/apply", CapabilityLocal, SectionSettings.WithSettings("terminal"), s.handleShellWrapApply)
	reg("/api/shell-wrap/disable", CapabilityLocal, SectionSettings.WithSettings("terminal"), s.handleShellWrapDisable)
	// cli-parity L2: Claude Code status line, start at login and browser
	// capture setup. Whole-route Local (each writes outside Observer's own
	// files); POSTs need the confirm token the GET mints and preview first.
	reg("/api/setup/statusline", CapabilityLocal, SectionSettings.WithSettings("tools"), s.handleSetupStatusline)
	reg("/api/setup/login-start", CapabilityLocal, SectionSettings.WithSettings("health"), s.handleSetupLoginStart)
	reg("/api/setup/browser", CapabilityLocal, SectionSettings.WithSettings("browser"), s.handleSetupBrowser)
	reg("/api/browser/sites", CapabilityLocal, SectionSettings.WithSettings("browser"), s.handleBrowserSites)
	// Re-pricing stored costs (gap PRICE-REPRICE-1): dry run, apply, revert.
	// Whole-route Local - an apply rewrites stored spend rows; the writes
	// also need the confirm token the status GET mints.
	reg("/api/reprice/status", CapabilityLocal, SectionSettings.WithSettings("pricing"), s.handleRepriceStatus)
	reg("/api/reprice/plan", CapabilityLocal, SectionSettings.WithSettings("pricing"), s.handleRepricePlan)
	reg("/api/reprice/apply", CapabilityLocal, SectionSettings.WithSettings("pricing"), s.handleRepriceApply)
	reg("/api/reprice/revert", CapabilityLocal, SectionSettings.WithSettings("pricing"), s.handleRepriceRevert)
	reg("/api/setup/hooks", CapabilityLocal, SectionSettings.WithSettings("hooks"), s.handleSetupHooks)
	reg("/api/setup/mcp", CapabilityLocal, SectionSettings.WithSettings("mcp"), s.handleSetupMCP)
	// T-537: point a tool's own OTLP exporter at this node (opt-in, every
	// POST confirm-gated, audited). The hooks subsection, like the other
	// AI-client config writes.
	reg("/api/setup/telemetry", CapabilityLocal, SectionSettings.WithSettings("hooks"), s.handleSetupTelemetry)
	// Windows-home init (T-421 item 4): `observer init --windows-*-home` for a
	// WSL daemon. Whole-route Local (it names and writes the operator's
	// Windows-side config files); the apply also needs the confirm token the
	// GET mints. The hooks subsection, like the other setup writes.
	reg("/api/setup/windows-homes", CapabilityLocal, SectionSettings.WithSettings("hooks"), s.handleWindowsHomes)
	reg("/api/setup/windows-homes/apply", CapabilityLocal, SectionSettings.WithSettings("hooks"), s.handleWindowsHomesApply)
	reg("/api/health/doctor", CapabilityView, SectionSettings.WithSettings("health"), s.handleHealthDoctor)
	// Per-tool doctor (T-421 item 3): `observer doctor <tool>` behind the
	// Connected tools "Run checks" action. Local: per-adapter findings quote
	// local paths and the run probes this machine (the mcp-doctor class).
	reg("/api/health/doctor/tool", CapabilityLocal, SectionSettings.WithSettings("tools"), s.handleToolDoctor)
	reg("/api/health/failures", CapabilityView, SectionSettings.WithSettings("health"), s.handleHealthFailures)
	// cli-parity L5: "Update in a terminal" on the Settings > Health update
	// card. Whole-route Local (it runs the install method's fixed update argv
	// in a local setup PTY); the POST also needs the confirm token.
	reg("/api/health/update-terminal", CapabilityLocal, SectionSettings.WithSettings("health"), s.handleHealthUpdateTerminal)
	// end cli-parity L5
	reg("/api/mcp/value", CapabilityView, SectionSettings.WithSettings("mcp"), s.handleMCPValue)
	reg("/api/admin/restart", CapabilityLocal, SectionNone, s.handleAdminRestart)
	// In-place binary update (enterprise-update-management plan §3.10).
	// CapabilityLocal: replacing the daemon's own executable is the most
	// privileged thing this surface can be asked to do, so it is refused on
	// any remotely-exposed bind before a principal is resolved — the same
	// posture as the restart route beside it.
	reg("/api/update/apply", CapabilityLocal, SectionNone, s.handleUpdateApply)
	// W5 read side. CapabilityView, not Local: it discloses this node's own
	// version and update state to a viewer who can already see /api/status,
	// and the Settings -> Health card needs it on every bind mode.
	reg("/api/update/status", CapabilityView, SectionSettings, s.handleUpdateStatus)
	// The "Update automatically" switch (dashboard CLI parity B-S7): writes
	// [update].auto_apply, a sensitive key, through the config save pipeline.
	// Local like the apply route; governed with the Org settings section that
	// owns the [update] keys.
	reg("/api/update/auto-apply", CapabilityLocal, SectionSettings.WithSettings("org"), s.handleUpdateAutoApply)
	// Launch binary paths (dashboard CLI parity follow-up): the [launch.tools.<tool>].path
	// overrides, Local like every config write, governed with Settings > Session attach.
	reg("/api/launch/tool-paths", CapabilityLocal, SectionSettings.WithSettings("terminal"), s.handleLaunchToolPaths)
	// The default workspace folder ([workspace].default_dir): Local because
	// the answer names a local path and a save creates a folder; governed
	// with Settings > Terminal, where its card lives.
	reg("/api/workspace/default", CapabilityLocal, SectionSettings.WithSettings("terminal"), s.handleDefaultWorkspace)
	// The node-local update ledger (`observer update history`). Local, not
	// View: a ledger reason can name a local path, which is exactly why the
	// org-bound posture carries enums only.
	reg("/api/update/history", CapabilityLocal, SectionSettings.WithSettings("health"), s.handleUpdateHistory)
	// `observer config adopt-defaults`: GET previews, POST appends the
	// missing default adapters to an explicit enabled_adapters list (a
	// config write, so Local).
	reg("/api/config/adopt-defaults", CapabilityLocal, SectionSettings.WithSettings("tools"), s.handleAdoptDefaults)
	// W5: the VS Code extension's self-report. CapabilityLocal, mirroring
	// /api/loc/editor-change above — a loopback report from an editor sharing
	// this machine, never something a remote caller writes.
	reg("/api/update/extension-version", CapabilityLocal, SectionSettings, s.handleUpdateExtensionVersion)
	reg("/api/admin/antigravity-bridge.exe", CapabilityView, SectionNone, s.handleAntigravityBridge)
	reg("/api/scan/run", CapabilityLocal, SectionSettings.WithSettings("backfill"), s.handleScanRun)
	reg("/api/backfill/status", CapabilityView, SectionSettings.WithSettings("backfill"), s.handleBackfillStatus)
	reg("/api/backfill/run", CapabilityLocal, SectionSettings.WithSettings("backfill"), s.handleBackfillRun)
	reg("/api/prune/run", CapabilityLocal, SectionSettings.WithSettings("retention"), s.handlePruneRun)
	reg("/api/backfill/jobs", CapabilityView, SectionSettings.WithSettings("backfill"), s.handleBackfillJobsList)
	reg("/api/backfill/jobs/", CapabilityView, SectionSettings, s.handleBackfillJob)
	reg("/api/health/watcher", CapabilityView, SectionNone, s.handleWatcherHealth)
}

// registerEnrolmentRoutes registers enrolment and connect.
func (s *Server) registerEnrolmentRoutes(reg routeRegFunc) {
	reg("/api/enrolment/status", CapabilityView, SectionSettings.WithSettings("enrolment"), s.handleEnrolmentStatus)
	// The front door's one sentence (plan 07 M8.4, connect.go): identity and
	// destination, the same sentence `observer status` prints.
	reg("/api/connect/status", CapabilityView, SectionSettings.WithSettings("enrolment"), s.handleConnectStatus)
	// "Sign in and connect this machine" (Getting started v2,
	// connect_flow.go): start runs `observer connect --json --no-browser
	// [team]` as a child of this binary, progress reads its latest JSON
	// line, cancel stops it. All Local: the child stores a credential on
	// THIS machine and writes its config. start and cancel need the confirm
	// token. The Enrolment (Account) section is a floor section, so an
	// organization can never hide these.
	reg("/api/connect/start", CapabilityLocal, SectionSettings.WithSettings("enrolment"), s.handleConnectStart)
	reg("/api/connect/progress", CapabilityLocal, SectionSettings.WithSettings("enrolment"), s.handleConnectProgress)
	reg("/api/connect/cancel", CapabilityLocal, SectionSettings.WithSettings("enrolment"), s.handleConnectCancel)
	reg("/api/enrolment/last-payload", CapabilityView, SectionSettings.WithSettings("enrolment"), s.handleEnrolmentLastPayload)
	reg("/api/enrolment/unenroll", CapabilityLocal, SectionSettings.WithSettings("enrolment"), s.handleEnrolmentUnenroll)
	// Mints a one-time enrolment token for a teammate through the org server
	// this node is already enrolled with. EXECUTE, not Local: it is a real
	// mutation (it creates a credential on the org server) so it must never
	// sit at plain View, but it is exactly the kind of action a paired remote
	// owner legitimately drives — the same tier as the session /tags and
	// vocabulary-management writes. It reaches the ORG server, never this
	// machine's config or filesystem, which is what separates it from the
	// Local tier.
	reg("/api/enrolment/invite", CapabilityExecute, SectionSettings.WithSettings("enrolment"), s.handleEnrolmentInvite)
	// Settings > Enrolment management (backlog item 6): enrol (code / link /
	// sign-in), the governance-grant consent decision, status, grant report,
	// push-now and leave - the `observer enroll` / `org` / `unenroll` surface.
	// ALL Local: they write this machine's config.toml + keychain or spend an
	// enrolment code; the writes require the confirm token minted by
	// /api/enrolment/manage. Served by Options.EnrolManager (cmd-wired).
	reg("/api/enrolment/manage", CapabilityLocal, SectionSettings.WithSettings("enrolment"), s.handleEnrolmentManage)
	reg("/api/enrolment/grant", CapabilityLocal, SectionSettings.WithSettings("enrolment"), s.handleEnrolmentGrantReport)
	reg("/api/enrolment/probe", CapabilityLocal, SectionSettings.WithSettings("enrolment"), s.handleEnrolmentProbe)
	reg("/api/enrolment/enrol", CapabilityLocal, SectionSettings.WithSettings("enrolment"), s.handleEnrolmentEnrol)
	reg("/api/enrolment/grant-decision", CapabilityLocal, SectionSettings.WithSettings("enrolment"), s.handleEnrolmentGrantDecision)
	reg("/api/enrolment/idp/start", CapabilityLocal, SectionSettings.WithSettings("enrolment"), s.handleEnrolmentIdPStart)
	reg("/api/enrolment/idp/poll", CapabilityLocal, SectionSettings.WithSettings("enrolment"), s.handleEnrolmentIdPPoll)
	reg("/api/enrolment/push-now", CapabilityLocal, SectionSettings.WithSettings("enrolment"), s.handleEnrolmentPushNow)
	reg("/api/enrolment/share-history", CapabilityLocal, SectionSettings.WithSettings("enrolment"), s.handleEnrolmentShareHistory)
	reg("/api/enrolment/resync", CapabilityLocal, SectionSettings.WithSettings("enrolment"), s.handleEnrolmentResync)
	reg("/api/enrolment/leave", CapabilityLocal, SectionSettings.WithSettings("enrolment"), s.handleEnrolmentLeave)
}

// registerRemoteRoutes registers remote access, the terminal workspace layout
// and Tailscale.
func (s *Server) registerRemoteRoutes(reg routeRegFunc) {
	// Remote-access management surface (dashboard-management-surface plan §9).
	// Reads are View (a paired remote owner may see state/audit/sessions — never
	// the secret, §11); mutations are Local (arm/disarm/rotate + session revoke
	// are owner-loopback-only, never a remote principal's to drive).
	reg("/api/remote/config", CapabilityView, SectionRemote, s.handleRemoteConfig)
	reg("/api/remote/enable", CapabilityLocal, SectionRemote, s.handleRemoteEnable)
	reg("/api/remote/disable", CapabilityLocal, SectionRemote, s.handleRemoteDisable)
	reg("/api/remote/rotate", CapabilityLocal, SectionRemote, s.handleRemoteRotate)
	reg("/api/remote/add-device", CapabilityLocal, SectionRemote, s.handleRemoteAddDevice)
	// Flip [remote].allow_terminal on an armed controller WITHOUT rotating the
	// pairing secret or dropping paired devices (Local; owner-loopback only).
	reg("/api/remote/allow-terminal", CapabilityLocal, SectionRemote, s.handleRemoteSetAllowTerminal)
	// Flip [remote].allow_terminal_view — the independent READ opt-in that lets a
	// remote paired device SEE / read-only-subscribe to a remote-sensitive
	// (attach/resume) terminal (§3.2). Strictly weaker than allow_terminal
	// (write). Local; owner-loopback only; hot-reloads the live VIEW gate.
	reg("/api/remote/allow-terminal-view", CapabilityLocal, SectionRemote, s.handleRemoteSetAllowTerminalView)
	// Flip the post-authorization remote writer policy. Credential validation,
	// allow_terminal, TLS, pairing, and allow_terminal_view remain independent.
	// Local; owner-loopback only; hot-reloads for the next acquire.
	reg("/api/remote/allow-remote-takeover", CapabilityLocal, SectionRemote.WithTab("terminal-control"), s.handleRemoteSetAllowRemoteTakeover)
	// Flip [remote].revoke_standing_on_takeover — the OPT-IN hardening that
	// makes a LOCAL writer takeover of a standing-credential remote writer also
	// revoke standing access (default false = seamless). Local; owner-loopback
	// only; no live gate (the takeover hook reads the persisted value).
	reg("/api/remote/standing-revoke-on-takeover", CapabilityLocal, SectionRemote.WithTab("terminal-control"), s.handleRemoteSetRevokeStandingOnTakeover)
	// Terminal Workspace dock-grid layout (migration 073, node-local): READ is
	// View (a remote paired device renders the shared grid read-only); SAVE is
	// Local (arranging the grid is an owner action). Two single-purpose paths
	// per the whole-route classification rule above.
	reg("/api/terminal/workspace-layout", CapabilityView, SectionTerminals, s.handleWorkspaceLayoutGet)
	reg("/api/terminal/workspace-layout/save", CapabilityLocal, SectionTerminals, s.handleWorkspaceLayoutSave)
	// Execute-tier LOCAL approval (§4.γ/§6): mints a single-use terminal-control
	// capability + bound confirm for a target device+handle, returned in the
	// response body only. Owner-loopback-only (Local) — a remote principal can
	// never self-approve.
	reg("/api/remote/approve-execute", CapabilityLocal, SectionRemote, s.handleRemoteApproveExecute)
	// Standing terminal-control secret (standing-terminal-access §B). The status
	// GET is a metadata-only View read (never the secret); mint (enable/rotate)
	// and revoke are owner-loopback-only Local mutations — the raw secret rides
	// the mint POST response body only.
	reg("/api/remote/standing-terminal", CapabilityView, SectionRemote.WithTab("terminal-control"), s.handleStandingTerminalStatus)
	reg("/api/remote/standing-terminal/mint", CapabilityLocal, SectionRemote.WithTab("terminal-control"), s.handleStandingTerminalMint)
	reg("/api/remote/standing-terminal/revoke", CapabilityLocal, SectionRemote.WithTab("terminal-control"), s.handleStandingTerminalRevoke)
	reg("/api/remote/audit", CapabilityView, SectionRemote.WithTab("audit"), s.handleRemoteAudit)
	reg("/api/remote/sessions", CapabilityView, SectionRemote, s.handleRemoteSessions)
	reg("/api/remote/sessions/revoke-all", CapabilityLocal, SectionRemote, s.handleRemoteSessionsRevokeAll)
	reg("/api/remote/sessions/", CapabilityLocal, SectionRemote, s.handleRemoteSessionRevoke)
	reg("/api/remote/selfcheck", CapabilityView, SectionRemote, s.handleRemoteSelfcheck)
	// Tailnet detection + serve-command guidance (P1). Read-only View: runs
	// `tailscale status --json` via internal/tailnet and generates the
	// `tailscale serve` string — Observer never execs `tailscale up|serve`.
	reg("/api/remote/tailscale/status", CapabilityView, SectionRemote, s.handleRemoteTailscaleStatus)
	reg("/api/remote/tailscale/serve", CapabilityLocal, SectionRemote, s.handleRemoteTailscaleServe)
	// One-time Tailscale operator grant, run in the in-dashboard PTY so the
	// user types their sudo password once (dashboard-tailnet-guided-setup §B).
	// Local (owner-loopback only) + confirm-gated, like the arm verbs; the
	// spawned session is local-writer-only at the lease seam.
	reg("/api/remote/tailscale/operator-grant", CapabilityLocal, SectionRemote, s.handleRemoteTailscaleOperatorGrant)
	// Interactive `tailscale up` login, run in the in-dashboard PTY so the auth
	// URL it prints is shown right there (dashboard-tailnet-guided-setup v2).
	// Local (owner-loopback only) + confirm-gated; the spawned session is
	// SpecSetup → local-writer-only. sudo-vs-not is resolved server-side.
	reg("/api/remote/tailscale/login", CapabilityLocal, SectionRemote, s.handleRemoteTailscaleLogin)
	// Guided Tailscale install on Linux (official install.sh via sudo), run in
	// the in-dashboard PTY (dashboard-tailnet-guided-setup v2). Local +
	// confirm-gated; refused off-Linux or when tailscale is already present.
	reg("/api/remote/tailscale/install", CapabilityLocal, SectionRemote, s.handleRemoteTailscaleInstall)
}

// registerTerminalRunRoutes registers terminal policy, first launch, runs and
// limits, and the Arena.
func (s *Server) registerTerminalRunRoutes(reg routeRegFunc) {
	// Terminal launch-policy management (P1). Whole-route Local (owner-loopback
	// only): the GET mints the confirm token + reads [terminal.launch], the PUT
	// writes the privilege-expanding allow_fresh_agent/allowed_tools/
	// allowed_project_roots block. The runs history is a metadata-only View read.
	reg("/api/terminal/policy", CapabilityLocal, SectionTerminals, s.handleTerminalPolicy)
	// The launchpad's first-launch consent (door A): the three launch-policy
	// opt-ins a first launch needs, previewed and applied as one save, plus
	// the playground folder created only on consent. Whole-route Local like
	// the policy editor; the guard's self-approval rule denies it to an agent.
	reg("/api/terminal/first-launch", CapabilityLocal, SectionTerminals, s.handleTerminalFirstLaunch)
	reg("/api/terminal/runs", CapabilityView, SectionTerminals, s.handleTerminalRuns)
	// Runtime bounds (max_concurrent / idle_timeout) — a Local write that
	// live-applies to the PTY manager with no restart, unlike the start-captured
	// launch policy above.
	reg("/api/terminal/limits", CapabilityLocal, SectionTerminals, s.handleTerminalLimits)
	// Agent Arena (plan: agent-arena-terminal-multi-harness-2026-08-22.md).
	// Reads are View; the mutation POSTs auto-escalate to Execute via the
	// standard V-route rule AND re-check the confirm token in-handler
	// (spend + code-mutation surface).
	reg("/api/arena/runs", CapabilityView, SectionTerminals.WithTab("arena"), s.handleArenaRuns)
	// Model pickers (judge + candidates): read-only, GET only. View like its
	// siblings and like the New Terminal picker's /api/terminal/launch/models
	// (the same class of data: model ids this node has used): a remote
	// principal who may start an Arena run must be able to pick its models.
	reg("/api/arena/models", CapabilityView, SectionTerminals.WithTab("arena"), s.handleArenaModels)
	reg("/api/arena/runs/{id}", CapabilityView, SectionTerminals.WithTab("arena"), func(w http.ResponseWriter, r *http.Request) {
		s.handleArenaRunDetail(w, r, r.PathValue("id"))
	})
	reg("/api/arena/runs/{id}/diff/{cid}", CapabilityView, SectionTerminals.WithTab("arena"), func(w http.ResponseWriter, r *http.Request) {
		s.handleArenaRunDiff(w, r, r.PathValue("id"), r.PathValue("cid"))
	})
	reg("/api/arena/runs/{id}/action/{cid}", CapabilityView, SectionTerminals.WithTab("arena"), func(w http.ResponseWriter, r *http.Request) {
		s.handleArenaCandidateAction(w, r, r.PathValue("id"), r.PathValue("cid"))
	})
}

// registerComponentRoutes registers governance and components.
func (s *Server) registerComponentRoutes(reg routeRegFunc) {
	// Admin-controlled Plane B: the node's own governance posture. VIEW and
	// SectionNone — it is registered UNCONDITIONALLY and can never be hidden,
	// because it is how the SPA learns what was hidden and by whom (T8's
	// "never a silent absence" rule, at the API level).
	reg("/api/governance", CapabilityView, SectionNone, s.handleGovernance)
	reg("/api/components", CapabilityView, SectionNone, s.handleComponents) // read-only catalog (components.go); never hidden, like governance
	// This binary's CycloneDX SBOM (components.go, T-670), a read like the catalog.
	reg("/api/components/sbom", CapabilityView, SectionNone, s.handleComponentsSBOM)
	// Settings > Components (modular packaging P1, components_manage.go).
	// SectionNone like the catalog: what runs on this machine is never a hidden
	// page, because every NotInstalled page points here and a hidden target
	// would be a dead end; the org governs components through its own rail
	// (node.components, phase P4), not through page visibility. The state
	// read is View; every POST is Local and needs the confirm token.
	reg("/api/components/state", CapabilityView, SectionNone, s.handleComponentsState)
	reg("/api/components/preview", CapabilityLocal, SectionNone, s.handleComponentsPreview)
	reg("/api/components/apply", CapabilityLocal, SectionNone, s.handleComponentsApply)
	reg("/api/components/teardown", CapabilityLocal, SectionNone, s.handleComponentsTeardown)
	reg("/api/components/purge/preview", CapabilityLocal, SectionNone, s.handleComponentsPurgePreview)
	reg("/api/components/purge/execute", CapabilityLocal, SectionNone, s.handleComponentsPurgeExecute)
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
		stopHTTPServer(srv)
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// dashboardShutdownGrace is how long a dashboard listener lets in-flight
// requests finish after its context is cancelled. A var for tests.
var dashboardShutdownGrace = 5 * time.Second

// stopHTTPServer is the one way a dashboard listener stops (T-553): a
// graceful Shutdown for dashboardShutdownGrace, then Close for whatever is
// still in flight (an SSE stream, a slow query). Shutdown never cancels a
// running handler, so without the Close a long query kept the DB busy after
// the daemon had released its ports, and the deadline error it returned used
// to fail the whole daemon's stop. Close drops those connections, which
// cancels each request's context.
func stopHTTPServer(srv *http.Server) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), dashboardShutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		_ = srv.Close()
	}
}
