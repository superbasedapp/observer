package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cachetrack"
	"github.com/marmutapp/superbased-observer/internal/codeintel"
	"github.com/marmutapp/superbased-observer/internal/compression/conversation"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/identity"
	"github.com/marmutapp/superbased-observer/internal/intelligence/compaction"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/messagesummary"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/pidbridge"
	"github.com/marmutapp/superbased-observer/internal/proxy"
	"github.com/marmutapp/superbased-observer/internal/routing"
	"github.com/marmutapp/superbased-observer/internal/routingconfig"
	"github.com/marmutapp/superbased-observer/internal/selfobs/emit"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newProxyCmd returns the `proxy` subcommand group. Currently only hosts
// `proxy start`; room for `proxy status` / `proxy stop` if we adopt a
// long-running daemon model later.
func newProxyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run the API reverse proxy for accurate token capture",
	}
	cmd.AddCommand(newProxyStartCmd())
	return cmd
}

func newProxyStartCmd() *cobra.Command {
	var (
		configPath string
		port       int
		bindAddr   string
	)
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the proxy on localhost (point ANTHROPIC_BASE_URL / OPENAI_BASE_URL here)",
		Long: "Starts the API reverse proxy on localhost:<port>.\n" +
			"Claude Code: ANTHROPIC_BASE_URL=http://localhost:<port>\n" +
			"Codex:       OPENAI_BASE_URL=http://localhost:<port>/v1",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			// Built BEFORE buildProxy so the C1 judge relay func
			// (docs/plans/c1-judge-relay-spec-2026-08-15.md §3) can be threaded
			// into the admission judge build — the org client (and its bearer/
			// signing-key access) must exist before admission wiring runs.
			var relay orgJudgeRelayFunc
			oc, orgCleanup, ocEnabled, ocErr := buildOrgClient(ctx, configPath)
			if ocErr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "policy resource: org client init failed (LKG/poller skipped): %v\n", ocErr)
			} else if ocEnabled && oc != nil {
				defer orgCleanup()
				relay = orgJudgeRelayFuncFor(oc)
			}

			p, cleanup, addr, _, _, admissionHandle, _, err := buildProxy(ctx, configPath, "", port, bindAddr, relay)
			if err != nil {
				return err
			}
			defer cleanup()

			// Plane-A P0-5 §6.5 / R2-B3: standalone `observer proxy start` must
			// load verified LKG BEFORE binding the listener, and run the
			// policy-resource poller — same org-rail posture as `observer start`.
			// gw wires the gateway.providers family (Phase 3, gateway config
			// plane spec) onto this proxy's own SetLaneTable, same as the
			// full `observer start` path.
			if ocErr == nil && ocEnabled && oc != nil {
				if pcfg, pdb, pcleanup, perr := loadConfigAndDB(ctx, configPath); perr == nil {
					bootstrapUpstreams, bootstrapAutoLane := pcfg.Proxy.Upstreams, pcfg.Proxy.AutoDefaultLane
					bootstrapOrgRoute := pcfg.Proxy.OrgRoute
					gw := newGatewayProvidersHandle(
						p.SetLaneTable,
						func() {
							_ = p.SetRoutingSnapshotWithFallback(bootstrapUpstreams, bootstrapAutoLane,
								bootstrapOrgRoute.Mode, bootstrapOrgRoute.Primary, bootstrapOrgRoute.Fallbacks,
								bootstrapOrgRoute.TerminalPolicy, bootstrapOrgRoute.DirectFallbackCustodyAck)
						},
						p.LaneTable,
					)
					// Bind the atomic lanes+org-route+fallback setter (Sol S7 /
					// Luna L16) so a gateway.providers MODE body flips the mode
					// and installs the fallback terminal rung in one generation.
					gw.SetRouteApply(p.SetRoutingSnapshotWithFallback)
					// node.governance (admin-controlled Plane B) and
					// node.features (org-parity W5.1) are both passed nil
					// here on purpose: `observer proxy start` runs no
					// dashboard, so there is no surface for either a
					// governance body or a feature-gate body to govern. Both
					// families are still polled and reported; nothing is
					// applied. Every call through a nil handle is a no-op by
					// construction (nodeFeaturesHandle.Allowed/TerminalAllowed
					// both nil-check to "allowed").
					loadPolicyResourceLKG(ctx, pcfg, oc, store.New(pdb), admissionHandle, gw, nil, nil, newLogger(pcfg.Observer.LogLevel))
					pcleanup()
					go runPolicyResourcePoller(ctx, pcfg, oc, admissionHandle, gw, nil, nil, nil, newLogger(pcfg.Observer.LogLevel))
				} else {
					fmt.Fprintf(cmd.ErrOrStderr(), "policy resource: LKG/poller skipped — db open failed: %v\n", perr)
				}
			}

			// buildProxy opens the DB without the integrity probe (fast bind);
			// run the one-time quick_check + path-hash backfill in the
			// background so it never delays the listener on a large DB.
			go runStartupDBMaintenance(ctx, configPath)

			fmt.Fprintf(cmd.OutOrStdout(), "proxy listening on %s — ctrl-c to stop\n", addr)
			if err := p.ListenAndServe(ctx, addr); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().IntVar(&port, "port", 0, "Override [proxy].port")
	cmd.Flags().StringVar(&bindAddr, "bind", "127.0.0.1", "Bind address (default localhost only)")
	return cmd
}

// buildProxy loads config, opens the DB, constructs the Proxy wired to the
// storage layer, and returns the Proxy + cleanup closure + resolved listen
// address + the compression-profiles hot-reload hook (nil when conversation
// compression is disabled at boot — the master switch stays restart-gated)
// + the live router's demotion accessor (nil when routing is not wired;
// `observer start` hands it to the same-process dashboard, R2.4)
// + the shared admission handle (gap P0-7): an opaque carrier for the ONE
// *obs.AdmissionService the proxy's admitter enforces, so `observer start` can
// hand the SAME live instance to the dashboard's policy/egress editors instead
// of the dashboard building a second, split instance. Nil when admission is
// disabled; discarded by `observer proxy` and the benchmark harness.
// The db is closed by the cleanup.
//
// recipeName is the deprecated `--recipe` alias: it no longer overlays
// the Load() chain (Track R, P2.2) — it maps onto the [profiles] table
// for this run via applyRecipeAliasToProfiles. Pass "" everywhere new.
//
// relay is the C1 judge-relay func (docs/plans/c1-judge-relay-spec-2026-08-15.md
// §3), built by the caller from its own orgclient.Client instance (which must
// therefore be constructed BEFORE calling buildProxy) and threaded through to
// the admission judge build. Pass nil where no orgclient instance is in scope
// (the benchmark harness) — admission then behaves exactly as it did before
// C1 for a config that doesn't set use_org_relay, and soft-fails honestly
// (judge=nil, hosting="org_relay", one logged warning) for one that does.
func buildProxy(ctx context.Context, configPath, recipeName string, portOverride int, bindAddr string, relay orgJudgeRelayFunc) (*proxy.Proxy, func(), string, func(), func() map[string]string, *obsAdmissionHandle, *RoutingStateHandle, error) {
	loadFresh := func() (config.Config, error) {
		cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
		if err != nil {
			return config.Config{}, err
		}
		if err := applyRecipeAliasToProfiles(&cfg, recipeName); err != nil {
			return config.Config{}, err
		}
		return cfg, nil
	}
	cfg, err := loadFresh()
	if err != nil {
		return nil, nil, "", nil, nil, nil, nil, fmt.Errorf("load config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Observer.DBPath), 0o755); err != nil {
		return nil, nil, "", nil, nil, nil, nil, fmt.Errorf("ensure db dir: %w", err)
	}
	// No integrity probe here: this is a long-running daemon open. The multi-GB
	// PRAGMA quick_check is deferred off the readiness path and run once via
	// db.RunStartupMaintenance after the listener binds (start.go / proxy.go
	// standalone). See db.Options.IntegrityCheck.
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		return nil, nil, "", nil, nil, nil, nil, fmt.Errorf("open db %s: %w", cfg.Observer.DBPath, err)
	}
	s := store.New(database)

	port := cfg.Proxy.Port
	if portOverride > 0 {
		port = portOverride
	}
	if port <= 0 || port > 65535 {
		_ = database.Close()
		return nil, nil, "", nil, nil, nil, nil, fmt.Errorf("proxy: port %d out of range", port)
	}

	logger := newLogger(cfg.Observer.LogLevel)

	// Org attribution: stamp api_turns (and any other rows the proxy
	// inserts) with the enrolled org_id/user_email. No-op on solo-local
	// installs — NewStamper returns a no-op stamper when org_enrolment is
	// empty/absent, so the proxy behaves identically when not enrolled.
	if stmp, err := identity.NewStamper(ctx, database); err != nil {
		logger.Warn("proxy: org stamper init failed; api_turns will not be org-attributed", "err", err)
	} else {
		s = s.WithStamper(stmp)
	}

	// Wire the pid → session_id bridge. The SessionStart hook writes
	// entries; the proxy resolves a client's TCP remote addr through
	// /proc into an ancestor pid that owns the bridge row. Prune once
	// at startup so rebooted machines don't carry stale entries.
	bridge := pidbridge.New(database)
	if _, err := bridge.Prune(ctx, 6*time.Hour); err != nil {
		logger.Warn("pidbridge prune", "err", err)
	}
	resolver := pidbridge.NewProcResolver(bridge, "", 30*time.Second)

	opts := proxy.Options{
		AnthropicUpstream: cfg.Proxy.AnthropicUpstream,
		OpenAIUpstream:    cfg.Proxy.OpenAIUpstream,
		ChatGPTUpstream:   cfg.Proxy.ChatGPTUpstream,
		GeminiUpstream:    cfg.Proxy.GeminiUpstream,
		Upstreams:         cfg.Proxy.Upstreams,
		AutoDefaultLane:   cfg.Proxy.AutoDefaultLane,
		ForceChatGPTHTTP:  cfg.Proxy.ForceChatGPTHTTP,
		PrewarmTargets:    cfg.Proxy.PrewarmTargets,
		Sink:              s,
		ObserverLog:       s,
		SessionResolver:   resolver,
		CostComputer:      costEngineAdapter{e: acquireProcessCostEngine(ctx, cfg, database, logger)},
		Logger:            logger,
		CompressTypes:     cfg.Compression.Conversation.CompressTypes,
	}
	// Limit-snapshot capture for the Next-Message Cost & Limit Predictor
	// (migration 049). Default-on per [predict]; the store (*Store)
	// satisfies proxy.LimitSink via InsertLimitSnapshot. The cost-estimate
	// half needs no wiring (pure read-side at the dashboard/CLI seam).
	if cfg.Predict.Enabled {
		opts.LimitSink = s
	}
	if cfg.Observer.Process.Enabled && cfg.Observer.Process.Network.Enabled {
		opts.NetworkSink = s
		opts.NetworkCapture = proxy.NetworkCaptureOptions{
			Enabled:          true,
			CaptureBodies:    cfg.Observer.Process.Network.CaptureBodies,
			MaxRequestBytes:  cfg.Observer.Process.Network.MaxRequestBytes,
			MaxResponseBytes: cfg.Observer.Process.Network.MaxResponseBytes,
			CaptureHeaders:   cfg.Observer.Process.Network.CaptureHeaders,
			ScrubBodies:      cfg.Observer.Process.Network.ScrubBodies,
			StoreBinary:      cfg.Observer.Process.Network.StoreBinary,
		}
		logger.Info("process network capture: proxy seam wired",
			"capture_bodies", cfg.Observer.Process.Network.CaptureBodies,
			"max_request_bytes", cfg.Observer.Process.Network.MaxRequestBytes,
			"max_response_bytes", cfg.Observer.Process.Network.MaxResponseBytes)
	}

	// Tier-1 cache observation per spec §8 / C8. Default-on per
	// §11; the loader's Default() merges with [cachetrack] in
	// config.toml so an install with no section gets
	// Enabled=true. The store (*Store) satisfies proxy.CacheSink
	// via (*Store).PersistCacheObservation, and the engine is
	// owned at the daemon's proxy assembly per R-engine =
	// Option A (single store-side instance). The watcher's store
	// shares THIS same engine: `observer start` calls
	// Watcher.SetCacheEngine(p.CacheEngine()) so Tier-2
	// (transcript) ingest advances the same CacheModel state.
	wireCacheTrack(cfg, s, &opts, logger)
	var profilesReload func()
	if cfg.Compression.Conversation.Enabled {
		masterPath, _ := config.ResolveGlobalPath(configPath)
		router, authCache, reload := newCompressionRouter(cfg, masterPath, loadFresh, database, logger)
		profilesReload = reload
		if authCache != nil {
			opts.AuthCache = authCacheAdapter{c: authCache}
		}
		// V7-2 warning input: with profile routing, OpenAI-path traffic
		// runs its ASSIGNED profile's compress_types (codex-safe's
		// ["logs"] under baked defaults), not the master values — feed
		// the warning what codex traffic will actually experience.
		// Build-time snapshot; assignment hot-reload (P2.5) leaves the
		// advisory warning on the boot-time assignment.
		oaiProfile := config.ResolveProfileName(cfg.Profiles, models.ProviderOpenAI, "")
		if resolved, err := config.ResolveCompression(cfg.Compression, oaiProfile); err == nil {
			opts.CompressTypes = resolved.Conversation.CompressTypes
		}
		opts.Compressor = router
	}
	if cfg.Compression.Conversation.Compaction.InjectPostCompact {
		opts.PostCompactInjector = compaction.NewInjector(database)
	}
	// Guard proxy seams (guard spec §8 / G9, §9.2 / G10): egress scan
	// + injection heuristics on the request path, tool_use inspection
	// on the response path, MCP tool-declaration observation feeding
	// the pin diff. The Guard instance is the per-process shared one
	// (guardwire.go) — in the `observer start` assembly this build
	// runs FIRST, so the instance constructed here is the same one
	// wireGuard hands the watcher store, making taint state
	// daemon-wide (the cachetrack single-engine precedent). Off-board
	// when guard is disabled/off or every [guard.proxy] + [guard.mcp]
	// feature is off: opts.Guard stays nil and the proxy is
	// byte-identical to the pre-guard baseline.
	wireGuardProxy(ctx, cfg, s, &opts, logger)
	// P1-10: construct the self-obs sink once for the proxy lifetime.
	// Handed to wireRouting for Decide sampling; Shutdown on cleanup.
	selfObsSink, selfObsCleanup, serr := buildSelfObsSink(cfg, logger)
	if serr != nil {
		logger.Warn("selfobs: sink build failed — using Nop", "err", serr)
		selfObsSink = emit.Nop()
		selfObsCleanup = func() {}
	}
	routingDemotions, routingStateHandle := wireRouting(ctx, cfg, s, &opts, logger, selfObsSink)

	// Pre-forward input-admission gate (admission spec §6.2). No-op unless
	// [observability.admission] is enabled; bound here so internal/proxy
	// never imports internal/obs (obs_wire.go owns the adapter). The returned
	// handle carries the ONE admission service (gap P0-7) so `observer start`
	// can share it with the dashboard editors; nil when admission is off.
	admissionHandle := wireAdmission(ctx, cfg, database, relay, &opts, logger, selfObsSink)

	// The gateway rail (docs/observability.md "proxy turn (automatic)"):
	// synthesizes a Plane-A trace for every proxied LLM turn when
	// [observability].proxy_turn_traces is on. No-op (opts.ObsSink stays
	// nil) unless [observability] itself is enabled. Placed after
	// wireAdmission so it can lift opts.AdmissionUserHeader when admission
	// left it unset.
	wireObsProxyTurns(ctx, cfg, database, &opts, logger)

	// Plane B AI Gateway virtual-key source (P5a Sol S2). Lazy: no keychain
	// probe until a gateway-routed request first needs the key, so solo
	// installs are unaffected. internal/proxy never imports internal/orgclient
	// — the adapter is bound here, the CostComputer/Admitter seam pattern.
	opts.VirtualKeySource = newVirtualKeySource(cfg, filepath.Dir(cfg.Observer.DBPath), logger)
	// The node's bounded-drain seam (enterprise-update-management plan §3.7
	// step 4a, rulings R9/R13). Always wired: the gate ADMITS everything
	// until an apply closes it, so a daemon that never updates behaves
	// exactly as before. internal/proxy never imports internal/quiesce — the
	// concrete gate is bound here, the Sink/Admitter/CostComputer pattern.
	opts.DrainGate = updateDrainGate()

	p, err := proxy.New(opts)
	if err != nil {
		selfObsCleanup()
		_ = database.Close()
		return nil, nil, "", nil, nil, nil, nil, err
	}
	// Install the node-local [proxy.org_route] bootstrap onto the routing
	// snapshot (SetOrgGatewayRoute). Inert when no section is configured; an
	// org-published mode body supersedes it hot via the same one-snapshot seam.
	applyOrgRouteBootstrap(p, cfg, logger)
	// §R12.3 optional active prober — OFF by default (no gratuitous
	// network). When enabled it re-fires the prewarm HEADs on the
	// configured cadence: connectivity failures surface in the daemon
	// log and the connection pool stays warm. Breaker STATE remains
	// owned by the passive snapshot refresher (one owner) — the probe
	// is an observability surface, not a second health writer.
	if cfg.Routing.Enabled && cfg.Routing.Reliability.Probe.Enabled {
		interval := time.Duration(cfg.Routing.Reliability.Probe.IntervalSeconds) * time.Second
		probeTargets := []string{cfg.Proxy.AnthropicUpstream, cfg.Proxy.OpenAIUpstream}
		go func() {
			t := time.NewTicker(interval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					p.Prewarm(ctx, probeTargets)
				}
			}
		}()
		logger.Info("routing: active upstream prober enabled", "interval", interval)
	}
	addr := net.JoinHostPort(bindAddr, strconv.Itoa(port))
	cleanup := func() {
		selfObsCleanup()
		_ = database.Close()
	}
	return p, cleanup, addr, profilesReload, routingDemotions, admissionHandle, routingStateHandle, nil
}

// wireGuardProxy wires the Guard proxy seams (guard spec §8 / G9, §9.2 / G10)
// onto opts: egress scan + injection heuristics on the request path,
// tool_use inspection on the response path, and MCP tool-declaration
// observation feeding the pin diff. The Guard instance is the per-process
// shared one (guardwire.go) — in the `observer start` assembly buildProxy
// runs FIRST, so the instance acquired here is the same one wireGuard hands
// the watcher store, making taint state daemon-wide (the cachetrack
// single-engine precedent). No-op only when guard is disabled/off. The Guard
// stays attached when the egress/response/MCP scan toggles are all off because
// the budget rule is another independent request-path consumer. Extracted from
// buildProxy to keep its cyclomatic complexity in check.
func wireGuardProxy(ctx context.Context, cfg config.Config, s *store.Store, opts *proxy.Options, logger *slog.Logger) {
	g := acquireProcessGuard(ctx, cfg, s, logger)
	if g == nil {
		return
	}
	// §9.2: the proxy is also where MCP tool declarations are
	// observed (the tools array in request bodies) — the
	// adapter forwards them to the mcpsec runner off-path.
	mcpRunner := newMCPSecRunner(configGuardMCP{
		Pinning:             cfg.Guard.MCP.Pinning,
		PoisoningHeuristics: cfg.Guard.MCP.PoisoningHeuristics,
	}, s, g, logger)
	opts.Guard = guardScannerAdapter{g: g, st: s, logger: logger, mcp: mcpRunner}
	logger.Info("guard: proxy seams wired",
		"egress_scan", cfg.Guard.Proxy.EgressScan,
		"egress_action", cfg.Guard.Proxy.EgressAction,
		"response_scan", cfg.Guard.Proxy.ResponseScan,
		"injection_heuristics", cfg.Guard.Proxy.InjectionHeuristics,
		"mcp_pinning", cfg.Guard.MCP.Pinning)
}

// wireCacheTrack wires the Tier-1 cache-observation engine (spec §8 / §11) onto
// opts and hands the SAME engine to the store so Tier-2 (watcher / backfill)
// observations advance the shared CacheModel state (§24.4 — single engine,
// multiple feed paths). No-op (with a log line) when [cachetrack] is disabled.
// Extracted from buildProxy to keep its cyclomatic complexity in check.
func wireCacheTrack(cfg config.Config, s *store.Store, opts *proxy.Options, logger *slog.Logger) {
	if !cfg.CacheTrack.Enabled {
		logger.Info("cachetrack: disabled by config")
		return
	}
	engine := cachetrack.NewEngine(cfg.CacheTrack.MaxTrackedSessions)
	opts.CacheEngine = engine
	opts.CacheSink = s
	// C10 wiring: hand the SAME engine instance to the store so Tier-2
	// (watcher / backfill) observations advance the shared CacheModel state.
	// CacheEventExistsForMessage is the cross-tier dedup so a Tier-1 message
	// can't be double-observed by Tier-2.
	s.SetCacheEngine(engine)
	logger.Info("cachetrack: engine wired", "max_tracked_sessions", cfg.CacheTrack.MaxTrackedSessions)
	path := cfg.CacheTrack.CalibrateLogPath
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		logger.Warn("cachetrack: calibrate log path open failed", "path", path, "err", err)
		return
	}
	engine.EnableCalibrateSink(f)
	logger.Info("cachetrack: calibrate sidecar wired",
		"path", path, "cap_blocks", cachetrack.CalibrateBlockCap)
	// File handle leaks until process exit — intentional; the sidecar is a
	// soak-time diagnostic, not a steady-state surface. Auto-stop trips after
	// CalibrateBlockCap writes; the operator unsets the config and restarts.
}

// wireRouting assembles the Channel B routing seam (model-routing spec
// §R5/§R11) onto opts. Gated on the [routing] master switch + a non-off
// mode: when off, no router is wired and the request path is
// byte-identical to a pre-routing build (pinned by the proxy seam
// tests). The policy compiles from config (template expansion + appended
// custom rules, §R6.3); lint errors degrade affected rules to fail-open
// and are logged loudly, never fatal — a typo'd policy must not take
// the proxy down.
//
// Returns the live router's §R18.3 demotion accessor (R2.4) so the
// same-process dashboard can surface calibration demotions — they are
// in-memory state only a live router can answer for. Nil when routing
// is not wired.
func wireRouting(ctx context.Context, cfg config.Config, s *store.Store, opts *proxy.Options, logger *slog.Logger, selfObsSink emit.Sink) (func() map[string]string, *RoutingStateHandle) {
	if !cfg.Routing.Enabled || cfg.Routing.Mode == "off" {
		return nil, nil
	}
	// localSpec is the IMMUTABLE node-local spec (BEFORE org composition),
	// retained on the liveRouter so P0-7 ReloadOrgPolicy can reproduce this
	// construction exactly (plan §4 B5). spec is the working copy composition
	// mutates below.
	localSpec := routingconfig.Spec(cfg.Routing)
	spec := localSpec
	// composedOrgVersion is the org routing-policy version actually COMPOSED
	// into the live policy (0 when none / a compose failure fell back to
	// local). It is the RoutingStateHandle's runningVersion — the org-layer
	// running identity for the P0-6 reporter (R5-B2).
	var composedOrgVersion int64
	// orgBodyMode is the composed org body's [routing].mode, captured for the
	// Arc 4 P3b managed-enforce lift (honored only for a managed node holding
	// enforce.routing; ignored by ComposeOrgPolicy itself under §R23).
	var orgBodyMode string
	// §R19.1 org policy composition: the cached (signature-verified)
	// org document's hard constraints intersect in; its soft rules
	// rank under local. The cache never carries an enforce switch —
	// the [routing] gate above is the only one (§R23).
	if orgPol, ok, perr := s.GetOrgRoutingPolicy(ctx); perr != nil {
		logger.Warn("routing: org policy cache read failed", "err", perr)
	} else if ok {
		composed, cerr := routingconfig.ComposeOrgPolicy(spec, orgPol.Body)
		if cerr != nil {
			logger.Warn("routing: org policy body unusable; continuing with local policy", "err", cerr)
		} else {
			spec = composed
			composedOrgVersion = orgPol.Version
			orgBodyMode = routingconfig.OrgBodyMode(orgPol.Body)
			logger.Info("routing: org policy composed", "version", orgPol.Version)
		}
	}
	policy, issues := routing.Compile(spec)
	for _, issue := range issues {
		logger.Warn("routing: policy lint finding",
			"check", issue.Check, "rule", issue.RuleName,
			"severity", string(issue.Severity), "msg", issue.Message)
	}
	resolver := routing.NewTierResolver()
	overrides, provenance, benchErrs := routingconfig.ResolvedTierOverrides(cfg.Routing)
	for _, berr := range benchErrs {
		logger.Warn("routing: benchmark import skipped", "err", berr)
	}
	for _, prov := range provenance {
		logger.Info("routing: benchmark tiers imported", "provenance", prov)
	}
	// §R11.7 local upstreams: declared models place in TierLocal,
	// the OpenAI-shape local representative installs, and the
	// proxy learns the per-model endpoint routes.
	luTiers, luReps, luRoutes := routingconfig.LocalUpstreamRouting(cfg.Routing)
	if luTiers != nil {
		overrides = routing.MergeTierOverrides(luTiers, overrides)
	}
	if luReps != nil {
		resolver.ReloadWithLocalUpstreams(overrides, luReps)
	} else if overrides != nil {
		resolver.Reload(overrides)
	}
	if len(luRoutes) > 0 {
		opts.LocalUpstreams = luRoutes
		logger.Info("routing: local upstreams wired", "models", len(luRoutes))
	}
	// §R12.4 key pools — local-only config; never log key material.
	if len(cfg.Routing.KeyPool) > 0 {
		opts.KeyPools = cfg.Routing.KeyPool
		logger.Info("routing: key pools wired", "providers", len(cfg.Routing.KeyPool))
	}
	refresher := store.NewRoutingRefresher(s, policy, resolver, routingPriceFn(acquireProcessCostEngine(ctx, cfg, nil, logger)))
	go refresher.Run(ctx)
	lr := newLiveRouter(policy, cfg.Routing.Mode, refresher, s, logger)
	// Seed the composed org body mode so the managed-enforce lift (once
	// start.go injects the predicate via SetManagedEnforce) can honor a
	// managed node's cached enforce policy from the first request, before the
	// first hot-reload cycle. No-op on a local-only node (orgBodyMode "").
	lr.orgMode = orgBodyMode
	opts.ModelRouter = lr
	// §R7.2/§R18.3 calibration job: refreshes model_calibration
	// through the existing one-owner seam and (auto_demote) grades
	// the policy's downshift rules — pure SQL, off the hot path,
	// same daemon as the watcher in `observer start`.
	if cfg.Routing.Calibration.Enabled {
		go routingCalibrationLoop(ctx, s, cfg, lr, logger)
	}
	// §R12.2 same-target retries follow the routing master gate
	// (config lives under [routing.reliability]).
	opts.Reliability = proxy.ReliabilityOptions{
		MaxRetries:           cfg.Routing.Reliability.MaxRetries,
		RetryOverloaded:      cfg.Routing.Reliability.RetryOverloaded,
		RetryUnavailable:     cfg.Routing.Reliability.RetryUnavailable,
		RetryConnectionReset: cfg.Routing.Reliability.RetryConnectionReset,
	}
	logger.Info("routing: Channel B wired",
		"mode", cfg.Routing.Mode, "policy", policy.Name, "hash", policy.Hash())
	// P0-6 router read handle (§4.2): capture the org-layer running identity.
	// effectiveHash is the live policy hash ONLY when an org policy was
	// composed (composedOrgVersion > 0); local-only routing reports version 0
	// + empty hash so the reader resolves none/no_policy (R5-B2).
	handle := &RoutingStateHandle{}
	init := routingState{mode: cfg.Routing.Mode}
	if composedOrgVersion > 0 {
		init.version = composedOrgVersion
		init.hash = policy.Hash()
	}
	handle.store(init)
	// P0-7 hot-reload wiring (plan §4.4 decision A): retain the immutable
	// local spec + the state handle on the router, and hang the reload
	// closure off the handle so start.go can register the org reload sink
	// without a new buildProxy return value (arity frozen at 8).
	lr.localSpec = localSpec
	lr.handle = handle
	handle.reload = lr.ReloadOrgPolicy
	handle.setME = lr.SetManagedEnforce
	if cfg.SelfObs.Enabled {
		lr.SetSelfObs(selfObsSink, cfg.SelfObs.RoutingSampleN)
	}
	return lr.DemotedRules, handle
}

// pipelineAdapter bridges conversation.Pipeline (no context parameter —
// the pipeline is a pure function by design) to proxy.Compressor which
// is context-aware. Lives in cmd/observer so the conversation package
// stays free of the proxy interface.
type pipelineAdapter struct {
	p *conversation.Pipeline
}

// costEngineAdapter bridges (*cost.Engine).Compute to proxy.CostComputer
// — same pattern as pipelineAdapter for the conversation pipeline.
// Lives here so the proxy contract stays free of an intelligence-pkg
// import cycle.
type costEngineAdapter struct {
	e *cost.Engine
}

// Compute implements proxy.CostComputer.
func (a costEngineAdapter) Compute(model string, t proxy.CostTokens) (float64, bool) {
	if a.e == nil {
		return 0, false
	}
	return a.e.Compute(model, cost.TokenBundle{
		Input:           t.Input,
		Output:          t.Output,
		CacheRead:       t.CacheRead,
		CacheCreation:   t.CacheCreation,
		CacheCreation1h: t.CacheCreation1h,
		Fast:            t.Fast,
	})
}

// Compress implements proxy.Compressor (the legacy non-session-aware
// path; calls into [Pipeline.Run] which delegates to RunInSession with
// an empty sessionID).
func (a pipelineAdapter) Compress(ctx context.Context, provider string, body []byte) proxy.CompressionResult {
	return a.CompressInSession(ctx, provider, body, "")
}

// CompressInSession implements proxy.SessionAwareCompressor. The proxy
// passes the extracted session_id (Anthropic Pro/Max OAuth path) so
// session-scoped v1.4.42 features (rolling summaries, read-cache
// auto-substitution) can fire.
func (a pipelineAdapter) CompressInSession(ctx context.Context, provider string, body []byte, sessionID string) proxy.CompressionResult {
	r := a.p.RunInSessionContext(ctx, provider, body, sessionID)
	events := make([]proxy.CompressionEvent, 0, len(r.Events))
	for _, e := range r.Events {
		events = append(events, proxy.CompressionEvent{
			Mechanism:       e.Mechanism,
			OriginalBytes:   e.OriginalBytes,
			CompressedBytes: e.CompressedBytes,
			MsgIndex:        e.MsgIndex,
			ImportanceScore: e.ImportanceScore,
			BodyHash:        e.BodyHash,
		})
	}
	return proxy.CompressionResult{
		Body:              r.Body,
		Skipped:           r.Skipped,
		MessagePrefixHash: r.MessagePrefixHash,
		OriginalBytes:     r.OriginalBytes,
		CompressedBytes:   r.CompressedBytes,
		CompressedCount:   r.CompressedCount,
		DroppedCount:      r.DroppedCount,
		MarkerCount:       r.MarkerCount,
		Events:            events,
	}
}

// costEnginePricingAdapter bridges cost.Engine.Lookup → the
// messagesummary.PricingLookup interface so the DBRecorder can price
// summary calls without messagesummary importing the cost package
// (avoids the import cycle: messagesummary depends on conversation,
// conversation is consumed by cost via the dashboard).
type costEnginePricingAdapter struct {
	e *cost.Engine
}

func (a costEnginePricingAdapter) Lookup(model string) (messagesummary.Pricing, bool) {
	p, ok := a.e.Lookup(model)
	if !ok {
		return messagesummary.Pricing{}, false
	}
	return messagesummary.Pricing{
		Input:           p.Input,
		Output:          p.Output,
		CacheRead:       p.CacheRead,
		CacheCreation:   p.CacheCreation,
		CacheCreation1h: p.CacheCreation1h,
	}, true
}

// authCacheAdapter bridges messagesummary.AuthCache to proxy.AuthCache.
// Both have identically-shaped credential types but live in separate
// packages for import-cycle reasons; this adapter does the trivial
// field-by-field copy.
type authCacheAdapter struct {
	c *messagesummary.AuthCache
}

// Set implements proxy.AuthCache.
func (a authCacheAdapter) Set(sessionID string, creds proxy.AuthCredentials) {
	a.c.Set(sessionID, messagesummary.AuthCredentials{
		Authorization: creds.Authorization,
		APIKey:        creds.APIKey,
	})
}

// buildCodeIntelProvider returns the code-intelligence provider for the
// proxy + MCP layers. The NATIVE engine is the only implementation (the
// external codegraph dependency was decommissioned in Phase 4 — see
// docs/codeintel/migration-from-codegraph.md). The engine is returned
// even when its index is still empty: it self-heals as `observer start`
// indexes projects, flipping Available() true mid-run without a restart.
// Never returns nil — an unavailable provider degrades enrichment
// gracefully.
func buildCodeIntelProvider(cfg config.Config, database *sql.DB, logger *slog.Logger) codeintel.Provider {
	if !cfg.CodeIntel.Enabled || database == nil {
		return codeintel.Unavailable()
	}
	native := codeintel.NewEngine(store.New(database))
	if native.Available() {
		logger.Info("codeintel: native engine attached (structural enrichment, traversal, collapse)")
	} else {
		logger.Info("codeintel: native engine attached; index empty — enrichment activates as projects are indexed")
	}
	return native
}

// codeintelPipelineAdapter bridges codeintel.Provider to
// conversation.SymbolLookup. The conversation package owns the
// interface so it never imports the codeintel engine — the adapter
// here in cmd/observer is the connecting tissue. Pattern mirrors
// pipelineAdapter + authCacheAdapter above.
//
// The adapter does a one-line per-symbol field translation between
// codeintel.Symbol and conversation.CompressorSymbol. They carry the
// same logical data; the duplicate type lets each package own its
// own surface.
type codeintelPipelineAdapter struct {
	p codeintel.Provider
}

func (a codeintelPipelineAdapter) Available() bool {
	return a.p != nil && a.p.Available()
}

func (a codeintelPipelineAdapter) Stale(absPath string) bool {
	if a.p == nil {
		return false
	}
	return a.p.Stale(absPath)
}

func (a codeintelPipelineAdapter) SymbolsInFile(ctx context.Context, absPath string) ([]conversation.CompressorSymbol, error) {
	if a.p == nil {
		return nil, nil
	}
	syms, err := a.p.SymbolsInFile(ctx, absPath)
	if err != nil || len(syms) == 0 {
		return nil, err
	}
	out := make([]conversation.CompressorSymbol, 0, len(syms))
	for _, s := range syms {
		out = append(out, conversation.CompressorSymbol{
			Name:      s.Name,
			Kind:      s.Kind,
			StartLine: s.StartLine,
			EndLine:   s.EndLine,
			Exact:     s.Exact,
		})
	}
	return out, nil
}
