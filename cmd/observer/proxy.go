//go:build !sbo_omit_capture_proxy

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

	"github.com/marmutapp/superbased-observer/internal/codeintelapi"
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
	"github.com/marmutapp/superbased-observer/internal/proxyauth"
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

			pwire, err := buildProxy(ctx, configPath, "", port, bindAddr, relay)
			p, cleanup, addr, admissionHandle := pwire.Proxy, pwire.Cleanup, pwire.Addr, pwire.Admission
			if err != nil {
				return err
			}
			defer cleanup()
			// Lane P1: recorded route lanes resolve before the listener accepts.
			if lanePort, ok := proxyPortFromAddr(addr); ok {
				_ = installRouteLanesAtStart(p, lanePort, cmd.ErrOrStderr())
			}

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
					fmt.Fprintf(cmd.ErrOrStderr(), "policy resource: LKG/poller skipped - db open failed: %v\n", perr)
				}
			}

			// buildProxy opens the DB without the integrity probe (fast bind);
			// run the one-time quick_check + path-hash backfill in the
			// background so it never delays the listener on a large DB.
			go runStartupDBMaintenance(ctx, configPath)

			fmt.Fprintf(cmd.OutOrStdout(), "proxy listening on %s - ctrl-c to stop\n", addr)
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

// obsProxyBinder binds Plane A observability onto the proxy options (the
// admitter and egress reporter of the shared admission service, then the
// gateway rail). obs_wire_proxy.go sets it from its init when obs is
// compiled in; it stays nil in a build without obs and on the public tree,
// which is the stub's "no admission, no gateway rail" (lane MP-L1L, T-715).
// The registration keeps every proxy-typed obs adapter in that one private
// file, so obs_wire_stub.go never imports internal/proxy.
var obsProxyBinder func(ctx context.Context, cfg config.Config, db *sql.DB, h *obsAdmissionHandle, opts *proxy.Options, logger *slog.Logger)

// The core activityTurn (nodeactivity.go) must spell proxy.ActivityTurn: a
// duplicate map key fails to compile the moment the two differ.
var _ = map[bool]struct{}{false: {}, activityTurn == proxy.ActivityTurn: {}}

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
func buildProxy(ctx context.Context, configPath, recipeName string, portOverride int, bindAddr string, relay orgJudgeRelayFunc) (proxyWiring, error) {
	loadFresh := func() (config.Config, error) {
		cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
		if err != nil {
			return config.Config{}, err
		}
		if err := applyRecipeAliasToProfiles(&cfg, recipeName); err != nil {
			return config.Config{}, err
		}
		// Component gate (T-659 / T-661): every load, including the
		// compression-profile hot reload, sees inactive components off.
		return applyProxyComponentGate(cfg), nil
	}
	cfg, err := loadFresh()
	if err != nil {
		return proxyWiring{}, fmt.Errorf("load config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Observer.DBPath), 0o755); err != nil {
		return proxyWiring{}, fmt.Errorf("ensure db dir: %w", err)
	}
	// No integrity probe here: this is a long-running daemon open. The multi-GB
	// PRAGMA quick_check is deferred off the readiness path and run once via
	// db.RunStartupMaintenance after the listener binds (start.go / proxy.go
	// standalone). See db.Options.IntegrityCheck.
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		return proxyWiring{}, fmt.Errorf("open db %s: %w", cfg.Observer.DBPath, err)
	}
	s := store.New(database)

	port := cfg.Proxy.Port
	if portOverride > 0 {
		port = portOverride
	}
	if port <= 0 || port > 65535 {
		// D-516: the port only matters when the proxy listens. With
		// capture.proxy inactive (or compiled out) nothing binds it, so a bad
		// value never stops start; the wiring keeps the default.
		if !componentSnapshotFor(configPath).Active("capture.proxy") {
			port = config.Default().Proxy.Port
		} else {
			_ = database.Close()
			return proxyWiring{}, fmt.Errorf("proxy: port %d out of range", port)
		}
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
		// Node activity + soft-budget warning seams (nodeactivity.go,
		// 2026-10-02 budget-latency arc). Both are process-level
		// fan-outs the daemon's subsystems subscribe to after the proxy
		// is built, so the proxy never learns who listens.
		Activity:          processNodeActivity.Note,
		BudgetWarning:     processBudgetWarningHeader,
		AnthropicUpstream: cfg.Proxy.AnthropicUpstream,
		OpenAIUpstream:    cfg.Proxy.OpenAIUpstream,
		ChatGPTUpstream:   cfg.Proxy.ChatGPTUpstream,
		GeminiUpstream:    cfg.Proxy.GeminiUpstream,
		Upstreams:         cfg.Proxy.Upstreams,
		// The registry's built-in lanes under [proxy.agent_upstreams]
		// (proxylane.go), so a launcher's lane resolves on a fresh install.
		AgentUpstreams:   effectiveAgentUpstreams(cfg),
		AutoDefaultLane:  cfg.Proxy.AutoDefaultLane,
		ForceChatGPTHTTP: cfg.Proxy.ForceChatGPTHTTP,
		PrewarmTargets:   cfg.Proxy.PrewarmTargets,
		Sink:             s,
		ObserverLog:      s,
		SessionResolver:  resolver,
		CostComputer:     costEngineAdapter{e: acquireProcessCostEngine(ctx, cfg, database, logger)},
		Logger:           logger,
		CompressTypes:    cfg.Compression.Conversation.CompressTypes,
	}
	// Limit-snapshot capture for the Next-Message Cost & Limit Predictor
	// (migration 049). Default-on per [predict]; the store (*Store)
	// satisfies proxy.LimitSink via InsertLimitSnapshot. The cost-estimate
	// half needs no wiring (pure read-side at the dashboard/CLI seam).
	if cfg.Predict.Enabled {
		opts.LimitSink = s
	}
	// Proxy-side tool-version capture (T-784): the User-Agent build of a
	// session-bound request, written through the one tool-version seam.
	opts.ToolVersionSink = proxyToolVersionSink{s: s}
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
	if engine := buildCacheTrackEngine(cfg, s, logger); engine != nil {
		opts.CacheEngine = engine
		opts.CacheSink = s
	}
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
	// Agent Access P4 (mcprelay_wire.go): the ONE production binding of the
	// node MCP relay handle. Under [mcp_relay].enabled this stores the
	// process-wide processMCPRelay handle (which the tools.mcp_access
	// policy-resource publisher, the policy-state point reader and the
	// daemon's relay runtime goroutine in start.go all read), binds the
	// proxy tools[] seam on opts and the MCP-access lookup on the SAME
	// per-process Guard wireGuardProxy just composed (nil when guard is off:
	// the lookup is then simply not bound). ngov is nil here by design:
	// `observer start` builds the node-governance handle after buildProxy
	// and attaches it via processMCPRelay.Load().SetGovernance. With
	// [mcp_relay].enabled=false this is a no-op that binds nothing.
	bindMCPRelayProxy(wireMCPRelay(cfg, s, nil, lookupProcessGuard(cfg.Observer.DBPath), logger), &opts)
	// P1-10: construct the self-obs sink once for the proxy lifetime.
	// Handed to wireRouting for Decide sampling; Shutdown on cleanup.
	selfObsSink, selfObsCleanup, serr := buildSelfObsSink(cfg, logger)
	if serr != nil {
		logger.Warn("selfobs: sink build failed - using Nop", "err", serr)
		selfObsSink = emit.Nop()
		selfObsCleanup = func() {}
	}
	routingDemotions, routingStateHandle := wireRouting(ctx, cfg, s, &opts, logger, selfObsSink)

	// Pre-forward input-admission gate (admission spec §6.2). No-op unless
	// [observability.admission] is enabled; bound here so internal/proxy
	// never imports internal/obs (obs_wire.go owns the adapter). The returned
	// handle carries the ONE admission service (gap P0-7) so `observer start`
	// can share it with the dashboard editors; nil when admission is off.
	admissionHandle := wireAdmission(ctx, cfg, database, relay, logger, selfObsSink)

	// The admitter seams, then the gateway rail (docs/observability.md
	// "proxy turn (automatic)"): synthesizes a Plane-A trace for every
	// proxied LLM turn when [observability].proxy_turn_traces is on. No-op
	// (opts.ObsSink stays nil) unless [observability] itself is enabled.
	// The rail runs after the admitter so it can lift
	// opts.AdmissionUserHeader when admission left it unset. nil binder: a
	// build without obs (obs_wire_proxy.go not linked).
	if obsProxyBinder != nil {
		obsProxyBinder(ctx, cfg, database, admissionHandle, &opts, logger)
	}

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
	// Proxy client authentication (OSH-R-009, proxy_clientauth.go): the
	// token the proxy accepts and whether a plain request is refused, decided
	// once here. Both switches off (the default): no token, nothing read.
	var clientEnf proxyauth.Enforcement
	opts.ClientToken, clientEnf = wireProxyClientAuth(cfg, port, logger)
	opts.RequireClientAuth = clientEnf.Enforce

	p, err := proxy.New(opts)
	if err != nil {
		selfObsCleanup()
		_ = database.Close()
		return proxyWiring{}, err
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
	return proxyWiring{
		Proxy:            p,
		Cleanup:          cleanup,
		Addr:             addr,
		ProfilesReload:   profilesReload,
		RoutingDemotions: routingDemotions,
		Admission:        admissionHandle,
		Routing:          routingStateHandle,
	}, nil
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

// pipelineAdapter bridges conversation.Pipeline (no context parameter —
// the pipeline is a pure function by design) to proxy.Compressor which
// is context-aware. Lives in cmd/observer so the conversation package
// stays free of the proxy interface.
type pipelineAdapter struct {
	p *conversation.Pipeline
}

// costEngineAdapter bridges (*cost.Engine).ComputeAt to proxy.CostComputer
// — same pattern as pipelineAdapter for the conversation pipeline. It
// passes CostTokens.At through so time-of-day-dependent rates (e.g.
// peak/off-peak) resolve against the turn's own timestamp rather than
// wall-clock-now. Lives here so the proxy contract stays free of an
// intelligence-pkg import cycle.
type costEngineAdapter struct {
	e *cost.Engine
}

// Compute implements proxy.CostComputer.
func (a costEngineAdapter) Compute(model string, t proxy.CostTokens) (float64, bool) {
	if a.e == nil {
		return 0, false
	}
	// A tier sold as its own SKU (OpenAI Ultrafast) is priced under that
	// SKU when the table has it; otherwise the model's own rate applies and
	// the engine records a PricingWarnings entry (TierUnpriced).
	model, _ = a.e.ResolveServiceTier(model, t.ServiceTier)
	return a.e.ComputeAt(model, cost.TokenBundle{
		Input:           t.Input,
		Output:          t.Output,
		CacheRead:       t.CacheRead,
		CacheCreation:   t.CacheCreation,
		CacheCreation1h: t.CacheCreation1h,
		Fast:            t.Fast,
	}, t.At)
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

// codeintelPipelineAdapter bridges codeintelapi.Provider to
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
	p codeintelapi.Provider
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
