package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/marmutapp/superbased-observer/internal/clientwire"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/hook"
	browseringest "github.com/marmutapp/superbased-observer/internal/ingest/browser"
	otlpingest "github.com/marmutapp/superbased-observer/internal/ingest/otlp"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/intelligence/advisor"
	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/mcpregister"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/shutdown"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/surfaceenrich"
)

// newStartCmd implements `observer start` — the full-mode entrypoint that
// runs the proxy + watcher + dashboard in one process. Each component
// runs in its own goroutine with a shared context; any one's error
// cancels the others.
//
// What `start` auto-wires on launch:
//   - HOOKS for every detected AI tool, idempotently — see
//     [autoRegisterHooks]. Gated by `[observer.hooks] auto_register`,
//     default true. This is the on-launch self-heal path; users no
//     longer need to remember `observer init` for hook capture.
//
// What `start` deliberately does NOT touch:
//   - MCP REGISTRATION. The MCP stdio server cannot run alongside the
//     other goroutines (it owns stdin/stdout), and each AI client is
//     expected to spawn its own `observer serve` subprocess. MCP
//     registration writes per-client config (`~/.claude.json`,
//     `~/.cursor/mcp.json`, `~/.codex/config.toml`) that we treat as
//     explicit user opt-in — `observer init` (or `init --skip-hooks`
//     for MCP-only) is the dedicated path.
//   - PER-TOOL PROXY-ROUTING config (e.g. codex `base_url`). That stays
//     in `observer init` behind `--skip-proxy-route`. The proxy itself
//     still binds on `start`; the AI client routes into it via env
//     vars (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`) or per-tool config.
//
// So a vanilla `observer start` produces an install with: live capture
// (watcher + hooks) + proxy listener + dashboard, but no MCP overhead
// in any AI client unless the user separately ran `observer init`.
func newStartCmd() *cobra.Command {
	var (
		configPath  string
		recipeName  string
		port        int
		bindAddr    string
		dashAddr    string
		noDashboard bool
		noOpen      bool
	)
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start proxy + watcher + dashboard in a single process",
		Long: "Runs the API reverse proxy, the session-log watcher, and the\n" +
			"local analytics dashboard concurrently. Use this when you want\n" +
			"one foreground process to capture everything and serve the\n" +
			"http://127.0.0.1:8081/ dashboard at the same time.\n\n" +
			"Pass --no-dashboard to skip the dashboard goroutine (useful when\n" +
			"you want a separate `observer dashboard` process bound to a\n" +
			"different address).\n\n" +
			"MCP stdio is registered separately via `observer init` - each\n" +
			"AI tool will launch its own `observer serve` subprocess.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			// D-MU2: until the stop watchdog below is armed, a stop request
			// still ends the process within a bound.
			startupHandoff := startupStopGuard(ctx, startupStopBound, cmd.ErrOrStderr(), daemonHardExit)
			defer startupHandoff()

			// Record the daemon's own --config so every dashboard-launched
			// child (`observer <tool> --config <path>`) resolves the SAME
			// proxy port and DB the daemon runs on (Q1 probe P1, 2026-09-03:
			// children of a --config daemon routed at the default 8820 and
			// opened the default ~/.observer DB).
			setDaemonConfigPath(configPath)

			// Config schema auto-migration (daemon-only write owner):
			// rewrite deprecated keys (renamed or removed config keys, see
			// internal/config/migrate) in place before anything Loads the file, so
			// this run and every short-lived subprocess afterwards see
			// the current schema and stop emitting deprecation warnings.
			// Runs here — NOT in config.Load — because Load fires in many
			// concurrent subprocesses and only the daemon should write.
			// Fail-open: a migration error never blocks startup.
			if migPath, perr := config.ResolveGlobalPath(configPath); perr == nil {
				if mres, merr := config.MigrateFile(migPath); merr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "WARN config auto-migrate failed for %s: %v (continuing)\n", migPath, merr)
				} else if mres.Skipped {
					fmt.Fprintf(cmd.ErrOrStderr(), "WARN config auto-migrate skipped %s: %s\n", migPath, mres.SkipReason)
				} else if mres.Migrated {
					fmt.Fprintf(cmd.ErrOrStderr(), "migrated config %s (schema %d → %d, %d change(s)); backup at %s.bak\n",
						migPath, mres.FromVersion, mres.ToVersion, len(mres.Changes), migPath)
				}
			}

			// Review C156-04 (T-354): a managed node that enrolled before a
			// policy family was mapped to its grant gets that family added
			// once, here, before the config is loaded (the policy lists are
			// read once at start). Fail-open; see org_managed_families.go.
			reconcileManagedPolicyAtStart(cmd.Context(), configPath, cmd.ErrOrStderr())

			// Write a per-PID lockfile in the DB dir so concurrent
			// daemons can be detected by `observer doctor`. Two
			// observers writing the same SQLite file race on cursor
			// state and have silently corrupted backfill in the past.
			// LoadGovernance rather than Load: the daemon must retain WHICH
			// sidecar generation its own process was built from, because pinned
			// settings are restart-bound for its own subsystems (this function
			// reads config once). That retained identity is what makes
			// pending_restart reachable instead of the node overclaiming
			// `effective` the instant it writes a new pinned map (§1.6 /
			// review M3).
			cfgForLock, govOutcome, lockErr := config.LoadGovernance(config.LoadOptions{GlobalPath: configPath})
			// Component gate (modular packaging P1, components_gate.go): the
			// effective component set is resolved ONCE here; every goroutine
			// and builder below consults it. The inert overlay turns off the
			// start-time switches of inactive components in this in-memory
			// copy only. With no [components] block every compiled component
			// is active and both are no-ops.
			comps := componentstate.Legacy()
			if lockErr == nil {
				// Governed (lane MP-GOV, ledger MODPKG-7): on an org-managed
				// node the local block may not narrow the node; its distro and
				// remove entries are ignored and reportComponentIssues warns.
				comps = componentSnapshotForConfig(cfgForLock)
				cfgForLock = applyInertOverlay(cfgForLock, comps)
			}
			reportComponentIssues(cmd.ErrOrStderr(), comps)
			// D-MU1: adapter root discovery (aider's home walk) runs in the
			// background from here on, before anything reads WatchPaths, so
			// no listener waits on a walk that a macOS privacy prompt can
			// block indefinitely.
			if lockErr == nil {
				configureAdapterDiscovery(ctx, cfgForLock, comps.AdapterActive)
			}
			// Before the first guard posture is signed: the security
			// module's state rides in it (security_core.go).
			setDaemonSecurityState(configPath, comps, slog.Default())
			// The security.scanning floors' facts provider (lane SEC-E).
			bindSecurityScanning(configPath, comps)
			// Ledger MODPKG-13 (T-679): with capture.proxy inactive no proxy
			// binds, so a route Observer left in another tool's config fails
			// its sessions; name it and its teardown.
			warnProxyRouteWithoutProxyFor(cmd.Context(), cmd.ErrOrStderr(), comps, configPath)

			// Bounded stop (T-553): every daemon goroutine runs through
			// stopTracker (namedGroup below), and stopWatchdog, armed the
			// moment a stop begins, names what is still running part-way
			// through daemonShutdownBound and forces the exit at the bound,
			// with every goroutine's stack written beside the DB. On
			// 2026-10-06 daemons released their ports on SIGTERM and then ran
			// on for minutes with the DB open (one needed SIGKILL), and a
			// second SIGTERM did nothing because the signal context kept
			// swallowing it. Disarm is deferred here, ahead of every later
			// defer, so it runs after the DB close and the lock removal.
			stopTracker := shutdown.NewTracker()
			stopDBPath := ""
			if lockErr == nil {
				stopDBPath = cfgForLock.Observer.DBPath
			}
			stopWatchdog := daemonShutdownWatchdog(stopTracker, cmd.ErrOrStderr(), shutdownStackDir(stopDBPath))
			defer stopWatchdog.Disarm()
			startupHandoff()
			go func() {
				<-ctx.Done()
				// Release the signal capture: from here a second SIGTERM or
				// ctrl-c takes the default action (terminate) instead of
				// being absorbed by a context that is already cancelled.
				cancel()
				stopTracker.AdvanceStage(shutdown.StageRunning, shutdown.StageComponents)
				stopWatchdog.Arm()
			}()

			// T3.3: WARN once, right at startup, if this daemon is running
			// on a replaced/deleted binary (e.g. a build/release overwrote
			// bin/observer while this process kept its original inode open)
			// — that silently runs old code no matter what's on disk now.
			if msg := staleBinaryWarning(); msg != "" {
				fmt.Fprint(cmd.ErrOrStderr(), msg)
			}

			if lockErr == nil {
				binary, _ := absoluteBinaryPath()
				lockPath, lerr := diag.WriteLock(filepath.Dir(cfgForLock.Observer.DBPath), diag.LockInfo{
					PID:        os.Getpid(),
					StartedAt:  time.Now().UTC(),
					DBPath:     cfgForLock.Observer.DBPath,
					BinaryPath: binary,
					Version:    version,
				})
				if lerr == nil {
					defer func() { _ = diag.RemoveLock(lockPath) }()
				}

				// Cross-env split guardrail: warn if a foreign-OS
				// observer.db exists that this daemon won't read (a second
				// daemon, or rows stranded by a hook that wrote a sibling DB
				// instead of running in this daemon's context). Cross-OS hook
				// capture is handled by registering the AI tool's hooks as a
				// wsl.exe bridge so they execute in the daemon's context; this
				// guardrail surfaces an otherwise-silent split (e.g. a stale
				// native-binary registration writing the wrong DB).
				// Only when the watched adapters include a tool whose hooks
				// register across OSes (live run 2, finding N4: with
				// enabled_adapters = ["poolside"] the start still looked at
				// the Windows mount's observer.db).
				if crossEnvSiblingCheckApplies(cfgForLock.Observer.Watch.EnabledAdapters, config.Default().Observer.Watch.EnabledAdapters, cfgForLock.Observer.Hooks.AutoRegister) {
					for _, sib := range diag.DetectCrossEnvSiblingDBs(cfgForLock.Observer.DBPath, crossmount.AllHomes()) {
						fmt.Fprintf(cmd.ErrOrStderr(),
							"WARN cross-env observer.db at %s (%s): this daemon reads %s. "+
								"Rows already in that sibling DB won't appear here - re-register that tool's hooks "+
								"via `observer init` so they run in this daemon's context.\n",
							sib.Path, sib.Origin, cfgForLock.Observer.DBPath)
					}
				}

				// DI-07: [terminal.launch].allowed_tools and
				// [observer.watch].enabled_adapters are two independent
				// allow-lists (CLAUDE.md #4 — each BY DESIGN; the missing
				// cross-check between them was the bug). A tool that is
				// launchable from the dashboard but not watched will run and
				// produce nothing to look at, silently. Named ONLY when the
				// operator has an explicit (non-nil) enabled_adapters list —
				// the default (nil) watches everything, so there is nothing
				// to warn about. `observer doctor` carries the matching note
				// (diag.checkAdapters) so the two surfaces never disagree.
				if warn := allowedNotWatchedWarning(
					diag.AllowedToolsNotWatched(cfgForLock),
					len(cfgForLock.Observer.Watch.EnabledAdapters),
					len(config.Default().Observer.Watch.EnabledAdapters),
				); warn != "" {
					fmt.Fprint(cmd.ErrOrStderr(), warn)
				}
			}

			// Auto-register hooks for every detected tool, idempotently.
			// Already-registered entries are no-ops; stale-args entries
			// get refreshed silently. Conflicts with non-observer
			// entries log a warning and skip — never overwrite
			// user-authored configuration. Set
			// [observer.hooks] auto_register = false to opt out.
			//
			// Defaults to true even when config load failed (lockErr !=
			// nil) because the most common reason for a fresh install
			// having no working config is "the user just installed and
			// hasn't run init yet" — exactly the case we want to
			// auto-heal.
			autoRegister := true
			// B4 (phase-3a review): default true mirrors autoRegister's
			// own fail-open rationale above — a config that failed to
			// load is most often "fresh install, no config.toml yet",
			// and [guard.prompt] itself defaults to Enabled+HookLane
			// true, so "assume the feature is on" is the honest default
			// here too, not a special case.
			promptLaneEnabled := true
			if lockErr == nil {
				autoRegister = cfgForLock.Observer.Hooks.AutoRegister
				promptLaneEnabled = cfgForLock.Guard.Prompt.Enabled && cfgForLock.Guard.Prompt.HookLane
			}
			if autoRegister {
				autoRegisterHooks(cmd.OutOrStdout(), cmd.ErrOrStderr(), configPath, promptLaneEnabled)
			}
			// Command wrapping (backlog item 7): re-point already-applied
			// shims at this binary when the one they name is gone. Inert unless
			// [shell_wrap].enabled; never creates a shim; fail-soft. Skipped
			// when the shell-wrap component is inactive.
			if comps.Active("integration.shell-wrap") {
				refreshShellWrapShims(cmdContext(cmd), cmd.OutOrStdout(), cmd.ErrOrStderr(), configPath)
			}

			// Org push client (Teams) — constructed only when
			// orgClientShouldStart says so, so a solo-local install never
			// probes the OS keychain or opens an org code path. Shared with
			// the dashboard (its enrolment endpoints) and driven by the push
			// loop below. A construction failure is WARN-only: org mode must
			// never block the daemon (P1).
			//
			// orgClientShouldStart (see its doc comment for the full
			// four-state truth table) is Enabled && (a config org_server_url
			// OR a persisted org_enrolment DB row) — NOT the narrower
			// Enabled && OrgServerURL != "" this used to gate on. That
			// narrower gate (BLOCK-1, code review) silently killed every org
			// loop — push, guard-policy poll, announcement/routing-policy
			// fetch, grant renewal — on a node that was genuinely enrolled
			// (a real DB row, a real bearer credential) whenever its config
			// happened to carry a blank org_server_url, a shape
			// ensureOrgClientBlock's header-idempotent write can produce and
			// that re-enrolling does not repair. The only case that should
			// skip construction is a node with NEITHER a config URL NOR a
			// persisted row — genuinely never enrolled — which gets the one
			// startup notice below instead of every loop silently going dark.
			//
			// Built BEFORE buildProxy (not after, as in the original
			// ordering) because the C1 judge relay
			// (docs/plans/c1-judge-relay-spec-2026-08-15.md §3) needs a
			// plain orgJudgeRelayFunc threaded INTO buildProxy so the
			// admission/eval judge wiring inside it can use the relay. A nil
			// orgClient (org push disabled, or construction failed) yields a
			// nil relay func — orgJudgeRelayFuncFor is nil-safe — which the
			// judge build treats as "no relay available" (soft fail).
			var orgClient *orgclient.Client
			var orgStore *store.Store
			// orgIntelLive is the live [intelligence].org_enrichment reader the
			// org-plane rail gate and the consent report share (nil without an
			// org client; the dashboard's OrgIntel manager invalidates it).
			var orgIntelLive *liveOrgEnrichment
			if lockErr == nil && comps.Active("org.client") && orgClientShouldStart(cfgForLock.OrgClient, func() bool {
				return hasPersistedEnrolment(ctx, cfgForLock.Observer.DBPath)
			}) {
				bundle, oerr := buildOrgBundle(ctx, configPath)
				if oerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "org push disabled: client init failed: %v\n", oerr)
				} else {
					orgClient, orgStore = bundle.client, bundle.store
					defer bundle.cleanup()
					persistMachineProof(orgClient, orgStore)  // WINNODE item 4
					bindDaemonCredential(orgClient, orgStore) // WINNODE2 item 1b
					// The security pillar wire (security plan 7.4): the org push
					// composes security rows only while the security module is
					// active and the share level allows (security_orgpush.go).
					// Bound here, where the push loop is built, so a headless
					// daemon sends them too (lane SEC-E2 audit finding 3).
					bindSecurityOrgProviders(orgStore, comps.ModuleActive("security"))
					// The org's baseline approvals from the security pull
					// (lane LEFT-SHARED, security_baseline_org.go).
					bindSecurityBaselineOrg(orgStore)
				}
			} else if lockErr == nil && cfgForLock.OrgClient.Enabled && comps.Active("org.client") {
				// Reachable only when Enabled but orgClientShouldStart said
				// no — i.e. no config URL AND no persisted enrolment row.
				// Same stream (stderr) as the sibling "client init failed"
				// notice above (NIT-1: they used to disagree, one on stdout
				// and one on stderr).
				fmt.Fprintln(cmd.ErrOrStderr(),
					"org push disabled: [org_client].enabled = true but org_server_url is empty and no enrolment record was found (not enrolled)")
			}
			// The hook-path budget admission has one publisher, the org
			// budget service, built only with an org client below. Without
			// one, a file left by an earlier enrolled run would deny every
			// hook until its period ended (B-625: forever); clear it once
			// (D-359, review P3-05).
			if lockErr == nil && orgClient == nil {
				if cerr := clearBudgetAdmission(cfgForLock.Observer.DBPath); cerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "budget admission: could not remove a leftover hook admission file: %v\n", cerr)
				}
			}
			orgJudgeRelay := orgJudgeRelayFuncFor(orgClient)

			pwire, err := buildProxy(ctx, configPath, recipeName, port, bindAddr, orgJudgeRelay)
			p, pCleanup, addr, profilesReload, routingDemotions, admissionHandle, routingHandle := pwire.Proxy, pwire.Cleanup, pwire.Addr, pwire.ProfilesReload, pwire.RoutingDemotions, pwire.Admission, pwire.Routing
			if err != nil {
				return err
			}
			defer pCleanup()

			// Lane P1: put every recorded node-local route lane into the proxy
			// BEFORE its listener accepts, so a third-party-provider lane route
			// written by an earlier run never meets a refused lane (HTTP 502).
			var routeLanes *routeLaneInstaller
			if lanePort, ok := proxyPortFromAddr(addr); ok {
				routeLanes = installRouteLanesAtStart(p, lanePort, cmd.ErrOrStderr())
			}

			// ONE daemon-lifetime gateway.providers install seam, shared by
			// the LKG loader, the steady-state poller AND the P0-6 reporter.
			// It must be a single instance: the handle is the only holder of
			// the accepted org lane table's identity (version + signed
			// BodyHash), so a second instance would report a different — and
			// wrong — effective state than the one that installed the table
			// (docs/plans/policy-state-v2-gateway-providers-spec-2026-08-15.md
			// §2.2). nil when config never loaded, in which case orgClient is
			// nil too and no call site is reached.
			var gw *gatewayProvidersHandle
			if lockErr == nil {
				bootstrapUpstreams, bootstrapAutoLane := cfgForLock.Proxy.Upstreams, cfgForLock.Proxy.AutoDefaultLane
				bootstrapOrgRoute := cfgForLock.Proxy.OrgRoute
				gw = newGatewayProvidersHandle(
					p.SetLaneTable,
					func() {
						// A withdrawn/rejected org policy restores the node's
						// own config.toml routing — both the [proxy] lanes AND
						// the [proxy.org_route] bootstrap mode — never an empty
						// table or a stranded org mode (fail-open to the
						// operator's own configured routing, one atomic swap).
						_ = p.SetRoutingSnapshotWithFallback(bootstrapUpstreams, bootstrapAutoLane,
							bootstrapOrgRoute.Mode, bootstrapOrgRoute.Primary, bootstrapOrgRoute.Fallbacks,
							bootstrapOrgRoute.TerminalPolicy, bootstrapOrgRoute.DirectFallbackCustodyAck)
					},
					p.LaneTable,
				)
				// Bind the atomic lanes+org-route+fallback setter so a
				// gateway.providers MODE body installs lanes, mode, and the
				// fallback terminal rung in one generation (Sol S7 / Luna L16).
				gw.SetRouteApply(p.SetRoutingSnapshotWithFallback)
			}

			// ONE daemon-lifetime node.governance install seam (admin-
			// controlled Plane B, docs/plans/admin-controlled-plane-b-spec-2026-08-15.md
			// §3), for the same one-owner reason as gw above: it holds the
			// accepted resource's identity AND is the single place the
			// enrolment GRANT is intersected with it, so the dashboard's
			// route guard, GET /api/governance and the P0-6 reporter can
			// never disagree about what this node actually applies.
			//
			// Its store-backed identity loader is attached below, where the
			// daemon's long-lived DB handle exists. Until then (and forever
			// on a build with no DB) the handle resolves to the dormant
			// posture, which is exactly an ungranted node.
			ngov := newNodeGovernanceHandle(nil, slog.Default())
			// Agent Access P4 (mcprelay_wire.go): the relay handle was bound
			// by buildProxy before ngov existed; attach the governance handle
			// now so the managed-vs-individual rule reads the live grant.
			// nil handle ([mcp_relay].enabled=false) = no-op.
			processMCPRelay.Load().SetGovernance(ngov)
			// ONE daemon-lifetime node.features install seam (org-parity
			// W5.1): holds the accepted per-feature governance body, read by
			// the dashboard's terminal/remote/routing-apply/patterns-write
			// enforcement seams via FeatureGate/TerminalFeatureGate below.
			// nil-safe (a nil *nodeFeaturesHandle answers "allowed" from
			// every method — see nodeFeaturesHandle.Allowed), so it is safe
			// to construct unconditionally even when lockErr != nil.
			nf := newNodeFeaturesHandle()
			processNodeFeatures.Store(nf)
			if lockErr == nil {
				// P6 item 5: the daemon is the ONE writer of the node.features
				// tools.disallow LKG sidecar (CLAUDE.md #4), mirroring the
				// governance sidecar below. Binding the writer makes every
				// node.features apply/inert/clear refresh the on-disk disallow
				// list that bare CLI launchers and `observer adapters` read.
				nf.SetSidecarWriter(makeFeaturesSidecarWriter(cfgForLock, version, slog.Default()))
				// The daemon is the ONE writer of the governance sidecar
				// (CLAUDE.md #4). Every other process — hooks, `observer
				// serve`, every subcommand — READS it through config.Load.
				// There is deliberately no second path in which the daemon
				// injects its in-memory posture into its own config.Load:
				// that would recreate the two-owner split in a subtler form,
				// with the daemon converging a cycle earlier than everything
				// else and reporting `effective` while the hooks were still
				// one generation behind.
				ngov.SetSidecar(
					config.ResolveGovernanceSidecarPath(cfgForLock, ""),
					version,
					startupSidecarFrom(govOutcome),
				)
				// T-845: the posture loop records the verified copy of what the
				// handle writes in the MAC'd org lock and repairs the files from it.
				setProcessGovernanceCopy(ngov.VerifiedCopy())
				// Track C item 3: report the EFFECTIVE value of every
				// reportable pinnable key. cfgForLock is the config this
				// daemon process is actually running — including whatever
				// the governance sidecar applied at load — which is
				// precisely the fact the organization cannot otherwise
				// learn from an ack that only says "accepted".
				ngov.SetEffectivePinReader(func() map[string]string {
					return effectivePinValues(cfgForLock)
				})
			}
			// The renewal latch is per-daemon-run and in-memory (§4.3): a
			// persisted deny latch would be a second, node-local revocation
			// clock an admin cannot clear.
			renewalTracker := &orgclient.RenewalTracker{}
			// Declared out here so the startup PRIME below can reach it: the
			// wire is built with the org client, but its first posture may
			// only be published once the governance identity loader exists
			// (finding H3c).
			var budgetWire *orgBudgetHandle
			if orgClient != nil {
				orgClient.SetRenewalSink(renewalTracker.Observe)
				// Component posture on the org wire (plan 6.4, T-682).
				orgClient.SetComponentPostureProvider(componentPostureProvider(configPath, cfgForLock))
				// Admin and developer messaging (T-854): the developer's
				// [messages] choices, read at use time, and the opt-in
				// desktop notification for a new admin message.
				wireOrgMessages(orgClient, configPath)
				// Follow a node.components policy change live: teardown of
				// newly blocked components and the scheduled purge (T-682).
				go newComponentPolicyFollower(configPath, orgStore, comps, slog.Default()).run(ctx)
				if lockErr == nil {
					orgClient.SetGovernanceSidecarPath(config.ResolveGovernanceSidecarPath(cfgForLock, ""))
					// P6 item 5: Unenroll also deletes the node.features
					// tools.disallow LKG sidecar so a launcher after unenrol
					// reads no stale disallow list.
					orgClient.SetFeaturesSidecarPath(config.ResolveFeaturesSidecarPath(cfgForLock, ""))
					// Share directives are LOWERING-ONLY and HOT (§2.4): the
					// provider resolves cfg.Share ∧ Effective.Share on every
					// push, reading the same handle the dashboard guard reads.
					orgClient.SetShareProvider(governanceShareProvider(cfgForLock.OrgClient, ngov))
					// The org's push-interval CEILING (signed node-governance
					// pin org_client.push_interval_seconds, 2026-10-02
					// budget-latency arc) is HOT: the push loop re-reads it
					// every cycle and composes it with the node's OWN
					// pre-governance interval, so lowering (or releasing) it
					// converges without a restart.
					orgClient.SetPushIntervalGovernance(
						govOutcome.HotLocalInt("org_client.push_interval_seconds", int64(cfgForLock.OrgClient.PushIntervalSeconds)),
						func() int64 {
							return config.GovernancePinnedPushInterval(ngov.Effective(context.Background()).Pinned)
						},
					)
					// Arc 4 P6b managed-integrity probe (plan §9): the collector
					// gathers this host's coarse tamper-evidence each push cycle.
					// The client consults it only for a managed node, so this is
					// inert on the individual plane.
					dbPath := cfgForLock.Observer.DBPath
					if home, herr := os.UserHomeDir(); herr == nil {
						binaryPath, _ := absoluteBinaryPath()
						orgClient.SetIntegrityCollector(func() orgcontract.ManagedIntegrityReport {
							// Track C item 2 + lane P1 + T-900: route drift
							// follows the same route posture route maintenance
							// acts on (govern.Effective.RoutePosture through
							// routeDriftPolicy): maintained routes are drift
							// when they do not reach this proxy, released
							// routes never are, and with no posture only an
							// organization route left in place can drift. T-901:
							// "reaches this proxy" compares the route's port
							// with this daemon's own listener. A tool never
							// installed, or one Observer cannot route here and
							// never routed, never counts (proxyroute.DriftedTools).
							// Resolved LIVE from the governance handle on every
							// cycle (the SetManagedEnforce precedent), so a
							// changed pin or a revoked authority changes the
							// reading at the next report, not at the next restart.
							// T-915: the component selection is the one route
							// maintenance acts on (routeSelection), resolved
							// from the same config each cycle, so an installed
							// tool the policy did not select reads as "not
							// selected by policy" and a node whose route writer
							// is off reads as "routing switched off by
							// policy", never as drift.
							listenPort, _ := proxyPortFromAddr(addr)
							routeDrift := routeDriftPolicy(ngov.Effective(ctx).RoutePosture(), listenPort, routeSelection(componentSnapshotFor(configPath)))
							// T-847: the hook targets this node's own
							// auto-registration owns, each with a dry run, so
							// a missing or weakened hook (or a deleted
							// registry) is a located risk.
							// T-874: compare the registry's binary_path with
							// the registration command (what the hooks were
							// written with and what `observer doctor`
							// compares), plus the real binary, never with the
							// real binary alone.
							regCommand := binaryPath
							if binaryPath != "" {
								regCommand = registrationCommand(binaryPath)
							}
							rep := collectManagedIntegritySignals(dbPath, home, regCommand, routeDrift, hookIntegrityInputs{
								Expected:   probeExpectedHooks(configPath, cfgForLock.Guard.Prompt.Enabled && cfgForLock.Guard.Prompt.HookLane),
								Tracker:    hookRepairTracker,
								Now:        time.Now(),
								RealBinary: binaryPath,
							})
							// Adapter config P7: an enforced org AI tool
							// setting that no longer holds is a closed
							// capture-risk label (detail on the envelope).
							agentConfigDriftRisk(ctx, orgStore, &rep)
							// OBS-6: the routable surfaces this node ran
							// sessions on that never reached its proxy, judged
							// like the doctor's route.observed check. With no
							// store the observation stays "not reported".
							if orgStore != nil {
								addRouteObservation(ctx, orgStore, func(since time.Time) diag.RelayJournal {
									return diag.RelayBypassSince("", since)
								}, time.Now(), nil, &rep)
								// DEC-7: the tools whose hooks a settings
								// layer switches off, and the config-layer
								// findings that weaken capture or routing,
								// read like the doctor's hooks.disabled and
								// config.layers rows. With no store the
								// reading stays "not reported".
								addConfigLayers(ctx, storeConfigLayerSource(orgStore, home), &rep)
							}
							// OBS-7: tools whose captured sessions show their
							// registered hooks never firing (hooks.liveness).
							addHookLiveness(ctx, storeHookSilentSource(orgStore), time.Now(), &rep)
							// CLI-1b: command wrapping the organization keeps
							// on is not applied.
							addShellWrapPosture(ctx, ngov.Effective(ctx).ShellWrapPosture(), configPath, &rep)
							// S-15 (D17): a cached vendor org policy blocks
							// Observer's MCP server or pins a tool's route.
							addVendorPolicyRisks(home, os.Getenv, &rep)
							return rep
						})
					}
					// Org AI TOOL POLICY (adapter config P6/P7). ONE gate,
					// resolved LIVE from the governance grant: a MANAGED
					// enrolment with a live grant fetches the signed policy,
					// applies it to the vendor files and reports what it did.
					// An individual node never calls the rail, never applies
					// and never reports (a released agent ignores all of it).
					agentConfigGate := func(c context.Context) bool { return ngov.Effective(c).ManagedDefaultsApply() }
					orgStore.SetAgentConfigStateGate(agentConfigGate)
					orgClient.SetAgentConfigPolicyGate(agentConfigGate)
					agentConfigApplier := newAgentConfigOrgApplier(orgStore, cfgForLock, agentConfigGate, slog.Default())
					orgClient.SetAgentConfigPolicySink(agentConfigApplier.Kick)
					agentConfigApplier.Start(ctx)
					// Org BUDGET rail (org-budget plan §3.3c/§3.3d). The
					// boundary composes the org's per-caller caps onto the
					// node's own [guard.budget] numbers and applies the result
					// to the LIVE guard, so a cap lands without a restart. The
					// guard instance is the SHARED per-(process, db) one
					// buildProxy already composed — never a second guard — and
					// a nil one (guard off / construction failed) leaves the
					// handle inert but still reporting an honest "off" posture.
					//
					// authoritative is resolved LIVE from the governance grant,
					// exactly like routingHandle.SetManagedEnforce above, so a
					// revoked enforce.budget stops being authoritative on the
					// next cycle rather than at the next restart. It is false on
					// every individual/BYO node by construction (the token is
					// stripped there).
					budgetWire = newOrgBudgetHandle(
						lookupProcessGuard(dbPath),
						cfgForLock.Guard.Budget,
						func() bool { return ngov.Effective(context.Background()).GrantsBudgetEnforcement() },
						orgStore,
						slog.Default(),
					)
					// fail_closed is resolved LIVE too (REVIEW-4 P4-04): the
					// node's own value, or the CURRENT governance pin, so a
					// pin from an organization this node has left does not
					// arm B-625 for the next one until a restart.
					budgetWire.failClosed = liveBudgetFailClosed(
						ownBudgetFailClosed(configPath, cfgForLock, govOutcome.Applied),
						func() map[string]any {
							eff := ngov.Effective(context.Background())
							if !eff.Active {
								return nil
							}
							return eff.Pinned
						})
					// The budget-WARNING service (budgetwarn_wire.go): the
					// org's warn ladder, once per period, onto every
					// developer surface. It reads the SAME accounting the
					// guard enforces with, re-measures on every committed
					// proxied turn and once a minute otherwise.
					budgetWire.warn = newBudgetWarnService(dbPath,
						processGuardBudgetSpend(dbPath),
						budgetWarnDesktopNotifier(cfgForLock.Guard.Alerts.Desktop),
						slog.Default())
					// Per-tool / per-model caps are warned too (Sol A5-04),
					// measured through the guard's own accounting lookup.
					budgetWire.warn.SetSubjectSpend(processBudgetSubjectSpend(dbPath))
					// The hook path's budget stop (T-519): the managed
					// decision the process controller takes, published for
					// every hook-capable tool's next prompt or tool call.
					budgetWire.warn.SetAdmission(processHookBudgetAdmission(dbPath))
					// The developer cost display (org display policy):
					// the warning messages and the guard's budget verdict
					// text render in it. A newly verified document
					// re-renders at once instead of at the idle tick.
					costDisplay := newCostDisplayResolver(orgStore)
					budgetWire.warn.SetDisplay(costDisplay.Mode)
					if g := lookupProcessGuard(dbPath); g != nil {
						g.SetCostDisplay(costDisplay.Mode)
					}
					orgClient.SetDisplayPolicySink(func() {
						costDisplay.Invalidate()
						budgetWire.warn.Kick()
					})
					processBudgetWarn.Store(budgetWire.warn)
					processNodeActivity.Subscribe(func(kind string) {
						if isTurnActivity(kind) {
							budgetWire.warn.Kick()
						}
					})
					orgClient.SetBudgetSink(budgetWire.onBudgetFetch)
					orgClient.SetBudgetPostureProvider(nodeInterventionPostureProvider(ctx, orgStore, dbPath,
						nodeBudgetPricingPostureProvider(dbPath, budgetWire.postureProvider())))
					// Document FRESHNESS (finding M3). The window lives in
					// [guard.budget] beside the numbers it protects, and it is
					// pushed onto the client rather than read there: the org
					// client's own config section is [org_client], and one knob
					// answering to two sections is the drift this avoids.
					orgClient.SetBudgetMaxDocumentAge(
						budgetDocumentMaxAge(cfgForLock.Guard.Budget, slog.Default()),
					)
					// The FIRST posture is published by budgetWire.Prime()
					// below, not here: the capability it reports is resolved
					// through the governance IDENTITY LOADER, which is
					// installed further down this function. Publishing now
					// would report every managed node as un-required and
					// un-armed for the whole startup window (finding H3c).

					// Org PRICING rail (pricing arc §3.3). It is wired
					// immediately after the budget rail and gated on the SAME
					// switch (ruling R2): a cap and the rate it is measured in
					// are one governance fact, and a node that applied one
					// without the other would enforce this quarter's cap
					// against last quarter's prices.
					//
					// The engine handed over is the SHARED per-(process, db)
					// one buildProxy already composed — never a second engine
					// — so the rates the proxy stamps onto api_turns.cost_usd
					// and the rates the org-push pricer stamps onto
					// token_usage.estimated_cost_usd are the same rates, which
					// matters because the node's guard reads the MAX of the
					// two.
					pricingWire := newOrgPricingHandle(
						lookupProcessCostEngine(dbPath), cfgForLock, slog.Default(), orgStore,
					)
					orgClient.SetPricingAuthoritative(func() bool {
						return ngov.Effective(context.Background()).GrantsBudgetEnforcement()
					})
					orgClient.SetPricingRail(
						func() bool { return cfgForLock.Guard.Budget.FromOrg },
						pricingWire.onPricingFetch,
					)
					// COLD START, before the first poll (which is a push cycle
					// away). Every turn priced in between would otherwise be
					// stamped at seed rates, permanently: api_turns.cost_usd is
					// written at capture and this arc has no retroactive
					// re-pricing (ruling R8).
					if _, perr := orgClient.LoadPersistedPricing(ctx); perr != nil {
						slog.Default().Warn("org pricing: could not load the persisted document", "err", perr)
					}

					// Org-served Cloud Intelligence RESULT rail (org-served-
					// cloud-intelligence plan §2.1/W5). The gate is resolved
					// LIVE from the node-authored [intelligence].org_enrichment
					// key, RAISED on a managed node that holds extract.intel —
					// exactly the same node-authored-floor / managed-raise
					// shape as the share tiers, read off the ONE govern
					// share-tier table (intelRailEnabled). nil-safe: a build
					// that never reaches here leaves the rail OFF. The fetch
					// loop already lives on the shared push goroutine; this
					// only installs the request gate.
					//
					// Parity (design 3.7): the node-authored input is read
					// LIVE from config.toml (an `observer intel accept` or a
					// dashboard accept rewrites it after start), and on an
					// individual-tenancy enrolment it additionally needs an
					// active consent record (INV-13), so a hand-edited key
					// alone never opens the org plane there.
					orgIntelLive = newLiveOrgEnrichment(configPath, cfgForLock.Intelligence.OrgEnrichment)
					intelRailGate := func() bool {
						ctx := context.Background()
						return intelRailEnabled(
							orgIntelLocalOptIn(ctx, orgStore, orgIntelLive.Get()),
							ngov.Effective(ctx),
						)
					}
					orgClient.SetIntelRail(intelRailGate)
					// The consent report rail: the node's own posture, sent
					// when it changes (orgclient.runIntelConsentCycle).
					orgClient.SetIntelConsentSource(orgIntelConsentSource(orgStore, orgIntelLive))
					// Parity phase 2 (B1): the background sweep queues quiet
					// org-authority sessions as node-built evidence under the
					// same gate (orgintel.PlanSubmit adds the individual
					// consent and level rules); the push cycle sends them.
					orgClient.SetIntelSubmitSource(orgIntelSubmitSource(orgStore, orgIntelLive, intelRailGate, lookupProcessCostEngine(dbPath)))
				}
			}

			w, wCleanup, err := buildWatcher(ctx, configPath)
			if err != nil {
				return err
			}
			defer wCleanup()

			// Share the proxy's cachetrack engine with the watcher's store
			// so Tier-2 (transcript) cache observations advance the SAME
			// CacheModel state the proxy's Tier-1 path does. Without this,
			// the watcher store's engine is nil and every transcript cache
			// observation is dropped, so sessions never routed through the
			// proxy show no cache warm/cold status at all. No-op when cache
			// tracking is disabled ([cachetrack].enabled = false → nil).
			if eng := p.CacheEngine(); eng != nil {
				w.SetCacheEngine(eng)
			}
			// Rows from transcript-only tools are node activity too
			// (2026-10-02 budget-latency arc, P3): they kick the org push
			// and the budget-warning re-measure exactly as a proxied turn.
			w.SetIngestNotifier(noteIngestActivity)
			// The first-run view's history-capture progress (T-922): the
			// initial scan Watch starts below reports into this model and
			// the dashboard reads it (Options.CaptureProgress).
			captureProgress := wireCaptureProgress(w)

			// Project Identity Resolver v2 (§3.1): the ONE production wiring
			// of the lazy root-commit exec. Adapters resolve identity with
			// IdentityOptions.RootCommit = nil (never fork git per parsed
			// line) and `observer hook` leaves it nil too (a short-lived
			// per-tool-call store must not shell out on the agent's critical
			// path); the watcher's long-lived store runs it instead, at most
			// once per project root per store.RootCommitRecheckInterval.
			// Leaving this unwired is not a failure — maybeRunLazyRootCommit
			// is a no-op on a nil resolver, and every other identity signal
			// (remote, upstream, owners, workspace, fingerprint, worktree)
			// is pure file reads and lands regardless; only the remote-less-
			// clone fold (resolver rule 6) needs the root commit.
			w.SetRootCommitResolver(git.DefaultRootCommit)

			// OTel exporter (Teams M4) — constructed only when [exporter.otel]
			// enabled = true, so a solo-local install builds no OTLP client and
			// makes zero exporter network calls. It tails api_turns
			// independently of the org server (M0 only). A construction failure
			// is WARN-only: the exporter must never block the daemon (P1).
			var otelExporter otelExporterHandle
			if lockErr == nil && cfgForLock.Exporter.OTel.Enabled {
				exp, otelCleanup, _, oerr := buildOTelExporter(ctx, configPath)
				if oerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "otel exporter disabled: init failed: %v\n", oerr)
				} else {
					otelExporter = exp
					defer otelCleanup()
				}
			}

			// Dashboard wiring — opt-out so users can run a separate
			// `observer dashboard` process bound to a non-loopback iface
			// or a different port without conflict.
			var dashboardServer daemonDashboard
			var dashboardListen string
			// Session-attach socket Host (design Phase 1): derived directly off
			// the ONE shared terminal stack (buildTerminalSurfaces) below, so
			// `observer <tool> --attach` spawns through the same PTY stack the
			// dashboard drives WITHOUT requiring the dashboard launch gate. Set
			// whenever [terminal.attach].enabled is true — in the dashboard
			// branch, or the --no-dashboard attach-only branch. Nil ⇒ no PTY
			// stack ⇒ attach unserved (honest-disabled), never a parallel stack.
			var attachHostImpl attachSocketHost
			// Phase 2 (plan §4.4): the tailnet-serve backend — a dedicated
			// loopback listener distinct from the owner-trusted direct
			// dashboard listener, served with the full auth stack. Populated
			// only when [remote] is enabled in tailscale mode AND Ready().
			var remoteBackendAddr string
			// daemonDB is the daemon's long-lived handle (dashboard or
			// attach-only branch); the bounded stop checkpoints the WAL
			// through it after every component has returned (T-553).
			var daemonDB *sql.DB
			if !noDashboard && !comps.Active("ui.dashboard") {
				// D-514: one reason, then headless. A build without the
				// dashboard (-tags sbo_omit_ui_dashboard) names the build;
				// an inactive one points at the selection.
				fmt.Fprintf(cmd.ErrOrStderr(), "components: dashboard not started (%s); running as with --no-dashboard\n", loopSkipReason(comps, []string{"ui.dashboard"}))
				noDashboard = true
			}
			if !noDashboard {
				cfg, database, dbCleanup, err := loadConfigAndDB(ctx, configPath)
				if err != nil {
					return err
				}
				defer dbCleanup()
				cfg = applyInertOverlay(cfg, comps)
				daemonDB = database
				resolvedConfigPath, _ := config.ResolveGlobalPath(configPath)
				// First-run view (T-922): record once, before the watcher's
				// initial scan starts (ng.Go("watcher") below), whether this
				// install is fresh. Fail-open.
				recordFirstRunInstall(ctx, database, cfg.Observer.DBPath, slog.Default())
				// WINNODE2 item 11: fold Windows project rows split by case.
				mergeCaseDuplicateProjectsAtStart(ctx, database, slog.Default())
				// Build the daemon's ONE termsession.Manager + termsvc.Service
				// (CLAUDE.md #4) and derive the two INDEPENDENT surfaces off it:
				// the dashboard launch manager (gated by allow_dashboard_launch)
				// and the attach-socket host (gated by [terminal.attach].enabled).
				// The two are decoupled — attach no longer requires the launch
				// gate. surfaces.close reaps the shared PTY stack and MUST run
				// before the DB closes; defer-LIFO keeps it ahead of dbCleanup.
				surfaces, err := buildTerminalSurfaces(ctx, cfg, database, slog.Default(), nf)
				if err != nil {
					return err
				}
				defer surfaces.close()
				// The sandbox posture aggregate (sandbox plan v2 section 8.4):
				// the org push composes it only while the Sandboxes and VMs
				// module is active and a prober exists.
				bindSandboxCapability(ctx, orgStore, sandboxModuleActive(comps), surfaces.sandboxProber)
				// The governance handle reads the enrolment grant through the
				// daemon's own long-lived DB handle. It is bounded-refresh
				// rather than event-driven because `observer enroll` writes
				// the grant from a SEPARATE process (§2.3), which no
				// in-process sink can observe.
				ngov.SetIdentityLoader(governanceIdentityLoader(store.New(database)))
				// Request-grants G8: verified feature access grants lift
				// their pins in the sidecar, and tool access grants let a
				// dashboard launch of a disallowed tool through.
				ngov.SetFeatureExceptions(daemonFeatureExceptions(store.New(database)))
				ngov.SetPageGrants(daemonPageGrants(store.New(database)))
				nf.SetToolGrant(daemonToolGrant(store.New(database)))
				nf.SetFeatureGrant(daemonFeatureGrant(store.New(database)))
				launchMgr, launchStatus, policyStop := surfaces.launchMgr, surfaces.launchStatus, surfaces.policyStop
				attachHostImpl = surfaces.attachHost
				remoteCtrl := buildRemoteController(cfg, database)
				// Wire the §4.δ remote-execute authorizer onto the launch manager
				// (no-op + fail-closed unless BOTH the [remote] substrate and the
				// PTY launcher exist; a nil launch manager no-ops too). Same
				// assembly as `observer dashboard`.
				wireRemoteExecuteTier(cfg, launchMgr, remoteCtrl)
				// Cold-storage seam for archived process trails (P3.5).
				// nil + a no-op closer when [archive].enabled is false, so an
				// operator who never turned archival on pays nothing.
				processArchive, closeArchive := openProcessArchiveReader(ctx, cfg)
				defer closeArchive()
				// Projects-page ROI + commit-alignment arc (docs/plans/
				// projects-page-roi-and-commit-alignment-plan-2026-09-21.md
				// §4 W3): the §3.6 "J" judge-tier seam is build-tag-split
				// (projects_wire.go/projects_judge_wire.go).
				projectsJudgeGrade, projectsJudgeGradeReason := projectsDashboardOptions(&cfg)
				opts := dashapi.Options{
					ProcessArchive: processArchive,
					Projects:       cfg.Projects,
					// Plans & limits: the same service the "plans" loop below runs.
					Plans: processPlans(cfg, database, slog.Default()),
					// Custom scanners (security_custom_cmd.go): nil unless the
					// security.scan.custom component is active.
					CustomScanners: customScannersForDashboard(cmd.Context(), comps, configPath, store.New(database)),
					// CommitAlignmentAvailability (cloud_gradecommit.go) is the
					// SAME function `observer cloud grade-commit` itself calls,
					// so the dashboard and the CLI never disagree about why
					// cloud grading is unavailable.
					CloudGradeAvailability: CommitAlignmentAvailability,
					JudgeGrade:             projectsJudgeGrade,
					JudgeGradeReason:       projectsJudgeGradeReason,
					// Projects page "Rescan now" (commitscan_wire.go): the daemon's own
					// commit scanner, nil when [projects].commit_scan is off.
					CommitRescan: commitRescanWithDelivery(cfg, database),
					// Package checks card (security_deps_dash.go): the install
					// gate's state and the dashboard accept of its disclosure.
					PackageChecks: packageChecksDash(resolvedConfigPath, database),
					// Scanners card (security_scan_dash.go): the OSV database
					// download's one-time accept (PT-19).
					ScannerDB: scannerDBDash(resolvedConfigPath, database),
					// SARIF upload (security_sarifimport.go): one file the
					// developer picked, through the CLI's own import (lane SEC-P4).
					SARIFImport: sarifImportDash(database),
					// Code rules card (security_opengrep_dash.go): the guided
					// install with its size consent (lane SEC-G2).
					Opengrep: opengrepDash(resolvedConfigPath, database),
					IaC:      iacDash(resolvedConfigPath, database),
					// AI change records card (security_provenance_cmd.go, lane sec-f2a).
					Provenance: provenanceDash(resolvedConfigPath, database),
					// The one security opt-in rule (security_optin.go): the
					// components state's security_selected (which Settings rows and
					// the Explain button show), and the trust, git hooks and
					// scanner routes.
					SecuritySelected: securitySelected,
					// The Components page's view with the modules' own rules
					// (components_gate.go), so a removed sandbox root reads as off there
					// as in `observer components status` (P-057).
					ComponentStateView: componentStateView,
					// The launch row's Observer-entry test (launch_trust_own.go), so
					// the New Terminal trust chip leaves out what the launch leaves out.
					RepoTrustOwn: repoTrustDashboardOwn,
					// The launch row's conditional rows (trust_conditions.go), so the
					// review lists N2's initializeCommand row as the launch reads it.
					RepoTrustPaths: repoTrustDashboardPaths(resolvedConfigPath),
					// Delivery (delivery_wire.go, D-689): the [delivery] tunables and the
					// one process-wide delivery service the poll loop also runs.
					Delivery:        cfg.Delivery,
					DeliveryService: deliveryDashOption(cfg, database),
					// Admin-controlled Plane B (spec §3.5): the ONE seam the
					// dashboard has onto governance. nil on an ungoverned
					// build; here it is the daemon's single install seam, so
					// the route guard, the SPA and the P0-6 report can never
					// disagree about what this node applies.
					Governance: ngov.Effective,
					// Org-parity W5.1: the same one-owner node.features
					// handle the LKG loader and poller install into, above.
					// nil-safe methods (see nodeFeaturesHandle.Allowed /
					// TerminalAllowed) so an ungoverned/solo node's seams
					// fail open exactly like Governance's nil convention.
					FeatureGate:         nf.Allowed,
					TerminalFeatureGate: nf.TerminalAllowed,
					DB:                  database,
					DBPath:              cfg.Observer.DBPath,
					CostEngine:          acquireProcessCostEngine(ctx, cfg, database, slog.Default()),
					// Production read caches: page loads fan several spend panels out at
					// once and share one row read; watcher health is served SWR
					// (optimization review 2026-09-27, findings N4/N5).
					ReadCaches: true,
					Predict:    cfg.Predict,
					Scoring:    cfg.Intelligence.Scoring,
					CacheWarm:  cfg.CacheWarm,
					Tasks:      cfg.Tasks,
					// LOC editor endpoint credential: generated on first
					// start into [loc].editor_token_file, read back after.
					// Never fatal — an unreadable file yields "" and the
					// endpoint keeps its loopback-only posture.
					LocEditorToken:         resolveLocEditorToken(locEditorTokenPath(cfg), slog.Default()),
					LocEditorTokenRequired: cfg.Loc.EditorTokenRequired,
					Dashboard:              cfg.Dashboard,
					MonthlyBudgetUSD:       cfg.Intelligence.MonthlyBudgetUSD,
					ConfigPath:             resolvedConfigPath,
					RecognizesSessionFile:  recognizesSessionFile(),
					CursorSemanticsFor:     cursorSemanticsFor(),
					// `observer start` always runs the watcher beside the
					// dashboard (ng.Go("watcher") below); the sidebar keys
					// its watcher line to this, not to Claude setup (T-585).
					WatcherRunning:  true,
					CaptureProgress: captureProgress,
					ToolCatalog:     toolCatalog(),
					// Connected tools hooks probe: the options the
					// auto-registration above wrote with (T-376).
					HookRegistryOptions: hookProbeOptionsSeam(configPath),
					// Connected tools per-tool "Run checks" (T-421 item 3): the
					// same report builder `observer doctor <tool>` prints.
					ToolDoctor: dashboardToolDoctor(configPath),
					// Cloud account seam (cloudaccount_wire.go): local sign-in probe +
					// `observer cloud login|logout` subprocess runner behind the Settings
					// → Cloud Intelligence Sign-in button. Spawns the CLI; links nothing new.
					CloudAccount:   newCloudAccountSeams(resolvedConfigPath),
					ArenaAdmission: arenaBudgetAdmissionSeam(resolvedConfigPath),
					ArenaPreflight: arenaPreflightSeam(resolvedConfigPath),
					// OSH-R-005: may an Arena drive skip the harness's permission checks.
					ArenaPermissionBypass: arenaPermissionBypassSeam(resolvedConfigPath),
					ProxyPort:             cfg.Proxy.Port,
					// OSH-R-009: the Setup route writers write the client
					// token form when the node wants client auth.
					ProxyClientToken: daemonProxyClientToken(cfg),
					StashDir:         cfg.Compression.Conversation.Stash.Dir,
					GuardEnabled:     cfg.Guard.Enabled,
					GuardMode:        cfg.Guard.Mode,
					GuardStrict:      cfg.Guard.Strict,
					GuardHookFailure: guardHookFailureSeam(configPath),
					GuardToolGates:   guardToolGatesSeam(configPath, surfaces.sandboxProber),
					Version:          version,
					// Session handoff (docs/session-handoff.md P2): the
					// shared handoffsvc runner behind
					// /api/session/<id>/handoff*.
					BuildHandoff: handoffRunner(cfg, database),
					// P2.5: config saves hot-reload the proxy's compression
					// profile router — new sessions resolve against the
					// updated [profiles] table / compression params without
					// a restart. Nil when compression is off at boot (the
					// master switch stays restart-gated).
					OnConfigSaved: profilesReload,
					// P6.7: demo mode — temp DB seeded from embedded
					// fixtures; never touches the real observer.db.
					DemoSeeder: demoSeeder(slog.Default()),
					// R2.4: the live router's §R18.3 demotion set —
					// in-memory state only this process can answer for.
					// Nil when routing isn't wired; the status endpoint
					// reports demotions_live accordingly.
					RoutingDemotions: routingDemotions,
					// D4: the generalized-observability subsystem registers
					// its /api/obs/* trajectory endpoints here (the single
					// host->obs seam; nil when disabled or under no_obs).
					// admissionHandle (gap P0-7) shares the proxy's ONE live
					// admission service with the dashboard policy/egress editors,
					// so an edit hot-swaps the instance the proxy enforces.
					ExtraRoutes: append(obsDashboardRoutes(ctx, cfg, configPath, database, admissionHandle, slog.Default()), append(hostedDashboardRoutes(configPath), gatesSandboxDashboardRoutes(configPath)...)...),
					// Embedded web-terminal launcher (docs/session-handoff.md
					// launch section). Nil when [handoff].allow_dashboard_launch
					// is false → endpoints 503, button hidden.
					LaunchManager:  launchMgr,
					TerminalStatus: launchStatus,
					// Node-intervention policy-stop explanation
					// (policystop.go). Nil unless the launch manager is also
					// wired — a policy stop only ever concerns a dashboard-
					// launched PTY run.
					PolicyStop: policyStop,
					// B9 sandboxed terminals: the availability probe behind
					// GET /api/terminal/sandbox + the fail-closed launch
					// validation. Nil unless [terminal.sandbox].enabled →
					// endpoint reports disabled and a sandbox request 501s.
					SandboxProber: surfaces.sandboxProber,
					// The first-start install's version picker (lane LEFT-SBX):
					// nil in a build without the container driver.
					SandboxInstallVersions: sandboxInstallVersionsSeam(resolvedConfigPath),
					// The Settings card's org forbid of sign-in seeding (lane
					// BOXSIGNIN): the composed managed view, nil without the sandbox.
					SandboxSignInForbidden: sandboxSignInForbiddenSeam(resolvedConfigPath),
					// The New Terminal "project policy" line (lane sec-p2b): reads the
					// project match record; shown only when the node holds a project delivery.
					ProjectPolicy: terminalProjectPolicySeam(cfg, store.New(database)),
					// Tool-binary-resolution seams (tool-binary-resolution arc
					// §5): pre-launch verdict + guided install. Plain funcs so
					// the dashboard package never imports internal/toolresolve.
					ToolPreflight:    toolPreflightSeam(resolvedConfigPath, allowToolInstallSeam(resolvedConfigPath)),
					AllowToolInstall: allowToolInstallSeam(resolvedConfigPath),
					ToolInstallHint:  toolInstallHintSeam(),
					// Refuse a guided install whose grounded prerequisites
					// (unzip, bzip2, ...) are missing, with the fix.
					ToolInstallBlocked: toolInstallBlockedSeam(),
					// The record of guided installs this dashboard ran + the
					// matching uninstall (tool_installs, agent migration 149).
					ToolInstalls: surfaces.toolInstalls,
					// Command wrapping (backlog item 7): the one shim / start-up-file
					// applier, behind the Settings -> Terminal card.
					ShellWrap: newShellWrapService(resolvedConfigPath, dashResolveEnv),
					// Windows-home init (T-421 item 4): `observer init
					// --windows-*-home` behind Connected tools, WSL only.
					WindowsHomes: newWindowsHomeService(resolvedConfigPath, cfg.Proxy.Port),
					// Re-pricing stored costs (PRICE-REPRICE-1): the one plan/apply/
					// revert service `observer reprice` also uses, behind the Settings card.
					Reprice: newRepriceService(ctx, cfg, database, slog.Default(), ngov.Effective),
					// After New Terminal install/launch: re-detect adapters
					// and hot-add newly-existing session dirs into the live
					// watcher (Muse/Prime-after-install capture gap).
					RefreshWatchRoots: refreshWatchRootsSeam(w),
					// New Terminal model picker (B5): recent-usage history
					// over the daemon's own database, composed with the
					// capability registry's Known examples by
					// modelSuggestionsFor.
					RecentModels: recentModelsSeam(database),
					// Per-terminal project panel (Arc A): token→root resolver
					// from termsvc. Nil when the launch manager is absent → 404.
					ProjectRootResolver: projectRootResolver(launchMgr),
					// Per-terminal session cockpit (Session Cockpit): token→run/
					// session-link resolver from termsvc. Nil when the launch
					// manager is absent → cockpit 404s.
					SessionResolver: sessionResolver(launchMgr),
					// Restart-from-dashboard (docs/plans/dashboard-daemon-
					// restart-plan-2026-07-14.md): preflight the config, then
					// cancel the root context so the daemon runs its NORMAL
					// graceful shutdown (component drain + surfaces.close PTY reap
					// + dbCleanup); main() re-execs after every defer completes.
					// Refuses up front if the config wouldn't come back
					// (never shut down into a brick) or on an OS without execve.
					// The restart hook lives in sandbox_liveruns.go beside the
					// live-run gate: a restart with a live sandboxed run asks
					// (end them, or restart when they finish) instead of
					// ending it (sandbox plan v2 section 5.5, SBX-UPD-1).
					RestartFunc:      daemonRestartFunc(configPath, cancel),
					RestartPreflight: daemonRestartPreflight(configPath),
					LiveSandboxRuns:  startLiveRuns(configPath, cancel, surfaces.mgr, database),
					// Remote-access substrate (plan §4). Nil unless [remote] is
					// enabled AND a pairing secret is provisioned, so a
					// non-loopback dashboard bind stays fail-closed. Built once
					// and shared by the direct listener guard, the Phase-2
					// tailnet backend, and CheckRemoteBind.
					Remote:      remoteCtrl,
					RemoteAudit: remoteAuditSink(database),
					// In-place binary update (enterprise-update-management
					// plan §3.7/§3.10). The seam runs the drain and the
					// fork-exec-and-watch handshake IN THIS PROCESS, because
					// they are only meaningful where the listeners live; the
					// dashboard contributes a loopback-only route and nothing
					// else. Nil when [update].enabled is false, which the
					// handler reports as 501 rather than as a 404 the caller
					// would misread as "old daemon".
					UpdateApplyFunc: updateRuntimeFor(cfg, resolvedConfigPath, store.New(database), orgClient, surfaces.mgr, slog.Default()).ApplySeam(),
					// W5 read side: the Settings -> Health update card and the
					// update banner. StatusSeam is deliberately non-nil even
					// when [update].enabled is false — it then reports
					// Enabled:false, which the card renders as "off on this
					// node" rather than as "up to date".
					UpdateStatusFunc: updateRuntimeFor(cfg, resolvedConfigPath, store.New(database), orgClient, surfaces.mgr, slog.Default()).StatusSeam(),
					// W5: the VS Code extension's self-report (ruling R6). The
					// daemon cannot discover the extension's version on its
					// own, so the extension tells it once per activation and
					// the org board can show editor/daemon skew.
					UpdateExtensionVersionFunc: updateRuntimeFor(cfg, resolvedConfigPath, store.New(database), orgClient, surfaces.mgr, slog.Default()).ExtensionVersionSeam(),
					// Agent Access P10 (mcp_access_dashboard.go): GET
					// /api/mcp-access/status for the Security page and the
					// VS Code status item - the `observer mcp status` body
					// plus coverage rows, effective state and connect URL.
					MCPAccessStatus: mcpAccessStatusSeam(resolvedConfigPath, database),
					// Settings > Enrolment management (backlog item 6): enrol / consent /
					// status / grant / push-now / leave through the CLI's own code
					// paths. Wired even when not enrolled - that is how a node enrols
					// from the UI. pushLoop tells the outcome whether a restart is
					// needed before pushes start. The governance hook makes an enrol or
					// leave show on /api/governance at once.
					EnrolManager:       enrolManagerFor(resolvedConfigPath, orgClient != nil, ngov).withRetire(orgClient), // T-718: Leave retires the daemon's budget rail live
					Components:         dashboardComponents(resolvedConfigPath, database),                                 // Settings > Components + route guard (MP-DASH)
					ComponentArtifacts: dashboardComponentArtifacts(resolvedConfigPath),                                   // artifact_states on /api/components (T-707)
					BinaryInstall:      dashboardBinaryInstall,                                                            // binary_install on /api/components (U12)
					// Settings > Cloud Intelligence (org plane): the same
					// functions `observer intel` runs; a write invalidates
					// the rail gate's live opt-in read.
					OrgIntel: newOrgIntelDashboard(resolvedConfigPath, orgIntelLive.invalidate),
				}
				// Assign the concrete client only when present so Options.OrgClient
				// stays a nil interface (not a non-nil interface holding a nil
				// pointer) on a solo-local install — the enrolment handlers key
				// off that nil to report not-enrolled.
				if orgClient != nil {
					opts.OrgClient = orgClient
					// The Requests page (request-grants G6) rides the same
					// client: same server, same credential.
					opts.Requests = orgClient
					// The Messages page (T-854) too: replies and receipts
					// go to the same server over the same credential.
					opts.Messages = orgClient
				}
				dashboardServer, err = newDaemonDashboard(opts)
				if err != nil {
					return err
				}
				// Standing-takeover provenance hook (opt-in policy
				// [remote].revoke_standing_on_takeover, default off): the
				// concrete manager reports a local takeover of a
				// standing-credential remote writer; the dashboard decides
				// whether that also revokes standing access. Registered
				// post-construction — termsession never imports dashboard.
				if surfaces.mgr != nil {
					surfaces.mgr.SetOnStandingLocalTakeover(dashboardServer.OnStandingLocalTakeover)
				}
				// Durable-listen-address precedence (issue #8):
				// --dashboard-addr flag > OBSERVER_DASHBOARD_ADDR env >
				// [dashboard].addr config > built-in default. Use the cobra
				// Changed check (not a zero-value test) so an unset flag doesn't
				// mask the env/config layers.
				dashFlag := ""
				if cmd.Flags().Changed("dashboard-addr") {
					dashFlag = dashAddr
				}
				dashboardListen = resolveDashboardAddr(dashFlag, cfg.Dashboard.Addr, "127.0.0.1:8081")
				// Never expose an unauthenticated dashboard (plan §4.6): a
				// non-loopback bind without a ready [remote] substrate binds
				// 127.0.0.1 on the same port instead and says why once
				// (D-514 / D-516: start with the setting off, never refuse).
				dashboardListen = feasibleDashboardAddr(dashboardListen, remoteCtrl, cmd.ErrOrStderr())
				noteDashboardListen(dashboardListen)
				// The address is recorded beside the database so a CLI asking
				// about live sandboxed runs finds this daemon however it was
				// started (SBX-UPD audit finding 3).
				if removeListenRecord, lerr := writeDashboardListenRecord(cfg.Observer.DBPath, dashboardListen); lerr == nil {
					defer removeListenRecord()
				} else {
					slog.Default().Warn("dashboard: could not record the listen address", "err", lerr)
				}
				// D-514: the settings config.Load switched off because this
				// build cannot honour them yet, one line each.
				for _, line := range cfg.Deferred {
					fmt.Fprintln(cmd.ErrOrStderr(), "WARN config: "+line)
				}
				// The sections config.Load set aside because their optional
				// component is not active (internal/config/component_sections.go).
				for _, line := range cfg.Inert {
					fmt.Fprintln(cmd.ErrOrStderr(), "WARN config: "+line)
				}
				// Enterprise update management, daemon side (plan §3.7/§3.9).
				// One block, placed here because everything below it depends
				// on the listener address being settled.
				if updateRT := updateRuntimeFor(cfg, resolvedConfigPath, store.New(database), orgClient, surfaces.mgr, slog.Default()); updateRT != nil {
					// The org-bound posture is composed from this, and until
					// it is set the push envelope carries no update_posture
					// key at all — the pre-feature shape, exactly.
					updateRT.PublishPosture()
					// A node that starts with state=applying and NO parent
					// watching (a kill after the old parent exited, or a host
					// reboot) settles itself here. This is the residual
					// ruling R14 recommends a supervisor for.
					updateRT.RecoverAtBoot(ctx)
					go func() {
						// The child self-check is owed only when an older
						// daemon spawned this process. It must not report
						// until the listeners are actually accepting, because
						// a bind failure is exactly the boot crash the
						// handshake exists to catch — so it waits for the
						// dashboard socket the same way the readiness banner
						// does, and lets the parent's own timeout be the
						// bound if the listener never comes up.
						if handshakeChildNonce() != "" {
							waitForListener(ctx, dashboardListen)
							updateRT.ReportChildSelfCheck(ctx)
						}
						updateRT.AutoApplyLoop(ctx)
					}()
				}
				// Phase 2 (plan §4.4): arm the tailnet-serve backend when
				// [remote] is enabled in tailscale mode with a Ready() substrate
				// and a pinned loopback backend addr. The direct listener above
				// stays loopback owner-trusted; this SEPARATE loopback listener
				// requires auth for every request.
				if remoteCtrl != nil && remoteCtrl.Ready() &&
					strings.EqualFold(strings.TrimSpace(cfg.Remote.Mode), "tailscale") &&
					strings.TrimSpace(cfg.Remote.TailscaleBackendAddr) != "" {
					remoteBackendAddr = strings.TrimSpace(cfg.Remote.TailscaleBackendAddr)
				}
			} else if lockErr == nil && cfgForLock.Terminal.Attach.Enabled {
				// Session-attach WITHOUT the dashboard (--no-dashboard): the
				// attach socket still serves off its OWN shared terminal stack,
				// gated only by [terminal.attach].enabled. This branch and the
				// dashboard branch above are mutually exclusive on noDashboard, so
				// the daemon still builds EXACTLY ONE termsession.Manager per run
				// (the one-owner invariant, CLAUDE.md #4). The launch manager
				// surface is unused here (no dashboard drives it); only the attach
				// host is taken. surfaces.close reaps the PTY stack before the DB
				// closes (defer-LIFO ahead of dbCleanup).
				cfg, database, dbCleanup, err := loadConfigAndDB(ctx, configPath)
				if err != nil {
					return err
				}
				defer dbCleanup()
				cfg = applyInertOverlay(cfg, comps)
				daemonDB = database
				surfaces, err := buildTerminalSurfaces(ctx, cfg, database, slog.Default(), nf)
				if err != nil {
					return err
				}
				defer surfaces.close()
				// Same governance identity loader as the dashboard branch:
				// even with no dashboard to govern, the node must still
				// report a truthful node.governance effective-state row.
				ngov.SetIdentityLoader(governanceIdentityLoader(store.New(database)))
				// Request-grants G8: verified feature access grants lift
				// their pins in the sidecar, and tool access grants let a
				// dashboard launch of a disallowed tool through.
				ngov.SetFeatureExceptions(daemonFeatureExceptions(store.New(database)))
				ngov.SetPageGrants(daemonPageGrants(store.New(database)))
				nf.SetToolGrant(daemonToolGrant(store.New(database)))
				nf.SetFeatureGrant(daemonFeatureGrant(store.New(database)))
				attachHostImpl = surfaces.attachHost
			}

			if dashboardServer != nil {
				dashURL := "http://" + dashboardListen
				fmt.Fprintf(cmd.OutOrStdout(),
					"start: %s + watcher + dashboard - ctrl-c to stop\n", proxyStartLabel(addr, comps))
				fmt.Fprintf(cmd.OutOrStdout(), "  dashboard → %s (starting…)\n", dashURL)
				// Print a distinct "ready" line the moment the listener
				// actually accepts a connection, so the operator isn't told
				// the URL works before it does. Honest readiness: dials the
				// bind addr until connect (the dashboard goroutine below
				// Listens on it) or ctx-cancel. Best-effort; a failure to
				// dial is silent (the URL line already told them where).
				go announceDashboardReady(ctx, cmd.OutOrStdout(), dashboardListen, dashURL)
				// Auto-open on interactive launches only (P1.14): a TTY
				// stdout means a human just typed `observer start`;
				// daemonized launches (setsid / systemd / redirected
				// logs) never pop a browser. Best-effort + delayed so
				// the listener is up first.
				if !noOpen && stdoutIsTerminal() {
					go func() {
						select {
						case <-time.After(700 * time.Millisecond):
							openBrowser(dashURL)
						case <-ctx.Done():
						}
					}()
				}
			} else {
				why := "dashboard disabled via --no-dashboard"
				if !dashboardInBuild {
					why = "no dashboard: ui.dashboard is not in this build"
				} else if !comps.Active("ui.dashboard") {
					why = "dashboard inactive (ui.dashboard)"
				}
				fmt.Fprintf(cmd.OutOrStdout(),
					"start: %s + watcher (%s) - ctrl-c to stop\n",
					proxyStartLabel(addr, comps), why)
			}

			// Plane-A P0-5 Phase W (plan §6.5): load a verified
			// Last-Known-Good v1 policy resource for every v1 family into
			// the shared admission service (admission.input,
			// egress.routing_guardrail) AND — Phase 3, gateway config
			// plane spec — the proxy's live lane table (gateway.providers)
			// BEFORE the proxy listener below starts accepting traffic —
			// run synchronously, here, ahead of the errgroup that
			// launches ListenAndServe. Its own short-lived config+DB
			// handle (closed immediately after) is sufficient: the
			// org-layer identity fence itself is wired inside
			// wireAdmission (reusing the daemon's own long-lived db) —
			// this handle is needed only for the durable-cache
			// read/repair path. No-op when the org rail is disabled
			// (orgClient nil) or the node has never enrolled.
			if orgClient != nil {
				if pcfg, pdb, pcleanup, perr := loadConfigAndDB(ctx, configPath); perr == nil {
					loadPolicyResourceLKG(ctx, pcfg, orgClient, store.New(pdb), admissionHandle, gw, ngov, nf, newLogger(pcfg.Observer.LogLevel))
					// The stored security managed pull (lane SEC-E); the
					// shared poll step fetches it from then on.
					loadSecurityManagedAtStart(ctx, pcfg, store.New(pdb))
					pcleanup()
				} else {
					fmt.Fprintf(cmd.ErrOrStderr(), "policy resource: LKG load skipped: db open failed: %v\n", perr)
				}
			}

			g, gctx := errgroup.WithContext(ctx)
			// Every goroutine below is tracked by name (T-553), and a stop
			// that begins because a component failed (gctx cancelled without
			// a signal) arms the same watchdog as a SIGTERM does.
			// Every loop is gated by its component (components_gate.go:
			// daemonLoopComponents); with no [components] block all start.
			ng := newGatedGroup(namedGroup{g: g, t: stopTracker}, comps, cmd.ErrOrStderr())
			go func() {
				<-gctx.Done()
				stopTracker.AdvanceStage(shutdown.StageRunning, shutdown.StageComponents)
				stopWatchdog.Arm()
			}()
			// Listener scope for the in-place update handshake
			// (enterprise-update-management plan §3.7 step 7). The proxy and
			// the dashboard listen on THIS context, not gctx directly, so an
			// apply can release their sockets while the old daemon STAYS
			// ALIVE to supervise its successor. Cancelling gctx would end the
			// supervisor along with the listeners, which is exactly the
			// execve-replace failure the handshake exists to avoid.
			//
			// Nothing else changes: listenerCtx is a child of gctx, so a
			// normal shutdown still stops both, and a listener that returns
			// nil on graceful close leaves the errgroup running.
			listenerCtx, releaseListeners := context.WithCancel(gctx)
			defer releaseListeners()
			// The apply releases those sockets right before it forks its
			// successor, so the new binary can BIND them while this process
			// stays alive to watch it. Without this the child fails with
			// EADDRINUSE and every apply rolls back — a deterministic
			// failure, not a race. No-op when the updater is disabled or the
			// daemon never reached the wiring block.
			currentUpdateRuntime().SetReleaseListeners(releaseListeners)
			// Diagnostic profiling server (default OFF). Armed only when
			// OBSERVER_PPROF_ADDR names a loopback host:port; loopback is
			// enforced and any bind failure is fail-soft. Started first so a
			// profile can capture the daemon's steady-state background loops
			// (CPU-audit work-stream). See cmd/observer/pprof.go.
			maybeServePprof(gctx, os.Getenv(pprofEnvVar), cmd.OutOrStdout(), cmd.ErrOrStderr())
			// The governance sidecar writer (§1.4). Unconditional and
			// self-gating: it returns immediately when no sidecar path was
			// attached, and on an ungranted node it writes a DORMANT file
			// (state + empty pinned map) rather than nothing, because
			// presence-with-empty is unambiguous while absence is
			// indistinguishable from "the daemon never ran".
			ng.Go("governance-sidecar", func() error {
				runGovernanceSidecarWriter(gctx, ngov)
				return nil
			})
			// The budget-warning service loop (nil-safe: an unenrolled node
			// never builds one).
			ng.Go("budget-warn", func() error {
				processBudgetWarn.Load().Run(gctx)
				return nil
			})
			ng.Go("proxy", func() error {
				if err := p.ListenAndServe(listenerCtx, addr); err != nil && !errors.Is(err, context.Canceled) {
					return fmt.Errorf("proxy: %w", err)
				}
				return nil
			})
			// A sandboxed run's projected transcripts (lane SBX-P3C, G27).
			setSandboxProjectionWatcher(w.AddProjectionRoot)
			ng.Go("watcher", func() error {
				if err := w.Watch(gctx); err != nil && !errors.Is(err, context.Canceled) {
					return fmt.Errorf("watcher: %w", err)
				}
				return nil
			})
			// Hosted-surface enricher (internal/surfaceenrich): stamps
			// `ide`/`jetbrains-<product>` onto sessions the JetBrains AI
			// Assistant drove through its ACP agents (Junie, Claude Code,
			// Codex, Copilot CLI), from the IDE's own
			// aia-task-history/*.agentsession pointer files. Runs beside
			// the watcher on the watcher store's two surface seams; inert
			// on a box with no JetBrains vendor directory; P1 fail-soft —
			// every miss is logged and retried, never cancels a sibling.
			ng.Go("surface-enricher", func() error {
				load, stamp := w.SurfaceSeams()
				surfaceenrich.New(surfaceenrich.Options{
					Load:   load,
					Stamp:  stamp,
					Logger: newLogger(cfgForLock.Observer.LogLevel),
				}).Run(gctx)
				return nil
			})
			// Agent-guidance inventory (internal/guidance): one scan at start,
			// then one every [guidance].rescan_minutes over every project root
			// the store knows, recording which CLAUDE.md / AGENTS.md / skill /
			// rule / command files each AI tool reads here. Names, sizes,
			// hashes and front-matter only — never a body. Self-gating on
			// [guidance].enabled and P1 fail-soft like every sibling loop: a
			// failed root is logged and retried, never cancels the daemon.
			ng.Go("guidance-scan", func() error {
				guidanceScanLoop(gctx, configPath)
				return nil
			})
			// Plans & limits (internal/planlimitssvc, docs/plans-and-limits.md):
			// polls the accounts the user added and reads the passive limits
			// Observer already captured. With no account added it reads the
			// local database only. P1 fail-soft.
			ng.Go("plans", func() error {
				plansLoop(gctx, configPath)
				return nil
			})
			// Commit-history capture (internal/commitscan): a read-only `git
			// log` scanner over every active project root, feeding the
			// Projects page's commit ledger and ROI proxies. Never installs a
			// git hook. Self-gating on [projects].commit_scan and P1
			// fail-soft like every sibling loop — a failed root is logged and
			// retried with backoff, and a missing git binary just idles the
			// scanner (doctor + the page surface the reason honestly).
			ng.Go("commit-scan", func() error {
				commitScanLoop(gctx, configPath)
				return nil
			})
			// Delivery (internal/deliverysvc, D-689): the code-host and
			// mirror poll loop. It makes no network call until the user
			// connects a code host or opts a project into a mirror schedule;
			// until then each tick reads two small local tables. P1
			// fail-soft like every sibling loop.
			ng.Go("delivery", func() error {
				deliveryLoop(gctx, configPath)
				return nil
			})
			// Session quality scoring (spec §15.2, internal/intelligence/
			// scoring): scores each session once it has been idle for
			// [intelligence.scoring].idle_minutes, re-scores sessions that saw
			// new activity, and works the never-scored backlog off in capped
			// passes. Before this loop the score only existed after a manual
			// `observer score`, so the Sessions table's quality columns and the
			// session Quality card stayed empty. Self-gating on
			// [intelligence.scoring].auto (default on); P1 fail-soft.
			ng.Go("session-score", func() error {
				sessionScoreLoop(gctx, configPath)
				return nil
			})
			// Stored spend-dedup verdicts (internal/spendverdict, agent
			// migration 143): re-derives every session whose api_turns /
			// token_usage rows changed, so the windowed spend surfaces (Cost,
			// Analysis, the guard's budget windows) apply the session
			// header's rule without re-deriving on the read path. P1
			// fail-soft.
			ng.Go("spend-verdicts", func() error {
				spendVerdictLoop(gctx, configPath)
				return nil
			})
			// One-time DB integrity probe + path-hash backfill, moved OFF the
			// readiness path (2026-07-16). db.Open never verifies by default, so
			// the listener binds fast; the multi-GB
			// `PRAGMA quick_check` (~14s even warm on the 9.5GB DB, and it used
			// to run once per synchronous daemon open) runs HERE, exactly once,
			// after the proxy/dashboard are already serving. Fail-soft (P1):
			// logs loudly on corruption, never cancels siblings.
			ng.Go("db-maintenance", func() error {
				// One concise heads-up so the multi-minute quick_check on a
				// large DB isn't silent — the dashboard is already serving.
				fmt.Fprintln(cmd.OutOrStdout(), "  (background) verifying database integrity - does not block the dashboard")
				fmt.Fprintln(cmd.OutOrStdout(), "  full integrity check + compaction are on-demand: `observer doctor db`, `observer prune --vacuum`")
				runStartupDBMaintenance(gctx, configPath)
				return nil
			})
			// Code-intelligence index-on-start (ADR-0002: index time only,
			// never the proxy hot path). Best-effort like the org loops —
			// a codeintel failure NEVER cancels proxy/watcher/dashboard.
			// Opt-in since D-307: when off it only prints the one-line
			// upgrade note for an install that default change turned off.
			ng.Go("codeintel", func() error {
				runCodeIntelOnStart(gctx, configPath, cmd.ErrOrStderr())
				return nil
			})
			// Periodic maintenance tick (Ticket B of the 2026-07-12
			// hook-stall + DB-prune plan): re-runs the full retention pass
			// every [observer.retention].interval_hours (default 24) so a
			// daemon that stays up for weeks still prunes — before this,
			// retention only ran at startup (prune_on_startup) and via
			// manual `observer prune`. P1 fail-soft like every sibling:
			// the loop logs failures and never cancels
			// proxy/watcher/dashboard. ≤ 0 disables the tick.
			ng.Go("retention", func() error {
				retentionTickLoop(gctx, configPath)
				return nil
			})
			// WAL watchdog (§1e follow-through, 2026-08-22): WARN + TRUNCATE
			// checkpoint once observer.db-wal exceeds
			// [observer.retention].wal_alert_mb, so a stall-era "frames all
			// checkpointed but file never released" state can never again
			// sit at 15.5 GB unnoticed. P1 fail-soft like the retention
			// sibling; wal_alert_mb <= 0 disables.
			ng.Go("wal-watchdog", func() error {
				walWatchdogLoop(gctx, configPath)
				return nil
			})
			// Temp-file / deleted-open watchdog (T3.1, P2-I,
			// docs/plans/observer-disk-compute-remediation-plan-2026-08-26.md):
			// WARNs once the monitored SQLite temp dir (T1.4a, tempwatch.go)
			// plus this process's own deleted-but-open files cross a
			// threshold — visible before the disk fills, not discovered
			// after. Same P1 fail-soft posture as every sibling loop.
			ng.Go("temp-watchdog", func() error {
				tempWatchdogLoop(gctx, configPath)
				return nil
			})
			// Cloud auto-sync (arc 2 R2a, docs/cloud-intelligence.md): when
			// [cloud].auto_sync=true, periodically spawn `observer cloud sync`
			// as a SUBPROCESS so the standing-grant sync happens without a
			// manual run. The daemon links NO cloud network package; the child
			// is the same consent-gated CLI that sends nothing without a live
			// grant (see cmd/observer/cloudautosync.go for the zero-egress
			// rationale, pinned by tests/invariant/cloud_egress_test.go).
			// Fail-soft + P1 like every sibling: inert unless opted in, and it
			// never cancels proxy/watcher/dashboard.
			ng.Go("cloud-auto-sync", func() error {
				runCloudAutoSyncFromConfig(gctx, cmd.OutOrStdout(), cmd.ErrOrStderr(), configPath)
				return nil
			})
			// Cloud auto-enrich (value-upgrade plan §W3, "background by
			// default"): once the developer's own cloud_enrich_policy row
			// (`observer cloud enable`) is on with background enabled, sweep
			// for personal-authority sessions that have gone quiet and spawn
			// `observer cloud consent` for each — the same consent-gated CLI,
			// so this loop's own egress is exactly zero (see
			// cmd/observer/cloudautoenrich.go). The policy is re-read live on
			// every tick, so a dashboard toggle takes effect without a daemon
			// restart. Fail-soft + P1 like every sibling loop.
			ng.Go("cloud-auto-enrich", func() error {
				runCloudAutoEnrichFromConfig(gctx, cmd.OutOrStdout(), cmd.ErrOrStderr(), configPath)
				return nil
			})
			// The opt-in pricing-feed poller ([pricing.feed].enabled AND .auto),
			// same posture as the cloud poller above: inert unless both flags
			// are set, runs the sync ladder IN-PROCESS through the egress gate
			// (the one typed egress) and re-prices the live cost engine on an
			// applied feed (finding F5), refuses on an org-enrolled node, never
			// cancels the daemon.
			ng.Go("pricing-auto-sync", func() error {
				runPricingAutoSyncFromConfig(gctx, cmd.OutOrStdout(), cmd.ErrOrStderr(), configPath)
				return nil
			})
			if dashboardServer != nil {
				ng.Go("dashboard", func() error {
					if err := dashboardServer.ListenAndServe(listenerCtx, dashboardListen); err != nil && !errors.Is(err, context.Canceled) {
						return fmt.Errorf("dashboard: %w", err)
					}
					return nil
				})
			}
			// Session-attach control socket (design 2026-07-19, Phase 1). An
			// owner-only AF_UNIX socket under the DB dir; `observer <tool>
			// --attach` connects and asks the daemon to spawn the tool's PTY
			// through the SAME termsession.Manager the dashboard drives (the
			// operator's terminal is viewer #1, the dashboard can join as viewer
			// #2). Its enablement predicate is [terminal.attach].enabled ALONE
			// (default on) — decoupled from the dashboard launch gate: the
			// attach host is derived directly off the ONE shared terminal stack
			// built above (attachHostImpl), so it serves even when
			// [handoff].allow_dashboard_launch is false and even under
			// --no-dashboard. It still requires an in-process PTY backend.
			// Fail-soft + P1 like every sibling: a socket/serve failure never
			// cancels the daemon.
			switch {
			case lockErr != nil:
				// Config never loaded; the daemon already warned at startup.
				// Stay silent here rather than emit a misleading attach notice.
			case !comps.Active("terminals"):
				// The inert overlay switched attach off; name the real cause.
				fmt.Fprintln(cmd.ErrOrStderr(),
					"session-attach disabled: the terminals component is inactive or not in this build (observer components status).")
			case !cfgForLock.Terminal.Attach.Enabled:
				// Honest disabled copy naming the EXACT config key (repo
				// convention): attach is off by explicit choice — it defaults on.
				fmt.Fprintln(cmd.ErrOrStderr(),
					"session-attach disabled: set [terminal.attach].enabled = true to let `observer <tool> --attach` join daemon-owned sessions.")
			case !ptySupported():
				// Enabled but this OS has no in-process PTY backend. The
				// This arm is gated on PTYSupported() alone, so name THAT
				// cause (audit DI-16) rather than the stale "run the daemon
				// under WSL/Linux", which has been wrong since ConPTY landed
				// (a6cc151c3, 2026-07-04): a native Windows daemon runs these
				// terminals fine when it's new enough. The
				// allow_dashboard_launch=false cause is reported where that
				// gate lives (the dashboard's 503 copy).
				fmt.Fprintln(cmd.ErrOrStderr(),
					"session-attach ([terminal.attach].enabled) is on but the embedded terminal is unsupported on this OS "+
						"(Windows before 10 version 1809 has no ConPTY; other platforms need a PTY backend).")
			case attachHostImpl == nil:
				// Defensive: enabled + PTY-capable but no terminal stack was
				// derived this run. With the decoupling above this should not
				// happen (the attach host is built whenever attach is enabled),
				// so name the surface honestly rather than pretend it serves.
				fmt.Fprintln(cmd.ErrOrStderr(),
					"session-attach ([terminal.attach].enabled) is on but no terminal stack was built this run; attach is unavailable.")
			case !localipc.Supported():
				// This OS has no attach TRANSPORT whose owner-only security
				// model actually holds (DI-09 full): unix serves an AF_UNIX
				// socket under a 0700 directory, Windows a named pipe with a
				// protected owner-only DACL, and everything else — plan9,
				// js/wasm — has neither. The channel carries the writer lease
				// and any forwarded provider credentials, so we refuse rather
				// than open one the OS will not gate. Dashboard launch and
				// Jump-in via the in-dashboard terminal are unaffected — only
				// the standalone `--attach` client is.
				fmt.Fprintf(cmd.ErrOrStderr(),
					"session-attach ([terminal.attach].enabled) is on but there is no owner-only attach transport on this OS (%s) - "+
						"dashboard launch and Jump-in via the terminal still work; `observer <tool> --attach` does not.\n",
					runtime.GOOS)
			default:
				endpoint, eerr := attachEndpoint(cfgForLock.Observer.DBPath)
				if eerr != nil {
					// The endpoint itself is unusable (on unix: a socket path
					// past UNIX_PATH_MAX). The transport's message names the
					// cause and the fix; don't bury it.
					fmt.Fprintf(cmd.ErrOrStderr(), "session-attach disabled: %v\n", eerr)
				} else {
					ln, lerr := localipc.ListenSocket(endpoint)
					if lerr != nil {
						fmt.Fprintf(cmd.ErrOrStderr(), "session-attach disabled: cannot listen on %s: %v\n", endpoint, lerr)
					} else {
						fmt.Fprintf(cmd.OutOrStdout(), "  session-attach → %s (%s; observer <tool> --attach)\n",
							endpoint, localipc.DefaultTransport().Describe())
						host := attachHostImpl
						ng.Go("attach-socket", func() error {
							// Serve closes ln on gctx-cancel. On unix ln.Close
							// (the lockedListener) OWNS the socket unlink —
							// ordered before its flock release and
							// inode-guarded — so a restart re-binds cleanly.
							// We must NOT os.Remove the path here: by the time
							// Serve returns a replacement daemon may already
							// hold the lock and have bound a NEW socket at the
							// same path, and an unconditional remove would
							// destroy IT (F3). On Windows the pipe object
							// disappears with its last handle, so Close is the
							// whole teardown. A serve error is logged, never
							// propagated.
							serr := serveAttach(gctx, ln, host, slog.Default())
							_ = ln.Close()
							if serr != nil && !errors.Is(serr, context.Canceled) {
								fmt.Fprintf(cmd.ErrOrStderr(), "session-attach: %v\n", serr)
							}
							return nil
						})
					}
				}
			}
			// Phase 2 (plan §4.4): the tailnet-serve backend — a SECOND loopback
			// listener, remote-exposed (auth for every request), that
			// `tailscale serve` forwards to. Distinct from the owner-trusted
			// direct dashboard listener above.
			if dashboardServer != nil && remoteBackendAddr != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "  remote (tailnet backend) → %s\n", remoteBackendAddr)
				ng.Go("tailnet-backend", func() error {
					if err := dashboardServer.ListenAndServeTailnetBackend(gctx, remoteBackendAddr); err != nil && !errors.Is(err, context.Canceled) {
						return fmt.Errorf("remote backend: %w", err)
					}
					return nil
				})
			}
			// T-849 (tamper audit fixes 7 + 8): hook maintenance on the
			// policy-state heartbeat. On a managed node it re-runs the
			// idempotent auto-registration (each repair is logged and
			// reported as hook_repaired naming the tool and the file) and
			// then reports the managed-integrity probe, instead of waiting
			// for a restart and the 900 s push. An individual node keeps the
			// start-only behaviour unless [observer.hooks] periodic_register
			// says "always"; auto_register = false is always respected.
			{
				var managedFn func(context.Context) bool
				var reportFn func(context.Context)
				if orgClient != nil {
					managedFn = orgClient.IsManagedEnrolment
					reportFn = func(c context.Context) { orgClient.ReportManagedIntegrity(c) }
				}
				hm := newHookMaintenance(cfgForLock, lockErr == nil, configPath, cmd.OutOrStdout(), cmd.ErrOrStderr(), managedFn, reportFn)
				// Lane P1: on a managed node whose organization governs an
				// enforcement point in the API proxy, the same loop keeps the
				// routable AI tools routed through this proxy (written once the
				// proxy serves, repaired every heartbeat). Built only with an
				// org client, so an individual node never writes a route.
				if orgClient != nil {
					hm.routes = newRouteMaintenance(configPath, addr,
						func(c context.Context) govern.RoutePostureVerdict { return ngov.Effective(c).RoutePosture() },
						routeLanes, cmd.OutOrStdout(), cmd.ErrOrStderr())
					// CLI-1b (D6): the same heartbeat keeps the native
					// command wrap applied (or removes the one it applied)
					// when the admin pinned shell_wrap.org_maintain.
					hm.routes = withShellWrapMaintenance(hm.routes, newShellWrapMaintenance(configPath,
						func(c context.Context) govern.ShellWrapPostureVerdict { return ngov.Effective(c).ShellWrapPosture() },
						cmd.OutOrStdout(), cmd.ErrOrStderr()))
					hm.waitProxy = func(c context.Context) {
						wctx, cancel := context.WithTimeout(c, 2*time.Minute)
						defer cancel()
						waitForListener(wctx, addr)
					}
				}
				ng.Go("hook-maintenance", func() error {
					hm.run(gctx)
					return nil
				})
			}
			if orgClient != nil {
				// P0-7 router hot-reload (docs/plans/plane-a-p0-7-guard-router-
				// hotreload-plan.md §4.4/§4.5): apply an accepted org routing
				// policy to the LIVE router in-process, so P0-6 flips the router
				// point pending_restart -> effective with no daemon restart. The
				// sink fires on every accepted routing-fetch cycle (both newly-
				// cached and already-current arms, SF7). Reload is nil-safe when
				// routing is off (routingHandle nil / closure unset), so this
				// registration is unconditional. It fires BEFORE the P0-6 routing
				// outcome sink (SF8) because the sink runs inside FetchRoutingPolicy,
				// which returns before PushLoop pokes the outcome sink.
				orgClient.SetRoutingReloadSink(func(ctx context.Context) {
					if rerr := routingHandle.Reload(ctx); rerr != nil {
						fmt.Fprintf(cmd.ErrOrStderr(), "routing: org policy hot-reload failed: %v\n", rerr)
					}
				})
				// Arc 4 P3b managed-enforce (§R23 lift): let the live router
				// honor the org routing body's mode ONLY on a managed node that
				// holds enforce.routing. Resolved live from the governance grant;
				// nil-safe + inert on every individual/BYO node (the token is
				// stripped there). Injected here, where both the router handle
				// and the governance handle exist (buildProxy predates ngov).
				routingHandle.SetManagedEnforce(func() bool {
					return ngov.Effective(context.Background()).GrantsRoutingEnforcement()
				})
				// P0-5 policy-resource → P0-6 reporter seam: the policy-state
				// reporter is constructed below on every org-client node, and its
				// recordPolicyResource sink is handed to the policy-resource
				// poller so admitter/egress last-fetch slots populate.
				var policyResourceSink policyResourceOutcomeSink
				// P0-6 effective-policy-state reporter (docs/plans/plane-a-p0-6-
				// effective-policy-state-plan.md §4.3): an independent daemon reporter
				// emits a four-row desired/effective snapshot at startup + heartbeat +
				// on-change. The SEND gate is the reporter's own effectiveEnabled:
				// the local [org_client.share].policy_state opt-in (default off),
				// LOWERED by a node.governance share directive and — on a managed
				// node holding extract.policy_state — RAISED by one. The reporter
				// is therefore CONSTRUCTED whenever the org client is on, never
				// only when the local file already says yes: a node whose TOML
				// left the key off would otherwise have no reporter for the org's
				// raise to act on, and the org would read every governed developer
				// as governance_lapsed forever (D-DEMO-13, demo estate 2026-09-21).
				// A node that is neither opted in nor raised keeps the reporter
				// DORMANT (report() returns before any read or send). Self-
				// contained DB handle + the shared (memoized) process guard; the two
				// outcome sinks are registered BEFORE the poll loops so the first
				// fetch outcome is captured. Nil-sink no-op until registered (R6-1).
				{
					if rcfg, rdb, rcleanup, rerr := loadConfigAndDB(gctx, configPath); rerr == nil {
						rlogger := newLogger(rcfg.Observer.LogLevel)
						rst := store.New(rdb)
						rguard := acquireProcessGuard(gctx, rcfg, rst, rlogger)
						rep := buildPolicyStateReporter(orgClient, rguard, rst, admissionHandle, routingHandle, gw, ngov, nf, rcfg, version, rlogger)
						orgClient.SetGuardOutcomeSink(rep.recordGuard)
						orgClient.SetRoutingOutcomeSink(rep.recordRouting)
						policyResourceSink = rep.recordPolicyResource
						ng.Go("policy-state-reporter", func() error {
							defer rcleanup()
							return rep.run(gctx, policyStateHeartbeat(rcfg))
						})
					} else {
						fmt.Fprintf(cmd.ErrOrStderr(), "policy-state reporter disabled: db open failed: %v\n", rerr)
					}
				}
				// COLD START for the BUDGET rail (finding H3), and the first
				// moment it is honest to publish a posture: the governance
				// identity loader is installed by now, so the managed /
				// enforce.budget capability resolves truthfully.
				//
				// The persisted document (agent migration 119) is restored
				// FIRST, so a restarted daemon continues with exactly the caps
				// the previous process enforced instead of spending a push
				// interval either uncapped (a restart-to-bypass window) or —
				// on a node that requires an org budget — blocking with a body
				// it already had on disk.
				if budgetWire != nil {
					primed, perr := orgClient.LoadPersistedBudget(ctx)
					if perr != nil {
						slog.Default().Warn("org budget: could not load the persisted document", "err", perr)
					}
					budgetWire.Prime(primed)
				}
				// The org push loop never propagates an error: a stuck/failing
				// push must never cancel the proxy, watcher, or dashboard (P1).
				// PushLoop already WARN-logs failures and stops cleanly on an
				// auth failure or ctx-cancel. Its FIRST cycle runs immediately
				// rather than one interval later (finding H3b), so the budget
				// rail's first real answer arrives in seconds.
				// The module managed pulls (roadmap F0-7): only rails whose
				// consuming module is active register, so an install that
				// uses none makes no request (managedpull_wire.go).
				wireManagedPullRails(ctx, orgClient, comps, ngov)
				ng.Go("org-push", func() error {
					_ = orgClient.PushLoop(gctx)
					return nil
				})
				// Policy freshness (P2, 2026-10-02 budget-latency arc): node
				// activity - a proxied request, a prompt hook's activity
				// stamp - triggers a tiny conditional probe of the org's
				// policy version vector (30 s floor, 5 min backstop), and only
				// the rails that moved are fetched through their own signed
				// paths. Like the push loop it never propagates an error.
				processNodeActivity.Subscribe(func(string) { orgClient.NoteActivity() })
				// Activity-driven push (P3): new rows pull the next push
				// forward (15 s floor, 3-10 s coalesce, ceiling = the push
				// interval; internal/pushsched).
				processNodeActivity.Subscribe(func(kind string) {
					if isPushActivity(kind) {
						orgClient.NotePushActivity()
					}
				})
				ng.Go("policy-freshness", func() error {
					_ = orgClient.PolicyFreshnessLoop(gctx)
					return nil
				})
				ng.Go("activity-stamp", func() error {
					watchActivityStamp(gctx, cfgForLock.Observer.DBPath, processNodeActivity.Note)
					return nil
				})
				// Org policy-bundle poll (guard spec §14.2): fetch once at
				// start + every policy_poll_interval; verified bundles
				// land in the local cache the guard's org layer loads
				// from, rejections emit R-205 through the runner. Gated
				// on the guard being on (a guard-off agent ignores the
				// channel — the §14.2 compat posture) and P1 like every
				// sibling: never propagates an error.
				ng.Go("org-policy-bundle-poll", func() error {
					pcfg, pdb, pcleanup, perr := loadConfigAndDB(gctx, configPath)
					if perr != nil {
						return nil
					}
					defer pcleanup()
					if !pcfg.Guard.Enabled || pcfg.Guard.Mode == "off" {
						return nil
					}
					cachePath := orgBundleCachePath(pcfg)
					if cachePath == "" {
						return nil
					}
					plogger := newLogger(pcfg.Observer.LogLevel)
					runner := newPolicyBundleRunner(pcfg, store.New(pdb), plogger,
						strings.TrimRight(pcfg.OrgClient.OrgServerURL, "/"))
					// An applied org bundle can change enforcement:
					// re-publish the hook posture right away.
					runner.onGuardReload = func(gd *guard.Guard) {
						publishGuardPosture(configPath, pcfg.Guard, gd, plogger)
					}
					// The posture loop wakes this poll the moment it finds
					// the cached bundle edited or deleted (T-864 gap 1).
					setProcessPolicyBundleKick(orgClient.KickPolicyBundlePoll)
					defer setProcessPolicyBundleKick(nil)
					_ = orgClient.PolicyPollLoop(gctx, cachePath, runner.onResult)
					return nil
				})
				// The project audience matcher (project_audience.go): match
				// records for recently active project roots, once the org
				// delivered a v3 project-scoped bundle. Never propagates an
				// error.
				ng.Go("project-audience-match", func() error {
					mcfg, mdb, mcleanup, merr := loadConfigAndDB(gctx, configPath)
					if merr != nil {
						return nil
					}
					defer mcleanup()
					runProjectAudienceMatch(gctx, orgBundleCachePath(mcfg), store.New(mdb), orgClient.ResolveProject)
					return nil
				})
				// Plane-A P0-5 Phase W (plan §6.6/§6.9): poll every v1
				// policy-resource family whenever enrolled, independent
				// of accept_families — applying accepted/inert bodies
				// onto the shared admission service's Org layer
				// (admission.input, egress.routing_guardrail) AND — Phase
				// 3, gateway config plane spec — the proxy's live lane
				// table (gateway.providers), clearing them on
				// ErrNotEnrolled or an identity/generation mismatch. P1
				// like every sibling poll loop: never propagates an
				// error.
				ng.Go("policy-resource-poller", func() error {
					pcfg, ok := cfgForLock, lockErr == nil
					if !ok {
						return nil
					}
					runPolicyResourcePoller(gctx, pcfg, orgClient, admissionHandle, gw, ngov, nf, policyResourceSink, newLogger(pcfg.Observer.LogLevel))
					return nil
				})
				// Grant renewal (§4). P1 like every sibling loop: it never
				// propagates an error, and a node that cannot renew simply
				// lapses at its current expiry — which is the offboarding
				// behaviour, not a failure.
				ng.Go("grant-renewal", func() error {
					rcfg, rdb, rcleanup, rerr := loadConfigAndDB(gctx, configPath)
					if rerr != nil {
						return nil
					}
					defer rcleanup()
					runGrantRenewal(gctx, orgClient, store.New(rdb), renewalTracker, newLogger(rcfg.Observer.LogLevel))
					return nil
				})
			}
			// Agent Access P4 (mcprelay_wire.go): the node MCP relay runtime
			// under [mcp_relay].enabled — relay + hash-chained record store +
			// the optional dedicated loopback listener. Runs on enrolled AND
			// individual nodes (an individual node dials a gateway only when
			// [mcp_relay].gateway_url is set). P1 like every sibling: never
			// propagates an error; a failed start logs and the seams bound by
			// buildProxy keep answering from the cached table.
			ng.Go("mcp-relay", func() error {
				h := processMCPRelay.Load()
				if h == nil {
					return nil
				}
				mcfg, mdb, mcleanup, merr := loadConfigAndDB(gctx, configPath)
				if merr != nil {
					return nil
				}
				defer mcleanup()
				mlogger := newLogger(mcfg.Observer.LogLevel)
				if _, rerr := startMCPRelayRuntime(gctx, mcfg, mdb, store.New(mdb), h, mlogger); rerr != nil {
					mlogger.Warn("mcp-relay: runtime start failed; node-side seams keep answering from the cached table", "err", rerr)
					return nil
				}
				<-gctx.Done()
				return nil
			})
			// Guard cloud tier (guard spec §15, D1 explicit opt-in):
			// daemon-resident dispatcher sweeping the guard_events tail
			// to the configured webhooks + LLM judge through the single
			// notify.Egress worker. Fail-soft and P1 like every sibling:
			// the goroutine never propagates an error, and a cloud
			// outage degrades to core local behaviour. Gated on guard
			// on + [guard.cloud].enabled + at least one event-fed
			// feature configured (reputation alone is the on-demand
			// CLI surface).
			ng.Go("guard-cloud", func() error {
				ccfg, cdb, ccleanup, cerr := loadConfigAndDB(gctx, configPath)
				if cerr != nil {
					return nil
				}
				defer ccleanup()
				if !ccfg.Guard.Enabled || ccfg.Guard.Mode == "off" || !ccfg.Guard.Cloud.Enabled {
					return nil
				}
				clogger := newLogger(ccfg.Observer.LogLevel)
				d := newCloudDispatcher(ccfg.Guard.Cloud, store.New(cdb), clogger, nil)
				if !d.hasEventFeatures() {
					d.egress.Close()
					return nil
				}
				clogger.Info("guard cloud: dispatcher running",
					"webhooks", len(ccfg.Guard.Cloud.Webhooks),
					"llm_judge", ccfg.Guard.Cloud.LLMJudge.Enabled)
				d.run(gctx)
				return nil
			})
			if otelExporter != nil {
				// The OTel exporter never propagates an error: a failing or
				// unreachable collector must never cancel the proxy, watcher,
				// dashboard, or push loop (P1). Start returns when gctx-cancel
				// closes the row tail; then flush remaining spans with a
				// detached, bounded context so shutdown doesn't drop them.
				ng.Go("otel-exporter", func() error {
					if err := otelExporter.Start(gctx); err != nil && !errors.Is(err, context.Canceled) {
						fmt.Fprintf(cmd.ErrOrStderr(), "otel exporter stopped: %v\n", err)
					}
					sctx, scancel := context.WithTimeout(context.WithoutCancel(gctx), 5*time.Second)
					_ = otelExporter.Stop(sctx)
					scancel()
					return nil
				})
				// Guard-event OTel feed (guard spec §11.4, G16): sweeps the
				// guard_events tail into the same exporter rail. Doubly
				// gated — the exporter exists only under [exporter.otel]
				// enabled, and the tail additionally requires guard on +
				// [guard.export].otel (both default off). Fail-soft and P1
				// like every sibling; the exporter's Stop above flushes
				// whatever this tail emitted.
				ng.Go("guard-otel-tail", func() error {
					tcfg, tdb, tcleanup, terr := loadConfigAndDB(gctx, configPath)
					if terr != nil {
						return nil
					}
					defer tcleanup()
					if !tcfg.Guard.Enabled || tcfg.Guard.Mode == "off" || !tcfg.Guard.Export.OTel {
						return nil
					}
					tlogger := newLogger(tcfg.Observer.LogLevel)
					tail := &guardOTelTail{
						st: store.New(tdb), sink: otelExporter, logger: tlogger,
						interval: time.Duration(tcfg.Exporter.OTel.PollIntervalSeconds) * time.Second,
					}
					tlogger.Info("guard otel: guard-event tail running",
						"endpoint", tcfg.Exporter.OTel.Endpoint)
					tail.run(gctx)
					return nil
				})
			}
			// Native OTLP receiver (native-console Rail A, made vendor-agnostic
			// by T-475): ingests any mapped AI tool's own telemetry export
			// (internal/otlpvendor: Claude Code, Codex, Gemini CLI, Qwen Code,
			// Copilot, ...) straight into the store, deduped against the proxy
			// and the tool's transcript. Gated by [ingest.otel] enabled
			// (default off → no listener, solo-local UX unchanged), loopback-
			// only unless allow_non_loopback, which then requires the receiver
			// token. Fail-soft + P1: a bind failure logs and returns nil,
			// never cancelling siblings.
			ng.Go("otlp-receiver", func() error {
				rcfg, rdb, rcleanup, rerr := loadConfigAndDB(gctx, configPath)
				if rerr != nil {
					return nil
				}
				defer rcleanup()
				// The shared OTLP receiver serves logs when [ingest.otel]
				// is on and traces when [observability] is on (the obs
				// subsystem registers its trace handler here — the single
				// host->obs seam, build-tagged). Off only when both are off.
				if !rcfg.Ingest.OTel.Enabled && !rcfg.Observability.Enabled {
					return nil
				}
				rlogger := newLogger(rcfg.Observer.LogLevel)
				opts := otlpingest.Options{
					GRPCAddr:         rcfg.Ingest.OTel.GRPCAddr,
					HTTPAddr:         rcfg.Ingest.OTel.HTTPAddr,
					AllowNonLoopback: rcfg.Ingest.OTel.AllowNonLoopback,
					Logger:           rlogger,
				}
				// A receiver opened to the network authenticates every
				// request (SR27-B5, T-475): the shared token is generated
				// once and kept 0600 beside the DB. Fail closed: no
				// token, no non-loopback listener.
				if rcfg.Ingest.OTel.AllowNonLoopback {
					tok, terr := resolveLocalTokenFile(otlpIngestTokenPath(rcfg))
					if terr != nil {
						fmt.Fprintf(cmd.ErrOrStderr(), "otlp receiver disabled: allow_non_loopback needs a receiver token and it could not be resolved: %v\n", terr)
						return nil
					}
					opts.RequireToken, opts.ReceiverToken = true, tok
					rlogger.Info("otlp receiver: non-loopback bind requires the receiver token header",
						"header", otlpingest.HeaderEdgeToken, "token_file", otlpIngestTokenPath(rcfg))
				}
				// Plane A (internal/obs) gets every trace resource no
				// coding-tool mapping row claims; Plane B (the vendor
				// table) gets the claimed ones, plus every logs export.
				planeA := newObsTraceHandler(gctx, rcfg, rdb, rlogger)
				opts.TraceHandler = planeA
				if rcfg.Ingest.OTel.Enabled {
					// The vendor table and logs handler belong to
					// ingest.otlp (otlp_ingest.go / otlp_ingest_omit.go).
					opts.Handler, opts.TraceHandler = wireVendorOTLPIngest(gctx, rcfg, rdb, rlogger, planeA)
				}
				if opts.Handler == nil && opts.TraceHandler == nil {
					return nil // nothing this build can serve
				}
				recv, err := otlpingest.New(opts)
				if err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "otlp receiver disabled: init failed: %v\n", err)
					return nil
				}
				recv.Start()
				<-gctx.Done()
				sctx, scancel := context.WithTimeout(context.WithoutCancel(gctx), 5*time.Second)
				_ = recv.Shutdown(sctx)
				scancel()
				return nil
			})
			// Browser-chatbot loopback ingest listener (opt-in alternate to
			// the native-messaging bridge). Gated by [browser].enabled AND
			// [browser.listener].enabled (both default so the LISTENER is
			// OFF — the bridge is the default receiver). Its own dedicated
			// loopback port (default 127.0.0.1:8821), never :8820 / the
			// dashboard mux. ONE OWNER: the injected Handler funnels every
			// body through ingestBrowserTurn — the SAME browserchat.Normalize
			// → store.Ingest path the `observer browser hook` command uses,
			// so the transport is a deployment detail, not a schema fork.
			// Fail-soft + P1: a bind failure logs and returns nil, never
			// cancelling siblings.
			ng.Go("browser-listener", func() error {
				bcfg, bdb, bcleanup, berr := loadConfigAndDB(gctx, configPath)
				if berr != nil {
					return nil
				}
				defer bcleanup()
				if !bcfg.Browser.Enabled || !bcfg.Browser.Listener.Enabled {
					return nil // rail or listener off — native-messaging bridge only.
				}
				blogger := newLogger(bcfg.Observer.LogLevel)
				bst := store.New(bdb)
				// Same guard as the watcher (acquireProcessGuard keys on the
				// DB path), so a browser prompt arriving over the loopback
				// rail runs the post-hoc capture lane at ingest instead of
				// waiting for `observer guard rescan` (PGC-2 / P3).
				wireGuard(gctx, bcfg, bst, blogger)
				browserCfg := bcfg.Browser
				browserHealthPath := filepath.Join(browserObserverDir(bcfg), browserHealthFileName)
				// Resolve the shared ingress token: the configured value, else
				// an auto-generated one persisted 0600 next to the observer DB
				// so the clientless loopback listener is never unauthenticated
				// (A4). A resolution failure logs but does not disable the rail
				// (fail-soft) — the receiver still enforces loopback-only.
				browserToken, terr := resolveBrowserIngestToken(bcfg)
				if terr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "browser listener: token resolve failed (%v) - continuing loopback-only\n", terr)
				}
				recv, err := browseringest.New(browseringest.Options{
					Addr:             bcfg.Browser.Listener.ListenAddr,
					AllowNonLoopback: bcfg.Browser.Listener.AllowNonLoopback,
					Token:            browserToken,
					Logger:           blogger,
					Handler: func(ctx context.Context, body []byte) error {
						return ingestBrowserTurn(ctx, bst, body, browserCfg, browserHealthPath)
					},
				})
				if err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "browser listener disabled: init failed: %v\n", err)
					return nil
				}
				recv.Start()
				<-gctx.Done()
				sctx, scancel := context.WithTimeout(context.WithoutCancel(gctx), 5*time.Second)
				_ = recv.Shutdown(sctx)
				scancel()
				return nil
			})
			// Node-side observability alert evaluator (general-observability
			// gap-audit item #9): threshold rules over THIS node's own local
			// obs_* data, so a node with org sharing off still gets error-rate
			// / cost / p95 alerting. Gated by [observability] + [observability.
			// alerts] both enabled (obsAlertLoop returns immediately otherwise,
			// and is a no-op under the no_obs build). Fires an outbound webhook
			// per crossing — the reason it is opt-in + default-off. Fail-soft +
			// P1 like every sibling: a webhook outage degrades to local
			// recording and never cancels proxy/watcher/dashboard.
			ng.Go("obs-alerts", func() error {
				obsAlertLoop(gctx, configPath)
				return nil
			})
			// Hook failure semantics (hook-parity audit section 5.7): the
			// ONE writer of guard-posture.json (the hook reads it before
			// stdin to decide whether a gate hook failure blocks) and the
			// ONE drainer of guard-hookfail.jsonl into guard_events. P1
			// like every sibling: never cancels proxy/watcher/dashboard.
			ng.Go("guard-posture", func() error {
				guardPostureLoop(gctx, configPath)
				return nil
			})
			// Code security (security pillar Phase A): the signed posture
			// writer and the quick-scan endpoint, both moduleGates rows.
			startSecurityModule(gctx, ng, configPath, comps)
			// Repository trust (security Phase B): the config baseline
			// loop, a moduleGates row of security.trust.
			startRepoTrustBaseline(gctx, ng, configPath, comps)
			// R-112 to R-114 (D-761): the ONE writer of
			// guard-git-aliases.json, the per-project git alias table the
			// hook reads so an alias that hides `--no-verify` is judged as
			// what it runs, without the hook ever running git. P1 like
			// every sibling.
			ng.Go("guard-git-aliases", func() error {
				gitAliasLoop(gctx, configPath)
				return nil
			})
			// T-323: a user guard-policy.toml that does not load is
			// dropped (built-ins + the org bundle stay in force); this
			// loop makes that loud with one guard event per distinct file
			// content, which reaches the org on the guard_events push.
			// P1 like every sibling.
			ng.Go("guard-user-policy", func() error {
				guardUserPolicyLoop(gctx, configPath)
				return nil
			})
			// The ONE drainer of the lifecycle hook spool (hook-parity Lane
			// C1): lifecycle hooks append session / turn / sub-agent end rows
			// DB-free beside the config; this loop ingests them. P1 like
			// every sibling.
			ng.Go("hook-lifecycle", func() error {
				hookLifecycleLoop(gctx, configPath)
				return nil
			})
			// Scheduled personal cost digest (gap-register G13): a weekly /
			// monthly per-tool/per-model observed-spend rollup emailed through
			// the shared [email] channel. Gated by [digest].enabled AND
			// [email].enabled (digestLoop returns immediately otherwise).
			// Fail-soft + P1 like obsAlertLoop: a digest outage logs a warning
			// and never cancels proxy/watcher/dashboard.
			ng.Go("digest", func() error {
				digestLoop(gctx, configPath)
				return nil
			})
			// Advisor digest refresher (plan Phase 3): keeps the one-row
			// advisor_digest snapshot warm so the session-start hook and
			// the MCP get_suggestions tool point-read instead of
			// computing. Self-contained config+DB handle; best-effort
			// (P1) — failures log and never cancel siblings.
			ng.Go("advisor-digest", func() error {
				acfg, adb, acleanup, aerr := loadConfigAndDB(gctx, configPath)
				if aerr != nil || !acfg.Advisor.Enabled {
					return nil
				}
				defer acleanup()
				refresh := func() {
					guardMode, routingMode, shadow := advisorPostureInputs(gctx, acfg, store.New(adb), acfg.Advisor.WindowDays)
					rep, rerr := advisor.Run(gctx, adb, advisor.Options{
						WindowDays:    acfg.Advisor.WindowDays,
						MinConfidence: acfg.Advisor.MinConfidence,
						MinSavingsUSD: acfg.Advisor.MinSavingsUSD,
						CostEngine:    acquireProcessCostEngine(gctx, acfg, adb, slog.Default()),
						GuardMode:     guardMode,
						RoutingMode:   routingMode,
						RoutingShadow: shadow,
						ContextWindow: advisorContextWindows(gctx, store.New(adb)),
					})
					if rerr == nil {
						rerr = advisor.SaveDigest(gctx, adb, rep, 5)
					}
					if rerr != nil && !errors.Is(rerr, context.Canceled) {
						fmt.Fprintf(cmd.ErrOrStderr(), "advisor digest refresh: %v\n", rerr)
					}
				}
				refresh()
				every := acfg.Advisor.DigestRefreshMinutes
				if every <= 0 {
					every = 30
				}
				ticker := time.NewTicker(time.Duration(every) * time.Minute)
				defer ticker.Stop()
				for {
					select {
					case <-gctx.Done():
						return nil
					case <-ticker.C:
						refresh()
					}
				}
			})
			// Guard baseline scans (spec §9.2 + §13.2): pin every
			// configured MCP server on daemon start so first-sight
			// baselines exist before any session traffic (changes made
			// while the daemon was down surface as R-301/305 now), and
			// re-verify pinned native-dialect artifacts against the
			// current policy (drift while down surfaces as R-204 now).
			// One pass each, best-effort (P1) — failures log inside the
			// runners and never cancel siblings. Live config edits
			// re-check via the shared watcher trigger (guardwire.go).
			ng.Go("guard-baseline-scan", func() error {
				mcfg, mdb, mcleanup, merr := loadConfigAndDB(gctx, configPath)
				if merr != nil {
					return nil
				}
				defer mcleanup()
				if !mcfg.Guard.Enabled || mcfg.Guard.Mode == "off" {
					return nil
				}
				if !mcfg.Guard.MCP.Pinning && !mcfg.Guard.Dialects.Compile {
					return nil
				}
				logger := newLogger(mcfg.Observer.LogLevel)
				st := store.New(mdb)
				gd := acquireProcessGuard(gctx, mcfg, st, logger)
				if gd == nil {
					return nil
				}
				if mcfg.Guard.MCP.Pinning {
					runner := newMCPSecRunner(configGuardMCP{
						Pinning:             mcfg.Guard.MCP.Pinning,
						PoisoningHeuristics: mcfg.Guard.MCP.PoisoningHeuristics,
					}, st, gd, logger)
					sum := runner.ScanConfigs(gctx)
					if sum.Servers > 0 || len(sum.Findings) > 0 {
						logger.Info("guard mcp: baseline scan",
							"servers", sum.Servers, "new_pins", sum.NewPins, "findings", len(sum.Findings))
					}
				}
				if mcfg.Guard.Dialects.Compile {
					if dr := newDialectRunner(configGuardDialects{
						Compile: mcfg.Guard.Dialects.Compile,
						Targets: mcfg.Guard.Dialects.Targets,
					}, st, gd, logger); dr != nil {
						sum := dr.CheckDrift(gctx)
						if sum.Checked > 0 || len(sum.Drifted) > 0 {
							logger.Info("guard compile: baseline drift check",
								"pinned", sum.Checked, "drifted", len(sum.Drifted), "events", sum.EventsRecorded)
						}
					}
				}
				return nil
			})
			// Process Observability (docs/process-observability.md) — opt-in,
			// daemon-resident OS-level process capture. Gated on
			// [observer.process].enabled (default off) and fail-open: a
			// missing/unsupported backend or any runtime error degrades to a
			// WARN and never cancels the proxy/watcher/dashboard.
			ng.Go("process-observer", func() error {
				return runProcessObserver(gctx, configPath)
			})
			// Org intervention is an enrollment capability, independent of the
			// optional process-observation setting. It resolves live authority
			// on every action and includes already-running vendor processes.
			ng.Go("node-intervention", func() error {
				return runNodeIntervention(gctx, configPath, w)
			})
			waitErr := g.Wait()
			// Every component has returned: checkpoint the WAL once on the
			// daemon's own handle, then the deferred cleanups run (T-553).
			stopTracker.SetStage(shutdown.StageCheckpoint)
			checkpointOnShutdown(daemonDB)
			stopTracker.SetStage(shutdown.StageClosing)
			if ctx.Err() != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "shutdown: components stopped in %s; closing\n",
					stopWatchdog.Elapsed().Round(time.Millisecond))
			}
			if waitErr != nil && !errors.Is(waitErr, context.Canceled) {
				return waitErr
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&recipeName, "recipe", "", "DEPRECATED: run with the named compression profile ("+strings.Join(config.RecipeNames(), ", ")+") as the default for ALL proxy traffic this run. Use [profiles] in config.toml instead.")
	_ = cmd.Flags().MarkDeprecated("recipe", "recipes are now compression profiles resolved per provider - this run maps the name onto [profiles].default for all proxy traffic; set [profiles] in config.toml for a durable assignment (watcher-side [compression.shell]/[compression.indexing] recipe keys no longer apply)")
	cmd.Flags().IntVar(&port, "port", 0, "Override [proxy].port")
	cmd.Flags().StringVar(&bindAddr, "bind", "127.0.0.1", "Proxy bind address (default localhost only)")
	cmd.Flags().StringVar(&dashAddr, "dashboard-addr", "", "Dashboard listen address (default 127.0.0.1:8081)")
	cmd.Flags().BoolVar(&noDashboard, "no-dashboard", false, "Skip the dashboard goroutine")
	cmd.Flags().BoolVar(&noOpen, "no-open", false, "Don't auto-open the dashboard in a browser on interactive launches")
	return cmd
}

// orgClientShouldStart is the SINGLE predicate `observer start` consults
// before constructing the org client (push loop, guard-policy poll,
// announcement/routing-policy fetch, grant renewal). It replaces the old
// `cfg.OrgClient.Enrolled()` gate (Enabled && OrgServerURL != ""), which a
// code review (BLOCK-1) correctly rejected: a node can be legitimately
// enrolled — a real org_enrolment DB row, a real bearer credential — with
// a genuinely blank config org_server_url, because ensureOrgClientBlock
// (cmd/observer/org.go) is header-idempotent (an existing [org_client]
// table header means org_server_url is never written) and re-enrolling
// does not repair a config missing the field. The old gate silently
// switched off every org loop for that node.
//
// The true four-state gate:
//
//	enabled | configURL set | row exists | starts? | who dials
//	--------|---------------|------------|---------|---------------------------
//	false   | any           | any        | no      | (org rail off by choice)
//	true    | no            | no         | no      | nobody — genuinely never
//	        |               |            |         | enrolled; ONE startup notice
//	true    | yes           | no         | yes     | buildOrgClient IS constructed,
//	        |               |            |         | but every loop's first step
//	        |               |            |         | is store.LoadEnrolment — nil
//	        |               |            |         | there means errIdle/
//	        |               |            |         | ErrNotEnrolled immediately, so
//	        |               |            |         | NOTHING dials the config URL
//	        |               |            |         | (or anywhere) until `observer
//	        |               |            |         | enroll` persists a row (pinned
//	        |               |            |         | by
//	        |               |            |         | TestStartupConstructsOrgClientWithConfigURLButNoRow)
//	true    | no            | yes        | yes     | buildOrgClient; the loops
//	        |               |            |         | dial the PERSISTED row's URL
//	        |               |            |         | (orgclient.Client.PushOnce
//	        |               |            |         | reads it from the DB, not
//	        |               |            |         | from config)
//	true    | yes           | yes        | yes     | same as the row-only case;
//	        |               |            |         | config URL is unused here too
//
// hasEnrolment is injected I/O (a DB lookup) so this predicate itself
// stays pure and table-testable — see orgClientShouldStart_test.go.
func orgClientShouldStart(cfg config.OrgClientConfig, hasEnrolment func() bool) bool {
	if !cfg.Enabled {
		return false
	}
	if cfg.ConfiguredServerURL() {
		return true
	}
	return hasEnrolment()
}

// hasPersistedEnrolment does a minimal, read-only probe of the
// org_enrolment table — the same table internal/diag's checkOrgEnrolment
// and orgclient.Client.PushOnce already read — so orgClientShouldStart
// can tell a genuinely never-enrolled node (no row) from an
// already-enrolled one whose [org_client].org_server_url happens to be
// blank in config.
//
// Best-effort: any error opening or querying the DB is treated as
// "assume enrolled" (true) rather than "assume not enrolled". On an
// error we cannot tell which is true, and biasing toward NOT disabling a
// working org rail is the safer failure mode here — buildOrgClient's own
// DB open, right after this returns true, will surface a real DB problem
// through its normal WARN-only construction-failure path anyway (org
// mode must never block the daemon, P1). Biasing the other way would
// silently re-introduce the exact BLOCK-1 failure mode (a real enrolment
// going dark) on top of an unrelated, probably-transient DB hiccup.
func hasPersistedEnrolment(ctx context.Context, dbPath string) bool {
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		return true
	}
	defer database.Close()
	var n int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM org_enrolment`).Scan(&n); err != nil {
		return true
	}
	return n > 0
}

// announceDashboardReady dials listenAddr until a TCP connection
// succeeds (the dashboard goroutine binds it) or ctx is cancelled, then
// prints one "dashboard ready" line to w. It exists so `observer start`
// reports the URL as working only once it actually accepts connections —
// before the 2026-07-16 readiness-path fixes the banner printed the URL
// ~24s (a large-DB integrity scan) before the listener bound. Best-effort:
// a never-binding listener (immediate ctx-cancel / shutdown) prints
// nothing, and the earlier "(starting…)" URL line already located it.
func announceDashboardReady(ctx context.Context, w io.Writer, listenAddr, url string) {
	d := net.Dialer{Timeout: 500 * time.Millisecond}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, err := d.DialContext(ctx, "tcp", listenAddr)
		if err == nil {
			_ = conn.Close()
			fmt.Fprintf(w, "  dashboard ready → %s\n", url)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// autoRegisterHooks installs hooks for every tool the hook registry
// detects on the current host, idempotently. Output goes to stdout
// for installs, stderr for warnings; tools whose hooks are already
// up-to-date stay silent so steady-state restarts are quiet.
//
// This is the on-launch self-heal path: a fresh install (or a Cursor
// install that happens AFTER the daemon was first started, like the
// WSL+Windows-Cursor case) gets its hooks wired without the user
// having to discover and run `observer init`. The same idempotent
// register* implementations init.go calls are reused, so explicit
// `observer init` and on-launch auto-register cannot disagree.
//
// Force is left false: a non-observer entry in someone's hooks file
// is a clear signal that the user (or a different tool) put it
// there, and silently overwriting that on every observer start would
// be far worse than not auto-registering.
//
// A failure gets the same loud startup-WARN treatment
// diag.DetectCrossEnvSiblingDBs gets above (a "WARN " line on
// stderr naming the tool, the target file, the error, and a
// remediation hint) — this used to be a bare stderr line easy to
// miss on a long-running daemon whose stdout/stderr nobody reads,
// which is exactly how the Windows-Cursor bridge registration
// silently stayed broken for a month (see
// docs/audits/cursor-windows-capture-diagnosis-2026-08-07.md §4 F3).
// Every outcome — success or failure — is also persisted into
// hook_checksums.json via RecordAutoRegisterResult so it's
// inspectable later, not just at the moment this ran.
// promptLaneEnabled gates B4's PromptLaneOnly mechanisms: true means
// [guard.prompt].enabled && [guard.prompt].hook_lane, exactly the
// condition that lets the prompt-submit engine actually evaluate
// anything on the hook lane (internal/guard/promptguard.go's own
// Enabled/HookLane checks) — a mechanism whose ENTIRE hook surface is
// that one event has nothing to do when this is false.
func autoRegisterHooks(stdout, stderr io.Writer, configPath string, promptLaneEnabled bool) {
	autoRegisterHooksPass(stdout, stderr, configPath, promptLaneEnabled, false)
}

// autoRegisterHooksPass is autoRegisterHooks with the T-872 switch:
// repairOwned is true only for a MANAGED node's heartbeat pass
// (hookMaintenance), where an artifact Observer owns by name and installed
// before, but that no longer reads as Observer's (a plugin overwritten with an
// empty module, a stubbed entry under Observer's hook name), is rewritten and
// reported as hook_repaired instead of refused. Every other caller passes
// false and keeps the refusal.
func autoRegisterHooksPass(stdout, stderr io.Writer, configPath string, promptLaneEnabled, repairOwned bool) {
	// Component gate (modular packaging P1, ledger MODPKG-6): hooks are
	// registered only while integration.hooks is active, and only for
	// tools whose adapter is active, so a removed component's hooks never
	// come back on the next start.
	comps := componentSnapshotFor(configPath)
	if !comps.Active("integration.hooks") {
		return
	}
	reg, ok := newAutoRegisterRegistryWith(stderr, configPath, repairOwned)
	if !ok {
		return
	}
	// T-847: note a deleted hook_checksums.json before this pass recreates it.
	reg.BeginPass(hookRepairTracker, time.Now())
	for _, tool := range reg.Installed() {
		if !comps.AdapterActive(tool) {
			continue
		}
		autoRegisterTarget(reg, tool, promptLaneEnabled, stdout, stderr)
	}
	autoRepairMCP(stdout, stderr, configPath, comps)
}

// autoRepairMCP repairs an EXISTING Observer MCP entry whose command no
// longer exists (U2, FIX-UPGRADE): an npm or pip upgrade deletes the binary
// path an older init wrote, and only `observer init --force` used to fix
// it. MCP stays opt-in: nothing is added where no Observer entry exists,
// and an entry naming a command that still exists (another install, a
// user's own edit) is left alone (mcpregister RepairOnly). Gated like
// init's MCP step by integration.mcp-server.
func autoRepairMCP(stdout, stderr io.Writer, configPath string, comps componentstate.Snapshot) {
	if !comps.Active("integration.mcp-server") {
		return
	}
	binary, err := absoluteBinaryPath()
	if err != nil {
		return
	}
	resolvedConfig, _ := config.ResolveGlobalPath(configPath)
	command := mcpRegistrationCommand(binary, registrationStableMCPCommand(configPath))
	reg, err := mcpregister.NewRegistrar(mcpregister.RegisterOptions{
		BinaryPath: command,
		ConfigPath: registrationConfigArg(resolvedConfig, ""),
		SelfBinary: binary,
		RepairOnly: true,
	})
	if err != nil {
		return
	}
	for _, tool := range reg.Installed() {
		if !comps.AdapterActive(tool) {
			continue
		}
		res := reg.Register(tool)
		switch {
		case res.Error != nil:
			fmt.Fprintf(stderr, "WARN auto-repair mcp %s: %v\n", tool, res.Error)
		case res.Added:
			fmt.Fprintf(stdout, "auto-repair mcp %s: the observer entry in %s named a binary that no longer exists; it now runs %s\n",
				tool, res.ConfigPath, command)
		}
	}
}

// proxyStartLabel is the start banner's proxy half: today's "proxy <addr>",
// or a plain statement that the proxy listener is inactive.
func proxyStartLabel(addr string, comps componentstate.Snapshot) string {
	if !comps.Active("capture.proxy") {
		return "proxy inactive (capture.proxy)"
	}
	return "proxy " + addr
}

// autoRegisterOptions is the ONE builder of the hook.Options every
// auto-registration writes with (this binary, the resolved global config,
// the WSL distro, the owes-live filter). The dashboard's Connected tools
// hooks probe dry-runs through the same options (hookProbeOptionsSeam),
// because the registrars only count an entry as registered when its
// command matches the one they would write exactly (T-376).
func autoRegisterOptions(configPath string) (hook.Options, error) {
	binary, err := absoluteBinaryPath()
	if err != nil {
		return hook.Options{}, err
	}
	resolvedConfig, _ := config.ResolveGlobalPath(configPath)
	opts := hook.Options{
		WindowsPATH: hook.PersistentWindowsPATH,
		GOOS:        autoRegisterGOOS,
		// U1 + U5 (FIX-UPGRADE): the same command and --config argument
		// `observer init` writes (registration.go), so the two writers no
		// longer rewrite each other, and an npm / pip install registers the
		// package manager's launcher, which survives an upgrade.
		BinaryPath: registrationCommand(binary),
		// FU-214: a "-wsl" twin runs the observer.exe itself, never the
		// launcher BinaryPath may name.
		WSLTwinBinaryPath: registrationWSLTwinBinary(binary),
		ConfigPath:        registrationConfigArg(resolvedConfig, ""),
		WSLDistro:         os.Getenv("WSL_DISTRO_NAME"),
		SkipEvent:         autoRegisterSkipEvent,
		// T-725: a start from another binary path (or a hook written
		// without --config) must leave an equivalent existing hook, and
		// the user's file, untouched; only a missing or broken hook is
		// rewritten. The dashboard probe shares this, so it reports an
		// equivalent hook as registered.
		KeepEquivalentHooks: true,
		// A host that fails open on a hook failure is told to fail closed
		// while guard enforcement closes the tool gate (Goose on_failure).
		ToolGateFailsClosed: registrationToolGateFailsClosed(configPath),
		// AW-37: the fail-closed Windows hook bridge, for an enforcing
		// managed node (switched off behind LC6 inside the writer).
		WindowsBridgeFailClosed: registrationWindowsBridgeFailClosed(configPath),
		// A managed node with repository trust selected pins the plugin
		// shim's binary and config (security pillar plan 5.1 item 6).
		PinPluginPaths: registrationPinPluginPaths(configPath),
		// The security feedback's post-tool events (lane sec-h): written
		// only while security.feedback is selected, removed when it is not.
		Selected: registrationSelected(configPath, ""),
	}
	if autoRegisterWSLHost != nil {
		autoRegisterWSLHost(&opts)
	}
	return opts, nil
}

// autoRegisterWSLHost, when set, makes the auto-registration registry a
// Windows observer.exe's that sees one WSL home: a test seam only (nil in
// production), so a test on a Linux host can drive the Windows to WSL twins
// (FU-197) without a real \\wsl.localhost\ path. Production finds the home
// through crossmount (a Windows host's running distros, FU-189).
var autoRegisterWSLHost func(*hook.Options)

// autoRegisterGOOS is the OS the auto-registration registry writes for: ""
// (the running OS) in production. A test seam only, so a test on any host
// can drive the macOS-only Xcode agent-home targets (FU-145).
var autoRegisterGOOS = ""

// hookProbeOptionsSeam is the dashboard's Options.HookRegistryOptions:
// autoRegisterOptions with DryRun on (the dashboard forces it too).
func hookProbeOptionsSeam(configPath string) func() (hook.Options, error) {
	return func() (hook.Options, error) {
		opts, err := autoRegisterOptions(configPath)
		opts.DryRun = true
		return opts, err
	}
}

// newAutoRegisterRegistry builds the hook.Registry every auto-registration
// writes through (autoRegisterOptions).
func newAutoRegisterRegistry(stderr io.Writer, configPath string) (*hook.Registry, bool) {
	return newAutoRegisterRegistryWith(stderr, configPath, false)
}

// newAutoRegisterRegistryWith is newAutoRegisterRegistry with
// hook.Options.RepairOwnedArtifacts set to repairOwned (T-872: a managed
// node's repair pass only).
func newAutoRegisterRegistryWith(stderr io.Writer, configPath string, repairOwned bool) (*hook.Registry, bool) {
	opts, err := autoRegisterOptions(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "auto-register: cannot resolve binary path: %v\n", err)
		return nil, false
	}
	opts.RepairOwnedArtifacts = repairOwned
	reg, err := hook.NewRegistry(opts)
	if err != nil {
		fmt.Fprintf(stderr, "auto-register: %v\n", err)
		return nil, false
	}
	return reg, true
}

// autoRegisterOwesLive is the CLOSED set of bindings added to a
// grandfathered mechanism AFTER the live-grounding ruling (2026-10-02) that
// have not passed a live test yet: `observer start` does not write them
// (`observer init`, consented, does), so a grandfathered mechanism cannot
// carry a new doc-grounded event into auto-registration. Keyed "tool
// NativeEvent". TestAutoRegisterOwesLiveIsCurrent fails once an entry's
// binding is live (remove it) or is no longer registered.
var autoRegisterOwesLive = map[string]string{
	"poolside PreToolUse": "hook-parity A4: the pool CLI is not installed on demo node 1; doc-grounded",
	// Integration 5: the shell PreToolUse gate is no longer written (the
	// Lane D mod's beforeToolCall is the gate of record), so the entry
	// moved to the mod event. The mod is one file, so this keeps the gate
	// from being a REASON to auto-register; it cannot drop the event from
	// a mod written for the prompt gate.
	"command-code beforeToolCall": "hook-parity A4 / Lane D: command-code is not installed on demo node 1; doc-grounded",
	"devin pre_run_command":       "hook-parity A5: Windsurf / Devin Desktop is not installed on demo node 1; doc-grounded",
	"devin pre_write_code":        "hook-parity A5: Windsurf / Devin Desktop is not installed on demo node 1; doc-grounded",
	"devin pre_read_code":         "hook-parity A5: Windsurf / Devin Desktop is not installed on demo node 1; doc-grounded",
	"devin pre_mcp_tool_use":      "hook-parity A5: Windsurf / Devin Desktop is not installed on demo node 1; doc-grounded",
	// Review M2-10: droid's UserPromptSubmit has NEVER fired live (D-247;
	// on node 1 `droid exec` 0.233.0 fired PreToolUse from the same file but
	// never UserPromptSubmit). The grandfather basis ("worked before the
	// ruling") does not hold for a hook that never ran, so `observer start`
	// writes only the live PreToolUse gate, and the root-shape repair no
	// longer lifts a wrapped UserPromptSubmit group into activity.
	"droid UserPromptSubmit": "review M2-10: never fired live (D-247, droid exec 0.233.0 on node 1); doc-grounded",
}

// autoRegisterSkipEvent is `observer start`'s per-event filter (hook.Options
// SkipEvent): skip a binding that owes its live test.
func autoRegisterSkipEvent(tool, event string) bool {
	base := clientwire.HookTargetBase(tool)
	_, owes := autoRegisterOwesLive[base+" "+event]
	return owes
}

// autoRegisterTarget registers ONE target when autoRegisterDecision admits
// it, records the result in hook_checksums.json and reports it: the one
// per-target body every auto-registration shares.
func autoRegisterTarget(reg *hook.Registry, tool string, promptLaneEnabled bool, stdout, stderr io.Writer) {
	if !autoRegisterDecision(tool, promptLaneEnabled) {
		return
	}
	// T-847: Reconcile is Register plus the outcome record in
	// hook_checksums.json (tool, result, registered events) and the repair
	// classification the managed-integrity probe reports for a day.
	rec := reg.Reconcile(tool, hookRepairTracker, time.Now())
	res := rec.Result
	if rec.RecordErr != nil {
		fmt.Fprintf(stderr, "auto-register %s: failed to persist result to hook_checksums.json: %v\n", tool, rec.RecordErr)
	}
	logAutoRegisterRewrites(stdout, tool, res)
	if len(rec.Repaired) > 0 {
		fmt.Fprintf(stderr,
			"WARN auto-register %s: repaired %d previously registered hook(s) in %s: %s (reported to the org as hook_repaired on a managed node)\n",
			tool, len(rec.Repaired), res.ConfigPath, strings.Join(rec.Repaired, ", "))
	}
	switch {
	case res.Error != nil:
		fmt.Fprintf(stderr,
			"WARN auto-register %s: %s: %v - %s\n",
			tool, res.ConfigPath, res.Error, autoRegisterRemediation(tool))
	case len(res.HooksAdded) > 0:
		fmt.Fprintf(stdout,
			"auto-register %s: installed %d hook(s) at %s\n",
			tool, len(res.HooksAdded), res.ConfigPath)
	}
	if res.Error == nil && len(res.TrustRecorded) > 0 {
		fmt.Fprintf(stdout, "auto-register %s: recorded host trust for Observer's own hook(s): %s\n",
			tool, strings.Join(res.TrustRecorded, ", "))
	}
	if res.Error == nil && res.TrustNote != "" {
		fmt.Fprintf(stderr, "WARN auto-register %s: %s\n", tool, res.TrustNote)
	}
	logAutoRegisterWarnings(stderr, tool, res)
}

// logAutoRegisterWarnings prints a registration's non-fatal warnings (e.g. a
// Windows hook runner whose shell is not on the Windows PATH): the hooks are
// in place, but the host may not run them as launched today.
func logAutoRegisterWarnings(w io.Writer, tool string, res hook.RegistrationResult) {
	if res.Error != nil {
		return
	}
	for _, msg := range res.Warnings {
		fmt.Fprintf(w, "WARN auto-register %s: %s\n", tool, msg)
	}
}

// logAutoRegisterRewrites names every existing observer hook entry an
// auto-registration replaced and why (T-725), so a rewrite of the user's
// config file is never silent. Kept-equivalent entries are summarised in
// one line. Commands are paths and argument names only.
func logAutoRegisterRewrites(w io.Writer, tool string, res hook.RegistrationResult) {
	if res.DryRun || res.Error != nil {
		return
	}
	for _, rw := range res.Rewrites {
		fmt.Fprintf(w, "auto-register %s: rewrote hook %s in %s (%s): %q -> %q\n",
			tool, rw.Event, res.ConfigPath, rw.Reason, rw.From, rw.To)
	}
	if n := len(res.KeptEquivalent); n > 0 {
		fmt.Fprintf(w, "auto-register %s: kept %d equivalent existing hook(s) in %s unchanged\n",
			tool, n, res.ConfigPath)
	}
}

// autoRegisterInstalledTool is the post-guided-install twin of
// autoRegisterHooks: the same writer (hook.Registry.Register), the same
// per-target decision (autoRegisterDecision: capability, prompt lane, live
// gate) and the same result bookkeeping, scoped to the one tool the
// dashboard just installed, so its hooks land without a daemon restart. A
// successful guided install IS the detection signal for that tool, so the
// native target is registered even before the vendor created its config
// directory; a cross-OS "-windows" variant, an Xcode agent-home target
// (FU-145) and a WSL twin (FU-197) are registered only when detected,
// exactly as at start. The caller applies the [observer.hooks]
// auto_register switch (the same consent `observer start` honours).
func autoRegisterInstalledTool(stdout, stderr io.Writer, configPath string, promptLaneEnabled bool, tool string) {
	if comps := componentSnapshotFor(configPath); !comps.Active("integration.hooks") || !comps.AdapterActive(tool) {
		return
	}
	reg, ok := newAutoRegisterRegistry(stderr, configPath)
	if !ok {
		return
	}
	autoRegisterTarget(reg, tool, promptLaneEnabled, stdout, stderr)
	for _, t := range reg.Installed() {
		if t != tool && clientwire.HookTargetBase(t) == tool {
			autoRegisterTarget(reg, t, promptLaneEnabled, stdout, stderr)
		}
	}
}

// autoRegisterDecision is autoRegisterHooks' pure per-target decision:
// whether `observer start` registers tool (a hook.Registry.Installed()
// target, "-windows" variants included) given the prompt-lane switch. It
// writes nothing; the hook-parity golden gate calls it directly.
func autoRegisterDecision(tool string, promptLaneEnabled bool) bool {
	if !hookSupported(tool) {
		return false
	}
	// Capability-shaped gate (hook-parity Lane C2, audit section 5.4),
	// replacing B4's PromptLaneOnly skip: a mechanism is written only when
	// one of its WIRED bindings serves a feature that is on. A mechanism
	// whose wired bindings are all prompt-family (Gemini CLI, Poolside,
	// Cascade, commandcode) has nothing to do with the prompt hook lane off,
	// exactly as before; one that also wires lifecycle or capture bindings
	// (Claude Code, Cursor, Codex, and since Lane C Qwen Code and Qoder) is
	// always worth registering. advertisedCapability strips a
	// "-windows" suffix (B3, final-fix review), so a cross-OS bridge target
	// resolves the same capability as its native twin. Only the bindings
	// `observer start` would actually write count (autoRegisterSkipEvent
	// drops a tool gate that still owes its live test), so a mechanism whose
	// one non-prompt binding is skipped is not written for its prompt event
	// alone while the prompt lane is off.
	if !hookRegistrationWanted(tool, promptLaneEnabled, autoRegisterSkipEvent) {
		return false
	}
	// Live gate (hook-parity audit section 7 ruling 4, Lane 0 step 9):
	// `observer start` writes a vendor config only when every event it
	// registers passed a live test on a real install, or the mechanism is
	// grandfathered. Anything else is `observer init` only (consented).
	if _, initOnly := initOnlyHookTarget(tool, autoRegisterHostGOOS); initOnly {
		return false
	}
	// The target's own row: a "-windows" bridge's or an Xcode agent-home
	// target's base tool (clientwire.HookTargetCapability, FU-145).
	c, _ := clientwire.HookTargetCapability(tool)
	return autoRegisterLiveGate(c)
}

// initOnlyHookTargets are registration targets `observer start` does not
// write although their mechanism passed the live gate: the live run that
// admitted the mechanism covered another OS shape of it. Each row is one
// target on one host OS ("" = every host OS); a row goes when that shape
// passes its own live end-to-end run.
var initOnlyHookTargets = []struct {
	target, goos, reason string
}{
	// The 2026-10-21 wave was live-run on WSL Ubuntu (Linux shape); its
	// six "-windows" wsl.exe bridges (Windows vendor, WSL daemon) passed
	// their own live run on 2026-10-22 and left this table. The
	// Windows-native shapes (an observer.exe on the Windows host) have not.
	{"ibm-bob", "windows", "the Windows-native (cmd.exe) shape was not live-run (2026-10-21 E2E was WSL-native)"},
	{"codebuddy", "windows", "the Windows-native (Git Bash) shape was not live-run (2026-10-21 E2E was WSL-native)"},
	{"deepagents-code", "windows", "the Windows-native (cmd.exe) shape was not live-run (2026-10-21 E2E was WSL-native)"},
	{"dimcode", "windows", "the Windows-native (cmd.exe) shape was not live-run (2026-10-21 E2E was WSL-native)"},
	{"dirac", "windows", "the Windows-native .ps1 shape was not live-run (2026-10-21 E2E was WSL-native)"},
	{"vtcode", "windows", "the Windows-native (Git sh, %APPDATA% config) shape was not live-run (2026-10-21 E2E was WSL-native)"},
}

// autoRegisterHostGOOS is the host OS initOnlyHookTargets is read for (the
// running OS; the Linux hook-parity golden pins it).
var autoRegisterHostGOOS = runtime.GOOS

// initOnlyHookTarget reports the reason target is `observer init`-only on a
// host running goos.
func initOnlyHookTarget(target, goos string) (string, bool) {
	for _, row := range initOnlyHookTargets {
		if row.target == target && (row.goos == "" || row.goos == goos) {
			return row.reason, true
		}
	}
	return "", false
}

// hookRegistrationWanted is the capability-shaped registration gate shared
// by `observer start` (autoRegisterDecision) and `observer init`
// (wireAIClients): tool's mechanism carries a wired binding whose feature is
// on. The tool gate is treated as on here (refining it from [guard].mode is
// still open). skip, when non-nil, excludes the bindings the caller will not
// write (`observer start` passes autoRegisterSkipEvent; `observer init`
// writes every Registered binding and passes nil).
func hookRegistrationWanted(tool string, promptLaneEnabled bool, skip func(tool, event string) bool) bool {
	return clientwire.HookRegistrationWanted(tool, promptLaneEnabled, skip)
}

// grandfatheredAutoRegister is the CLOSED set of mechanisms `observer start`
// auto-registered before the live-grounding ruling (2026-10-02). Each keeps
// its status but owes a live test: TestGrandfatheredAutoRegisterOwesLive-
// Grounding fails once an entry's registered bindings are all live, so the
// entry is then removed rather than left as dead weight. A NEW mechanism
// never joins this list: it joins auto-registration by going live.
var grandfatheredAutoRegister = map[integration.HookMechanism]string{
	integration.HookClaudeSettings: "live grounding owed: 19 of 22 registered events are doc-grounded (PreToolUse, UserPromptSubmit and SessionEnd are live)",
	integration.HookCursor:         "live grounding owed: registered events are fixture-grounded (testdata/cursor/hooks-log)",
	integration.HookCodexConfig:    "live grounding owed: PreToolUse, PermissionRequest, PostToolUse and Stop are doc-grounded (SessionStart and UserPromptSubmit are live)",
	integration.HookQwenSettings:   "live grounding owed: UserPromptSubmit is doc-grounded (Part B, 2026-09-07)",
	integration.HookFactoryJSON:    "live grounding owed: UserPromptSubmit is doc-grounded (Part B, 2026-09-07)",
	integration.HookQoderJSON:      "live grounding owed: UserPromptSubmit is doc-grounded (Part B, 2026-09-07)",
	integration.HookPoolsideYAML:   "live grounding owed: UserPromptSubmit is doc-grounded (Part B, 2026-09-07)",
	integration.HookCascadeJSON:    "live grounding owed: pre_user_prompt is doc-grounded (Part B, 2026-09-07)",
	integration.HookCommandCodeMod: "live grounding owed: the Mods export shape is unverified against a live install",
	// Antigravity (HookAntigravityJSON) is deliberately NOT here (Sol
	// A2-08): its PreInvocation hook was added on 2026-10-02, the same day
	// as the ruling, and had never had a live run, so listing it let a NEW
	// mechanism into auto-registration through the exemption D-043 closes.
	// It is `observer init` only until its bindings go live.
}

// initOnlyHookMechanisms are the mechanisms `observer start` never writes,
// live or not: each is `observer init` only (consented), for the reason
// given.
var initOnlyHookMechanisms = map[integration.HookMechanism]string{
	// Autohand device sync mirrors the hooks member of config.json between
	// a user's devices, and a pre-tool hook that fails BLOCKS the call: a
	// hook written on one OS (its binary path) would block every tool on a
	// synced device of another OS. Writing it needs the user's consent.
	integration.HookAutohandConfig: "Autohand device sync mirrors config.json hooks across devices, and a failing pre-tool hook blocks every tool there",
}

// autoRegisterLiveGate reports whether `observer start` may write c's
// mechanism: every registered binding live, or a grandfathered mechanism.
func autoRegisterLiveGate(c integration.Capability) bool {
	// A writer built but switched off until a live check passes (DEC-12)
	// is never written, by `observer start` or anything else.
	if c.Hook.LiveGate.Waiting() {
		return false
	}
	if _, initOnly := initOnlyHookMechanisms[c.Hook.Mechanism]; initOnly {
		return false
	}
	if c.Hook.RegisteredAllLive() {
		return true
	}
	_, ok := grandfatheredAutoRegister[c.Hook.Mechanism]
	return ok
}

// autoRegisterRemediation returns a one-line, tool-specific fix
// suggestion for an autoRegisterHooks failure WARN. Table-driven
// rather than a growing if/else ladder (CLAUDE.md module-boundary
// discipline #5); the tool strings are exactly hook.Registry's
// Installed()/Register() vocabulary.
func autoRegisterRemediation(tool string) string {
	initFlags := map[string]string{
		"claude-code":         "--claude-code",
		"claude-code-windows": "--claude-code",
		"claude-code-xcode":   "--claude-code",
		"claude-code-wsl":     "--claude-code",
		"cursor":              "--cursor",
		"cursor-windows":      "--cursor",
		"cursor-wsl":          "--cursor",
		"codex":               "--codex",
		"codex-windows":       "--codex",
		"codex-xcode":         "--codex",
		"codex-wsl":           "--codex",
	}
	if flag, ok := initFlags[tool]; ok {
		return fmt.Sprintf("run: observer init %s --force (or clear the conflicting hooks entry by hand)", flag)
	}
	// B2 (phase-3a review): the long-tail Part B item 2 vendors have no
	// dedicated `observer init --<tool>` flag at all — they're only
	// selected via --all or the zero-selector auto-detect default
	// (resolveTools: with no cc/codex/cursor/cline flag AND no --all,
	// every `installed` tool is still selected). Naming a flag that
	// doesn't exist would be a broken remediation hint, so these get
	// their own explicit entry rather than silently falling to the
	// generic text below for a reason the operator can't tell apart.
	noDedicatedInitFlag := map[string]bool{
		"gemini-cli": true, "qwen-code": true, "droid": true,
		"qoder": true, "poolside": true, "devin": true, "command-code": true,
	}
	if noDedicatedInitFlag[tool] {
		return "run: observer init --force (no dedicated --" + tool + " flag; --all also selects it) - or clear the conflicting hooks entry by hand"
	}
	return "run: observer init --force (or clear the conflicting hooks entry by hand)"
}

// allowedNotWatchedWarning builds the DI-07 startup WARN naming the
// [terminal.launch].allowed_tools entries an explicit
// [observer.watch].enabled_adapters list leaves uncaptured (audit DI-07,
// docs/plans/dashboard-install-gap-remediation-research-2026-09-02.md §5.4).
// unwatched is diag.AllowedToolsNotWatched's result (nil/empty when there is
// no gap — including the nil-enabled_adapters "watch everything" case, which
// this func never sees an empty-vs-nil distinction for since the caller
// already resolved that). enabledLen/defaultLen are the operator's explicit
// list length and the built-in default's length, purely for the message —
// this function does no config reading itself so it is trivially testable.
//
// Returns "" when unwatched is empty (nothing to warn about); otherwise a
// single "WARN "-prefixed, newline-terminated line matching the sibling
// cross-env-DB WARN's style.
// crossEnvSiblingCheckApplies reports whether the cross-env observer.db
// check runs at start. A sibling database is written by a hook of a tool
// registered from the other OS, so with the watched adapters restricted
// (an explicit enabled_adapters list that leaves out a default adapter) the
// foreign mounts are looked at only when the list keeps a tool whose hooks
// register as a cross-OS bridge (integration.HookSpec.CrossOSBridge, a
// capability, never a tool name) AND hooks auto-register at start; a
// restricted list with auto-registration off (live run 2, finding N4:
// enabled_adapters = ["poolside"], auto_register = false, yet the start
// stat'd the Windows mount's observer.db) is left alone. An empty list, or
// one naming every default, watches everything and always checks.
func crossEnvSiblingCheckApplies(enabled, defaults []string, autoRegister bool) bool {
	if len(enabled) == 0 {
		return true
	}
	have := make(map[string]bool, len(enabled))
	for _, tool := range enabled {
		have[tool] = true
	}
	restricted := false
	for _, d := range defaults {
		if !have[d] {
			restricted = true
			break
		}
	}
	if !restricted {
		return true
	}
	if !autoRegister {
		return false
	}
	for _, tool := range enabled {
		if c, ok := integration.For(tool); ok && c.Hook.CrossOSBridge {
			return true
		}
	}
	return false
}

func allowedNotWatchedWarning(unwatched []string, enabledLen, defaultLen int) string {
	if len(unwatched) == 0 {
		return ""
	}
	return fmt.Sprintf(
		"WARN [terminal.launch].allowed_tools lists %d tool(s) that your explicit "+
			"[observer.watch].enabled_adapters (%d entries; the default has %d) does not watch - "+
			"they will launch from the dashboard but never be captured: %s. "+
			"Add them to enabled_adapters or delete the key to watch the default set.\n",
		len(unwatched), enabledLen, defaultLen, strings.Join(unwatched, ", "),
	)
}
