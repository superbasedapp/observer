// Command observer is the CLI entry point for the SuperBased Observer.
//
// All capture/query/manage subcommands (scan, watch, init, uninstall, serve,
// doctor, status, tail, prune, cost, score, discover, patterns, learn,
// suggest, dashboard, metrics, summarize, export) are wired directly under
// the root. The legacy `observer observer ...` nesting is preserved as a
// hidden alias group so installed hooks and MCP registrations from earlier
// versions keep working without re-init.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/antigravity"
	"github.com/marmutapp/superbased-observer/internal/adapter/claudecode"
	"github.com/marmutapp/superbased-observer/internal/adapter/clinecli"
	"github.com/marmutapp/superbased-observer/internal/adapter/copilot"
	"github.com/marmutapp/superbased-observer/internal/adapter/cowork"
	"github.com/marmutapp/superbased-observer/internal/adapter/cursor"
	adapterdefaults "github.com/marmutapp/superbased-observer/internal/adapter/defaults"
	"github.com/marmutapp/superbased-observer/internal/adapter/hermes"
	"github.com/marmutapp/superbased-observer/internal/compression/indexing"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/freshness"
	"github.com/marmutapp/superbased-observer/internal/identity"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/watcher"
)

// version is stamped at build time via -ldflags="-X main.version=...".
var version = "dev"

func main() {
	// Trusted OOB launcher emission (F3): when this process was spawned by the
	// daemon as an `observer <tool>` launcher (OBSERVER_OOB_* env present), emit
	// the authenticated Hello + launcher_started up front and tool_exec_end on
	// the way out. A no-op for every normal invocation.
	endOOB := emitOOBLaunchHello()
	root := newRootCmd()
	executed, err := root.ExecuteC()
	// Launcher commands deliberately silence Cobra because they render their
	// own contextual failures. Restore only errors carrying a separately
	// bounded safe message, and do so before the OOB end frame can announce
	// process exit to a dashboard terminal. Ordinary Cobra errors and vendor
	// exitErr values retain their existing behavior.
	renderSuppressedLauncherError(os.Stderr, root, executed, err)
	exitCode := 0
	var ec exitErr
	if errors.As(err, &ec) {
		exitCode = int(ec)
	} else if err != nil {
		exitCode = 1
	}
	endOOB(exitCode)
	// Dashboard-triggered restart: the daemon has now completed graceful
	// shutdown AND every defer (DB closed, PTY children reaped, listeners
	// released), so re-exec the process image in place — the daemon relaunches
	// itself with no CLI/supervisor. execSelf only returns on failure; fall
	// through to a normal exit then.
	if restartRequested.Load() {
		if xerr := execSelf(); xerr != nil {
			fmt.Fprintf(os.Stderr, "observer: dashboard restart failed, exiting instead: %v\n", xerr)
		}
	}
	if err != nil {
		// `observer run` forwards the wrapped command's exit code via exitErr;
		// everything else gets a generic non-zero exit (cobra already printed).
		os.Exit(exitCode)
	}
}

// invocationName returns the command name to show in help/usage, derived from
// how the binary was invoked. Both `superbased` and `observer` are supported
// command names (dual-name compatibility, 2026-07-23): npm/PyPI install both,
// and the release tarball ships a `superbased` alias beside `observer`. Only an
// explicit `superbased` argv[0] flips the displayed name; every other argv[0]
// (the npm/PyPI shim, which spawns the binary as `observer`; a temp test
// binary; a bare path) defaults to the canonical `observer`. Runtime behaviour
// is identical either way — self-invocations (hooks, MCP, launchers) resolve
// os.Executable() absolute paths, never this name.
func invocationName() string {
	return commandNameFrom(os.Args[0])
}

// commandNameFrom maps an argv[0] to the displayed command name. Only an
// explicit `superbased` basename flips it; anything else defaults to the
// canonical `observer`. It splits on both path separators (and trims `.exe`
// case-insensitively) so a Windows argv[0] resolves the same regardless of the
// OS the binary was built for — filepath.Base only honours the host separator.
func commandNameFrom(argv0 string) string {
	base := argv0
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	if strings.HasSuffix(strings.ToLower(base), ".exe") {
		base = base[:len(base)-len(".exe")]
	}
	if strings.EqualFold(base, "superbased") {
		return "superbased"
	}
	return "observer"
}

// newRootCmd assembles the CLI against the production one-shot seams.
func newRootCmd() *cobra.Command { return newRootCmdWith(defaultUsageDeps()) }

// newRootCmdWith is newRootCmd with the one-shot report's I/O seams
// injected (usage.go::usageDeps) — the bare-root fallthrough's state
// probes and the adapter set its scan walks. Production passes
// defaultUsageDeps(); tests pass stubs so the fallthrough matrix never
// depends on what is listening on the test machine or on the operator's
// real session files.
func newRootCmdWith(deps usageDeps) *cobra.Command {
	root := &cobra.Command{
		Use:          invocationName(),
		Short:        "SuperBased — unify AI coding tool activity",
		Long:         "Captures, normalizes, and analyzes tool call activity from AI coding assistants.\nSee README.md for a feature tour.",
		Version:      version,
		SilenceUsage: true,
		// Bare `observer` greets with daemon status + the three
		// commands that matter, instead of the full help wall
		// (usability arc P1.13). `observer --help` / `observer help`
		// keep the complete command list.
		//
		// EXCEPTION (the one-shot fallthrough, plan §1.1): on a machine
		// with no SuperBased state at all — no ~/.observer/observer.db,
		// no ~/.observer/config.toml, no daemon listening — there is
		// nothing to greet the user about, so bare `observer` runs the
		// one-shot usage report instead. A state branch, never an
		// invocation-channel branch. See usage.go::runBareRoot.
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runBareRoot(cmd, deps)
		},
	}
	for _, c := range observerSubcommandsWith(deps) {
		root.AddCommand(c)
	}
	root.AddCommand(newClaudeCmd())
	root.AddCommand(newCodexCmd())
	root.AddCommand(newOpencodeCmd())
	root.AddCommand(newClineCLICmd())
	root.AddCommand(newCopilotCLICmd())
	root.AddCommand(newOpenclawCmd())
	root.AddCommand(newGeminiCmd())
	root.AddCommand(newPiCmd())
	root.AddCommand(newHermesCmd())
	root.AddCommand(newKiloCmd())
	root.AddCommand(newCursorCmd())
	root.AddCommand(newAntigravityCmd())
	root.AddCommand(newQwenCmd())
	root.AddCommand(newKiroCmd())
	root.AddCommand(newKimiCmd())
	root.AddCommand(newGrokCmd())
	root.AddCommand(newQoderCmd())
	root.AddCommand(newGooseCmd())
	root.AddCommand(newCrushCmd())
	root.AddCommand(newDevinCmd())
	root.AddCommand(newDroidCmd())
	root.AddCommand(newOpenInterpreterCmd())
	root.AddCommand(newCommandCodeCmd())
	root.AddCommand(newAiderCmd())
	root.AddCommand(newMuseCmd())
	root.AddCommand(newPrimeAgentCmd())
	root.AddCommand(newZcodeCmd())
	root.AddCommand(newVibeCmd())
	root.AddCommand(newFreebuffCmd())
	root.AddCommand(newLOCCmd())
	root.AddCommand(newGuardCmd())
	root.AddCommand(newBenchmarkCmd())
	root.AddCommand(newHookCmd())
	root.AddCommand(newBrowserCmd())
	root.AddCommand(newProxyCmd())
	root.AddCommand(newIndexCmd())
	root.AddCommand(newCodeIntelCmd())
	root.AddCommand(newRunCmd())
	root.AddCommand(newServiceCmd())
	root.AddCommand(newStartCmd())
	root.AddCommand(newRemoteCmd())
	root.AddCommand(newSSHCmd())
	root.AddCommand(newEvalCmd())
	root.AddCommand(newObsCmd())
	root.AddCommand(newDigestCmd())
	root.AddCommand(newEnrollCmd())
	root.AddCommand(newUnenrollCmd())
	root.AddCommand(newOrgCmd())
	root.AddCommand(newObserverAliasCmd())
	root.AddCommand(newPrivacyCmd())
	root.AddCommand(newUpdateCmd())
	root.AddCommand(newWorkspacesCmd())
	root.AddCommand(newCloudCmd())
	root.AddCommand(newPricingCmd())
	return root
}

// observerSubcommands returns the full set of capture/query/manage commands.
// Each constructor returns a fresh *cobra.Command, so the slice can be
// regenerated by the alias group below without sharing state with the root.
func observerSubcommands() []*cobra.Command {
	return observerSubcommandsWith(defaultUsageDeps())
}

// observerSubcommandsWith is observerSubcommands with the one-shot
// report's I/O seams injected (only `usage` consumes them).
func observerSubcommandsWith(deps usageDeps) []*cobra.Command {
	return []*cobra.Command{
		newScanCmd(),
		newUsageCmd(deps),
		newWatchCmd(),
		newInitCmd(),
		newUninstallCmd(),
		newServeCmd(),
		newDoctorCmd(),
		newAdaptersCmd(),
		newContractCmd(),
		newStatusCmd(),
		newTailCmd(),
		newPruneCmd(),
		newProcessCmd(),
		newProcessBridgeCmd(),
		newDBCmd(),
		newCostCmd(),
		newScoreCmd(),
		newAdviseCmd(),
		newDiscoverCmd(),
		newPatternsCmd(),
		newLearnCmd(),
		newSuggestCmd(),
		newDashboardCmd(),
		newMetricsCmd(),
		newSummarizeCmd(),
		newExportCmd(),
		newReportCmd(),
		newAggregateCmd(),
		newBackfillCmd(),
		newMCPAuditCmd(),
		newCacheHealthCmd(),
		newCacheStatusCmd(),
		newRoutingCmd(),
		newModelValueCmd(),
		newPredictCmd(),
		newTasksCmd(),
		newArchiveCmd(),
		newStatuslineCmd(),
		newHandoffCmd(),
		newVerbosityCmd(),
		newTagCmd(),
		newTagsCmd(),
		newProfileCmd(),
		newExperimentCmd(),
		newConfigCmd(),
	}
}

// newObserverAliasCmd preserves the deprecated `observer observer <sub>` form
// so existing hook registrations, MCP entries, and user scripts continue to
// work after the flatten. Hidden from --help; the canonical surface is the
// root.
func newObserverAliasCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:        "observer",
		Short:      "Deprecated alias group — use the top-level subcommands instead.",
		Hidden:     true,
		Deprecated: "subcommands have been promoted to the root (e.g. `observer scan` instead of `observer observer scan`).",
	}
	for _, c := range observerSubcommands() {
		cmd.AddCommand(c)
	}
	return cmd
}

func newScanCmd() *cobra.Command {
	var (
		configPath    string
		force         bool
		adapterFilter string
		sessionFiles  []string
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "One-time backfill — parse all known session files",
		Long: `Walks every detected adapter's session files and ingests their
events. Default mode resumes from the saved parse cursor — fast, but
won't recover anything the live watcher dropped silently. Pass --force
to ignore the cursor and re-walk every file from offset 0; the
(source_file, source_event_id) UNIQUE index keeps re-walks idempotent
(rows already in the DB are no-ops, missing rows get inserted).

` + "`scan --force`" + ` is the recovery path when you notice gaps in the
Actions tab — typically a watcher that fell behind because of fsnotify
event drops or a daemon restart that lost in-flight state. The
dashboard's "Run all" button on the Backfill tab calls this path
first, then runs the surgical column-update backfills (--message-id,
--cache-tier, etc.) on top.

Pass ` + "`--adapter <name>`" + ` to scope the scan to a single adapter
(e.g. ` + "`observer scan --force --adapter codex`" + `) — useful as
the per-invocation recovery path for the v1.4.51 misrouting bug
class, where the upgrade-time cleanup re-parses Codex sessions that
the pre-fix poller silently routed to claude-code. The flag
overrides ` + "`enabled_adapters`" + ` in config for this invocation
only.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			w, cleanup, err := buildWatcherWithOverride(cmd.Context(), configPath, adapterFilter)
			if err != nil {
				return err
			}
			defer cleanup()
			var res watcher.ScanResult
			switch {
			case len(sessionFiles) > 0:
				for _, path := range sessionFiles {
					one, scanErr := w.ScanFile(cmd.Context(), path, force)
					res.FilesProcessed += one.FilesProcessed
					res.Errors += one.Errors
					if scanErr != nil {
						return scanErr
					}
				}
			case force:
				res, err = w.Rescan(cmd.Context())
			default:
				res, err = w.Scan(cmd.Context())
			}
			if err != nil {
				return err
			}
			label := "scan"
			if force {
				label = "rescan (from zero)"
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"%s complete: files_processed=%d errors=%d\n",
				label, res.FilesProcessed, res.Errors)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&force, "force", false, "Ignore saved parse cursors and re-walk every file from offset 0 (recovery path for watcher gaps)")
	cmd.Flags().StringVar(&adapterFilter, "adapter", "", "Restrict to a single adapter (e.g. codex, claude-code). Overrides enabled_adapters in config for this invocation only.")
	cmd.Flags().StringArrayVar(&sessionFiles, "file", nil, "Process only this recognized session file (repeatable); combine with --force for targeted recovery")
	return cmd
}

func newWatchCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Start the fsnotify-based live watcher daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			w, cleanup, err := buildWatcher(ctx, configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			// buildWatcher opens the DB without the integrity probe (fast bind);
			// run the one-time quick_check + path-hash backfill in the
			// background so it never delays the watcher on a large DB.
			go runStartupDBMaintenance(ctx, configPath)
			// Periodic maintenance tick — same
			// [observer.retention].interval_hours loop `observer start`
			// runs, so a standalone watch daemon that stays up for weeks
			// still prunes (its FIRST iteration is the prune_on_startup pass,
			// moved off the synchronous buildWatcher path). Fail-soft.
			go retentionTickLoop(ctx, configPath)
			fmt.Fprintln(cmd.OutOrStdout(), "watcher running — ctrl-c to stop")
			if err := w.Watch(ctx); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return cmd
}

// recognizesSessionFile returns a predicate matching any of the
// default adapters' IsSessionFile checks. Used by the dashboard's
// /api/health/watcher endpoint to filter out orphaned parse_cursors
// rows (paths an older adapter version once tracked but no current
// adapter recognises) from the "behind" count — without this filter
// the user-visible banner shows orphan rows forever, since Rescan
// only re-walks paths that some adapter still claims.
func recognizesSessionFile() func(string) bool {
	adapters := adapterdefaults.Adapters()
	return func(path string) bool {
		for _, a := range adapters {
			if a.IsSessionFile(path) {
				return true
			}
		}
		return false
	}
}

// cursorSemanticsFor returns the boundary translator that tells the
// dashboard's /api/health/watcher endpoint what a parse_cursors row's
// saved cursor MEANS for a given path. Same injection seam as
// recognizesSessionFile — the adapter's own capability declaration
// (adapter.CursorSemantics, an optional interface) is resolved to
// plain capability flags HERE, so the dashboard branches on shape and
// never on a tool name (CLAUDE.md module rules #2 / #3).
//
// Adapters that do not implement the optional interface resolve to
// byte-offset semantics — the behaviour every adapter had before it
// existed.
func cursorSemanticsFor() func(string) dashboard.CursorSemantics {
	adapters := adapterdefaults.Adapters()
	return func(path string) dashboard.CursorSemantics {
		sem := adapter.ResolveCursorSemantics(adapters, path)
		return dashboard.CursorSemantics{
			Kind:            sem.Kind.String(),
			LagMeaningful:   sem.Kind.LagMeaningful(),
			ActionsExpected: sem.Kind.ActionsExpected(),
			Reason:          sem.Detail,
		}
	}
}

// toolCatalog snapshots every default adapter's stable name +
// canonical watch paths for the dashboard's Connected-tools panel
// (P4.1). Same injection seam as recognizesSessionFile — the
// dashboard never imports adapter packages.
func toolCatalog() []dashboard.ToolCatalogEntry {
	adapters := adapterdefaults.Adapters()
	out := make([]dashboard.ToolCatalogEntry, 0, len(adapters))
	for _, a := range adapters {
		out = append(out, dashboard.ToolCatalogEntry{Tool: a.Name(), WatchPaths: a.WatchPaths()})
	}
	return out
}

// buildWatcher loads config, opens the DB, registers adapters, and returns a
// configured watcher plus a cleanup closure. Runs a retention pass first
// when prune_on_startup is set (spec §19).

// buildWatcher is the standard caller — uses enabled_adapters from
// config. See buildWatcherWithOverride for the scan --adapter path.
func buildWatcher(ctx context.Context, configPath string) (*watcher.Watcher, func(), error) {
	return buildWatcherWithOverride(ctx, configPath, "")
}

// wireGuard composes the guard layer into a Store's ingest path:
// acquires the per-process shared Guard (constructed on first ask —
// guardwire.go; in the `observer start` assembly the proxy build has
// usually constructed it already, so the watcher receives the SAME
// instance and proxy-marked taint is visible to the ingest seam's
// T-5xx rules) and calls SetGuard. Every failure path is
// WARN-and-continue — the watcher must never refuse to run over a
// guard problem (the Q2 fail-open philosophy applied at composition).
func wireGuard(ctx context.Context, cfg config.Config, st *store.Store, logger *slog.Logger) {
	g := acquireProcessGuard(ctx, cfg, st, logger)
	if g == nil {
		return
	}
	st.SetGuard(g)
	logger.Info("guard layer active", "mode", string(g.Mode()), "rules", g.RuleCount())
}

// buildWatcherWithOverride is the same as buildWatcher except that
// adapterFilter, when non-empty, overrides cfg.Observer.Watch.EnabledAdapters
// for this invocation. Used by scan --adapter <name> to scope a
// recovery scan to a single adapter without editing the user's
// config.toml or interfering with a running watch daemon.
func buildWatcherWithOverride(ctx context.Context, configPath, adapterFilter string) (*watcher.Watcher, func(), error) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return nil, nil, fmt.Errorf("load config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Observer.DBPath), 0o755); err != nil {
		return nil, nil, fmt.Errorf("ensure db dir: %w", err)
	}
	// No integrity probe here: this is a long-running daemon open (`observer
	// start` / `observer watch`). The multi-GB PRAGMA quick_check is deferred
	// off the readiness path and run once via db.RunStartupMaintenance after
	// the listener binds. See db.Options.IntegrityCheck.
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		return nil, nil, fmt.Errorf("open db %s: %w", cfg.Observer.DBPath, err)
	}

	logger := newLogger(cfg.Observer.LogLevel)
	// The prune_on_startup retention pass used to run HERE, synchronously,
	// before buildWatcher returned — which meant it blocked the `observer
	// start` readiness path. On a multi-GB DB the delete + incremental
	// vacuum can take many seconds, delaying the listener bind. It now runs
	// in the background as the FIRST iteration of retentionTickLoop (the one
	// owner of every retention pass), after the daemon is already serving.
	// See prune.go::retentionTickLoop. `observer start` and `observer watch`
	// both run that loop; `observer backfill` (which also calls buildWatcher)
	// no longer prunes as a side effect — correct, a scan should not delete.

	st := store.New(database)
	// Org attribution: stamp ingested sessions/actions/token_usage with the
	// enrolled org_id/user_email. No-op on solo-local installs — NewStamper
	// returns a no-op stamper when org_enrolment is empty/absent, so the
	// watcher ingest path behaves identically when not enrolled.
	if stmp, err := identity.NewStamper(ctx, database); err != nil {
		logger.Warn("org stamper init failed; ingest will not be org-attributed", "err", err)
	} else {
		st = st.WithStamper(stmp)
	}
	// Guard layer (guard spec §3.2 seam 3): build the composition layer
	// and wire the post-hoc ingest seam so watcher-captured actions get
	// flagged. P1-safe end to end: construction problems log and the
	// watcher runs unguarded; policy-file problems degrade inside the
	// Guard (LoadIssues) rather than failing it.
	wireGuard(ctx, cfg, st, logger)
	// Task-tracking ingest seam (docs/task-tracking.md, [tasks].enabled,
	// default true): gates Store.Ingest's post-hoc task_items/
	// task_transitions decode. A pure config bool, so no acquire/
	// construction step like guard/cache — see internal/store/taskflow.go.
	st.SetTasksEnabled(cfg.Tasks.Enabled)
	st.SetTasksOptions(cfg.Tasks.MatchMode, cfg.Tasks.ConcurrentAttribution, cfg.Tasks.IncludeSidechains)
	// [tasks].backfill_on_start (FIX-4, default false): re-derive
	// task_items/task_transitions from historical actions rows once,
	// same work as `observer backfill --tasks` run automatically for an
	// operator who just flipped [tasks].enabled on. Backgrounded — a
	// large corpus must not delay the rest of daemon startup — and
	// BackfillTaskItems is idempotent, so a daemon restart mid-backfill
	// just resumes covering the same ground harmlessly.
	if cfg.Tasks.BackfillOnStart {
		go func() {
			res, err := st.BackfillTaskItems(context.Background(), 0)
			if err != nil {
				logger.Warn("tasks.backfill_on_start failed", "error", err)
				return
			}
			logger.Info("tasks.backfill_on_start complete",
				"actions_scanned", res.ActionsScanned, "transitions_written", res.TransitionsWritten)
		}()
	}
	// Enterprise message-content capture (2026-08-28 ruling): the producer
	// that feeds adapter-parsed conversation text into otel_content. Inert
	// unless the node's own share posture ships raw content — see
	// wireContentCapture / internal/store/messagecontent.go.
	wireContentCapture(cfg, st)
	reg := adapter.NewRegistry()
	for _, a := range adapterdefaults.Adapters() {
		// Wire per-adapter config into adapters that support it.
		// Antigravity has the network_recovery opt-in for the
		// gRPC fallback against the running language_server.
		if ag, ok := a.(*antigravity.Adapter); ok {
			ag.WithNetworkRecovery(cfg.Observer.Antigravity.NetworkRecovery)
			// Startup nudge: CLI .pb files require the gRPC fallback
			// to surface in the dashboard (the agy CLI doesn't ship
			// the desktop oscrypt secret). Warn once on start so the
			// operator notices the gap before opening the dashboard
			// and finding an empty Antigravity section.
			warnAntigravityCLIWithoutNetworkRecovery(logger, cfg.Observer.Antigravity.NetworkRecovery)
			// Persistent decrypt+gRPC-failure tracker (Issue #4
			// follow-up). Skips files we know are unrecoverable
			// across CLI invocations — the in-memory cache from
			// the v1.6.11 first pass only helped the long-running
			// daemon. Scoped to adapter="antigravity" so a future
			// adapter using the same store can't collide.
			ag.WithUnrecoverableTracker(antigravityTrackerShim{st: st})
			// DB-aware dedup reader for the plaintext-transcript
			// augmentation path (Phase 1 of
			// docs/plans/antigravity-token-coverage-design-2026-05-24.md).
			// Closes the universal-duplication bug where later parse
			// cycles re-emitted every transcript USER_INPUT after the
			// originating agy.exe terminated — see the
			// TargetCoverageReader docstring for the cross-cycle race.
			ag.WithTargetCoverageReader(antigravityTargetCoverageShim{st: st})
			// Optional shape-mismatch wire-bytes dump (Issue #5
			// follow-up). Off by default — operator enables via
			// [observer.antigravity] dump_shape_mismatches_dir in
			// config.toml to capture proto payloads for offline
			// path-mapping analysis.
			ag.WithShapeMismatchDumpDir(cfg.Observer.Antigravity.DumpShapeMismatchesDir)
		}
		// Cursor: defer transcript-derived events when the live hook
		// has already captured the session (any row tagged
		// SourceFile="cursor:hook" implies beforeSubmitPrompt fired,
		// stop will follow with token + tool_use replay). The watcher
		// path is then a fallback for cold-start ingestion / pre-
		// install historical transcripts only.
		if ca, ok := a.(*cursor.Adapter); ok {
			ca.WithSessionHookChecker(func(ctx context.Context, sessionID string) (bool, error) {
				return st.SessionHasSourceFileRows(ctx, sessionID, "cursor:hook")
			})
		}
		// Cline CLI: same cross-path dedup gate. The adapter shipped
		// the SessionHookChecker seam (mirroring cursor's) but the
		// wiring was missed at install time — with cline hook commands
		// registered, both paths emitted independently and the
		// UNIQUE(source_file, source_event_id) key never caught the
		// cross-path duplicates (the H1 hermes-audit shape).
		if cl, ok := a.(*clinecli.Adapter); ok {
			cl.WithSessionHookChecker(func(ctx context.Context, sessionID string) (bool, error) {
				return st.SessionHasSourceFileRows(ctx, sessionID, "clinecli:hook")
			})
		}
		// Hermes: partitioned cross-path dedup gate (the H1 audit
		// finding, observed live 2026-06-11 as a 2× token count on a
		// hook-covered session). Unlike cursor/clinecli the SQLite
		// path is NOT skipped wholesale — it suppresses only the
		// event classes the hook path also emits (tool_calls + token
		// rows) and keeps the classes only SQLite can see
		// (user_prompt / assistant text / system_prompt).
		if hm, ok := a.(*hermes.Adapter); ok {
			hm.WithSessionHookChecker(func(ctx context.Context, sessionID string) (bool, error) {
				return st.SessionHasSourceFileRows(ctx, sessionID, "hermes:hook")
			})
		}
		// Claude-code: stamp per-turn effort.level from the hook-
		// captured claudecode_effort sidecar onto tool_use ToolEvents
		// at parse time. The Claude Code JSONL itself never carries
		// the user's effort dropdown selection; PreToolUse /
		// PostToolUse hooks do (`effort.level`), and observer's hook
		// handler upserts them into the sidecar. Joining at parse
		// time (rather than on every dashboard read) keeps the hot
		// query path unchanged.
		if cc, ok := a.(*claudecode.Adapter); ok {
			cc.WithEffortLookup(func(ctx context.Context, sessionID string) (map[string]string, error) {
				return st.LoadClaudecodeEffortMap(ctx, sessionID)
			})
		}
		reg.Register(a)
	}
	// Cross-mount detector results: emit at DEBUG. INFO was useful when
	// the detector was new (users could see exactly which Windows-side
	// homes WSL2 picked up), but in steady state every scan re-prints
	// 8+ lines of the same data. Diagnostics that actually change
	// behavior (Copilot debug-log enable below, watcher cursors, etc.)
	// stay at INFO; this is purely informational and stable across
	// runs, so DEBUG is the right level.
	for _, h := range crossmount.ExtraHomes() {
		logger.Debug("crossmount: detected extra home",
			"path", h.Path, "os", h.OS, "origin", h.Origin)
	}
	// Auto-enable Copilot Chat's debug-log capture across every
	// cross-mount-resolved $HOME's VS Code install. Without this flip,
	// Copilot writes only a session_start line to main.jsonl and the
	// adapter has nothing to ingest. Per user direction the flip is
	// automatic — but EnsureDebugEnabled logs INFO whenever it
	// actually changes a file so the user sees what observer touched.
	// Idempotent across restarts; silent steady state.
	copilot.EnsureDebugEnabled(ctx, logger, crossmount.AllHomes())
	var classifier *freshness.Classifier
	if cfg.Observer.Freshness.EnableContentHashing {
		classifier = freshness.New(database, freshness.Options{
			MaxHashSizeMB:    cfg.Observer.Freshness.MaxHashFileSizeMB,
			IgnorePatterns:   cfg.Observer.Freshness.IgnorePatterns,
			FastPathStatOnly: cfg.Observer.Freshness.FastPathStatOnly,
		})
	}
	var indexer *indexing.Indexer
	if cfg.Compression.Indexing.Enabled {
		indexer = indexing.New(database, cfg.Compression.Indexing.MaxExcerptBytes)
	}
	allow := cfg.Observer.Watch.EnabledAdapters
	if adapterFilter != "" {
		allow = []string{adapterFilter}
	} else {
		// Once-per-startup warning when a registered default adapter
		// is silently filtered out by an explicit `enabled_adapters`
		// list in the user's config (Invariant #51). Config.Default()
		// only applies when the key is absent, so adding a new
		// adapter to defaults is a no-op for any existing user with
		// an explicit allow-list from a prior release. The warning
		// names the missing tools and prints the exact remediation.
		// Skipped on the --adapter override path (where filtering is
		// the user's intent) and on fresh configs where Default()
		// already populated every default.
		warnMissingDefaultsFromAllowList(logger, adapterdefaults.Adapters(), cfg.Observer.Watch.EnabledAdapters)
	}
	w := watcher.New(st, reg, watcher.Options{
		Logger: logger,
		NativePredicate: map[string]func(string) bool{
			"claude-code": claudecode.IsNativeTool,
			"cowork":      cowork.IsNativeTool,
		},
		Allow:        allow,
		PollInterval: time.Duration(cfg.Observer.Watch.PollIntervalSeconds) * time.Second,
		Classifier:   classifier,
		Indexer:      indexer,
		MaxFileBytes: int64(cfg.Observer.Watch.MaxFileSizeMB) * 1024 * 1024,
	})

	cleanup := func() { _ = database.Close() }
	return w, cleanup, nil
}

// warnMissingDefaultsFromAllowList logs a WARN when one or more
// adapters in the registered default set are absent from the user's
// explicit `enabled_adapters` allow-list. Long-term fix for the
// Invariant #51 bug class — `config.Default()` only fills
// EnabledAdapters when the key is unset, so adding a new adapter to
// the defaults is silently a no-op for any user whose config.toml
// pins an explicit list from a prior release. The warning names each
// missing tool and prints the exact append-this-string remediation
// the user can paste into config.toml. No-op when the allow-list is
// empty (fresh installs get Default()'s full list applied at load
// time) or when every default is already present.
// warnAntigravityCLIWithoutNetworkRecovery scans every cross-mount
// home for ~/.gemini/antigravity-cli/conversations/*.pb and emits one
// startup WARN if any are found while network_recovery is off.
// Idempotent + cheap (one Stat per home, one ReadDir on hits) — runs
// once per daemon start. Best-effort: silent on permission errors.
func warnAntigravityCLIWithoutNetworkRecovery(logger *slog.Logger, networkRecovery string) {
	if strings.EqualFold(strings.TrimSpace(networkRecovery), "local") {
		return
	}
	for _, h := range crossmount.AllHomes() {
		dir := filepath.Join(h.Path, ".gemini", "antigravity-cli", "conversations")
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		n := 0
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".pb") {
				n++
			}
		}
		if n > 0 {
			logger.Warn(
				"antigravity-cli .pb files present but network_recovery is off — CLI conversations will not appear in the dashboard until you set [observer.antigravity] network_recovery = \"local\" in ~/.observer/config.toml",
				"dir", dir,
				"pb_count", n,
				"network_recovery", networkRecovery,
			)
			return
		}
	}
}

// warnMissingDefaultsFromAllowList is Invariant #51's startup guard.
// Config.Default() only seeds [observer.watch] enabled_adapters when
// the key is ABSENT from config.toml — BurntSushi TOML decoding only
// overwrites keys present in the file — so an operator with an
// explicit list from an older release silently never runs any
// adapter added to the registry since. This has recurred three times
// (latest: 5 adapters, invisible sessions) precisely because the old
// single-line warning was easy to miss in scrollback. The banner below
// is deliberately loud: it names every missing adapter, states the
// concrete consequence, and gives the one-command fix.
func warnMissingDefaultsFromAllowList(logger *slog.Logger, defaults []adapter.Adapter, allow []string) {
	if len(allow) == 0 {
		return
	}
	have := make(map[string]struct{}, len(allow))
	for _, t := range allow {
		have[t] = struct{}{}
	}
	var missing []string
	for _, a := range defaults {
		if _, ok := have[a.Name()]; !ok {
			missing = append(missing, a.Name())
		}
	}
	if len(missing) == 0 {
		return
	}
	missingList := strings.Join(missing, ", ")
	banner := "" +
		"##################################################################\n" +
		fmt.Sprintf("# OBSERVER: %d default adapter(s) are NOT enabled in your config.toml.\n", len(missing)) +
		"# Missing: " + missingList + "\n" +
		"# Sessions from these tools will not be captured at all until you fix this.\n" +
		"# Fix it now:   observer config adopt-defaults --write\n" +
		"# Preview only: observer config adopt-defaults\n" +
		"# Or edit by hand: " + remediationConfigHint() + "\n" +
		"##################################################################"
	logger.Warn(
		banner,
		"missing", strings.Join(missing, ","),
		"remediation_cmd", "observer config adopt-defaults --write",
		"remediation", "edit "+remediationConfigHint()+" and add: "+missingList,
	)
}

// remediationConfigHint returns a short, user-facing hint for the
// config.toml path. The actual loaded path may differ from this
// default (e.g. --config flag, XDG override), but the standard
// location covers >99% of installs and keeps the warning concise.
func remediationConfigHint() string {
	return "~/.observer/config.toml [observer.watch] enabled_adapters"
}

// antigravityTrackerShim adapts *store.Store to the
// antigravity.UnrecoverableTracker interface, scoping every call to
// adapter="antigravity". Defined here (not in internal/store) so the
// adapter package stays store-free per the architecture quick
// reference in CLAUDE.md. Issue #4 follow-up.
type antigravityTrackerShim struct {
	st *store.Store
}

func (s antigravityTrackerShim) Lookup(ctx context.Context, sourceFile string, size, mtimeUnix int64) (string, bool, error) {
	entry, err := s.st.LookupUnrecoverable(ctx, "antigravity", sourceFile, size, mtimeUnix)
	if err != nil {
		return "", false, err
	}
	if entry == nil {
		return "", false, nil
	}
	return entry.Reason, true, nil
}

func (s antigravityTrackerShim) Mark(ctx context.Context, sourceFile string, size, mtimeUnix int64, reason string) error {
	return s.st.MarkUnrecoverable(ctx, "antigravity", sourceFile, size, mtimeUnix, reason)
}

func (s antigravityTrackerShim) Clear(ctx context.Context, sourceFile string) error {
	return s.st.ClearUnrecoverable(ctx, "antigravity", sourceFile)
}

// antigravityTargetCoverageShim adapts *store.Store to the
// antigravity.TargetCoverageReader interface. Lives here (not in
// internal/store) for the same reason as antigravityTrackerShim —
// the adapter package stays store-free per CLAUDE.md's architecture
// quick reference.
type antigravityTargetCoverageShim struct {
	st *store.Store
}

func (s antigravityTargetCoverageShim) LoadActionTargets(ctx context.Context, sourceFile string) ([]string, []string, error) {
	return s.st.LoadActionTargets(ctx, sourceFile)
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
