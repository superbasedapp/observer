package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	adapterdefaults "github.com/marmutapp/superbased-observer/internal/adapter/defaults"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/dblease"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/watcher"
)

func newDoctorCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
		probeHook  bool
	)
	cmd := &cobra.Command{
		Use:   "doctor [tool]",
		Short: "Run health checks on the observer (DB, hooks, MCP)",
		Long: "Verifies database integrity, hook checksums, MCP registrations, and\n" +
			"the running binary's path against what was recorded by `observer init`.\n" +
			"Exits non-zero if any check fails.\n\n" +
			"Pass an optional tool name to scope the output to one integration,\n" +
			"e.g. `observer doctor opencode` (provider-compatibility probe) or\n" +
			"`observer doctor org` (enrolment). The name is matched as a\n" +
			"substring against check ids.\n\n" +
			"--probe-hook fires a synthetic, obviously-fake secret through the\n" +
			"REGISTERED prompt-submit hook command exactly as the host tool\n" +
			"would invoke it, and reports whether it actually got blocked —\n" +
			"the live counterpart of the PromptLane=hook registry claim. With\n" +
			"a tool argument, probes just that tool; without one, probes every\n" +
			"PromptLane=hook tool.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			binary, err := absoluteBinaryPath()
			if err != nil {
				return err
			}

			if probeHook {
				var tools []string
				if len(args) == 1 {
					tools = []string{args[0]}
				} else {
					tools = probeHookToolCandidates()
				}
				var checks []diag.Check
				for _, tool := range tools {
					checks = append(checks, runProbeHook(cmd.Context(), binary, configPath, tool))
				}
				report := diag.Report{Checks: checks}
				if jsonOut {
					body, _ := json.MarshalIndent(report, "", "  ")
					fmt.Fprintln(cmd.OutOrStdout(), string(body))
				} else {
					printReport(cmd.OutOrStdout(), report)
				}
				if report.Failed() {
					return errors.New("one or more probes failed")
				}
				return nil
			}

			report := diag.Run(cmd.Context(), diag.DoctorOptions{
				Config:     cfg,
				DB:         database,
				BinaryPath: binary,
				// Fold the obs-plane admission health checks (judge
				// reachability + audit-chain verify) into doctor, built in the
				// one obs wiring file so diag never imports internal/obs.
				ExtraChecks: append(
					obsAdmissionDoctorChecks(cmd.Context(), cfg, database, slog.Default()),
					oversizeCaptureCheck(cmd.Context(), cfg, database),
					otlpIngressPostureCheck(cfg),
				),
			})
			if len(args) == 1 {
				// A known adapter name gets a focused, per-adapter capture
				// check (detection + watch path + proxy-routing for the
				// routable ones). Otherwise fall back to a substring filter
				// over the general checks (org, hooks, db, …).
				if c, ok := diag.CheckAdapter(args[0], cfg); ok {
					report = diag.Report{Checks: []diag.Check{c}}
				} else {
					report = report.Filter(args[0])
					if len(report.Checks) == 0 {
						return fmt.Errorf("no doctor checks or adapters match %q (adapters: claude-code, codex, opencode, cursor, cline, copilot, gemini-cli, …; checks: org, hooks, db, mcp, governance)", args[0])
					}
				}
			}
			if jsonOut {
				body, _ := json.MarshalIndent(report, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(body))
			} else {
				printReport(cmd.OutOrStdout(), report)
			}
			if report.Failed() {
				return errors.New("one or more checks failed")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit machine-readable JSON instead of formatted output")
	cmd.Flags().BoolVar(&probeHook, "probe-hook", false, "Fire a synthetic secret through the registered prompt-submit hook and report whether it actually blocked")
	return cmd
}

func newStatusCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show observer DB stats and recent activity",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			snap, err := diag.Snapshot(cmd.Context(), database, cfg.Observer.DBPath)
			if err != nil {
				return err
			}
			if jsonOut {
				body, _ := json.MarshalIndent(snap, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(body))
				return nil
			}
			fmt.Fprint(cmd.OutOrStdout(), diag.FormatStatus(snap))
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit machine-readable JSON")
	return cmd
}

func newTailCmd() *cobra.Command {
	var (
		configPath   string
		intervalSecs int
		pageSize     int
		sinceMinutes int
	)
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Live-stream captured actions to the terminal",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			_, database, cleanup, err := loadConfigAndDB(ctx, configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			opts := diag.TailOptions{
				Interval: time.Duration(intervalSecs) * time.Second,
				PageSize: pageSize,
			}
			if sinceMinutes > 0 {
				opts.Since = time.Now().UTC().Add(-time.Duration(sinceMinutes) * time.Minute)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "tail running — ctrl-c to stop")
			if err := diag.Tail(ctx, database, cmd.OutOrStdout(), opts); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().IntVar(&intervalSecs, "interval", 1, "Poll interval in seconds")
	cmd.Flags().IntVar(&pageSize, "page-size", 100, "Max rows to read per poll")
	cmd.Flags().IntVar(&sinceMinutes, "since", 0, "Replay actions from the last N minutes before tailing live")
	return cmd
}

// loadConfigAndDB centralizes the config + DB open boilerplate that every
// command in this package needs. Caller must invoke cleanup() to close the DB.
//
// There is deliberately only ONE of these. It used to have a
// `loadConfigAndDBFast` twin that differed solely in passing
// SkipIntegrityCheck, and the split was the bug: `PRAGMA quick_check`
// checksums every page of the file, so the "slow" variant made every
// read-only reporting command's cost scale with the size of the database
// rather than with the query. On the reference 14.7 GB install that was
// >120s to print a table. Callers picked the wrong twin four separate times
// (the MCP server, the daemon, `observer run`, and then the ~85 sites
// reaching this function) because nothing at the call site signals which one
// is correct.
//
// db.Open no longer verifies by default (see db.Options.IntegrityCheck), so
// this is now uniformly the fast path. The probe still runs where it belongs:
// once per daemon via db.RunStartupMaintenance, off the readiness path, and
// as `observer doctor`'s reported `db.integrity` check.
func loadConfigAndDB(ctx context.Context, configPath string) (config.Config, *sql.DB, func(), error) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return config.Config{}, nil, func() {}, fmt.Errorf("load config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Observer.DBPath), 0o755); err != nil {
		return config.Config{}, nil, func() {}, fmt.Errorf("ensure db dir: %w", err)
	}
	// T1.4b (2026-08-26 disk/compute remediation plan): thread the
	// operator-tunable [observer.db] block into every db.Open call made
	// through this one central opener, instead of only the ones that
	// happened to construct db.Options by hand. Zero/empty config values
	// pass through unchanged — db.Open's own defaulting logic (built-in
	// 1024 MB heap / "memory" temp_store / 16 conns / 5 min idle) applies
	// exactly as it does for an unconfigured [observer.db] block; a
	// negative HardHeapLimitMB stays negative through the MB→bytes
	// multiply, preserving the negative-disables convention.
	database, err := db.Open(ctx, db.Options{
		Path:               cfg.Observer.DBPath,
		HardHeapLimitBytes: int64(cfg.Observer.DB.HardHeapLimitMB) * (1 << 20),
		TempStore:          cfg.Observer.DB.TempStore,
		MaxOpenConns:       cfg.Observer.DB.MaxOpenConns,
		ConnMaxIdleTime:    time.Duration(cfg.Observer.DB.ConnMaxIdleSeconds) * time.Second,
	})
	if err != nil {
		return config.Config{}, nil, func() {}, fmt.Errorf("open db %s: %w", cfg.Observer.DBPath, err)
	}
	cleanup := func() { _ = database.Close() }
	return cfg, database, cleanup, nil
}

// runStartupDBMaintenance runs the daemon's one-time DB integrity probe and
// schema-034 path-hash backfill in the background, OFF the readiness path.
// db.Open never verifies by default (fast bind); this pays
// the multi-GB `PRAGMA quick_check` exactly once, after the listener is
// already serving. Called from a single goroutine per daemon process
// (`observer start` / `observer proxy start` / `observer watch`).
//
// T2.2 (2026-08-26 disk/compute remediation plan, P1-D): above
// [observer.db].integrity_check_max_gb the quick_check half is skipped —
// its cost scales with the whole file, not with the work the daemon came
// to do, and on a very large DB it was the dominant startup CPU cost. The
// backfill half always runs regardless (cheap after its done-marker).
// `observer doctor` is unaffected — internal/diag/doctor.go's
// checkDBIntegrity calls `PRAGMA quick_check` directly and
// unconditionally, independent of this gate, as the authoritative
// on-demand probe.
//
// T2.3 (P1-F): guarded by a dblease so only one observer process on this
// machine runs this pass per tick; a second process fails open (proceeds
// anyway) on any lease error and simply skips its own pass when another
// process legitimately holds the lease.
//
// Fail-soft: a corruption result is logged loudly (Error, pointing at
// `observer doctor`) but never cancels the caller — the daemon is already up,
// and a false alarm from a transient read must not take it down. Uses its own
// short-lived handle so it doesn't outlive on a component's pool.
func runStartupDBMaintenance(ctx context.Context, configPath string) {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return
	}
	defer cleanup()
	logger := newLogger(cfg.Observer.LogLevel)

	release, proceed := acquireMaintenanceLease(cfg, "db-maintenance", logger)
	defer release()
	if !proceed {
		return
	}

	started := time.Now()
	if skip, sizeBytes := dbIntegrityCheckShouldSkip(cfg); skip {
		logger.Info(fmt.Sprintf(
			"database integrity check skipped (DB > %d GB) — run `observer doctor db` to verify on demand",
			cfg.Observer.DB.IntegrityCheckMaxGB,
		),
			"db_bytes", sizeBytes)
		if err := db.RunStartupBackfillOnly(ctx, database); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			logger.Error("db path-hash backfill failed", "err", err, "elapsed_ms", time.Since(started).Milliseconds())
		}
		return
	}
	if err := db.RunStartupMaintenance(ctx, database); err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		logger.Error("db startup maintenance failed — POSSIBLE CORRUPTION; run `observer doctor`",
			"err", err, "elapsed_ms", time.Since(started).Milliseconds())
		return
	}
	logger.Info("db integrity check ok (background)", "elapsed_ms", time.Since(started).Milliseconds())
}

// otlpIngressPostureCheck is the NODE-OTLP-1 doctor WARN (codebase audit
// 2026-09-16). The node's OTLP receiver is opened when [ingest.otel] or
// [observability] is enabled, and it binds loopback by default — in which case
// the receiver's own Host-header guard makes it a same-machine channel and
// there is nothing to warn about.
//
// `[ingest.otel].allow_non_loopback = true` is the posture that needs saying
// out loud: it opens the listener to the network AND, because that same flag is
// what tells the receiver it is no longer a same-machine channel, it turns the
// Host guard off. The node path has no receiver-token option at all
// (otlp.Options.RequireToken is edge-only; `observer start` never sets it), so
// the resulting listener is unauthenticated by construction — anyone who can
// reach the port can inject spans, drive a billable judge, or fabricate
// telemetry.
//
// WARN, never FAIL: it is a legitimate deliberate deployment (a host collecting
// from containers on a private bridge), it is off by default, and doctor's
// exit code must not flip on a documented operator choice.
func otlpIngressPostureCheck(cfg config.Config) diag.Check {
	const name = "otlp.ingress"
	enabled := cfg.Ingest.OTel.Enabled || cfg.Observability.Enabled
	if !enabled {
		return diag.Check{
			Name:    name,
			Status:  diag.StatusOK,
			Message: "OTLP receiver not opened ([ingest.otel] and [observability] both disabled)",
		}
	}
	if !cfg.Ingest.OTel.AllowNonLoopback {
		return diag.Check{
			Name:    name,
			Status:  diag.StatusOK,
			Message: "OTLP receiver is loopback-only (bind + Host-header guard)",
			Details: []string{
				fmt.Sprintf("grpc=%s http=%s", cfg.Ingest.OTel.GRPCAddr, cfg.Ingest.OTel.HTTPAddr),
			},
		}
	}
	return diag.Check{
		Name:    name,
		Status:  diag.StatusWarn,
		Message: "OTLP receiver is bound non-loopback with NO authentication",
		Details: []string{
			fmt.Sprintf("grpc=%s http=%s", cfg.Ingest.OTel.GRPCAddr, cfg.Ingest.OTel.HTTPAddr),
			"[ingest.otel].allow_non_loopback = true opens the receiver to the network",
			"it also disables the Host-header loopback guard (a non-loopback receiver must serve real host names)",
			"the node receiver has no token option — anything that can reach the port can inject telemetry",
			"set allow_non_loopback = false, or restrict the port with a host firewall",
		},
	}
}

// dbIntegrityCheckShouldSkip reports whether the AUTOMATIC startup
// `PRAGMA quick_check` should be skipped because the DB file exceeds
// [observer.db].integrity_check_max_gb (T2.2). Stat failures fail open
// (never skip — an unreadable size shouldn't silently disable the
// probe). ≤ 0 disables the gate: quick_check always runs.
func dbIntegrityCheckShouldSkip(cfg config.Config) (skip bool, sizeBytes int64) {
	maxGB := cfg.Observer.DB.IntegrityCheckMaxGB
	if maxGB <= 0 {
		return false, 0
	}
	fi, err := os.Stat(cfg.Observer.DBPath)
	if err != nil {
		return false, 0
	}
	sizeBytes = fi.Size()
	limit := int64(maxGB) << 30
	return sizeBytes > limit, sizeBytes
}

// acquireMaintenanceLease is the shared T2.3 dblease wrapper for the
// daemon's automatic maintenance entry points (this file's
// runStartupDBMaintenance, prune.go's retentionTickLoop/runRetention, and
// codeintel.go's runCodeIntelOnStart): a lease held by ANOTHER process
// (acquired=false, err==nil) means this pass legitimately skips — some
// other observer process is already doing the work. Any lease ERROR
// (e.g. the lock directory couldn't be created) must never block real
// work, so it fails open and proceeds as if the lease were held. The
// returned release is always safe to defer, even on the skip/error paths
// (it's a no-op there).
func acquireMaintenanceLease(cfg config.Config, name string, logger *slog.Logger) (release func(), proceed bool) {
	release, acquired, err := dblease.TryAcquire(filepath.Dir(cfg.Observer.DBPath), name)
	if err != nil {
		logger.Debug("dblease: acquire failed, proceeding without cross-process coordination",
			"lease", name, "err", err)
		return func() {}, true
	}
	if !acquired {
		logger.Debug("skipped: another observer holds the lease", "lease", name)
		return func() {}, false
	}
	return release, true
}

// printReport renders a diag.Report as one line per check, with optional
// indented detail lines for warn/fail entries.
// maxOversizeDetails caps the per-path bullets doctor prints for the
// oversize check; the count in the message is always the true total.
const maxOversizeDetails = 10

// maxOversizeScanRows bounds how many parse_cursors rows the oversize
// check stats. parse_cursors carries no size column, so answering the
// question costs one os.Stat per row; on a large install that is tens of
// thousands of syscalls on a command an operator expects to be instant.
// A truncated scan says so in the message rather than pretending the
// remainder is clean.
const maxOversizeScanRows = 5000

// oversizeCaptureCheck surfaces the session files the watcher's
// MaxFileBytes DoS guard is currently skipping — the operator-facing
// half of the P1-3 fix, which until now was WARN-in-the-log only and
// invisible to `observer status` / `doctor` / the dashboard.
//
// It reads the same two inputs the daemon's gate does (the persisted
// parse cursor and the file's size on disk) and applies the SAME
// predicate, [watcher.OversizeSkipped], so the operator can never read
// a different rule than the daemon applies. Files whose cursor is not a
// byte count (watermark stores) are exempt from the gate, so they are
// resolved out here through the adapters' own capability declaration
// (adapter.CursorSemantics), never by tool name.
//
// A skipped file is a WARN, not a FAIL: capture is stalled on it, but
// the rest of the daemon is healthy and a hook-captured tool call for
// that same session still lands.
func oversizeCaptureCheck(ctx context.Context, cfg config.Config, database *sql.DB) diag.Check {
	check := diag.Check{Name: "capture.oversize", Status: diag.StatusOK}
	capMB := cfg.Observer.Watch.MaxFileSizeMB
	maxBytes := int64(capMB) * 1024 * 1024
	if maxBytes <= 0 {
		check.Message = "oversize gate disabled ([observer.watch] max_file_size_mb = 0)"
		return check
	}
	entries, err := store.New(database).ListCursors(ctx)
	if err != nil {
		check.Status = diag.StatusWarn
		check.Message = fmt.Sprintf("could not read parse cursors: %v", err)
		return check
	}
	truncated := false
	if len(entries) > maxOversizeScanRows {
		entries = entries[:maxOversizeScanRows]
		truncated = true
	}
	adapters := adapterdefaults.Adapters()
	type stalled struct {
		path    string
		size    int64
		blocked int64
	}
	var list []stalled
	for _, e := range entries {
		info, statErr := os.Stat(e.SourceFile)
		if statErr != nil || info.IsDir() {
			continue
		}
		sem := adapter.ResolveCursorSemantics(adapters, e.SourceFile)
		if !sem.Kind.SizeGateMeaningful() {
			continue
		}
		streams := sem.DeltaGateMeaningful()
		if !watcher.OversizeSkipped(info.Size(), e.ByteOffset, maxBytes, streams) {
			continue
		}
		blocked := info.Size()
		if streams {
			blocked = watcher.OversizeUnreadDelta(info.Size(), e.ByteOffset)
		}
		list = append(list, stalled{path: e.SourceFile, size: info.Size(), blocked: blocked})
	}
	suffix := ""
	if truncated {
		suffix = fmt.Sprintf(" (first %d tracked files only)", maxOversizeScanRows)
	}
	if len(list) == 0 {
		check.Message = fmt.Sprintf("no tracked session file is past the %d MB oversize cap%s", capMB, suffix)
		return check
	}
	sort.Slice(list, func(i, j int) bool { return list[i].blocked > list[j].blocked })
	check.Status = diag.StatusWarn
	check.Message = fmt.Sprintf("%d tracked session file(s) skipped by the %d MB oversize gate%s — transcript capture is stalled on them", len(list), capMB, suffix)
	for i, s := range list {
		if i == maxOversizeDetails {
			check.Details = append(check.Details, fmt.Sprintf("… and %d more", len(list)-i))
			break
		}
		check.Details = append(check.Details, fmt.Sprintf("%s (size %d MB, over-cap bytes %d MB)",
			s.path, s.size/(1024*1024), s.blocked/(1024*1024)))
	}
	check.Details = append(check.Details,
		"raise [observer.watch] max_file_size_mb, or archive/rotate the file, to resume capture")
	return check
}

func printReport(w io.Writer, report diag.Report) {
	for _, c := range report.Checks {
		symbol := "✓"
		switch c.Status {
		case diag.StatusWarn:
			symbol = "⚠"
		case diag.StatusFail:
			symbol = "✗"
		}
		fmt.Fprintf(w, "%s %-20s %s\n", symbol, c.Name, c.Message)
		for _, d := range c.Details {
			fmt.Fprintf(w, "    %s\n", d)
		}
	}
	ok, warn, fail := report.Counts()
	fmt.Fprintf(w, "\n%d ok, %d warn, %d fail\n", ok, warn, fail)
	if fail == 0 && warn == 0 {
		// The one celebratory line the CLI allows itself (§9 voice
		// note, calm register): an all-green doctor run earns a star.
		fmt.Fprintf(w, "all checks passed ★\n")
	}
}
