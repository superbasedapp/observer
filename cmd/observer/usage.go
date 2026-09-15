package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	adapterdefaults "github.com/marmutapp/superbased-observer/internal/adapter/defaults"
	"github.com/marmutapp/superbased-observer/internal/adapter/mirrorbase"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/oneshot"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/watcher"
)

// The one-shot report's fixed vocabulary. Everything here is either a
// user-visible default documented in docs/plans/npx-one-shot-report-plan-2026-07-30.md
// §1.5 or a lifecycle constant of the scratch directory.
const (
	// oneShotDirPrefix names the scratch directory os.MkdirTemp creates
	// (inside TMPDIR) for one `observer usage` run. The prefix is also
	// the sweep key for orphans left by a `kill -9`.
	oneShotDirPrefix = "observer-usage-"
	// oneShotStaleAge is how old an orphaned scratch directory must be
	// before the best-effort sweep removes it.
	oneShotStaleAge = 24 * time.Hour
	// oneShotDBName is the scratch database's file name inside the
	// scratch directory. A directory (not a bare file) is used so one
	// RemoveAll reclaims the -wal and -shm siblings too.
	oneShotDBName = "usage.db"
	// oneShotSchema is the stable --json envelope discriminator
	// (plan §2.5). Additive-only.
	oneShotSchema = "superbased.usage/1"
	// oneShotDefaultBudget is the default wall-clock budget around the
	// scan (0 disables it). It guarantees a bounded first paint so the
	// command can never hang a script or a demo.
	oneShotDefaultBudget = 30 * time.Second
	// oneShotCountBudget bounds the (best-effort, budget-expiry-only)
	// enumeration that turns "read N files" into "read N of M files".
	oneShotCountBudget = 2 * time.Second
	// oneShotMirrorDirName is the subdirectory of the scratch dir that
	// internal/adapter/mirrorbase.SetBaseForProcess redirects every
	// foreign-mount SQLite mirror write into for the duration of one
	// run (F1): it dies with the scratch dir instead of landing under
	// the operator's persistent os.UserCacheDir().
	oneShotMirrorDirName = "mirror"
	// oneShotPIDFileName is the file the scratch dir carries recording
	// the PID that created it, so a concurrent invocation's orphan
	// sweep (sweepStaleOneShotDirs) can tell a still-running --budget 0
	// scan apart from a genuine kill -9 orphan (F13) instead of relying
	// on directory mtime alone.
	oneShotPIDFileName = "pid"
	// oneShotStaleHardCap is the liveness-unknown fallback age: a
	// scratch dir with no readable/parseable pidfile (an old binary's
	// orphan, or a corrupted write) is left alone until it is this old,
	// then swept regardless. Reasoning (F13): the safe direction on an
	// UNKNOWN liveness read is to NOT delete — a false-positive sweep
	// destroys a live --budget 0 run's only copy of its scratch DB —
	// but "unknown forever" would let those same corrupted-pidfile
	// orphans accumulate without bound, so a generous cap (far beyond
	// any believable single invocation) still reclaims them eventually.
	oneShotStaleHardCap = 7 * 24 * time.Hour
)

// usageDeps are the injectable I/O seams of the one-shot usage path.
// Production wiring is defaultUsageDeps(); tests substitute a fixed
// adapter set (so a scan never walks the operator's real homes) and a
// fixed clock.
type usageDeps struct {
	// adapters returns the adapter set to scan. Production:
	// adapterdefaults.Adapters (every registered adapter, with NO
	// per-adapter enrichment — see buildOneShotRegistry).
	adapters func() []adapter.Adapter
	// homeDir resolves the user's home directory (os.UserHomeDir, which
	// honors $HOME).
	homeDir func() (string, error)
	// getenv is the environment lookup. It is ALSO the source the
	// OBSERVER_* filter (oneShotEnv) wraps before handing it to
	// config.Load.
	getenv func(key string) string
	// now is the clock the reporting window is anchored to.
	now func() time.Time
}

// defaultUsageDeps returns the production seams.
func defaultUsageDeps() usageDeps {
	return usageDeps{
		adapters: adapterdefaults.Adapters,
		homeDir:  os.UserHomeDir,
		getenv:   os.Getenv,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// usageOptions is the flag surface of `observer usage` (plan §1.5).
type usageOptions struct {
	since      string
	days       int
	daysSet    bool
	groupBy    string
	tool       string
	budget     time.Duration
	jsonOut    bool
	keepDB     string
	configPath string
	noProgress bool
}

// defaultUsageOptions returns the flag defaults. Used by the bare-root
// fallthrough, which runs the report without a parsed flag set.
func defaultUsageOptions() usageOptions {
	return usageOptions{
		since:   "30d",
		groupBy: "tool-model",
		budget:  oneShotDefaultBudget,
	}
}

// newUsageCmd wires `observer usage` — the zero-config, zero-network,
// one-shot cost report — against the given I/O seams. Production callers
// pass defaultUsageDeps(); tests pass stubs (see usage_test.go).
func newUsageCmd(deps usageDeps) *cobra.Command {
	o := defaultUsageOptions()
	cmd := &cobra.Command{
		Use:   "usage",
		Short: "One-shot cost table from your AI tools' own session files (no daemon, throwaway DB)",
		Long: `Scans every detected AI coding tool's own local session files into a
THROWAWAY database in a temp directory, prints one tool × model cost
table, and deletes the database again.

Zero configuration, zero network calls: pricing is embedded in the
binary, nothing is fetched at runtime. Nothing is written outside the
scratch directory — in particular this command never creates or reads
~/.observer, never writes any AI tool's config, and never binds a port.
By default it also IGNORES ~/.observer/config.toml (so the numbers are
reproducible on any machine); pass --config <path> to honor a real
config and its [intelligence.pricing] overrides.

The window is enforced twice: session files last modified before it are
never opened, and rows outside it are excluded from the rollup. The scan
is wrapped in a wall-clock --budget (default 30s, 0 = unlimited); on
expiry the table still prints, with an honest "partial" footer.

Sibling commands, so the split is clear:

  observer usage   one-shot on a throwaway DB — what you're reading now
  observer scan    ingest into the DB at ~/.observer/observer.db
  observer cost    query the DB you've been capturing into (and, once
                   you run ` + "`observer start`" + `, the wire-accurate
                   proxy-tier turns it collects)

Bare ` + "`observer`" + ` runs this report too, but only on a machine with no
local state (no ~/.observer/observer.db, no ~/.observer/config.toml, no
daemon listening); otherwise it prints the welcome screen. Set
OBSERVER_ONESHOT=off to always get the welcome screen.

Dollar figures are ` + oneshot.PriceBasis + `.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			o.daysSet = cmd.Flags().Changed("days")
			return runUsage(cmd, o, deps)
		},
	}
	cmd.Flags().StringVar(&o.since, "since", o.since, "Window: 7d | 30d | 90d | all | an RFC3339 timestamp")
	// NB: no backticks in any flag description — cobra reads a backticked
	// word as the flag's value placeholder in --help.
	cmd.Flags().IntVar(&o.days, "days", 0, "Alias for --since <N>d (symmetry with the cost command)")
	cmd.Flags().StringVar(&o.groupBy, "group-by", o.groupBy, "Rollup key: tool-model | tool | model | day")
	cmd.Flags().StringVar(&o.tool, "tool", "", "Restrict the report to a single tool (e.g. claude-code)")
	cmd.Flags().DurationVar(&o.budget, "budget", o.budget, "Wall-clock budget for the scan only (0 = unlimited)")
	cmd.Flags().BoolVar(&o.jsonOut, "json", false, "Emit the machine-readable "+oneShotSchema+" JSON shape (suppresses progress)")
	cmd.Flags().StringVar(&o.keepDB, "keep-db", "", "Keep the scratch database at this path instead of deleting it")
	cmd.Flags().StringVar(&o.configPath, "config", "", "Honor this config.toml (default: ignore every config and every OBSERVER_* env var)")
	cmd.Flags().BoolVar(&o.noProgress, "no-progress", false, "Suppress scan progress on stderr (implied by --json and by a non-TTY stderr)")
	return cmd
}

// runUsage is the whole one-shot flow (plan §2.2), in order: install the
// signal handler, parse the window, sweep orphaned scratch dirs, create
// this run's scratch dir, load a config that reaches for nothing on disk,
// open the scratch DB, scan every detected adapter into it under the
// budget, roll the result up through the shared cost engine, map that
// single result into the pure oneshot.Table shape, print it, and delete
// everything.
//
// It deliberately does NOT use cmd/observer's shared
// load-config-then-open-DB helper (diag.go), because that helper MkdirAlls
// the config-derived database directory — i.e. it would create
// ~/.observer, the exact side effect this feature promises not to have.
// It also never sets db.Options.IntegrityCheck, and never constructs a
// stamper, guard, classifier, indexer, or cache engine — see plan §2.4 for
// the full list of side effects this path is contractually free of.
func runUsage(cmd *cobra.Command, o usageOptions, deps usageDeps) error {
	// The signal handler is installed FIRST, before anything is created
	// on disk (F4): if os.MkdirTemp ran first and a ^C landed in the gap
	// before this handler existed, the OS default disposition would kill
	// the process immediately — no Go defer ever runs on that path, so
	// the freshly created scratch dir (and, once F1 lands below, its
	// mirrorbase override) would leak with nothing left to sweep it
	// until the next run's orphan sweep picks it up 24h later. Installing
	// the handler first guarantees that by the time the scratch dir
	// exists, a ^C is already being converted into graceful ctx
	// cancellation instead of an immediate kill.
	ctx, stopSignals := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	// A SECOND ^C must hard-terminate a wedged scan rather than wait on
	// graceful cleanup that may never finish (F4b): once the first signal
	// fires (ctx.Done), immediately restore Go's default disposition for
	// the same two signals so the next one kills the process the normal
	// way, exactly as if this handler had never been installed. stop() is
	// safe to call more than once (also deferred above).
	go func() {
		<-ctx.Done()
		stopSignals()
	}()

	sinceSpec := o.since
	if o.daysSet && o.days > 0 {
		sinceSpec = strconv.Itoa(o.days) + "d"
	}
	since, windowLabel, err := oneshot.Window(sinceSpec, deps.now())
	if err != nil {
		return fmt.Errorf("usage: %w", err)
	}
	groupBy, err := parseUsageGroupBy(o.groupBy)
	if err != nil {
		return fmt.Errorf("usage: %w", err)
	}

	// Best-effort cleanup of scratch dirs orphaned by a kill -9 in an
	// earlier run (precedent: claude_proxy_route.go::sweepStaleBypassFiles).
	sweepStaleOneShotDirs(os.TempDir(), oneShotStaleAge)

	tmp, err := os.MkdirTemp("", oneShotDirPrefix+"*")
	if err != nil {
		return fmt.Errorf("usage: create scratch dir: %w", err)
	}
	// removeScratch is turned off below if --keep-db fails every fallback
	// (F9): the scratch database is the only intact copy of this run's
	// data at that point, and this deferred cleanup must not destroy it
	// out from under the operator.
	removeScratch := true
	defer func() {
		if removeScratch {
			_ = os.RemoveAll(tmp)
		}
	}()
	// Best-effort: a failure to write the pidfile just means the orphan
	// sweep falls back to its liveness-unknown hard-cap path for this
	// dir (F13) — never fatal to the run itself.
	writeOneShotPIDFile(tmp)

	// Every foreign-mount SQLite mirror write (7 adapters —
	// internal/adapter/mirrorbase's doc comment names them) is
	// redirected into the scratch dir for the remainder of this process
	// (F1): it dies with the deferred RemoveAll above instead of
	// persisting under the operator's os.UserCacheDir(), which would
	// violate this command's "nothing survives outside the temp dir"
	// contract. Reset on the way out — this process is about to exit
	// anyway, but the test binary runs many invocations in one process
	// image, so leaving the override set would leak into whatever runs
	// next.
	mirrorbase.SetBaseForProcess(filepath.Join(tmp, oneShotMirrorDirName))
	defer mirrorbase.SetBaseForProcess("")

	cfg, err := loadOneShotConfig(o.configPath, tmp, deps)
	if err != nil {
		return err
	}
	// In memory only — no process-wide environment mutation (the trick
	// `backfill --dry-run` needs is unnecessary here: nothing downstream
	// re-loads the config), and no config write.
	cfg.Observer.DBPath = filepath.Join(tmp, oneShotDBName)

	// IntegrityCheck deliberately left at its false default: the probe is
	// a full-file checksum and this database is empty and brand new.
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		return fmt.Errorf("usage: open scratch db: %w", err)
	}
	dbClosed := false
	closeDB := func() {
		if !dbClosed {
			dbClosed = true
			_ = database.Close()
		}
	}
	defer closeDB()

	progress := newUsageProgress(cmd.ErrOrStderr(), o.noProgress || o.jsonOut)
	scan := scanOneShot(ctx, scanOneShotParams{
		cfg:      cfg,
		database: database,
		adapters: deps.adapters(),
		since:    since,
		budget:   o.budget,
		progress: progress,
	})
	if cerr := ctx.Err(); cerr != nil {
		// Interrupted, not budget-expired (the budget lives on a derived
		// context). Bail out; the deferred cleanup still runs.
		return fmt.Errorf("usage: interrupted: %w", cerr)
	}

	sum, err := acquireProcessCostEngine(ctx, cfg, database, slog.Default()).Summary(ctx, database, cost.Options{
		Since:   since,
		GroupBy: groupBy,
		Source:  cost.SourceAuto,
		Tool:    o.tool,
		Limit:   0, // engine default: the 50 highest-cost rows (see rowLimitNote)
		Now:     deps.now,
	})
	if err != nil {
		return fmt.Errorf("usage: cost rollup: %w", err)
	}

	// The TOTAL line's "N tools · M models" distinct counts (F11) are
	// deliberately computed from a SEPARATE, always-model-tool-keyed,
	// effectively-uncapped rollup over the same window/tool filter —
	// never from sum.Rows above. Two independent bugs made the old
	// per-groupBy derivation lie: (a) under --group-by day, cost.Row.Key
	// IS the bare date (groupKey never encodes tool/model for that
	// grouping), so counting distinct row keys counted DAYS as if they
	// were tools ("30 tools · 0 models"); (b) under the default
	// tool-model grouping, sum.Rows is already capped at the engine's
	// 50-highest-cost-rows default, so a corpus with >50 distinct
	// tool×model pairs under-counted silently. This query's raised Limit
	// makes that cap a non-issue for any realistic one-shot corpus.
	distinctTools, distinctModels, derr := oneShotDistinctCounts(ctx, cfg, database, since, o.tool, deps.now)
	if derr != nil {
		// Non-fatal: the TOTAL line's distinct counts degrade to
		// whatever summaryToTable already derived from sum.Rows rather
		// than failing the whole report over a display-only figure.
		distinctTools, distinctModels = -1, -1
	}

	// Everything below reads only in-memory values, so the scratch DB can
	// be released now — which is also what makes --keep-db a clean move
	// (no live WAL) before the deferred RemoveAll.
	closeDB()
	keptDB, err := keepScratchDB(cfg.Observer.DBPath, o.keepDB)
	if err != nil {
		// keepScratchDB already tried a rename and a same-filesystem
		// stream-copy fallback; both failed. Preserve the scratch dir
		// instead of letting the deferred RemoveAll above destroy the
		// only intact copy of this run's database (F9) — the wrapped
		// error names exactly where it survives.
		removeScratch = false
		return err
	}

	table := summaryToTable(sum, groupBy, since, windowLabel)
	if distinctTools >= 0 {
		table.ToolCount = distinctTools
	}
	if distinctModels >= 0 {
		table.ModelCount = distinctModels
	}
	applyScanState(&table, scan, oneShotHomeLabel(deps), o.budget)
	table.Notes = oneshot.Notes(integration.Capabilities(), scan.toolsScanned, oneshot.State{
		UnknownModelCount: table.UnknownModelCount,
		UnpricedTokens:    table.UnpricedTokens,
		Partial:           table.Partial,
		Empty:             table.Empty,
	})
	table.Notes = append(table.Notes, oneShotExtraNotes(oneShotExtraNoteInput{
		summary:       sum,
		scanErrors:    scan.errors,
		keptDB:        keptDB,
		ignoredConfig: ignoredConfigPath(o.configPath, deps),
	})...)

	if o.jsonOut {
		return writeUsageJSON(cmd.OutOrStdout(), table)
	}
	out := cmd.OutOrStdout()
	fmt.Fprint(out, oneshot.Render(table, oneshot.RenderOptions{Color: usageColorEnabled(out, deps)}))
	return nil
}

// parseUsageGroupBy maps the --group-by vocabulary onto the cost engine's
// existing GroupBy values. tool-model is the default two-column shape; day
// puts the date in the leftmost (TOOL) cell, since the report's column set
// is fixed.
func parseUsageGroupBy(s string) (cost.GroupBy, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "tool-model", "model-tool":
		return cost.GroupByModelTool, nil
	case "tool":
		return cost.GroupByTool, nil
	case "model":
		return cost.GroupByModel, nil
	case "day":
		return cost.GroupByDay, nil
	default:
		return "", fmt.Errorf("--group-by %q not in {tool-model, tool, model, day}", s)
	}
}

// loadOneShotConfig loads the configuration this run will use.
//
// With no --config the GlobalPath points at a file that cannot exist
// (inside the scratch dir), which config.Load treats as "no file" and
// yields pure config.Default() — and the Env lookup is filtered so a
// stray OBSERVER_* variable in the caller's environment can neither
// redirect the database nor re-enable the one capture path that opens a
// socket ([observer.antigravity] network_recovery). With --config both
// the file and the environment are honored, because opting in is the
// whole point of the flag.
func loadOneShotConfig(configPath, tmp string, deps usageDeps) (config.Config, error) {
	globalPath := configPath
	honorEnv := configPath != ""
	if globalPath == "" {
		globalPath = filepath.Join(tmp, "absent.toml")
	}
	cfg, err := config.Load(config.LoadOptions{
		GlobalPath: globalPath,
		Env:        oneShotEnv(deps.getenv, honorEnv),
	})
	if err != nil {
		return config.Config{}, fmt.Errorf("usage: load config: %w", err)
	}
	return cfg, nil
}

// oneShotEnv returns the environment lookup config.Load should use. On the
// default path every OBSERVER_* key reads as unset — the zero-config
// promise is only real if the caller's environment cannot silently
// redirect this run. With --config (honorEnv) the caller has explicitly
// asked for their own configuration, environment included.
func oneShotEnv(getenv func(string) string, honorEnv bool) func(string) string {
	if getenv == nil {
		getenv = os.Getenv
	}
	if honorEnv {
		return getenv
	}
	return func(key string) string {
		if strings.HasPrefix(key, "OBSERVER_") {
			return ""
		}
		return getenv(key)
	}
}

// sweepStaleOneShotDirs removes observer-usage-* scratch directories under
// dir that are older than maxAge — orphans of a `kill -9` that never ran
// the deferred RemoveAll. Best-effort: unreadable dirs, foreign-owned
// entries (a shared, non-sticky TMPDIR can hold another user's LIVE run),
// and failed removals are all silently skipped.
func sweepStaleOneShotDirs(dir string, maxAge time.Duration) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	hardCutoff := time.Now().Add(-oneShotStaleHardCap)
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), oneShotDirPrefix) {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil || !info.ModTime().Before(cutoff) {
			continue
		}
		if !fileOwnedByCurrentUser(info) {
			continue
		}
		full := filepath.Join(dir, e.Name())
		if oneShotDirLive(full, info.ModTime(), hardCutoff) {
			// A directory this old normally means an orphan, but its
			// pidfile says otherwise (or liveness is unknown and it is
			// still within the hard cap) — a --budget 0 scan can
			// legitimately run far longer than oneShotStaleAge (F13).
			// Leave it for the next sweep to re-check.
			continue
		}
		_ = os.RemoveAll(full)
	}
}

// oneShotDirLive reports whether the scratch directory at path should be
// preserved from the sweep because its recorded owner process is still
// running (F13). Directory mtime alone is not liveness — a long
// --budget 0 scan can leave its scratch dir's mtime stale (nothing
// touches it after the initial writes) well past oneShotStaleAge while
// still actively running.
//
// Three outcomes:
//  1. a readable, parseable pidfile naming a live process — preserve;
//  2. a readable, parseable pidfile naming a dead process — sweep it;
//  3. liveness is UNKNOWN (missing or unparsable pidfile — a pre-F13
//     binary's orphan, or a corrupted write) — the safe default is to
//     preserve, because a false-positive sweep destroys a live run's
//     only copy of its scratch database, but that would let unknown-
//     liveness orphans accumulate forever, so past oneShotStaleHardCap
//     an unknown-liveness dir is swept anyway.
func oneShotDirLive(path string, modTime, hardCutoff time.Time) bool {
	raw, err := os.ReadFile(filepath.Join(path, oneShotPIDFileName)) //nolint:gosec // G304: path is a TMPDIR entry already validated by prefix+ownership above.
	if err != nil {
		return modTime.After(hardCutoff)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return modTime.After(hardCutoff)
	}
	return oneShotProcessAlive(pid)
}

// writeOneShotPIDFile records this process's PID in the scratch dir so a
// concurrent invocation's orphan sweep (sweepStaleOneShotDirs) can tell a
// still-running --budget 0 scan apart from a genuine kill -9 orphan (F13)
// instead of relying on directory mtime alone. Best-effort: a write
// failure just means the sweep falls back to the liveness-unknown
// hard-cap path for this dir — never fatal to the run itself.
func writeOneShotPIDFile(tmp string) {
	_ = os.WriteFile(filepath.Join(tmp, oneShotPIDFileName), []byte(strconv.Itoa(os.Getpid())), 0o600)
}

// oneShotProcessAlive reports whether pid names a live process on this
// OS. Mirrors the pattern in internal/diag/lockfile.go's unexported
// processAlive (duplicated here, not imported, since that helper is
// unexported and internal/diag is outside this task's file set).
func oneShotProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		// os.FindProcess only succeeds on Windows by opening a live
		// process handle, so success alone already proves liveness —
		// there is no portable signal(0) probe to layer on top.
		return true
	}
	sigErr := proc.Signal(syscall.Signal(0))
	if sigErr == nil {
		return true
	}
	// EPERM means the process exists (owned by someone else) — still
	// alive from this sweep's perspective; any other error (typically
	// ESRCH) means it is gone.
	return errors.Is(sigErr, syscall.EPERM)
}

// oneShotRenameFile is os.Rename behind a package-level var so a test can
// force the cross-device fallback path in keepScratchDB deterministically
// (F9) without needing an actual second filesystem.
var oneShotRenameFile = os.Rename

// keepScratchDB implements --keep-db: it moves the scratch database out of
// the (about to be deleted) scratch directory to dest and returns the
// absolute path it landed on. An empty dest is a no-op returning "".
//
// os.Rename is tried first (same-filesystem fast path). On failure
// (typically EXDEV — dest is on a different filesystem than the scratch
// dir) it falls back to a stream copy (io.Copy on opened files, never the
// whole database read into memory — F9, the scratch DB can be sizeable)
// into a temp file IN dest's directory, fsync+close, then an os.Rename of
// THAT into place — same-filesystem, so the publish step is still atomic
// and a reader never observes a partially written dest path.
//
// If every path fails, the error is returned AND the source is left
// intact rather than silently lost: runUsage's caller skips the scratch
// dir's deferred RemoveAll whenever this returns a non-nil error, so the
// scratch database — the only copy of this run's data — survives at src
// for manual recovery. The returned error names that path.
func keepScratchDB(src, dest string) (string, error) {
	if dest == "" {
		return "", nil
	}
	abs, err := filepath.Abs(dest)
	if err != nil {
		return "", fmt.Errorf("usage: --keep-db %q: %w", dest, err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return "", fmt.Errorf("usage: --keep-db %q: %w", dest, err)
	}
	if err := oneShotRenameFile(src, abs); err == nil {
		return abs, nil
	}
	kept, cerr := keepScratchDBByCopy(src, abs)
	if cerr == nil {
		return kept, nil
	}
	return "", fmt.Errorf("usage: --keep-db %q: %w (the scratch database was NOT moved — it survives at %s until this process exits; copy it out before then)", dest, cerr, src)
}

// keepScratchDBByCopy is keepScratchDB's cross-device fallback: stream-copy
// src into a same-directory-as-dest temp file, sync+close it, then rename
// it onto abs. The temp file is removed on any failure so a half-written
// artifact never lands at the caller-visible path.
func keepScratchDBByCopy(src, abs string) (string, error) {
	in, err := os.Open(src) //nolint:gosec // G304: src is this process's own scratch database path.
	if err != nil {
		return "", fmt.Errorf("open scratch db: %w", err)
	}
	defer in.Close()

	tmpFile, err := os.CreateTemp(filepath.Dir(abs), ".usage-keepdb-*")
	if err != nil {
		return "", fmt.Errorf("create destination temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	published := false
	defer func() {
		if !published {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := io.Copy(tmpFile, in); err != nil {
		_ = tmpFile.Close()
		return "", fmt.Errorf("copy scratch db: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return "", fmt.Errorf("sync scratch db: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return "", fmt.Errorf("close scratch db: %w", err)
	}
	if err := os.Rename(tmpPath, abs); err != nil {
		return "", fmt.Errorf("publish scratch db: %w", err)
	}
	published = true
	return abs, nil
}

// ignoredConfigPath returns the path of a real config.toml that exists but
// was deliberately NOT read on this run (so the footer can say so), or ""
// when --config was passed or no such file exists.
func ignoredConfigPath(configPath string, deps usageDeps) string {
	if configPath != "" {
		return ""
	}
	home, err := deps.homeDir()
	if err != nil || home == "" {
		return ""
	}
	p := filepath.Join(home, ".observer", "config.toml")
	if !oneShotFileExists(p) {
		return ""
	}
	return p
}

// oneShotHomeLabel is the display value for "where we looked" in the
// empty-corpus line: the resolved home directory, or the literal "$HOME"
// when it cannot be resolved.
func oneShotHomeLabel(deps usageDeps) string {
	if home, err := deps.homeDir(); err == nil && home != "" {
		return home
	}
	return "$HOME"
}

// oneShotFileExists reports whether path exists as something other than a
// directory. Read-only, one Stat, never an error to the caller.
func oneShotFileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

// usageColorEnabled reports whether the rendered table may carry ANSI
// escapes: only when it is going to a real terminal on stdout and NO_COLOR
// is unset. A redirected or test-captured writer always gets plain bytes.
func usageColorEnabled(out io.Writer, deps usageDeps) bool {
	if out != io.Writer(os.Stdout) {
		return false
	}
	if deps.getenv("NO_COLOR") != "" {
		return false
	}
	return stdoutIsTerminal()
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

// scanOneShotParams bundles the inputs of one scan pass.
type scanOneShotParams struct {
	cfg      config.Config
	database *sql.DB
	adapters []adapter.Adapter
	since    time.Time
	budget   time.Duration
	progress *usageProgress
}

// scanOneShotResult is what the scan pass reports back.
type scanOneShotResult struct {
	// toolsScanned names the adapters that were actually detected and
	// walked, in scan order. This — not "tools that produced rows" — is
	// the input oneshot.Notes needs: a tool whose files we read but whose
	// tokens are unavailable locally is exactly the case the honesty
	// footer exists to explain.
	toolsScanned []string
	// filesProcessed / errors accumulate across adapters.
	filesProcessed int
	errors         int
	// budgetHit is true when the wall-clock budget expired mid-scan.
	budgetHit bool
	// filesTotal is the best-known total session-file count; only
	// populated (best-effort) when budgetHit.
	filesTotal int
	// adaptersConsidered / rootsChecked describe the search space, for the
	// empty-corpus note.
	adaptersConsidered int
	rootsChecked       []string
}

// scanOneShot walks every detected adapter's session files into the
// scratch database under the wall-clock budget.
//
// Deliberately LEANER than cmd/observer's buildWatcherWithOverride: no
// per-adapter enrichment (the cursor / clinecli / hermes hook-dedup
// checkers and the claude-code effort lookup exist to dedup against
// hook-captured rows, and a brand-new scratch database has none), no org
// stamper, no guard, no freshness classifier, no FTS5 indexer, no cache
// engine, and — the one that matters for plan §2.4 — the antigravity
// network-recovery opt-in is never enabled, since that is the single
// capture path that would open a socket (a localhost gRPC call).
//
// One watcher is built per adapter (Allow scoped to that one name) purely
// so progress can be reported per tool and a budget expiry can be
// observed between tools; the watcher's own scan remains serial, which is
// the only shape the daemon has ever run.
func scanOneShot(ctx context.Context, p scanOneShotParams) scanOneShotResult {
	var res scanOneShotResult

	reg := buildOneShotRegistry(p.adapters)
	allow := p.cfg.Observer.Watch.EnabledAdapters
	detected := reg.Detected(allow)
	res.adaptersConsidered = len(p.adapters)
	res.rootsChecked = oneShotCandidateRoots(p.adapters)

	names := make([]string, 0, len(detected))
	for _, a := range detected {
		names = append(names, a.Name())
	}
	p.progress.detected(names, len(p.adapters))
	if len(detected) == 0 {
		return res
	}

	scanCtx := ctx
	if p.budget > 0 {
		var cancel context.CancelFunc
		scanCtx, cancel = context.WithTimeout(ctx, p.budget)
		defer cancel()
	}

	st := store.New(p.database)
	for _, a := range detected {
		if scanCtx.Err() != nil {
			break
		}
		p.progress.start(a.Name())
		w := watcher.New(st, reg, watcher.Options{
			Logger:             oneShotLogger{},
			Allow:              []string{a.Name()},
			Classifier:         nil,
			Indexer:            nil,
			MaxFileBytes:       int64(p.cfg.Observer.Watch.MaxFileSizeMB) * 1024 * 1024,
			SkipModifiedBefore: p.since,
		})
		// Scan (not Rescan): the scratch DB has no cursors, so every file
		// is read from offset 0 anyway.
		r, err := w.Scan(scanCtx)
		res.filesProcessed += r.FilesProcessed
		res.errors += r.Errors
		if err != nil {
			res.errors++
		}
		res.toolsScanned = append(res.toolsScanned, a.Name())
		p.progress.done(a.Name(), r.FilesProcessed)
	}
	p.progress.finish(res.filesProcessed, res.errors)

	if errors.Is(scanCtx.Err(), context.DeadlineExceeded) {
		res.budgetHit = true
		res.filesTotal = countOneShotSessionFiles(ctx, detected, p.since, res.filesProcessed)
	}
	return res
}

// buildOneShotRegistry registers every supplied adapter with NO
// per-adapter enrichment (see scanOneShot's doc comment for why each
// omission is safe on a throwaway database).
func buildOneShotRegistry(adapters []adapter.Adapter) *adapter.Registry {
	reg := adapter.NewRegistry()
	for _, a := range adapters {
		reg.Register(a)
	}
	return reg
}

// oneShotCandidateRoots lists every adapter watch root that was checked,
// deduped and sorted — the "looked in" set behind the empty-corpus note.
func oneShotCandidateRoots(adapters []adapter.Adapter) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, a := range adapters {
		for _, r := range a.WatchPaths() {
			if r == "" {
				continue
			}
			if _, ok := seen[r]; ok {
				continue
			}
			seen[r] = struct{}{}
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}

// countOneShotSessionFiles counts the session files the given adapters
// claim WITHIN the reporting window (since — a zero value means no
// filter, matching watcher.go's own SkipModifiedBefore semantics), so a
// budget-truncated run can say "read N of M" with M denominated over the
// same window the scan itself honored (F12) — not every file the adapter
// has ever produced. Best-effort and itself time-boxed (oneShotCountBudget)
// — an incomplete count degrades to floor, never below the number already
// read, so the footer can never claim we read more files than exist.
func countOneShotSessionFiles(ctx context.Context, adapters []adapter.Adapter, since time.Time, floor int) int {
	countCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), oneShotCountBudget)
	defer cancel()
	total := 0
	for _, a := range adapters {
		for _, root := range a.WatchPaths() {
			_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
				if countCtx.Err() != nil {
					return countCtx.Err()
				}
				if err != nil || d.IsDir() {
					return nil //nolint:nilerr // a missing/unreadable root simply contributes nothing
				}
				if !a.IsSessionFile(path) {
					return nil
				}
				// Mirror watcher.go's own SkipModifiedBefore semantics
				// (F12): the scan this count is reconciled against skips
				// files older than the window, so a bare file count with
				// no mtime filter over-counts the denominator — the
				// footer would read "read N of M" with M inflated by
				// every out-of-window file the scan never intended to
				// touch. Fail open (count it in) when mtime can't be
				// read, exactly like the scan does.
				if !since.IsZero() {
					if info, infoErr := d.Info(); infoErr == nil && info.ModTime().Before(since) {
						return nil
					}
				}
				total++
				return nil
			})
		}
	}
	if total < floor {
		return floor
	}
	return total
}

// oneShotLogger silences the watcher's per-file chatter on this path: the
// table on stdout is the whole output, and scan problems are surfaced as
// one counted stderr line instead of a stream of per-file warnings.
type oneShotLogger struct{}

func (oneShotLogger) Debug(string, ...any) {}
func (oneShotLogger) Info(string, ...any)  {}
func (oneShotLogger) Warn(string, ...any)  {}
func (oneShotLogger) Error(string, ...any) {}

// ---------------------------------------------------------------------------
// progress (stderr only — stdout stays byte-clean so the table pipes)
// ---------------------------------------------------------------------------

// usageProgress writes scan progress to stderr. On a TTY it rewrites one
// line in place; otherwise it prints one plain line per adapter. Silenced
// entirely by --no-progress and by --json.
type usageProgress struct {
	w     io.Writer
	tty   bool
	quiet bool
	// lastWidth is the visible width of the in-place TTY line, so the
	// next write can blank the remainder.
	lastWidth int
}

// newUsageProgress builds the progress reporter for w.
func newUsageProgress(w io.Writer, quiet bool) *usageProgress {
	return &usageProgress{w: w, tty: !quiet && w == io.Writer(os.Stderr) && stderrIsTerminal(), quiet: quiet || w == nil}
}

// detected prints the "signs of life" line: which tools were found, out of
// how many adapters checked. Printed BEFORE any walking starts.
func (p *usageProgress) detected(tools []string, considered int) {
	if p.quiet {
		return
	}
	if len(tools) == 0 {
		fmt.Fprintf(p.w, "no AI coding tools detected (%d adapters checked)\n", considered)
		return
	}
	fmt.Fprintf(p.w, "detected %d of %d adapters: %s\n", len(tools), considered, strings.Join(tools, ", "))
}

// start announces the adapter about to be walked.
func (p *usageProgress) start(tool string) {
	if p.quiet || !p.tty {
		return
	}
	p.line("scanning " + tool + " …")
}

// done reports one adapter's completed walk.
func (p *usageProgress) done(tool string, files int) {
	if p.quiet {
		return
	}
	msg := fmt.Sprintf("scanned %s — %d file(s)", tool, files)
	if p.tty {
		p.line(msg)
		return
	}
	fmt.Fprintln(p.w, msg)
}

// finish clears the in-place TTY line and, when the scan hit errors,
// reports them in exactly one line.
func (p *usageProgress) finish(files, errCount int) {
	if p.quiet {
		return
	}
	if p.tty {
		p.line("")
		fmt.Fprint(p.w, "\r")
	}
	if errCount > 0 {
		fmt.Fprintf(p.w, "%d file(s) could not be parsed and were skipped (%d read)\n", errCount, files)
	}
}

// line rewrites the single in-place TTY progress line, padding out the
// previous content so a shorter message leaves no tail behind.
func (p *usageProgress) line(msg string) {
	pad := 0
	if n := p.lastWidth - len([]rune(msg)); n > 0 {
		pad = n
	}
	fmt.Fprint(p.w, "\r"+msg+strings.Repeat(" ", pad))
	p.lastWidth = len([]rune(msg))
}

// stderrIsTerminal reports whether stderr is an interactive console —
// the gate for in-place progress rewriting. Mirrors stdoutIsTerminal.
func stderrIsTerminal() bool {
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// ---------------------------------------------------------------------------
// cost.Summary → oneshot.Table (THE seam: no cost.* type leaks past here)
// ---------------------------------------------------------------------------

// summaryToTable maps one cost.Summary into the pure oneshot.Table value
// type. This function is the single translation seam between the cost
// engine and the renderer (CLAUDE.md #2) — nothing else in this file, and
// nothing at all in internal/oneshot, touches a cost.* type.
//
// Row keys are unpacked according to the GroupBy that produced them; the
// engine's sentinels ("<unknown>" model, "<no-tool>" tool) are carried
// through verbatim rather than blanked, because "we don't know" is the
// honest cell content. CACHE_W sums 5-minute and 1-hour cache writes:
// both are cache-creation volume, and the report has one cache-write
// column.
func summaryToTable(sum cost.Summary, groupBy cost.GroupBy, since time.Time, windowLabel string) oneshot.Table {
	t := oneshot.Table{
		WindowSince:       since,
		WindowLabel:       windowLabel,
		Reliability:       sum.Reliability,
		Tier:              "log", // this command only ever reads local session files
		UnknownModelCount: sum.UnknownModelCount,
		UnpricedTokens:    sum.UnpricedTokens,
	}
	tools := map[string]struct{}{}
	models := map[string]struct{}{}
	for _, r := range sum.Rows {
		var tool, model string
		switch groupBy {
		case cost.GroupByModelTool:
			model, tool = cost.SplitModelToolKey(r.Key)
		case cost.GroupByTool, cost.GroupByDay:
			// GroupByDay reuses the leftmost cell as the row label; the
			// report's column set is fixed.
			tool = r.Key
		case cost.GroupByModel:
			model = r.Key
		default:
			tool = r.Key
		}
		if tool != "" {
			tools[tool] = struct{}{}
		}
		if model != "" {
			models[model] = struct{}{}
		}
		t.Rows = append(t.Rows, oneshot.Row{
			Tool:          tool,
			Model:         model,
			Input:         r.Tokens.Input,
			Output:        r.Tokens.Output,
			CacheRead:     r.Tokens.CacheRead,
			CacheCreation: r.Tokens.CacheCreation + r.Tokens.CacheCreation1h,
			Turns:         r.TurnCount,
			USD:           r.CostUSD,
			Reliability:   r.Reliability,
			PricingSource: r.PricingSource,
		})
	}
	t.ToolCount = len(tools)
	t.ModelCount = len(models)
	// Totals come from the summary, not from the rows above: the engine
	// computes them over the WHOLE window before its row limit applies.
	t.TotalInput = sum.TotalTokens.Input
	t.TotalOutput = sum.TotalTokens.Output
	t.TotalCacheRead = sum.TotalTokens.CacheRead
	t.TotalCacheCreation = sum.TotalTokens.CacheCreation + sum.TotalTokens.CacheCreation1h
	t.TotalTurns = sum.TurnCount
	t.TotalUSD = sum.TotalCost
	return t
}

// applyScanState records the scan's partial/empty facts on the table
// BEFORE notes are derived (oneshot.Notes reads them from State).
func applyScanState(t *oneshot.Table, scan scanOneShotResult, home string, budget time.Duration) {
	if scan.budgetHit {
		t.Partial = &oneshot.PartialScan{
			Budget:      budget.String(),
			FilesWalked: scan.filesProcessed,
			FilesTotal:  scan.filesTotal,
		}
	}
	// "Empty" means no session files were ever read — never claimed when
	// the budget cut the look short (Partial says that instead), and
	// never claimed just because zero cost ROWS resulted (F10): a corpus
	// where every session file was read but produced no cost rows (all
	// files failed to parse, or --tool filtered everything out, or the
	// files simply carry no local token source) is a real, non-empty scan
	// — it renders the normal table (zero data rows, TOTAL all-zero) so
	// the scan_errors / no_local_token_source / etc. notes actually reach
	// the reader, instead of the generic "nothing found" empty-state line
	// silently swallowing them.
	if len(t.Rows) == 0 && !scan.budgetHit && scan.filesProcessed == 0 {
		t.Empty = &oneshot.EmptyCorpus{
			Home:         home,
			Looked:       scan.rootsChecked,
			AdapterCount: scan.adaptersConsidered,
		}
	}
}

// oneShotExtraNoteInput carries the facts behind the notes this command
// owns (as opposed to the capability-derived ones oneshot.Notes emits).
type oneShotExtraNoteInput struct {
	summary       cost.Summary
	scanErrors    int
	keptDB        string
	ignoredConfig string
}

// oneShotExtraNotes builds the footer lines that come from the command
// boundary rather than the capability registry: an ignored real config
// (and how to opt in), a kept scratch database, a row-limited table, and
// unparseable files. Each is emitted only when true.
func oneShotExtraNotes(in oneShotExtraNoteInput) []oneshot.Note {
	var notes []oneshot.Note
	if in.ignoredConfig != "" {
		notes = append(notes, oneshot.Note{
			Code: "config_ignored",
			Text: fmt.Sprintf("%s was NOT read — any [intelligence.pricing] overrides in it are ignored; rerun with --config %s to honor it",
				in.ignoredConfig, in.ignoredConfig),
		})
	}
	if n := len(in.summary.Rows); n > 0 && n >= costSummaryDefaultLimit {
		notes = append(notes, oneshot.Note{
			Code: "row_limit",
			Text: fmt.Sprintf("showing the %d highest-cost rows; the TOTAL line covers the whole window", n),
		})
	}
	if in.scanErrors > 0 {
		notes = append(notes, oneshot.Note{
			Code: "scan_errors",
			Text: fmt.Sprintf("%d session file(s) could not be parsed and are missing from these totals", in.scanErrors),
		})
	}
	if in.keptDB != "" {
		notes = append(notes, oneshot.Note{
			Code: "kept_db",
			Text: fmt.Sprintf("kept the scratch database at %s (delete it whenever)", in.keptDB),
		})
	}
	return notes
}

// costSummaryDefaultLimit mirrors cost.Options.Limit's zero-value default
// (internal/intelligence/cost/summary.go): the engine returns the 50
// highest-cost rows. Used only to decide whether the table was truncated
// and therefore needs the row_limit note.
const costSummaryDefaultLimit = 50

// oneShotDistinctLimit is the Limit passed to oneShotDistinctCounts'
// GroupByModelTool rollup — large enough that no realistic one-shot
// corpus's distinct tool×model pair count ever hits it, so the "cap"
// that exists for cost.Summary's *display* rows (costSummaryDefaultLimit)
// never leaks into the TOTAL line's distinct counts (F11).
const oneShotDistinctLimit = 1 << 20

// oneShotDistinctCounts returns the true distinct tool and model counts
// across the WHOLE window (never capped by the display row limit, and
// never conflated with a --group-by day/tool/model key that doesn't carry
// both dimensions), by running one extra GroupByModelTool rollup keyed on
// the same window/tool filter as the report's own summary. This is the
// fix for F11: the report's --group-by (day/tool/model/tool-model)
// governs only how ROWS are displayed; the TOTAL line's distinct counts
// are a property of the whole corpus and must not change shape with it.
func oneShotDistinctCounts(ctx context.Context, cfg config.Config, database *sql.DB, since time.Time, tool string, now func() time.Time) (toolCount, modelCount int, err error) {
	sum, err := acquireProcessCostEngine(ctx, cfg, database, slog.Default()).Summary(ctx, database, cost.Options{
		Since:   since,
		GroupBy: cost.GroupByModelTool,
		Source:  cost.SourceAuto,
		Tool:    tool,
		Limit:   oneShotDistinctLimit,
		Now:     now,
	})
	if err != nil {
		return 0, 0, fmt.Errorf("usage: distinct tool/model rollup: %w", err)
	}
	tools := map[string]struct{}{}
	models := map[string]struct{}{}
	for _, r := range sum.Rows {
		model, toolName := cost.SplitModelToolKey(r.Key)
		if toolName != "" {
			tools[toolName] = struct{}{}
		}
		if model != "" {
			models[model] = struct{}{}
		}
	}
	return len(tools), len(models), nil
}

// ---------------------------------------------------------------------------
// --json (plan §2.5): stable, additive-only, mirrors oneshot.Table
// ---------------------------------------------------------------------------

type usageJSONEnvelope struct {
	Schema      string          `json:"schema"`
	Window      usageJSONWindow `json:"window"`
	Reliability string          `json:"reliability"`
	Tier        string          `json:"tier"`
	PriceBasis  string          `json:"price_basis"`
	Rows        []usageJSONRow  `json:"rows"`
	Total       usageJSONTotal  `json:"total"`
	Notes       []usageJSONNote `json:"notes"`
}

type usageJSONWindow struct {
	Since   string `json:"since"`
	Label   string `json:"label"`
	Partial bool   `json:"partial"`
}

type usageJSONRow struct {
	Tool          string  `json:"tool"`
	Model         string  `json:"model"`
	Input         int64   `json:"input"`
	Output        int64   `json:"output"`
	CacheRead     int64   `json:"cache_read"`
	CacheCreation int64   `json:"cache_creation"`
	Turns         int     `json:"turns"`
	USD           float64 `json:"usd"`
	Reliability   string  `json:"reliability"`
	PricingSource string  `json:"pricing_source,omitempty"`
}

type usageJSONTotal struct {
	Tools         int     `json:"tools"`
	Models        int     `json:"models"`
	Input         int64   `json:"input"`
	Output        int64   `json:"output"`
	CacheRead     int64   `json:"cache_read"`
	CacheCreation int64   `json:"cache_creation"`
	Turns         int     `json:"turns"`
	USD           float64 `json:"usd"`
}

type usageJSONNote struct {
	Code  string   `json:"code"`
	Tools []string `json:"tools,omitempty"`
	Text  string   `json:"text"`
}

// writeUsageJSON emits the oneShotSchema envelope for t. Built from the
// same oneshot.Table the renderer consumes, so the two surfaces can never
// disagree about a number or a note.
func writeUsageJSON(w io.Writer, t oneshot.Table) error {
	env := usageJSONEnvelope{
		Schema: oneShotSchema,
		Window: usageJSONWindow{
			Label:   t.WindowLabel,
			Partial: t.Partial != nil,
		},
		Reliability: t.Reliability,
		Tier:        t.Tier,
		PriceBasis:  oneshot.PriceBasis,
		Rows:        make([]usageJSONRow, 0, len(t.Rows)),
		Total: usageJSONTotal{
			Tools:         t.ToolCount,
			Models:        t.ModelCount,
			Input:         t.TotalInput,
			Output:        t.TotalOutput,
			CacheRead:     t.TotalCacheRead,
			CacheCreation: t.TotalCacheCreation,
			Turns:         t.TotalTurns,
			USD:           t.TotalUSD,
		},
		Notes: make([]usageJSONNote, 0, len(t.Notes)),
	}
	if !t.WindowSince.IsZero() {
		env.Window.Since = t.WindowSince.UTC().Format(time.RFC3339)
	}
	if env.Tier == "" {
		env.Tier = "log"
	}
	for _, r := range t.Rows {
		env.Rows = append(env.Rows, usageJSONRow{
			Tool:          r.Tool,
			Model:         r.Model,
			Input:         r.Input,
			Output:        r.Output,
			CacheRead:     r.CacheRead,
			CacheCreation: r.CacheCreation,
			Turns:         r.Turns,
			USD:           r.USD,
			Reliability:   r.Reliability,
			PricingSource: r.PricingSource,
		})
	}
	for _, n := range t.Notes {
		env.Notes = append(env.Notes, usageJSONNote{Code: n.Code, Tools: n.Tools, Text: n.Text})
	}
	body, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("usage: marshal json: %w", err)
	}
	_, err = fmt.Fprintln(w, string(body))
	return err
}

// ---------------------------------------------------------------------------
// bare-root fallthrough (plan §1.1)
// ---------------------------------------------------------------------------

// oneShotFallthroughEligible reports whether bare `observer` should run
// the one-shot usage report instead of printing the welcome screen. It is
// a STATE branch, never an invocation-channel branch (CLAUDE.md #3): the
// report replaces the greeting only on a machine that has no SuperBased
// state to greet you about. Every probe is read-only, cheap, and entirely
// local filesystem — no socket of any kind is opened here (F2).
//
// All three must hold:
//  1. OBSERVER_ONESHOT is not "off";
//  2. ~/.observer/observer.db does not exist;
//  3. ~/.observer/config.toml does not exist.
//
// A prior revision also probed 127.0.0.1:8081/8820 for a listening
// dashboard/proxy — a real outbound connect attempt, which contradicted
// the "zero sockets" claim this command makes about a bare `npx
// @superbased/observer` invocation (F2, CRITICAL). It was removed, not
// replaced, because the two remaining filesystem checks already cover
// every case a live daemon implies:
//   - a default-config daemon cannot be running at all without
//     ~/.observer existing (it is where db.Open and config.Load put
//     everything), so condition 2 alone already rules that case out;
//   - a daemon running against a CUSTOM config (a non-default DB path or
//     a config.toml elsewhere) leaves no trace under ~/.observer for this
//     one-shot run to collide with — its state is untouched by a scratch
//     scan into a throwaway temp dir regardless of what is listening;
//   - OBSERVER_ONESHOT=off remains the explicit escape hatch for any
//     case an operator judges these two heuristics insufficient for.
func oneShotFallthroughEligible(deps usageDeps) bool {
	if strings.EqualFold(strings.TrimSpace(deps.getenv("OBSERVER_ONESHOT")), "off") {
		return false
	}
	home, err := deps.homeDir()
	if err != nil || home == "" {
		return false
	}
	dir := filepath.Join(home, ".observer")
	if oneShotFileExists(filepath.Join(dir, "observer.db")) {
		return false
	}
	if oneShotFileExists(filepath.Join(dir, "config.toml")) {
		return false
	}
	return true
}

// runBareRoot is the root command's RunE body: the one-shot report on a
// machine with no local state, the unchanged welcome screen otherwise.
func runBareRoot(cmd *cobra.Command, deps usageDeps) error {
	if !oneShotFallthroughEligible(deps) {
		return printWelcome(cmd)
	}
	fmt.Fprintf(cmd.ErrOrStderr(),
		"no local SuperBased state found — showing a one-shot usage report (`%s usage`); nothing is written outside a temp dir. `%s --help` for everything else, OBSERVER_ONESHOT=off to disable.\n",
		invocationName(), invocationName())
	return runUsage(cmd, defaultUsageOptions(), deps)
}
