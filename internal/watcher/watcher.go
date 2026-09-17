package watcher

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/cachetrack"
	"github.com/marmutapp/superbased-observer/internal/compression/indexing"
	"github.com/marmutapp/superbased-observer/internal/freshness"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Logger is the subset of slog.Logger used by the watcher. Satisfied by
// *slog.Logger.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// Watcher drives session-file ingestion for every registered adapter, both
// one-shot (Scan) and continuous (Watch).
type Watcher struct {
	store    *store.Store
	registry *adapter.Registry
	logger   Logger
	// nativePredicate maps an adapter name to its native-tool predicate
	// used for setting actions.is_native_tool.
	nativePredicate map[string]func(rawToolName string) bool
	// allow restricts which adapter names are active; empty means all.
	allow []string
	// debounce delays re-parsing of a file after a fsnotify event to coalesce
	// bursts of writes.
	debounce time.Duration
	// pollInterval, when > 0, drives the polling fallback that recovers
	// from fsnotify Write/Create events dropped on busy filesystems
	// (notably WSL2/NTFS). Zero disables polling — fsnotify is the only
	// trigger.
	pollInterval time.Duration
	// classifier, when non-nil, is passed to store.Ingest so file-typed
	// actions get content_hash + freshness computed.
	classifier *freshness.Classifier
	// indexer, when non-nil, stores tool output excerpts in FTS5.
	indexer *indexing.Indexer
	// fileLocks serializes concurrent processFile invocations per
	// source_file. fsnotify-debounced fires and poller-tick fires CAN
	// race on the same file (documented "race is safe via UNIQUE
	// constraints"), but the loser of that race wastes a full
	// BEGIN IMMEDIATE acquisition cycle and — when the holder is slow
	// on lossy filesystems (WSL2 /mnt/c, OneDrive-synced dirs) —
	// can trip SQLITE_BUSY. Per-file locking eliminates the intra-file
	// race; inter-file contention is still handled by SQLite's
	// busy_timeout backoff.
	fileLocks sync.Map // map[string]*sync.Mutex
	// warningDedup suppresses repeated adapter warnings with the same
	// (adapter, path, message) tuple within a TTL window. The
	// antigravity adapter, on Windows, emits the same OSCrypt /
	// unrecoverable warning every ~30 s poll for the lifetime of an
	// untouched .pb file — at ~96% of stderr volume it drowns real
	// diagnostics (V3 batch finding). With a 5-minute window the same
	// signal still surfaces, just not every poll. nil disables dedup
	// (every warning fires).
	warningDedup *warningDeduper
	// maxFileBytes skips parsing files larger than this (DoS guard). Zero
	// disables the cap. See Options.MaxFileBytes.
	maxFileBytes int64
	// skipModifiedBefore gates the historic scan's WalkDir callback.
	// See Options.SkipModifiedBefore.
	skipModifiedBefore time.Time
	// rootDetectInterval is the cadence of the standalone re-detect loop
	// Watch runs (runRootDetector). See Options.RootDetectInterval.
	rootDetectInterval time.Duration

	// Live fsnotify state, owned by Watch and mutated by RefreshRoots /
	// applyDetectedRoots under liveMu. fsw is non-nil only while Watch is
	// inside its event loop; RefreshRoots is a no-op hot-add when Watch
	// has not started yet (Scan still runs).
	liveMu    sync.Mutex
	fsw       *fsnotify.Watcher
	byRoot    map[string]adapter.Adapter
	refreshCh chan struct{} // buffered 1; nudges Watch to re-apply + Scan

	// rootCache memoizes each adapter's identity-deduped watch roots
	// against a fingerprint of the RAW WatchPaths slice they were
	// computed from. See watchRoots — the dedup does filesystem work
	// (Stat + EvalSymlinks + SameFile per root) and the cursor poller
	// re-derives the root→adapter map on EVERY grown file, so without
	// this the steady-state poll cost is O(adapters × roots) syscalls
	// per row. Guarded by its own mutex: watchRoots is called from
	// applyDetectedRoots (which already holds liveMu), so the lock
	// order is always liveMu → rootMu, never the reverse.
	rootMu    sync.Mutex
	rootCache map[string]rootCacheEntry
	// dedupRoots is the identity-fold seam watchRoots calls on a cache
	// miss. Set to adapter.DedupRootsByIdentity by New; a test may
	// substitute a counting wrapper to observe memoization. Per-Watcher
	// (not a package var) so substituting it can never race a parallel
	// test. nil falls back to the real fold.
	dedupRoots func([]string) []string
	// budgetCaptureMu/budgetCaptureSeen memoize the last strict budget pass
	// per (adapter, source file). An unchanged file costs one stat instead of
	// a parse; see internal/watcher/budgetcapture.go for the entry shape and
	// the invalidation rules.
	budgetCaptureMu   sync.Mutex
	budgetCaptureSeen map[string]budgetCaptureSeenEntry
}

// rootCacheEntry is one memoized (adapter → deduped roots) mapping,
// keyed in Watcher.rootCache by adapter name and validated against a
// fingerprint of the raw WatchPaths slice, so an adapter installed
// mid-daemon (whose WatchPaths starts returning a new root) invalidates
// itself on the next call rather than serving a stale root set.
type rootCacheEntry struct {
	fingerprint string
	deduped     []string
}

// Options configures New.
type Options struct {
	Logger          Logger
	NativePredicate map[string]func(string) bool
	Allow           []string
	Debounce        time.Duration
	// PollInterval, when > 0, runs a polling fallback alongside fsnotify
	// in Watch — every tick, every known parse_cursors row is stat()'d
	// and reprocessed if file_size > byte_offset; every 15th tick a full
	// Scan walks the watch roots to discover never-seen files. Recovers
	// from fsnotify event drops on WSL2/NTFS and other lossy
	// filesystems. Zero (or negative) disables polling entirely.
	PollInterval time.Duration
	// Classifier is optional; when set, file-typed actions gain freshness
	// classification and the file_state table is updated.
	Classifier *freshness.Classifier
	// Indexer is optional; when set, tool output excerpts go into FTS5
	// action_excerpts.
	Indexer *indexing.Indexer
	// AdapterWarningTTL is the dedup window for adapter warnings logged
	// from processFile. Identical (adapter, path, message) tuples are
	// suppressed until the TTL expires. Zero uses
	// defaultAdapterWarningTTL (5 min); a negative value disables dedup.
	// See V3-3 in docs/observer-platform-issues-v3.md.
	AdapterWarningTTL time.Duration
	// MaxFileBytes skips parsing any session file larger than this many
	// bytes — a DoS guard against a malformed or hostile multi-GB file in
	// a watch root driving the daemon into unbounded allocation. Zero (or
	// negative) disables the cap. Wired from [watcher].max_file_bytes.
	MaxFileBytes int64
	// SkipModifiedBefore, when non-zero, makes the historic scan (Scan /
	// Rescan) skip any session file whose mtime is strictly before this
	// instant — a file whose last write predates the window cannot
	// contain any in-window rows, so parsing it is pure waste. This is
	// honored ONLY in scan()'s WalkDir callback, using the fs.DirEntry
	// the walk already handed us (no extra os.Stat on the hit path) for
	// a regular file; a symlink entry costs one extra os.Stat to reach
	// the TARGET's mtime, since processFile follows safe symlinks and
	// parses the target, not the link. The continuous Watch()/fsnotify/
	// poller path is untouched — a live
	// write always bumps mtime to "now", so the filter would never fire
	// there anyway, and Watch's own initial Scan call still benefits.
	// The zero value (time.Time{}) changes nothing: every file is
	// processed exactly as before this field existed.
	SkipModifiedBefore time.Time
	// RootDetectInterval is the cadence of Watch's standalone
	// re-detection loop: every tick, adapter detection re-runs and any
	// watch root that appeared since the last pass is registered with
	// fsnotify AND walked once (see hotAddRoots). Zero uses
	// defaultRootDetectInterval (30s); a negative value disables the
	// loop entirely.
	//
	// Deliberately INDEPENDENT of PollInterval. Before this field the
	// only automatic re-detection lived inside the poller's every-15th-
	// tick branch, so `[observer.watch] poll_interval_seconds = 0`
	// silently disabled hot-add altogether — a tool installed after the
	// daemon started was never watched and never walked until a
	// dashboard RefreshRoots or a restart.
	RootDetectInterval time.Duration
}

// New returns a watcher. Reasonable zero defaults apply.
func New(s *store.Store, r *adapter.Registry, opts Options) *Watcher {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Debounce <= 0 {
		opts.Debounce = 300 * time.Millisecond
	}
	if opts.NativePredicate == nil {
		opts.NativePredicate = map[string]func(string) bool{}
	}
	pollInterval := opts.PollInterval
	if pollInterval < 0 {
		pollInterval = 0
	}
	warningTTL := opts.AdapterWarningTTL
	if warningTTL == 0 {
		warningTTL = defaultAdapterWarningTTL
	}
	rootDetect := opts.RootDetectInterval
	if rootDetect == 0 {
		rootDetect = defaultRootDetectInterval
	}
	// A negative TTL disables dedup. newWarningDeduper handles
	// non-positive values as "always allow", so a single deduper
	// instance covers both branches.
	return &Watcher{
		store:              s,
		registry:           r,
		logger:             opts.Logger,
		nativePredicate:    opts.NativePredicate,
		allow:              opts.Allow,
		debounce:           opts.Debounce,
		pollInterval:       pollInterval,
		classifier:         opts.Classifier,
		indexer:            opts.Indexer,
		warningDedup:       newWarningDeduper(warningTTL),
		maxFileBytes:       opts.MaxFileBytes,
		skipModifiedBefore: opts.SkipModifiedBefore,
		rootDetectInterval: rootDetect,
		refreshCh:          make(chan struct{}, 1),
		dedupRoots:         adapter.DedupRootsByIdentity,
	}
}

// RefreshRoots re-runs adapter detection, hot-adds any newly-existing
// watch roots into the live fsnotify set, and performs an immediate Scan.
//
// This is the seam behind the New Terminal install→launch capture gap:
// tools installed while the daemon is already running (Muse, Prime Agent,
// and any other adapter whose sessions directory appears only after first
// use) were invisible to Watch because detection + addRecursive ran once
// at start. Callers (dashboard launch/install) invoke this fail-open;
// repeated calls are cheap and idempotent.
//
// When Watch is not yet running, hot-add is skipped and only Scan runs
// (Detected roots that exist are still walked). A pending refresh signal
// is still queued so the next Watch loop iteration applies roots as soon
// as fsnotify is live.
func (w *Watcher) RefreshRoots(ctx context.Context) (ScanResult, error) {
	if added := w.hotAddRoots(ctx); added > 0 {
		w.logger.Info("watcher.RefreshRoots: hot-added watch roots", "count", added)
	}
	select {
	case w.refreshCh <- struct{}{}:
	default:
	}
	return w.Scan(ctx)
}

// rootBinding is one (adapter, watch root) pair the live fsnotify set
// just gained. applyDetectedRoots returns them so the caller can walk
// EXACTLY the roots that appeared, instead of re-walking every root of
// every detected adapter.
type rootBinding struct {
	adapter adapter.Adapter
	root    string
}

// applyDetectedRoots adds every currently-Detected adapter root that is
// not already in byRoot to the live fsnotify watcher. Returns the
// bindings that were newly added. No-op when Watch is not running
// (fsw == nil).
//
// Registration ONLY — it never walks. Callers that want the new root's
// pre-existing backlog captured go through hotAddRoots.
func (w *Watcher) applyDetectedRoots() []rootBinding {
	w.liveMu.Lock()
	defer w.liveMu.Unlock()
	if w.fsw == nil || w.byRoot == nil {
		return nil
	}
	var added []rootBinding
	for _, a := range w.registry.Detected(w.allow) {
		for _, root := range w.watchRoots(a) {
			if root == "" {
				continue
			}
			if _, ok := w.byRoot[root]; ok {
				continue
			}
			addRes := addRecursive(w.fsw, root)
			if addRes.RootErr != nil {
				w.logger.Warn("watcher.applyDetectedRoots: add path",
					"adapter", a.Name(), "root", root, "err", addRes.RootErr)
				continue
			}
			// One WARN per root per pass for partial failures: the root
			// IS registered and its watched subtree keeps delivering, so
			// this is a gap to report, not a reason to drop the root.
			if addRes.Failed > 0 {
				w.logger.Warn("watcher.applyDetectedRoots: some subdirectories could not be watched",
					"adapter", a.Name(), "root", root,
					"watched", addRes.Added, "failed", addRes.Failed, "err", addRes.FirstErr)
			}
			w.byRoot[root] = a
			added = append(added, rootBinding{adapter: a, root: root})
			// A root that does not exist is registered anyway —
			// addRecursive's WalkDir swallows the stat error, and
			// adapters return canonical roots regardless of install
			// state — but it is not news. Only an EXISTING root is
			// worth an operator's attention at Info; the rest are
			// bookkeeping and belong at Debug, where they stop
			// drowning the real hot-add events in the journal.
			if info, err := dirStat(root); err == nil && info.IsDir() {
				w.logger.Info("watcher: hot-added watch root",
					"adapter", a.Name(), "root", root)
			} else {
				w.logger.Debug("watcher: hot-added watch root (absent)",
					"adapter", a.Name(), "root", root)
			}
		}
	}
	return added
}

// hotAddRoots registers newly-detected watch roots AND immediately walks
// each one, so a tool installed (or first used, or only now discovered)
// after the daemon started captures the files that were already sitting
// under its store — the New Terminal install→launch premise.
//
// fsnotify only ever reports what happens AFTER a watch is registered,
// so registration alone leaves a newly-appeared root's backlog invisible
// until something else walks it. Before this seam existed that "something
// else" was whatever full Scan the call site happened to run next: at
// Watch startup an immediate one, from RefreshRoots an immediate one, and
// automatically only inside the poller's every-15th-tick branch — which
// is up to 15 poll intervals late and does not run at all when polling is
// disabled. The walk now belongs to the hot-add itself.
//
// The walk is scoped to the new roots (not a full Scan) and goes through
// the same processFile path as the startup walk, so it is idempotent via
// parse_cursors + the (source_file, source_event_id) UNIQUE index, and it
// inherits the identity dedup of watchRoots — the bindings ARE the
// deduped roots, and a root already in byRoot is never re-added.
func (w *Watcher) hotAddRoots(ctx context.Context) int {
	added := w.applyDetectedRoots()
	for _, b := range added {
		if ctx.Err() != nil {
			break
		}
		res := w.walkRoot(ctx, b.adapter, b.root, false)
		if res.FilesProcessed > 0 || res.Errors > 0 {
			w.logger.Info("watcher: walked hot-added root",
				"adapter", b.adapter.Name(), "root", b.root,
				"files", res.FilesProcessed, "errors", res.Errors)
		}
	}
	return len(added)
}

// defaultRootDetectInterval is the cadence of Watch's standalone
// re-detection loop when Options.RootDetectInterval is zero. It matches
// the effective cadence of the poller's old full-scan branch (15 ticks ×
// the 2s default poll interval) but costs one detection pass instead of
// a walk of every root.
const defaultRootDetectInterval = 30 * time.Second

// runRootDetector re-runs adapter detection on its own cadence, hot-adds
// any root that appeared, and walks it. Independent of the poller so a
// node with `poll_interval_seconds = 0` still picks up a tool installed
// mid-daemon. Exits with ctx.
func (w *Watcher) runRootDetector(ctx context.Context) {
	if w.rootDetectInterval <= 0 {
		return
	}
	ticker := time.NewTicker(w.rootDetectInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = w.hotAddRoots(ctx)
		}
	}
}

// snapshotByRoot returns a copy of the live root→adapter map for
// lock-free event dispatch.
func (w *Watcher) snapshotByRoot() map[string]adapter.Adapter {
	w.liveMu.Lock()
	defer w.liveMu.Unlock()
	out := make(map[string]adapter.Adapter, len(w.byRoot))
	for k, v := range w.byRoot {
		out[k] = v
	}
	return out
}

// SetCacheEngine wires the per-process cachetrack.Engine through to the
// watcher's store so Tier-2 (transcript) cache observations are recorded.
// The daemon passes the SAME instance the proxy uses (Proxy.CacheEngine)
// so both feed paths advance one shared CacheModel state; cross-tier
// dedup (CacheEventExistsForMessage) keeps a message from being observed
// twice. Until this is called the watcher's store has a nil engine and
// drops every transcript cache observation — which is why non-proxied
// sessions had no cache_entries. Idempotent; nil is a no-op disable.
func (w *Watcher) SetCacheEngine(e *cachetrack.Engine) { w.store.SetCacheEngine(e) }

// SetRootCommitResolver wires the lazy root-commit exec (Project Identity
// Resolver v2, docs/plans/project-identity-resolver-v2-plan-2026-09-06.md
// §3.1) through to the watcher's store. The daemon passes
// git.DefaultRootCommit.
//
// The WATCHER is the deliberate home for this, not the adapters and not
// the hook path. Adapters pass IdentityOptions.RootCommit = nil because
// they run per parsed line; `observer hook` builds a short-lived store per
// tool call, so an exec there would fork git on the agent's critical path.
// The watcher's store is long-lived and its Ingest already runs once per
// batch, where store.RootCommitNeedsCheck's 7-day fence collapses the exec
// to at most one `git rev-list` per project root per week. A session
// captured by the hook still gets its root commit filled in on the
// watcher's next scan of the same project, because the column is written
// backfill-on-touch against the shared projects row.
//
// Idempotent; nil is a no-op disable (the store's own default), which is
// what keeps internal/store's tests from ever shelling out to git.
func (w *Watcher) SetRootCommitResolver(fn store.RootCommitResolverFunc) {
	w.store.SetRootCommitResolver(fn)
}

// SurfaceSeams exposes the watcher store's two capture-surface seams —
// LoadSessionSurface (found=false on a missing session, never an error
// for that case) and SetSessionSurface — for the daemon-lifetime
// surface enricher (internal/surfaceenrich) that runs beside the
// watcher on the SAME store handle. It deliberately returns two funcs
// rather than the *store.Store, so the enricher cannot grow into a
// second writer of anything else (CLAUDE.md Module Boundaries #2/#4).
func (w *Watcher) SurfaceSeams() (
	load func(ctx context.Context, sessionID string) (models.SessionSurface, bool, error),
	stamp func(ctx context.Context, sf models.SessionSurface) (bool, error),
) {
	load = func(ctx context.Context, sessionID string) (models.SessionSurface, bool, error) {
		sf, err := w.store.LoadSessionSurface(ctx, sessionID)
		if errors.Is(err, sql.ErrNoRows) {
			return models.SessionSurface{}, false, nil
		}
		if err != nil {
			return models.SessionSurface{}, false, err
		}
		return sf, true, nil
	}
	return load, w.store.SetSessionSurface
}

// Scan walks every detected adapter's watch paths once, parsing every
// session file from its saved offset. Returns the total number of newly
// inserted actions + a count of errors (non-fatal).
func (w *Watcher) Scan(ctx context.Context) (ScanResult, error) {
	return w.scan(ctx, false)
}

// Rescan is Scan with the saved cursor ignored — every JSONL is parsed
// from offset 0 again. The (source_file, source_event_id) UNIQUE index
// makes ingest idempotent, so re-walking is safe; rows that already
// exist are no-ops, rows the watcher dropped silently get inserted.
//
// Surfaced via `observer scan --force` and the dashboard's "Run All"
// button. Recovery path for the well-known watcher-falls-behind
// failure mode: parse_cursors stuck at offset N while the JSONL has
// grown past N, and only some action types (typically user_prompts
// via a separate path) get ingested while assistant turns + tool
// calls go missing.
func (w *Watcher) Rescan(ctx context.Context) (ScanResult, error) {
	return w.scan(ctx, true)
}

// ScanFile processes one recognized transcript through the normal ingestion
// and cursor path. It supports bounded recovery without rescanning all history.
func (w *Watcher) ScanFile(ctx context.Context, path string, forceFromZero bool) (ScanResult, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return ScanResult{}, fmt.Errorf("watcher.ScanFile: %w", err)
	}
	for _, a := range w.registry.Detected(w.allow) {
		if !a.IsSessionFile(path) {
			continue
		}
		if err := w.processFile(ctx, a, path, forceFromZero); err != nil {
			return ScanResult{Errors: 1}, err
		}
		return ScanResult{FilesProcessed: 1}, nil
	}
	return ScanResult{}, fmt.Errorf("watcher.ScanFile: no enabled adapter recognizes %s", path)
}

func (w *Watcher) scan(ctx context.Context, forceFromZero bool) (ScanResult, error) {
	var res ScanResult
	detected := w.registry.Detected(w.allow)
	if len(detected) == 0 {
		w.logger.Info("watcher.Scan: no adapters detected — nothing to do")
		return res, nil
	}
	for _, a := range detected {
		for _, root := range w.watchRoots(a) {
			r := w.walkRoot(ctx, a, root, forceFromZero)
			res.FilesProcessed += r.FilesProcessed
			res.Errors += r.Errors
		}
	}
	return res, nil
}

// walkRoot walks ONE (adapter, root) pair and processes every session
// file under it. The single walk implementation shared by the full scan
// (scan, over every detected adapter's roots) and the scoped hot-add
// walk (hotAddRoots, over just the roots that appeared) — so a file
// picked up by either path takes the identical processFile route,
// cursor semantics included.
func (w *Watcher) walkRoot(ctx context.Context, a adapter.Adapter, root string, forceFromZero bool) ScanResult {
	var res ScanResult
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			// Missing roots are not fatal — skip.
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !a.IsSessionFile(path) {
			return nil
		}
		if !w.skipModifiedBefore.IsZero() {
			// A file whose last write predates the window
			// cannot contain any in-window rows — skip it
			// without ever opening it. Use the fs.DirEntry
			// info the walk already fetched (no extra
			// os.Stat on the hit path) — EXCEPT for a
			// symlink: WalkDir's DirEntry is built from
			// Lstat, so d.Info() reports the LINK's own
			// mtime, while processFile follows safe symlinks
			// and parses the TARGET. An old symlink pointing
			// at a freshly-updated session file must not be
			// skipped on the link's stale mtime, so for a
			// symlink entry we os.Stat(path) instead, which
			// follows the link to the target's mtime. If
			// either stat errors (e.g. a raced deletion or a
			// broken symlink), fall through and let
			// processFile's own os.Stat/open handle it —
			// fail-open, never fail-skip.
			info, infoErr := d.Info()
			if infoErr == nil && d.Type()&fs.ModeSymlink != 0 {
				info, infoErr = os.Stat(path)
			}
			if infoErr == nil && info.ModTime().Before(w.skipModifiedBefore) {
				return nil
			}
		}
		if err := w.processFile(ctx, a, path, forceFromZero); err != nil {
			res.Errors++
			w.logger.Warn("watcher.Scan: process failed",
				"adapter", a.Name(), "path", path, "err", err)
			return nil
		}
		res.FilesProcessed++
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, ctx.Err()) {
		w.logger.Warn("watcher.Scan: walk failed",
			"adapter", a.Name(), "root", root, "err", walkErr)
	}
	return res
}

// ScanResult is the summary of a scan invocation.
type ScanResult struct {
	FilesProcessed int
	Errors         int
}

// Watch starts an fsnotify watch on every detected adapter's roots (plus an
// initial Scan) and keeps ingesting until ctx is cancelled.
//
// Unlike the pre-RefreshRoots idle path, an empty Detected set at start no
// longer parks forever on ctx.Done: the event loop + poller always run so
// RefreshRoots (and the poller's periodic applyDetectedRoots) can hot-add
// roots when a tool is installed after the daemon starts. An empty
// enabled_adapters allow-list still yields nothing to watch — Detected
// stays empty — so ephemeral/benchmark configs that pin `[]` remain safe.
func (w *Watcher) Watch(ctx context.Context) error {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("watcher.Watch: fsnotify.NewWatcher: %w", err)
	}
	defer func() {
		w.liveMu.Lock()
		w.fsw = nil
		w.byRoot = nil
		w.liveMu.Unlock()
		_ = fsw.Close()
	}()

	w.liveMu.Lock()
	w.fsw = fsw
	w.byRoot = map[string]adapter.Adapter{}
	w.liveMu.Unlock()

	// Registration only: the initial full Scan directly below walks every
	// one of these roots anyway, so paying hotAddRoots' scoped walk here
	// would walk the whole tree twice at startup.
	if n := len(w.applyDetectedRoots()); n == 0 {
		w.logger.Info("watcher.Watch: no adapters detected yet — waiting for RefreshRoots / root re-detect")
	}

	// Initial scan, so existing files are caught up before watching.
	if _, err := w.Scan(ctx); err != nil {
		return err
	}

	// Drain any RefreshRoots signal that arrived before fsw was live so
	// we don't leave a stale nudge that would only re-Scan once.
	select {
	case <-w.refreshCh:
		_ = w.hotAddRoots(ctx)
		if _, err := w.Scan(ctx); err != nil {
			return err
		}
	default:
	}

	// Standalone root re-detection. Independent of the poller so a node
	// that disabled polling still hot-adds (and walks) a store that
	// appears after the daemon started.
	go w.runRootDetector(ctx)

	// Polling fallback. fsnotify is documented to drop events on busy or
	// virtualized filesystems (e.g. WSL2 reading from a Windows NTFS
	// mount, network FUSE mounts). When that happens for a Write, the
	// debounced fire never trips and the watcher silently sits behind a
	// growing JSONL until the user clicks Run All. The poller is the
	// safety net: every tick re-checks every known parse_cursors row,
	// and every 15th tick re-scans the watch roots to discover never-
	// seen files (Create-event drops are the same bug class) AND
	// applyDetectedRoots so a tool installed mid-daemon is eventually
	// fsnotify-wired even without a dashboard kick.
	//
	// processFile is idempotent (cursor + the (source_file,
	// source_event_id) UNIQUE index), so racing fsnotify and the poller
	// is safe.
	if w.pollInterval > 0 {
		go w.runPoller(ctx)
	}

	type debounceKey struct {
		path string
	}
	var (
		pending       = map[debounceKey]*time.Timer{}
		pendingSettle = map[debounceKey]*time.Timer{}
		pendingMu     sync.Mutex
	)
	fire := func(a adapter.Adapter, path string) {
		if err := w.processFile(ctx, a, path, false); err != nil {
			w.logger.Warn("watcher.Watch: process failed",
				"adapter", a.Name(), "path", path, "err", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-w.refreshCh:
			_ = w.hotAddRoots(ctx)
			if _, err := w.Scan(ctx); err != nil && ctx.Err() == nil {
				w.logger.Warn("watcher.Watch: refresh scan failed", "err", err)
			}
		case err, ok := <-fsw.Errors:
			if !ok {
				return nil
			}
			w.logger.Warn("watcher.Watch: fsnotify error", "err", err)
		case ev, ok := <-fsw.Events:
			if !ok {
				return nil
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}
			a := adapterForPath(w.snapshotByRoot(), ev.Name)
			if a == nil || !a.IsSessionFile(ev.Name) {
				// New directory created under a watched root? Try to watch it.
				if ev.Op&fsnotify.Create != 0 {
					_ = addIfDir(fsw, ev.Name)
				}
				continue
			}
			k := debounceKey{path: ev.Name}
			pendingMu.Lock()
			if t, ok := pending[k]; ok {
				t.Stop()
			}
			aLocal, pathLocal := a, ev.Name
			pending[k] = time.AfterFunc(w.debounce, func() {
				pendingMu.Lock()
				delete(pending, k)
				pendingMu.Unlock()
				fire(aLocal, pathLocal)
			})
			// Some tools create the session file early, then append the
			// interesting tail (token_count, task_complete, tool output)
			// a moment later. On Windows/NTFS those follow-up Write
			// events can go missing in practice, leaving the cursor stuck
			// at a partial file until the next full rescan. A second,
			// longer debounce gives each touched session file one more
			// parse pass after writes have settled, even if the OS never
			// delivers another event.
			const settleDelay = 2 * time.Second
			if t, ok := pendingSettle[k]; ok {
				t.Stop()
			}
			pendingSettle[k] = time.AfterFunc(settleDelay, func() {
				pendingMu.Lock()
				delete(pendingSettle, k)
				pendingMu.Unlock()
				fire(aLocal, pathLocal)
			})
			pendingMu.Unlock()
		}
	}
}

// processFile reads the saved cursor, parses the file, ingests the events,
// and persists the new cursor — all inside a single logical unit. When
// forceFromZero is true the cursor is ignored (Rescan path) and parsing
// starts at offset 0; the post-parse cursor update still uses MAX(),
// so a re-scan can never regress an advanced cursor.
// symlinkLeafEscapes reports whether path is a symlink whose resolved target
// lies outside every one of roots. Each root is resolved too, so a legitimately
// symlinked watch root still matches its own files. Regular files and symlinks
// that resolve back inside a watch root return false (the fast path); a
// dangling or looping symlink returns true (refuse). The returned string is the
// resolved target, for the skip log.
func symlinkLeafEscapes(path string, roots []string) (bool, string) {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return false, "" // regular file (or vanished) — unchanged behaviour.
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return true, "" // dangling / looping symlink — refuse.
	}
	for _, r := range roots {
		if r == "" {
			continue
		}
		resolvedRoot := r
		if rr, err := filepath.EvalSymlinks(r); err == nil {
			resolvedRoot = rr
		}
		if adapter.HasPathPrefix(real, resolvedRoot) {
			return false, real // target stays inside a watch root — allow.
		}
	}
	return true, real
}

func (w *Watcher) processFile(ctx context.Context, a adapter.Adapter, path string, forceFromZero bool) error {
	_, err := w.processFileMode(ctx, a, path, forceFromZero, false)
	return err
}

// processFileStrict is the reconciliation variant of processFile. It keeps
// the normal watcher fail-open behavior out of the strict status path: skips,
// warnings, retries, parser errors, and panics remain visible to the caller.
func (w *Watcher) processFileStrict(ctx context.Context, a adapter.Adapter, path string) (budgetCaptureFileOutcome, error) {
	before, snapshotErr := strictBudgetFileSnapshot(a, path)
	if snapshotErr != nil {
		return budgetCaptureFileOutcome{
			incomplete:       true,
			incompleteDetail: snapshotErr.Error(),
		}, nil
	}
	// Parse only the tail since the ordinary cursor. Re-reading every source
	// from byte zero on every two-second control cycle cannot finish inside the
	// pass deadline on a real corpus, which made the pass report scan_canceled
	// forever (accounting-readiness correction, 2026-09-14). The events were
	// always ingested idempotently; only the starting offset changes.
	out, err := w.processFileMode(ctx, a, path, false, true)
	out.beforeSnapshot = &before
	after, afterErr := strictBudgetFileSnapshot(a, path)
	if afterErr != nil {
		out.incomplete = true
		out.incompleteDetail = afterErr.Error()
	} else if detail := strictBudgetFileChange(before, after); detail != "" {
		out.incomplete = true
		out.incompleteDetail = detail
	}
	return out, err
}

func (w *Watcher) processFileMode(ctx context.Context, a adapter.Adapter, path string, forceFromZero, strict bool) (out budgetCaptureFileOutcome, err error) {
	if w.skipProcessFile(ctx, a, path, forceFromZero, strict, &out) {
		return out, nil
	}

	// Recover from a panic in adapter parsing. Normal watcher calls preserve
	// the historical fail-open behavior; strict callers receive an outcome.
	defer func() {
		if recovered := recover(); recovered != nil {
			out.parserPanic = true
			if !strict {
				w.logger.Warn("watcher.processFile: recovered from adapter panic",
					"path", path, "adapter", a.Name(), "panic", recovered)
			}
			err = nil
		}
	}()

	mu, lockErr := w.lockProcessFile(ctx, path, strict)
	if lockErr != nil {
		return out, lockErr
	}
	defer mu.Unlock()
	if strict && !strictProcessFileRegular(path, &out) {
		return out, nil
	}

	var off int64
	if !forceFromZero {
		var getErr error
		off, getErr = w.store.GetCursor(ctx, path)
		if getErr != nil {
			if strict {
				out.storeError = getErr
				return out, nil
			}
			return out, getErr
		}
	}
	if strict {
		// Resume from the highest position this daemon has already reconciled
		// for this exact file. The ordinary cursor is the floor (everything
		// before it is ingested, actions included); the strict memo carries the
		// tail this pass already consumed. The ordinary cursor is deliberately
		// NEVER advanced from here: strict ingest is usage-only, so moving it
		// would silently skip action/content capture for those bytes.
		if memo, ok := w.budgetCaptureOffset(a, path); ok && memo > off {
			off = memo
		}
	}
	out.startOffset = off
	res, parseErr := a.ParseSessionFile(ctx, path, off)
	if parseErr != nil {
		if strict {
			out.parseError = parseErr
			return out, nil
		}
		return out, parseErr
	}
	out.warnings = append([]string(nil), res.Warnings...)
	out.retrySuggested = res.RetrySuggested
	if strict && len(res.Warnings) == 0 && !res.RetrySuggested {
		if complete, detail := strictFileCursorComplete(a, path, res.NewOffset); !complete {
			out.incomplete = true
			out.incompleteDetail = detail
		}
	}
	// Strict reconciliation releases the per-file lock after parsing and lets
	// the caller ingest complete results in batches. Its final file/directory
	// snapshots still reject any source mutation during that interval, and the
	// cursor is advanced by flushBudgetCaptureBatch only after the batch has
	// been ingested - never before, so a dropped batch cannot skip usage.
	if strict {
		out.strictResult = &res
		return out, nil
	}
	w.logProcessWarnings(a, path, res.Warnings)
	if ingestErr := w.ingestProcessResult(ctx, a, res); ingestErr != nil {
		return out, ingestErr
	}
	out.parsed = true

	// Strict catchup deliberately leaves the ordinary cursor untouched. The
	// full source was parsed and its events were ingested idempotently, but a
	// later ordinary pass owns cursor advancement. This also ensures a strict
	// pass can never advance a cursor past a warning or retry hint.
	// Persist the cursor when:
	//   - the adapter advanced past the prior offset (normal progress), OR
	//   - the adapter explicitly asked to be re-polled (RetrySuggested)
	//     — without writing a cursor row, fresh files with no prior
	//     entry would never be picked up by pollCursors, so the
	//     retry hint would be silently dropped.
	// MAX(off, NewOffset) guards against accidental cursor regression
	// when RetrySuggested is set with NewOffset < off (e.g. an adapter
	// returning fromOffset on a transient miss).
	if setErr := w.persistProcessCursor(ctx, path, off, res); setErr != nil {
		return out, setErr
	}
	return out, nil
}

// skipProcessFile applies the pre-parse safety gates shared by ordinary and
// strict processing. It returns true when the caller must stop before opening
// the source.
func (w *Watcher) skipProcessFile(ctx context.Context, a adapter.Adapter, path string, forceFromZero, strict bool, out *budgetCaptureFileOutcome) bool {
	// Refuse a symlink whose target escapes the watch root before opening it.
	// fsnotify + WalkDir only gate on the path PREFIX (HasPathPrefix does not
	// resolve symlinks, by design — a watch root may itself be a symlink), so a
	// symlink planted under a watched dir (~/.claude/projects/x.jsonl ->
	// /etc/passwd) would otherwise be opened and its contents excerpted into
	// the DB. Regular files and in-tree symlinks take the fast path unchanged.
	if escapes, real := symlinkLeafEscapes(path, a.WatchPaths()); escapes {
		out.unsafeSymlink = true
		if !strict {
			w.logger.Warn("watcher.processFile: skipping symlink whose target escapes the watch root",
				"path", path, "resolved", real)
		}
		return true
	}

	// DoS guard: skip a file larger than the configured cap before parsing.
	// A malformed or hostile multi-GB session file in a watch root would
	// otherwise drive the adapter's whole-file read into unbounded allocation.
	//
	// The guard is capability-branched on the file's declared cursor
	// semantics (CursorKind.SizeGateMeaningful), NOT applied uniformly: a
	// watermark SQLite store is queried incrementally through the sql
	// driver — its size never enters the heap in one piece — and gating it
	// turns a normally-growing store into permanent silent capture loss
	// the day it crosses the cap (the 2026-08-27 Windows opencode.db
	// finding). Adapters that don't implement CursorSemantics keep the
	// gate for every file, which is the pre-existing behaviour.
	//
	// For the files that DO stay gated, WHAT is compared against the cap
	// is decided by a SECOND capability the adapter declares:
	// FileCursorSemantics.DeltaGateMeaningful(). An adapter that seeks to
	// the persisted offset and streams forward allocates on the order of
	// the UNREAD TAIL, so the tail is what the guard should bound; gating
	// its total size froze six Codex transcripts on the 2026-09-16 audit
	// box at ~52 MB while the files grew to 85 MB.
	//
	// A byte-offset cursor does NOT imply that, which is why it is a
	// separate flag and not a property of CursorKind: several adapters
	// persist `NewOffset = fi.Size()` while os.ReadFile-ing the whole
	// file on every tick, and for those the TOTAL size is the allocation.
	// The zero value keeps the pre-existing total-size behaviour.
	if w.maxFileBytes <= 0 {
		return false
	}
	fi, statErr := os.Stat(path)
	if statErr != nil || fi.Size() <= w.maxFileBytes {
		return false
	}
	sem := fileCursorSemantics(a, path)
	if !sem.Kind.SizeGateMeaningful() {
		if !strict && w.warningDedup.Allow(a.Name()+"|"+path+"|<oversize-watermark-exempt>") {
			w.logger.Info("watcher.processFile: oversize watermark store exempt from size gate",
				"path", path, "size", fi.Size(), "max", w.maxFileBytes)
		}
		return false
	}
	// A cursor read failure (or a forced from-zero pass) leaves off at 0,
	// so the delta is the whole file and the gate stays closed — the
	// conservative direction for a DoS guard. The cursor is not even read
	// for a whole-file reader: its value cannot change that answer.
	var off int64
	streams := sem.DeltaGateMeaningful()
	if streams && !forceFromZero {
		off, _ = w.store.GetCursor(ctx, path)
	}
	if !OversizeSkipped(fi.Size(), off, w.maxFileBytes, streams) {
		if !strict && w.warningDedup.Allow(a.Name()+"|"+path+"|<oversize-tail-streaming>") {
			w.logger.Info("watcher.processFile: oversize file still streaming from its cursor",
				"path", path, "size", fi.Size(), "cursor", off,
				"unread", OversizeUnreadDelta(fi.Size(), off), "max", w.maxFileBytes)
		}
		return false
	}
	out.oversize = true
	// Deduped per (adapter, path) on the warning TTL: an append-only log
	// that stays past the cap emitted this WARN on every poll tick
	// before (1,146 lines across 6 paths in one audit log sample).
	if !strict && w.warningDedup.Allow(a.Name()+"|"+path+"|<oversize>") {
		w.logger.Warn("watcher.processFile: skipping oversize file",
			"path", path, "size", fi.Size(), "cursor", off,
			"streams_from_cursor", streams, "max", w.maxFileBytes)
	}
	return true
}

// OversizeUnreadDelta returns the byte count a SEEK-AND-STREAM parse of a
// file of size bytes would have to read when its persisted cursor sits
// at off. A missing (<= 0) or impossible (> size, i.e. the file was
// truncated or rotated) cursor means the next parse re-reads the whole
// file, so the delta is the full size.
//
// It is meaningful ONLY for a file whose adapter declared
// StreamsFromCursor; for a whole-file reader one parse allocates the
// file's total size no matter where the cursor sits.
func OversizeUnreadDelta(size, off int64) int64 {
	if off <= 0 || off > size {
		return size
	}
	return size - off
}

// OversizeSkipped reports whether the watcher's MaxFileBytes DoS guard
// skips a gated file of size bytes whose cursor is at off.
//
// streams is the adapter's FileCursorSemantics.DeltaGateMeaningful()
// answer. When false — the default for every adapter that has not
// declared otherwise — the comparison is against the file's TOTAL size,
// which is what a whole-file os.ReadFile actually allocates.
//
// It is the ONE owner of that predicate: the watcher's pre-parse gate
// and `observer doctor`'s oversize check both call it, so the operator
// never reads a different rule than the daemon applies. A non-positive
// maxBytes disables the guard.
func OversizeSkipped(size, off, maxBytes int64, streams bool) bool {
	if maxBytes <= 0 {
		return false
	}
	if !streams {
		return size > maxBytes
	}
	return OversizeUnreadDelta(size, off) > maxBytes
}

// lockProcessFile serializes processing of one source path. Strict callers
// use the context-aware lock so a canceled reconciliation can stop waiting;
// ordinary watcher processing preserves its blocking acquisition.
func (w *Watcher) lockProcessFile(ctx context.Context, path string, strict bool) (*sync.Mutex, error) {
	muRaw, _ := w.fileLocks.LoadOrStore(path, &sync.Mutex{})
	mu := muRaw.(*sync.Mutex)
	if strict {
		if err := lockWatcherFile(ctx, mu); err != nil {
			return nil, err
		}
	} else {
		mu.Lock()
	}
	return mu, nil
}

// strictProcessFileRegular checks the source after the strict lock is held so
// a reconciliation never parses a vanished or non-regular path.
func strictProcessFileRegular(path string, out *budgetCaptureFileOutcome) bool {
	info, statErr := os.Stat(path)
	if statErr != nil {
		out.incomplete = true
		out.incompleteDetail = fmt.Sprintf("stat source %s before parse: %v", path, statErr)
		return false
	}
	if !info.Mode().IsRegular() {
		out.incomplete = true
		out.incompleteDetail = fmt.Sprintf("source %s is not a regular file", path)
		return false
	}
	return true
}

// logProcessWarnings emits ordinary adapter warnings with the watcher's
// existing deduplication policy. Strict reconciliation returns warnings to its
// caller instead of logging them and therefore never calls this helper.
func (w *Watcher) logProcessWarnings(a adapter.Adapter, path string, warnings []string) {
	for _, msg := range warnings {
		// Dedup identical (adapter, path, message) within the TTL — otherwise
		// antigravity's OSCrypt-retrieval warnings (and any other adapter that
		// emits the same warning every poll) flood stderr and drown diagnostics.
		// M4.5 collapses antigravity decrypt failures across paths because the
		// initial scan can produce hundreds of identical lines.
		key := a.Name() + "|" + path + "|" + msg
		if isAntigravityDecryptFailure(a.Name(), msg) {
			key = a.Name() + "|<decrypt-failure-batch>|" + extractDecryptFailureFamily(msg)
		}
		if w.warningDedup.Allow(key) {
			w.logger.Warn("adapter warning", "adapter", a.Name(), "path", path, "msg", msg)
		}
	}
}

// ingestProcessResult sends a parsed result through the ordinary store path.
func (w *Watcher) ingestProcessResult(ctx context.Context, a adapter.Adapter, res adapter.ParseResult) error {
	native := w.nativePredicate[a.Name()]
	if native == nil {
		native = func(string) bool { return false }
	}
	_, err := w.store.Ingest(ctx, res.ToolEvents, res.TokenEvents, store.IngestOptions{
		IsNativeTool:        native,
		Classifier:          w.classifier,
		RecordFailures:      true,
		Indexer:             w.indexer,
		CacheObservations:   res.CacheObservations,
		SessionProcessSeeds: res.SessionProcessSeeds,
		SessionLineages:     res.SessionLineages,
		SessionSurfaces:     res.SessionSurfaces,
		OutcomeUpdates:      res.OutcomeUpdates,
	})
	return err
}

// persistProcessCursor advances the ordinary watcher cursor without allowing
// a retry response to regress an already stored offset.
func (w *Watcher) persistProcessCursor(ctx context.Context, path string, off int64, res adapter.ParseResult) error {
	if res.NewOffset <= off && !res.RetrySuggested {
		return nil
	}
	target := res.NewOffset
	if off > target {
		target = off
	}
	return w.store.SetCursor(ctx, path, target)
}

// strictFileCursorComplete checks byte-offset files for a full EOF catchup.
// Watermark stores explicitly opt out because their cursor is not a byte
// count; their parser's monotonic watermark and sidecar/WAL handling remain
// the freshness authority. This avoids using a SQLite main-file mtime as a
// proxy for source health.
func strictFileCursorComplete(a adapter.Adapter, path string, offset int64) (bool, string) {
	if semantics, ok := a.(adapter.CursorSemantics); ok && !semantics.CursorSemanticsFor(path).Kind.LagMeaningful() {
		return true, ""
	}
	info, err := os.Stat(path)
	if err != nil {
		return false, fmt.Sprintf("stat source %s after parse: %v", path, err)
	}
	if offset < info.Size() {
		return false, fmt.Sprintf("source %s remained at offset %d of %d bytes", path, offset, info.Size())
	}
	return true, ""
}

// lockWatcherFile waits for one source-file lock without making a strict
// reconciliation immune to context cancellation. The normal watcher keeps
// its historical blocking mutex acquisition; only the bounded catchup path
// needs this context-aware variant.
func lockWatcherFile(ctx context.Context, mu *sync.Mutex) error {
	if ctx == nil {
		mu.Lock()
		return nil
	}
	for {
		if mu.TryLock() {
			return nil
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// pollFullScanEvery is how many poll ticks pass between full-tree scans.
// At the default 2s tick that's one root walk every 30s — frequent
// enough to catch fsnotify Create drops within a minute, infrequent
// enough to keep the cost on deep adapter trees (codex
// sessions/YYYY/MM/DD/) negligible.
const pollFullScanEvery = 15

// runPoller drives the polling fallback inside Watch. Owns its own
// ticker so it never stalls the fsnotify select loop. Exits with ctx.
func (w *Watcher) runPoller(ctx context.Context) {
	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()
	tickCount := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tickCount++
			if tickCount%pollFullScanEvery == 0 {
				// Hot-add any roots that appeared since Watch started
				// (dashboard install, CLI install of a new tool, …)
				// before walking — otherwise Scan finds files but
				// live fsnotify still misses Create/Write on the new tree.
				// Registration only: the full Scan below covers the new
				// tree, and runRootDetector owns the scoped hot-add walk.
				_ = w.applyDetectedRoots()
				if _, err := w.Scan(ctx); err != nil && ctx.Err() == nil {
					w.logger.Warn("watcher.poll: full scan failed", "err", err)
				}
				continue
			}
			if err := w.pollCursors(ctx); err != nil && ctx.Err() == nil {
				w.logger.Warn("watcher.poll: cursor pass failed", "err", err)
			}
		}
	}
}

// pollCursors stats every known session file and re-runs processFile when
// the file has grown past the saved cursor. Cheap: one query +
// N stats. Logs at Info level only when a poll actually advanced a
// cursor, so steady-state polling produces no noise.
func (w *Watcher) pollCursors(ctx context.Context) error {
	cursors, err := w.store.ListCursors(ctx)
	if err != nil {
		return err
	}
	for _, c := range cursors {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		fi, statErr := osStat(c.SourceFile)
		if statErr != nil {
			// File gone or unreadable. Not a poll concern — orphan
			// surfacing lives in the dashboard's health endpoint.
			continue
		}
		if fi.Size() <= c.ByteOffset {
			continue
		}
		a := w.adapterFor(c.SourceFile)
		if a == nil {
			// No current adapter owns this path (orphan
			// parse_cursors row from a tightened IsSessionFile,
			// or a stale row from a removed adapter). Same
			// exclusion rule the health endpoint uses.
			continue
		}
		// Defensive: root-based dispatch picked an adapter, but the
		// adapter's IsSessionFile must also accept the file (this
		// catches stray files placed inside a watch root that
		// shouldn't be ingested — e.g. README.md inside
		// ~/.codex/sessions). Skip + log so the operator sees the
		// mismatch instead of misrouting silently.
		if !a.IsSessionFile(c.SourceFile) {
			w.logger.Warn("watcher.poll: root-matched adapter rejected file shape",
				"adapter", a.Name(), "path", c.SourceFile)
			continue
		}
		behind := fi.Size() - c.ByteOffset
		if err := w.processFile(ctx, a, c.SourceFile, false); err != nil {
			w.logger.Warn("watcher.poll: process failed",
				"adapter", a.Name(), "path", c.SourceFile, "err", err)
			continue
		}
		w.logger.Info("watcher.poll: caught up dropped writes",
			"adapter", a.Name(), "path", c.SourceFile, "behind_bytes", behind)
	}
	return nil
}

// adapterFor returns the adapter whose WatchPaths contain path, or
// nil if none does. Used by the poller to dispatch a per-file
// reprocess without re-walking the watch roots.
//
// Pre-v1.4.51 this iterated registry.Detected(allow) and returned the
// first adapter whose IsSessionFile claimed path — pure shape-based
// dispatch. Because the registry sorts adapters by Name() and
// claude-code's IsSessionFile was a bare `.jsonl` extension match,
// any JSONL file (including Codex rollout-*.jsonl) ended up
// dispatched to claude-code first, silently misrouting + stranding
// token rows whenever fsnotify dropped a write event on WSL2/NTFS.
//
// Post-fix: dispatch uses longest-watched-root prefix — same rule
// the fsnotify event-handler path has always used (adapterForPath).
// The registry is still queried per call so dynamically-added
// adapters appear without restarting Watch.
// fileCursorSemantics resolves one adapter's declaration about one file,
// which is what the MaxFileBytes DoS guard branches on: whether the
// guard applies at all (CursorKind.SizeGateMeaningful) and, when it
// does, whether it bounds the unread tail or the whole file
// (FileCursorSemantics.DeltaGateMeaningful). Never the tool name.
//
// An adapter that does not implement CursorSemantics gets the zero
// value: gated, on total size — exactly the pre-interface behaviour.
func fileCursorSemantics(a adapter.Adapter, path string) adapter.FileCursorSemantics {
	if cs, ok := a.(adapter.CursorSemantics); ok {
		return cs.CursorSemanticsFor(path)
	}
	return adapter.FileCursorSemantics{}
}

func (w *Watcher) adapterFor(path string) adapter.Adapter {
	byRoot := map[string]adapter.Adapter{}
	for _, a := range w.registry.Detected(w.allow) {
		for _, root := range w.watchRoots(a) {
			byRoot[root] = a
		}
	}
	return adapterForPath(byRoot, path)
}

// watchRoots is the ONE way the watcher reads an adapter's roots for
// registration / scanning / dispatch mapping: WatchPaths collapsed by
// directory identity.
//
// Adapters return canonical CANDIDATE roots — several spellings of the
// same tree are legitimate (a Windows MSIX install exposes the Claude
// Desktop sessions dir as both `%APPDATA%\Claude\…` and
// `…\Packages\Claude_*\LocalCache\Roaming\Claude\…`, the latter being
// the only spelling a WSL daemon can traverse over DrvFs). Registering
// both walks ONE tree twice and ingests every session file under two
// distinct source_file values — an exact 2x action-row inflation
// (audit finding IDE-01). adapter.DedupRootsByIdentity folds them
// (string spelling → EvalSymlinks → os.SameFile, first occurrence
// wins) while retaining roots that do not exist, so Invariant #48
// still holds and the walk below still skips them.
//
// Deliberately NOT applied to processFile's symlinkLeafEscapes check:
// that one wants every spelling an adapter claims, so a file under a
// symlinked root spelling is still recognised as in-tree.
//
// MEMOIZED. The fold above is filesystem work — os.Stat, EvalSymlinks
// and an os.SameFile sweep for every root — while adapterFor rebuilds
// the whole root→adapter map on EVERY grown cursor row the poller sees
// (pollCursors), i.e. potentially per file per tick. The deduped result
// is therefore cached per adapter, keyed on a fingerprint of the RAW
// WatchPaths slice: the same adapter returning the same roots costs one
// map lookup, while an adapter whose roots CHANGE (a tool installed
// mid-daemon, whose sessions dir only now exists) recomputes on the
// next call. WatchPaths itself is still called every time — it is the
// adapters' own cheap accessor and the only honest way to notice a
// changed root set.
//
// The returned slice is shared with the cache and MUST be treated as
// read-only by callers (every call site ranges over it).
func (w *Watcher) watchRoots(a adapter.Adapter) []string {
	raw := a.WatchPaths()
	// NUL is not a legal path byte on any supported platform, so
	// joining on it cannot alias two distinct slices.
	fingerprint := strings.Join(raw, "\x00")
	name := a.Name()

	w.rootMu.Lock()
	defer w.rootMu.Unlock()
	if e, ok := w.rootCache[name]; ok && e.fingerprint == fingerprint {
		return e.deduped
	}
	fold := w.dedupRoots
	if fold == nil {
		fold = adapter.DedupRootsByIdentity
	}
	deduped := fold(raw)
	if w.rootCache == nil {
		w.rootCache = make(map[string]rootCacheEntry, 8)
	}
	w.rootCache[name] = rootCacheEntry{fingerprint: fingerprint, deduped: deduped}
	return deduped
}

// adapterForPath returns the adapter whose watched root is a prefix of path,
// or nil if none match.
func adapterForPath(byRoot map[string]adapter.Adapter, path string) adapter.Adapter {
	// Prefer the longest matching root.
	var (
		bestRoot string
		best     adapter.Adapter
	)
	for root, a := range byRoot {
		if hasPathPrefix(path, root) && len(root) > len(bestRoot) {
			bestRoot = root
			best = a
		}
	}
	return best
}

// hasPathPrefix delegates to adapter.HasPathPrefix — single source of
// truth for path-prefix semantics shared by the watcher and every
// adapter's IsSessionFile.
func hasPathPrefix(p, prefix string) bool {
	return adapter.HasPathPrefix(p, prefix)
}

// watchAdder is the one fsnotify.Watcher method addRecursive needs.
// Narrowing it to an interface keeps the walk testable with an
// injected failing Add — *fsnotify.Watcher satisfies it unchanged.
type watchAdder interface {
	Add(name string) error
}

// addRecursiveResult summarizes one addRecursive pass over a root.
// Failed/FirstErr describe SUBDIRECTORY watches the OS refused;
// RootErr is the separate, more serious case of the root itself being
// unwatchable.
type addRecursiveResult struct {
	Added    int
	Failed   int
	FirstErr error
	RootErr  error
}

// addRecursive adds root and every subdirectory to the fsnotify watcher.
// A root that is itself a FILE (aider's per-repo transcript paths) is
// watched directly. Non-existent paths add nothing and report no error
// — callers check detection separately.
//
// A per-directory Add failure is COUNTED AND SKIPPED, never propagated:
// returning it from the WalkDir callback aborted the whole root's walk,
// so one inotify watch-limit (ENOSPC) or EACCES on a single nested
// directory left every sibling and descendant unwatched — with the
// watches already added leaked into the fsnotify watcher — and dropped
// the root until the next poller retry. Losing one subdirectory is a
// gap; losing the root's whole subtree is silent capture loss.
func addRecursive(fsw watchAdder, root string) addRecursiveResult {
	var res addRecursiveResult
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		// Only the root itself when it is a file; non-root files are
		// covered by their parent directory's watch as usual.
		if !d.IsDir() && path != root {
			return nil
		}
		if addErr := fsw.Add(path); addErr != nil {
			if path == root {
				res.RootErr = addErr
			} else {
				res.Failed++
				if res.FirstErr == nil {
					res.FirstErr = addErr
				}
			}
			return nil
		}
		res.Added++
		return nil
	})
	if res.RootErr == nil && walkErr != nil {
		res.RootErr = walkErr
	}
	return res
}

func addIfDir(fsw *fsnotify.Watcher, path string) error {
	fi, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	info, err := dirStat(fi)
	if err != nil || !info.IsDir() {
		return err
	}
	return fsw.Add(fi)
}

// dirStat is a wrapper over os.Stat used only so that the call site reads as
// a directory check — kept here to avoid importing os in the main body.
func dirStat(path string) (fs.FileInfo, error) {
	return osStat(path)
}
