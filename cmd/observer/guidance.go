package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guidance"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// -----------------------------------------------------------------------------
// Agent-guidance inventory: the daemon-lifetime scan loop and the
// `observer guidance` CLI.
//
// The loop is the ONE writer of the guidance_* tables from the daemon; the CLI
// runs the same pass on demand. Both go through guidanceScanPass, which is
// pure orchestration over injected seams (roots / exists / scan / persist /
// now) so it is exercised with fakes rather than a live DB and a live
// filesystem (CLAUDE.md module-boundary rule #1 + #2).
// -----------------------------------------------------------------------------

// guidanceSeams is the set of dependencies guidanceScanPass runs on. Each is a
// plain func: the pass never sees a *store.Store, a *sql.DB or the os package,
// which is what makes it testable without either.
type guidanceSeams struct {
	// Roots lists the project roots to consider. Production: the store's
	// own projects table, most recently active first and capped (see
	// [config.GuidanceConfig.MaxRootsPerPass]).
	Roots func(ctx context.Context) ([]string, error)
	// NeverScannedRoots lists the roots that carry NO guidance row at all
	// and are not in `exclude` — the candidate set for the first-scan poll,
	// and nothing else. It is a SEPARATE seam from Roots on purpose: the
	// poll must never be able to widen the root set the periodic pass
	// already bounds. Nil disables the poll.
	//
	// `exclude` is the poll's per-daemon-lifetime attempted set, and it is
	// passed DOWN rather than applied to the result, because filtering
	// after the store's LIMIT starves every root behind a full page of
	// already-attempted ones. See store.GuidanceNeverScannedRoots.
	NeverScannedRoots func(ctx context.Context, exclude []string) ([]string, error)
	// UserScopeRoot is the sentinel root the operator's HOME-directory
	// guidance is inventoried under. It is scanned ONCE per pass — the
	// home tree is the same for every project, so scanning it per project
	// meant N walks of ~/.claude and N duplicate rows. Empty disables the
	// user-scope half of the pass.
	UserScopeRoot string
	// SkipRoot filters a DISCOVERED root out of the pass BEFORE any
	// filesystem work, returning the reason it was filtered. Production:
	// the [guidance.RootFilter] table (scratchpads, the OS temp dir,
	// ~/.observer's harness arenas). Nil scans everything. It is never
	// consulted for a root the caller named explicitly.
	SkipRoot func(root string) (string, bool)
	// Exists reports whether a root is still a directory on this machine. A
	// root that has been deleted, or lives on an unmounted share, is skipped
	// — never scanned into an empty inventory that would tombstone every
	// row the operator still has on another machine.
	Exists func(root string) bool
	// Scan inventories one root. The ctx it receives carries the per-root
	// time budget, so a slow mount bounds itself.
	Scan func(ctx context.Context, root string) (guidance.Result, error)
	// Persist upserts one root's scan.
	Persist func(ctx context.Context, root string, files []guidance.File, at time.Time) (store.GuidanceScanSummary, error)
	// Now is the scan timestamp source. It is read ONCE PER ROOT: each
	// root lands under its own scannedAt the moment it completes, so a
	// pass that is later cut short has still durably recorded everything
	// it got through (the live defect this replaced — a four-minute pass
	// that persisted nothing because every root shared one end-of-pass
	// timestamp).
	Now func() time.Time
	// RootTimeout bounds ONE root. Zero means unbounded.
	RootTimeout time.Duration
	// PassTimeout bounds the WHOLE pass. Roots not reached inside it are
	// left for the next tick, which is why the start offset rotates.
	// Zero means unbounded.
	PassTimeout time.Duration
	// PauseBetween is a small breather between roots so a pass is a
	// background trickle rather than a CPU spike. Zero disables it.
	PauseBetween time.Duration
	// Sleep is the pause implementation; nil uses a real timer. Tests
	// inject a no-op so a pass does not actually wait.
	Sleep func(ctx context.Context, d time.Duration)
	// StartOffset rotates the root list so the tail of a capped list is
	// not starved pass after pass. Ignored when the caller named roots.
	StartOffset int
	// OnRoot, when set, is called as each root completes — the streaming
	// seam behind `guidance scan --all`'s per-root lines.
	OnRoot func(guidanceRootResult)
	// Logger is optional; a nil logger silences the pass.
	Logger *slog.Logger
}

// guidanceRootResult is one root's outcome. A failed root carries its error
// and does NOT abort the pass — one unreadable project must never stop the
// other twenty from being inventoried.
type guidanceRootResult struct {
	Root       string `json:"root"`
	Added      int    `json:"added"`
	Updated    int    `json:"updated"`
	Tombstoned int    `json:"tombstoned"`
	Unchanged  int    `json:"unchanged"`
	Files      int    `json:"files"`
	Skipped    int    `json:"skipped"`
	// ScannedAt is THIS root's own scan timestamp, empty when the root
	// was not persisted.
	ScannedAt string `json:"scanned_at,omitempty"`
	// Incomplete means the root's walk ran out of time budget. Its
	// inventory is partial and was deliberately NOT persisted: the
	// store's upsert tombstones every row a scan did not re-see, so
	// persisting a half-walked tree would mark present guidance files as
	// gone. It is retried on the next pass.
	Incomplete bool `json:"incomplete,omitempty"`
	// Err is the failure that stopped THIS root, if any.
	Err string `json:"error,omitempty"`
	// Warnings are the scanner's own per-file complaints (unreadable file,
	// bad front matter). Surfaced, never swallowed.
	Warnings []string `json:"warnings,omitempty"`
}

// Persisted reports whether this root's inventory reached the database.
func (r guidanceRootResult) Persisted() bool {
	return r.Err == "" && !r.Incomplete && r.ScannedAt != ""
}

// guidancePassResult is a whole pass's outcome.
type guidancePassResult struct {
	// ScannedAt is when the pass STARTED. Each root carries its own
	// timestamp; this one is the pass's identity, not a row's.
	ScannedAt string               `json:"scanned_at"`
	Roots     []guidanceRootResult `json:"roots"`
	// SkippedMissing counts roots that are no longer directories here.
	SkippedMissing int `json:"skipped_missing"`
	// SkippedFiltered counts roots the filter table excluded, and
	// SkipReasons breaks that down by the table's reason label.
	SkippedFiltered int            `json:"skipped_filtered"`
	SkipReasons     map[string]int `json:"skip_reasons,omitempty"`
	// Incomplete counts roots that overran the per-root budget.
	Incomplete int `json:"incomplete"`
	// NotReached counts roots the pass budget never got to. They are not
	// a failure — the next tick starts where this one stopped.
	NotReached int `json:"not_reached"`
	// Consumed is how many entries of the offered root list this pass
	// worked through; the loop advances its rotation by exactly this.
	Consumed int `json:"consumed"`
	// Total is the size of the offered root list.
	Total      int   `json:"total"`
	DurationMS int64 `json:"duration_ms"`
}

// guidanceScanPass scans every root the seams offer, skipping those that are
// filtered out or not present on this machine, and returns a per-root result.
// It returns an error only when the ROOT LIST itself could not be read, or the
// CALLER's context was cancelled; a per-root failure lands in that root's row,
// and an exhausted time budget is a bounded, honest partial pass.
func guidanceScanPass(ctx context.Context, seams guidanceSeams, only []string) (guidancePassResult, error) {
	now := seams.Now
	if now == nil {
		now = time.Now
	}
	started := now().UTC()
	res := guidancePassResult{ScannedAt: started.Format(time.RFC3339), SkipReasons: map[string]int{}}

	roots := only
	rotate := len(only) == 0
	if rotate {
		if seams.Roots == nil {
			return res, fmt.Errorf("guidance: no project-root source wired")
		}
		var err error
		roots, err = seams.Roots(ctx)
		if err != nil {
			return res, fmt.Errorf("guidance: list project roots: %w", err)
		}
	}
	res.Total = len(roots)
	if rotate {
		roots = rotateGuidanceRoots(roots, seams.StartOffset)
	}
	// The home-scope pass rides along with every pass, whether it covers
	// every project or just the one the operator named: user-scope
	// guidance is what the tools read in BOTH cases, and it is scanned
	// once rather than once per root.
	if seams.UserScopeRoot != "" {
		roots = append(roots, seams.UserScopeRoot)
	}
	roots = dedupeGuidanceRoots(roots)

	// The pass budget is a DEADLINE, not a cancellation: reaching it is a
	// normal outcome that ends the pass cleanly with everything scanned so
	// far already persisted. Only the CALLER's cancellation is an error.
	passCtx := ctx
	if seams.PassTimeout > 0 {
		var cancel context.CancelFunc
		passCtx, cancel = context.WithTimeout(ctx, seams.PassTimeout)
		defer cancel()
	}

	for i, root := range roots {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if passCtx.Err() != nil {
			res.NotReached = len(roots) - i
			break
		}
		if root != seams.UserScopeRoot {
			res.Consumed++
		}
		if i > 0 && seams.PauseBetween > 0 {
			guidanceSleep(passCtx, seams.PauseBetween, seams.Sleep)
		}
		// The filter applies to DISCOVERED roots only. A root the operator
		// named on the command line was asked for explicitly — refusing to
		// scan `--project /tmp/repro` because it lives under the temp dir
		// would be the tool second-guessing a direct instruction.
		if rotate && seams.SkipRoot != nil && root != seams.UserScopeRoot {
			if reason, skip := seams.SkipRoot(root); skip {
				res.SkippedFiltered++
				res.SkipReasons[reason]++
				continue
			}
		}
		if seams.Exists != nil && !seams.Exists(root) {
			res.SkippedMissing++
			continue
		}
		row := guidanceScanOneRoot(ctx, passCtx, seams, root, now)
		if row.Incomplete {
			res.Incomplete++
		}
		res.Roots = append(res.Roots, row)
		if seams.OnRoot != nil {
			seams.OnRoot(row)
		}
	}
	res.DurationMS = now().UTC().Sub(started).Milliseconds()
	return res, nil
}

// guidanceScanOneRoot runs (and persists) exactly one root under its own time
// budget and its own timestamp. It never returns an error: every outcome is a
// field on the row, because one root's problem is not the pass's problem.
func guidanceScanOneRoot(
	parent, passCtx context.Context,
	seams guidanceSeams,
	root string,
	now func() time.Time,
) guidanceRootResult {
	row := guidanceRootResult{Root: root}

	rootCtx := passCtx
	if seams.RootTimeout > 0 {
		var cancel context.CancelFunc
		rootCtx, cancel = context.WithTimeout(passCtx, seams.RootTimeout)
		defer cancel()
	}
	scanned, err := seams.Scan(rootCtx, root)
	row.Files = len(scanned.Files)
	row.Skipped = scanned.Skipped
	row.Warnings = scanned.Errors

	// An overrun is NOT the same as a failure, and neither is persistable:
	// a partial inventory handed to the upsert would tombstone every
	// guidance file the truncated walk never reached.
	if scanned.Incomplete || (err != nil && rootCtx.Err() != nil && parent.Err() == nil) {
		row.Incomplete = true
		row.Err = "time budget exceeded; not persisted, retried next pass"
		if seams.Logger != nil {
			seams.Logger.Warn("guidance scan ran out of time budget", "root", root, "files_seen", row.Files)
		}
		return row
	}
	if err != nil {
		row.Err = err.Error()
		if seams.Logger != nil {
			seams.Logger.Warn("guidance scan failed", "root", root, "err", err)
		}
		return row
	}

	// Each root is stamped and persisted the moment IT finishes, rather
	// than the whole pass sharing one end-of-pass write: a pass that is
	// later cut short has still durably recorded every root before the
	// cut.
	at := now().UTC()
	summary, err := seams.Persist(parent, root, scanned.Files, at)
	if err != nil {
		row.Err = err.Error()
		if seams.Logger != nil {
			seams.Logger.Warn("guidance persist failed", "root", root, "err", err)
		}
		return row
	}
	row.ScannedAt = at.Format(time.RFC3339)
	row.Added, row.Updated = summary.Added, summary.Updated
	row.Tombstoned, row.Unchanged = summary.Tombstoned, summary.Unchanged
	return row
}

// guidanceSleep pauses between roots, honouring cancellation. The seam exists
// so a test does not actually wait.
func guidanceSleep(ctx context.Context, d time.Duration, sleep func(context.Context, time.Duration)) {
	if sleep != nil {
		sleep(ctx, d)
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// rotateGuidanceRoots starts the list at offset and wraps. The list is
// ordered most-recently-active first and capped, so without rotation the same
// head would be re-walked every pass while the tail was never reached at all.
func rotateGuidanceRoots(in []string, offset int) []string {
	if len(in) == 0 || offset <= 0 {
		return in
	}
	off := offset % len(in)
	if off == 0 {
		return in
	}
	out := make([]string, 0, len(in))
	out = append(out, in[off:]...)
	out = append(out, in[:off]...)
	return out
}

// dedupeGuidanceRoots cleans and de-duplicates a root list, preserving the
// caller's order. Two spellings of the same directory would otherwise scan it
// twice and race each other's tombstones.
func dedupeGuidanceRoots(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, r := range in {
		if r == "" {
			continue
		}
		c := filepath.Clean(r)
		if seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}

// guidanceOptions projects the [guidance] config block onto the scanner's
// options, falling back to the package's own defaults for any value the
// operator left at zero.
func guidanceOptions(cfg config.GuidanceConfig) guidance.Options {
	opts := guidance.DefaultOptions()
	if cfg.MaxFileBytes > 0 {
		opts.MaxFileBytes = cfg.MaxFileBytes
	}
	if cfg.MaxDepth > 0 {
		opts.MaxDepth = cfg.MaxDepth
	}
	opts.IncludeUserScope = cfg.IncludeUserScope
	if opts.IncludeUserScope && opts.UserHome == "" {
		if home, err := os.UserHomeDir(); err == nil {
			opts.UserHome = home
		}
	}
	return opts
}

// Seeded budgets. Each is what a <= 0 config value resolves to, so a
// half-written [guidance] section is bounded rather than unbounded.
//
// They exist because the compile-time 200-root cap was not a budget at
// all: on a machine with 404 recorded roots — most of them slow DrvFs
// mounts — a start-up pass burned four CPU-minutes and, because every
// root shared one end-of-pass write, persisted nothing.
const (
	guidanceDefaultMaxRootsPerPass = 50
	guidanceDefaultRootTimeout     = 20 * time.Second
	guidanceDefaultPassTimeout     = 10 * time.Minute
	guidanceDefaultStartupDelay    = 90 * time.Second
	// guidancePauseBetweenRoots keeps a pass a background trickle. It is
	// not a config key: it is small enough that no operator needs to tune
	// it, and the real bounds are the two timeouts.
	guidancePauseBetweenRoots = 250 * time.Millisecond
	// guidanceDefaultFirstScanPoll is how often the daemon looks for
	// never-scanned roots. Not a budget — a cadence — so 0 is a real
	// setting meaning "never poll", exactly like startup_delay_seconds.
	guidanceDefaultFirstScanPoll = 60 * time.Second
	// guidanceFirstScanMaxRoots caps ONE first-scan trigger. Never-scanned
	// roots are rare by construction, so a poll that suddenly has fifty of
	// them is a machine that just imported a lot of history — and walking
	// fifty filesystems inside a 60-second tick is the CPU spike the whole
	// budget system exists to prevent. The rest wait for the next poll.
	guidanceFirstScanMaxRoots = 5
)

// guidanceFirstScanPoll resolves the poll cadence. 0 disables it; a
// NEGATIVE value (which config.Validate refuses anyway) falls back to the
// seeded cadence rather than being read as "disabled" by accident.
func guidanceFirstScanPoll(cfg config.GuidanceConfig) time.Duration {
	if cfg.FirstScanPollSeconds == 0 {
		return 0
	}
	if cfg.FirstScanPollSeconds < 0 {
		return guidanceDefaultFirstScanPoll
	}
	return time.Duration(cfg.FirstScanPollSeconds) * time.Second
}

// guidanceBudgets resolves the [guidance] time/size budgets, substituting the
// seeded default for any value the operator left at zero.
func guidanceBudgets(cfg config.GuidanceConfig) (maxRoots int, rootTimeout, passTimeout time.Duration) {
	maxRoots = cfg.MaxRootsPerPass
	if maxRoots <= 0 {
		maxRoots = guidanceDefaultMaxRootsPerPass
	}
	rootTimeout = time.Duration(cfg.RootTimeoutSeconds) * time.Second
	if rootTimeout <= 0 {
		rootTimeout = guidanceDefaultRootTimeout
	}
	passTimeout = time.Duration(cfg.PassTimeoutMinutes) * time.Minute
	if passTimeout <= 0 {
		passTimeout = guidanceDefaultPassTimeout
	}
	return maxRoots, rootTimeout, passTimeout
}

// guidanceStartupDelay is how long the daemon waits before its FIRST pass.
// Unlike the budgets, 0 is a meaningful setting here — it means "scan now" —
// so only a NEGATIVE value is clamped.
func guidanceStartupDelay(cfg config.GuidanceConfig) time.Duration {
	if cfg.StartupDelaySeconds <= 0 {
		return 0
	}
	return time.Duration(cfg.StartupDelaySeconds) * time.Second
}

// guidanceRootFilter builds the production root-skip table: the OS temp dir
// and Observer's own state directory resolved here (the pure package never
// touches os), with the user-scope sentinel exempted.
func guidanceRootFilter() guidance.RootFilter {
	f := guidance.RootFilter{
		TempDir:       os.TempDir(),
		SentinelRoots: []string{store.GuidanceUserScopeRoot},
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		f.HomeDir = home
		f.ObserverDir = filepath.Join(home, ".observer")
	}
	return f
}

// guidanceSeamsFor builds the production seams over a live store.
func guidanceSeamsFor(st *store.Store, cfg config.GuidanceConfig, logger *slog.Logger) guidanceSeams {
	opts := guidanceOptions(cfg)
	maxRoots, rootTimeout, passTimeout := guidanceBudgets(cfg)
	filter := guidanceRootFilter()
	// One scrubber for the whole pass. It runs at THIS boundary rather
	// than inside internal/guidance so the scanner stays pure: everything
	// derived from a file's bytes (its description, its front-matter
	// values) is redacted BEFORE it is persisted, because the inventory is
	// served over the dashboard's remote-ungated route and a CLAUDE.md
	// whose first line is an API key is a real shape.
	scrubber := scrub.New()
	userScopeRoot := ""
	if opts.IncludeUserScope && opts.UserHome != "" {
		userScopeRoot = store.GuidanceUserScopeRoot
	}
	return guidanceSeams{
		Roots: func(ctx context.Context) ([]string, error) {
			return st.GuidanceScanRoots(ctx, maxRoots)
		},
		NeverScannedRoots: func(ctx context.Context, exclude []string) ([]string, error) {
			// Deliberately capped well below maxRoots: this list is
			// consumed a handful at a time, and a huge candidate set is
			// exactly the shape that should trickle, not burst. The cap is
			// safe ONLY because `exclude` is applied inside the query — it
			// is a page of remaining work, not a page of the same head.
			return st.GuidanceNeverScannedRoots(ctx, guidanceFirstScanMaxRoots*4, exclude)
		},
		UserScopeRoot: userScopeRoot,
		SkipRoot: func(root string) (string, bool) {
			reason, skip := filter.Skip(root)
			return string(reason), skip
		},
		Exists: func(root string) bool {
			if root == store.GuidanceUserScopeRoot {
				return opts.UserHome != "" && guidanceRootExists(opts.UserHome)
			}
			return guidanceRootExists(root)
		},
		Scan: func(ctx context.Context, root string) (guidance.Result, error) {
			o := opts
			// A previous scan's rows are the cache: an unchanged file
			// (same size, same mtime) is not re-read or re-hashed. A cache
			// that cannot be loaded is not an error — it just means a full
			// read, which is always correct.
			if known, err := st.GuidanceKnownFiles(ctx, root); err == nil && len(known) > 0 {
				o.Known = func(abs string) (guidance.KnownFile, bool) {
					k, ok := known[abs]
					return k, ok
				}
			}
			anchor := root
			if root == store.GuidanceUserScopeRoot {
				o.UserScopeOnly = true
				anchor = o.UserHome
			} else {
				// Project passes never re-walk the home tree; the sentinel
				// root owns it.
				o.IncludeUserScope = false
			}
			res, err := guidance.Scan(ctx, anchor, guidance.OSFS(anchor), o)
			if err != nil {
				return res, err
			}
			scrubGuidanceMetadata(scrubber, res.Files)
			return res, nil
		},
		Persist:      st.UpsertGuidanceScan,
		Now:          time.Now,
		RootTimeout:  rootTimeout,
		PassTimeout:  passTimeout,
		PauseBetween: guidancePauseBetweenRoots,
		Logger:       logger,
	}
}

// scrubGuidanceMetadata redacts everything a scan derived from a file's
// BODY before it reaches the database: the description (the file's first
// prose line) and every front-matter value. Names are left alone — they
// are identifiers (a filename, a skill's own name), not free text.
func scrubGuidanceMetadata(scrubber *scrub.Scrubber, files []guidance.File) {
	if scrubber == nil {
		return
	}
	for i := range files {
		files[i].Description = scrubber.String(files[i].Description)
		for k, v := range files[i].Frontmatter {
			files[i].Frontmatter[k] = scrubber.String(v)
		}
	}
}

// guidanceRootExists reports whether root is a directory here and now.
func guidanceRootExists(root string) bool {
	info, err := os.Stat(root)
	return err == nil && info.IsDir()
}

// guidanceLoopDeps is what the loop runs on: the pass seams plus the two
// intervals and an injectable timer, so the start-up delay and the one
// line-per-pass log are testable without waiting 90 real seconds.
type guidanceLoopDeps struct {
	Seams        guidanceSeams
	StartupDelay time.Duration
	Rescan       time.Duration
	Logger       *slog.Logger
	// FirstScanPoll is how often the loop looks for NEVER-scanned roots and
	// inventories just those. Zero disables the poll; so does a nil
	// Seams.NeverScannedRoots.
	FirstScanPoll time.Duration
	// After is the timer seam (time.After in production).
	After func(d time.Duration) <-chan time.Time
}

// guidanceFirstScanTargets is the pure decision: which of the offered
// never-scanned roots this poll should actually walk.
//
// Four filters, in order, and each exists for a live failure mode:
//
//  1. attempted — roots this daemon has already tried. "Never scanned" is
//     derived from "has no guidance row", so a project that genuinely has
//     no CLAUDE.md scans into zero rows and stays a candidate forever. The
//     per-lifetime memory is what stops it being re-walked every minute.
//  2. SkipRoot — the same filter table the periodic pass uses
//     (scratchpads, the temp dir, ~/.observer). These are DISCOVERED roots,
//     not roots an operator named, so the filter applies.
//  3. Exists — a root that is not a directory on this machine is skipped,
//     never scanned into an empty result that would tombstone rows.
//  4. limit — one capped batch, never loop-until-done.
//
// A root filtered by 2 or 3 is still marked attempted by the caller, so a
// permanently-filtered root is evaluated once per daemon lifetime rather
// than on every tick.
func guidanceFirstScanTargets(
	candidates []string,
	attempted map[string]bool,
	skip func(root string) (string, bool),
	exists func(root string) bool,
	limit int,
) (targets, considered []string) {
	for _, root := range candidates {
		if len(targets) >= limit {
			break
		}
		if root == "" || attempted[root] {
			continue
		}
		considered = append(considered, root)
		if skip != nil {
			if _, skipped := skip(root); skipped {
				continue
			}
		}
		if exists != nil && !exists(root) {
			continue
		}
		targets = append(targets, root)
	}
	return targets, considered
}

// sortedGuidanceKeys renders a set as a deterministic slice. Order is not
// semantically load-bearing (it feeds a NOT IN), but a stable one keeps the
// generated SQL identical between ticks, which keeps SQLite's statement cache
// useful and a failure reproducible.
func sortedGuidanceKeys(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// guidanceFirstScanOnce runs one first-scan trigger: list the never-scanned
// roots, pick the ones this poll should walk, and scan JUST those under the
// same per-root and per-pass budgets the periodic pass uses.
//
// It runs on the loop's own goroutine, outside any write transaction — the
// candidate list is one read, and each root's inventory is persisted by the
// same [guidanceScanOneRoot] path as always.
func guidanceFirstScanOnce(ctx context.Context, seams guidanceSeams, attempted map[string]bool, logger *slog.Logger) {
	if seams.NeverScannedRoots == nil {
		return
	}
	candidates, err := seams.NeverScannedRoots(ctx, sortedGuidanceKeys(attempted))
	if err != nil {
		if ctx.Err() == nil && logger != nil {
			logger.Warn("guidance first-scan poll failed", "err", err)
		}
		return
	}
	targets, considered := guidanceFirstScanTargets(
		candidates, attempted, seams.SkipRoot, seams.Exists, guidanceFirstScanMaxRoots)
	for _, root := range considered {
		attempted[root] = true
	}
	if len(targets) == 0 {
		return
	}

	pass := seams
	// The home tree is the periodic pass's job and is scanned once per
	// pass there; a first-scan trigger must never widen its own root set.
	pass.UserScopeRoot = ""
	pass.OnRoot = func(row guidanceRootResult) {
		if logger == nil {
			return
		}
		logger.Info("guidance first scan",
			"root", row.Root,
			"files", row.Files,
			"added", row.Added,
			"persisted", row.Persisted(),
			"incomplete", row.Incomplete,
			"error", row.Err,
		)
	}
	if _, err := guidanceScanPass(ctx, pass, targets); err != nil && ctx.Err() == nil && logger != nil {
		logger.Warn("guidance first scan pass failed", "err", err)
	}
}

// guidanceRunLoop is the daemon-lifetime loop: one pass after StartupDelay,
// then one every Rescan. P1 fail-soft like every sibling background loop — it
// logs and retries, and never cancels proxy/watcher/dashboard.
//
// The start-up delay matters: a daemon restart already has the proxy warming
// TLS, the watcher enumerating adapters and the dashboard building. Walking
// every project root at that same moment is what made a restart feel like a
// CPU spike, and the inventory is never urgent — it describes files that were
// already there before the restart.
func guidanceRunLoop(ctx context.Context, deps guidanceLoopDeps) {
	after := deps.After
	if after == nil {
		after = time.After
	}
	offset := 0

	runOnce := func() {
		seams := deps.Seams
		seams.StartOffset = offset
		res, err := guidanceScanPass(ctx, seams, nil)
		if err != nil {
			if ctx.Err() == nil && deps.Logger != nil {
				deps.Logger.Warn("guidance scan pass failed", "err", err)
			}
			return
		}
		if res.Total > 0 {
			offset = (offset + res.Consumed) % res.Total
		}
		if deps.Logger != nil {
			deps.Logger.Info("guidance scan pass", guidancePassLogArgs(res)...)
		}
	}

	if deps.StartupDelay > 0 {
		select {
		case <-ctx.Done():
			return
		case <-after(deps.StartupDelay):
		}
	}
	runOnce()

	// Two independent cadences from here on. A nil channel blocks forever
	// in a select, so "this cadence is off" needs no flag and no branch:
	// with both off the loop simply returns, exactly as it did before the
	// first-scan poll existed.
	var rescanC, pollC <-chan time.Time
	if deps.Rescan > 0 {
		rescanC = after(deps.Rescan)
	}
	attempted := map[string]bool{}
	pollOn := deps.FirstScanPoll > 0 && deps.Seams.NeverScannedRoots != nil
	if pollOn {
		pollC = after(deps.FirstScanPoll)
	}
	if rescanC == nil && pollC == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-rescanC:
			runOnce()
			rescanC = after(deps.Rescan)
		case <-pollC:
			guidanceFirstScanOnce(ctx, deps.Seams, attempted, deps.Logger)
			pollC = after(deps.FirstScanPoll)
		}
	}
}

// guidancePassLogArgs is the ONE line an operator sees per pass. Before this,
// the daemon log carried no guidance line at all, so a pass that burned
// minutes and persisted nothing was completely invisible.
func guidancePassLogArgs(res guidancePassResult) []any {
	var files, changed, persisted int
	for _, r := range res.Roots {
		files += r.Files
		changed += r.Added + r.Updated + r.Tombstoned
		if r.Persisted() {
			persisted++
		}
	}
	return []any{
		"roots", persisted,
		"files", files,
		"changed", changed,
		"skipped_filtered", res.SkippedFiltered,
		"skipped_missing", res.SkippedMissing,
		"incomplete", res.Incomplete,
		"not_reached", res.NotReached,
		"duration_ms", res.DurationMS,
	}
}

// guidanceScanLoop wires guidanceRunLoop over the live config and store.
func guidanceScanLoop(ctx context.Context, configPath string) {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return
	}
	defer cleanup()
	if !cfg.Guidance.Enabled {
		return
	}
	logger := newLogger(cfg.Observer.LogLevel)
	guidanceRunLoop(ctx, guidanceLoopDeps{
		Seams:         guidanceSeamsFor(store.New(database), cfg.Guidance, logger),
		StartupDelay:  guidanceStartupDelay(cfg.Guidance),
		Rescan:        time.Duration(cfg.Guidance.RescanMinutes) * time.Minute,
		FirstScanPoll: guidanceFirstScanPoll(cfg.Guidance),
		Logger:        logger,
	})
}

// -----------------------------------------------------------------------------
// CLI
// -----------------------------------------------------------------------------

// newGuidanceCmd builds `observer guidance` — the operator's view of the
// agent-guidance inventory.
func newGuidanceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "guidance",
		Short: "Inventory the AI-guidance files (CLAUDE.md, AGENTS.md, skills, rules) a project carries",
		Long: "Lists the guidance files each AI coding tool reads in a project:\n" +
			"instruction files (CLAUDE.md, AGENTS.md, GEMINI.md), skills, sub-agent\n" +
			"definitions, slash commands, and conditionally-applied rules.\n\n" +
			"The daemon refreshes this inventory every [guidance].rescan_minutes;\n" +
			"`guidance scan` runs the same pass on demand. Only names, sizes, hashes\n" +
			"and front-matter metadata are stored — never a file's body, and every\n" +
			"stored description passes through the secret scrubber first.\n\n" +
			"Your HOME-directory guidance (~/.claude/…, ~/.codex/…) applies to every\n" +
			"project, so it is scanned once per pass and listed under the root \"~\";\n" +
			"it is folded into every project's listing.",
	}
	cmd.AddCommand(newGuidanceScanCmd(), newGuidanceListCmd())
	return cmd
}

func newGuidanceScanCmd() *cobra.Command {
	var (
		configPath string
		project    string
		all        bool
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan one project (or every known project) for guidance files",
		Long: "Re-inventories guidance files and records what changed.\n\n" +
			"With --all, every project root the observer knows. With --project, just\n" +
			"that root. With neither, the current working directory.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if all && project != "" {
				return fmt.Errorf("guidance scan: pass --all or --project, not both")
			}
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			if !cfg.Guidance.Enabled {
				fmt.Fprintln(cmd.OutOrStdout(), "guidance scanning is disabled ([guidance].enabled = false)")
				return nil
			}

			var only []string
			switch {
			case all:
				// nil → the seams' own root list.
			case project != "":
				abs, err := filepath.Abs(project)
				if err != nil {
					return fmt.Errorf("guidance scan: resolve --project: %w", err)
				}
				only = []string{abs}
			default:
				cwd, err := os.Getwd()
				if err != nil {
					return fmt.Errorf("guidance scan: resolve working directory: %w", err)
				}
				only = []string{cwd}
			}

			seams := guidanceSeamsFor(store.New(database), cfg.Guidance, newLogger(cfg.Observer.LogLevel))
			// `--all` is the long one: on a machine with hundreds of
			// recorded roots it runs for minutes under the same budgets
			// the daemon uses, so it STREAMS a line per root as each
			// completes rather than printing nothing until the end.
			streaming := all && !jsonOut
			if streaming {
				out := cmd.OutOrStdout()
				fmt.Fprintln(out, guidanceScanHeader)
				seams.OnRoot = func(row guidanceRootResult) {
					fmt.Fprintln(out, guidanceScanLine(row))
				}
			}
			res, err := guidanceScanPass(cmd.Context(), seams, only)
			if err != nil {
				return err
			}
			if streaming {
				printGuidanceScanTail(cmd, res)
				return nil
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}
			printGuidanceScan(cmd, res)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&project, "project", "", "Scan one project root (default: the working directory)")
	cmd.Flags().BoolVar(&all, "all", false, "Scan every project root the observer knows")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit the raw JSON payload")
	return cmd
}

func newGuidanceListCmd() *cobra.Command {
	var (
		configPath string
		project    string
		absent     bool
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the guidance files recorded for a project",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			root := project
			if root == "" {
				cwd, err := os.Getwd()
				if err != nil {
					return fmt.Errorf("guidance list: resolve working directory: %w", err)
				}
				root = cwd
			}
			abs, err := filepath.Abs(root)
			if err != nil {
				return fmt.Errorf("guidance list: resolve --project: %w", err)
			}
			rows, err := store.New(database).ListGuidance(cmd.Context(), abs, absent)
			if err != nil {
				return fmt.Errorf("guidance list: %w", err)
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if rows == nil {
					rows = []store.GuidanceRow{}
				}
				return enc.Encode(map[string]any{"root": abs, "rows": rows})
			}
			printGuidanceList(cmd, abs, rows)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&project, "project", "", "Project root (default: the working directory)")
	cmd.Flags().BoolVar(&absent, "absent", false, "Also list files that were recorded once but are gone now")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit the raw JSON payload")
	return cmd
}

// guidanceScanHeader / guidanceScanLine are the STREAMING renderer: fixed
// widths rather than a tabwriter, because a tabwriter cannot align columns it
// has not seen yet and a streaming table must print each row as it lands.
const guidanceScanHeader = "ROOT                                                          FILES  ADDED  UPDATED   GONE  UNCHGD"

func guidanceScanLine(r guidanceRootResult) string {
	root := r.Root
	if len(root) > 60 {
		root = "…" + root[len(root)-59:]
	}
	if r.Err != "" {
		note := "failed"
		if r.Incomplete {
			note = "incomplete"
		}
		return fmt.Sprintf("%-60s  %-38s", root, "("+note+": "+r.Err+")")
	}
	return fmt.Sprintf("%-60s %6d %6d %8d %6d %7d",
		root, r.Files, r.Added, r.Updated, r.Tombstoned, r.Unchanged)
}

// printGuidanceScan renders a scan pass as one line per root.
func printGuidanceScan(cmd *cobra.Command, res guidancePassResult) {
	out := cmd.OutOrStdout()
	if len(res.Roots) == 0 {
		fmt.Fprintln(out, "no project roots scanned (nothing known, filtered out, or none present on this machine)")
		printGuidanceScanTail(cmd, res)
		return
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ROOT\tFILES\tADDED\tUPDATED\tGONE\tUNCHANGED")
	for _, r := range res.Roots {
		if r.Err != "" {
			note := r.Err
			if r.Incomplete {
				note = "incomplete: " + r.Err
			}
			fmt.Fprintf(tw, "%s\t-\t-\t-\t-\t-\t(%s)\n", r.Root, note)
			continue
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\n",
			r.Root, r.Files, r.Added, r.Updated, r.Tombstoned, r.Unchanged)
	}
	_ = tw.Flush()
	printGuidanceScanTail(cmd, res)
}

// printGuidanceScanTail is everything after the per-root rows: why roots were
// left out, and the scanner's own warnings. It is shared by the batch and the
// streaming renderers so a streamed pass ends with the same honest summary.
func printGuidanceScanTail(cmd *cobra.Command, res guidancePassResult) {
	out := cmd.OutOrStdout()
	if res.SkippedMissing > 0 {
		fmt.Fprintf(out, "\n%d root(s) skipped — not a directory on this machine\n", res.SkippedMissing)
	}
	if res.SkippedFiltered > 0 {
		reasons := make([]string, 0, len(res.SkipReasons))
		for k := range res.SkipReasons {
			reasons = append(reasons, k)
		}
		sort.Strings(reasons)
		parts := make([]string, 0, len(reasons))
		for _, k := range reasons {
			parts = append(parts, fmt.Sprintf("%s=%d", k, res.SkipReasons[k]))
		}
		fmt.Fprintf(out, "%d root(s) filtered out (%s)\n", res.SkippedFiltered, strings.Join(parts, ", "))
	}
	if res.Incomplete > 0 {
		fmt.Fprintf(out, "%d root(s) ran out of time budget — NOT persisted (a partial inventory would tombstone real files); retried next pass\n", res.Incomplete)
	}
	if res.NotReached > 0 {
		fmt.Fprintf(out, "%d root(s) not reached inside the pass budget — the next pass starts where this one stopped\n", res.NotReached)
	}
	for _, r := range res.Roots {
		for _, warn := range r.Warnings {
			fmt.Fprintf(out, "warn: %s: %s\n", r.Root, warn)
		}
	}
}

// printGuidanceList renders one project's inventory as a compact table.
func printGuidanceList(cmd *cobra.Command, root string, rows []store.GuidanceRow) {
	out := cmd.OutOrStdout()
	if len(rows) == 0 {
		fmt.Fprintf(out, "no guidance files recorded for %s\n", root)
		fmt.Fprintf(out, "run `observer guidance scan --project %s` to inventory it\n", root)
		return
	}
	sorted := make([]store.GuidanceRow, len(rows))
	copy(sorted, rows)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.Tool != b.Tool {
			return a.Tool < b.Tool
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.RelPath < b.RelPath
	})

	fmt.Fprintf(out, "%s — %d guidance file(s)\n\n", root, len(sorted))
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TOOL\tKIND\tNAME\tPATH\tSIZE\tMODIFIED\tPRESENT")
	for _, r := range sorted {
		modified := "-"
		if !r.ModifiedAt.IsZero() {
			modified = r.ModifiedAt.Local().Format("2006-01-02 15:04")
		}
		present := "yes"
		if !r.Present {
			present = "GONE"
		}
		name := r.Name
		if name == "" {
			name = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Tool, r.Kind, name, r.RelPath, humanGuidanceSize(r.SizeBytes), modified, present)
	}
	_ = tw.Flush()
}

// humanGuidanceSize renders a byte count compactly. Sizes here are small by
// nature (prose files), so KB is the largest unit worth spelling.
func humanGuidanceSize(n int64) string {
	switch {
	case n <= 0:
		return "0"
	case n < 1024:
		return fmt.Sprintf("%dB", n)
	default:
		return fmt.Sprintf("%.1fKB", float64(n)/1024)
	}
}
