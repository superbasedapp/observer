package commitscan

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/loc"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
)

// Defaults for every Options field a caller leaves at its zero value (plan
// §2 R2).
const (
	defaultInterval       = 120 * time.Second
	defaultMaxPerTick     = 500
	defaultWorkers        = 2
	defaultLinkWindow     = 14 * 24 * time.Hour
	defaultMaxOutputBytes = 8 << 20 // 8 MiB
	defaultNotRepoRecheck = 30 * time.Minute

	// watermarkOverlap is subtracted from the stored watermark before the
	// next incremental scan's --since, so a commit landed after the
	// previous scan read but before it wrote its watermark is never
	// missed. UpsertCommits' (project_id, sha) UNIQUE key makes the
	// resulting re-fetch a no-op.
	watermarkOverlap = 1 * time.Hour

	// reachabilityLookback extends the revalidation window (plan R2/F3)
	// one day past LinkWindow, so a commit that is still linkable under
	// the attribution rule is never revalidated right at the window's own
	// edge.
	reachabilityLookback = 24 * time.Hour

	// maxBackoffTicks caps the per-root consecutive-failure backoff
	// (2^n ticks, capped here) — plan R2/F14.
	maxBackoffTicks = 64

	// minPageCommits is the floor scanPage's overflow-retry halves the
	// page size down to before giving up (2026-09-22 review F13): an 8
	// MiB page that still overflows at 1 commit means that SINGLE
	// commit's own numstat output cannot fit the byte cap, and no
	// further shrinking can help — the scan records a failure instead of
	// silently advancing the watermark past the ungettable commit.
	minPageCommits = 1

	// reachabilityPageShas is the starting page size for the
	// reachability rev-list walk (2026-09-22 review finding #7). Each
	// line is just a 40-character sha plus a newline, so this starts far
	// larger than a commit-log page's MaxPerTick — the byte cap is only
	// realistically at risk on an enormous or very long-lived
	// sub-project history.
	reachabilityPageShas = 20000

	// minReachabilityPageShas is the floor reachability paging halves
	// down to before giving up on ONE page and skipping the revalidation
	// pass without mutating reachability (2026-09-22 review finding #7) —
	// the same floor-and-skip shape as minPageCommits, at sha-list scale.
	minReachabilityPageShas = 1

	// gitNotFoundError is the fixed marker text State.LastError carries
	// when Options.Unavailable classifies an Exec failure as "git is not
	// on PATH" (plan R9). internal/store.CommitCaptureState looks for
	// this exact substring; keep the two in sync if it ever changes.
	gitNotFoundError = "git not found on PATH"
)

// Root is one project the scanner may poll: its identity plus its
// filesystem root.
type Root struct {
	ProjectID int64
	RootPath  string
}

// State is one project's durable scanner watermark + health — the plain
// shape internal/store.ScanState mirrors on the other side of the Options
// seam.
type State struct {
	ProjectID           int64
	LastSHA             string
	LastCommittedAt     time.Time
	LastScanAt          time.Time
	LastError           string
	ConsecutiveFailures int
	// LocalAuthorHash is commitlog.HashAuthorName of the repository's
	// configured user.name, resolved on every successful scan (review
	// 2026-09-29 finding 8). "" = unknown (unset, or the read failed); the
	// store keeps the last known value rather than clearing it on "".
	LocalAuthorHash string
}

// Result is the outcome of one ScanOnce/FullScan call.
type Result struct {
	ProjectID    int64
	RootPath     string
	CommitsSeen  int
	Inserted     int
	Reachability int  // number of reachable shas the revalidation pass observed (0 if it did not run)
	Overflow     bool // the git-log invocation hit its byte cap
	// HeadSHA is the concrete sha this scan pinned HEAD to ("" for a
	// repository with no commits yet). Additive (S10-SKILLS): the
	// AfterScan step reuses it instead of re-resolving HEAD itself.
	HeadSHA string
	// Subtree is the project's path prefix inside its repository ("" when
	// the project root is the toplevel), as resolveSubtree computed it.
	Subtree string
}

// Options wires every dependency the scanner needs. Every func field is
// required for Run to do useful work; New fills the numeric/duration
// fields left at their zero value with the defaults above.
type Options struct {
	// Roots lists the candidate project roots for one pass. Production:
	// internal/store.ActiveProjectRoots (a session in the last
	// [projects].active_project_days).
	Roots func(ctx context.Context) ([]Root, error)
	// Scannable reports whether root is a directory the scanner may run
	// git in. Optional: nil means every root is scannable (the test
	// default — fixtures use roots that exist only inside a fake Exec).
	// Production wires a plain os.Stat IsDir check (cmd/observer
	// commitscan_wire.go). A root that fails it is skipped BEFORE any
	// state read or git exec and logged once per root at Info, never as
	// a per-tick "scan failed" WARN — this is what keeps the synthetic
	// placeholder roots adapters file root-less sessions under
	// ("[cursor]", "[antigravity]", "[grokbot]", …) out of the scanner
	// (2026-09-23: a fresh "[cursor]" project produced a
	// `fatal: cannot change to '[cursor]'` WARN every 120 s).
	Scannable func(root string) bool
	// Exec runs one read-only git invocation rooted at root, capped at
	// maxBytes of stdout. Production: internal/gitview.RunReadOnly.
	Exec func(ctx context.Context, root string, maxBytes int, args ...string) ([]byte, bool, error)
	// Unavailable classifies an Exec error as "git itself is not
	// runnable" (as opposed to an ordinary per-invocation failure — a
	// missing repo, a timeout, a permission error). Production wires
	// errors.Is(err, gitview.ErrGitUnavailable). Optional: nil means no
	// error is ever classified this way, so the scanner only ever
	// backs off per-root and never goes globally idle.
	Unavailable func(err error) bool
	// NotRepo classifies an Exec error as "this root exists but is not
	// inside any git repository" (a scratch folder like /tmp, a /mnt/c
	// workspace that was never `git init`-ed). Production wires
	// internal/gitview.IsNotRepoError. A root so classified is skipped
	// BEFORE any state read or git exec until NotRepoRecheck elapses, and
	// logged ONCE per root per process at Info, never as a per-tick "scan
	// failed" WARN; after NotRepoRecheck the root is scanned again, so a
	// later `git init` is picked up. Its persisted failure count is pinned
	// at 1 (not incremented), so the exponential backoff never stretches
	// the recheck cadence past NotRepoRecheck. Optional: nil means no error
	// is ever classified this way (the pre-2026-09-26 behaviour).
	NotRepo func(err error) bool
	// NotRepoRecheck is how long a NotRepo-classified root is skipped before
	// it is probed again. Default 30 minutes.
	NotRepoRecheck time.Duration
	// NoCommits classifies a `--quiet` git probe's failure as "this
	// target did not resolve, silently" — the SAME structural predicate
	// resolveHeadSHA applies to BOTH its FIRST probe (`git rev-parse
	// --verify --quiet HEAD`) and, when that first probe is
	// NoCommits-classified, its independent second ref-state probe
	// (`git show-ref --verify --quiet <branch>`) before ever concluding
	// "this repository has no commits yet" (2026-09-22 review findings
	// #6, then S8, then finding 11 — NoCommits is a STRUCTURAL,
	// exit-code-based classification, not a message-text match, and now
	// also gates the second probe so a corrupt/unreadable repository's
	// show-ref failure is never misread as "no ref yet"; see
	// gitview.IsNoCommitsError's doc comment). Production wires
	// internal/gitview.IsNoCommitsError. Optional: nil means every
	// resolveHeadSHA failure is treated as a genuine failure (the safe
	// default — never silently guessing "no commits" for an
	// unclassified error); resolveHeadSHA never reaches the second probe
	// when NoCommits is nil, so the second probe never needs its own nil
	// check.
	NoCommits func(err error) bool
	// State reads one project's durable watermark. ok=false means never
	// scanned. Production: internal/store.CommitScanState.
	State func(ctx context.Context, projectID int64) (State, bool, error)
	// SetState persists one project's watermark, after every attempt —
	// success or failure. Production: internal/store.SetCommitScanState.
	SetState func(ctx context.Context, st State) error
	// Sink writes a batch of parsed commits for one project and reports
	// how many were genuinely new. Production: internal/store.UpsertCommits.
	Sink func(ctx context.Context, projectID int64, commits []commitlog.Commit, scannedAt time.Time) (int, error)
	// LocalAuthorName reads the repository's effective author identity at
	// root - the configured user.name (local config over global), which is
	// what a local commit records as its author name (%an) - for the
	// foreign_author ownership gate (review 2026-09-29 finding 8). An unset
	// identity is ("", nil) or an error; both mean unknown. Production:
	// a read-only `config --get user.name` through gitview (cmd/observer
	// commitscan_wire.go). Optional: nil means the identity is always
	// unknown (the pre-author-check behaviour).
	LocalAuthorName func(ctx context.Context, root string) (string, error)
	// Reachability revalidates which of a project's already-stored
	// commits (at or after `since`) are still HEAD-reachable. Production:
	// internal/store.MarkCommitsReachability.
	Reachability func(ctx context.Context, projectID int64, reachable map[string]bool, since time.Time) error
	// AfterScan, when set, runs after every SUCCESSFUL daemon tick for a
	// root, with the scan's pinned HEAD and subtree (S10-SKILLS: the
	// skills-history git step, internal/skillscan, wired in
	// cmd/observer/commitscan_wire.go). It therefore inherits this
	// scanner's active-project set, backoff, unborn/non-repo
	// classification and HEAD pin, and never runs for a root whose scan
	// failed. Optional: nil (the zero value) leaves the scanner exactly as
	// before. It is not called by ScanOnce/FullScan themselves, so
	// `observer backfill --commits` is unaffected.
	AfterScan func(ctx context.Context, root Root, res Result)

	// Interval between ticks. Default 120s.
	Interval time.Duration
	// MaxPerTick bounds how many commits ONE incremental scan asks git
	// for (`git log -n <MaxPerTick>`). Default 500. FullScan takes its
	// own max and ignores this field.
	MaxPerTick int
	// Workers bounds how many roots are scanned concurrently in one pass.
	// Default 2.
	Workers int
	// LinkWindow is the attribution window (plan R4.4) that sizes the
	// reachability-revalidation lookback: `LinkWindow + 24h`. Default 14
	// days.
	LinkWindow time.Duration
	// MaxOutputBytes caps each git invocation's captured stdout. Default
	// 8 MiB.
	MaxOutputBytes int
	// Logger is optional; a nil logger silences the scanner.
	Logger *slog.Logger
	// Now is the clock; nil uses time.Now. Tests inject a fixed clock.
	Now func() time.Time
}

// Scanner is the running instance built by New.
type Scanner struct {
	opts Options
	// gitUnavailable latches once any Exec call is classified
	// Unavailable — the whole scanner goes idle for its remaining
	// lifetime (plan R9). sync/atomic.Bool would be simplest, but the
	// module's Go floor (1.22) already has it; use it directly.
	gitUnavailable atomic.Bool
	warnOnce       sync.Once
	// skipped records roots Scannable rejected, so each is logged once.
	skipped sync.Map
	// notRepoUntil maps a root NotRepo classified to the time.Time before
	// which runPass skips it; notRepoLogged records roots already logged,
	// so each is logged once per process however often it is re-probed.
	notRepoUntil  sync.Map
	notRepoLogged sync.Map
}

// New builds a Scanner, filling every zero-valued numeric/duration Options
// field with its documented default.
func New(opts Options) *Scanner {
	if opts.Interval <= 0 {
		opts.Interval = defaultInterval
	}
	if opts.MaxPerTick <= 0 {
		opts.MaxPerTick = defaultMaxPerTick
	}
	if opts.Workers <= 0 {
		opts.Workers = defaultWorkers
	}
	if opts.LinkWindow <= 0 {
		opts.LinkWindow = defaultLinkWindow
	}
	if opts.MaxOutputBytes <= 0 {
		opts.MaxOutputBytes = defaultMaxOutputBytes
	}
	if opts.NotRepoRecheck <= 0 {
		opts.NotRepoRecheck = defaultNotRepoRecheck
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Scanner{opts: opts}
}

// warn logs at Warn level when a logger was configured; a nil Logger
// silences the scanner entirely (mirrors internal/surfaceenrich /
// cmd/observer's guidance loop convention).
func (s *Scanner) warn(msg string, args ...any) {
	if s.opts.Logger != nil {
		s.opts.Logger.Warn(msg, args...)
	}
}

// Run loops until ctx is cancelled: one pass immediately, then one every
// Interval. A pass that finds git unavailable logs exactly one WARN
// (across the scanner's whole lifetime) and every subsequent pass becomes
// a no-op — R9's "scanner idle" state.
func (s *Scanner) Run(ctx context.Context) {
	s.runPass(ctx)
	ticker := time.NewTicker(s.opts.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runPass(ctx)
		}
	}
}

// runPass scans every due root once, bounded by the worker pool.
func (s *Scanner) runPass(ctx context.Context) {
	if s.gitUnavailable.Load() {
		return
	}
	roots, err := s.opts.Roots(ctx)
	if err != nil {
		s.warn("commitscan: list roots failed", "error", err)
		return
	}

	var due []Root
	for _, r := range roots {
		if s.opts.Scannable != nil && !s.opts.Scannable(r.RootPath) {
			if _, seen := s.skipped.LoadOrStore(r.RootPath, struct{}{}); !seen && s.opts.Logger != nil {
				s.opts.Logger.Info("commitscan: root is not a directory - skipping (placeholder or unmounted project root)",
					"project_id", r.ProjectID, "root", r.RootPath)
			}
			continue
		}
		if until, ok := s.notRepoUntil.Load(r.RootPath); ok && s.opts.Now().Before(until.(time.Time)) {
			continue
		}
		st, ok, err := s.opts.State(ctx, r.ProjectID)
		if err != nil {
			s.warn("commitscan: read state failed", "project_id", r.ProjectID, "error", err)
			continue
		}
		if !ok || dueForScan(s.opts.Now(), s.opts.Interval, st) {
			due = append(due, r)
		}
	}

	sem := make(chan struct{}, s.opts.Workers)
	var wg sync.WaitGroup
	for _, root := range due {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(root Root) {
			defer wg.Done()
			defer func() { <-sem }()
			s.scanRootTick(ctx, root)
		}(root)
	}
	wg.Wait()
}

// scanRootTick runs one incremental ScanOnce for root and reacts to a
// git-unavailable classification by latching the scanner idle.
func (s *Scanner) scanRootTick(ctx context.Context, root Root) {
	res, err := s.ScanOnce(ctx, root)
	if err == nil {
		s.notRepoUntil.Delete(root.RootPath)
		if s.opts.AfterScan != nil {
			s.opts.AfterScan(ctx, root, res)
		}
		return
	}
	if s.opts.Unavailable != nil && s.opts.Unavailable(err) {
		if s.gitUnavailable.CompareAndSwap(false, true) {
			s.warnOnce.Do(func() {
				s.warn("commitscan: git not found on PATH — commit-capture scanner going idle")
			})
		}
		return
	}
	if s.isNotRepo(err) {
		s.notRepoUntil.Store(root.RootPath, s.opts.Now().Add(s.opts.NotRepoRecheck))
		if _, seen := s.notRepoLogged.LoadOrStore(root.RootPath, struct{}{}); !seen && s.opts.Logger != nil {
			s.opts.Logger.Info("commitscan: root is not a git repository - skipping, re-checked periodically",
				"project_id", root.ProjectID, "root", root.RootPath, "recheck", s.opts.NotRepoRecheck)
		}
		return
	}
	s.warn("commitscan: scan failed", "project_id", root.ProjectID, "root", root.RootPath, "error", err)
}

// dueForScan reports whether a root with the given stored state should be
// scanned on this tick, applying the per-root consecutive-failure backoff
// (plan R2/F14): a healthy root (ConsecutiveFailures == 0) is always due;
// a failing root waits min(2^failures, maxBackoffTicks) ticks since its
// last attempt.
func dueForScan(now time.Time, interval time.Duration, st State) bool {
	if st.ConsecutiveFailures <= 0 {
		return true
	}
	return now.Sub(st.LastScanAt) >= backoffDuration(st.ConsecutiveFailures, interval)
}

func backoffDuration(consecutiveFailures int, interval time.Duration) time.Duration {
	n := consecutiveFailures
	if n > 6 { // 2^6 == maxBackoffTicks; avoid a large shift for a large counter
		n = 6
	}
	ticks := 1 << n
	if ticks > maxBackoffTicks {
		ticks = maxBackoffTicks
	}
	return time.Duration(ticks) * interval
}

// ScanOnce runs one scan of root. A project with a completed prior scan
// (LastCommittedAt already set) gets an ordinary INCREMENTAL page: its
// --since is derived from the stored watermark (last committed-at minus
// the overlap window), bounded to MaxPerTick commits.
//
// A project with NO completed prior scan — either genuinely never
// scanned (ok == false), or one whose backfill was interrupted before it
// finished (ok == true but LastCommittedAt is still zero: a page-1
// overflow that exhausted the retry floor per F13, or a mid-walk ctx
// cancellation) — instead runs the FULL paged history walk in THIS one
// call (2026-09-22 review F12): stopping at a single MaxPerTick page
// here, as the code did before this fix, would strand every commit
// older than the newest MaxPerTick forever, because every LATER
// incremental scan's --since only ever moves the watermark forward and
// can never see behind it.
//
// The bound on this daemon-tick call is per-git-invocation, not
// wall-clock: FullScan's paged loop sinks each page as it lands and
// every page stays inside the exec seam's own per-command timeout
// (commitScanExecTimeout, 60s in cmd/observer/commitscan_wire.go), but
// the OVERALL call is not itself time-boxed — a first-time backfill of
// an especially large repository can therefore run past the daemon's
// nominal 120s Interval. That is acceptable because Scanner.Run's
// ticker COALESCES missed ticks (time.Ticker's channel is buffered by
// exactly 1) rather than queuing them, and runPass bounds concurrency to
// Workers (2) roots at a time via its semaphore — so at most 2 roots
// are ever mid-backfill together, and every OTHER due root is merely
// delayed to a later tick, never skipped or starved.
func (s *Scanner) ScanOnce(ctx context.Context, root Root) (Result, error) {
	st, ok, err := s.opts.State(ctx, root.ProjectID)
	if err != nil {
		return Result{ProjectID: root.ProjectID, RootPath: root.RootPath}, err
	}
	if !ok || st.LastCommittedAt.IsZero() {
		return s.FullScan(ctx, root, time.Time{}, 0)
	}
	since := st.LastCommittedAt.Add(-watermarkOverlap).UTC().Format(time.RFC3339)
	// bounded=false: an incremental tick must COMPLETE the range back to
	// the watermark before advancing it (2026-09-22 review finding S2) —
	// see scan's doc comment.
	return s.scan(ctx, root, since, s.opts.MaxPerTick, false)
}

// FullScan runs an UNBOUNDED-by-watermark scan of root — `observer
// backfill --commits`'s full-history pass. since (zero = the beginning of
// history) and max (<= 0 = unbounded) are the caller's own choice, NOT
// derived from stored state.
//
// An unbounded max is walked in PAGES (newest first, `--skip` offsets) so
// every git invocation stays inside the exec seam's per-command timeout —
// one `git log --numstat` over a whole multi-thousand-commit history
// takes tens of seconds and would be killed. Each page starts at
// MaxPerTick commits; a page that overflows the byte cap is retried at a
// smaller size (scanPage, plan review F13) rather than shrinking every
// OTHER page too, so the per-page request size can vary — the loop
// therefore advances `skip` by however many commits THIS page actually
// asked for (scanPage's usedMax), never the nominal MaxPerTick, or a
// shrunk page would silently skip the commits between what it fetched
// and where the next page starts. The watermark is the newest commit of
// the first page; the pages are sunk as they arrive, so a failure
// mid-walk keeps what already landed and reports the error (and does
// NOT advance the watermark, since finishScan is only reached after the
// loop completes cleanly).
//
// HEAD is resolved to a concrete sha ONCE, before the first page
// (resolveHeadSHA, plan review F16), and that same sha is used for every
// page's `git log` AND the tail reachability rev-list — never the
// mutable ref "HEAD" re-resolved per invocation — so a rebase, reset, or
// fast-forward landing between two pages of the SAME scan cannot cause a
// later page to walk a different history than the first page already
// committed to.
func (s *Scanner) FullScan(ctx context.Context, root Root, since time.Time, max int) (Result, error) {
	sinceStr := ""
	if !since.IsZero() {
		sinceStr = since.UTC().Format(time.RFC3339)
	}
	if max > 0 {
		// bounded=true: this IS the one place a caller may accept a
		// single page as the whole answer — max is the caller's own
		// explicit "at most this many commits" request, not a watermark
		// range that must be completed (2026-09-22 review finding S2).
		return s.scan(ctx, root, sinceStr, max, true)
	}
	res := Result{ProjectID: root.ProjectID, RootPath: root.RootPath}
	now := s.opts.Now()
	subtree, rev, noCommits, err := s.resolveScanTarget(ctx, root, now)
	if err != nil {
		return res, err
	}
	res.HeadSHA, res.Subtree = rev, subtree
	if noCommits {
		s.finishEmptyScan(ctx, root, now, &res)
		return res, nil
	}
	pageSize := s.opts.MaxPerTick
	var newest []commitlog.Commit
	for skip := 0; ; {
		if err := ctx.Err(); err != nil {
			s.recordFailure(ctx, root.ProjectID, now, err)
			return res, err
		}
		commits, overflow, inserted, usedMax, err := s.scanPage(ctx, root, rev, sinceStr, pageSize, skip, subtree, now)
		if err != nil {
			return res, err
		}
		res.CommitsSeen += len(commits)
		res.Inserted += inserted
		res.Overflow = res.Overflow || overflow
		if skip == 0 {
			newest = commits
		}
		if len(commits) < usedMax {
			break
		}
		skip += usedMax
	}
	s.finishScan(ctx, root, now, newest, subtree, rev, &res)
	return res, nil
}

// scan is the shared core for an INCREMENTAL tick (ScanOnce, bounded
// false) or a caller-bounded page request (FullScan's max>0 branch,
// bounded true): run git log, parse it, sink the commits (recording a
// failure on any error), then revalidate reachability and persist the
// resulting state.
//
// bounded decides when ONE page is allowed to be the whole answer
// (2026-09-22 review finding S2, superseding the review-rework
// "shrunk" version below):
//
//   - bounded=true (FullScan's max>0 branch): the caller explicitly
//     asked for AT MOST `max` commits — not "every commit since
//     `since`" — so a page that fits within `max` without ever hitting
//     the byte cap IS the caller's whole, correct answer, whether or
//     not more commits exist beyond it. This is the ONE place a caller
//     may accept a single page.
//   - bounded=false (an ordinary incremental tick): `max` is only
//     MaxPerTick, a PAGE SIZE, not a promise that the whole range fits
//     in one page — a range with exactly MaxPerTick commits, or more,
//     is completely ordinary. Stopping after one clean, full page here
//     permanently strands every commit older than it: the watermark
//     still advances to that page's newest commit, so the next
//     incremental tick's `--since` starts AFTER the stranded commits
//     and never revisits them. An incremental range is therefore
//     complete only once a SHORT page proves nothing older remains —
//     `scan` keeps paging with `--skip` at the last-used page size
//     regardless of whether any page needed an overflow shrink.
//
// (The round-1-rework version of this function only kept paging past a
// page that needed an overflow SHRINK — the "shrunk" flag — which fixed
// F13's shrink-stranding but left a clean, unshrunk, exactly-full page
// still stopping early; that residual is finding S2.)
func (s *Scanner) scan(ctx context.Context, root Root, since string, max int, bounded bool) (Result, error) {
	res := Result{ProjectID: root.ProjectID, RootPath: root.RootPath}
	now := s.opts.Now()
	subtree, rev, noCommits, err := s.resolveScanTarget(ctx, root, now)
	if err != nil {
		return res, err
	}
	res.HeadSHA, res.Subtree = rev, subtree
	if noCommits {
		s.finishEmptyScan(ctx, root, now, &res)
		return res, nil
	}

	var newest []commitlog.Commit
	pageSize := max
	for skip := 0; ; {
		if err := ctx.Err(); err != nil {
			s.recordFailure(ctx, root.ProjectID, now, err)
			return res, err
		}
		commits, overflow, inserted, usedMax, perr := s.scanPage(ctx, root, rev, since, pageSize, skip, subtree, now)
		if perr != nil {
			return res, perr
		}
		res.CommitsSeen += len(commits)
		res.Inserted += inserted
		res.Overflow = res.Overflow || overflow
		if skip == 0 {
			newest = commits
		}
		if bounded && !overflow {
			// The caller's own single-page contract: it asked for AT
			// MOST `max` commits and got a page that fit without a
			// shrink — that IS the accepted answer.
			break
		}
		if len(commits) < usedMax {
			// This (possibly shrunk) page is shorter than what it asked
			// for — the range in view is exhausted, whether bounded or
			// not.
			break
		}
		skip += usedMax
		pageSize = usedMax
	}
	s.finishScan(ctx, root, now, newest, subtree, rev, &res)
	return res, nil
}

// resolveScanTarget resolves the subtree pathspec and the fixed HEAD sha
// ONCE for one scan call, the ONE shared way scan() and FullScan() both
// need it (2026-09-22 review finding #6): a genuine failure from either
// git invocation is now a recorded scan failure — never a silent
// fallback to the whole repository or to the mutable ref "HEAD" — and
// the one legitimate non-error case, a brand-new repository with no
// commits yet, is reported back as noCommits so the caller can finish
// the scan as a clean, empty, successful pass instead of asking git to
// walk history that does not exist.
func (s *Scanner) resolveScanTarget(ctx context.Context, root Root, now time.Time) (subtree, rev string, noCommits bool, err error) {
	subtree, err = s.resolveSubtree(ctx, root, now)
	if err != nil {
		return "", "", false, err
	}
	rev, noCommits, err = s.resolveHeadSHA(ctx, root, now)
	if err != nil {
		return "", "", false, err
	}
	return subtree, rev, noCommits, nil
}

// resolveHeadSHA resolves HEAD to a concrete commit sha ONCE per scan
// call, through the same Exec seam every other git invocation of that
// scan uses (plan review F16): the log page(s) and the reachability
// rev-list then all walk this SAME fixed sha instead of the mutable ref
// "HEAD", so a rebase, reset, or fast-forward landing mid-scan cannot
// make a later page (or the reachability pass) see a different history
// than the first page already committed to.
//
// `--verify --quiet` (rather than a bare `rev-parse HEAD`) is what makes
// this safe to fail on (2026-09-22 review finding #6 / F16 residue): the
// pre-fix version treated EVERY failure — a transient error, a
// corrupted repository, git itself misbehaving — identically to a
// brand-new repository with no commits yet, silently falling back to
// the MUTABLE ref "HEAD" in both cases. That defeats the whole point of
// pinning one sha: a later page (or the reachability pass) could then
// resolve "HEAD" to a DIFFERENT commit than the first page already
// committed to.
//
// Options.NoCommits (production: gitview.IsNoCommitsError) classifies
// the first probe's failure STRUCTURALLY — exit code + `--quiet`'s
// documented EMPTY diagnostic — never by matching a particular
// diagnostic's wording (2026-09-22 review finding S8, superseding F16's
// message-text match). That structural signal alone is still
// AMBIGUOUS: a detached HEAD pointing at a missing/invalid object fails
// `rev-parse --verify --quiet HEAD` the exact same silent way a
// genuinely unborn repository does. So a NoCommits-classified failure
// only triggers a SECOND, independent ref-state probe before this
// function concludes "no commits yet":
//
//  1. `git symbolic-ref -q HEAD` — does HEAD point at a branch at all
//     (a normal, non-detached checkout)? Its failure means HEAD is
//     detached at something that doesn't resolve, or the ref file
//     itself is malformed — a genuine error, never "healthy empty".
//  2. `git show-ref --verify --quiet <that branch>` — does the branch
//     HEAD points at already have a commit? Its FAILURE is the ONE
//     healthy no-commit state ONLY when that failure is itself the
//     exact same quiet-miss shape probe 1 required — exit 1, empty
//     stderr, reclassified through the SAME Options.NoCommits predicate
//     (2026-09-22 review finding 11: the pre-fix code treated ANY
//     show-ref error, including exit 128 from a corrupt repository or a
//     permission failure, as "no ref yet"). Its SUCCESS would mean the
//     branch DOES have a commit, contradicting probe 1's failure — an
//     inconsistent repository state, a genuine error. Any OTHER failure
//     shape is likewise a genuine error, never a silent "healthy empty".
//
// Every other combination — the first probe not NoCommits-classified,
// or the second/third probe class contradicting a healthy read — is a
// genuine, recorded scan failure that aborts the call instead of
// guessing.
func (s *Scanner) resolveHeadSHA(ctx context.Context, root Root, now time.Time) (sha string, noCommits bool, err error) {
	out, _, execErr := s.opts.Exec(ctx, root.RootPath, 4<<10, "rev-parse", "--verify", "--quiet", "HEAD")
	if execErr == nil {
		return strings.TrimSpace(string(out)), false, nil
	}
	if s.opts.NoCommits == nil || !s.opts.NoCommits(execErr) {
		s.recordFailure(ctx, root.ProjectID, now, execErr)
		return "", false, execErr
	}
	// The rev-parse probe alone cannot distinguish a genuinely unborn
	// repository from a detached/dangling HEAD — the independent
	// ref-state probe decides which one this is.
	branchOut, _, symErr := s.opts.Exec(ctx, root.RootPath, 4<<10, "symbolic-ref", "-q", "HEAD")
	if symErr != nil {
		wrapped := fmt.Errorf("commitscan: HEAD did not resolve and is not a symbolic ref either (dangling or malformed HEAD): %w", symErr)
		s.recordFailure(ctx, root.ProjectID, now, wrapped)
		return "", false, wrapped
	}
	branch := strings.TrimSpace(string(branchOut))
	_, _, refErr := s.opts.Exec(ctx, root.RootPath, 4<<10, "show-ref", "--verify", "--quiet", branch)
	if refErr == nil {
		wrapped := fmt.Errorf("commitscan: HEAD did not resolve but its branch %q already has a ref (inconsistent repository state)", branch)
		s.recordFailure(ctx, root.ProjectID, now, wrapped)
		return "", false, wrapped
	}
	// s.opts.NoCommits is guaranteed non-nil here: the first probe above
	// only reaches this point when it is set AND classified execErr as a
	// quiet miss. Reuse that SAME structural predicate (2026-09-22 review
	// finding 11) rather than accepting any show-ref error as "no ref" —
	// show-ref documents the identical --quiet contract (exit 1, empty
	// stderr) as the rev-parse probe, so the ONE classifier applies to
	// both; a differently-shaped failure (e.g. exit 128 from a corrupt
	// repository or a permission error) is a genuine scan failure.
	if !s.opts.NoCommits(refErr) {
		wrapped := fmt.Errorf("commitscan: show-ref probe for branch %q failed unexpectedly (not a quiet no-ref miss): %w", branch, refErr)
		s.recordFailure(ctx, root.ProjectID, now, wrapped)
		return "", false, wrapped
	}
	// HEAD symbolically points at a branch with no commit yet — the ONE
	// healthy no-commit state (show-ref's exact quiet-miss shape).
	return "", true, nil
}

// resolveSubtree returns the project root's path RELATIVE to its
// repository's toplevel (forward slashes, trailing "/"), or "" when the
// root IS the toplevel or the prefix cannot be determined. A project
// rooted in a subdirectory of a repository (the dashboard's `web/`,
// `marketing/…` and friends are separate projects because sessions
// start there) must not be credited with the whole repository's history:
// its `git log` is limited to that subtree and each numstat path is
// re-based onto the project root so loc.PathHash joins the AI edits the
// watcher hashed relative to the SAME root.
//
// The prefix comes STRAIGHT from git (`rev-parse --show-prefix`, which
// prints the CWD's path relative to the toplevel, forward-slashed, with
// a trailing "/", empty at the toplevel itself) rather than being
// computed on the Go side with filepath.Rel against `--show-toplevel`
// (plan review F14): a symlinked project root resolved `--show-toplevel`
// to the symlink TARGET, so Go's lexical Rel against the (unresolved)
// RootPath produced a "../…" escape and silently fell back to
// whole-repository behaviour; on a case-insensitive filesystem, Rel also
// preserved the STORED root's casing in the remainder while git's own
// `--numstat` paths carry the repository's actual casing, so
// rebaseSubtree's case-sensitive HasPrefix could drop every file. Both
// classes are eliminated by never doing our own path comparison: the
// prefix IS the answer git itself computed for this exact `-C root`
// invocation, in git's own path semantics, every time.
//
// A `--show-prefix` failure is now a recorded scan failure that aborts
// the call, never a silent "" (2026-09-22 review finding #6 / F14
// residue): "" means "the project root IS the toplevel", which would
// scan the WHOLE repository and credit an unrelated sibling
// sub-project's files to this one. `--show-prefix` needs no commits to
// exist (it is pure working-directory structure), so unlike
// resolveHeadSHA there is no legitimate non-error failure case here —
// every failure is genuine.
func (s *Scanner) resolveSubtree(ctx context.Context, root Root, now time.Time) (string, error) {
	out, _, err := s.opts.Exec(ctx, root.RootPath, 4<<10, "rev-parse", "--show-prefix")
	if err != nil {
		s.recordFailure(ctx, root.ProjectID, now, err)
		return "", err
	}
	prefix := strings.TrimSpace(string(out))
	if prefix == "" {
		return "", nil
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return prefix, nil
}

// subtreePathspec is the pathspec that limits a git invocation to the
// project's own subtree. git resolves a pathspec relative to the CWD,
// and every scanner invocation runs with `-C <project root>`, so from
// inside the subdirectory the subtree is simply "." — while `--numstat`
// paths in the output stay TOPLEVEL-relative, which is why rebaseSubtree
// still strips the toplevel-relative prefix. (Passing the prefix itself
// as the pathspec looked for <root>/<prefix>/ and matched nothing —
// caught live 2026-09-22 on this repo's webcloud/ sub-project.)
func subtreePathspec(subtree string) string {
	if subtree == "" {
		return ""
	}
	return "."
}

// rebaseSubtree strips the subtree prefix from every commit file so the
// stored RelPath/PathHash are relative to the PROJECT root. A numstat
// path that does NOT carry the prefix should be impossible under a
// matching pathspec + prefix pair, but silently dropping it if it ever
// happens (a pathspec/prefix mismatch — e.g. the subtree moved between
// the resolveSubtree probe and the log invocation) would corrupt AI-line
// attribution with no trace; it is a recorded scan failure instead
// (plan review F14), never a silent drop.
func rebaseSubtree(commits []commitlog.Commit, subtree string) ([]commitlog.Commit, error) {
	if subtree == "" {
		return commits, nil
	}
	for i := range commits {
		kept := commits[i].Files[:0]
		for _, f := range commits[i].Files {
			if !strings.HasPrefix(f.RelPath, subtree) {
				return nil, fmt.Errorf("commitscan: numstat path %q for commit %s does not carry the subtree prefix %q",
					f.RelPath, commits[i].SHA, subtree)
			}
			f.RelPath = strings.TrimPrefix(f.RelPath, subtree)
			f.PathHash = loc.PathHash("", f.RelPath)
			kept = append(kept, f)
		}
		commits[i].Files = kept
	}
	return commits, nil
}

// scanPage runs one `git log` page (up to max commits from offset skip,
// at the fixed revision rev) and sinks the parsed commits. Every failure
// is recorded against the project before it is returned.
//
// A page whose output overflows the exec seam's byte cap is retried at
// HALF the requested max (down to minPageCommits) rather than parsed and
// accepted as a truncated "success" (plan review F13): commitlog.ParseLog
// would happily drop the trailing partial record and hand back whatever
// fit, but because a page's watermark/skip bookkeeping assumes it saw
// EVERYTHING it asked for, silently accepting a truncated page would
// strand the commits git could not fit — exactly like F12 did. If even
// the floor page size still overflows (a single commit's own numstat
// output exceeds the cap), the page is reported as a hard failure and
// nothing from it is sunk, so the caller never advances the watermark
// past the gap.
//
// usedMax is the page size THIS call actually settled on (== max unless
// an overflow retry shrank it), which the caller needs to advance a
// multi-page walk's `skip` correctly instead of assuming every page was
// the nominal size.
func (s *Scanner) scanPage(ctx context.Context, root Root, rev, since string, max, skip int, subtree string, now time.Time) (commits []commitlog.Commit, overflow bool, inserted, usedMax int, err error) {
	pageMax := max
	for {
		out, of, execErr := s.opts.Exec(ctx, root.RootPath, s.opts.MaxOutputBytes,
			commitlog.PageArgsRev(rev, since, pageMax, skip, subtreePathspec(subtree))...)
		if execErr != nil {
			s.recordFailure(ctx, root.ProjectID, now, execErr)
			return nil, overflow, 0, pageMax, execErr
		}
		if of {
			overflow = true
			if pageMax <= minPageCommits {
				ovErr := fmt.Errorf("commitscan: git log page still overflows %d bytes at the minimum page size (%d commit(s)); raise the byte cap or investigate an oversized single-commit diff",
					s.opts.MaxOutputBytes, pageMax)
				s.recordFailure(ctx, root.ProjectID, now, ovErr)
				return nil, overflow, 0, pageMax, ovErr
			}
			next := pageMax / 2
			if next < minPageCommits {
				next = minPageCommits
			}
			s.warn("commitscan: git log page overflowed the byte cap, retrying at a smaller page size",
				"project_id", root.ProjectID, "from", pageMax, "to", next)
			pageMax = next
			continue
		}
		parsed, perr := commitlog.ParseLog(out, false)
		if perr != nil {
			s.recordFailure(ctx, root.ProjectID, now, perr)
			return nil, overflow, 0, pageMax, perr
		}
		parsed, rerr := rebaseSubtree(parsed, subtree)
		if rerr != nil {
			s.recordFailure(ctx, root.ProjectID, now, rerr)
			return nil, overflow, 0, pageMax, rerr
		}
		ins, serr := s.opts.Sink(ctx, root.ProjectID, parsed, now)
		if serr != nil {
			s.recordFailure(ctx, root.ProjectID, now, serr)
			return nil, overflow, 0, pageMax, serr
		}
		return parsed, overflow, ins, pageMax, nil
	}
}

// finishScan is the shared tail of a successful scan: reachability
// revalidation (best-effort) and the persisted watermark, derived from
// the newest commit among `commits` (the first page of a full scan) or
// carried over from the previous state when nothing new was seen.
func (s *Scanner) finishScan(ctx context.Context, root Root, now time.Time, commits []commitlog.Commit, subtree, rev string, res *Result) {
	// The local identity read (review 2026-09-29 finding 8) is best-effort
	// and runs before the reachability pass, so that pass stays the scan's
	// last invocation.
	localAuthor := s.resolveLocalAuthorHash(ctx, root)

	// Reachability revalidation (plan R2/F3) is best-effort: a failure
	// here never fails the scan that already landed new commits.
	res.Reachability = s.revalidateReachability(ctx, root, now, subtree, rev)

	newState := State{ProjectID: root.ProjectID, LastScanAt: now, LocalAuthorHash: localAuthor}
	if maxSHA, maxAt, ok := newestCommit(commits); ok {
		newState.LastSHA, newState.LastCommittedAt = maxSHA, maxAt
	} else if prev, ok, _ := s.opts.State(ctx, root.ProjectID); ok {
		newState.LastSHA, newState.LastCommittedAt = prev.LastSHA, prev.LastCommittedAt
	}
	if err := s.opts.SetState(ctx, newState); err != nil {
		s.warn("commitscan: persist state failed", "project_id", root.ProjectID, "error", err)
	}
}

// resolveLocalAuthorHash reads the repository's effective identity through
// Options.LocalAuthorName and hashes it with the SAME rule as every stored
// commit's author hash (commitlog.HashAuthorName), so the ownership fold can
// tell a local commit from a teammate's pulled one (review 2026-09-29
// finding 8). Best-effort: no reader, a read error or an unset identity is ""
// = unknown, which keeps the ownership rule's pre-author-check behaviour; it
// never fails the scan. The raw name never leaves this function.
func (s *Scanner) resolveLocalAuthorHash(ctx context.Context, root Root) string {
	if s.opts.LocalAuthorName == nil {
		return ""
	}
	name, err := s.opts.LocalAuthorName(ctx, root.RootPath)
	if err != nil {
		return ""
	}
	return commitlog.HashAuthorName(name)
}

// finishEmptyScan persists a clean, successful "nothing to scan yet"
// state for a call that resolved a brand-new, commit-less repository
// (resolveHeadSHA's noCommits case, 2026-09-22 review finding #6): there
// is no HEAD to run a log page or a reachability rev-list against, so
// unlike finishScan this skips both entirely rather than issuing
// invocations that would themselves fail on the exact same unborn ref.
// The prior watermark (if any) is left untouched — a project can only
// reach this path on its own FIRST scan, since a repository that once
// had commits cannot un-commit its way back to "unborn" — and, like
// every other successful scan, ConsecutiveFailures/LastError reset to
// their zero value.
func (s *Scanner) finishEmptyScan(ctx context.Context, root Root, now time.Time, res *Result) {
	newState := State{ProjectID: root.ProjectID, LastScanAt: now}
	if prev, ok, _ := s.opts.State(ctx, root.ProjectID); ok {
		newState.LastSHA, newState.LastCommittedAt = prev.LastSHA, prev.LastCommittedAt
	}
	if err := s.opts.SetState(ctx, newState); err != nil {
		s.warn("commitscan: persist state failed", "project_id", root.ProjectID, "error", err)
	}
	// res is intentionally left at its zero CommitsSeen/Inserted/Overflow/
	// Reachability values — there was nothing to scan.
}

// revalidateReachability re-derives the set of currently reachable shas
// (from rev — the SAME fixed sha this scan already resolved and used for
// its log page(s), never a freshly re-resolved "HEAD"; plan review F16)
// and hands it to Options.Reachability. Returns the number of reachable
// shas observed, or 0 on any failure (logged, never propagated — plan
// R2/F3 is best-effort).
//
// For a WHOLE-REPOSITORY project the walk stays bounded to the
// LinkWindow + lookback window, same as before. For a SUB-PROJECT
// (subtree != "") it walks the pathspec-scoped history UNBOUNDED instead
// (plan review F15): a sub-project's stored rows can include legacy
// whole-repository commits captured before the pathspec existed, and
// those can be arbitrarily old, so bounding the revalidation to the
// lookback window would leave an old wrongly-scoped row stuck at
// reachable=1 forever — contrary to the "flagged on the next tick"
// operator documentation. A pathspec-scoped rev-list carries no
// --numstat, so walking it unbounded is cheap (no per-commit diff to
// render), unlike the log page(s) it is paired with.
//
// The walk itself is PAGED (`--max-count`/`--skip`, 2026-09-22 review
// finding #7): the pre-fix version discarded Exec's overflow flag and
// handed Options.Reachability whatever byte-capped, possibly-truncated
// line list it got. Every stored sha that git WOULD have reported past
// that silent cut was then flagged reachable=0 by the caller (a stored
// sha absent from the set is presumed gone), destroying valid
// attribution for commits that are actually still perfectly reachable.
// A page that itself overflows is retried at half the sha count (down to
// a floor) exactly like scanPage's commit-log retry, so the full
// reachable set is always assembled before Options.Reachability ever
// sees it; a page's own overflow retry never mutates the accumulated
// set.
func (s *Scanner) revalidateReachability(ctx context.Context, root Root, now time.Time, subtree, rev string) int {
	if rev == "" {
		rev = "HEAD"
	}
	since := now.Add(-(s.opts.LinkWindow + reachabilityLookback))
	unbounded := subtree != ""
	if unbounded {
		// Unbounded for a sub-project (see doc comment above): `since`
		// zero tells store.MarkCommitsReachability to check EVERY stored
		// row for this project, not just the ones inside the lookback
		// window.
		since = time.Time{}
	}
	pathspec := subtreePathspec(subtree)

	reachable := map[string]bool{}
	pageSize := reachabilityPageShas
	for skip := 0; ; {
		args := []string{"rev-list", rev}
		if !unbounded {
			args = append(args, "--since="+since.UTC().Format(time.RFC3339))
		}
		args = append(args, "--max-count="+strconv.Itoa(pageSize))
		if skip > 0 {
			args = append(args, "--skip="+strconv.Itoa(skip))
		}
		args = append(args, "--")
		if pathspec != "" {
			args = append(args, pathspec)
		}
		out, overflow, err := s.opts.Exec(ctx, root.RootPath, s.opts.MaxOutputBytes, args...)
		if err != nil {
			s.warn("commitscan: reachability rev-list failed", "project_id", root.ProjectID, "error", err)
			return 0
		}
		if overflow {
			if pageSize <= minReachabilityPageShas {
				s.warn("commitscan: reachability rev-list page still overflows the byte cap at the minimum page size; skipping this revalidation pass without mutating reachability",
					"project_id", root.ProjectID, "page_shas", pageSize)
				return 0
			}
			next := pageSize / 2
			if next < minReachabilityPageShas {
				next = minReachabilityPageShas
			}
			s.warn("commitscan: reachability rev-list page overflowed the byte cap, retrying at a smaller page size",
				"project_id", root.ProjectID, "from", pageSize, "to", next)
			pageSize = next
			continue // retry the SAME skip offset at the smaller page size
		}
		var lines int
		for _, line := range strings.Split(string(out), "\n") {
			sha := strings.TrimSpace(line)
			if sha != "" {
				reachable[sha] = true
				lines++
			}
		}
		if lines < pageSize {
			break
		}
		skip += pageSize
	}

	if err := s.opts.Reachability(ctx, root.ProjectID, reachable, since); err != nil {
		s.warn("commitscan: reachability update failed", "project_id", root.ProjectID, "error", err)
		return 0
	}
	return len(reachable)
}

// recordFailure persists the failure onto the project's durable state,
// incrementing ConsecutiveFailures for the backoff computation. When
// Options.Unavailable classifies err as "git itself is missing", LastError
// carries the fixed gitNotFoundError marker instead of err's own message
// (internal/store.CommitCaptureState matches on that exact substring).
//
// A NotRepo-classified failure is still recorded (the project's capture
// state honestly reads "error" with git's own message), but its failure
// count is pinned at 1 rather than incremented: the in-memory
// NotRepoRecheck skip governs how often such a root is re-probed, and an
// ever-growing backoff would otherwise delay picking up a later `git init`.
func (s *Scanner) recordFailure(ctx context.Context, projectID int64, now time.Time, err error) {
	prev, _, _ := s.opts.State(ctx, projectID)
	msg := err.Error()
	if s.opts.Unavailable != nil && s.opts.Unavailable(err) {
		msg = gitNotFoundError
	}
	failures := prev.ConsecutiveFailures + 1
	if s.isNotRepo(err) {
		failures = 1
	}
	next := State{
		ProjectID:           projectID,
		LastSHA:             prev.LastSHA,
		LastCommittedAt:     prev.LastCommittedAt,
		LastScanAt:          now,
		LastError:           msg,
		ConsecutiveFailures: failures,
	}
	if serr := s.opts.SetState(ctx, next); serr != nil {
		s.warn("commitscan: persist failure state failed", "project_id", projectID, "error", serr)
	}
}

// isNotRepo reports whether Options.NotRepo classifies err as "root is not
// inside a git repository"; false when NotRepo is unset.
func (s *Scanner) isNotRepo(err error) bool {
	return err != nil && s.opts.NotRepo != nil && s.opts.NotRepo(err)
}

// newestCommit returns the sha/committed-at of the commit with the latest
// CommittedAt in commits. `git log --date-order` normally yields this as
// commits[0], but this is computed explicitly rather than assumed.
func newestCommit(commits []commitlog.Commit) (sha string, at time.Time, ok bool) {
	for _, c := range commits {
		if !ok || c.CommittedAt.After(at) {
			sha, at, ok = c.SHA, c.CommittedAt, true
		}
	}
	return sha, at, ok
}
