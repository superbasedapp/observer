// terminal_discover.go — the daemon's generic, tool-agnostic terminal-run
// discovery sweep (Session Cockpit correlation, part C / the core).
//
// Honesty posture. Only two launchers correlate a dashboard-launched terminal
// run to its observer session today: claude-code via a KNOWN-id OOB echo
// (SourceOOB, 0.95) and codex via a post-launch rollout-diff scan
// (SourceDiscovered, 0.75). Every OTHER launcher (opencode, gemini, cline-cli,
// …) never links — its Session Cockpit waits forever. This periodic sweep closes
// that gap generically: it links a LIVE, still-uncorrelated run to a UNIQUE
// candidate observer session by project + time + tool agreement, recorded as
// termrun.SourceDiscovered (0.75) through the SAME termsvc.Service.Correlate
// seam the codex launcher uses.
//
// It is unique-or-abstain, never a guess. A run is linked ONLY when it has
// EXACTLY one candidate session AND that session is the candidate of EXACTLY one
// run this tick, and only after the same unique pair survives dwellTicks
// CONSECUTIVE ticks. Any ambiguity — two candidates for a run, one session
// shared by two runs, a candidate set that changes between ticks — abstains and
// the run honestly stays uncorrelated. The wrong-pair risk that remains (two
// genuinely-concurrent same-project runs whose sessions never overlap as
// candidates) is accepted and bounded by four independent guards: the store's
// tool + git-root + time-window candidate filter, the exclude-source-session
// rule, the dwell requirement, and the not-yet-linked precondition (the sweep
// only ever touches runs the store still reports as uncorrelated, so a stronger
// OOB link always wins and is never downgraded — 0.75 sits below OOB's 0.95 but
// above MinLinkConfidence, so a discovered link still attaches downstream links
// until upgraded). This is why the confidence is 0.75, not 0.95: the id rests on
// a project/time/uniqueness inference, not a forced or echoed id.
package main

import (
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// terminalDiscoverConfig tunes the discovery sweep. Injectable so tests can use
// tiny counts/intervals.
type terminalDiscoverConfig struct {
	// interval is the sweep cadence (production: 10s).
	interval time.Duration
	// skew widens the candidate time window backwards: a session that started up
	// to skew BEFORE the run's launched_at still counts, absorbing coarse clock
	// granularity and the small ordering gap between a launch stamp and the
	// tool's own session-start write (production: 5s).
	skew time.Duration
	// dwellTicks is how many CONSECUTIVE ticks the SAME unique (run,session) pair
	// must be observed before it is linked. Requiring persistence rejects a pair
	// that was only momentarily unique — e.g. a second concurrent run whose
	// session had not yet surfaced as a candidate on the first tick (production:
	// 2).
	dwellTicks int
	// runLimit bounds how many live uncorrelated runs a tick inspects
	// (production: 64).
	runLimit int
	// candLimit bounds how many candidate sessions the store returns per run
	// (production: 8). A run with more candidates than this is inherently
	// ambiguous and abstains anyway, so the cap only bounds work.
	candLimit int
	// window is the FORWARD ceiling on the candidate time window: a session is a
	// candidate only if it started at or before launched_at + window. It exists to
	// stop a stale, long-idle uncorrelated run from being claimed by an unrelated
	// bare-launch session hours later — but that is a SECONDARY guard, not the
	// primary one: the primary correctness guarantees are the mandatory
	// tool+project-root match, the unique-or-abstain pairing (step 3), and the
	// dwellTicks persistence requirement, all of which hold regardless of how wide
	// this ceiling is. Widened from 30m to 2h (2026-09-02): a lazily-session-
	// creating CLI/TUI tool (declares adapter.CursorWatermark/CursorEncrypted, so
	// it is excluded from the fast post-launch discovery path in
	// terminal_discover_generic.go and depends on THIS sweep exclusively) may not
	// write its first session row until the operator's first real message — e.g.
	// opencode, whose Session Cockpit was observed live waiting 48+ minutes past
	// launch before the tool wrote anything, well past the old 30m ceiling, with
	// no way to ever recover once past it (production: 2h).
	window time.Duration
}

// defaultTerminalDiscoverConfig is the production timing: sweep every 10s, open
// the candidate window 5s before launch, require the same unique pair on 2
// consecutive ticks, bound the per-tick fan-out to 64 runs × 8 candidates, and
// give a launch up to 2h to produce its first session record before the
// forward ceiling permanently closes the run's correlation opportunity.
func defaultTerminalDiscoverConfig() terminalDiscoverConfig {
	return terminalDiscoverConfig{
		interval:   10 * time.Second,
		skew:       5 * time.Second,
		dwellTicks: 2,
		runLimit:   64,
		candLimit:  8,
		window:     2 * time.Hour,
	}
}

// terminalDiscoverStore is the narrow store seam the sweep reads (fake-able in
// tests). It is exactly the two discovery queries — nothing else of *store.Store
// leaks in — so the sweep's dependency on storage is one injected interface.
type terminalDiscoverStore interface {
	CapturedSessionForTool(ctx context.Context, sessionID, tool string) (bool, error)
	LiveRunForSession(ctx context.Context, sessionID string, minConfidence float64) (bool, error)
	// ListLiveUncorrelatedRuns returns the live terminal runs that carry NO
	// correlation at or above minConfidence yet (the sweep's candidates for
	// linking).
	ListLiveUncorrelatedRuns(ctx context.Context, minConfidence float64, limit int) ([]store.UncorrelatedTerminalRun, error)
	// CandidateSessionsForTerminalRun returns the observer sessions that could be
	// the run's, filtered by tool + git root + a start time within the window
	// [after, until], excluding the run's own source session (a handoff/resume
	// predecessor is never a correlation target).
	CandidateSessionsForTerminalRun(ctx context.Context, tool, gitRoot, rawDir string, after, until time.Time, excludeSessionID string, minConfidence float64, limit int) ([]store.DiscoveryCandidateSession, error)
	// ProjectRootForSession resolves a session id to its stored
	// projects.root_path (the raw stored spelling), returning "" without error
	// when the session is unknown or carries no project. The handoff fallback
	// uses it to recover a handoff run's project root from its SOURCE session —
	// termsvc.LaunchHandoff records no launch Dir, so ProjectRoot misses, but a
	// handoff continues the same project as its source (see tick step 2).
	ProjectRootForSession(ctx context.Context, sessionID string) (string, error)
	// SessionLinkedToAnyRun reports whether the store already holds a run
	// correlated to sessionID at or above minConfidence. The pre-correlate
	// revalidation consults it at the link moment (tick step 4) to close the
	// SESSION-side of the candidate-set staleness race: a candidate list captured
	// at the tick's opening query can go stale if an OOB echo links the session to
	// a DIFFERENT run mid-tick, so a last-instant recheck mirrors the candidate
	// query's own NOT-EXISTS filter and stops the sweep linking a session another
	// run just claimed.
	SessionLinkedToAnyRun(ctx context.Context, sessionID string, minConfidence float64) (bool, error)
}

// pendingDiscovery is the per-run dwell state: the unique candidate session most
// recently observed for the run, and how many CONSECUTIVE ticks that same pair
// has held. A change in sessionID resets streak to 1; the run dropping out of
// the unique-pair set entirely drops the entry.
type pendingDiscovery struct {
	sessionID string
	streak    int
}

// terminalDiscoverer is the daemon-resident discovery sweep. All I/O is injected
// (the store seam plus function seams over termsvc.Service), so the loop is
// unit-testable with fakes and never imports the concrete service.
type terminalDiscoverer struct {
	// nativeSession resolves a primary rollout writer under the live terminal's
	// process tree. Nil means this discovery mechanism is not wired.
	nativeSession func(context.Context, string) (terminalNativeIdentity, error)
	st            terminalDiscoverStore
	// handleForRun resolves a run id to its LIVE PTY handle (prod:
	// svc.HandleForRun). It is the in-memory liveness truth: a stale crash-orphan
	// row from a previous daemon boot has no live handle, misses here, and is
	// skipped — the sweep only ever links runs THIS daemon is running.
	handleForRun func(runID string) (string, bool)
	// sessionLinkForRun reports the observer session a run has ALREADY been
	// correlated to and at what confidence (prod: svc.SessionLinkForRun). ok=true
	// only once a link ≥ termrun.MinLinkConfidence is established. The sweep
	// re-checks it at the link moment so a run a stronger/earlier source (OOB /
	// rollout discovery) correlated mid-dwell is never given a second, possibly
	// different, pair (pre-correlate revalidation, tick step 4).
	sessionLinkForRun func(runID string) (sessionID string, confidence float64, ok bool)
	// runDir resolves a live handle to the directory its child process actually
	// runs in (prod: svc.SpawnDir): the validated launch root when the launch
	// carried one, otherwise the daemon's own cwd, which the child inherits.
	//
	// It is deliberately NOT svc.ProjectRoot. ProjectRoot answers an
	// AUTHORIZATION question ("what may the Files/Git panel browse?") and is
	// empty for a launch with no requested project root — which every dashboard
	// "New Terminal" is on a node with no [terminal.launch].allowed_project_roots
	// configured. Keying correlation off that answer made this sweep skip such
	// runs forever, so their Session Cockpit sat at "linking…" for the whole
	// window even though the child's cwd and the session's project root were
	// both known and equal. Correlation asks a FACT question, so it reads the
	// factual seam; ok=false now means only an unknown handle or an unreadable
	// daemon cwd.
	runDir func(handle string) (string, bool)
	// correlate records the scored run→session link (prod: svc.Correlate). The
	// sweep always calls it with termrun.SourceDiscovered.
	correlate func(ctx context.Context, runID, sessionID string, source termrun.Source, at time.Time) error
	// resolveGitRoot maps a launch dir to its git worktree root (prod: memoized
	// git.Resolve(dir).Root; tests: identity). The per-dir memo lives in
	// rootCache, so this may be the raw resolver.
	resolveGitRoot func(dir string) string
	// now is the clock (prod: time.Now). The link timestamp is now().UTC().
	now    func() time.Time
	logger *slog.Logger
	cfg    terminalDiscoverConfig
	// pending is the dwell state, keyed by run id. Owned here; mutated only from
	// tick (the loop is single-goroutine, so no lock is needed).
	//
	// Uniform soundness invariant: pending dwell state survives ONLY a fully-sound
	// tick in which the pair was re-observed as globally unique. ANY unsound tick
	// clears ALL of it — a run-list error, a runLimit/candLimit cap hit, or a
	// TRANSIENT per-run resolution failure (candidate query error or handoff
	// source-root lookup error). The reason is uniform: two observations separated
	// by an unsound tick are not "consecutive" in any meaningful sense, because
	// the ambiguity a sound tick would have caught went unseen during the outage.
	pending map[string]pendingDiscovery
	// rootCache memoizes dir→git-root across ticks (a dir's git root is stable),
	// so resolveGitRoot runs at most once per distinct dir. Owned here.
	rootCache map[string]string
}

// newTerminalDiscoverer builds a discoverer from its injected seams. A nil
// logger is replaced with a discard logger so the loop never dereferences nil.
func newTerminalDiscoverer(
	st terminalDiscoverStore,
	handleForRun func(runID string) (string, bool),
	nativeSession func(context.Context, string) (terminalNativeIdentity, error),
	sessionLinkForRun func(runID string) (sessionID string, confidence float64, ok bool),
	runDir func(handle string) (string, bool),
	correlate func(ctx context.Context, runID, sessionID string, source termrun.Source, at time.Time) error,
	resolveGitRoot func(dir string) string,
	now func() time.Time,
	logger *slog.Logger,
	cfg terminalDiscoverConfig,
) *terminalDiscoverer {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if now == nil {
		now = time.Now
	}
	return &terminalDiscoverer{
		st:                st,
		nativeSession:     nativeSession,
		handleForRun:      handleForRun,
		sessionLinkForRun: sessionLinkForRun,
		runDir:            runDir,
		correlate:         correlate,
		resolveGitRoot:    resolveGitRoot,
		now:               now,
		logger:            logger,
		cfg:               cfg,
		pending:           make(map[string]pendingDiscovery),
		rootCache:         make(map[string]string),
	}
}

// run is the ticker loop (processobs sweep precedent). It sweeps every
// cfg.interval and returns on ctx cancellation — the shared teardown cancels the
// context BEFORE the DB closes, so no in-flight tick can race the close.
func (d *terminalDiscoverer) run(ctx context.Context) {
	t := time.NewTicker(d.cfg.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.tick(ctx)
		}
	}
}

// tick runs ONE discovery pass and returns the number of links it made
// (separated from run for direct testing). It is best-effort throughout: one
// run's failure never aborts the tick, and per-tick activity is logged at DEBUG
// (only a rare LINK is INFO).
func (d *terminalDiscoverer) tick(ctx context.Context) int {
	// 1. The live uncorrelated runs. A store error is an UNSOUND tick: dwell state
	// must not survive it, or two observations separated by a failed tick would
	// count as "consecutive" and the ambiguity present during the outage would go
	// unseen. Clear ALL pending and return (uniform soundness invariant on the
	// pending field). No live runs also clears ALL pending and never touches the
	// sessions query.
	runs, err := d.st.ListLiveUncorrelatedRuns(ctx, termrun.MinLinkConfidence, d.cfg.runLimit)
	if err != nil {
		d.logger.Debug("terminal discovery: list live uncorrelated runs failed — abstaining this tick and clearing dwell", "err", err)
		if len(d.pending) > 0 {
			d.pending = make(map[string]pendingDiscovery)
		}
		return 0
	}
	if len(runs) == 0 {
		if len(d.pending) > 0 {
			d.pending = make(map[string]pendingDiscovery)
		}
		return 0
	}
	// Soundness before work: the run list may be TRUNCATED at runLimit, hiding
	// live uncorrelated runs from the cross-run uniqueness check in step 3. A
	// hidden run could share a candidate session and make an "exclusive" pair a
	// mistake (e.g. R1's only candidate S looks exclusive, but a hidden R2 also
	// has S). When the list is at the cap, abstain tick-wide — clear ALL pending
	// and make no links. 64 concurrent uncorrelated terminals is pathological;
	// one tick of latency in a state where linking would be guesswork anyway is
	// the honest cost. The caps are therefore pure WORK bounds, never a
	// correctness shortcut.
	if len(runs) >= d.cfg.runLimit {
		d.logger.Debug("terminal discovery: live uncorrelated run list at cap — abstaining this tick (possible truncation would invalidate the uniqueness proof)",
			"runs", len(runs), "runLimit", d.cfg.runLimit)
		if len(d.pending) > 0 {
			d.pending = make(map[string]pendingDiscovery)
		}
		return 0
	}

	// Native adapter identity survives delayed first records and simultaneous
	// same-project terminals. Withhold supported runs from timing inference.
	nativeLinks, runs := d.discoverNativeSessions(ctx, runs)

	// 2. For each run, resolve its live handle → launch dir → git root, then ask
	// the store for candidate sessions. Two failure classes are treated
	// DIFFERENTLY:
	//   • STRUCTURAL skips (permanent states) drop only the affected run and are
	//     treated as ABSENT for dwell (pending dropped in step 4 like any run not
	//     producing a pair): a handleForRun miss (run ended — it also leaves the
	//     store list next tick), a runDir miss on a NON-handoff run (an unknown
	//     handle, or a daemon whose own cwd is unreadable — a launch with no
	//     requested project root is NOT such a miss: its child inherits the
	//     daemon cwd, which svc.SpawnDir reports), and a handoff source root that
	//     resolves to EMPTY with a nil error (source session unknown to the
	//     corpus). RESIDUAL, accepted honestly: a structurally dir-less LIVE run is
	//     invisible to the cross-run uniqueness check in step 3, so its child
	//     sessions remain claimable by OTHER runs — the same accepted-residual
	//     class as a bare (non-run) launch. A tick-wide abstain on these permanent
	//     states would disable the sweep for as long as such a run lives, so they
	//     stay per-run.
	//   • TRANSIENT failures (a candidate query error, or the handoff source-root
	//     lookup error above) make the WHOLE tick unsound — an unresolved run is
	//     hidden from the uniqueness check, so a competitor it would contest goes
	//     unseen and another run can look falsely exclusive. These abstain
	//     TICK-WIDE (clear ALL pending, return nativeLinks), the same shape as the cap
	//     abstains.
	cands := make(map[string][]string, len(runs))
	for _, run := range runs {
		handle, ok := d.handleForRun(run.RunID)
		if !ok {
			continue // no live handle: a stale/ended run this daemon isn't running
		}
		// Resolve the (gitRoot, rawDir) the candidate query filters on. Two paths:
		//   • launch dir known → resolve its git root (memoized) + use the raw dir;
		//   • launch dir MISSING but this is a handoff → recover the root from the
		//     SOURCE session (below).
		var gitRoot, rawDir string
		if dir, dok := d.runDir(handle); dok {
			gitRoot = d.resolveRoot(dir)
			rawDir = dir
		} else if run.Kind == string(termrun.KindHandoff) && run.SourceSessionID != "" {
			// Handoff fallback: termsvc.LaunchHandoff records NO launch Dir, so
			// ProjectRoot misses — yet a handoff CONTINUES the same project as its
			// source session, so the target's project root == the source session's
			// project root. Recover it from the stored projects.root_path row (the
			// SAME corpus CandidateSessionsForTerminalRun filters on) and use it as
			// BOTH gitRoot and rawDir with NO git.Resolve and NO rootCache: the value
			// already carries the exact stored spelling the query matches — which
			// also makes a cross-OS handoff work, since both sides are the identical
			// stored spelling. The sweep's SourceSessionID exclusion (passed below)
			// still guards the source session itself from ever becoming this run's
			// correlation target.
			root, rerr := d.st.ProjectRootForSession(ctx, run.SourceSessionID)
			if rerr != nil {
				// TRANSIENT failure: the handoff source-root lookup ERRORED. Like a
				// candidate-query error below, this makes the whole tick unsound — a
				// run we cannot resolve is invisible to the cross-run uniqueness check
				// in step 3, so a competitor it would have contested stays hidden and
				// another run could look falsely exclusive. Abstain tick-wide: clear
				// ALL pending and make no links (same shape as the cap abstains).
				d.logger.Debug("terminal discovery: source-session project root lookup failed — abstaining this tick (an unresolved run could hide a competitor from the uniqueness check)",
					"run", run.RunID, "source", run.SourceSessionID, "err", rerr)
				if len(d.pending) > 0 {
					d.pending = make(map[string]pendingDiscovery)
				}
				return nativeLinks
			}
			if root == "" {
				// STRUCTURAL skip (permanent state, nil error): the source session is
				// unknown to the corpus / carries no project. This is a stable "no
				// browsable root" condition, not a transient failure — skip only THIS
				// run (a tick-wide abstain on it would disable the sweep for as long as
				// such a run lives). Its child session is left claimable by other runs,
				// the same accepted residual as a structurally dir-less launch.
				d.logger.Debug("terminal discovery: source session has no stored project root — skipping handoff run",
					"run", run.RunID, "source", run.SourceSessionID)
				continue
			}
			gitRoot = root
			rawDir = root
		} else {
			// No working directory for this run at all (unknown handle, or an
			// unreadable daemon cwd) and no handoff source to recover one from.
			// Nothing to filter candidates on, so abstain for this run.
			continue
		}
		tool := canonicalToolForRun(run.Tool)
		after := run.LaunchedAt.Add(-d.cfg.skew)
		until := run.LaunchedAt.Add(d.cfg.window)
		if d.now().After(until) {
			// STRUCTURAL skip (permanent for this run): the forward window has fully
			// closed — a legit daemon-launched session begins within launch +
			// tool-startup + ingest lag, so once now() is past launched_at + window
			// no session can ever be an eligible candidate for this run. The
			// candidate query would only return sessions the ceiling excludes, so
			// skip it entirely rather than pay the round-trip. Skip only THIS run
			// (not a tick-wide abstain): a permanently-unlinkable run must not hide a
			// live competitor from the step-3 uniqueness check, and it contests
			// nothing itself.
			continue
		}
		sessions, cerr := d.st.CandidateSessionsForTerminalRun(
			ctx, tool, gitRoot, rawDir, after, until, run.SourceSessionID, termrun.MinLinkConfidence, d.cfg.candLimit,
		)
		if cerr != nil {
			// TRANSIENT failure: this run's candidate list is unresolved, so it is
			// hidden from the cross-run uniqueness check in step 3 — a competitor it
			// would contest goes unseen and another run could look falsely exclusive.
			// Abstain tick-wide (clear ALL pending, no links), the same shape as the
			// cap abstains.
			d.logger.Debug("terminal discovery: candidate sessions query failed — abstaining this tick (an unresolved run could hide a competitor from the uniqueness check)",
				"run", run.RunID, "err", cerr)
			if len(d.pending) > 0 {
				d.pending = make(map[string]pendingDiscovery)
			}
			return nativeLinks
		}
		ids := make([]string, 0, len(sessions))
		for _, s := range sessions {
			ids = append(ids, s.SessionID)
		}
		cands[run.RunID] = ids
	}

	// Soundness before work (companion to the runLimit cap above): if ANY run's
	// candidate list is at candLimit, the store may have TRUNCATED hidden
	// candidates for it — and a hidden candidate can make a DIFFERENT run's single
	// candidate look exclusive when it is not. Abstain tick-wide rather than risk
	// a wrong exclusive link. 8+ fresh same-tool-same-project sessions in one
	// window is pathological; honest abstention costs a tick of latency in a state
	// where linking would be guesswork anyway.
	for runID, ids := range cands {
		if len(ids) >= d.cfg.candLimit {
			d.logger.Debug("terminal discovery: a run's candidate list is at cap — abstaining this tick (hidden candidates can invalidate cross-run exclusivity)",
				"run", runID, "candidates", len(ids), "candLimit", d.cfg.candLimit)
			if len(d.pending) > 0 {
				d.pending = make(map[string]pendingDiscovery)
			}
			return nativeLinks
		}
	}

	// 3. Reduce to the mutually-unique pairs (run has exactly one candidate AND
	// that session is the candidate of exactly one run). Everything else abstains.
	pairs := uniqueRunSessionPairs(cands)

	// 4. Dwell + link. Drop pending for every run absent from the unique-pair set
	// this tick (absent, ambiguous, ended, or already linked).
	for runID := range d.pending {
		if _, ok := pairs[runID]; !ok {
			delete(d.pending, runID)
		}
	}
	links := nativeLinks
	for runID, sessionID := range pairs {
		p, ok := d.pending[runID]
		if ok && p.sessionID == sessionID {
			p.streak++
		} else {
			p = pendingDiscovery{sessionID: sessionID, streak: 1}
		}
		d.pending[runID] = p
		if p.streak < d.cfg.dwellTicks {
			continue
		}
		// Pre-correlate revalidation (see linkBlockedByRevalidation): re-check the
		// run side AND the session side at the link moment; a blocked link drops the
		// pending entry inside the helper.
		if d.linkBlockedByRevalidation(ctx, runID, sessionID) {
			continue
		}
		// The pair has held for the full dwell — link it at SourceDiscovered.
		if cerr := d.correlate(ctx, runID, sessionID, termrun.SourceDiscovered, d.now().UTC()); cerr != nil {
			// Keep the pending entry and retry next tick (the pair is still unique
			// and will re-dwell; a transient correlate failure never abandons it).
			d.logger.Debug("terminal discovery: correlate failed — will retry next tick",
				"run", runID, "session", sessionID, "err", cerr)
			continue
		}
		delete(d.pending, runID)
		links++
		d.logger.Info("terminal discovery: linked run to session (project+time uniqueness)",
			"run", runID, "session", sessionID, "source", string(termrun.SourceDiscovered))
	}
	return links
}

// linkBlockedByRevalidation re-checks, at the link moment, the three truths that
// may have changed since this tick's opening store query — the run side (a, b)
// and the SESSION side (c) — and reports whether the link must be abandoned. On
// ANY block it DROPS the run's pending entry (so it re-dwells cleanly if the pair
// re-emerges) and logs at DEBUG. termsvc.Service.Correlate persists BEFORE its
// in-memory liveness check, so linking a stale pair could write a link for a
// just-ended run, a SECOND (possibly different) pair for a run a real source
// already claimed, or a link to a session another run just took. The three
// checks:
//   - (a) handleForRun gone ⇒ the run ended mid-dwell.
//   - (b) sessionLinkForRun established ⇒ a stronger/earlier source won mid-dwell
//     — the sweep must not add a second pair.
//   - (c) SessionLinkedToAnyRun ⇒ the candidate set went stale w.r.t. the session
//     side: an OOB echo linked this session to another run AFTER this tick's
//     candidate query (whose NOT-EXISTS filter would have excluded it). Re-run
//     that filter at the last instant — on error do NOT link, on claimed do NOT
//     link — shrinking the session-side race to the same µs residual as the run
//     side.
//
// Residual: a microseconds-scale TOCTOU remains between these rechecks and
// Correlate's own write. It is now SYMMETRIC — both the run side AND the session
// side are re-checked at link time. A lost µs race leaves two runs pointing at
// ONE session, where readers resolve the strongest row and the next OOB upgrade
// corrects the cockpit — never a downgraded or destroyed link (the store upsert
// MAX-upgrades per (run,session) pair and the in-memory map only replaces on
// STRICTLY stronger confidence).
func (d *terminalDiscoverer) linkBlockedByRevalidation(ctx context.Context, runID, sessionID string) bool {
	if _, live := d.handleForRun(runID); !live {
		delete(d.pending, runID)
		d.logger.Debug("terminal discovery: run ended between tick start and link — skipping", "run", runID)
		return true
	}
	if _, _, linked := d.sessionLinkForRun(runID); linked {
		delete(d.pending, runID)
		d.logger.Debug("terminal discovery: run already linked by a stronger source mid-dwell — skipping",
			"run", runID, "session", sessionID)
		return true
	}
	claimed, serr := d.st.SessionLinkedToAnyRun(ctx, sessionID, termrun.MinLinkConfidence)
	if serr != nil {
		delete(d.pending, runID)
		d.logger.Debug("terminal discovery: session-link recheck failed — dropping pending, not linking",
			"run", runID, "session", sessionID, "err", serr)
		return true
	}
	if claimed {
		delete(d.pending, runID)
		d.logger.Debug("terminal discovery: session already linked to another run mid-dwell — skipping",
			"run", runID, "session", sessionID)
		return true
	}
	return false
}

// resolveRoot returns the memoized git root for a launch dir, resolving it at
// most once per distinct dir across the sweep's lifetime (a dir's git root does
// not change). The memo is the sweep's own map, so resolveGitRoot may be the raw
// resolver.
func (d *terminalDiscoverer) resolveRoot(dir string) string {
	if r, ok := d.rootCache[dir]; ok {
		return r
	}
	r := d.resolveGitRoot(dir)
	d.rootCache[dir] = r
	return r
}

// uniqueRunSessionPairs returns runID->sessionID for exactly the pairs where the
// run has EXACTLY one (distinct) candidate AND that session appears as a
// candidate of EXACTLY one run this tick. Everything else abstains — this is the
// unique-or-abstain rule that keeps the sweep from ever guessing between two
// plausible sessions or attributing one session to two runs. Pure (no I/O), so
// the abstention policy is unit-tested directly.
func uniqueRunSessionPairs(cands map[string][]string) map[string]string {
	// sessionRuns counts how many DISTINCT runs list each session as a candidate.
	sessionRuns := make(map[string]int)
	for _, sessions := range cands {
		for _, sid := range distinctStrings(sessions) {
			sessionRuns[sid]++
		}
	}
	out := make(map[string]string)
	for runID, sessions := range cands {
		distinct := distinctStrings(sessions)
		if len(distinct) != 1 {
			continue // zero or ≥2 candidates for this run → abstain
		}
		sid := distinct[0]
		if sessionRuns[sid] == 1 {
			out[runID] = sid // the session is this run's alone → the unique pair
		}
	}
	return out
}

// distinctStrings returns the distinct non-empty entries of s, preserving order.
// De-duping within a single run's candidate list keeps a (defensive) duplicated
// session id from inflating either the per-run count or the cross-run count.
func distinctStrings(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(s))
	out := make([]string, 0, len(s))
	for _, v := range s {
		if v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// canonicalToolForRun maps a terminal_run tool label to the sessions.tool
// spelling the candidate query filters on. A registry tool key passes through
// unchanged; a dashboard-handoff launcher verb ("claude") reverse-maps to its
// canonical tool key ("claude-code") via the integration registry; an unknown
// label passes through unchanged (no sessions will match it — the run honestly
// stays unlinked rather than mis-linking). Pure — the registry is a static data
// table.
func canonicalToolForRun(runTool string) string {
	if _, ok := integration.For(runTool); ok {
		return runTool
	}
	if t, ok := integration.ToolForLaunchSubcommand(runTool); ok {
		return t
	}
	return runTool
}
