package processobs

import (
	"sort"
	"strings"
	"time"
)

// Launch-seed matching (migration 086). A launcher records its child pid at
// spawn (the only moment it is knowable); the daemon's correlation sweep
// consumes the seed once the watcher has ingested a REAL session for that
// tool. This file is the pure pairing rule — no SQL, no I/O — so it stays
// pinned inside the processobs pure-logic boundary by imports_test.go.
//
// The bridge row this match produces is authoritative HIGH-confidence
// identity (every pidbridge reader treats it so), so the rule is deliberately
// CONSERVATIVE: exact tool, exact cwd, and a bounded start window, with an
// INJECTIVE pairing so two simultaneous launches in the same project can
// never cross-attribute.

// LaunchSeedBackSkew tolerates a seed recorded BEFORE its session row's
// started_at. The session timestamp comes from the tool's own first logged
// event, which can land after the process spawn (same shape as
// crossOSBackSkew's launch-to-first-prompt gap). Sized to match
// CrossOSWindow so the anchor window is symmetric.
const LaunchSeedBackSkew = 2 * time.Minute

// LaunchSeedForwardWindow bounds how long after a spawn a session may start
// and still match: a tool opened to an idle prompt creates its session only
// on first activity. Past this window a seed can no longer be matched
// reliably (another launch in the same project is likelier) and the sweep
// expires it instead.
const LaunchSeedForwardWindow = 15 * time.Minute

// LaunchSeed is one pending launcher-recorded child process (a pending
// launch_seeds row).
type LaunchSeed struct {
	PID       int
	Tool      string
	CWD       string
	StartedAt time.Time
	// RunID binds this seed to the terminal run the daemon minted BEFORE
	// spawning the launcher (migration 091). It is the deterministic half of
	// the pairing: with it, the seed's session is a JOIN through
	// terminal_run_session rather than an inference from cwd + tool + time.
	//
	// EMPTY IS THE HONEST NORMAL for every launch the daemon did not spawn —
	// a bare `observer codex` in the operator's own shell has no run, and the
	// heuristic below is the only rule that can serve it. A seed is never
	// given a fabricated run id to make the join fire.
	RunID string
}

// MatchLaunchSeeds pairs seeds to sessions and returns {pid → session_id}.
//
// TWO PASSES, deterministic first (migration 091 / task 9f).
//
//  1. RUN BINDING. A seed carrying a RunID is bound through runSessions —
//     the {run_id → session_id} map the caller loads from
//     terminal_run_session. That is not an inference: the daemon minted the
//     run id before it spawned the launcher, handed it to that exact child,
//     and later observed which session the run produced. No cwd comparison,
//     no tool comparison, no time window — none of those can add information
//     to an identity that is already known, and each could only reject a
//     correct answer (a tool whose project root differs from the launch cwd,
//     a session created outside the forward window).
//
//  2. HEURISTIC. Every remaining seed falls through to the original rule: a
//     session matches iff tool and project root NAME THE SAME DIRECTORY
//     (pathsEqual — see launchSeedCWDMatches) and the session started within
//     [seed−LaunchSeedBackSkew, seed+LaunchSeedForwardWindow]. Pairing is
//     greedy and injective: seeds are walked oldest-first, each taking the
//     EARLIEST-STARTED unclaimed matching session. Injectivity is the
//     two-simultaneous-sessions guard — one session can never absorb two
//     seeds, and two same-project launches pair deterministically instead of
//     both anchoring to whichever session sorts first.
//
// ORDER IS LOAD-BEARING. The run pass runs first and marks its sessions
// taken, so a heuristic candidate can never steal a session that a run
// already accounts for. Running them the other way round would let a
// coincidence of cwd + tool + timing outrank a known fact — which is exactly
// the failure this pass exists to end.
//
// runSessions is nil-safe (an install with no terminal runs, or a caller that
// cannot load them, simply gets pass 2 alone — the pre-091 behaviour). The
// CALLER is responsible for admitting only correlations it considers
// established; this function trusts what it is handed, so a weak correlation
// must be filtered out before it gets here, not re-judged here.
//
// A seed whose pid already appears in claimed is skipped by BOTH passes (the
// caller uses this to honour an existing session_pid_bridge row without
// re-matching).
func MatchLaunchSeeds(seeds []LaunchSeed, sessions []CrossOSSessionRef, claimed map[int]bool, runSessions map[string]string) map[int]string {
	out := make(map[int]string)
	takenSession := make(map[string]bool)

	// Pass 1 — deterministic run binding. Seeds are walked oldest-first so the
	// result cannot depend on the input order, and the session is still taken
	// injectively: two seeds carrying the SAME run id (a nested launch inside a
	// dashboard terminal, which inherits the run's environment) must not both
	// claim it. Oldest wins — that is the launcher the daemon actually spawned
	// for the run; anything later is a descendant.
	runSeeds := make([]LaunchSeed, 0, len(seeds))
	for _, s := range seeds {
		if s.PID <= 0 || s.RunID == "" || claimed[s.PID] {
			continue
		}
		if _, ok := runSessions[s.RunID]; ok {
			runSeeds = append(runSeeds, s)
		}
	}
	sort.Slice(runSeeds, func(i, j int) bool {
		if !runSeeds[i].StartedAt.Equal(runSeeds[j].StartedAt) {
			return runSeeds[i].StartedAt.Before(runSeeds[j].StartedAt)
		}
		return runSeeds[i].PID < runSeeds[j].PID
	})
	for _, s := range runSeeds {
		sessionID := runSessions[s.RunID]
		if sessionID == "" || takenSession[sessionID] || out[s.PID] != "" {
			continue
		}
		out[s.PID] = sessionID
		takenSession[sessionID] = true
	}

	// Pass 2 — the heuristic, over whatever pass 1 did not account for.
	type candidate struct {
		session CrossOSSessionRef
		seed    LaunchSeed
	}
	var cands []candidate
	for _, s := range seeds {
		if s.PID <= 0 || s.Tool == "" || claimed[s.PID] || out[s.PID] != "" {
			continue
		}
		for _, sess := range sessions {
			if sess.SessionID == "" || !launchSeedToolEqual(s.Tool, sess.Tool) {
				continue
			}
			if !launchSeedCWDMatches(s.CWD, sess.ProjectRoot) {
				continue
			}
			if sess.StartedAt.Before(s.StartedAt.Add(-LaunchSeedBackSkew)) ||
				sess.StartedAt.After(s.StartedAt.Add(LaunchSeedForwardWindow)) {
				continue
			}
			cands = append(cands, candidate{session: sess, seed: s})
		}
	}

	// Deterministic order: seeds oldest-first; within a seed, sessions
	// earliest-started-first (ties broken by id for stability).
	sort.Slice(cands, func(i, j int) bool {
		if !cands[i].seed.StartedAt.Equal(cands[j].seed.StartedAt) {
			return cands[i].seed.StartedAt.Before(cands[j].seed.StartedAt)
		}
		return cands[i].session.StartedAt.Before(cands[j].session.StartedAt)
	})

	for _, c := range cands {
		if out[c.seed.PID] != "" || takenSession[c.session.SessionID] {
			continue
		}
		out[c.seed.PID] = c.session.SessionID
		takenSession[c.session.SessionID] = true
	}
	return out
}

// launchSeedToolEqual compares tool names case-insensitively: launcher verbs
// and adapter canonical names agree today, but the comparison must not
// silently break if either side changes case.
func launchSeedToolEqual(a, b string) bool {
	return strings.EqualFold(a, b)
}

// launchSeedCWDMatches decides the project-root half of the pairing rule.
//
// A seed CWD is the launcher process's own working directory, recorded as the
// OS handed it over. A session's ProjectRoot is whatever shape the ADAPTER
// recorded — Windows-shaped (C:\proj) for a tool reached through the cross-OS
// hook bridge, a VS Code URI fsPath (/c:/proj), or simply the same path with a
// trailing separator. Comparing those verbatim is barrier B2 from the
// cwd-attribution scoping: two spellings of one directory never match, the
// seed expires unconsumed, and the launch silently falls back to the
// medium-confidence lazy correlation. So both sides are folded with the SAME
// normalizePath the cross-OS pass already uses (pathsEqual), rather than a
// second, weaker equality living here.
//
// An EMPTY seed CWD stays a wildcard — the pre-existing contract for a
// launcher that could not determine a directory. It is deliberately the last
// resort, not the norm: an empty CWD lets a seed pair with a same-tool session
// in ANY project, so recordLaunchSeed fills it from the launcher's own cwd
// (cmd/observer/launchseed.go) and only a genuinely unknowable directory
// reaches this branch.
func launchSeedCWDMatches(seedCWD, projectRoot string) bool {
	if seedCWD == "" {
		return true
	}
	return pathsEqual(seedCWD, projectRoot)
}
