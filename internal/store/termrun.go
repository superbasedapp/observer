package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// End-reason values stamped on terminal_run.end_reason (migration 072). They
// are the durable, race-free distinction the resilient-attach rediscovery gate
// keys off (review finding H2). Kept as store-owned constants because the store
// is the sole WRITER (via EndTerminalRun / StampLiveAttachRunsShutdown /
// StampResumedByRunID) and cmd/observer's rediscovery predicate is the sole
// READER — one owner per value.
const (
	// EndReasonChildExit — a natural process exit recorded via EndRunByHandle;
	// NOT resumable-by-restart.
	EndReasonChildExit = "child_exit"
	// EndReasonDaemonShutdown — stamped for every live attach run at graceful
	// daemon shutdown, BEFORE the PTYs are killed; IS resumable-by-restart.
	EndReasonDaemonShutdown = "daemon_shutdown"
	// EndReasonResumed — the orphan row was superseded by a successful
	// auto-resume spawn, so it must never be offered again across a later
	// restart.
	EndReasonResumed = "resumed"
)

// TerminalRun is one row of the NODE-LOCAL terminal-run identity table
// (terminal-product-exploitation plan §2.1a / §7, migration 064). It is the
// durable identity of a dashboard terminal launch, distinct from both the PTY
// handle and any agent session. Content-free by construction: the project root
// and OOB correlation nonce are carried as domain-separated hashes only
// (produced by internal/termrun). This struct — like RemoteAuditEvent — uses
// plain fields so the store stays decoupled from the pure package's enums.
//
// This is the ONE store seam for terminal_run / terminal_run_session; both
// tables are sentinel-pinned out of the org-push wire
// (tests/invariant/privacy_test.go). No paired orgserver migration exists.
type TerminalRun struct {
	// RunID is the opaque run identity minted at launch (termrun.NewRunID).
	RunID string
	// Tool is the target tool (e.g. "claude-code").
	Tool string
	// Kind is "handoff" or "fresh".
	Kind string
	// SourceSessionID is the handoff source session (kind=handoff only); it is
	// NEVER a correlated target. "" for a fresh launch.
	SourceSessionID string
	// ProjectRootHash is termrun.HashProjectRoot(root); never a raw path.
	ProjectRootHash string
	// CorrelationTokenHash is termrun.HashCorrelationToken(nonce); never the raw
	// nonce.
	CorrelationTokenHash string
	// LaunchedAt defaults to now (UTC) when zero.
	LaunchedAt time.Time
	// EndedAt is when the run's process exited; nil while running.
	EndedAt *time.Time
	// ExitCode is the run's exit code; nil while running.
	ExitCode *int
	// EndReason is the durable end-state discriminator (migration 072): one of
	// "" (running/crashed), EndReasonChildExit, EndReasonDaemonShutdown, or
	// EndReasonResumed.
	EndReason string
	// PID is the DETACHED child's process id (migration 108), recorded only for
	// a GUI run and only once its spawn returned. nil is the honest "no pid
	// recorded" — a PTY run never carries one (its identity is the PTY handle),
	// and a GUI row carries nil between the insert and the post-spawn stamp.
	PID *int
	// WrapApplied reports whether a GUI launch's routing wrap actually reached
	// the child (migration 108). false for every non-GUI kind, which has no
	// wrap concept at all.
	WrapApplied bool
	// WrapNote is the grounded reason for that verdict, or the caveat that
	// qualifies an applied wrap (migration 108). Server-composed metadata: no
	// argv, no environment values, no path.
	WrapNote string
}

// TerminalCorrelation is one scored link from a run to an observed agent
// session (terminal_run_session). A run has zero-or-more; downstream links
// attach only once confidence clears termrun.MinLinkConfidence.
type TerminalCorrelation struct {
	RunID      string
	SessionID  string
	Confidence float64
	// Source is "oob" | "marker" | "heuristic".
	Source string
	// ObservedAt defaults to now (UTC) when zero.
	ObservedAt time.Time
}

// InsertTerminalRun appends one terminal-run identity row. The sole writer of
// terminal_run (one-owner rule). A duplicate run id is an error (the id is
// crypto-random, so a collision signals a caller bug).
func (s *Store) InsertTerminalRun(ctx context.Context, run TerminalRun) error {
	launched := run.LaunchedAt
	if launched.IsZero() {
		launched = time.Now().UTC()
	}
	var endedArg any
	if run.EndedAt != nil {
		endedArg = run.EndedAt.UTC().Format(time.RFC3339Nano)
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO terminal_run
		   (run_id, tool, kind, source_session_id, project_root_hash,
		    correlation_token_hash, launched_at, ended_at, exit_code,
		    pid, wrap_applied, wrap_note)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		run.RunID, run.Tool, run.Kind, run.SourceSessionID, run.ProjectRootHash,
		run.CorrelationTokenHash, launched.UTC().Format(time.RFC3339Nano),
		endedArg, nullIntPtr(run.ExitCode),
		nullIntPtr(run.PID), boolToInt(run.WrapApplied), run.WrapNote)
	if err != nil {
		return fmt.Errorf("store.InsertTerminalRun: %w", err)
	}
	return nil
}

// StampTerminalRunSpawn records a GUI run's POST-SPAWN facts: the detached
// child's pid and the honest wrap verdict (migration 108). It is the sibling of
// EndTerminalRun — a guarded stamp on an existing row, not a second INSERT
// path, so InsertTerminalRun remains the sole creator of terminal_run rows and
// this file remains the table's one store seam.
//
// It exists because those three facts are only KNOWN after the spawn returns,
// while the row itself must be written BEFORE the spawn (the same record-then-
// spawn discipline every other launch kind follows, so a failed spawn closes
// out a real row instead of vanishing). A pid <= 0 is refused rather than
// stored: it would be an un-actionable fake, and the honest state is the NULL
// the insert already wrote.
func (s *Store) StampTerminalRunSpawn(ctx context.Context, runID string, pid int, wrapApplied bool, wrapNote string) error {
	if runID == "" {
		return nil
	}
	if pid <= 0 {
		return fmt.Errorf("store.StampTerminalRunSpawn: refusing a non-positive pid %d for run %s", pid, runID)
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE terminal_run
		    SET pid = ?, wrap_applied = ?, wrap_note = ?
		  WHERE run_id = ?`,
		pid, boolToInt(wrapApplied), wrapNote, runID)
	if err != nil {
		return fmt.Errorf("store.StampTerminalRunSpawn: %w", err)
	}
	return nil
}

// EndTerminalRun records a run's exit (ended_at + exit_code) and, when the run
// has no durable end-reason yet, stamps `reason` (typically EndReasonChildExit
// for a natural exit). Idempotent-safe for ended_at/exit_code (a re-reported
// exit is harmless).
//
// The end_reason write is GUARDED (`end_reason = ” → reason`, else unchanged)
// so a natural OnExit that fires AFTER a graceful-shutdown stamp cannot downgrade
// a 'daemon_shutdown' (or 'resumed') row back to 'child_exit'. That guard is the
// load-bearing half of the H2 fix: shutdown stamps the reason synchronously and
// deliberately does NOT set ended_at, and this racing exit may then set ended_at
// while leaving the reason intact — so the rediscovery gate reads a deterministic
// verdict either way.
func (s *Store) EndTerminalRun(ctx context.Context, runID string, endedAt time.Time, exitCode int, reason string) error {
	if endedAt.IsZero() {
		endedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE terminal_run
		    SET ended_at = ?, exit_code = ?,
		        end_reason = CASE WHEN end_reason = '' THEN ? ELSE end_reason END
		  WHERE run_id = ?`,
		endedAt.UTC().Format(time.RFC3339Nano), exitCode, reason, runID)
	if err != nil {
		return fmt.Errorf("store.EndTerminalRun: %w", err)
	}
	return nil
}

// StampLiveAttachRunsShutdown stamps end_reason='daemon_shutdown' on every LIVE
// attach run (kind='attach', not yet ended, no reason) at graceful daemon
// shutdown — the synchronous sweep the terminal stack runs BEFORE it kills the
// PTYs (review finding H2). It deliberately does NOT set ended_at: the natural
// OnExit that the PTY-kill triggers may record ended_at afterwards, but the
// durable reason already stamped here makes those runs deterministically
// resumable-by-restart. A run that already recorded its own exit (ended_at set
// OR reason already stamped) is excluded, so a clean child-exit is never
// mislabeled a shutdown orphan. Returns the number of rows stamped.
func (s *Store) StampLiveAttachRunsShutdown(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE terminal_run
		    SET end_reason = ?
		  WHERE kind = ? AND ended_at IS NULL AND end_reason = ''`,
		EndReasonDaemonShutdown, "attach")
	if err != nil {
		return 0, fmt.Errorf("store.StampLiveAttachRunsShutdown: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// StampLiveNonAttachRunsShutdown stamps end_reason='daemon_shutdown' AND
// ended_at=now on every LIVE NON-attach run (kind != 'attach', not yet ended, no
// reason) at graceful daemon shutdown — the sibling of
// StampLiveAttachRunsShutdown for the resume / fresh / handoff kinds. Without it,
// a non-attach run the daemon was driving when it shut down keeps ended_at NULL +
// end_reason ” forever, so the runs-history view shows a long-dead run as still
// LIVE (the 2026-07-20 orphaned resume-kind run report).
//
// Unlike the attach sweep, this DOES set ended_at (review finding 4): the
// non-attach kinds are NOT part of the resume-offer flow — nothing keys
// offerability on their NULL ended_at — and /api/terminal/runs
// (handleTerminalRuns) computes `running` as EndedAt==nil, so leaving ended_at
// NULL was the very bug this sweep was meant to fix (the row still rendered
// live). The durable reason alone is not enough for that read path; ended_at is
// what retires the row from the live view. The attach sweep, by contrast, MUST
// leave ended_at NULL because the resume-offer path (resumableSessionSet)
// distinguishes a daemon-death orphan by its NULL ended_at — so the two sweeps
// intentionally differ here. ended_at is written in the same RFC3339Nano UTC
// format every other stamp uses.
//
// It is a strictly ADDITIVE hygiene stamp and is DISJOINT from the attach sweep
// (kind != 'attach' vs kind = 'attach'), so the attach resume-offer path is
// provably untouched: resumableSessionSet / rediscoverResumableSessions offer
// ONLY kind='attach' runs, StampResumedByRunID targets ONLY kind='attach', and
// this function stamps ONLY the complementary non-attach kinds. The one
// kind-AGNOSTIC reader, LiveRunForSessionExcluding, already excludes
// 'daemon_shutdown' AND now also sees ended_at set, so a non-attach run
// correctly stops counting as a live resume-conflict once the daemon that owned
// it is gone — the desired behavior. A run that already recorded its own exit
// (ended_at set OR a reason stamped) is excluded. Returns the number of rows
// stamped.
func (s *Store) StampLiveNonAttachRunsShutdown(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE terminal_run
		    SET end_reason = ?, ended_at = ?
		  WHERE kind != ? AND ended_at IS NULL AND end_reason = ''`,
		EndReasonDaemonShutdown, time.Now().UTC().Format(time.RFC3339Nano), "attach")
	if err != nil {
		return 0, fmt.Errorf("store.StampLiveNonAttachRunsShutdown: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// StampResumedByRunID supersedes ONE specific resumable attach orphan — the
// rediscovered PREDECESSOR run whose id the caller resolved from the startup
// orphan set — by stamping end_reason='resumed', so a successful auto-resume
// spawn of that session can never re-offer that orphan across a later restart
// (review finding H2). It targets by exact run_id (not by session) precisely so
// the FRESH replacement run — which the auto-resume path spawns and which can
// correlate to the SAME session via OOB before this stamp runs (finding: wrong-
// run supersede) — is never touched: the fresh run's id differs, so its live row
// keeps end_reason=” and stays eligible for the shutdown sweep + its own future
// restart offer. It stamps ONLY when the run is an attach whose current reason is
// ” or 'daemon_shutdown' (a crash orphan or a shutdown orphan) — a child_exit or
// an already-resumed row is left untouched.
func (s *Store) StampResumedByRunID(ctx context.Context, runID string) error {
	if runID == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE terminal_run
		    SET end_reason = ?
		  WHERE run_id = ?
		    AND kind = ?
		    AND end_reason IN ('', ?)`,
		EndReasonResumed, runID, "attach", EndReasonDaemonShutdown)
	if err != nil {
		return fmt.Errorf("store.StampResumedByRunID: %w", err)
	}
	return nil
}

// StampResumedByRunIDs supersedes EACH given resumable attach orphan, applying
// StampResumedByRunID's exact guarded semantics per id. A single successful
// auto-resume can have MORE THAN ONE eligible predecessor for its session —
// historical duplicates or prior stamp failures — and every one must be stamped
// or the older rows stay offerable on the next restart (round-4 multi-orphan
// finding). A child_exit / already-resumed row is left untouched; only attach
// orphans (reason ” or 'daemon_shutdown') flip to 'resumed'. Empty input is a
// no-op; a per-id failure aborts and surfaces (the caller logs best-effort).
func (s *Store) StampResumedByRunIDs(ctx context.Context, runIDs []string) error {
	for _, id := range runIDs {
		if err := s.StampResumedByRunID(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// UpsertCorrelation records a scored run→session correlation, keeping the
// HIGHEST-confidence observation per (run_id, session_id): a later, weaker
// heuristic never downgrades an established OOB link. The scoring itself is
// owned by internal/termrun; this seam only persists the winner.
func (s *Store) UpsertCorrelation(ctx context.Context, c TerminalCorrelation) error {
	observed := c.ObservedAt
	if observed.IsZero() {
		observed = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO terminal_run_session (run_id, session_id, confidence, source, observed_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(run_id, session_id) DO UPDATE SET
		   confidence  = excluded.confidence,
		   source      = excluded.source,
		   observed_at = excluded.observed_at
		 WHERE excluded.confidence > terminal_run_session.confidence`,
		c.RunID, c.SessionID, c.Confidence, c.Source,
		observed.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("store.UpsertCorrelation: %w", err)
	}
	return nil
}

// LoadTerminalRun returns a run by id, or ok=false when absent.
func (s *Store) LoadTerminalRun(ctx context.Context, runID string) (TerminalRun, bool, error) {
	var run TerminalRun
	var launched string
	var ended sql.NullString
	var exit, pid sql.NullInt64
	var wrapApplied int
	err := s.db.QueryRowContext(ctx,
		`SELECT run_id, tool, kind, source_session_id, project_root_hash,
		        correlation_token_hash, launched_at, ended_at, exit_code, end_reason,
		        pid, wrap_applied, wrap_note
		   FROM terminal_run WHERE run_id = ?`, runID).
		Scan(&run.RunID, &run.Tool, &run.Kind, &run.SourceSessionID, &run.ProjectRootHash,
			&run.CorrelationTokenHash, &launched, &ended, &exit, &run.EndReason,
			&pid, &wrapApplied, &run.WrapNote)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TerminalRun{}, false, nil
		}
		return TerminalRun{}, false, fmt.Errorf("store.LoadTerminalRun: %w", err)
	}
	run.LaunchedAt, _ = time.Parse(time.RFC3339Nano, launched)
	if ended.Valid {
		if t, perr := time.Parse(time.RFC3339Nano, ended.String); perr == nil {
			run.EndedAt = &t
		}
	}
	if exit.Valid {
		v := int(exit.Int64)
		run.ExitCode = &v
	}
	if pid.Valid {
		v := int(pid.Int64)
		run.PID = &v
	}
	run.WrapApplied = wrapApplied != 0
	return run, true, nil
}

// TerminalRunSummary is one row of the read-only terminal-run history view
// (dashboard-management-surface plan §E). Metadata only, like TerminalRun: no
// raw path (the project root is hashed on the base row and not surfaced here)
// and no command text. It folds in the strongest correlated agent session (if
// any) and the observed command-boundary count, so the history view can link a
// run to the session it produced without an N+1 fan-out.
type TerminalRunSummary struct {
	RunID          string
	Tool           string
	Kind           string
	LaunchedAt     time.Time
	EndedAt        *time.Time
	ExitCode       *int
	EndReason      string  // "" | child_exit | daemon_shutdown | resumed (migration 072)
	BestSessionID  string  // strongest correlation; "" when none observed yet
	BestConfidence float64 // 0 when BestSessionID is ""
	CommandCount   int     // rows in terminal_commands for this run
}

// ListTerminalRuns returns the most-recent terminal runs (newest first), each
// folded with its strongest correlated session + observed command-boundary
// count. Read-only; the sole reader seam for the history view. limit is clamped
// by the caller. Both tables are NODE-LOCAL (never on the org-push wire).
func (s *Store) ListTerminalRuns(ctx context.Context, limit int) ([]TerminalRunSummary, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT r.run_id, r.tool, r.kind, r.launched_at, r.ended_at, r.exit_code, r.end_reason,
		        (SELECT trs.session_id FROM terminal_run_session trs
		           WHERE trs.run_id = r.run_id
		           ORDER BY trs.confidence DESC, trs.id ASC LIMIT 1),
		        (SELECT trs.confidence FROM terminal_run_session trs
		           WHERE trs.run_id = r.run_id
		           ORDER BY trs.confidence DESC, trs.id ASC LIMIT 1),
		        (SELECT COUNT(*) FROM terminal_commands tc WHERE tc.run_id = r.run_id)
		   FROM terminal_run r
		  ORDER BY r.launched_at DESC
		  LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store.ListTerminalRuns: %w", err)
	}
	defer rows.Close()
	var out []TerminalRunSummary
	for rows.Next() {
		var (
			sum      TerminalRunSummary
			launched string
			ended    sql.NullString
			exit     sql.NullInt64
			bestSess sql.NullString
			bestConf sql.NullFloat64
		)
		if scanErr := rows.Scan(&sum.RunID, &sum.Tool, &sum.Kind, &launched, &ended, &exit, &sum.EndReason,
			&bestSess, &bestConf, &sum.CommandCount); scanErr != nil {
			return nil, fmt.Errorf("store.ListTerminalRuns scan: %w", scanErr)
		}
		sum.LaunchedAt, _ = time.Parse(time.RFC3339Nano, launched)
		if ended.Valid {
			if t, perr := time.Parse(time.RFC3339Nano, ended.String); perr == nil {
				sum.EndedAt = &t
			}
		}
		if exit.Valid {
			v := int(exit.Int64)
			sum.ExitCode = &v
		}
		if bestSess.Valid {
			sum.BestSessionID = bestSess.String
			if bestConf.Valid {
				sum.BestConfidence = bestConf.Float64
			}
		}
		out = append(out, sum)
	}
	return out, rows.Err()
}

// LoadCorrelations returns a run's correlations, strongest first.
func (s *Store) LoadCorrelations(ctx context.Context, runID string) ([]TerminalCorrelation, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT run_id, session_id, confidence, source, observed_at
		   FROM terminal_run_session WHERE run_id = ?
		  ORDER BY confidence DESC, id ASC`, runID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadCorrelations: %w", err)
	}
	defer rows.Close()
	var out []TerminalCorrelation
	for rows.Next() {
		var c TerminalCorrelation
		var observed string
		if err := rows.Scan(&c.RunID, &c.SessionID, &c.Confidence, &c.Source, &observed); err != nil {
			return nil, fmt.Errorf("store.LoadCorrelations scan: %w", err)
		}
		c.ObservedAt, _ = time.Parse(time.RFC3339Nano, observed)
		out = append(out, c)
	}
	return out, rows.Err()
}

// liveRunExcludeBound caps the run-id exclusion list
// LiveRunForSessionExcluding splices into its NOT IN clause, so a pathological
// predecessor set can never build an unbounded SQL statement. Startup
// rediscovery already lists at most 500 runs (ListTerminalRuns cap), so a single
// session's predecessor list is far under this; the cap is a defensive ceiling,
// and any dropped id can only make the check MORE conservative (a false conflict,
// the safe direction), never miss a real one.
const liveRunExcludeBound = 512

// LiveRunForSession reports whether any LIVE terminal run — ended_at IS NULL AND
// end_reason not a conclusively-dead state — is correlated to sessionID at or
// above minConfidence. It is the durable AUTHORITY the attach resume conflict
// check consults so a resume is refused whenever a run is already driving that
// session — INCLUDING one the in-memory attach hub never saw (a dashboard resume,
// or any dashboard-spawned run that correlates to an AI session, does not ride
// the attach hub's lossy correlation feed and does not take the resume flock —
// round-5 finding 1).
//
// KIND-AGNOSTIC by design: any live run (attach, fresh, handoff, resume)
// correlated to the session counts, because ANY live driver of the session is a
// double-spawn conflict. The confidence gate mirrors termrun.MinLinkConfidence
// (passed in so the store stays free of the pure termrun package), so a weak
// heuristic guess never manufactures a false conflict — the same ABSTAIN rule
// the hub applies.
//
// Residual window: the correlation is persisted SYNCHRONOUSLY inside
// termsvc.Correlate (RecordCorrelation → UpsertCorrelation) BEFORE the in-memory
// link is set and BEFORE the advisory feed event is published, so by the time
// ANY correlation exists at all it is already queryable here — there is no
// window where a correlation is established yet not yet persisted. The only
// uncovered gap is the inherent pre-correlation window (before anything has
// correlated the run to a session), which no guard — in-memory or durable — can
// observe, and which is identical for every launch path.
func (s *Store) LiveRunForSession(ctx context.Context, sessionID string, minConfidence float64) (bool, error) {
	return s.LiveRunForSessionExcluding(ctx, sessionID, minConfidence, nil)
}

// LiveRunForSessionExcluding is LiveRunForSession with an explicit set of run ids
// the caller KNOWS are not live drivers — the target session's rediscovered
// startup PREDECESSOR orphans (review finding 1: self-blocking authority).
// Without it the rediscovery→auto-resume flow self-blocks: rediscovery offers a
// crash orphan (end_reason=” + ended_at NULL), the client auto-resumes, and this
// very authority finds that SAME predecessor row correlated + NULL-ended and
// refuses the resume as a conflict — zero spawn, every crash-orphan recovery
// broken.
//
// Two layers separate a real conflict from a self-block:
//   - The SQL excludes the CONCLUSIVELY-dead end states end_reason IN
//     ('daemon_shutdown','resumed'). A shutdown orphan and an already-superseded
//     orphan both keep ended_at NULL (StampLiveAttachRunsShutdown /
//     StampResumedByRunID change ONLY end_reason), so ended_at alone cannot retire
//     them — the reason can. This layer alone fixes the stale-'resumed' false
//     conflict.
//   - A crash orphan carries end_reason=” — indistinguishable from a genuinely
//     live run — so SQL cannot tell them apart; the caller therefore supplies the
//     exact predecessor run ids in excludeRunIDs, which the query removes with NOT
//     IN. A GENUINELY distinct live run for the same session (a dashboard run, not
//     in the predecessor set, end_reason=”) is NOT excluded and still conflicts.
//
// excludeRunIDs beyond liveRunExcludeBound are ignored (defensive ceiling).
func (s *Store) LiveRunForSessionExcluding(ctx context.Context, sessionID string, minConfidence float64, excludeRunIDs []string) (bool, error) {
	if sessionID == "" {
		return false, nil
	}
	// Placeholder order: the two dead-state reasons, then the excluded run ids,
	// then session id + confidence — matching the query text below.
	args := []any{EndReasonDaemonShutdown, EndReasonResumed}
	notIn := ""
	if len(excludeRunIDs) > 0 {
		ids := excludeRunIDs
		if len(ids) > liveRunExcludeBound {
			ids = ids[:liveRunExcludeBound]
		}
		ph := make([]string, len(ids))
		for i, id := range ids {
			ph[i] = "?"
			args = append(args, id)
		}
		notIn = " AND r.run_id NOT IN (" + strings.Join(ph, ",") + ")"
	}
	args = append(args, sessionID, minConfidence)

	query := `SELECT 1
		   FROM terminal_run r
		  WHERE r.ended_at IS NULL
		    AND r.end_reason NOT IN (?, ?)` + notIn + `
		    AND EXISTS (
		      SELECT 1 FROM terminal_run_session trs
		       WHERE trs.run_id = r.run_id
		         AND trs.session_id = ?
		         AND trs.confidence >= ?
		    )
		  LIMIT 1`
	var one int
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&one)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("store.LiveRunForSessionExcluding: %w", err)
	}
	return true, nil
}

// ResolveRunForSession returns the run most confidently correlated to a
// session, for the reverse lookup cost/status linking needs (plan §2.1a). It
// returns ok=false when no correlation exists; the caller applies the
// termrun.MinLinkConfidence gate on the returned confidence before attaching
// links.
func (s *Store) ResolveRunForSession(ctx context.Context, sessionID string) (runID string, confidence float64, ok bool, err error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT run_id, confidence FROM terminal_run_session
		  WHERE session_id = ?
		  ORDER BY confidence DESC, id ASC LIMIT 1`, sessionID)
	if serr := row.Scan(&runID, &confidence); serr != nil {
		if errors.Is(serr, sql.ErrNoRows) {
			return "", 0, false, nil
		}
		return "", 0, false, fmt.Errorf("store.ResolveRunForSession: %w", serr)
	}
	return runID, confidence, true, nil
}

// UncorrelatedTerminalRun is one live terminal run with no established
// correlation — a candidate for the daemon-side terminal→session discovery
// sweep to attempt matching against recent sessions.
type UncorrelatedTerminalRun struct {
	RunID           string
	Tool            string
	Kind            string
	SourceSessionID string
	LaunchedAt      time.Time
}

// ListLiveUncorrelatedRuns returns LIVE terminal runs (ended_at IS NULL AND
// end_reason = ”) that have no correlation at or above minConfidence,
// newest-launched first, capped at limit — the discovery sweep's work list.
// minConfidence is passed in by the caller (termrun.MinLinkConfidence) so the
// store stays free of the pure termrun package, the same posture as
// LiveRunForSessionExcluding. Both terminal_run and terminal_run_session are
// NODE-LOCAL (never on the org-push wire). Ordering uses julianday(), not raw
// text order: launched_at mixes RFC3339 ('...T08:00:00Z') and SQLite-default
// ('...  10:00:00') stamp shapes across the corpus, and those sort WRONG
// against each other as text (the 'T...Z' row can sort before or after a
// same-instant space-separated row depending on the literal bytes) — so
// under LIMIT the truncation must be julianday-chronological, matching
// CandidateSessionsForTerminalRun's ASC ordering fix.
func (s *Store) ListLiveUncorrelatedRuns(ctx context.Context, minConfidence float64, limit int) ([]UncorrelatedTerminalRun, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT r.run_id, r.tool, r.kind, r.source_session_id, r.launched_at
		   FROM terminal_run r
		  WHERE r.ended_at IS NULL
		    AND r.end_reason = ''
		    AND NOT EXISTS (SELECT 1 FROM terminal_run_session trs
		                     WHERE trs.run_id = r.run_id AND trs.confidence >= ?)
		  ORDER BY julianday(r.launched_at) DESC
		  LIMIT ?`, minConfidence, limit)
	if err != nil {
		return nil, fmt.Errorf("store.ListLiveUncorrelatedRuns: %w", err)
	}
	defer rows.Close()
	var out []UncorrelatedTerminalRun
	for rows.Next() {
		var u UncorrelatedTerminalRun
		var launched string
		if scanErr := rows.Scan(&u.RunID, &u.Tool, &u.Kind, &u.SourceSessionID, &launched); scanErr != nil {
			return nil, fmt.Errorf("store.ListLiveUncorrelatedRuns scan: %w", scanErr)
		}
		u.LaunchedAt = parseStamp(launched)
		out = append(out, u)
	}
	return out, rows.Err()
}

// SessionLinkedToAnyRun reports whether the session already carries a
// correlation at/above minConfidence to ANY terminal run (live or ended).
// It is the point-in-time re-check the discovery sweep runs immediately
// before linking, mirroring the candidate query's NOT EXISTS guard: a
// session claimed by another source mid-tick (e.g. an OOB echo) must not
// be linked a second time. minConfidence is caller-supplied
// (termrun.MinLinkConfidence) so the store stays free of the pure package.
func (s *Store) SessionLinkedToAnyRun(ctx context.Context, sessionID string, minConfidence float64) (bool, error) {
	if sessionID == "" {
		return false, nil
	}
	var one int
	err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM terminal_run_session WHERE session_id = ? AND confidence >= ?)`,
		sessionID, minConfidence).Scan(&one)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("store.SessionLinkedToAnyRun: %w", err)
	}
	return one == 1, nil
}

// DiscoveryCandidateSession is a session that could be a live run's child —
// the discovery sweep's per-run candidate result.
type DiscoveryCandidateSession struct {
	SessionID string
	StartedAt time.Time
}

// CandidateSessionsForTerminalRun lists sessions of tool started within the
// window [after, until] (both bounds caller-supplied and inclusive), scoped to
// the project whose projects.root_path equals gitRoot OR rawDir (a MANDATORY
// filter — there is no empty-root escape, unlike CandidateTargetSessions),
// excluding excludeSessionID and any session already linked to some run at or
// above minConfidence, oldest-first, capped at limit. The `until` ceiling
// keeps a long-idle uncorrelated run from claiming a bare-launch session that
// started hours later: daemon-launched tools start at spawn, so a legit
// session begins within launch + tool-startup + ingest lag, and the caller
// sizes the window to cover exactly that. minConfidence is passed in by the
// caller (termrun.MinLinkConfidence) so the store stays free of the pure
// termrun package, the same posture as LiveRunForSessionExcluding.
// julianday() — NOT datetime() — bridges the RFC3339 / RFC3339Nano /
// SQLite-default stamp formats the corpus mixes: datetime() truncates to whole
// seconds, so a fractional-second stamp up to ~1s before `after` would
// otherwise compare equal to the boundary and slip through (e.g.
// datetime('...01.100Z') >= datetime('...01.900Z') is TRUE — both truncate to
// :01). julianday() returns a float that preserves subsecond precision while
// still parsing the same mixed formats.
func (s *Store) CandidateSessionsForTerminalRun(ctx context.Context, tool, gitRoot, rawDir string, after, until time.Time, excludeSessionID string, minConfidence float64, limit int) ([]DiscoveryCandidateSession, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT s.id, s.started_at
		   FROM sessions s
		   LEFT JOIN projects p ON p.id = s.project_id
		  WHERE s.tool = ?
		    AND julianday(s.started_at) >= julianday(?)
		    AND julianday(s.started_at) <= julianday(?)
		    AND (COALESCE(p.root_path,'') = ? OR COALESCE(p.root_path,'') = ?)
		    AND s.id != ?
		    AND NOT EXISTS (SELECT 1 FROM terminal_run_session trs
		                     WHERE trs.session_id = s.id AND trs.confidence >= ?)
		  ORDER BY julianday(s.started_at) ASC, s.id ASC
		  LIMIT ?`,
		tool, timestamp(after), timestamp(until), gitRoot, rawDir, excludeSessionID, minConfidence, limit)
	if err != nil {
		return nil, fmt.Errorf("store.CandidateSessionsForTerminalRun: %w", err)
	}
	defer rows.Close()
	var out []DiscoveryCandidateSession
	for rows.Next() {
		var c DiscoveryCandidateSession
		var started string
		if scanErr := rows.Scan(&c.SessionID, &started); scanErr != nil {
			return nil, fmt.Errorf("store.CandidateSessionsForTerminalRun scan: %w", scanErr)
		}
		c.StartedAt = parseStamp(started)
		out = append(out, c)
	}
	return out, rows.Err()
}
