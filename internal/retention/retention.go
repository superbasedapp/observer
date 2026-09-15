package retention

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"
)

// Result summarizes one Run.
type Result struct {
	ActionsDeleted          int
	ExcerptsDeleted         int
	FailureContextDeleted   int
	OrphanedSessionsDeleted int
	LogEntriesDeleted       int
	FileStateDeleted        int
	SizePassesRun           int
	DBSizeBytesBefore       int64
	DBSizeBytesAfter        int64
	DurationMs              int64
	// SizeCapUnmet is set when the single bounded size-cap shed pass
	// (shrinkToCap) left the DB still over MaxDBSizeMB — because shedding
	// aged `actions` (the only table this pass prunes) couldn't bring it
	// under cap, either because the keep-floor stopped it or because a
	// DELETE alone (no automatic full VACUUM — see shrinkToCap) doesn't
	// shrink the file. That means the bulk is in OTHER tables
	// (token_usage / cache_*), or the file needs the operator-triggered
	// `observer prune --vacuum` compaction. The operator should raise
	// max_db_size_mb, add token retention, or run `observer prune
	// --vacuum` in a restart window rather than have this pass destroy
	// the actions table chasing an unreachable cap. The caller logs a
	// WARN. Historically (pre-2026-08-fix) this path looped a bare
	// `VACUUM` up to 12x per pass, which is exactly the incident this
	// field's guard now prevents.
	SizeCapUnmet bool
	// CacheRowsDeleted is the count of cache_* table rows removed
	// by the cachetrack sweep (spec §9). The retention package
	// itself doesn't touch cache_* tables (sql.DB-only by design);
	// the orchestration layer (cmd/observer/prune.go::runRetention)
	// calls store.PruneCacheRows after Run and sets this field on
	// the returned Result. Zero when [cachetrack].retention_days
	// is ≤ 0 (sweep disabled) or no eligible rows existed.
	CacheRowsDeleted int
	// RouterDecisionsDeleted is the count of router_decisions rows
	// removed by the routing decision-log sweep
	// ([routing].decision_log_retention_days, model-routing spec
	// §R21). Same orchestration pattern as CacheRowsDeleted: the
	// retention package never touches the table; runRetention calls
	// store.PruneRouterDecisions and sets this field.
	RouterDecisionsDeleted int64
	// GuardRowsDeleted is the count of guard_* rows removed by the
	// guard §10.3 sweep — same orchestration pattern as
	// CacheRowsDeleted (store.PruneGuardRows runs after Run; the
	// chain checkpoint keeps the audit chain verifiable across the
	// prune). Zero when [guard].retention_days is ≤ 0.
	GuardRowsDeleted int
	// PromptReconsiderRowsDeleted is the count of guard_prompt_reconsider
	// rows removed by the prompt-submit "reconsider-once" sweep (migration
	// 097, docs/plans/prompt-submit-intervention-exploration-2026-09-07.md
	// §5.4). Unlike CacheRowsDeleted/GuardRowsDeleted this sweep has no
	// config-gated retention-days knob: the table's own expires_at column
	// IS its prune horizon (a short-lived reconsider-once grant, default
	// 30 minutes), so runRetention calls store.PrunePromptReconsider
	// unconditionally on every pass — an expired-only age sweep with
	// nothing left to configure.
	PromptReconsiderRowsDeleted int
	// ProcessRowsDeleted is the count of process_runs + process_events rows
	// removed by the process-observability sweep
	// ([observer.process].retention_days, docs/process-observability.md §11).
	// Same orchestration pattern as CacheRowsDeleted: the retention package
	// never touches the tables; runRetention calls store.PruneProcessRows
	// and sets this field. Zero when the feature is disabled or the horizon
	// is ≤ 0.
	ProcessRowsDeleted int
	// HandoffRowsDeleted is the count of handoffs rows removed by the
	// session-handoff sweep ([handoff].retention_days, plan §15 P4). Same
	// orchestration pattern as CacheRowsDeleted: the retention package
	// never touches the table; runRetention calls store.PruneHandoffRows
	// and sets this field. Zero when [handoff].retention_days is ≤ 0.
	HandoffRowsDeleted int64
	// BenchmarkRowsDeleted is the count of benchmark_runs rows removed by the
	// Benchmarks-Harness sweep ([benchmark].retention_days, plan §3.12). Same
	// orchestration pattern as CacheRowsDeleted: the retention package never
	// touches the tables; runRetention calls store.PruneBenchmarkRows (which
	// cascades to the run's attempts/members/scores) and sets this field. Zero
	// when [benchmark].retention_days is ≤ 0.
	BenchmarkRowsDeleted int64
	// CodeIntelProjectsDeleted is the count of code-intelligence projects
	// whose codeintel_* rows were removed by the [codeintel].retention_days
	// sweep (Ticket B, docs/plans/claude-code-hook-stall-ticket-and-db-
	// prune-plan-2026-07-12.md). Same orchestration pattern as
	// CacheRowsDeleted: the retention package never touches the tables;
	// runRetention calls store.CodeIntelPruneStaleProjects and sets this
	// field. Zero when [codeintel].retention_days is ≤ 0.
	CodeIntelProjectsDeleted int
	// CodeIntelProjectsArchived is the count of code-intelligence projects
	// MOVED to cold storage (~/.observer/archive.db) this pass by the
	// [archive] sweep, rather than deleted
	// (docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md).
	// Same orchestration pattern as CacheRowsDeleted: the retention package
	// never touches the tables; runRetention drives internal/archivesvc and
	// sets this field.
	//
	// This is a SIBLING of CodeIntelProjectsDeleted, deliberately not a reuse
	// of it: "deleted" and "archived" are different fates for the operator —
	// one is gone, one is one rehydrate away — and a report that conflates
	// them would make the whole arc invisible in the numbers it should be
	// most visible in. Exactly one of the two is non-zero on any given pass,
	// because [archive].enabled selects which sweep runs.
	CodeIntelProjectsArchived int
	// CodeIntelRowsArchived is the total verified row count moved to cold
	// storage this pass — the useful magnitude behind
	// CodeIntelProjectsArchived, since projects vary by orders of magnitude.
	CodeIntelRowsArchived int64
	// ProcessWindowsArchived is the count of process-capture day-windows
	// moved to cold storage this pass (corpus archival Bucket B). Like
	// CodeIntelProjectsArchived it is a SIBLING of ProcessRowsDeleted, never
	// a repurposing of it: "moved, still readable" and "deleted, gone" are
	// different operator-visible outcomes and a report that conflated them
	// would be lying about the only-copy bucket.
	ProcessWindowsArchived int
	// ProcessRowsArchived is the total verified row count moved to cold
	// storage this pass.
	ProcessRowsArchived int64
	// ProcessWindowsExpired is the count of day-windows deleted from the
	// ARCHIVE FILE by its own (later) retention horizon.
	ProcessWindowsExpired int
	// IncrementalVacuumRun is set when Run issued a bounded PRAGMA
	// incremental_vacuum(N) at the end of the pass — possible only once
	// the DB has been converted to auto_vacuum=INCREMENTAL (the
	// `observer prune --vacuum` restart-window step). On an unconverted
	// DB (auto_vacuum=NONE) freed pages stay on the freelist until a full
	// VACUUM; this flag reports which regime applied.
	IncrementalVacuumRun bool
	// OrgIntelCacheDeleted is the count of node-local org_intel_cache rows
	// (org-served-cloud-intelligence, migration 112/114) removed this pass:
	// orphans whose session is gone, plus rows older than max_age_days. Same
	// orchestration pattern as CacheRowsDeleted — the retention package never
	// touches the table; runRetention calls store.PruneOrgIntelCache and sets
	// this field (finding 7).
	OrgIntelCacheDeleted int
}

// Options parameterize Run.
type Options struct {
	// MaxAgeDays drops actions whose timestamp is older than this. Zero
	// disables age-based action pruning.
	MaxAgeDays int
	// MaxDBSizeMB caps the DB file size. When exceeded after age pruning,
	// Run shaves off oldest 30-day windows until under the cap. Zero
	// disables size-based pruning.
	MaxDBSizeMB int
	// ObserverLogMaxAgeDays drops observer_log rows older than this. Zero
	// disables log pruning.
	ObserverLogMaxAgeDays int
	// FileStateMaxAgeDays drops file_state rows whose last_seen_at is older
	// than this. Defaults to 30 (spec §19) when zero.
	FileStateMaxAgeDays int
	// DBPath is the path the SQLite db lives at, used to measure file size
	// for size-cap pruning. Required when MaxDBSizeMB > 0.
	DBPath string
	// IncrementalVacuumPages bounds the PRAGMA incremental_vacuum(N)
	// chunk Run issues after its sweeps when the DB is in
	// auto_vacuum=INCREMENTAL mode. Bounded so a retention pass on a
	// live daemon returns freed pages to the OS in a short, non-exclusive
	// step instead of a full-file rewrite. Zero uses the default
	// (defaultIncrementalVacuumPages ≈ 200MB at 4KiB pages); negative
	// disables the step.
	IncrementalVacuumPages int
}

// Pruner runs retention on a database.
type Pruner struct{ db *sql.DB }

// New wraps an open database.
func New(db *sql.DB) *Pruner { return &Pruner{db: db} }

// Run executes retention with opts and returns a summary. The pruner is
// safe to call on an empty database; missing data is silently ignored.
func (p *Pruner) Run(ctx context.Context, opts Options) (Result, error) {
	start := time.Now()
	res := Result{}
	if p.db == nil {
		return res, errors.New("retention.Run: nil DB")
	}
	res.DBSizeBytesBefore = sizeOf(opts.DBPath)

	if opts.MaxAgeDays > 0 {
		cutoff := nowUTC().AddDate(0, 0, -opts.MaxAgeDays).Format(time.RFC3339Nano)
		if err := p.deleteActionsOlder(ctx, cutoff, &res); err != nil {
			return res, err
		}
	}

	if err := p.deleteOrphanedSessions(ctx, &res); err != nil {
		return res, err
	}

	if opts.ObserverLogMaxAgeDays > 0 {
		cutoff := nowUTC().AddDate(0, 0, -opts.ObserverLogMaxAgeDays).Format(time.RFC3339Nano)
		n, err := p.exec(ctx, `DELETE FROM observer_log WHERE timestamp < ?`, cutoff)
		if err != nil {
			return res, err
		}
		res.LogEntriesDeleted = n
	}

	fileStateAge := opts.FileStateMaxAgeDays
	if fileStateAge <= 0 {
		fileStateAge = 30
	}
	cutoff := nowUTC().AddDate(0, 0, -fileStateAge).Format(time.RFC3339Nano)
	n, err := p.exec(ctx, `DELETE FROM file_state WHERE last_seen_at < ?`, cutoff)
	if err != nil {
		return res, err
	}
	res.FileStateDeleted = n

	// Reclaim WAL space — auto_vacuum isn't enabled, so PRAGMA
	// wal_checkpoint(TRUNCATE) is the cheapest way to shrink storage.
	_, _ = p.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)

	if opts.MaxDBSizeMB > 0 {
		if err := p.shrinkToCap(ctx, opts, &res); err != nil {
			return res, err
		}
	}

	// Incremental vacuum (Ticket B): once the DB has been converted to
	// auto_vacuum=INCREMENTAL (`observer prune --vacuum` in a restart
	// window), each retention pass returns freed pages to the OS in a
	// bounded chunk — no exclusive full-file rewrite, safe on a live
	// daemon. On an unconverted DB (auto_vacuum=NONE, the historical
	// default) this is a no-op and freed pages stay on the freelist
	// until the operator runs the conversion.
	res.IncrementalVacuumRun = p.incrementalVacuum(ctx, opts.IncrementalVacuumPages)

	res.DBSizeBytesAfter = sizeOf(opts.DBPath)
	res.DurationMs = time.Since(start).Milliseconds()
	return res, nil
}

// defaultIncrementalVacuumPages is the per-pass bound for the live-safe
// incremental vacuum: 50k pages ≈ 200MB at the 4KiB page size, small
// enough to complete quickly under WAL yet large enough to keep up with
// any realistic sweep.
const defaultIncrementalVacuumPages = 50_000

// autoVacuumIncremental is SQLite's PRAGMA auto_vacuum mode value for
// INCREMENTAL (0=NONE, 1=FULL, 2=INCREMENTAL).
const autoVacuumIncremental = 2

// incrementalVacuum issues a bounded PRAGMA incremental_vacuum(N) when
// the DB is in auto_vacuum=INCREMENTAL mode, reporting whether it ran.
// Best-effort: any error (including "not in incremental mode") degrades
// to false — retention must never fail over a reclamation step.
func (p *Pruner) incrementalVacuum(ctx context.Context, pages int) bool {
	if pages < 0 {
		return false
	}
	if pages == 0 {
		pages = defaultIncrementalVacuumPages
	}
	var mode int
	if err := p.db.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&mode); err != nil {
		return false
	}
	if mode != autoVacuumIncremental {
		return false
	}
	// incremental_vacuum returns rows (one per freed page batch in some
	// builds); drive it with Exec — modernc.org/sqlite accepts that and
	// frees up to N pages from the freelist.
	if _, err := p.db.ExecContext(ctx, fmt.Sprintf(`PRAGMA incremental_vacuum(%d)`, pages)); err != nil {
		return false
	}
	return true
}

// ConvertToIncrementalVacuum switches the database to
// auto_vacuum=INCREMENTAL and runs the full VACUUM that makes the mode
// change take effect (SQLite requires a VACUUM to rewrite the file with
// the pointer-map pages the incremental mode needs). This is the
// one-time `observer prune --vacuum` restart-window step (Ticket B): the
// VACUUM takes an exclusive lock and rewrites the whole file, so callers
// MUST ensure no live daemon is using the DB — cmd/observer refuses when
// the proxy port answers. Idempotent: re-running on an already-converted
// DB is just a full VACUUM (compaction). Returns the resulting
// auto_vacuum mode (2 = INCREMENTAL) for caller reporting.
func ConvertToIncrementalVacuum(ctx context.Context, db *sql.DB) (int, error) {
	if db == nil {
		return 0, errors.New("retention.ConvertToIncrementalVacuum: nil DB")
	}
	// Pin one connection: PRAGMA auto_vacuum sets a per-connection intent
	// that only becomes the file's mode when the SAME connection runs the
	// VACUUM — through the pool the pragma could land on one connection
	// and the VACUUM on another, silently converting nothing.
	conn, err := db.Conn(ctx)
	if err != nil {
		return 0, fmt.Errorf("retention.ConvertToIncrementalVacuum: acquire connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `PRAGMA auto_vacuum = INCREMENTAL`); err != nil {
		return 0, fmt.Errorf("retention.ConvertToIncrementalVacuum: set auto_vacuum: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `VACUUM`); err != nil {
		return 0, fmt.Errorf("retention.ConvertToIncrementalVacuum: vacuum: %w", err)
	}
	var mode int
	if err := conn.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&mode); err != nil {
		return 0, fmt.Errorf("retention.ConvertToIncrementalVacuum: read mode: %w", err)
	}
	return mode, nil
}

// deleteActionsOlder deletes actions with timestamp < cutoff, plus the
// dependent FTS5 excerpts and failure_context rows (which carry FK to
// actions but no ON DELETE CASCADE).
func (p *Pruner) deleteActionsOlder(ctx context.Context, cutoff string, res *Result) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("retention: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	exc, err := tx.ExecContext(ctx,
		`DELETE FROM action_excerpts
		 WHERE action_id IN (SELECT id FROM actions WHERE timestamp < ?)`, cutoff)
	if err != nil {
		return fmt.Errorf("retention: delete excerpts: %w", err)
	}
	if n, err := exc.RowsAffected(); err == nil {
		res.ExcerptsDeleted += int(n)
	}

	fc, err := tx.ExecContext(ctx,
		`DELETE FROM failure_context
		 WHERE action_id IN (SELECT id FROM actions WHERE timestamp < ?)`, cutoff)
	if err != nil {
		return fmt.Errorf("retention: delete failure_context: %w", err)
	}
	if n, err := fc.RowsAffected(); err == nil {
		res.FailureContextDeleted += int(n)
	}

	// file_state references actions(id) via last_action_id; null it out
	// rather than delete the file_state row (which may still be useful for
	// recent freshness checks even after the originating action is pruned).
	if _, err := tx.ExecContext(ctx,
		`UPDATE file_state SET last_action_id = NULL
		 WHERE last_action_id IN (SELECT id FROM actions WHERE timestamp < ?)`, cutoff); err != nil {
		return fmt.Errorf("retention: null file_state.last_action_id: %w", err)
	}

	// Later migrations added more nullable action_id FKs to actions, none
	// with ON DELETE CASCADE: retrieval_signals (014), guard_events (040),
	// process_runs + process_events (044). A surviving reference to a pruned
	// action trips "FOREIGN KEY constraint failed (787)" and aborts the whole
	// DELETE — the live regression that left the actions table un-pruned
	// (2026-06-18). Null each ref rather than delete the row, matching the
	// file_state handling above: retrieval_signals preserves the K43 long
	// tail (014 comment), guard_events is an append-only audit chain with its
	// own retention, and process_runs/process_events carry their own
	// retention horizon — each row stays useful without the action link.
	for _, c := range []struct{ table, stmt string }{
		{"retrieval_signals", `UPDATE retrieval_signals SET action_id = NULL WHERE action_id IN (SELECT id FROM actions WHERE timestamp < ?)`},
		{"guard_events", `UPDATE guard_events SET action_id = NULL WHERE action_id IN (SELECT id FROM actions WHERE timestamp < ?)`},
		{"process_runs", `UPDATE process_runs SET action_id = NULL WHERE action_id IN (SELECT id FROM actions WHERE timestamp < ?)`},
		{"process_events", `UPDATE process_events SET action_id = NULL WHERE action_id IN (SELECT id FROM actions WHERE timestamp < ?)`},
	} {
		if _, err := tx.ExecContext(ctx, c.stmt, cutoff); err != nil {
			return fmt.Errorf("retention: null %s.action_id: %w", c.table, err)
		}
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM tool_account_observations WHERE observed_at < ?`, cutoff); err != nil {
		return fmt.Errorf("retention: delete account observations: %w", err)
	}
	a, err := tx.ExecContext(ctx, `DELETE FROM actions WHERE timestamp < ?`, cutoff)
	if err != nil {
		return fmt.Errorf("retention: delete actions: %w", err)
	}
	if n, err := a.RowsAffected(); err == nil {
		res.ActionsDeleted += int(n)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("retention: commit: %w", err)
	}
	return nil
}

// deleteOrphanedSessions removes sessions whose action set is empty after
// the actions delete pass AND that no other table still references. Other
// tables (token_usage, failure_context, compaction_events) carry FK NOT
// NULL references to sessions(id) without ON DELETE CASCADE, so a session
// with surviving rows in any of them must stay; deleting it would trip
// the foreign-key constraint.
//
// In practice this matters because subagent compaction turns can land
// token_usage rows for sessions whose JSONL adapter never produced a
// tool_use block (see decision log 2026-04-16). Those sessions look
// orphaned by the actions table alone, but their token_usage data is
// still load-bearing for cost rollups.
func (p *Pruner) deleteOrphanedSessions(ctx context.Context, res *Result) error {
	r, err := p.db.ExecContext(ctx,
		`DELETE FROM sessions
		 WHERE id NOT IN (SELECT DISTINCT session_id FROM actions)
		   AND id NOT IN (SELECT DISTINCT session_id FROM token_usage)
		   AND id NOT IN (SELECT DISTINCT session_id FROM failure_context)
		   AND id NOT IN (SELECT DISTINCT session_id FROM compaction_events)`)
	if err != nil {
		return fmt.Errorf("retention: orphaned sessions: %w", err)
	}
	if n, err := r.RowsAffected(); err == nil {
		res.OrphanedSessionsDeleted = int(n)
	}
	return nil
}

// sizeCapActionFloorDays is the keep-floor for the size-cap shrink: it
// will never delete `actions` newer than this many days, no matter how
// far over the size cap the DB is. The size loop only sheds `actions`, so
// without a floor a DB bloated by OTHER tables (token_usage / cache_*)
// drives it to delete the entire actions history chasing a cap it can't
// reach — which is exactly what nuked an operator's 68K-row actions table
// down to ~90 (to reclaim ~87MB on a 521MB DB). With the floor, recent
// actions (and their user_prompt boundaries, FTS excerpts, process links)
// are protected; if the floor isn't enough to hit the cap, the loop stops
// and sets SizeCapUnmet so the caller can WARN that the cap is too low for
// the non-actions bulk.
const sizeCapActionFloorDays = 30

// shrinkToCap performs AT MOST ONE bounded reclamation pass when the DB
// file exceeds the size cap: it sheds a single 30-day window of the
// oldest `actions` (never crossing the sizeCapActionFloorDays keep-floor),
// checkpoints the WAL, and runs the existing bounded incrementalVacuum
// (a no-op unless the DB has already been converted to
// auto_vacuum=INCREMENTAL via the daemon-down `observer prune --vacuum`
// step — that's fine and correct; it's live-safe either way).
//
// It NEVER issues a bare `VACUUM` and NEVER loops. A full VACUUM rewrites
// the entire file under an exclusive lock and needs ~2x disk headroom —
// on a many-GB DB that is a minutes-long stall and can itself exhaust
// disk. That reclamation class is operator-triggered only
// (ConvertToIncrementalVacuum / `observer prune --vacuum` in a restart
// window), never automatic (2026-08-26 incident: this loop ran a bare
// VACUUM up to 12x per pass, rewriting a ~40GB file to a /var/tmp temp
// copy on every startup and every retention tick).
//
// If, after the single pass, the DB is still over cap — because the
// oldest action is already within the keep-floor (actions can't be shed
// further so the bulk lives in other tables), because there are no
// actions left to shave, or because the pass didn't bring the file under
// cap (expected on an unconverted auto_vacuum=NONE DB, since a DELETE
// alone only frees pages to the internal freelist without a VACUUM) —
// shrinkToCap sets res.SizeCapUnmet and returns. The caller WARNs once,
// naming the real bulk and pointing at raising max_db_size_mb or running
// the daemon-down `observer prune --vacuum` compaction.
func (p *Pruner) shrinkToCap(ctx context.Context, opts Options, res *Result) error {
	cap := int64(opts.MaxDBSizeMB) * 1024 * 1024
	size := sizeOf(opts.DBPath)
	if size <= cap {
		return nil
	}

	var minTS sql.NullString
	if err := p.db.QueryRowContext(ctx,
		`SELECT MIN(timestamp) FROM actions`).Scan(&minTS); err != nil {
		return fmt.Errorf("retention: min timestamp: %w", err)
	}
	if !minTS.Valid {
		// No actions left to shave, yet still over cap → the bulk is in
		// other tables. Stop and flag rather than no-op silently.
		res.SizeCapUnmet = true
		return nil
	}
	min, err := time.Parse(time.RFC3339Nano, minTS.String)
	if err != nil {
		return fmt.Errorf("retention: parse min timestamp %q: %w", minTS.String, err)
	}

	// Floor guard: if the oldest action is already within the keep-floor,
	// we must not delete it — actions can't be shed further, so the
	// over-cap condition is owned by other tables. Gate here, before any
	// work, so an unreachable cap costs nothing beyond the MIN() lookup
	// above.
	floor := nowUTC().AddDate(0, 0, -sizeCapActionFloorDays)
	if !min.Before(floor) {
		res.SizeCapUnmet = true
		return nil
	}

	cutoff := min.Add(30 * 24 * time.Hour)
	if cutoff.After(floor) {
		cutoff = floor // clamp: never cross the keep-floor in one pass
	}
	actionsBefore := res.ActionsDeleted
	if err := p.deleteActionsOlder(ctx, cutoff.Format(time.RFC3339Nano), res); err != nil {
		return err
	}
	if err := p.deleteOrphanedSessions(ctx, res); err != nil {
		return err
	}
	_, _ = p.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	// Bounded, live-safe reclamation — a no-op unless the DB is already
	// auto_vacuum=INCREMENTAL. Never a bare VACUUM.
	p.incrementalVacuum(ctx, opts.IncrementalVacuumPages)
	res.SizePassesRun++

	// Report whether the single pass actually shed the bulk. A DELETE
	// with no incremental/full vacuum doesn't shrink the file at all
	// (freed pages just join the freelist), so on an unconverted DB this
	// will almost always still be over cap — that's expected; the fix is
	// `observer prune --vacuum`, not another automatic pass here.
	if res.ActionsDeleted == actionsBefore || sizeOf(opts.DBPath) > cap {
		res.SizeCapUnmet = true
	}
	return nil
}

// exec runs a DELETE / UPDATE and returns rows affected. Wraps the boilerplate
// the per-pass deletes don't need transactions for.
func (p *Pruner) exec(ctx context.Context, q string, args ...any) (int, error) {
	r, err := p.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, fmt.Errorf("retention.exec: %w", err)
	}
	n, _ := r.RowsAffected()
	return int(n), nil
}

// sizeOf returns the file size at path, or 0 on any error. Returns 0 for
// ":memory:" databases too (the path won't exist).
func sizeOf(path string) int64 {
	if path == "" || path == ":memory:" {
		return 0
	}
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// nowUTC is a var so tests can inject a fixed clock.
var nowUTC = func() time.Time { return time.Now().UTC() }
