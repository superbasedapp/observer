package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/taskflow"
)

// taskflow.go is the ONE store seam that owns task_items /
// task_transitions (migration 109, docs/task-tracking.md). All SQL for
// the task-tracking feature lives here (CLAUDE.md module boundary #4 —
// one owner per table); internal/taskflow stays pure decode/diff/
// attribution logic with no database/sql import.
//
// Mirrors the cachetrack/guard seams in Ingest: best-effort, post-hoc,
// over ACTUALLY INSERTED actions only (a.ID != 0 — a dedup-skipped
// re-parse never re-applies a transition through this path; the
// UNIQUE(session_id, key, source_event_id) constraint on
// task_transitions is the second line of defense specifically for the
// post_tool_batch double-capture case, §R2.6 item 3).

// SetTasksEnabled gates the taskflow ingest seam ([tasks].enabled,
// default true — this is a pure re-decode of data already captured in
// actions.raw_tool_input/raw_tool_output, not a new capture surface).
// Idempotent; false is a no-op on the ingest path, matching the
// SetCacheEngine/SetGuard wiring shape. Set once at daemon composition
// (cmd/observer/main.go) from cfg.Tasks.Enabled.
func (s *Store) SetTasksEnabled(enabled bool) { s.tasksEnabled = enabled }

// SetTasksOptions wires [tasks].match_mode / .concurrent_attribution /
// .include_sidechains (FIX-4) into the store seam alongside
// SetTasksEnabled. matchMode is consumed immediately (threaded into
// every taskflow.Decode call below). concurrentAttribution and
// includeSidechains are NOT consumed at this seam at all — every
// Phase-2 read surface (dashboard/CLI/MCP) builds its own explicit
// taskflow.Options from the config.TasksConfig it already holds and
// applies it directly against taskflow.Attributor and
// LoadTaskTokenRows/LoadSidechainOnlyTaskTokenRows, rather than reading
// TasksOptions() off a store instance those surfaces never called this
// setter on (internal/taskreport/report.go's LoadSessionTaskReport doc
// comment has the full story) — this seam does not branch on them
// itself either way (CLAUDE.md #3/#6).
func (s *Store) SetTasksOptions(matchMode, concurrentAttribution string, includeSidechains bool) {
	s.tasksMatchMode = matchMode
	s.tasksConcurrentAttribution = concurrentAttribution
	s.tasksIncludeSidechains = includeSidechains
}

// TasksOptions returns the current [tasks] behavior knobs as a
// taskflow.Options value, for a Phase-2 report/cost builder to apply
// without re-reading config directly.
func (s *Store) TasksOptions() taskflow.Options {
	return taskflow.Options{
		MatchMode:             s.tasksMatchMode,
		ConcurrentAttribution: s.tasksConcurrentAttribution,
		IncludeSidechains:     s.tasksIncludeSidechains,
	}
}

// taskEligibleActionTypes is the outer, cheap pre-filter before
// taskflow.Decode's per-(tool, raw_tool_name) table does the real
// narrowing. Matches the orchestrator's ingest-seam scope: todo_update
// (which over-selects claude-code's TaskStop/TaskOutput/TaskList —
// Decode excludes those by not registering them) ∪ task_complete
// (never itself decodes to items; reserved so a future phase can use
// task-terminus rows as session-end boundary hints without a second
// action_type sweep) ∪ post_tool_batch (under-selected by action_type
// alone — carries claude-code Task payloads in an envelope array).
var taskEligibleActionTypes = map[string]bool{
	models.ActionTodoUpdate:   true,
	models.ActionTaskComplete: true,
	"post_tool_batch":         true,
}

// applyTaskEvents decodes and folds every actually-inserted, task-
// eligible action in a batch, in the order they appear (callers pass
// batches already in chronological (timestamp, id) order — the
// Ingest path's insertion order, and the backfill path's explicit
// ORDER BY). Returns the count of transitions actually appended.
func (s *Store) applyTaskEvents(ctx context.Context, actions []models.Action) (int, error) {
	if !s.tasksEnabled {
		return 0, nil
	}
	return s.applyTaskEventsForce(ctx, actions)
}

// applyTaskEventsForce is applyTaskEvents without the [tasks].enabled
// gate — used by the explicit `observer backfill --tasks` re-derive
// pass, which the operator is deliberately asking to run regardless of
// the live daemon's current config.
func (s *Store) applyTaskEventsForce(ctx context.Context, actions []models.Action) (int, error) {
	var applied int
	for i := range actions {
		a := &actions[i]
		if a.ID == 0 || !taskEligibleActionTypes[a.ActionType] {
			continue
		}
		events := taskflow.Decode(taskflow.ActionInput{
			Tool:          a.Tool,
			RawToolName:   a.RawToolName,
			ActionType:    a.ActionType,
			RawToolInput:  a.RawToolInput,
			RawToolOutput: a.RawToolOutput,
			SessionID:     a.SessionID,
			ActionID:      a.ID,
			SourceEventID: a.SourceEventID,
			Ts:            a.Timestamp.UnixNano(),
			MatchMode:     s.tasksMatchMode,
		})
		for _, ev := range events {
			n, err := s.applyTaskEvent(ctx, ev)
			if err != nil {
				return applied, fmt.Errorf("store.applyTaskEvents: %w", err)
			}
			applied += n
		}
	}
	return applied, nil
}

// applyTaskEvent persists one decoded TaskEvent: per-item state via
// taskflow.Apply, plus (for Snapshot-kind events) the vanish
// bookkeeping described in migration 109's doc comment. A Failed event
// (§R2.6 item 5) mutates nothing and returns 0. Runs in one
// transaction so a event's items either all land or none do.
func (s *Store) applyTaskEvent(ctx context.Context, ev taskflow.TaskEvent) (int, error) {
	if ev.Failed {
		return 0, nil
	}
	// A Snapshot-kind event with zero items ("clear my todos") still
	// needs to run — its vanish bookkeeping below is what closes any
	// previously in_progress item's open window (FIX-2). A Delta-kind
	// event can never legitimately reach here with zero items
	// (taskflow.decodeOne already filters that case at the source), but
	// stay defensive rather than let an empty per-item loop silently
	// fall into the Snapshot-only vanish block below for the wrong kind.
	if len(ev.Items) == 0 && ev.Kind != taskflow.SnapshotKind {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// source_event_id is NOT NULL DEFAULT '' under
	// UNIQUE(session_id, key, source_event_id) (migration 109). A tool
	// call with no vendor id for this (id-less Delta shapes, e.g.
	// poolside's flat todo_action) leaves ev.SourceEventID empty — if
	// every such transition on the SAME key used the literal '' value,
	// the second and every later real transition for that key would
	// silently no-op against INSERT OR IGNORE, since they'd all share
	// the identical (session_id, key, '') triple. Synthesize a
	// per-action id instead: ev.ActionID is the source actions.id, one
	// per real event, so "aid:<id>" is unique across distinct calls
	// while staying IDEMPOTENT under re-processing (a re-applied action
	// row reproduces the same synthetic id and is correctly deduped).
	sourceEventID := ev.SourceEventID
	if sourceEventID == "" {
		sourceEventID = "aid:" + strconv.FormatInt(ev.ActionID, 10)
	}

	var transitions int
	for _, item := range ev.Items {
		existing, hasExisting, err := loadTaskItemState(ctx, tx, ev.SessionID, item.Key)
		if err != nil {
			return transitions, fmt.Errorf("load item state: %w", err)
		}
		var statePtr *taskflow.ItemState
		if hasExisting {
			statePtr = &existing
		}
		res := taskflow.Apply(statePtr, item, ev.Ts)

		var snapshotActionID any
		if ev.Kind == taskflow.SnapshotKind {
			snapshotActionID = ev.ActionID
		}
		if _, err := tx.ExecContext(ctx, upsertTaskItemSQL,
			ev.SessionID, ev.Tool, item.Key, item.KeyKind,
			nullableString(res.NewState.Content), nullableString(res.NewState.ActiveForm),
			nullableString(res.NewState.Owner), nullableString(res.NewState.RawStatus),
			res.NewState.Status, res.NewState.Order,
			timestamp(res.NewState.FirstSeenAt), timestamp(ev.Ts),
			snapshotActionID,
		); err != nil {
			return transitions, fmt.Errorf("upsert task_items: %w", err)
		}

		if res.Transition != nil {
			r, err := tx.ExecContext(ctx, insertTaskTransitionSQL,
				ev.SessionID, item.Key, res.Transition.FromStatus, res.Transition.ToStatus,
				timestamp(ev.Ts), ev.ActionID, sourceEventID,
			)
			if err != nil {
				return transitions, fmt.Errorf("insert task_transitions: %w", err)
			}
			if n, _ := r.RowsAffected(); n > 0 {
				transitions++
			}
		}
	}

	// Vanish bookkeeping (Snapshot-kind only, §R2.3.4): anything this
	// session's item set previously carried a last_snapshot_action_id
	// for, that did NOT get bumped to THIS event's action id above, was
	// absent from this rewrite — flag it rather than silently dropping
	// it. A Delta event never touches last_snapshot_action_id at all
	// (it stays NULL for native-keyed Delta items), so this UPDATE only
	// ever reaches Snapshot-family rows.
	//
	// A vanished item that was last-known in_progress otherwise leaves
	// its open interval open FOREVER — BuildOpenIntervals never sees a
	// closing transition for it, so it accrues elapsed time and
	// attribution against every row for the rest of the session (14
	// live cases on the grounding corpus). insertVanishedTransitionSQL
	// runs FIRST (it reads the pre-update `status` column) and appends
	// a synthetic in_progress -> vanished transition at THIS event's ts
	// for every such item — "window closed at last sighting, not a
	// completion" — before markVanishedTaskItemsSQL flips unmatched=1
	// and (for the same in_progress items) the status/raw_status
	// columns themselves to 'vanished', so task_items and
	// task_transitions never disagree about a vanished item's state.
	if ev.Kind == taskflow.SnapshotKind {
		vanishedSourceEventID := "vanished:" + strconv.FormatInt(ev.ActionID, 10)
		r, err := tx.ExecContext(ctx, insertVanishedTransitionSQL,
			timestamp(ev.Ts), ev.ActionID, vanishedSourceEventID, ev.SessionID, ev.ActionID)
		if err != nil {
			return transitions, fmt.Errorf("insert vanished transitions: %w", err)
		}
		if n, _ := r.RowsAffected(); n > 0 {
			transitions += int(n)
		}
		if _, err := tx.ExecContext(ctx, markVanishedTaskItemsSQL, ev.SessionID, ev.ActionID); err != nil {
			return transitions, fmt.Errorf("mark vanished: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return transitions, fmt.Errorf("commit: %w", err)
	}
	return transitions, nil
}

const upsertTaskItemSQL = `
INSERT INTO task_items
  (session_id, tool, key, key_kind, content, active_form, owner, raw_status,
   status, order_index, first_seen_at, last_seen_at, last_snapshot_action_id, unmatched)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
ON CONFLICT(session_id, key) DO UPDATE SET
  content = excluded.content,
  active_form = excluded.active_form,
  owner = excluded.owner,
  raw_status = excluded.raw_status,
  status = excluded.status,
  order_index = excluded.order_index,
  last_seen_at = excluded.last_seen_at,
  last_snapshot_action_id = CASE
    WHEN excluded.last_snapshot_action_id IS NOT NULL THEN excluded.last_snapshot_action_id
    ELSE task_items.last_snapshot_action_id
  END,
  unmatched = 0`

const insertTaskTransitionSQL = `
INSERT OR IGNORE INTO task_transitions
  (session_id, key, from_status, to_status, ts, action_id, source_event_id)
VALUES (?, ?, ?, ?, ?, ?, ?)`

// insertVanishedTransitionSQL appends a synthetic in_progress ->
// vanished transition (taskflow.StatusVanished) for every item this
// session last saw in_progress that a new Snapshot rewrite no longer
// lists. MUST run before markVanishedTaskItemsSQL, which is the
// statement that actually overwrites task_items.status — this SELECT
// reads the pre-update value. args: ts, action_id, source_event_id
// suffix, session_id, action_id (the != comparison).
const insertVanishedTransitionSQL = `
INSERT OR IGNORE INTO task_transitions
  (session_id, key, from_status, to_status, ts, action_id, source_event_id)
SELECT session_id, key, status, '` + taskflow.StatusVanished + `', ?, ?, ?
  FROM task_items
 WHERE session_id = ?
   AND last_snapshot_action_id IS NOT NULL
   AND last_snapshot_action_id != ?
   AND unmatched = 0
   AND status = '` + taskflow.StatusInProgress + `'`

// alreadyTerminalStatusList is the SQL IN-list literal for every
// status BuildOpenIntervals/Summarize already treat as a lifecycle
// terminus (taskflow.IsTerminal). markVanishedTaskItemsSQL excludes
// these: an item that already completed/cancelled/deleted (or, from an
// earlier vanish, was already marked vanished) dropping out of the
// NEXT snapshot resend is the EXPECTED shape for a tool whose UI only
// re-sends its still-open items — not a data-loss signal worth an
// unmatched flag.
const alreadyTerminalStatusList = `'` + taskflow.StatusCompleted + `','` + taskflow.StatusCancelled + `','` + taskflow.StatusDeleted + `','` + taskflow.StatusVanished + `'`

// markVanishedTaskItemsSQL flags every item a new Snapshot rewrite no
// longer lists (and that isn't already terminal — see
// alreadyTerminalStatusList) as unmatched, and — for whichever of
// those were in_progress — flips status/raw_status to 'vanished' so
// task_items stays consistent with the synthetic transition
// insertVanishedTransitionSQL just wrote for the same rows.
const markVanishedTaskItemsSQL = `
UPDATE task_items
   SET unmatched = 1,
       status = CASE WHEN status = '` + taskflow.StatusInProgress + `' THEN '` + taskflow.StatusVanished + `' ELSE status END,
       raw_status = CASE WHEN status = '` + taskflow.StatusInProgress + `' THEN '` + taskflow.StatusVanished + `' ELSE raw_status END
 WHERE session_id = ?
   AND last_snapshot_action_id IS NOT NULL
   AND last_snapshot_action_id != ?
   AND unmatched = 0
   AND status NOT IN (` + alreadyTerminalStatusList + `)`

func loadTaskItemState(ctx context.Context, tx *sql.Tx, sessionID, key string) (taskflow.ItemState, bool, error) {
	var st taskflow.ItemState
	var content, activeForm, owner, rawStatus sql.NullString
	var firstSeen sql.NullString
	var snapshotActionID sql.NullInt64
	err := tx.QueryRowContext(ctx, `
		SELECT content, active_form, owner, raw_status, status, order_index,
		       first_seen_at, last_snapshot_action_id
		  FROM task_items WHERE session_id = ? AND key = ?`, sessionID, key).
		Scan(&content, &activeForm, &owner, &rawStatus, &st.Status, &st.Order, &firstSeen, &snapshotActionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return st, false, nil
		}
		return st, false, err
	}
	st.Content = content.String
	st.ActiveForm = activeForm.String
	st.Owner = owner.String
	st.RawStatus = rawStatus.String
	if t, ok := parseDBTime(firstSeen.String); ok {
		st.FirstSeenAt = t
	}
	if snapshotActionID.Valid {
		st.LastSnapshotActionID = snapshotActionID.Int64
	}
	return st, true, nil
}

// TaskItemRow is one task_items row as loaded for a phase-2 consumer
// (dashboard/CLI/MCP). Mirrors the migration 109 columns 1:1.
type TaskItemRow struct {
	Key         string
	KeyKind     string
	Content     string
	ActiveForm  string
	Owner       string
	RawStatus   string
	Status      string
	Order       int
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	Unmatched   bool
}

// LoadTaskItems returns every task_items row for a session, ordered by
// order_index then first_seen_at — the natural display order for
// Snapshot-family tools, and creation order for Delta-family ones.
func (s *Store) LoadTaskItems(ctx context.Context, sessionID string) ([]TaskItemRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT key, key_kind, COALESCE(content,''), COALESCE(active_form,''),
		       COALESCE(owner,''), COALESCE(raw_status,''), status, order_index,
		       first_seen_at, last_seen_at, unmatched
		  FROM task_items
		 WHERE session_id = ?
		 ORDER BY order_index ASC, first_seen_at ASC`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadTaskItems: %w", err)
	}
	defer rows.Close()

	var out []TaskItemRow
	for rows.Next() {
		var r TaskItemRow
		var firstSeen, lastSeen string
		var unmatched int
		if err := rows.Scan(&r.Key, &r.KeyKind, &r.Content, &r.ActiveForm, &r.Owner,
			&r.RawStatus, &r.Status, &r.Order, &firstSeen, &lastSeen, &unmatched); err != nil {
			return nil, fmt.Errorf("store.LoadTaskItems: scan: %w", err)
		}
		if t, ok := parseDBTime(firstSeen); ok {
			r.FirstSeenAt = t
		}
		if t, ok := parseDBTime(lastSeen); ok {
			r.LastSeenAt = t
		}
		r.Unmatched = unmatched != 0
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadTaskItems: rows: %w", err)
	}
	return out, nil
}

// LoadTaskTransitions returns a session's transitions in chronological
// order — the substrate for taskflow.BuildOpenIntervals/Summarize.
func (s *Store) LoadTaskTransitions(ctx context.Context, sessionID string) ([]taskflow.Transition, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT key, from_status, to_status, ts, COALESCE(action_id, 0), source_event_id
		  FROM task_transitions
		 WHERE session_id = ?
		 ORDER BY ts ASC, id ASC`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadTaskTransitions: %w", err)
	}
	defer rows.Close()

	var out []taskflow.Transition
	for rows.Next() {
		var tr taskflow.Transition
		var ts string
		if err := rows.Scan(&tr.Key, &tr.FromStatus, &tr.ToStatus, &ts, &tr.ActionID, &tr.SourceEventID); err != nil {
			return nil, fmt.Errorf("store.LoadTaskTransitions: scan: %w", err)
		}
		if t, ok := parseDBTime(ts); ok {
			tr.Ts = t
		}
		out = append(out, tr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadTaskTransitions: rows: %w", err)
	}
	return out, nil
}

// TaskTokenRow is one token_usage row's shape as needed for the
// §R2.3.2 attribution sweep — a lean projection (CLAUDE.md's
// SubagentTokenRef precedent), never the full model row. Carries every
// field internal/intelligence/cost.TokenBundle needs (CacheCreation1h /
// WebSearchRequests included, matching internal/intelligence/
// dashboard/live.go's LookupAt+Compute pattern) plus RecordedCostUSD —
// this store seam never SUMS estimated_cost_usd itself (§R2.3.6: it is
// NULL on 100% of claude-code/codex/cowork rows) and never imports the
// cost engine (CLAUDE.md module boundary #1), but a per-row recorded
// cost is still handed to the caller so a tool that DOES report one
// (e.g. commandcode's provider-reported costUsd) can prefer it over
// the pricing-ladder estimate, same as live.go's `rec > 0` check.
type TaskTokenRow struct {
	Ts                 time.Time
	Model              string
	InputTokens        int64
	OutputTokens       int64
	CacheReadTokens    int64
	CacheWriteTokens   int64
	CacheWrite1hTokens int64
	ReasoningTokens    int64
	WebSearchRequests  int64
	RecordedCostUSD    float64
}

// LoadTaskTokenRows returns a session's non-sidechain token_usage rows
// in chronological order, for the caller to attribute via
// taskflow.NewAttributor and price via its own cost.Engine.
//
// includeSidechains=false (the [tasks].include_sidechains default)
// excludes token_usage.is_sidechain=1 rows (migration 087) — a spawned
// sub-agent's own usage is reported separately, never folded into
// whichever task happened to be open at the same wall-clock time
// (§3.3's option (a); option (b), resolving TaskUpdate.owner to an
// actual child session, is not implementable — owner is free text, not
// a session id, §R2.6 item 6).
func (s *Store) LoadTaskTokenRows(ctx context.Context, sessionID string, includeSidechains bool) ([]TaskTokenRow, error) {
	q := `
		SELECT timestamp, COALESCE(model,''), COALESCE(input_tokens,0), COALESCE(output_tokens,0),
		       COALESCE(cache_read_tokens,0), COALESCE(cache_creation_tokens,0),
		       COALESCE(cache_creation_1h_tokens,0), COALESCE(reasoning_tokens,0),
		       COALESCE(web_search_requests,0), COALESCE(estimated_cost_usd,0)
		  FROM token_usage
		 WHERE session_id = ?`
	if !includeSidechains {
		q += ` AND is_sidechain = 0`
	}
	q += ` ORDER BY timestamp ASC, id ASC`
	rows, err := s.db.QueryContext(ctx, q, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadTaskTokenRows: %w", err)
	}
	defer rows.Close()

	var out []TaskTokenRow
	for rows.Next() {
		var r TaskTokenRow
		var ts string
		if err := rows.Scan(&ts, &r.Model, &r.InputTokens, &r.OutputTokens,
			&r.CacheReadTokens, &r.CacheWriteTokens, &r.CacheWrite1hTokens, &r.ReasoningTokens,
			&r.WebSearchRequests, &r.RecordedCostUSD); err != nil {
			return nil, fmt.Errorf("store.LoadTaskTokenRows: scan: %w", err)
		}
		if t, ok := parseDBTime(ts); ok {
			r.Ts = t
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadTaskTokenRows: rows: %w", err)
	}
	return out, nil
}

// LoadSidechainOnlyTaskTokenRows returns ONLY a session's is_sidechain=1
// token_usage rows, same shape as LoadTaskTokenRows. A Phase-2 report
// builder calls this (instead of re-deriving a set-difference against
// LoadTaskTokenRows(ctx, id, true)) to report a session's sub-agent
// spend as its OWN total when [tasks].include_sidechains is false —
// "counted, just not attributed to a specific task" (§3.3 option (a)),
// never silently dropped from the session's totals altogether.
func (s *Store) LoadSidechainOnlyTaskTokenRows(ctx context.Context, sessionID string) ([]TaskTokenRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT timestamp, COALESCE(model,''), COALESCE(input_tokens,0), COALESCE(output_tokens,0),
		       COALESCE(cache_read_tokens,0), COALESCE(cache_creation_tokens,0),
		       COALESCE(cache_creation_1h_tokens,0), COALESCE(reasoning_tokens,0),
		       COALESCE(web_search_requests,0), COALESCE(estimated_cost_usd,0)
		  FROM token_usage
		 WHERE session_id = ? AND is_sidechain = 1
		 ORDER BY timestamp ASC, id ASC`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadSidechainOnlyTaskTokenRows: %w", err)
	}
	defer rows.Close()

	var out []TaskTokenRow
	for rows.Next() {
		var r TaskTokenRow
		var ts string
		if err := rows.Scan(&ts, &r.Model, &r.InputTokens, &r.OutputTokens,
			&r.CacheReadTokens, &r.CacheWriteTokens, &r.CacheWrite1hTokens, &r.ReasoningTokens,
			&r.WebSearchRequests, &r.RecordedCostUSD); err != nil {
			return nil, fmt.Errorf("store.LoadSidechainOnlyTaskTokenRows: scan: %w", err)
		}
		if t, ok := parseDBTime(ts); ok {
			r.Ts = t
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadSidechainOnlyTaskTokenRows: rows: %w", err)
	}
	return out, nil
}

// LoadTaskActionTimestamps returns a session's non-sidechain action
// timestamps in chronological order — the per-row substrate a Phase-2
// report builder needs to classify EVERY action through
// taskflow.Attributor.At exactly like LoadTaskTokenRows does for
// tokens. A single [start,end) range count can't attribute actions
// correctly across a paused-and-reopened task — a task can carry more
// than one OpenInterval after a pause/resume (FIX-1) — only a per-row
// sweep through the same Attributor the token totals use can, which is
// why this is the only per-action query this seam exposes.
func (s *Store) LoadTaskActionTimestamps(ctx context.Context, sessionID string, includeSidechains bool) ([]time.Time, error) {
	q := `SELECT timestamp FROM actions WHERE session_id = ?`
	if !includeSidechains {
		q += ` AND is_sidechain = 0`
	}
	q += ` ORDER BY timestamp ASC, id ASC`
	rows, err := s.db.QueryContext(ctx, q, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadTaskActionTimestamps: %w", err)
	}
	defer rows.Close()

	var out []time.Time
	for rows.Next() {
		var ts string
		if err := rows.Scan(&ts); err != nil {
			return nil, fmt.Errorf("store.LoadTaskActionTimestamps: scan: %w", err)
		}
		if t, ok := parseDBTime(ts); ok {
			out = append(out, t)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadTaskActionTimestamps: rows: %w", err)
	}
	return out, nil
}

// LoadTaskUnmatchedCount returns the count of task_items rows currently
// flagged unmatched=1 for a session — the §R2.3.7 caveat #4 "U items
// could not be matched across updates" surface. Zero for a session
// whose task tools are all genuinely keyed (native_id), or one with no
// churn.
func (s *Store) LoadTaskUnmatchedCount(ctx context.Context, sessionID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM task_items WHERE session_id = ? AND unmatched = 1`, sessionID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store.LoadTaskUnmatchedCount: %w", err)
	}
	return n, nil
}

// TaskSessionRef is one session-with-tasks row as needed by the
// Phase-2 rollup (project/tool/window breakdown) — lean, like every
// other Task*Row projection in this file.
type TaskSessionRef struct {
	SessionID string
	Tool      string
	ProjectID int64
}

// SessionsWithTasksInWindow is SessionsWithTasks' windowed/project-
// scoped sibling: joins task_items against sessions so the Phase-2
// rollup (GET /api/tasks?days=&project_id=&project=&tool=) can filter
// by the session's OWN started_at, project_id, project root path, and
// tool without a second N+1 lookup per candidate session. A zero
// since/until means "no bound" on that side (windowRange's
// convention); projectID<=0 means "every project" on that dimension.
// projectRoot/tool are the same string-keyed filters every other
// Analysis-page endpoint accepts (analysisScopeClause's `project`/
// `tool` query params, matched against projects.root_path/
// sessions.tool) — empty means "no filter" on that dimension. All four
// filters AND together when more than one is set.
func (s *Store) SessionsWithTasksInWindow(ctx context.Context, since, until time.Time, projectID int64, projectRoot, tool string) ([]TaskSessionRef, error) {
	q := `
		SELECT DISTINCT ti.session_id, s.tool, s.project_id
		  FROM task_items ti
		  JOIN sessions s ON s.id = ti.session_id`
	if projectRoot != "" {
		q += `
		  JOIN projects p ON p.id = s.project_id`
	}
	q += `
		 WHERE 1=1`
	var args []any
	if !since.IsZero() {
		q += ` AND s.started_at >= ?`
		args = append(args, timestamp(since))
	}
	if !until.IsZero() {
		q += ` AND s.started_at < ?`
		args = append(args, timestamp(until))
	}
	if projectID > 0 {
		q += ` AND s.project_id = ?`
		args = append(args, projectID)
	}
	if projectRoot != "" {
		q += ` AND p.root_path = ?`
		args = append(args, projectRoot)
	}
	if tool != "" {
		q += ` AND s.tool = ?`
		args = append(args, tool)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.SessionsWithTasksInWindow: %w", err)
	}
	defer rows.Close()

	var out []TaskSessionRef
	for rows.Next() {
		var ref TaskSessionRef
		if err := rows.Scan(&ref.SessionID, &ref.Tool, &ref.ProjectID); err != nil {
			return nil, fmt.Errorf("store.SessionsWithTasksInWindow: scan: %w", err)
		}
		out = append(out, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SessionsWithTasksInWindow: rows: %w", err)
	}
	return out, nil
}

// TaskBackfillResult tallies one `observer backfill --tasks` pass.
type TaskBackfillResult struct {
	ActionsScanned     int
	TransitionsWritten int
}

// taskBackfillPageSize bounds how many actions rows BackfillTaskItems
// holds in memory at once. The unbounded version materialized ~119MB
// for 26,995 post_tool_batch rows on the grounding corpus (only 697 of
// which carried a Task payload) — this pages the scan instead of
// loading the whole eligible set up front.
const taskBackfillPageSize = 500

// postToolBatchLikeFilter returns the SQL fragment (and its bind args)
// that cheaply narrows post_tool_batch rows to ones that MIGHT carry a
// decodable Task payload, before taskflow.Decode does the real
// json.Unmarshal-backed narrowing. Built from
// taskflow.RegisteredRawToolNames() rather than a second,
// hand-maintained name list — SQLite's LIKE is case-insensitive for
// ASCII, so raw casing doesn't matter here.
func postToolBatchLikeFilter() (string, []any) {
	names := taskflow.RegisteredRawToolNames()
	if len(names) == 0 {
		// No decoder is registered for anything — every post_tool_batch
		// row is ineligible. "1=0" is cheaper than "must always false".
		return "1=0", nil
	}
	clauses := make([]string, len(names))
	args := make([]any, len(names))
	for i, n := range names {
		clauses[i] = "raw_tool_input LIKE ?"
		args[i] = "%" + n + "%"
	}
	return strings.Join(clauses, " OR "), args
}

// BackfillTaskItems re-derives task_items/task_transitions from the
// actions rows already in the DB — no adapter re-parse, no watcher, no
// source-file walk (the "surgical column backfill" lane,
// docs/adapters.md §"Maintenance: when to add a backfill mode",
// backfillCodexReasoning's shape). Idempotent: re-running applies the
// SAME upserts and INSERT OR IGNORE transitions, so a repeat run is a
// no-op. Ignores [tasks].enabled — the operator explicitly asked for
// this pass via the CLI flag.
//
// Two departures from a naive "SELECT everything, then process" pass:
//  1. task_complete is EXCLUDED from the scan entirely — no decoderTable
//     entry ever matches it (Decode's per-(tool,raw_tool_name) lookup
//     naturally yields nothing for it), so scanning those rows is pure
//     waste at backfill scale. It stays in the live ingest-time
//     taskEligibleActionTypes map as a reserved, forward-looking hook;
//     this backfill pass optimizes for the actions rows that can
//     actually produce a transition today.
//  2. post_tool_batch rows are pre-filtered with postToolBatchLikeFilter
//     before being counted as eligible at all — see its doc comment.
//
// Rows are paged (taskBackfillPageSize) via a (timestamp, id) keyset
// cursor rather than materialized in one slice, bounding memory to one
// page regardless of corpus size; limit (0 = unlimited) caps the total
// number of rows scanned across all pages. ORDER BY (timestamp, id)
// matches the ingest path's ordering guarantee (parallel tool blocks
// share a message_id and a millisecond-adjacent timestamp — the house
// tiebreak, internal/store/subagents.go:28).
func (s *Store) BackfillTaskItems(ctx context.Context, limit int) (TaskBackfillResult, error) {
	var res TaskBackfillResult
	batchClause, batchArgs := postToolBatchLikeFilter()

	var cursorTs string
	var cursorID int64
	for {
		pageSize := taskBackfillPageSize
		if limit > 0 {
			remaining := limit - res.ActionsScanned
			if remaining <= 0 {
				break
			}
			if remaining < pageSize {
				pageSize = remaining
			}
		}

		//nolint:gosec // G201: batchClause is only "raw_tool_input LIKE ?" repeated
		// (postToolBatchLikeFilter, one placeholder per taskflow.RegisteredRawToolNames
		// entry — never user input); every actual value is bound via args below.
		q := fmt.Sprintf(`
			SELECT id, session_id, project_id, timestamp, tool, action_type,
			       COALESCE(raw_tool_name,''), COALESCE(raw_tool_input,''), COALESCE(raw_tool_output,''),
			       source_event_id
			  FROM actions
			 WHERE (action_type = 'todo_update' OR (action_type = 'post_tool_batch' AND (%s)))
			   AND (timestamp > ? OR (timestamp = ? AND id > ?))
			 ORDER BY timestamp ASC, id ASC
			 LIMIT %d`, batchClause, pageSize)
		args := make([]any, 0, len(batchArgs)+3)
		args = append(args, batchArgs...)
		args = append(args, cursorTs, cursorTs, cursorID)

		rows, err := s.db.QueryContext(ctx, q, args...)
		if err != nil {
			return res, fmt.Errorf("store.BackfillTaskItems: query: %w", err)
		}

		var page []models.Action
		for rows.Next() {
			var a models.Action
			var ts string
			if err := rows.Scan(&a.ID, &a.SessionID, &a.ProjectID, &ts, &a.Tool, &a.ActionType,
				&a.RawToolName, &a.RawToolInput, &a.RawToolOutput, &a.SourceEventID); err != nil {
				rows.Close()
				return res, fmt.Errorf("store.BackfillTaskItems: scan: %w", err)
			}
			if t, ok := parseDBTime(ts); ok {
				a.Timestamp = t
			}
			cursorTs, cursorID = ts, a.ID
			page = append(page, a)
		}
		rerr := rows.Err()
		rows.Close()
		if rerr != nil {
			return res, fmt.Errorf("store.BackfillTaskItems: rows: %w", rerr)
		}
		if len(page) == 0 {
			break
		}

		res.ActionsScanned += len(page)
		n, err := s.applyTaskEventsForce(ctx, page)
		if err != nil {
			return res, fmt.Errorf("store.BackfillTaskItems: %w", err)
		}
		res.TransitionsWritten += n

		if len(page) < pageSize {
			break // short page — this was the last one.
		}
	}
	return res, nil
}
