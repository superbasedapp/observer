package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Org push RE-SEND tracking (agent migration 140, lane R2-RESEND).
//
// The cursor wires (sessions, actions, api_turns, token_usage) ship each row
// once, by id. Migration 140's triggers queue a row in org_push_changes when a
// WIRE column of an already-eligible row changes (a token MAX-upgrade, an
// action outcome, a reparented transcript, a session's later ended_at /
// model / surface, a project that learns its remote, any backfill repair), and
// bump the one org_push_rev counter. SelectUnpushedSince re-sends queued rows
// through the same select heads and privacy strip as a first send, stamping
// every cursor-wire row with the counter snapshot as NodeRev; the org keeps a
// row's newest NodeRev. This file owns the two node-local tables; orgpush.go
// names neither (it reaches the queue only through pushChangesFilter).

// pushTrackedTables are the cursor-wire tables migration 140 tracks, in the
// re-send lane's priority order (session headers and token totals first, the
// high-volume actions last). Each row: the table, its floor key, and the
// PushCursor field its id is compared against.
var pushTrackedTables = []struct {
	table string
	key   string
	field func(*PushCursor) *int64
}{
	{"sessions", "org_push_floor_sessions", func(c *PushCursor) *int64 { return &c.Sessions }},
	{"token_usage", "org_push_floor_token_usage", func(c *PushCursor) *int64 { return &c.TokenUsage }},
	{"api_turns", "org_push_floor_api_turns", func(c *PushCursor) *int64 { return &c.APITurns }},
	{"actions", "org_push_floor_actions", func(c *PushCursor) *int64 { return &c.Actions }},
}

// pushResendRowCap bounds the re-send lane per push (rows across all four
// tables). The lane also never takes more than half the envelope, so a deep
// queue drains over several pushes and new rows keep flowing beside it.
const pushResendRowCap = 2000

// pushResendGarbageCap bounds one acknowledgement's sweep of queue rows that
// can never ship (row deleted, below the floor, outside the push scope).
const pushResendGarbageCap = 5000

// pushTracking is the enrolled node's per-table re-send floor: a row at or
// below its table's floor was deliberately never shared (the enrolment seed)
// and is never re-sent.
type pushTracking struct {
	floor map[string]int64
}

// PushAcks is what an accepted push acknowledges in the re-send queue. The
// zero value acknowledges nothing.
type PushAcks struct {
	// Rev is the change-sequence snapshot the batch was read at; every
	// cursor-wire row in the batch carried it as NodeRev. Only queue rows
	// with seq <= Rev are acknowledged, so a change that landed while the
	// batch was in flight stays queued and ships next time.
	Rev int64

	tracked     bool
	scopeFilter string
	floor       map[string]int64
	ceil        map[string]int64    // the cursor each lane started from
	main        map[string][2]int64 // (from, to] id range the cursor lane shipped
	resent      map[string][]int64  // ids the re-send lane shipped
	deletions   []int64             // tombstone seqs shipped or dropped (orgpushtomb.go)
	manifests   []manifestAck       // session manifests shipped or dropped
}

// recordMain notes the id range each cursor lane shipped: (cur, next].
func (a *PushAcks) recordMain(cur, next PushCursor) {
	if !a.tracked {
		return
	}
	a.main = map[string][2]int64{}
	a.ceil = map[string]int64{}
	for _, t := range pushTrackedTables {
		from, to := *t.field(&cur), *t.field(&next)
		a.ceil[t.table] = from
		if to > from {
			a.main[t.table] = [2]int64{from, to}
		}
	}
}

// addResent notes one row the re-send lane shipped.
func (a *PushAcks) addResent(table string, id int64) {
	if a.resent == nil {
		a.resent = map[string][]int64{}
	}
	a.resent[table] = append(a.resent[table], id)
}

// Resent reports how many rows of the batch were re-sends.
func (a PushAcks) Resent() int {
	n := 0
	for _, ids := range a.resent {
		n += len(ids)
	}
	return n
}

// pushChangesFilter is the re-send lane's WHERE clause for one tracked table
// (idExpr is that table's id column in the select head): the ids of the
// OLDEST queued changes (seq <= the batch's snapshot) in (floor, ceil], at
// most limit of them. The queue is the driving side - an indexed walk of
// (tbl, seq) materialized first, then id probes into the table - so a push
// costs O(queued rows), never a scan of the tracked table. Bound args, in
// order: rev, ceil, floor, limit.
func pushChangesFilter(table, idExpr string) string {
	return ` WHERE ` + idExpr + ` IN (SELECT row_id FROM org_push_changes
	         WHERE tbl = '` + table + `' AND seq <= ? AND row_id <= ? AND row_id > ?
	         ORDER BY seq LIMIT ?)`
}

// loadPushTracking reads the change-sequence snapshot and, when the node is
// enrolled (floors present), its per-table floors. tracking is nil on a node
// that is not enrolled.
func (s *Store) loadPushTracking(ctx context.Context) (int64, *pushTracking, error) {
	var rev int64
	err := s.db.QueryRowContext(ctx, `SELECT rev FROM org_push_rev WHERE k = 1`).Scan(&rev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, nil, fmt.Errorf("load push rev: %w", err)
	}
	tr := pushTracking{floor: map[string]int64{}}
	for _, t := range pushTrackedTables {
		v, err := s.readMeta(ctx, t.key)
		if err != nil {
			return 0, nil, fmt.Errorf("load push floor %s: %w", t.table, err)
		}
		if v == "" {
			continue
		}
		f, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, nil, fmt.Errorf("parse push floor %s=%q: %w", t.table, v, err)
		}
		tr.floor[t.table] = f
	}
	if len(tr.floor) == 0 {
		return rev, nil, nil
	}
	return rev, &tr, nil
}

// resetPushTrackingTx is the cursor-MOVER half of re-send tracking: the
// floors follow the new cursor, the queue (which described changes relative
// to the old baseline) is dropped, and the counter moves so every row read
// after the move carries a NodeRev newer than anything read before it.
func resetPushTrackingTx(ctx context.Context, tx *sql.Tx, c PushCursor) error {
	for _, t := range pushTrackedTables {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_meta (key, value) VALUES (?, ?)
			 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
			t.key, strconv.FormatInt(*t.field(&c), 10)); err != nil {
			return fmt.Errorf("save push floor %s: %w", t.table, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM org_push_changes`); err != nil {
		return fmt.Errorf("reset push changes: %w", err)
	}
	if err := clearPushDeletionsTx(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1`); err != nil {
		return fmt.Errorf("bump push rev: %w", err)
	}
	return nil
}

// clearPushTracking disarms re-send tracking (unenrol): no floors, no queue.
func (s *Store) clearPushTracking(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("clear push tracking: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, t := range pushTrackedTables {
		if _, err := tx.ExecContext(ctx, `DELETE FROM schema_meta WHERE key = ?`, t.key); err != nil {
			return fmt.Errorf("clear push floor %s: %w", t.table, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM org_push_changes`); err != nil {
		return fmt.Errorf("clear push changes: %w", err)
	}
	if err := clearPushDeletionsTx(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("clear push tracking: commit: %w", err)
	}
	return nil
}

// pushGarbageSQL selects, among the OLDEST pushResendGarbageCap queue rows
// (seq <= ?, row_id <= ?) of one table - exactly the head the re-send lane
// reads next - those that can never ship: the row is gone, at or below the
// floor (?), or outside the push scope. Bound args: tbl, seq, ceil, floor.
func pushGarbageSQL(table, scopeFilter string) string {
	var join, id, scope string
	switch table {
	case "sessions":
		join, id, scope = `LEFT JOIN sessions x ON x.rowid = pc.row_id`, `x.rowid`, `x.project_id`
	case "actions":
		join, id, scope = `LEFT JOIN actions x ON x.id = pc.row_id`, `x.id`, `x.project_id`
	case "api_turns":
		join, id, scope = `LEFT JOIN api_turns x ON x.id = pc.row_id`, `x.id`, `x.project_id`
	default: // token_usage: scope resolves through the owning session, like the lane
		join, id, scope = `LEFT JOIN token_usage x ON x.id = pc.row_id LEFT JOIN sessions xs ON xs.id = x.session_id`, `x.id`, `xs.project_id`
	}
	cond := id + ` IS NULL OR ` + id + ` <= ?`
	if scopeFilter != "" {
		cond += ` OR COALESCE(` + scope + `, -1) NOT IN (` + scopeFilter + `)`
	}
	//nolint:gosec // G202: table/join/id/scope are the in-package constants above; scopeFilter is the resolved integer project-id list.
	return `SELECT pc.row_id FROM (SELECT row_id FROM org_push_changes
	         WHERE tbl = ? AND seq <= ? AND row_id <= ? ORDER BY seq LIMIT ` + strconv.Itoa(pushResendGarbageCap) + `) pc
	         ` + join + ` WHERE ` + cond
}

// AckPushedChanges acknowledges an ACCEPTED push in the re-send queue: every
// queue row the batch delivered (its cursor lanes' id ranges and its re-sent
// rows) whose seq is <= the batch's snapshot is removed, plus a bounded sweep
// of queue rows that can never ship. A change newer than the snapshot stays
// queued. Idempotent; a no-op for an untracked batch.
func (s *Store) AckPushedChanges(ctx context.Context, a PushAcks) error {
	if !a.tracked {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.AckPushedChanges: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, t := range pushTrackedTables {
		if r, ok := a.main[t.table]; ok {
			if _, err := tx.ExecContext(ctx,
				`DELETE FROM org_push_changes WHERE tbl = ? AND seq <= ? AND row_id > ? AND row_id <= ?`,
				t.table, a.Rev, r[0], r[1]); err != nil {
				return fmt.Errorf("store.AckPushedChanges: %s range: %w", t.table, err)
			}
		}
		if err := deleteQueuedIDs(ctx, tx, t.table, a.Rev, a.resent[t.table]); err != nil {
			return fmt.Errorf("store.AckPushedChanges: %s resent: %w", t.table, err)
		}
		floor, tracked := a.floor[t.table]
		if !tracked {
			continue
		}
		rows, err := tx.QueryContext(ctx, pushGarbageSQL(t.table, a.scopeFilter), t.table, a.Rev, a.ceil[t.table], floor)
		if err != nil {
			return fmt.Errorf("store.AckPushedChanges: %s garbage: %w", t.table, err)
		}
		var dead []int64
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return fmt.Errorf("store.AckPushedChanges: %s garbage scan: %w", t.table, err)
			}
			dead = append(dead, id)
		}
		if err := closeRows(rows); err != nil {
			return fmt.Errorf("store.AckPushedChanges: %s garbage rows: %w", t.table, err)
		}
		if err := deleteQueuedIDs(ctx, tx, t.table, a.Rev, dead); err != nil {
			return fmt.Errorf("store.AckPushedChanges: %s garbage delete: %w", t.table, err)
		}
	}
	if err := ackPushDeletionsTx(ctx, tx, a); err != nil {
		return fmt.Errorf("store.AckPushedChanges: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.AckPushedChanges: commit: %w", err)
	}
	return nil
}

// deleteQueuedIDs removes queue rows of one table by id, seq <= rev, in
// bounded IN-list chunks.
func deleteQueuedIDs(ctx context.Context, tx *sql.Tx, table string, rev int64, ids []int64) error {
	const chunk = 500
	for len(ids) > 0 {
		n := len(ids)
		if n > chunk {
			n = chunk
		}
		args := make([]any, 0, n+2)
		args = append(args, table, rev)
		for _, id := range ids[:n] {
			args = append(args, id)
		}
		//nolint:gosec // G202: only the ?-placeholder list is concatenated; every value binds via args.
		q := `DELETE FROM org_push_changes WHERE tbl = ? AND seq <= ? AND row_id IN (` +
			strings.TrimSuffix(strings.Repeat("?,", n), ",") + `)`
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			return err
		}
		ids = ids[n:]
	}
	return nil
}

// PushResendPending reports how many rows per tracked table are queued for a
// re-send (0 for every table on a node that is not enrolled).
func (s *Store) PushResendPending(ctx context.Context) (map[string]int64, error) {
	out := map[string]int64{}
	rows, err := s.db.QueryContext(ctx, `SELECT tbl, COUNT(*) FROM org_push_changes GROUP BY tbl`)
	if err != nil {
		return nil, fmt.Errorf("store.PushResendPending: %w", err)
	}
	for rows.Next() {
		var t string
		var n int64
		if err := rows.Scan(&t, &n); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store.PushResendPending: scan: %w", err)
		}
		out[t] = n
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("store.PushResendPending: %w", err)
	}
	return out, nil
}

// ErrPushNotTracked is returned by EnqueuePushResync on a node that is not
// enrolled (no re-send floors), where there is nothing to converge.
var ErrPushNotTracked = errors.New("store: org push re-send tracking is not armed (node not enrolled)")

// PushResyncOptions bounds `observer org resync`.
type PushResyncOptions struct {
	// Since limits the heal to rows whose own timestamp (sessions:
	// started_at) is at or after it.
	Since time.Time
	// Limit caps the rows queued across all tables (most recent first).
	Limit int
	// DryRun reports what would change without writing anything.
	DryRun bool
}

// PushResyncTable is one table's line of a resync report.
type PushResyncTable struct {
	Table       string
	FloorBefore int64
	FloorAfter  int64
	Cursor      int64
	Queued      int64
}

// PushResyncReport is what EnqueuePushResync did (or, under DryRun, would do).
type PushResyncReport struct {
	Tables []PushResyncTable
	// EndedAtChecked is how many sessions in the window had ended_at
	// recomputed from their stored lifecycle actions (internal/sessionend);
	// only those whose stored value was wrong were actually rewritten.
	EndedAtChecked int
}

// resyncTimeColumn is each tracked table's event-time column for the window
// and for the post-enrolment floor proof.
var resyncTimeColumn = map[string]string{
	"sessions": "started_at", "actions": "timestamp", "api_turns": "timestamp", "token_usage": "timestamp",
}

// resyncIDColumn is each tracked table's cursor id column.
var resyncIDColumn = map[string]string{
	"sessions": "rowid", "actions": "id", "api_turns": "id", "token_usage": "id",
}

// enrolmentMargin widens the post-enrolment proof so a small capture-clock
// skew can only make the lowered floor MORE conservative.
const enrolmentMargin = 5 * time.Minute

// EnqueuePushResync is the one-shot HEAL for rows that diverged before re-send
// tracking existed (or before this node upgraded to it). It:
//
//  1. recomputes sessions.ended_at for sessions in the window from their own
//     lifecycle actions (refreshSessionEnded, the ingest path's one writer),
//     so a session whose close arrived after it shipped - or before
//     ended_at was written at all - converges too;
//  2. lowers each table's floor to the smallest id PROVABLY inserted after
//     enrolment (a row whose event time is after enrolled_at + a margin can
//     only have been inserted after enrolment, and so can every row with a
//     larger id), never raising it and never below the original seed;
//  3. queues rows in (floor, cursor] with an event time >= Since, most recent
//     first, capped at Limit across all tables.
//
// It never ships anything itself: the normal push loop drains the queue in
// capped batches. Safe to re-run (a row already queued stays queued; a row
// already converged re-sends harmlessly). Refused on a node that is not
// enrolled.
func (s *Store) EnqueuePushResync(ctx context.Context, opt PushResyncOptions) (PushResyncReport, error) {
	var rep PushResyncReport
	if opt.Limit <= 0 {
		return rep, errors.New("store.EnqueuePushResync: Limit must be positive")
	}
	_, tr, err := s.loadPushTracking(ctx)
	if err != nil {
		return rep, fmt.Errorf("store.EnqueuePushResync: %w", err)
	}
	if tr == nil {
		return rep, ErrPushNotTracked
	}
	cur, err := s.LoadPushCursor(ctx)
	if err != nil {
		return rep, fmt.Errorf("store.EnqueuePushResync: %w", err)
	}
	since := opt.Since.UTC().Format(time.RFC3339Nano)

	// (1) ended_at repair, bounded by the same window and limit.
	sessIDs, err := s.resyncSessionIDs(ctx, since, opt.Limit)
	if err != nil {
		return rep, fmt.Errorf("store.EnqueuePushResync: %w", err)
	}
	if !opt.DryRun && len(sessIDs) > 0 {
		set := make(map[string]struct{}, len(sessIDs))
		for _, id := range sessIDs {
			set[id] = struct{}{}
		}
		if err := s.refreshSessionEnded(ctx, set); err != nil {
			return rep, fmt.Errorf("store.EnqueuePushResync: %w", err)
		}
	}
	rep.EndedAtChecked = len(sessIDs)

	// (2) floor proof.
	var enrolledAt string
	err = s.db.QueryRowContext(ctx, `SELECT enrolled_at FROM org_enrolment WHERE id = 1`).Scan(&enrolledAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return rep, fmt.Errorf("store.EnqueuePushResync: enrolment: %w", err)
	}
	proof := ""
	if t, perr := time.Parse(time.RFC3339Nano, enrolledAt); perr == nil {
		proof = t.Add(enrolmentMargin).UTC().Format(time.RFC3339Nano)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return rep, fmt.Errorf("store.EnqueuePushResync: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var seq int64
	if !opt.DryRun {
		if _, err := tx.ExecContext(ctx, `UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1`); err != nil {
			return rep, fmt.Errorf("store.EnqueuePushResync: bump: %w", err)
		}
		if err := tx.QueryRowContext(ctx, `SELECT rev FROM org_push_rev WHERE k = 1`).Scan(&seq); err != nil {
			return rep, fmt.Errorf("store.EnqueuePushResync: rev: %w", err)
		}
	}
	remaining := int64(opt.Limit)
	for _, t := range pushTrackedTables {
		floor, ok := tr.floor[t.table]
		if !ok {
			continue
		}
		line, err := resyncTable(ctx, tx, t.table, t.key, floor, *t.field(&cur), resyncWindow{
			proof: proof, since: since, remaining: remaining, seq: seq, dryRun: opt.DryRun,
		})
		if err != nil {
			return rep, fmt.Errorf("store.EnqueuePushResync: %w", err)
		}
		remaining -= line.Queued
		rep.Tables = append(rep.Tables, line)
	}
	if opt.DryRun {
		return rep, nil
	}
	if err := tx.Commit(); err != nil {
		return rep, fmt.Errorf("store.EnqueuePushResync: commit: %w", err)
	}
	return rep, nil
}

// resyncWindow is one EnqueuePushResync pass's shared bounds.
type resyncWindow struct {
	proof, since string // RFC3339 enrolment proof time ("" = none) and window start
	remaining    int64  // rows still allowed across tables
	seq          int64  // queue seq to stamp (unused under dryRun)
	dryRun       bool
}

// resyncTable is EnqueuePushResync's per-table step: prove a lower floor,
// queue (or count) the window's rows in (floor, cursor], persist the floor.
func resyncTable(ctx context.Context, tx *sql.Tx, table, floorKey string, floor, cursor int64, w resyncWindow) (PushResyncTable, error) {
	line := PushResyncTable{Table: table, FloorBefore: floor, FloorAfter: floor, Cursor: cursor}
	idc, tsc := resyncIDColumn[table], resyncTimeColumn[table]
	if w.proof != "" {
		var minPost sql.NullInt64
		//nolint:gosec // G202: idc/tsc/table are the in-package constants above.
		if err := tx.QueryRowContext(ctx, `SELECT MIN(`+idc+`) FROM `+table+
			` WHERE julianday(`+tsc+`) >= julianday(?)`, w.proof).Scan(&minPost); err != nil {
			return line, fmt.Errorf("%s floor proof: %w", table, err)
		}
		if minPost.Valid && minPost.Int64-1 < floor {
			line.FloorAfter = minPost.Int64 - 1
		}
	}
	if w.remaining > 0 {
		//nolint:gosec // G202: idc/tsc/table are the in-package constants above.
		where := ` FROM ` + table + ` WHERE ` + idc + ` > ? AND ` + idc + ` <= ? AND julianday(` + tsc + `) >= julianday(?)`
		args := []any{line.FloorAfter, line.Cursor, w.since}
		if w.dryRun {
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT 1`+where+` LIMIT ?)`, append(args, w.remaining)...).Scan(&line.Queued); err != nil {
				return line, fmt.Errorf("%s count: %w", table, err)
			}
		} else {
			//nolint:gosec // G202: idc and where are built from the in-package constants above; values bind via args.
			q := `INSERT OR REPLACE INTO org_push_changes (tbl, row_id, seq) SELECT ?, ` + idc + `, ?` + where + ` ORDER BY ` + idc + ` DESC LIMIT ?`
			res, err := tx.ExecContext(ctx, q, append([]any{table, w.seq}, append(args, w.remaining)...)...)
			if err != nil {
				return line, fmt.Errorf("%s queue: %w", table, err)
			}
			line.Queued, _ = res.RowsAffected()
		}
	}
	if !w.dryRun && line.FloorAfter != floor {
		if _, err := tx.ExecContext(ctx, `UPDATE schema_meta SET value = ? WHERE key = ?`,
			strconv.FormatInt(line.FloorAfter, 10), floorKey); err != nil {
			return line, fmt.Errorf("%s floor: %w", table, err)
		}
	}
	return line, nil
}

// resyncSessionIDs lists sessions started in the window, most recent first,
// capped at limit - the ended_at repair set.
func (s *Store) resyncSessionIDs(ctx context.Context, since string, limit int) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id FROM sessions WHERE julianday(started_at) >= julianday(?) ORDER BY rowid DESC LIMIT ?`, since, limit)
	if err != nil {
		return nil, fmt.Errorf("resync sessions: %w", err)
	}
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("resync sessions scan: %w", err)
		}
		out = append(out, id)
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("resync sessions: %w", err)
	}
	return out, nil
}
