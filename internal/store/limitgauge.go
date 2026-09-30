package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// Arc 4 P5e predictions / limit-gauge aggregation, plus the per-session
// rate-limit window wire (lane F-WIRE, 2026-09-28). This file (NOT orgpush.go)
// owns every limit_snapshots read that feeds the org push: the privacy
// sentinel forbids that table name from ever appearing in orgpush.go, and the
// push path composes both wires via function calls, exactly like
// SelectRoutingSummaries. Two shapes leave the node, and only these two:
//
//   - SelectLimitGauges: the AGGREGATE per (day, provider) utilization stats.
//   - SelectSessionLimitSnapshots + coalesceSessionLimitSnapshots: the newest
//     window observation per (session, provider), metadata only (session id,
//     observing tool, provider, observed_at, the two windows' utilization and
//     reset stamps). See orgcontract.SessionLimitSnapshotRow.
//
// Neither ever reads scope_hash (an auth-identity hash), the raw header subset,
// the unified-status passthrough or the per-minute req_*/tok_* counters.

// limitGaugeWindowDays bounds the aggregate to the recent window; the server
// upserts by natural key, so re-pushing a window is idempotent.
const limitGaugeWindowDays = 7

// SelectLimitGauges aggregates the limit_snapshots log into the P5e wire rows.
// observed_at is unix seconds, so the day bucket is computed with the SQLite
// unixepoch modifier.
func (s *Store) SelectLimitGauges(ctx context.Context) ([]orgcontract.LimitGaugeRow, error) {
	since := time.Now().UTC().AddDate(0, 0, -limitGaugeWindowDays).Unix()
	rows, err := s.db.QueryContext(ctx, `
		SELECT strftime('%Y-%m-%d', observed_at, 'unixepoch') AS day, provider,
		       COUNT(*),
		       COALESCE(MAX(window_5h_util), 0), COALESCE(AVG(window_5h_util), 0),
		       COALESCE(MAX(window_7d_util), 0), COALESCE(AVG(window_7d_util), 0)
		FROM limit_snapshots
		WHERE observed_at >= ?
		GROUP BY day, provider
		ORDER BY day, provider`, since)
	if err != nil {
		return nil, fmt.Errorf("store.SelectLimitGauges: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []orgcontract.LimitGaugeRow{}
	for rows.Next() {
		var r orgcontract.LimitGaugeRow
		if err := rows.Scan(&r.Day, &r.Provider, &r.Snapshots,
			&r.Max5hUtil, &r.Avg5hUtil, &r.Max7dUtil, &r.Avg7dUtil); err != nil {
			return nil, fmt.Errorf("store.SelectLimitGauges: scan: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SelectLimitGauges: %w", err)
	}
	return out, nil
}

// probeLimitSnapshots is the Track R2 change-detection probe for the
// limit_gauge wire. It lives here — with the other limit_snapshots SQL — so
// orgsnapgate.go and orgpush.go stay free of the table name.
//
// PROBE: COALESCE(MAX(id),0) — one index-endpoint seek, O(1).
//
// WHY THAT REFLECTS MUTATION: limit_snapshots is append-only; the proxy's
// LimitSink only ever INSERTs a snapshot.
//
// RESIDUAL, BOUNDED BY THE FRESHNESS FLOOR: retention DELETEs inside the
// trailing window are not detected until snapGate's maxSkipAge fires.
func (s *Store) probeLimitSnapshots(ctx context.Context) (string, error) {
	return s.snapProbeScalar(ctx, `SELECT 'ls' || COALESCE(MAX(id), 0) FROM limit_snapshots`)
}

// pushCursorKeyLimitSnapshots is the schema_meta key persisting
// PushCursor.LimitSnapshots (the per-session rate-limit window wire's id
// high-water mark). It lives here, not beside the other cursor keys in
// orgpush.go, because the key spells the table name the privacy sentinel
// forbids in any string literal of that file; pushCursorFields references it
// by identifier.
const pushCursorKeyLimitSnapshots = "org_push_cursor_limit_snapshots"

// limitSnapshotHeadID is the limit_snapshots high-water id, the value
// enrolment seeds PushCursor.LimitSnapshots from (CurrentMaxIDs) so a node
// never retroactively ships its pre-enrolment windows. Same O(1)
// index-endpoint seek as probeLimitSnapshots; it lives here so orgpush.go
// stays free of the table name.
func (s *Store) limitSnapshotHeadID(ctx context.Context) (int64, error) {
	var id int64
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM limit_snapshots`).Scan(&id); err != nil {
		return 0, fmt.Errorf("store.limitSnapshotHeadID: %w", err)
	}
	return id, nil
}

// limitSnapshotsScanPerBatch caps the limit_snapshots rows one
// SelectUnpushedSince scans for the per-session wire. The scan is coalesced
// down to one row per (session, provider), so the cap bounds READ work, not
// wire size; the cursor carries the rest to the next tick.
const limitSnapshotsScanPerBatch = 2000

// LimitSnapshotCandidate is one scanned limit_snapshots row on its way to the
// per-session org wire: the node id the cursor advances over, the wire row it
// would ship as, and whether it may ship at all.
type LimitSnapshotCandidate struct {
	// ID is the node's limit_snapshots id (== Row.LocalID).
	ID int64
	// Row is the metadata-only wire shape (OrgID / UserEmail unstamped).
	Row orgcontract.SessionLimitSnapshotRow
	// Linked reports whether the row may ship: it names a session the node
	// knows, that session carries a tool, and (under a scoped push) the
	// session's project is in scope. An unlinked row is consumed by the
	// cursor but never shipped; the gauge is attributed to the observing
	// TOOL, and an unlinked snapshot has none.
	Linked bool
	// Settling reports an unlinked row that may still become linked: it names
	// a session id the node has no sessions row for YET, and it was observed
	// less than limitSnapshotSettleWindow ago. The proxy records a window as
	// the response lands, which can be before the watcher / hook has inserted
	// the session row, so consuming such a row as "unlinked" would lose the
	// window forever (review 2026-09-29 finding 6). The walk stops at a
	// settling row WITHOUT consuming it (the token_usage PushSettle
	// precedent); once the window elapses the row is consumed as today.
	Settling bool
}

// limitSnapshotSettleWindow bounds how long a snapshot naming a not-yet-known
// session is held back: DefaultPushSettleWindow, the token_usage holdback's
// bound, for the same reason (the proof arrives from a later parse).
const limitSnapshotSettleWindow = DefaultPushSettleWindow

// SelectSessionLimitSnapshots reads up to limit limit_snapshots rows with
// id > afterID, id ascending, as per-session wire candidates. scopeFilter is
// orgpush's resolved project-id IN-list ("" = unscoped): an out-of-scope row
// comes back unlinked, exactly like a row whose session is unknown.
//
// It selects ONLY the metadata columns the wire carries; scope_hash, raw,
// status and the req_*/tok_* counters are never read here.
func (s *Store) SelectSessionLimitSnapshots(ctx context.Context, afterID int64, limit int, scopeFilter string) ([]LimitSnapshotCandidate, error) {
	return s.selectSessionLimitSnapshotsAt(ctx, afterID, limit, scopeFilter, time.Now())
}

// selectSessionLimitSnapshotsAt is SelectSessionLimitSnapshots with the clock
// injected (the settle hold is relative to now).
func (s *Store) selectSessionLimitSnapshotsAt(ctx context.Context, afterID int64, limit int, scopeFilter string, now time.Time) ([]LimitSnapshotCandidate, error) {
	if limit <= 0 {
		return nil, nil
	}
	linked := `s.id IS NOT NULL AND COALESCE(s.tool, '') <> ''`
	if scopeFilter != "" {
		linked += ` AND s.project_id IN (` + scopeFilter + `)`
	}
	//nolint:gosec // G202: scopeFilter is orgpush's resolved integer project-id list (resolveScopeFilter), never user text; every value is bound.
	q := `SELECT l.id, COALESCE(l.session_id, ''), COALESCE(s.tool, ''), l.provider, l.observed_at,
	             l.window_5h_util, l.window_5h_reset, l.window_7d_util, l.window_7d_reset,
	             CASE WHEN ` + linked + ` THEN 1 ELSE 0 END,
	             CASE WHEN s.id IS NULL THEN 0 ELSE 1 END
	        FROM limit_snapshots l
	        LEFT JOIN sessions s ON s.id = l.session_id
	       WHERE l.id > ?
	       ORDER BY l.id ASC
	       LIMIT ?`
	rows, err := s.db.QueryContext(ctx, q, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("store.SelectSessionLimitSnapshots: %w", err)
	}
	defer func() { _ = rows.Close() }()

	settleSince := now.Add(-limitSnapshotSettleWindow).Unix()
	var out []LimitSnapshotCandidate
	for rows.Next() {
		var c LimitSnapshotCandidate
		var w5u, w7u sql.NullFloat64
		var w5r, w7r sql.NullInt64
		var linkedInt, knownInt int
		if err := rows.Scan(&c.ID, &c.Row.SessionID, &c.Row.Tool, &c.Row.Provider, &c.Row.ObservedAt,
			&w5u, &w5r, &w7u, &w7r, &linkedInt, &knownInt); err != nil {
			return nil, fmt.Errorf("store.SelectSessionLimitSnapshots: scan: %w", err)
		}
		c.Row.LocalID = c.ID
		c.Row.Window5hUtil, c.Row.Window7dUtil = fptr(w5u), fptr(w7u)
		c.Row.Window5hReset, c.Row.Window7dReset = iptr(w5r), iptr(w7r)
		c.Linked = linkedInt == 1 && c.Row.SessionID != "" && c.Row.Tool != ""
		c.Settling = !c.Linked && knownInt == 0 && c.Row.SessionID != "" && c.Row.ObservedAt > settleSince
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SelectSessionLimitSnapshots: %w", err)
	}
	return out, nil
}

// coalesceSessionLimitSnapshots folds id-ordered candidates into the rows one
// push ships: the NEWEST observation per (session, provider). It walks the
// candidates in id order and CONSUMES each one it can account for:
//
//   - a SETTLING candidate (unlinked only because its session row has not
//     landed yet, observed inside the settle window) STOPS the walk without
//     being consumed, so it is re-read - and may ship - on a later push;
//   - any other unlinked candidate is consumed and ships nothing;
//   - a linked candidate whose (session, provider) is already in the output is
//     consumed; it replaces that entry when it is at least as new (observed_at,
//     then local id), the node gauge's own ORDER BY observed_at DESC, id DESC;
//   - a linked candidate for a NEW key is appended only if admit accepts its
//     size; otherwise the walk STOPS without consuming it.
//
// admit(extra) reports whether extra bytes may be added and, when it returns
// true, reserves them; a replacement asks for the size difference (which may be
// negative, a release). newCursor is the id of the last consumed candidate, or
// cursor when nothing was consumed. The invariant this keeps: every snapshot
// id <= newCursor is shipped, superseded by a shipped newer row for the same
// key, or unlinked, so advancing the cursor never loses the newest window.
func coalesceSessionLimitSnapshots(cands []LimitSnapshotCandidate, cursor int64, admit func(extra int64) bool) ([]orgcontract.SessionLimitSnapshotRow, int64) {
	type key struct{ session, provider string }
	var out []orgcontract.SessionLimitSnapshotRow
	idx := map[key]int{}
	next := cursor
	for _, c := range cands {
		if c.Settling {
			break
		}
		if !c.Linked {
			next = c.ID
			continue
		}
		k := key{c.Row.SessionID, c.Row.Provider}
		i, seen := idx[k]
		if !seen {
			if !admit(jsonSize(c.Row)) {
				break
			}
			idx[k] = len(out)
			out = append(out, c.Row)
			next = c.ID
			continue
		}
		old := out[i]
		if c.Row.ObservedAt > old.ObservedAt || (c.Row.ObservedAt == old.ObservedAt && c.Row.LocalID >= old.LocalID) {
			if !admit(jsonSize(c.Row) - jsonSize(old)) {
				break
			}
			out[i] = c.Row
		}
		next = c.ID
	}
	return out, next
}
