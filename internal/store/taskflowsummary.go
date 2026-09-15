// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// taskflowsummary.go composes the W2 session task/todo checklist wire (see
// docs/plans/node-session-detail-trickle-up-to-org-plan-2026-09-10.md §2
// "W2"). This file — NOT orgpush.go — owns the task_items / task_transitions
// READ, exactly as cachesessionorgrows.go owns the cache_events read: the
// privacy sentinel forbids those table names from ever appearing in
// orgpush.go, so the push path composes these through a FUNCTION CALL.
//
// internal/store/taskflow.go stays the tables' one WRITER (CLAUDE.md module
// boundary #4). This file only reads.
//
// THE CONTENT GATE LIVES HERE, ONCE. Both Selects take a shipsContent bool,
// which the ONE call site in orgpush.go supplies as
// share.shipsRawContent(). When it is false the prose columns are not even
// SELECTed — the query does not read them, so there is no window in which a
// content string exists in a wire row and is later stripped. The status half
// is identical in both postures.
//
// WINDOW + IDEMPOTENCY. Both Selects bound the recompute to rows whose OWN
// timestamp falls in the trailing sessionTaskWindowDays window, and the server
// upserts by the same natural key the node uses ((session_id, key) for items,
// (session_id, key, source_event_id) for transitions), so re-pushing a window
// is idempotent — the same posture as SelectSessionCacheSummaries. An item
// that has not been touched for longer than the window shipped when it was
// fresh; it is not re-sent forever.

// sessionTaskWindowDays bounds the task recompute to items last seen (and
// transitions that occurred) in the trailing window. Seven days, matching
// sessionCacheWindowDays — a checklist is session-scoped and a session older
// than a week is not still being edited.
const sessionTaskWindowDays = 7

// SelectSessionTaskItems returns the current state of every checklist item
// touched in the trailing sessionTaskWindowDays window.
//
// shipsContent decides whether the three PROSE columns (content, active_form,
// owner) are read at all. With it false the returned rows carry the status
// half only, which is precisely what a node that opted into task_detail but
// not into content sharing has consented to disclose.
func (s *Store) SelectSessionTaskItems(ctx context.Context, shipsContent bool) ([]orgcontract.SessionTaskItemRow, error) {
	since := timestamp(time.Now().UTC().AddDate(0, 0, -sessionTaskWindowDays))

	// Two query texts rather than one with conditional binds: the content
	// columns are absent from the SELECT LIST in the metadata posture, so the
	// gate is structural (the values never enter the process) rather than a
	// post-hoc blank-out that a later edit could forget.
	query := `
		SELECT session_id, tool, key, key_kind, '', '', '',
		       COALESCE(raw_status, ''), status, order_index,
		       first_seen_at, last_seen_at, unmatched
		  FROM task_items
		 WHERE last_seen_at >= ?
		 ORDER BY session_id, order_index, first_seen_at, key`
	if shipsContent {
		query = `
		SELECT session_id, tool, key, key_kind,
		       COALESCE(content, ''), COALESCE(active_form, ''), COALESCE(owner, ''),
		       COALESCE(raw_status, ''), status, order_index,
		       first_seen_at, last_seen_at, unmatched
		  FROM task_items
		 WHERE last_seen_at >= ?
		 ORDER BY session_id, order_index, first_seen_at, key`
	}

	rows, err := s.db.QueryContext(ctx, query, since)
	if err != nil {
		return nil, fmt.Errorf("store.SelectSessionTaskItems: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []orgcontract.SessionTaskItemRow{}
	for rows.Next() {
		var r orgcontract.SessionTaskItemRow
		var unmatched int
		if err := rows.Scan(&r.SessionID, &r.Tool, &r.Key, &r.KeyKind,
			&r.Content, &r.ActiveForm, &r.Owner,
			&r.RawStatus, &r.Status, &r.OrderIndex,
			&r.FirstSeenAt, &r.LastSeenAt, &unmatched); err != nil {
			return nil, fmt.Errorf("store.SelectSessionTaskItems: scan: %w", err)
		}
		r.Unmatched = unmatched != 0
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SelectSessionTaskItems: %w", err)
	}
	return out, nil
}

// SelectSessionTaskTransitions returns every status change recorded in the
// trailing sessionTaskWindowDays window. There is no content gate: a
// transition is two closed-vocabulary statuses, a timestamp and two opaque
// correlation ids.
func (s *Store) SelectSessionTaskTransitions(ctx context.Context) ([]orgcontract.SessionTaskTransitionRow, error) {
	since := timestamp(time.Now().UTC().AddDate(0, 0, -sessionTaskWindowDays))
	rows, err := s.db.QueryContext(ctx, `
		SELECT session_id, key, from_status, to_status, ts,
		       COALESCE(action_id, 0), source_event_id
		  FROM task_transitions
		 WHERE ts >= ?
		 ORDER BY session_id, ts, id`, since)
	if err != nil {
		return nil, fmt.Errorf("store.SelectSessionTaskTransitions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []orgcontract.SessionTaskTransitionRow{}
	for rows.Next() {
		var r orgcontract.SessionTaskTransitionRow
		if err := rows.Scan(&r.SessionID, &r.Key, &r.FromStatus, &r.ToStatus,
			&r.Ts, &r.ActionID, &r.SourceEventID); err != nil {
			return nil, fmt.Errorf("store.SelectSessionTaskTransitions: scan: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SelectSessionTaskTransitions: %w", err)
	}
	return out, nil
}

// probeTaskFlow is the Track R2 change-detection probe SHARED by both task
// wire families (internal/store/orgsnapgate.go). It lives HERE, with the
// tables' other readers, so orgsnapgate.go and orgpush.go stay free of the
// task_* names the privacy sentinel forbids there.
//
// PROBE: three O(1) index-endpoint seeks concatenated.
//
// WHY THAT REFLECTS MUTATION: task_transitions is append-only (every writer is
// an INSERT OR IGNORE), so any new status change advances its MAX(id).
// task_items, by contrast, is UPSERTED IN PLACE — a status change re-uses the
// row and would leave MAX(id) untouched — so its last_seen_at high-water mark
// is carried too; the upsert always sets last_seen_at to the event's own time.
//
// RESIDUAL, BOUNDED BY THE FRESHNESS FLOOR: an in-place edit that neither adds
// a transition nor advances last_seen_at (a re-applied identical snapshot) is
// invisible here — and is also a no-op for the wire. snapGate's maxSkipAge
// recomputes within the hour regardless.
func (s *Store) probeTaskFlow(ctx context.Context) (string, error) {
	return s.snapProbeScalar(ctx, `
		SELECT 'ti' || (SELECT COALESCE(MAX(id), 0) FROM task_items)
		    || ':' || (SELECT COALESCE(MAX(last_seen_at), '') FROM task_items)
		    || ':tt' || (SELECT COALESCE(MAX(id), 0) FROM task_transitions)`)
}
