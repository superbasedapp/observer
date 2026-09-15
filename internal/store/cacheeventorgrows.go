// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// cacheeventorgrows.go composes the PER-EVENT cache timeline wire (operator
// directive item 6; server migration 142, wire type
// internal/orgcontract/cacheeventsession.go). This file — NOT orgpush.go —
// owns the cache_events read, exactly as cachesummary.go owns the fleet
// day-aggregate read and cachesessionorgrows.go the session BUCKET read: the
// privacy sentinel forbids the cache_* table names from ever appearing in
// orgpush.go, so the push path composes this through a FUNCTION CALL. That
// sentinel is unchanged by this wire and stays green.
//
// WHY A THIRD CACHE WIRE. The two existing ones are aggregates. The node's
// Cache tab renders a chronological timeline built by cachetrack.BuildTimeline
// over INDIVIDUAL events, and a bucket cannot be un-bucketed. This seam ships
// the events themselves so the org runs the same pure builder over the same
// rows.
//
// THE GATE LIVES HERE TOO, NOT ONLY AT THE CALL SITE. SelectSessionCacheEvents
// takes the whole ShareOptions and returns NOTHING unless share.
// shipsRawContent(). orgpush.go already composes it inside its own
// shipsRawContent() block, so this is a second, structural refusal rather than
// the only one: a future caller that forgets the outer gate still cannot get
// per-event cache rows out of this function. Note the tier is deliberately
// shipsRawContent(), NOT ShareOptions.CacheDetail — cache_detail gates the
// content-free FLEET aggregate and stays orthogonal in both directions.
//
// THE `detail` COLUMN IS NEVER SELECTED. cache_events.detail is the engine's
// bounded diagnostic JSON: no stable schema, no org reader, no honest
// retention story. It is absent from the SELECT list, so there is no window in
// which it sits in a wire row awaiting a strip step someone could forget —
// the same structural discipline toolaccountsummary.go uses for the identity
// half. api_turn_id / token_usage_id are likewise not selected (node-local row
// ids with no org referent), and the cache SCOPE / PREFIX hashes live in
// tables this file does not read at all.

// sessionCacheEventWindowDays bounds the recompute to events in the trailing
// window. Seven days, matching sessionCacheWindowDays so a session's bucketed
// summary and its per-event timeline always cover the same horizon — a
// timeline that ended before its own summary did would read as data loss.
const sessionCacheEventWindowDays = 7

// sessionCacheEventCap is the per-session cap on how many events this query
// returns, enforced IN SQL via ROW_NUMBER() OVER (PARTITION BY session_id
// ORDER BY timestamp DESC, id DESC) so discarded rows never reach the Go scan.
// It is the one place this wire's cardinality is bounded at the source: unlike
// its two bucketed siblings, this family is one row per cache-touching turn,
// and a long warm session produces hundreds.
//
// 500 tracks sessionNetworkEventCap and the node's own list-surface ceiling:
// the org wire never ships more per-session detail than the node dashboard is
// itself willing to render. MOST-RECENT-FIRST is the right direction to cut
// because BuildTimeline collapses old baseline runs anyway, so the tail that
// gets dropped is the one a reader is least able to act on.
const sessionCacheEventCap = 500

// sessionCacheEventsQuery is held as a const so cacheeventorgrows_test.go can
// assert its shape (no `detail`, no anchor ids) against the source text rather
// than only against scanned values.
//
// The window predicate is applied INSIDE the ROW_NUMBER subquery so the cap is
// taken over the windowed rows, not over all history.
const sessionCacheEventsQuery = `
	SELECT session_id, id, tier, timestamp, model, kind, cause,
	       diverged_seq, diverged_level,
	       tokens_read, tokens_written, tokens_written_1h,
	       cost_delta_usd, predicted_kind, message_id
	  FROM (
	        SELECT session_id, id, tier, timestamp, model, kind, cause,
	               diverged_seq, diverged_level,
	               tokens_read, tokens_written, tokens_written_1h,
	               cost_delta_usd, predicted_kind, message_id,
	               ROW_NUMBER() OVER (PARTITION BY session_id ORDER BY timestamp DESC, id DESC) AS rn
	          FROM cache_events
	         WHERE timestamp >= ?
	       )
	 WHERE rn <= ?
	 ORDER BY session_id, timestamp, id`

// SelectSessionCacheEvents returns every cache event recorded in the trailing
// sessionCacheEventWindowDays window, capped per session, for a node whose
// share posture ships raw content. It returns an EMPTY slice — never an
// error — for any other posture.
//
// WINDOW, NOT CURSOR — a deliberate trade-off. Every other snapshot wire in
// this family (SelectSessionCacheSummaries, SelectSessionToolAccounts,
// SelectSessionProcessRows) recomputes a bounded trailing window and relies on
// the server's upsert for idempotence, and this one does the same. A true
// cursor would mean a seventh field on store.PushCursor, which is persisted
// through schema_meta keys declared IN orgpush.go and seeded by
// CurrentMaxIDs' MAX(id) query there — both of which would put the
// cache_events name inside the file the privacy sentinel forbids it in, and
// the six-field cursor is additionally pinned by the enrolment high-water and
// CAS paths. The cost of the window is that already-delivered events are
// re-sent for up to seven days; that is bounded, and it is free of duplication
// because migration 142's natural key is (org_id, pushed_by_user_id,
// node_event_id) — the node's own row id, scoped by pusher. The Track R2 snap
// gate (probeCacheEvents, MAX(id) over the same append-only log) already
// suppresses the recompute entirely on ticks where nothing new was observed,
// so the steady-state cost is one O(1) probe, not a window scan.
func (s *Store) SelectSessionCacheEvents(ctx context.Context, share ShareOptions) ([]orgcontract.SessionCacheEventRow, error) {
	out := []orgcontract.SessionCacheEventRow{}
	if !share.shipsRawContent() {
		return out, nil
	}
	since := timestamp(time.Now().UTC().AddDate(0, 0, -sessionCacheEventWindowDays))
	rows, err := s.db.QueryContext(ctx, sessionCacheEventsQuery, since, sessionCacheEventCap)
	if err != nil {
		return nil, fmt.Errorf("store.SelectSessionCacheEvents: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			r             orgcontract.SessionCacheEventRow
			cause         sql.NullString
			divergedSeq   sql.NullInt64
			divergedLevel sql.NullString
			costDelta     sql.NullFloat64
			predictedKind sql.NullString
			messageID     sql.NullString
		)
		if err := rows.Scan(&r.SessionID, &r.NodeEventID, &r.Tier, &r.Timestamp,
			&r.Model, &r.Kind, &cause,
			&divergedSeq, &divergedLevel,
			&r.TokensRead, &r.TokensWritten, &r.TokensWritten1H,
			&costDelta, &predictedKind, &messageID); err != nil {
			return nil, fmt.Errorf("store.SelectSessionCacheEvents: scan: %w", err)
		}
		r.Cause = cause.String
		r.DivergedLevel = divergedLevel.String
		r.PredictedKind = predictedKind.String
		r.MessageID = messageID.String
		// The two numerics keep their NULL: nil = the engine did not compute
		// it, and 0 is a REAL reading for both (block 0 diverged / a zero cost
		// delta). Flattening either onto 0 would make the org timeline claim
		// something the node never said.
		if divergedSeq.Valid {
			v := divergedSeq.Int64
			r.DivergedSeq = &v
		}
		if costDelta.Valid {
			v := costDelta.Float64
			r.CostDeltaUSD = &v
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SelectSessionCacheEvents: %w", err)
	}
	return out, nil
}
