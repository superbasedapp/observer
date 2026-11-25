package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cachetrack"
)

// Cache-tracking persistence helpers per docs/plans/
// cache-tracking-implementation-spec-2026-06-08.md §C5.
//
// Three tables back the cachetrack subsystem (migration 036):
//
//   cache_segments — points of interest on the per-turn prefix-
//                    hash chain. Append-only; ≤ ~6 rows/turn.
//   cache_entries  — the modelled live provider cache, keyed by
//                    UNIQUE(model, cache_scope, prefix_hash).
//   cache_events   — per-turn reconciliation verdict + cause
//                    attribution.
//
// PRIVACY INVARIANT — these three tables are NODE-LOCAL in P0–P2:
// they MUST NOT appear in internal/store/orgpush.go::
// SelectUnpushedSince. The privacy sentinel in tests/invariant
// (C11) extends to cover them; any future wire addition fails
// loudly. CLAUDE.md no-content-in-DB Don't also applies — these
// columns store hashes / counts / enum strings / refs only.
//
// MODULE-BOUNDARY NOTE — the row types defined here are the
// store's own SQL-shaped types, NOT cachetrack domain types
// (spec §24.2: cachetrack types do not leak past the engine
// seam). The engine constructs these row values at the
// boundary (in C8 for proxy, C7 for transcript) before calling
// the helpers below.

// CacheSegmentRow is one row of cache_segments. APITurnID and
// TokenUsageID are mutually exclusive: tier='proxy' rows set
// APITurnID, tier='transcript' / tier='counts' rows set
// TokenUsageID. Use nil-int64 pointers to land NULL.
type CacheSegmentRow struct {
	SessionID     string
	APITurnID     *int64
	TokenUsageID  *int64
	Tier          string
	Model         string
	Seq           int
	Level         string
	BlockKind     string
	PrefixHash    string
	TokenEstimate *int
	IsBreakpoint  bool
	TTLTier       string
	SourceRef     string
	CreatedAt     time.Time
}

// CacheEntryRow is one row of cache_entries. The UNIQUE
// (model, cache_scope, prefix_hash) constraint drives the
// upsert path in UpsertCacheEntries: a row whose key collides
// with an existing entry updates the engine-observed fields
// (token_count, ttl_tier, last_refresh_at, expires_at, state,
// session_id) rather than failing the insert.
type CacheEntryRow struct {
	Model         string
	CacheScope    string
	SessionID     string
	PrefixHash    string
	TokenCount    int64
	TTLTier       string
	Tier          string
	CreatedAt     time.Time
	LastRefreshAt time.Time
	ExpiresAt     time.Time
	State         string
}

// CacheEventRow is one row of cache_events. DivergedSeq is a
// pointer so the engine can land NULL when no seq applies
// (the §7 row 9 block-diverged case is the only one that sets
// a value). CostDeltaUSD is similarly nullable (the engine
// computes it via internal/intelligence/cost in C9).
type CacheEventRow struct {
	SessionID       string
	APITurnID       *int64
	TokenUsageID    *int64
	Tier            string
	Timestamp       time.Time
	Model           string
	Kind            string
	Cause           string
	DivergedSeq     *int
	DivergedLevel   string
	TokensRead      int64
	TokensWritten   int64
	TokensWritten1h int64
	CostDeltaUSD    *float64
	PredictedKind   string
	Detail          string
	// MessageID is the upstream message identifier (`msg_xxx`
	// for Anthropic) that anchors this event independent of the
	// tier. Tier-1 (proxy) rows ALSO have this set via the
	// api_turns.request_id join, but stamping it on the row
	// directly lets the cross-tier dedup gate work without a
	// JOIN. Empty for non-Anthropic providers that don't
	// surface a per-turn message identifier.
	MessageID string
}

const insertCacheSegmentSQL = `
INSERT INTO cache_segments (
    session_id, api_turn_id, token_usage_id, tier, model,
    seq, level, block_kind, prefix_hash, token_estimate,
    is_breakpoint, ttl_tier, source_ref, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// InsertCacheSegments batches an INSERT of cache_segments rows
// inside a single transaction. Returns the count actually
// written. A failure aborts the whole batch (the txn rolls back);
// individual-row tolerance lives at the engine layer, not here.
//
// Caller invariant: per row exactly one of APITurnID /
// TokenUsageID should be non-nil; the table accepts both NULL
// but a row with both unset has no anchor and the dashboard
// timeline can't render it.
func (s *Store) InsertCacheSegments(ctx context.Context, segments []CacheSegmentRow) (int, error) {
	if len(segments) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.InsertCacheSegments: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, insertCacheSegmentSQL)
	if err != nil {
		return 0, fmt.Errorf("store.InsertCacheSegments: prepare: %w", err)
	}
	defer stmt.Close()

	for i := range segments {
		seg := &segments[i]
		if _, err := stmt.ExecContext(
			ctx,
			seg.SessionID,
			nullableInt64Ptr(seg.APITurnID),
			nullableInt64Ptr(seg.TokenUsageID),
			seg.Tier, seg.Model, seg.Seq, seg.Level,
			nullableString(seg.BlockKind),
			seg.PrefixHash,
			nullableIntPtr(seg.TokenEstimate),
			boolInt(seg.IsBreakpoint),
			nullableString(seg.TTLTier),
			nullableString(seg.SourceRef),
			timestamp(seg.CreatedAt),
		); err != nil {
			return 0, fmt.Errorf("store.InsertCacheSegments: exec[%d]: %w", i, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.InsertCacheSegments: commit: %w", err)
	}
	return len(segments), nil
}

const upsertCacheEntrySQL = `
INSERT INTO cache_entries (
    model, cache_scope, session_id, prefix_hash, token_count,
    ttl_tier, tier, created_at, last_refresh_at, expires_at, state
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(model, cache_scope, prefix_hash) DO UPDATE SET
    session_id      = excluded.session_id,
    token_count     = excluded.token_count,
    ttl_tier        = excluded.ttl_tier,
    last_refresh_at = excluded.last_refresh_at,
    expires_at      = excluded.expires_at,
    state           = excluded.state`

// UpsertCacheEntries inserts or updates cache_entries rows
// keyed by UNIQUE(model, cache_scope, prefix_hash). On conflict
// the engine-observed fields (token_count, ttl_tier,
// last_refresh_at, expires_at, state, session_id) take the new
// value; immutable identity (model, cache_scope, prefix_hash)
// and provenance (tier, created_at) are preserved by NOT
// listing them in the DO UPDATE set. Returns the count of rows
// processed (not just inserted — SQLite's RowsAffected counts
// upserts as 1 on the DO UPDATE branch too, which is the count
// we want for the maintenance audit).
func (s *Store) UpsertCacheEntries(ctx context.Context, entries []CacheEntryRow) (int, error) {
	if len(entries) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.UpsertCacheEntries: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, upsertCacheEntrySQL)
	if err != nil {
		return 0, fmt.Errorf("store.UpsertCacheEntries: prepare: %w", err)
	}
	defer stmt.Close()

	for i := range entries {
		e := &entries[i]
		if _, err := stmt.ExecContext(
			ctx,
			e.Model, e.CacheScope, nullableString(e.SessionID), e.PrefixHash,
			e.TokenCount, e.TTLTier, e.Tier,
			timestamp(e.CreatedAt), timestamp(e.LastRefreshAt), timestamp(e.ExpiresAt),
			e.State,
		); err != nil {
			return 0, fmt.Errorf("store.UpsertCacheEntries: exec[%d]: %w", i, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.UpsertCacheEntries: commit: %w", err)
	}
	return len(entries), nil
}

const insertCacheEventSQL = `
INSERT INTO cache_events (
    session_id, api_turn_id, token_usage_id, tier, timestamp, model,
    kind, cause, diverged_seq, diverged_level,
    tokens_read, tokens_written, tokens_written_1h,
    cost_delta_usd, predicted_kind, detail, message_id
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// InsertCacheEvents batches an INSERT of cache_events rows in a
// single transaction. Returns the count written.
//
// No UNIQUE constraint on the table — the engine is the single
// writer and produces one event per logical turn outcome; the
// cross-tier dedup gate (CacheEventExistsForMessage) prevents
// duplicate emission when a session is both proxied AND watched.
// In-tier idempotency lives at the engine boundary (C7/C8 check
// the gate before construct-and-emit).
func (s *Store) InsertCacheEvents(ctx context.Context, events []CacheEventRow) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.InsertCacheEvents: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, insertCacheEventSQL)
	if err != nil {
		return 0, fmt.Errorf("store.InsertCacheEvents: prepare: %w", err)
	}
	defer stmt.Close()

	for i := range events {
		ev := &events[i]
		if _, err := stmt.ExecContext(
			ctx,
			ev.SessionID,
			nullableInt64Ptr(ev.APITurnID),
			nullableInt64Ptr(ev.TokenUsageID),
			ev.Tier, timestamp(ev.Timestamp), ev.Model,
			ev.Kind, nullableString(ev.Cause),
			nullableIntPtr(ev.DivergedSeq),
			nullableString(ev.DivergedLevel),
			ev.TokensRead, ev.TokensWritten, ev.TokensWritten1h,
			nullableFloat64Ptr(ev.CostDeltaUSD),
			nullableString(ev.PredictedKind),
			nullableString(ev.Detail),
			nullableString(ev.MessageID),
		); err != nil {
			return 0, fmt.Errorf("store.InsertCacheEvents: exec[%d]: %w", i, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.InsertCacheEvents: commit: %w", err)
	}
	return len(events), nil
}

// CacheEventExistsForMessage is the §9 / §4 dedup gate: returns
// true when at least one cache_events row exists for the
// session+message tuple regardless of tier. Two lookups OR'd:
//
//   - Tier-1 path: join cache_events.api_turn_id ↔ api_turns.id
//     and match api_turns.request_id = ? (proxy stamps the
//     upstream message_id onto api_turns.request_id).
//   - Tier-2 path: direct match on cache_events.message_id (the
//     transcript-tier column added in migration 037).
//
// Tier-1 backfilled rows pre-037 leave message_id NULL but still
// match through the first arm — the join keeps them covered.
// Tier-2 rows always set message_id; the partial index
// idx_cache_events_msgid makes the second arm fast.
//
// An empty messageID yields false (the gate can only dedupe
// when the caller can identify the logical turn). Both Tier-2
// idempotent backfill AND the live cross-tier dedup (proxy
// observed, watcher would re-observe) rely on this.
func (s *Store) CacheEventExistsForMessage(ctx context.Context, sessionID, messageID string) (bool, error) {
	if sessionID == "" || messageID == "" {
		return false, nil
	}
	const q = `
		SELECT 1
		FROM cache_events ce
		LEFT JOIN api_turns t ON t.id = ce.api_turn_id
		WHERE ce.session_id = ?
		  AND ((ce.tier = 'proxy' AND t.request_id = ?)
		    OR (ce.message_id = ?))
		LIMIT 1`
	var one int
	switch err := s.db.QueryRowContext(ctx, q, sessionID, messageID, messageID).Scan(&one); {
	case err == nil:
		return true, nil
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	default:
		return false, fmt.Errorf("store.CacheEventExistsForMessage: %w", err)
	}
}

// CacheWindowOpts bounds a LoadLiveCacheWindows read.
type CacheWindowOpts struct {
	// SessionID restricts to one creating session; "" returns all.
	SessionID string
	// Now is the evaluation clock for the cold-grace filter. Zero uses
	// time.Now().UTC() at call time.
	Now time.Time
	// ColdGrace bounds how far past expiry an entry may be and still be
	// returned (so a status surface can show "recently cold"). Recency is
	// judged by expires_at, NOT the state column: the engine only sweeps
	// state→'expired' on an observed turn, so an idle session leaves
	// long-dead entries stuck at state='live'. Filtering on expires_at is
	// therefore the only reliable warm-vs-stale cut. Zero returns ONLY
	// entries still warm (expires_at >= Now); any positive value also
	// returns entries that expired within ColdGrace of Now.
	ColdGrace time.Duration
	// Limit caps the row count (newest-expiry-first). Zero = no cap.
	Limit int
}

// LoadLiveCacheWindows returns the cache_entries the warning system
// reasons over: entries still warm (expires_at >= Now) plus — when
// ColdGrace > 0 — recently-cold ones (expired within ColdGrace). Rows
// are ordered by expires_at ascending (soonest-to-die first) and capped
// by Limit. Empty result is not an error.
//
// Recency is gated by expires_at, NOT the state column. The engine only
// flips state→'expired' on an observed turn, so an idle session strands
// long-dead entries at state='live'. Trusting state would let those
// stale rows — which sort FIRST under expires_at ASC — consume the whole
// Limit and starve out the genuinely-warm caches, returning an empty
// status surface even while live caches exist (the bug this filter
// closes). Terminal states (invalidated/dropped) are excluded outright.
//
// This is a READ-ONLY surface over node-local cache state; it adds no
// wire column and is never pushed to an org server.
func (s *Store) LoadLiveCacheWindows(ctx context.Context, opts CacheWindowOpts) ([]CacheEntryRow, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	// cutoff = the oldest expires_at still surfaced. ColdGrace==0 ⇒ cutoff
	// is `now`, so only warm entries (expires_at >= now) qualify; a
	// positive ColdGrace also admits entries that went cold within the
	// grace window.
	cutoff := timestamp(now.Add(-opts.ColdGrace))

	var sb strings.Builder
	sb.WriteString(`
		SELECT model, cache_scope, COALESCE(session_id, ''),
		       prefix_hash, token_count, ttl_tier, tier,
		       created_at, last_refresh_at, expires_at, state
		FROM cache_entries
		WHERE state IN ('live','unverified','expired')
		      AND expires_at >= ?`)
	args := []any{cutoff}
	if opts.SessionID != "" {
		sb.WriteString(" AND session_id = ?")
		args = append(args, opts.SessionID)
	}
	sb.WriteString(" ORDER BY expires_at ASC, id ASC")
	if opts.Limit > 0 {
		sb.WriteString(" LIMIT ?")
		args = append(args, opts.Limit)
	}

	rows, err := s.db.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("store.LoadLiveCacheWindows: query: %w", err)
	}
	defer rows.Close()
	var out []CacheEntryRow
	for rows.Next() {
		var r CacheEntryRow
		var createdAt, lastRefreshAt, expiresAt string
		if err := rows.Scan(
			&r.Model, &r.CacheScope, &r.SessionID,
			&r.PrefixHash, &r.TokenCount, &r.TTLTier, &r.Tier,
			&createdAt, &lastRefreshAt, &expiresAt, &r.State,
		); err != nil {
			return nil, fmt.Errorf("store.LoadLiveCacheWindows: scan: %w", err)
		}
		r.CreatedAt = parseStamp(createdAt)
		r.LastRefreshAt = parseStamp(lastRefreshAt)
		r.ExpiresAt = parseStamp(expiresAt)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadLiveCacheWindows: rows: %w", err)
	}
	return out, nil
}

// ImplicitCacheActivity is the latest implicit-cache observation for one
// (session, model). Implicit (OpenAI/Codex) caches are anonymous and have
// NO addressable entry and NO provider-reported TTL, so they never land in
// cache_entries — only cache_events. The cache-expiry surface synthesizes a
// warm window from this: expiry is ESTIMATED as LastActivity + an idle
// window (see [config.CacheWarmConfig.ImplicitIdleSeconds]); the warm
// prefix at risk is PrefixTokens (the cached_tokens read on the most recent
// hit). Resolved to a window at the cachewarmsvc boundary.
type ImplicitCacheActivity struct {
	SessionID    string
	Model        string
	Tier         string
	PrefixTokens int64
	LastActivity time.Time
}

// LoadImplicitCacheActivity returns, per (session, model), the most recent
// implicit-cache hit/write — the basis for an ESTIMATED warm window for
// OpenAI/Codex sessions (which expose no TTL, so cache_entries is empty for
// them). implicit_miss is excluded: a miss means the prefix was NOT cached
// that turn, so it is not evidence of a live warm cache.
//
// A 24h recency ceiling bounds the scan (the documented max implicit
// lifetime is 24h for extended-retention models); precise warm-vs-cold is
// decided downstream from LastActivity + the configured idle window. Uses
// SQLite's bare-column-with-MAX(timestamp) to take token counts from the
// latest row of each group. Empty result is not an error.
func (s *Store) LoadImplicitCacheActivity(ctx context.Context, opts CacheWindowOpts) ([]ImplicitCacheActivity, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ceiling := timestamp(now.Add(-24 * time.Hour))

	var sb strings.Builder
	sb.WriteString(`
		SELECT session_id, model, tier,
		       MAX(timestamp) AS last_ts,
		       tokens_read, tokens_written
		FROM cache_events
		WHERE kind IN ('implicit_hit','implicit_write')
		      AND timestamp >= ?`)
	args := []any{ceiling}
	if opts.SessionID != "" {
		sb.WriteString(" AND session_id = ?")
		args = append(args, opts.SessionID)
	}
	sb.WriteString(" GROUP BY session_id, model")

	rows, err := s.db.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("store.LoadImplicitCacheActivity: query: %w", err)
	}
	defer rows.Close()
	var out []ImplicitCacheActivity
	for rows.Next() {
		var a ImplicitCacheActivity
		var lastTS string
		var read, written int64
		if err := rows.Scan(&a.SessionID, &a.Model, &a.Tier, &lastTS, &read, &written); err != nil {
			return nil, fmt.Errorf("store.LoadImplicitCacheActivity: scan: %w", err)
		}
		a.LastActivity = parseStamp(lastTS)
		a.PrefixTokens = read
		if written > a.PrefixTokens {
			a.PrefixTokens = written
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadImplicitCacheActivity: rows: %w", err)
	}
	return out, nil
}

// LoadCacheEntriesForScope returns all cache_entries rows for a
// (model, cache_scope) pair, ordered by created_at ascending.
// Used by the engine at daemon-restart re-anchor time to
// rebuild its in-memory state from persisted entries — and by
// the dashboard (C13) for the per-session cache panel.
func (s *Store) LoadCacheEntriesForScope(ctx context.Context, model, cacheScope string) ([]CacheEntryRow, error) {
	const q = `
		SELECT model, cache_scope, COALESCE(session_id, ''),
		       prefix_hash, token_count, ttl_tier, tier,
		       created_at, last_refresh_at, expires_at, state
		FROM cache_entries
		WHERE model = ? AND cache_scope = ?
		ORDER BY created_at ASC, id ASC`
	rows, err := s.db.QueryContext(ctx, q, model, cacheScope)
	if err != nil {
		return nil, fmt.Errorf("store.LoadCacheEntriesForScope: query: %w", err)
	}
	defer rows.Close()
	var out []CacheEntryRow
	for rows.Next() {
		var r CacheEntryRow
		var createdAt, lastRefreshAt, expiresAt string
		if err := rows.Scan(
			&r.Model, &r.CacheScope, &r.SessionID,
			&r.PrefixHash, &r.TokenCount, &r.TTLTier, &r.Tier,
			&createdAt, &lastRefreshAt, &expiresAt, &r.State,
		); err != nil {
			return nil, fmt.Errorf("store.LoadCacheEntriesForScope: scan: %w", err)
		}
		r.CreatedAt = parseStamp(createdAt)
		r.LastRefreshAt = parseStamp(lastRefreshAt)
		r.ExpiresAt = parseStamp(expiresAt)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadCacheEntriesForScope: rows: %w", err)
	}
	return out, nil
}

// LoadCacheEventsForSession returns all cache_events for a
// session, ordered by timestamp ascending then id. Used by the
// dashboard cache-panel API (C13). Empty result is not an error.
func (s *Store) LoadCacheEventsForSession(ctx context.Context, sessionID string) ([]CacheEventRow, error) {
	const q = `
		SELECT session_id, api_turn_id, token_usage_id, tier, timestamp, model,
		       kind, COALESCE(cause, ''),
		       diverged_seq, COALESCE(diverged_level, ''),
		       tokens_read, tokens_written, tokens_written_1h,
		       cost_delta_usd, COALESCE(predicted_kind, ''), COALESCE(detail, '')
		FROM cache_events
		WHERE session_id = ?
		ORDER BY timestamp ASC, id ASC`
	rows, err := s.db.QueryContext(ctx, q, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadCacheEventsForSession: query: %w", err)
	}
	defer rows.Close()
	var out []CacheEventRow
	for rows.Next() {
		var r CacheEventRow
		var ts string
		var apiTurnID, tokenUsageID sql.NullInt64
		var divergedSeq sql.NullInt64
		var costDelta sql.NullFloat64
		if err := rows.Scan(
			&r.SessionID, &apiTurnID, &tokenUsageID, &r.Tier, &ts, &r.Model,
			&r.Kind, &r.Cause,
			&divergedSeq, &r.DivergedLevel,
			&r.TokensRead, &r.TokensWritten, &r.TokensWritten1h,
			&costDelta, &r.PredictedKind, &r.Detail,
		); err != nil {
			return nil, fmt.Errorf("store.LoadCacheEventsForSession: scan: %w", err)
		}
		r.Timestamp = parseStamp(ts)
		if apiTurnID.Valid {
			v := apiTurnID.Int64
			r.APITurnID = &v
		}
		if tokenUsageID.Valid {
			v := tokenUsageID.Int64
			r.TokenUsageID = &v
		}
		if divergedSeq.Valid {
			v := int(divergedSeq.Int64)
			r.DivergedSeq = &v
		}
		if costDelta.Valid {
			v := costDelta.Float64
			r.CostDeltaUSD = &v
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadCacheEventsForSession: rows: %w", err)
	}
	return out, nil
}

// PruneCacheRows removes:
//
//   - cache_segments AND cache_events older than retentionDays;
//   - cache_entries in terminal states (expired, invalidated,
//     unverified) whose last_refresh_at is older than
//     terminalEntryRetentionDays.
//
// Called from the daemon maintenance tick (the long-running
// retention sweep already handles other tables). Returns the
// total count of rows removed across all three tables.
//
// A retentionDays of 0 or negative is treated as "no prune" and
// returns 0; that lets the caller pass cfg.RetentionDays
// straight through without a special-case branch.
func (s *Store) PruneCacheRows(ctx context.Context, retentionDays int) (int, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	const terminalEntryRetentionDays = 14
	now := time.Now().UTC()
	segmentsCutoff := timestamp(now.Add(-time.Duration(retentionDays) * 24 * time.Hour))
	entriesCutoff := timestamp(now.Add(-time.Duration(terminalEntryRetentionDays) * 24 * time.Hour))

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.PruneCacheRows: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var removed int

	r, err := tx.ExecContext(ctx, `DELETE FROM cache_segments WHERE created_at < ?`, segmentsCutoff)
	if err != nil {
		return 0, fmt.Errorf("store.PruneCacheRows: segments: %w", err)
	}
	n, _ := r.RowsAffected()
	removed += int(n)

	r, err = tx.ExecContext(ctx, `DELETE FROM cache_events WHERE timestamp < ?`, segmentsCutoff)
	if err != nil {
		return 0, fmt.Errorf("store.PruneCacheRows: events: %w", err)
	}
	n, _ = r.RowsAffected()
	removed += int(n)

	r, err = tx.ExecContext(ctx,
		`DELETE FROM cache_entries
		 WHERE state IN ('expired','invalidated','unverified')
		   AND last_refresh_at < ?`,
		entriesCutoff)
	if err != nil {
		return 0, fmt.Errorf("store.PruneCacheRows: entries: %w", err)
	}
	n, _ = r.RowsAffected()
	removed += int(n)

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.PruneCacheRows: commit: %w", err)
	}
	return removed, nil
}

// PersistCacheObservation translates a cachetrack ObserveResult
// into the cache_segments + cache_entries + cache_events rows
// and persists them. Each helper owns its own transaction
// (failure isolation: one table's write failing does NOT block
// the others); cache_events writes are last so even a partial
// failure leaves a diagnostic event row.
//
// Implements the [proxy.CacheSink] interface. The proxy never
// holds row-shaped types — translation happens here at the
// store seam (spec §24.2: cachetrack types ObserveInput +
// ObserveResult are the seam types; row types are store-local).
//
// Exactly one of apiTurnID / tokenUsageID is non-zero per call
// (mutually-exclusive cache_segments + cache_events anchors per
// the schema's column comments). Proxy callers pass
// (apiTurnID > 0, 0); Tier-2 backfill / ingest callers pass
// (0, tokenUsageID), where tokenUsageID may itself be 0 when the
// observation's token_usage row was not resolved at insert time
// (the cache rows then carry NULL on both anchors — still
// queryable by session_id + timestamp, just not joinable).
func (s *Store) PersistCacheObservation(ctx context.Context, in cachetrack.ObserveInput, result cachetrack.ObserveResult, apiTurnID, tokenUsageID int64) error {
	segs := make([]CacheSegmentRow, 0, len(result.Segments))
	for _, seg := range result.Segments {
		row := CacheSegmentRow{
			SessionID:    in.SessionID,
			Tier:         in.Tier.String(),
			Model:        in.Model,
			Seq:          seg.Seq,
			Level:        seg.Level.String(),
			BlockKind:    seg.Kind,
			PrefixHash:   seg.PrefixHash,
			IsBreakpoint: seg.IsBreakpoint,
			TTLTier:      seg.TTL.String(),
			CreatedAt:    in.Now,
		}
		if apiTurnID != 0 {
			id := apiTurnID
			row.APITurnID = &id
		}
		if tokenUsageID != 0 {
			id := tokenUsageID
			row.TokenUsageID = &id
		}
		if seg.TokenEstimate > 0 {
			te := seg.TokenEstimate
			row.TokenEstimate = &te
		}
		segs = append(segs, row)
	}
	if _, err := s.InsertCacheSegments(ctx, segs); err != nil {
		return fmt.Errorf("store.PersistCacheObservation: segments: %w", err)
	}

	entries := make([]CacheEntryRow, 0, len(result.Entries))
	for _, e := range result.Entries {
		entries = append(entries, CacheEntryRow{
			Model:         in.Model,
			CacheScope:    in.Scope,
			SessionID:     in.SessionID,
			PrefixHash:    e.PrefixHash,
			TokenCount:    e.TokenCount,
			TTLTier:       e.TTL.String(),
			Tier:          in.Tier.String(),
			CreatedAt:     e.CreatedAt,
			LastRefreshAt: e.LastRefreshAt,
			ExpiresAt:     e.ExpiresAt,
			State:         e.State.String(),
		})
	}
	if _, err := s.UpsertCacheEntries(ctx, entries); err != nil {
		return fmt.Errorf("store.PersistCacheObservation: entries: %w", err)
	}

	events := make([]CacheEventRow, 0, len(result.Events))
	for _, ev := range result.Events {
		row := CacheEventRow{
			SessionID:       in.SessionID,
			Tier:            in.Tier.String(),
			Timestamp:       ev.Timestamp,
			Model:           in.Model,
			Kind:            string(ev.Outcome.Kind),
			Cause:           string(ev.Outcome.Cause),
			DivergedLevel:   ev.Outcome.DivergedLevel.String(),
			TokensRead:      ev.TokensRead,
			TokensWritten:   ev.TokensWritten,
			TokensWritten1h: ev.TokensWritten1h,
			PredictedKind:   string(ev.PredictedKind),
			MessageID:       in.MessageID,
		}
		if apiTurnID != 0 {
			id := apiTurnID
			row.APITurnID = &id
		}
		if tokenUsageID != 0 {
			id := tokenUsageID
			row.TokenUsageID = &id
		}
		if ev.Outcome.DivergedSeq >= 0 {
			ds := ev.Outcome.DivergedSeq
			row.DivergedSeq = &ds
		}
		events = append(events, row)
	}
	if _, err := s.InsertCacheEvents(ctx, events); err != nil {
		return fmt.Errorf("store.PersistCacheObservation: events: %w", err)
	}
	return nil
}

// parseStamp decodes the RFC3339-ish UTC string format the
// store uses for all timestamps via [timestamp]. An empty
// string round-trips to the zero time.Time. Parse failures
// return the zero time too — the cache-panel UI handles zero
// times by hiding the column, so an unparseable stamp
// degrades gracefully rather than failing the whole query.
func parseStamp(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	// internal/store::timestamp emits time.RFC3339Nano-compatible
	// values; the live DB has both that and the older Z-suffixed
	// RFC3339. Try the looser parser first.
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC()
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC()
	}
	// Last-ditch: SQLite's default "YYYY-MM-DD HH:MM:SS" form.
	if t, err := time.Parse("2006-01-02 15:04:05", strings.TrimSpace(s)); err == nil {
		return t.UTC()
	}
	return time.Time{}
}
