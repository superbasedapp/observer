package store

import (
	"context"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// compressionorgrows.go is the W3.5 org-wire seam for compression
// savings/eviction (docs/plans/org-parity-full-depth-plan-2026-08-24.md §4
// "W3.5"). This file — NOT orgpush.go — owns the compression_events read (the
// privacy sentinel forbids that table name from ever appearing in
// orgpush.go; the push path composes this aggregate via a function call,
// same pattern as cachesummary.go / routingsummary.go).
//
// CONFIRMED BACKING STORE: compression_events (migration
// internal/db/migrations/009_compression_events.sql) is a durable, node-local
// SQLite table — not an in-memory-only computation. The node's own
// /api/compression/* dashboard handlers (handleCompressionEvents et al. in
// internal/intelligence/dashboard/dashboard.go) read this same table. So the
// figures this file ships are recomputed straight from the node's own
// persisted ground truth, exactly like the SavedBytes/SavedTokensEst math the
// node dashboard already performs — never a projection.
//
// Output is AGGREGATE ONLY: day × mechanism buckets with event/byte counts.
// No msg_index, no importance_score, no body_hash, no message content, no
// path — those stay node-local.

// compressionStatsWindowDays bounds the aggregate to the recent window; the
// server upserts by natural key (org_id, user_email, day, mechanism), so
// re-pushing a window is idempotent — same trailing-window recompute model as
// cacheSummaryWindowDays / routingSummaryWindowDays.
const compressionStatsWindowDays = 7

// compressionLossyMechanisms mirrors
// internal/intelligence/dashboard/compression_mechanism.go::lossyEvictionMechanisms
// exactly (currently just "drop"). It is DUPLICATED rather than imported:
// internal/store must not import internal/intelligence/dashboard (an
// HTTP-layer package) — see the CompressionStatRow doc comment in
// internal/orgcontract/compression.go for the full rationale. If the node
// ever adds a new lossy mechanism, that canonical map is the one to update
// first; this copy must follow.
var compressionLossyMechanisms = map[string]bool{
	"drop": true,
}

// SelectCompressionStatRows aggregates the compression_events log into the
// W3.5 wire rows: one row per (day, mechanism) bucket for events in the
// trailing window, replicating the SAME lossy-vs-real-savings split the
// node's own handleCompressionEvents performs per-event
// (internal/intelligence/dashboard/dashboard.go), just aggregated instead of
// per-event.
func (s *Store) SelectCompressionStatRows(ctx context.Context) ([]orgcontract.CompressionStatRow, error) {
	since := time.Now().UTC().AddDate(0, 0, -compressionStatsWindowDays)
	rows, err := s.db.QueryContext(ctx, `
		SELECT substr(timestamp, 1, 10) AS day, mechanism,
		       COUNT(*),
		       COALESCE(SUM(original_bytes), 0),
		       COALESCE(SUM(compressed_bytes), 0)
		FROM compression_events
		WHERE timestamp >= ?
		GROUP BY day, mechanism
		ORDER BY day, mechanism`, timestamp(since))
	if err != nil {
		return nil, fmt.Errorf("store.SelectCompressionStatRows: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []orgcontract.CompressionStatRow{}
	for rows.Next() {
		var r orgcontract.CompressionStatRow
		var originalBytes, compressedBytes int64
		if err := rows.Scan(&r.Day, &r.Mechanism, &r.Events, &originalBytes, &compressedBytes); err != nil {
			return nil, fmt.Errorf("store.SelectCompressionStatRows: scan: %w", err)
		}
		r.OriginalBytes = originalBytes
		r.CompressedBytes = compressedBytes
		if compressionLossyMechanisms[r.Mechanism] {
			// Lossy eviction: content is GONE, not retained smaller.
			// EvictedBytes carries the full original size; SavedBytes/
			// SavedTokensEst stay zero so eviction can never be summed
			// into a "savings" total (the retracted-claim trap).
			r.Lossy = true
			r.EvictedBytes = originalBytes
		} else {
			// Genuine compression: compressed_bytes is a real retained
			// size, so the delta is a measured saving, not a projection.
			r.SavedBytes = originalBytes - compressedBytes
			r.SavedTokensEst = r.SavedBytes / 4
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SelectCompressionStatRows: %w", err)
	}
	return out, nil
}

// probeCompressionEvents is the Track R2 change-detection probe for the
// compression_stats wire. It lives here — with the other compression_events
// SQL — so orgsnapgate.go and orgpush.go stay free of the table name.
//
// PROBE: COALESCE(MAX(id),0) — one index-endpoint seek, O(1).
//
// WHY THAT REFLECTS MUTATION: compression_events is append-only (the
// compression pipeline only ever INSERTs an event; nothing updates one).
//
// RESIDUAL, BOUNDED BY THE FRESHNESS FLOOR: retention DELETEs inside the
// trailing window are not detected until snapGate's maxSkipAge fires.
func (s *Store) probeCompressionEvents(ctx context.Context) (string, error) {
	return s.snapProbeScalar(ctx, `SELECT 'ce' || COALESCE(MAX(id), 0) FROM compression_events`)
}
