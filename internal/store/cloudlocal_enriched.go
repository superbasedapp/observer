package store

import (
	"context"
	"fmt"
	"strings"
)

// cloudlocal_enriched.go adds a single READ-ONLY batched lookup over the
// cloud_results table for the dashboard sessions-list page: given a page of
// local session ids, return the enrichment title (if any) the node already
// holds for each — the newest non-superseded cloud_results row per session.
//
// This lives in its own file (mirroring cloudlocal_lookup.go's pattern)
// rather than as an addition to cloudlocal.go's GetCloudSessionResult, which
// answers a different question (ONE session's full result + overrides, for
// the session-detail panel) at a different cardinality. This lookup answers
// "for these N sessions, which are enriched and what's their title" — the
// shape the sessions-list page needs, batched in one round trip instead of N.
//
// FF1: internal/store is the ONE SQL owner of the cloud_* tables
// (tests/invariant/cloud_dashboard_seam_test.go). The dashboard package must
// call through this seam, never embed its own SQL against cloud_results.
//
// cloud_results is NODE-LOCAL (migration 097) and never enters the org-push
// wire; this lookup performs no write and touches no other table.

// cloudEnrichedTitlesChunkSize bounds how many session ids go into a single
// IN (...) query. SQLite's default compiled-in limit on the number of host
// parameters (SQLITE_MAX_VARIABLE_NUMBER) is commonly 999 in modern builds
// but has been as low as 99 historically; 500 stays comfortably under either
// bound while still batching almost every realistic page in one query.
const cloudEnrichedTitlesChunkSize = 500

// LoadCloudEnrichedTitles returns, for the subset of sessionIDs that have a
// current (non-superseded) cloud_results row, the enrichment title extracted
// from that row's result_json (result_json's "$.title" field; missing or
// unparsable yields the empty string, matching the prior inline behavior).
// Session ids with no cloud_results row are simply absent from the returned
// map — that is the normal "not enriched" case, not an error.
//
// The query is chunked to keep each IN (...) list under SQLite's bound-
// parameter limit; a session id present in more than one chunk's result
// (impossible in practice — ids aren't repeated across chunks) would simply
// have the last-scanned value win, same as the single-query behavior it
// replaces.
func (s *Store) LoadCloudEnrichedTitles(ctx context.Context, sessionIDs []string) (map[string]string, error) {
	titles := make(map[string]string, len(sessionIDs))
	if len(sessionIDs) == 0 {
		return titles, nil
	}

	for start := 0; start < len(sessionIDs); start += cloudEnrichedTitlesChunkSize {
		end := start + cloudEnrichedTitlesChunkSize
		if end > len(sessionIDs) {
			end = len(sessionIDs)
		}
		chunk := sessionIDs[start:end]

		args := make([]any, 0, len(chunk))
		for _, id := range chunk {
			args = append(args, id)
		}
		placeholders := strings.TrimRight(strings.Repeat("?,", len(args)), ",")

		//nolint:gosec // G202: only the ?-placeholder list is concatenated; every value is bound.
		rows, err := s.db.QueryContext(ctx,
			`SELECT session_id, COALESCE(json_extract(result_json, '$.title'), '')
			   FROM cloud_results
			  WHERE session_id IN (`+placeholders+`) AND superseded_by IS NULL`,
			args...)
		if err != nil {
			return nil, fmt.Errorf("store.LoadCloudEnrichedTitles: %w", err)
		}
		for rows.Next() {
			var sid, title string
			if err := rows.Scan(&sid, &title); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("store.LoadCloudEnrichedTitles: %w", err)
			}
			titles[sid] = title
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store.LoadCloudEnrichedTitles: %w", err)
		}
		_ = rows.Close()
	}

	return titles, nil
}
