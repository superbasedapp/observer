// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// orgsnapoversize.go persists the snapshot paging gate's oversized-row report
// (orgsnapgate.go) so an operator sees it where they look: `observer org
// status` and the doctor org enrolment check. The gate lives in the daemon;
// those commands run in another process, so the report goes through one
// node-local schema_meta key. It holds family names, counts and sizes only,
// never row content. Every pusher (the daemon, or a CLI or dashboard push-now
// with its own gate) merges what its compose observed into it, so no pusher
// can erase what another saw without having looked at the whole family.

// OrgPushOversizedKey is the schema_meta key holding the JSON report. The
// doctor reads it directly (internal/diag keeps its own SQL), so the key and
// the JSON field names are a contract, pinned by
// TestOrgPushOversizedReportShape.
const OrgPushOversizedKey = "org_push_oversized_rows"

// OrgPushOversizedRow is one snapshot family's oversized-row report: rows that
// are larger than the whole snapshot budget ([org_client] max_push_bytes minus
// the envelope reserve) and so can never ship.
type OrgPushOversizedRow struct {
	Family       string `json:"family"`
	Rows         int64  `json:"rows"`
	LargestBytes int64  `json:"largest_bytes"`
	BudgetBytes  int64  `json:"budget_bytes"`
	// LastSeen is when the daemon last met a new oversized row (RFC 3339).
	LastSeen string `json:"last_seen"`
}

// Summary is the one-line operator rendering.
func (r OrgPushOversizedRow) Summary() string {
	return fmt.Sprintf("%s: %d row(s) larger than the %d-byte snapshot budget (largest %d bytes, last %s); raise [org_client] max_push_bytes to ship them",
		r.Family, r.Rows, r.BudgetBytes, r.LargestBytes, r.LastSeen)
}

// persistOrgPushOversized folds this compose's observations into the
// persisted report, family by family, by one ordered rule table:
//
//  1. the compose did not recompute the family: keep its entry (this compose
//     learned nothing; a CLI push-now whose gate skipped it must not erase
//     what the daemon saw);
//  2. the compose met oversized rows: write the entry (whichever pusher saw
//     them rewrites it, the daemon included, on every compose that meets
//     them); a complete compose states the exact count, a truncated one never
//     lowers the stored count;
//  3. the compose looked at every row and met none: drop the entry (the row
//     is gone, or a raised budget now fits it);
//  4. otherwise (truncated before it met any): keep the entry.
//
// An empty report removes the key. Best effort: the report is diagnostics,
// and a failed read or write only leaves the previous report in place.
func (s *Store) persistOrgPushOversized(ctx context.Context) {
	obs := s.snap.oversizeObservations()
	if len(obs) == 0 {
		return
	}
	current, err := s.LoadOrgPushOversizedRows(ctx)
	if err != nil {
		return
	}
	byFam := make(map[string]OrgPushOversizedRow, len(current))
	for _, r := range current {
		byFam[r.Family] = r
	}
	changed := false
	now := time.Now().UTC().Format(time.RFC3339)
	for fam, o := range obs {
		name := string(fam)
		prev, had := byFam[name]
		switch {
		case !o.ticked:
			continue
		case o.rows > 0:
			next := OrgPushOversizedRow{Family: name, Rows: o.rows, LargestBytes: o.largest, BudgetBytes: o.budget, LastSeen: now}
			if had && !o.complete {
				next.Rows = max(next.Rows, prev.Rows)
				next.LargestBytes = max(next.LargestBytes, prev.LargestBytes)
			}
			byFam[name], changed = next, true
		case o.complete && had:
			delete(byFam, name)
			changed = true
		}
	}
	if !changed {
		return
	}
	if len(byFam) == 0 {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM schema_meta WHERE key = ?`, OrgPushOversizedKey)
		return
	}
	rows := make([]OrgPushOversizedRow, 0, len(byFam))
	for _, r := range byFam {
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Family < rows[j].Family })
	raw, err := json.Marshal(rows)
	if err != nil {
		return
	}
	_, _ = s.db.ExecContext(ctx,
		`INSERT INTO schema_meta(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		OrgPushOversizedKey, string(raw))
}

// LoadOrgPushOversizedRows returns the persisted oversized-row report, nil
// when there is none.
func (s *Store) LoadOrgPushOversizedRows(ctx context.Context) ([]OrgPushOversizedRow, error) {
	v, err := s.readMeta(ctx, OrgPushOversizedKey)
	if err != nil {
		return nil, fmt.Errorf("store.LoadOrgPushOversizedRows: %w", err)
	}
	if v == "" {
		return nil, nil
	}
	var rows []OrgPushOversizedRow
	if err := json.Unmarshal([]byte(v), &rows); err != nil {
		return nil, fmt.Errorf("store.LoadOrgPushOversizedRows: %w", err)
	}
	return rows, nil
}
