// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/scoring"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// sessionqualitysummary.go composes the session quality score org wire
// (BL2-ORG, docs/plans/post-agent-access-backlog-tracker-2026-09-27.md). It is
// a SEPARATE FILE from orgpush.go for the same reason locsummary.go is: the
// push seam composes it through a FUNCTION CALL, and the score columns (and
// this family's probe) live with their one wire reader.
//
// internal/intelligence/scoring stays the ONE writer of the score columns
// (Scorer.Write); store.LoadSessionQuality is the node card's reader. This
// file only reads, for the wire.
//
// WHY A SNAPSHOT WIRE, NOT A SESSIONS COLUMN. Sessions ship once on the rowid
// cursor; the AutoScorer writes a score only after the session has been idle
// for a while, so by then the sessions row has almost always shipped and a
// column on it would never go out. This family is windowed on scored_at
// instead of started_at, so a session scored (or re-scored) now ships on the
// next push however old the session is. The snapshot gate (orgsnapgate.go)
// skips the recompute while MAX(scored_at) is unchanged, and the server
// upserts newest-scored-wins, so re-pushing the window is idempotent.
//
// WHAT SHIPS. Only sessions the scorer actually wrote AND stamped (quality_score
// and scored_at both non-NULL). A score written before agent migration 137 has
// no scored_at, cannot be ordered against a newer one, and stays node-local
// until the session is re-scored. An unscored session ships nothing - absence,
// never a zero row.

// sessionQualityWindowDays bounds the recompute to sessions scored in the
// trailing window, matching the other session-scoped snapshot wires (LOC, task
// items, tool accounts).
const sessionQualityWindowDays = 7

// sessionQualityStampLayout is the fixed-width UTC layout the wire carries, so
// the server's text comparison of two stamps is a correct time comparison on
// SQLite and on PostgreSQL under any collation (every punctuation character
// sits at the same offset).
const sessionQualityStampLayout = "2006-01-02T15:04:05.000000000Z"

// SelectSessionQualityRows returns one row per session scored inside the
// trailing sessionQualityWindowDays window, oldest score first. scope is the
// org-push project scope: a session outside it ships no score, exactly as its
// sessions row ships nothing.
func (s *Store) SelectSessionQualityRows(ctx context.Context, scope ScopeOptions) ([]orgcontract.SessionQualityRow, error) {
	filter, noMatch, err := s.resolveScopeFilter(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("store.SelectSessionQualityRows: scope: %w", err)
	}
	if noMatch {
		return nil, nil
	}
	scopeClause := ""
	if filter != "" {
		scopeClause = " AND project_id IN (" + filter + ")"
	}
	since := time.Now().UTC().AddDate(0, 0, -sessionQualityWindowDays).Format(time.RFC3339)

	//nolint:gosec // G202: scopeClause is an integer id list built by resolveScopeFilter; values bind via ?.
	q := `
SELECT id, quality_score, redundancy_ratio, error_rate,
       exploration_efficiency, continuity_score,
       onboarding_cost, turns_to_first_edit, retry_cost_tokens,
       stale_reads_wasteful, stale_reads_necessary, redundancy_ratio_wasteful,
       scored_at, scored_action_count
  FROM sessions
 WHERE quality_score IS NOT NULL AND scored_at IS NOT NULL AND scored_at >= ?` + scopeClause + `
 ORDER BY scored_at, id`
	rows, err := s.db.QueryContext(ctx, q, since)
	if err != nil {
		return nil, fmt.Errorf("store.SelectSessionQualityRows: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []orgcontract.SessionQualityRow{}
	for rows.Next() {
		var (
			r                      orgcontract.SessionQualityRow
			rr, er, ee, cs, rrw    sql.NullFloat64
			oc, tfe, rct, srw, srn sql.NullInt64
			sac                    sql.NullInt64
			scoredAt               string
		)
		if err := rows.Scan(&r.SessionID, &r.QualityScore, &rr, &er, &ee, &cs,
			&oc, &tfe, &rct, &srw, &srn, &rrw, &scoredAt, &sac); err != nil {
			return nil, fmt.Errorf("store.SelectSessionQualityRows: scan: %w", err)
		}
		stamp, ok := sessionQualityStamp(scoredAt)
		if !ok {
			// An unparseable stamp cannot be ordered against a newer score on
			// the server, so it is not shipped (the session is re-stamped the
			// next time the scorer writes it).
			continue
		}
		r.ScoredAt = stamp
		r.RedundancyRatio = fptr(rr)
		r.ErrorRate = fptr(er)
		r.ExplorationEfficiency = fptr(ee)
		r.ContinuityScore = fptr(cs)
		r.OnboardingCost = iptr(oc)
		r.TurnsToFirstEdit = iptr(tfe)
		r.RetryCostTokens = iptr(rct)
		r.StaleReadsWasteful = iptr(srw)
		r.StaleReadsNecessary = iptr(srn)
		r.RedundancyRatioWasteful = fptr(rrw)
		r.ScoredActionCount = iptr(sac)
		r.WeightRedundancy = scoring.WeightRedundancy
		r.WeightError = scoring.WeightError
		r.WeightExploration = scoring.WeightExploration
		r.WeightContinuity = scoring.WeightContinuity
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SelectSessionQualityRows: %w", err)
	}
	return out, nil
}

// sessionQualityStamp normalizes a stored scored_at (RFC3339 / RFC3339Nano, as
// Scorer.Write stamps it) onto the fixed-width wire layout.
func sessionQualityStamp(v string) (string, bool) {
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return "", false
	}
	return t.UTC().Format(sessionQualityStampLayout), true
}

// probeSessionQuality is the snapshot-gate change probe for the
// session_quality wire family (orgsnapgate.go). Every Scorer.Write stamps a
// fresh scored_at, so a new or refreshed score always advances
// MAX(scored_at); the count catches a scored session being removed.
//
// RESIDUAL, BOUNDED BY THE FRESHNESS FLOOR: sessions has no index on
// scored_at, so this is a scan of the sessions table - thousands of rows on a
// large node, cheap next to the recompute it skips. A window edge (a score
// ageing out of the 7-day window) changes nothing the server needs to know.
func (s *Store) probeSessionQuality(ctx context.Context) (string, error) {
	return s.snapProbeScalar(ctx,
		`SELECT 'sq' || COALESCE(MAX(scored_at), '') || ':' || COUNT(*) FROM sessions WHERE scored_at IS NOT NULL`)
}
