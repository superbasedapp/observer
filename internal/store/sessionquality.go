package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// SessionQuality is the persisted spec §15.2 quality score of one session as
// the scorer (internal/intelligence/scoring, the one writer) left it, plus the
// session's current action count so a reader can tell a current score from
// one that predates newer activity.
//
// Scored=false means the scorer has never written this session (quality_score
// IS NULL): every score field is then nil and must be rendered as "not scored
// yet", never as zero. The pointer fields are individually nil when their
// column is NULL even on a scored session: the §14.1 wasteful/necessary split
// is only computed for sessions with cache events, and the migration-137
// breakdown/stamp columns are NULL on a session scored before that migration.
type SessionQuality struct {
	SessionID string
	Scored    bool

	QualityScore            *float64
	RedundancyRatio         *float64
	ErrorRate               *float64
	ExplorationEfficiency   *float64
	ContinuityScore         *float64
	OnboardingCost          *int64
	TurnsToFirstEdit        *int64
	RetryCostTokens         *int64
	StaleReadsWasteful      *int64
	StaleReadsNecessary     *int64
	RedundancyRatioWasteful *float64
	ScoredAt                string
	ScoredActionCount       *int64

	// CurrentActionCount is COUNT(actions) for the session right now.
	CurrentActionCount int64
}

// LoadSessionQuality reads the persisted quality score for sessionID. found is
// false when no such session exists (the caller answers 404); a session that
// exists but was never scored returns found=true with Scored=false.
func (s *Store) LoadSessionQuality(ctx context.Context, sessionID string) (SessionQuality, bool, error) {
	out := SessionQuality{SessionID: sessionID}
	var (
		q, rr, er, ee, cs, rrw sql.NullFloat64
		oc, tfe, rct, srw, srn sql.NullInt64
		sac                    sql.NullInt64
		scoredAt               sql.NullString
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT quality_score, redundancy_ratio, error_rate,
		        exploration_efficiency, continuity_score,
		        onboarding_cost, turns_to_first_edit, retry_cost_tokens,
		        stale_reads_wasteful, stale_reads_necessary, redundancy_ratio_wasteful,
		        scored_at, scored_action_count,
		        (SELECT COUNT(*) FROM actions a WHERE a.session_id = s.id)
		   FROM sessions s WHERE s.id = ?`, sessionID,
	).Scan(&q, &rr, &er, &ee, &cs, &oc, &tfe, &rct, &srw, &srn, &rrw,
		&scoredAt, &sac, &out.CurrentActionCount)
	if errors.Is(err, sql.ErrNoRows) {
		return SessionQuality{}, false, nil
	}
	if err != nil {
		return SessionQuality{}, false, fmt.Errorf("store.LoadSessionQuality: %w", err)
	}
	out.Scored = q.Valid
	out.QualityScore = fptr(q)
	out.RedundancyRatio = fptr(rr)
	out.ErrorRate = fptr(er)
	out.ExplorationEfficiency = fptr(ee)
	out.ContinuityScore = fptr(cs)
	out.OnboardingCost = iptr(oc)
	out.TurnsToFirstEdit = iptr(tfe)
	out.RetryCostTokens = iptr(rct)
	out.StaleReadsWasteful = iptr(srw)
	out.StaleReadsNecessary = iptr(srn)
	out.RedundancyRatioWasteful = fptr(rrw)
	out.ScoredActionCount = iptr(sac)
	if scoredAt.Valid {
		out.ScoredAt = scoredAt.String
	}
	return out, true, nil
}
