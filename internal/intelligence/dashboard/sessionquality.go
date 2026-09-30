package dashboard

import (
	"fmt"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/intelligence/scoring"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// sessionquality.go serves /api/session/<id>/quality — the persisted spec
// §15.2 session quality score behind the session detail Quality card.
//
//	GET  → the stored score (store.LoadSessionQuality), or an honest
//	       {"scored":false} with the auto-scoring posture so the card can say
//	       WHEN a score will appear rather than showing a zero.
//	POST → score the session now (scoring.Scorer, the one writer), persist
//	       it, and answer the same shape. Execute-class via the method-aware
//	       escalation (sessionSubRouteCapabilities).
//
// This route is node-local. The score reaches the org on its own re-pushable
// wire family (BL2-ORG: store.SelectSessionQualityRows ->
// PushEnvelope.session_quality -> server session_quality), and the org drawer
// renders the same shared QualityPanel over GET /api/org/sessions/{id}/quality,
// read-only.

// sessionQualityWeights echoes scoring's formula weights so the card renders
// the formula from its one owner instead of a hard-coded copy.
type sessionQualityWeights struct {
	Redundancy  float64 `json:"redundancy"`
	Error       float64 `json:"error"`
	Exploration float64 `json:"exploration"`
	Continuity  float64 `json:"continuity"`
}

// sessionQualityAuto tells the card whether (and after how long) the daemon
// will score this session on its own.
type sessionQualityAuto struct {
	Enabled     bool `json:"enabled"`
	IdleMinutes int  `json:"idle_minutes"`
}

// sessionQualityWire is the GET/POST body. `scored` is the discriminator:
// false means the scorer never wrote this session and every score field is
// absent (render "not scored yet", never 0). On a scored session a field is
// still absent when its column is NULL (the wasteful/necessary split needs
// cache events; the breakdown/stamp columns predate migration 137 on an old
// score).
type sessionQualityWire struct {
	SessionID string `json:"session_id"`
	Scored    bool   `json:"scored"`

	QualityScore            *float64 `json:"quality_score,omitempty"`
	RedundancyRatio         *float64 `json:"redundancy_ratio,omitempty"`
	ErrorRate               *float64 `json:"error_rate,omitempty"`
	ExplorationEfficiency   *float64 `json:"exploration_efficiency,omitempty"`
	ContinuityScore         *float64 `json:"continuity_score,omitempty"`
	OnboardingCost          *int64   `json:"onboarding_cost,omitempty"`
	TurnsToFirstEdit        *int64   `json:"turns_to_first_edit,omitempty"`
	RetryCostTokens         *int64   `json:"retry_cost_tokens,omitempty"`
	StaleReadsWasteful      *int64   `json:"stale_reads_wasteful,omitempty"`
	StaleReadsNecessary     *int64   `json:"stale_reads_necessary,omitempty"`
	RedundancyRatioWasteful *float64 `json:"redundancy_ratio_wasteful,omitempty"`
	ScoredAt                string   `json:"scored_at,omitempty"`
	ScoredActionCount       *int64   `json:"scored_action_count,omitempty"`

	CurrentActionCount int64                 `json:"current_action_count"`
	Weights            sessionQualityWeights `json:"weights"`
	Auto               sessionQualityAuto    `json:"auto"`
}

// handleSessionQuality serves GET (read) and POST (score now).
func (s *Server) handleSessionQuality(w http.ResponseWriter, r *http.Request, sessionID string) {
	if sessionID == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	case http.MethodPost:
		if !s.scoreSessionNow(w, r, sessionID) {
			return
		}
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q, found, err := store.New(s.opts.DB).LoadSessionQuality(r.Context(), sessionID)
	if err != nil {
		http.Error(w, fmt.Sprintf("load session quality: %v", err), http.StatusInternalServerError)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, s.newSessionQualityWire(q))
}

// scoreSessionNow computes and persists the score for one session. It
// answers the error itself and returns false when the caller must stop.
func (s *Server) scoreSessionNow(w http.ResponseWriter, r *http.Request, sessionID string) bool {
	sc := scoring.New(s.opts.DB)
	scores, err := sc.ScoreSession(r.Context(), sessionID)
	if err != nil {
		http.Error(w, fmt.Sprintf("score session: %v", err), http.StatusInternalServerError)
		return false
	}
	// A session with no actions has nothing to score; the scorer's zero
	// value must not be written as if it were a measurement. The GET body
	// that follows still answers scored=false (or 404 for an unknown id).
	if scores.TotalActions == 0 {
		return true
	}
	if err := sc.Write(r.Context(), scores); err != nil {
		http.Error(w, fmt.Sprintf("write session score: %v", err), http.StatusInternalServerError)
		return false
	}
	return true
}

func (s *Server) newSessionQualityWire(q store.SessionQuality) sessionQualityWire {
	out := sessionQualityWire{
		SessionID:          q.SessionID,
		Scored:             q.Scored,
		CurrentActionCount: q.CurrentActionCount,
		Weights: sessionQualityWeights{
			Redundancy:  scoring.WeightRedundancy,
			Error:       scoring.WeightError,
			Exploration: scoring.WeightExploration,
			Continuity:  scoring.WeightContinuity,
		},
		Auto: sessionQualityAuto{
			Enabled:     s.opts.Scoring.Auto,
			IdleMinutes: int(s.opts.Scoring.Idle().Minutes()),
		},
	}
	if !q.Scored {
		return out
	}
	out.QualityScore = q.QualityScore
	out.RedundancyRatio = q.RedundancyRatio
	out.ErrorRate = q.ErrorRate
	out.ExplorationEfficiency = q.ExplorationEfficiency
	out.ContinuityScore = q.ContinuityScore
	out.OnboardingCost = q.OnboardingCost
	out.TurnsToFirstEdit = q.TurnsToFirstEdit
	out.RetryCostTokens = q.RetryCostTokens
	out.StaleReadsWasteful = q.StaleReadsWasteful
	out.StaleReadsNecessary = q.StaleReadsNecessary
	out.RedundancyRatioWasteful = q.RedundancyRatioWasteful
	out.ScoredAt = q.ScoredAt
	out.ScoredActionCount = q.ScoredActionCount
	return out
}
