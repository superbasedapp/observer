package dashboard

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cachetrack"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
)

// CacheForecastResponse is the JSON payload for
// GET /api/sessions/<id>/cache/forecast?model=X. Wraps the
// cachetrack.ForecastResult so the dashboard widget gets the
// math + the inputs it used (so operators can sanity-check the
// numbers without scrolling through cache_events). All dollar
// fields are raw USD; the frontend formats them.
//
// Spec §14.2. Pure read-side math — no new tables; the inputs
// are assembled from cache_entries (P) + cache_events (S, gap
// signal) + api_turns (O, T, fast detect) + cost.Table (rates).
type CacheForecastResponse struct {
	SessionID      string `json:"session_id"`
	CurrentModel   string `json:"current_model"`
	CandidateModel string `json:"candidate_model"`

	// Inputs the forecaster used. Echoed so operators see the
	// assembly without re-querying. CurrentPrefixTokens is P,
	// AvgSuffixTokens is S, AvgOutputTokens is O,
	// EstimatedRemainingTurns is T, CurrentFast carries the
	// fast-mode signal.
	CurrentPrefixTokens     int64 `json:"current_prefix_tokens"`
	AvgSuffixTokens         int64 `json:"avg_suffix_tokens"`
	AvgOutputTokens         int64 `json:"avg_output_tokens"`
	EstimatedRemainingTurns int64 `json:"estimated_remaining_turns"`
	ObservedTurns           int64 `json:"observed_turns"`
	CurrentFast             bool  `json:"current_fast,omitempty"`
	HasGapsOver5Min         bool  `json:"has_gaps_over_5_min,omitempty"`
	CandidateMinCacheable   int64 `json:"candidate_min_cacheable,omitempty"`

	// Headline forecast outputs.
	SwitchCostUSD          float64 `json:"switch_cost_usd"`
	PerTurnBeforeUSD       float64 `json:"per_turn_before_usd"`
	PerTurnAfterUSD        float64 `json:"per_turn_after_usd"`
	SavingsPerTurnUSD      float64 `json:"savings_per_turn_usd"`
	BreakEvenTurns         int64   `json:"break_even_turns"`
	EstimatedNetSavingsUSD float64 `json:"estimated_net_savings_usd"`

	// Warnings carries the cachetrack.WarningKind closed set
	// as strings. Frontend maps each to a pill (neutral for
	// informational like empty_prefix; warn for actionable
	// like cache_wont_engage / switch_never_pays_off).
	Warnings []string `json:"warnings,omitempty"`
}

// handleSessionCacheForecast serves
// GET /api/sessions/<id>/cache/forecast?model=X.
//
// Sub-route under handleSessionDetail. Returns 400 on missing
// session id or missing model query param; 404 when the session
// doesn't exist; 400 when the candidate model isn't in the
// pricing table (the forecaster needs rates to score, and an
// unknown candidate would silently produce zero per-turn deltas).
//
// All dollar math is in the cachetrack.Forecast pure function;
// this handler only assembles inputs from the existing tables.
// Spec §14.2 "no new tables" invariant: every SQL query targets
// rows already written by the proxy / watcher; the forecaster
// reads them through read-side aggregates.
func (s *Server) handleSessionCacheForecast(w http.ResponseWriter, r *http.Request, sessionID string) {
	if sessionID == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	candidateModel := r.URL.Query().Get("model")
	if candidateModel == "" {
		http.Error(w, "missing ?model=<candidate> query param", http.StatusBadRequest)
		return
	}
	ctx := r.Context()

	currentModel, err := loadSessionCurrentModel(ctx, s.db(), sessionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, fmt.Sprintf("load session: %v", err), http.StatusInternalServerError)
		return
	}
	if currentModel == "" {
		http.Error(w, "session has no observed model yet", http.StatusBadRequest)
		return
	}

	curRates, curOK := lookupRates(s.opts.CostEngine, currentModel)
	if !curOK {
		http.Error(w, fmt.Sprintf("current model %q has no pricing entry", currentModel), http.StatusBadRequest)
		return
	}
	candRates, candOK := lookupRates(s.opts.CostEngine, candidateModel)
	if !candOK {
		http.Error(w, fmt.Sprintf("candidate model %q has no pricing entry", candidateModel), http.StatusBadRequest)
		return
	}

	stats, err := loadSessionForecastStats(ctx, s.db(), sessionID, currentModel)
	if err != nil {
		http.Error(w, fmt.Sprintf("load forecast stats: %v", err), http.StatusInternalServerError)
		return
	}

	in := cachetrack.ForecastInput{
		CurrentPrefixTokens:     stats.PrefixTokens,
		AvgSuffixTokens:         stats.AvgSuffixTokens,
		AvgOutputTokens:         stats.AvgOutputTokens,
		EstimatedRemainingTurns: stats.EstimatedRemainingTurns,
		Current:                 currentModel,
		Candidate:               candidateModel,
		CurrentRates:            curRates,
		CandidateRates:          candRates,
		CandidateMinCacheable:   candidateMinCacheable(candidateModel),
		CurrentFast:             stats.CurrentFast,
		HasGapsOver5Min:         stats.HasGapsOver5Min,
	}
	result := cachetrack.Forecast(in)

	resp := CacheForecastResponse{
		SessionID:               sessionID,
		CurrentModel:            currentModel,
		CandidateModel:          candidateModel,
		CurrentPrefixTokens:     in.CurrentPrefixTokens,
		AvgSuffixTokens:         in.AvgSuffixTokens,
		AvgOutputTokens:         in.AvgOutputTokens,
		EstimatedRemainingTurns: in.EstimatedRemainingTurns,
		ObservedTurns:           stats.ObservedTurns,
		CurrentFast:             in.CurrentFast,
		HasGapsOver5Min:         in.HasGapsOver5Min,
		CandidateMinCacheable:   in.CandidateMinCacheable,
		SwitchCostUSD:           result.SwitchCostUSD,
		PerTurnBeforeUSD:        result.PerTurnBeforeUSD,
		PerTurnAfterUSD:         result.PerTurnAfterUSD,
		SavingsPerTurnUSD:       result.SavingsPerTurnUSD,
		BreakEvenTurns:          result.BreakEvenTurns,
		EstimatedNetSavingsUSD:  result.EstimatedNetSavingsUSD,
		Warnings:                warningStrings(result.Warnings),
	}
	writeJSON(w, resp)
}

// sessionForecastStats is the assembled-from-SQL input shape the
// handler folds into a cachetrack.ForecastInput. Carries the
// observed-turns count alongside the estimated-remaining-turns
// projection so the frontend can render both.
type sessionForecastStats struct {
	PrefixTokens            int64
	AvgSuffixTokens         int64
	AvgOutputTokens         int64
	ObservedTurns           int64
	EstimatedRemainingTurns int64
	CurrentFast             bool
	HasGapsOver5Min         bool
}

// loadSessionCurrentModel resolves the session's current model.
// Prefers the per-session sessions.model column; falls back to
// the most-recent api_turns.model when sessions.model is unset
// (shouldn't happen on a healthy install but pre-v1.5.x sessions
// occasionally landed model=” on the session row).
func loadSessionCurrentModel(ctx context.Context, db *sql.DB, sessionID string) (string, error) {
	var model sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(model, '') FROM sessions WHERE id = ?`, sessionID).Scan(&model); err != nil {
		return "", err
	}
	if model.Valid && model.String != "" {
		return model.String, nil
	}
	// Fallback: most-recent api_turns row.
	var apiModel sql.NullString
	err := db.QueryRowContext(ctx,
		`SELECT model FROM api_turns WHERE session_id = ? ORDER BY id DESC LIMIT 1`, sessionID).Scan(&apiModel)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return apiModel.String, nil
}

// loadSessionForecastStats runs the four small reads the
// forecaster needs:
//
//   - PrefixTokens P: MAX(token_count) over live cache_entries
//     for (session_id, current_model). When the engine hasn't
//     seen the session yet, P = 0 (the forecaster handles it
//     via WarningEmptyPrefix).
//   - AvgSuffixTokens S: AVG(tokens_written) on suffix_growth
//     write events (the unflagged warm-growth baseline). Falls
//     back to 0 when the session has no proxy capture yet.
//   - AvgOutputTokens O: AVG(output_tokens) on the session's
//     api_turns. 0 when no proxy capture.
//   - ObservedTurns + EstimatedRemainingTurns: turn count to
//     date is the proxy. T estimate uses observed_turns as a
//     plausible "session will run roughly this many more
//     turns" projection — short sessions stay short, long ones
//     run on. Not aspirational; the forecaster's per-turn delta
//     is the operator-actionable number, T just contextualizes
//     it. Zero turns → T = 0 (no estimate; forecaster
//     suppresses estimated_net_savings_usd).
//   - CurrentFast: any api_turn row with fast=1 in the last 10
//     turns means the session is in fast mode now. Conservative;
//     suppresses the warning on sessions where fast was used
//     once early and dropped.
//   - HasGapsOver5Min: MAX(turn_n_start - turn_n-1_start) > 5m
//     over the session's api_turns. The LAG SQL is wrapped to
//     SQLite's variant (julianday-based delta).
func loadSessionForecastStats(ctx context.Context, db *sql.DB, sessionID, currentModel string) (sessionForecastStats, error) {
	var stats sessionForecastStats

	// P — deepest live cached prefix for this session AND model.
	if err := db.QueryRowContext(
		ctx,
		`SELECT COALESCE(MAX(token_count), 0)
		   FROM cache_entries
		  WHERE session_id = ? AND model = ? AND state = 'live'`,
		sessionID, currentModel,
	).Scan(&stats.PrefixTokens); err != nil {
		return stats, fmt.Errorf("prefix tokens: %w", err)
	}

	// S — avg suffix_growth write tokens. Filter on cause to
	// exclude rewrites + reanchors which would inflate S.
	if err := db.QueryRowContext(
		ctx,
		`SELECT COALESCE(CAST(AVG(tokens_written) AS INTEGER), 0)
		   FROM cache_events
		  WHERE session_id = ?
		    AND kind = 'write'
		    AND cause = 'suffix_growth'
		    AND tokens_written > 0`,
		sessionID,
	).Scan(&stats.AvgSuffixTokens); err != nil {
		return stats, fmt.Errorf("avg suffix tokens: %w", err)
	}

	// O — avg output tokens across the session's api_turns.
	if err := db.QueryRowContext(
		ctx,
		`SELECT COALESCE(CAST(AVG(output_tokens) AS INTEGER), 0)
		   FROM api_turns
		  WHERE session_id = ? AND output_tokens > 0`,
		sessionID,
	).Scan(&stats.AvgOutputTokens); err != nil {
		return stats, fmt.Errorf("avg output tokens: %w", err)
	}

	// Observed turns + T estimate.
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM api_turns WHERE session_id = ?`,
		sessionID,
	).Scan(&stats.ObservedTurns); err != nil {
		return stats, fmt.Errorf("observed turns: %w", err)
	}
	stats.EstimatedRemainingTurns = stats.ObservedTurns

	// CurrentFast: any fast=1 in the most recent 10 turns.
	var fastRecentCount int64
	if err := db.QueryRowContext(
		ctx, `
		SELECT COUNT(*) FROM (
		  SELECT fast FROM api_turns
		   WHERE session_id = ?
		   ORDER BY id DESC LIMIT 10
		) WHERE fast = 1`, sessionID,
	).Scan(&fastRecentCount); err != nil {
		return stats, fmt.Errorf("fast detect: %w", err)
	}
	stats.CurrentFast = fastRecentCount > 0

	// Gap detection: scan adjacent turn timestamps; if any gap
	// > 5 min, flag. Done in Go to keep the SQL portable (SQLite
	// LAG availability varies across modernc.org/sqlite versions).
	rows, err := db.QueryContext(ctx,
		`SELECT timestamp FROM api_turns WHERE session_id = ? ORDER BY id ASC`, sessionID)
	if err != nil {
		return stats, fmt.Errorf("gap scan: %w", err)
	}
	defer rows.Close()
	var prev time.Time
	for rows.Next() {
		var tsStr string
		if err := rows.Scan(&tsStr); err != nil {
			return stats, fmt.Errorf("gap scan row: %w", err)
		}
		ts, perr := time.Parse(time.RFC3339Nano, tsStr)
		if perr != nil {
			ts, perr = time.Parse(time.RFC3339, tsStr)
			if perr != nil {
				continue
			}
		}
		if !prev.IsZero() {
			gap := ts.Sub(prev)
			if gap > 5*time.Minute {
				stats.HasGapsOver5Min = true
				break
			}
		}
		prev = ts
	}
	if err := rows.Err(); err != nil {
		return stats, fmt.Errorf("gap scan rows: %w", err)
	}

	return stats, nil
}

// lookupRates resolves a model id to the cachetrack RatePair the
// forecaster needs. Bridges between cost.Pricing (8+ fields the
// cost engine cares about) and cachetrack.RatePair (5 fields the
// forecaster reads), so the cachetrack package stays cost-import-
// free per spec §24.1.
//
// **Unit conversion is load-bearing here.** cost.Pricing stores
// rates as $ per MILLION tokens (so the Cost-engine multiplications
// in cost/engine.go:288-290 divide by 1_000_000 before summing).
// cachetrack.RatePair stores rates per TOKEN — see
// internal/cachetrack/forecast_test.go::opusRates (Input: 15e-6).
// The forecaster's math multiplies token counts by RatePair fields
// directly, so passing $/M values without the /1e6 conversion
// produces dollar numbers ~1,000,000× too large
// (operator-reported regression 2026-06-10: $39K switch cost
// + $4.1M net savings on a session whose actual spend was $8.74).
// Pinned by TestLookupRates_PerTokenScale.
//
// Returns (RatePair, false) when the cost engine is unwired or
// the model has no pricing entry — handler emits 400 in that
// case rather than producing zero-rate math.
func lookupRates(engine *cost.Engine, model string) (cachetrack.RatePair, bool) {
	if engine == nil {
		return cachetrack.RatePair{}, false
	}
	p, ok := engine.Lookup(model)
	if !ok {
		return cachetrack.RatePair{}, false
	}
	const perMillion = 1_000_000.0
	return cachetrack.RatePair{
		Input:           p.Input / perMillion,
		Output:          p.Output / perMillion,
		CacheRead:       p.CacheRead / perMillion,
		CacheCreation:   p.CacheCreation / perMillion,
		CacheCreation1h: p.CacheCreation1h / perMillion,
		FastMultiplier:  p.FastMultiplier,
	}, true
}

// candidateMinCacheable returns the candidate model's minimum
// cacheable prefix size. Anthropic publishes per-family
// thresholds; the values below are the spec §14.2 reference.
// Non-Anthropic candidates return 0 (forecaster suppresses the
// "won't engage" warning).
func candidateMinCacheable(model string) int64 {
	switch {
	case modelHasPrefix(model, "claude-haiku"):
		return 1024
	case modelHasPrefix(model, "claude-sonnet"):
		return 4096
	case modelHasPrefix(model, "claude-opus"):
		return 8192
	}
	return 0
}

// modelHasPrefix is a tiny prefix-match helper that survives
// the per-model normalization the cost engine applies. Avoids
// pulling strings.HasPrefix into this single use site.
func modelHasPrefix(model, prefix string) bool {
	if len(model) < len(prefix) {
		return false
	}
	return model[:len(prefix)] == prefix
}

// warningStrings converts the closed-set WarningKind list to the
// strings the JSON encoder emits. Keeps the wire vocabulary
// stable across releases (consumed by webapp UI mapping).
func warningStrings(warns []cachetrack.WarningKind) []string {
	if len(warns) == 0 {
		return nil
	}
	out := make([]string, len(warns))
	for i, w := range warns {
		out[i] = string(w)
	}
	return out
}
