package dashboard

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/predict"
	"github.com/marmutapp/superbased-observer/internal/predictsvc"
	"github.com/marmutapp/superbased-observer/internal/sessiongauge"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Predictor defaults — overridden by the [predict] config block (Phase D).
const (
	predictYoungSessionMessages = 3
	predictDefaultTurns         = 12
	predictPriorWindowDays      = 30
)

// PredictResponse is the JSON payload for GET /api/session/<id>/predict —
// the Next-Message Cost & Limit Predictor. Two composed halves: the cost
// estimate (always available where the session has token data) and the
// limit gauge (proxy-gated; Available=false with a NeedsProxy hint until
// the proxy captures rate-limit headers).
type PredictResponse struct {
	SessionID string `json:"session_id"`
	Model     string `json:"model"`
	Tool      string `json:"tool"`

	// Estimate is the cost half. HasEstimate=false (with a Reason) when
	// there's no token substrate — e.g. a hook-only session with no model.
	Estimate predict.EstimateResult `json:"estimate"`
	Reason   string                 `json:"reason,omitempty"`

	// Limit is the proxy-gated half. See LimitGauge.
	Limit LimitGauge `json:"limit"`

	// Projection is the run-out projection of the limit windows and of any
	// budget in force (predict_projection.go). Additive.
	Projection PredictProjection `json:"projection"`
}

// LimitGauge is the rate-limit / subscription-window half of the
// predictor. The type and the ladder that fills it live in the pure shared
// derivation internal/sessiongauge (Limit), so the org session drawer renders
// the same gauge from the same arithmetic; this alias keeps the wire shape
// (see sessiongauge.LimitGauge for the three named unavailable outcomes).
type LimitGauge = sessiongauge.LimitGauge

// handleSessionPredict serves GET /api/session/<id>/predict. Sub-route
// under handleSessionDetail. The cost estimate is pure read-side math
// over token_usage (no new tables); the limit gauge is unavailable until
// the Phase-C proxy capture lands.
func (s *Server) handleSessionPredict(w http.ResponseWriter, r *http.Request, sessionID string) {
	if sessionID == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	st := store.New(s.opts.DB)

	shape, err := st.LoadSessionShape(ctx, sessionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, fmt.Sprintf("load session shape: %v", err), http.StatusInternalServerError)
		return
	}

	resp := PredictResponse{
		SessionID: sessionID,
		Model:     shape.Model,
		Tool:      shape.Tool,
		// Limit gauge: populated from the latest proxy-captured snapshot
		// for this session's provider; falls back to the tool's own
		// transcript-captured rate_limits (codex) and finally to
		// needs-proxy when nothing exists yet.
		Limit: loadLimitGauge(ctx, st, shape.Tool, sessionID),
	}

	// No model → no turn substrate at all (hook-only / no tokens): the
	// shape's model falls back to the dominant turn-row model, so an
	// empty one means there are no turn rows to observe. Honest empty.
	if shape.Model == "" {
		resp.Estimate = predict.EstimateResult{PrefixTokens: shape.PrefixTokens, Warnings: []predict.Warning{predict.WarnNoSessionHistory}}
		resp.Reason = predictReasonNoModel
		resp.Projection = s.buildPredictProjection(ctx, st, shape.Tool, sessionID, resp.Limit, resp.Estimate)
		writeJSON(w, resp)
		return
	}

	// A missing pricing entry is a PRICING gap, not a data gap, so it must
	// not short-circuit the estimate: the prefix, the per-turn token
	// quantiles and the fan-out observations are facts about the session
	// and stay in the response. Only the dollar columns drop out (see
	// predict.EstimateInput.PricingUnknown). Bailing here used to return a
	// zeroed EstimateResult carrying a false no_session_history, which the
	// context-window surface then rendered as "no prefix observed yet" on
	// sessions with observed turns (opencode alias models such as
	// "big-pickle" have no pricing row).
	ctRates, priced := lookupRates(s.opts.CostEngine, shape.Model)
	if !priced {
		resp.Reason = predictReasonUnpriced(shape.Model, s.pricingManagedByOrg(ctx))
	}

	young := s.opts.Predict.YoungSessionMessages
	if young <= 0 {
		young = predictYoungSessionMessages
	}
	defaultTurns := s.opts.Predict.DefaultTurnsPerMessage
	if defaultTurns <= 0 {
		defaultTurns = predictDefaultTurns
	}
	priorWindow := s.opts.Predict.PriorWindowDays
	if priorWindow <= 0 {
		priorWindow = predictPriorWindowDays
	}

	// Resolve the cross-session prior only when the session's own
	// fan-out is missing or too young (the 3-tier T ladder).
	var prior []int
	if len(shape.TurnsPerMessage) == 0 || shape.ObservedMessages < young {
		prior, err = st.LoadToolProjectPrior(ctx, shape.Tool, shape.ProjectID, priorWindow)
		if err != nil {
			http.Error(w, fmt.Sprintf("load prior: %v", err), http.StatusInternalServerError)
			return
		}
	}

	in := predict.EstimateInput{
		Model: shape.Model,
		Rates: predict.RatePair{
			Input:          ctRates.Input,
			Output:         ctRates.Output,
			CacheRead:      ctRates.CacheRead,
			CacheCreation:  ctRates.CacheCreation,
			FastMultiplier: ctRates.FastMultiplier,
		},
		CurrentFast:          loadSessionFastNow(ctx, s.db(), sessionID),
		PricingUnknown:       !priced,
		PrefixTokens:         shape.PrefixTokens,
		TurnSamples:          shape.TurnSamples,
		TurnsPerMessage:      shape.TurnsPerMessage,
		ObservedMessages:     shape.ObservedMessages,
		YoungThreshold:       young,
		PriorTurnsPerMessage: prior,
		DefaultTurns:         defaultTurns,
	}
	resp.Estimate = predict.Estimate(in)
	resp.Projection = s.buildPredictProjection(ctx, st, shape.Tool, sessionID, resp.Limit, resp.Estimate)
	writeJSON(w, resp)
}

// loadLimitGauge resolves the limit gauge for a session through
// predictsvc.LoadLimitGauge (shared with `observer predict`): it loads the two
// observations the shared ladder reads and hands them to sessiongauge.Limit,
// which owns the ladder (audited no-source finding -> proxy window ->
// transcript window -> no_window / needs_proxy).
//
//   - Proxy: the newest proxy-captured snapshot for the session tool's
//     provider, ATTRIBUTED to the tool that observed it (a node-wide
//     per-provider read would leak one tool's subscription gauge, e.g. Claude
//     Code's 5h/weekly, onto every other anthropic-default tool's session).
//   - Transcript: the tool's own transcript-captured rate_limits (codex
//     token_count -> ActionRateLimit rows); st.LatestRateLimitWindows is
//     ok=false for any tool that does not emit those rows.
//
// A load error degrades to "no observation", never an error page.
func loadLimitGauge(ctx context.Context, st *store.Store, tool, sessionID string) LimitGauge {
	return predictsvc.LoadLimitGauge(ctx, st, tool, sessionID, time.Now())
}

// loadSessionFastNow reports whether the session is in the provider's
// fast tier now — any fast=1 in its most-recent 10 token rows. Best-
// effort; a query error degrades to false (the estimate just omits the
// fast multiplier + warning).
func loadSessionFastNow(ctx context.Context, db *sql.DB, sessionID string) bool {
	var fastCount int64
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM (
		  SELECT fast FROM token_usage
		   WHERE session_id = ?
		   ORDER BY timestamp DESC, id DESC LIMIT 10
		) WHERE fast = 1`, sessionID).Scan(&fastCount)
	if err != nil {
		return false
	}
	return fastCount > 0
}

// The Cost tab renders these reasons after "No cost estimate yet." as
// sentences (T-374): each ends with a full stop and names a dashboard
// control, never a CLI command, and never uses a dash as a separator.
// The proxy-routing advice for a session with no model is the tab's own
// line (it carries the setup link), so the reason does not repeat it.
const predictReasonNoModel = "No model has been observed for this session yet."

// predictReasonUnpriced is the reason for a model the cost engine cannot
// price: the estimate keeps its token facts, only the dollars drop out.
//
// It names only what the developer can actually do (CG-22). The Settings >
// Pricing card overrides models it already lists and has no free-text model,
// so on a node that owns its pricing the way in is a config.toml entry; on a
// node whose organization governs the Pricing section (read-only or hidden,
// the managed default) the only way is the organization's own price list.
func predictReasonUnpriced(model string, orgManaged bool) string {
	if orgManaged {
		return fmt.Sprintf("Model %q has no pricing entry, so no dollar estimate is possible. Pricing on this machine is set by your organization, so ask your admin to add a price for it.", model)
	}
	return fmt.Sprintf("Model %q has no pricing entry, so no dollar estimate is possible. The Settings > Pricing card only overrides models it already lists, so add an [intelligence.pricing.models.%q] entry for it in config.toml.", model, model)
}

// pricingManagedByOrg reports whether the organization governs this node's
// Settings > Pricing section (read-only or hidden), so a local price cannot
// be added from here. False with no governance wired (an individual node).
func (s *Server) pricingManagedByOrg(ctx context.Context) bool {
	if s.opts.Governance == nil {
		return false
	}
	eff := s.opts.Governance(ctx)
	return eff.IsSettingsSectionReadOnly("pricing") || eff.IsSettingsSectionHidden("pricing")
}
