package dashboard

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/predict"
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
}

// LimitGauge is the rate-limit / subscription-window half of the
// predictor. In v1 the capture path (proxy graft + limit_snapshots) is
// Phase C; until a snapshot exists for the session's scope the gauge is
// Available=false / NeedsProxy=true and the surface renders a help-icon
// "route through the proxy to unlock" state — never fabricated numbers.
type LimitGauge struct {
	Available  bool `json:"available"`
	NeedsProxy bool `json:"needs_proxy"`
	// NoWindow is true when the proxy HAS captured a snapshot for this
	// provider but it carried no subscription-window utilization (e.g.
	// OpenAI/codex, or Anthropic API-key traffic — only classic
	// per-minute headers). Distinct from NeedsProxy so the surface shows
	// "this provider exposes no 5h/weekly window" rather than the
	// (wrong) "route through the proxy" hint.
	NoWindow bool `json:"no_window,omitempty"`
	// ObservedAge is a human-readable staleness hint ("2m ago") when a
	// snapshot exists — the window keeps ticking from other sessions on
	// the same account, so the gauge is only as fresh as the last
	// proxied response.
	ObservedAge string `json:"observed_age,omitempty"`
	// Source names where the window came from: "proxy" (Anthropic
	// response headers via limit_snapshots) or "transcript" (a tool's own
	// session log, e.g. codex token_count rate_limits). Empty when the
	// gauge is unavailable.
	Source string `json:"source,omitempty"`
	// Populated once snapshots land (Phase C): 5h / weekly utilization
	// (0..1), reset unix timestamps, and the predicted next-message
	// utilization-delta band. Omitted while unavailable.
	Window5hUtil   *float64 `json:"window_5h_util,omitempty"`
	Window5hReset  *int64   `json:"window_5h_reset,omitempty"`
	Window7dUtil   *float64 `json:"window_7d_util,omitempty"`
	Window7dReset  *int64   `json:"window_7d_reset,omitempty"`
	ObservedAtUnix *int64   `json:"observed_at_unix,omitempty"`
}

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
		resp.Reason = "no model observed for this session — route the client through the observer proxy (or send a message) to capture token/cost data"
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
		resp.Reason = fmt.Sprintf("model %q has no pricing entry — cannot estimate cost", shape.Model)
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
	writeJSON(w, resp)
}

// loadLimitGauge resolves the limit gauge for a session. Primary source
// is the proxy-captured snapshot for the session's provider (Anthropic
// response headers). When that yields no subscription window — because
// the session isn't proxied, or the provider doesn't expose 5h/weekly in
// headers at all (OpenAI/codex) — it falls back to the tool's own
// transcript-captured rate_limits (codex token_count → ActionRateLimit
// rows). No window from either source → needs-proxy / no-window.
//
// The fallback is capability-driven: st.LatestRateLimitWindows returns
// ok=false for any tool that doesn't emit those rows, so there's no
// branch on source identity here.
func loadLimitGauge(ctx context.Context, st *store.Store, tool, sessionID string) LimitGauge {
	provider := providerForTool(tool)
	// Attribute the window to the tool that observed it — a node-wide
	// per-provider read leaks one tool's subscription gauge (e.g. Claude
	// Code's 5h/weekly) onto every other anthropic-default tool's session
	// detail (cline-cli, cursor, …) that never produced one.
	snap, ok, err := st.LatestLimitSnapshotForTool(ctx, provider, tool)

	var g LimitGauge
	switch {
	case err != nil || !ok:
		g = LimitGauge{Available: false, NeedsProxy: true}
	default:
		g = LimitGauge{ObservedAge: humanizeAge(time.Since(snap.ObservedAt))}
		if snap.Window5hUtil == nil && snap.Window7dUtil == nil {
			g.NoWindow = true
		} else {
			g.Available = true
			g.Source = "proxy"
			g.Window5hUtil = snap.Window5hUtil
			g.Window5hReset = snap.Window5hReset
			g.Window7dUtil = snap.Window7dUtil
			g.Window7dReset = snap.Window7dReset
			if !snap.ObservedAt.IsZero() {
				u := snap.ObservedAt.Unix()
				g.ObservedAtUnix = &u
			}
		}
	}

	// Transcript fallback for providers without subscription-window
	// headers (codex). Only consulted when the header path produced no
	// usable window — a real proxied Anthropic window always wins.
	if !g.Available {
		if w, found, werr := st.LatestRateLimitWindows(ctx, tool, sessionID); werr == nil && found &&
			(w.Window5hUtil != nil || w.Window7dUtil != nil) {
			g = LimitGauge{
				Available:     true,
				Source:        "transcript",
				Window5hUtil:  w.Window5hUtil,
				Window5hReset: w.Window5hReset,
				Window7dUtil:  w.Window7dUtil,
				Window7dReset: w.Window7dReset,
			}
			if !w.ObservedAt.IsZero() {
				g.ObservedAge = humanizeAge(time.Since(w.ObservedAt))
				u := w.ObservedAt.Unix()
				g.ObservedAtUnix = &u
			}
		}
	}
	return g
}

// providerForTool maps an AI-tool name to the upstream provider the
// limit snapshot is keyed by. Capability-style: Anthropic-family tools
// vs OpenAI-family; unknown defaults to anthropic (the common proxied
// case). Branches on the known OpenAI tools rather than source identity
// elsewhere in the pipeline.
func providerForTool(tool string) string {
	switch tool {
	case "codex", "copilot", "copilot-cli":
		return "openai"
	default:
		return "anthropic"
	}
}

// humanizeAge renders a short staleness string for the gauge.
func humanizeAge(d time.Duration) string {
	if d < time.Minute {
		return "just now"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
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
