package advisor

import (
	"fmt"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
)

// rowCost prices one turn row through the injected PriceFn.
func rowCost(f *Facts, s *SessionFacts, r TurnFact) (float64, bool) {
	cc1 := r.CacheCreation1h
	if cc1 > r.CacheCreation {
		cc1 = r.CacheCreation
	}
	return f.Price(rowModel(s, r), cost.TokenBundle{
		Input: r.Input, Output: r.Output, CacheRead: r.CacheRead,
		CacheCreation: r.CacheCreation, CacheCreation1h: cc1, Fast: r.Fast,
	})
}

// baselineCost is the median per-turn cost of the head of the session's
// FIRST idle-gap segment (calibration T4: a resume after a long gap
// re-anchors economics, so later segments never feed the baseline). Head =
// first decile, min 10 rows.
func baselineCost(f *Facts, s *SessionFacts, segs [][]TurnFact) (float64, bool) {
	first := segs[0]
	n := len(first)
	head := n
	if d := len(s.Rows) / 10; d > 10 {
		head = d
	} else if n > 10 {
		head = 10
	}
	if head > n {
		head = n
	}
	var costs []float64
	for _, r := range first[:head] {
		if c, ok := rowCost(f, s, r); ok {
			costs = append(costs, c)
		}
	}
	if len(costs) == 0 {
		return 0, false
	}
	sort.Float64s(costs)
	return costs[len(costs)/2], true
}

// contextWindowTiers are the standard provider context sizes the empirical
// snap-up resolves to (200K Claude standard, 272K GPT-5.x, 500K
// enterprise Sonnet, 1M beta/[1m]).
var contextWindowTiers = []int64{200_000, 272_000, 500_000, 1_000_000}

// contextWindowOf infers a session's context window. Model strings carry
// the truth only sometimes ([1m] suffix; gpt-5 family) — claude-code
// transcripts on the 1M beta often record the plain model id while the
// session demonstrably runs 600K+ windows. So the model-tag base is
// snapped UP to the smallest standard tier that contains the session's
// observed max window: capability inferred from data, never trusted to
// the label alone (operator feedback 2026-06-10).
//
// The Tokenomics window (s.ContextWindow) is the base whenever the data
// states one. The model-tag guess below is only the fallback for models
// the Tokenomics data does not cover yet; the capture docs require a
// window for every model, so it shrinks as coverage grows.
func contextWindowOf(s *SessionFacts) int64 {
	base := int64(200_000)
	m := sessionModelOf(s)
	switch {
	case s.ContextWindow > 0:
		base = s.ContextWindow
	case strings.Contains(m, "[1m]"):
		base = 1_000_000
	case strings.HasPrefix(m, "gpt-5"):
		base = 272_000
	}
	var maxWin int64
	for _, r := range s.Rows {
		if w := r.Window(); w > maxWin {
			maxWin = w
		}
	}
	if maxWin > base {
		for _, tier := range contextWindowTiers {
			if tier >= maxWin {
				return tier
			}
		}
		return contextWindowTiers[len(contextWindowTiers)-1]
	}
	return base
}

// balloonThresholdFor resolves the per-session balloon threshold:
// fraction × inferred context window, floored at BalloonFloorTokens.
func balloonThresholdFor(s *SessionFacts, t Thresholds) int64 {
	th := int64(t.BalloonWindowFraction * float64(contextWindowOf(s)))
	if th < t.BalloonFloorTokens {
		th = t.BalloonFloorTokens
	}
	return th
}

// detectSessionBalloon is the flagship (research-doc A1+A2 fused): find the
// turn where the session's prompt window crossed the balloon threshold,
// price everything after it, and compare against the fresh-session
// counterfactual (one re-onboard + the same turn count at the early-session
// baseline cost). Savings are presented with the calibration haircut and
// the arithmetic in Evidence.Math.
func detectSessionBalloon(f *Facts, t Thresholds) []Suggestion {
	var out []Suggestion
	for i := range f.Sessions {
		s := &f.Sessions[i]
		threshold := balloonThresholdFor(s, t)
		// A handoff TARGET session's FIRST turn is a large cold
		// rehydration write BY DESIGN (the whole handover doc arrives
		// as the first prompt / context). Exempt row 0 from the
		// balloon-crossing scan so the detector never fires BECAUSE OF
		// the rehydration turn — a session that genuinely balloons at a
		// later turn still crosses and fires normally.
		startRow := 0
		if s.HandoffTarget {
			startRow = 1
		}
		idx := -1
		for j := startRow; j < len(s.Rows); j++ {
			if s.Rows[j].Window() >= threshold {
				idx = j
				break
			}
		}
		if idx < 0 || len(s.Rows)-idx < t.BalloonMinRowsAfter {
			continue
		}
		segs := segments(s.Rows, t.IdleGapMinutes)
		baseline, ok := baselineCost(f, s, segs)
		if !ok {
			continue
		}
		after := s.Rows[idx:]
		var actual float64
		priced := 0
		for _, r := range after {
			if c, ok := rowCost(f, s, r); ok {
				actual += c
				priced++
			}
		}
		if priced == 0 {
			continue
		}
		// Re-onboard: rebuilding a ~20K-token working context (read the
		// files the next subtask actually needs) at input + 5m-write rates.
		reonboard, _ := f.Price(rowModel(s, after[0]), cost.TokenBundle{Input: 20_000, CacheCreation: 20_000})
		counterfactual := reonboard + float64(len(after))*baseline
		saving := (actual - counterfactual) * t.CounterfactualHaircut
		if saving <= 0 {
			continue
		}
		conf := 0.7
		if len(after) >= 50 {
			conf = 0.9
		}
		maxWin := int64(0)
		for _, r := range s.Rows {
			if w := r.Window(); w > maxWin {
				maxWin = w
			}
		}
		out = append(out, Suggestion{
			DedupKey: "session_balloon|" + s.ID,
			Detector: "session_balloon",
			Category: CategoryCost,
			Scope:    ScopeSession,
			ScopeID:  s.ID,
			Severity: SeverityAdvice,
			Title:    fmt.Sprintf("Session ballooned to %dK-token turns", maxWin/1000),
			Nudge: fmt.Sprintf(
				"This session crossed a %dK-token prompt window at turn %d of %d and kept carrying that history every turn after. The %d post-balloon turns cost $%.2f; the same work in a fresh session (one ~20K re-onboard, then turns at your early-session rate of $%.4f) would have cost about $%.2f — roughly $%.2f avoidable. Rule of thumb: /clear or a new session when you switch subtasks.",
				threshold/1000, idx+1, len(s.Rows), len(after), actual, baseline, counterfactual, saving,
			),
			SavingsUSD: round2(saving),
			Confidence: conf,
			Evidence: Evidence{
				Numbers: map[string]float64{
					"rows":              float64(len(s.Rows)),
					"balloon_row":       float64(idx + 1),
					"rows_after":        float64(len(after)),
					"max_window_tokens": float64(maxWin),
					"actual_usd":        round2(actual),
					"counterfactual":    round2(counterfactual),
					"baseline_per_turn": baseline,
					"haircut":           t.CounterfactualHaircut,
				},
				Math: fmt.Sprintf("($%.2f actual − $%.2f counterfactual) × %.0f%% haircut = $%.2f", actual, counterfactual, t.CounterfactualHaircut*100, saving),
			},
		})
	}
	return out
}

// detectIdleRecache (research-doc A5): turns that paid to rebuild an
// expired cache after an idle gap longer than the cache TTL — cache_read
// = 0 with cache_creation > 0 right after the gap. Phase-0 sizing: 52
// events ≈ $150/60d on the live corpus, ~$3 per event.
func detectIdleRecache(f *Facts, t Thresholds) []Suggestion {
	var out []Suggestion
	for i := range f.Sessions {
		s := &f.Sessions[i]
		var events int
		var wasted float64
		for j := 1; j < len(s.Rows); j++ {
			r := s.Rows[j]
			gap := r.TS.Sub(s.Rows[j-1].TS).Minutes()
			if gap <= t.IdleGapMinutes || r.CacheRead != 0 || r.CacheCreation == 0 {
				continue
			}
			cc1 := r.CacheCreation1h
			if cc1 > r.CacheCreation {
				cc1 = r.CacheCreation
			}
			if c, ok := f.Price(rowModel(s, r), cost.TokenBundle{CacheCreation: r.CacheCreation, CacheCreation1h: cc1, Fast: r.Fast}); ok {
				events++
				wasted += c
			}
		}
		if events < t.IdleRecacheMinEvents {
			continue
		}
		out = append(out, Suggestion{
			DedupKey: "idle_recache|" + s.ID,
			Detector: "idle_recache",
			Category: CategoryCost,
			Scope:    ScopeSession,
			ScopeID:  s.ID,
			Severity: SeverityInfo,
			Title:    fmt.Sprintf("%d turns rebuilt an expired cache after idle gaps", events),
			Nudge: fmt.Sprintf(
				"%d turns in this session paid to re-write the prompt cache after a break longer than the ~%.0f-minute cache TTL (≈$%.2f of cache-write spend that a warm cache would have served at a tenth the rate). For long think-breaks, finish the subtask first or consider the 1h cache tier.",
				events, t.IdleGapMinutes, wasted,
			),
			SavingsUSD: round2(wasted * 0.9), // a warm read would still cost ~10% of input rate
			Confidence: 0.8,
			Evidence: Evidence{
				Numbers: map[string]float64{
					"recache_events":  float64(events),
					"write_spend_usd": round2(wasted),
				},
				Math: fmt.Sprintf("$%.2f re-cache writes × 90%% (a warm cache read costs ~10%% of input rate) = $%.2f", wasted, wasted*0.9),
			},
		})
	}
	return out
}

// detectLongContextCrossing (research-doc A3, demoted fires-rarely per
// calibration §4 — zero crossings on the calibration corpus with correct
// per-model thresholds). The premium estimate is the documented LC ≈ 2×
// approximation (premium ≈ half the LC turns' cost); Phase 2 can sharpen
// it with a standard-rate pricing export from the cost engine.
func detectLongContextCrossing(f *Facts, _ Thresholds) []Suggestion {
	var out []Suggestion
	for i := range f.Sessions {
		s := &f.Sessions[i]
		var lcTurns int
		var lcCost float64
		for _, r := range s.Rows {
			th := f.LCThreshold(rowModel(s, r))
			if th <= 0 || r.Window() <= th {
				continue
			}
			if c, ok := rowCost(f, s, r); ok {
				lcTurns++
				lcCost += c
			}
		}
		if lcTurns == 0 {
			continue
		}
		premium := lcCost / 2
		out = append(out, Suggestion{
			DedupKey: "long_context_crossing|" + s.ID,
			Detector: "long_context_crossing",
			Category: CategoryCost,
			Scope:    ScopeSession,
			ScopeID:  s.ID,
			Severity: SeverityAdvice,
			Title:    fmt.Sprintf("%d turns ran in the long-context tier", lcTurns),
			Nudge: fmt.Sprintf(
				"%d turns exceeded this model's long-context threshold and paid roughly 2× rates (≈$%.2f premium). Compacting or restarting before the threshold avoids the surcharge entirely.",
				lcTurns, premium,
			),
			SavingsUSD: round2(premium),
			Confidence: 0.6,
			Evidence: Evidence{
				Numbers: map[string]float64{"lc_turns": float64(lcTurns), "lc_cost_usd": round2(lcCost)},
				Math:    fmt.Sprintf("$%.2f spent on LC turns; premium ≈ half (LC ≈ 2× standard) = $%.2f", lcCost, premium),
			},
		})
	}
	return out
}

func round2(v float64) float64 {
	return float64(int64(v*100+0.5)) / 100
}
