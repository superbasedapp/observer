package dashboard

import (
	"net/http"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/intelligence/discover"
	"github.com/marmutapp/superbased-observer/internal/timebucket"
)

// handleAnalysisHeadline serves /api/analysis/headline?days=N — the
// tile values for the Analysis tab's KPI band. v1.4.50 rewrites the
// shape to address three audit findings against the prior version:
//
//  1. The old "effective rate" formula divided period $ by
//     (output + cache_write). Cache-write tokens are PAID-FOR setup
//     overhead, not value tokens — including them in the denominator
//     meant high cache churn (write-but-never-read) artificially
//     lowered the displayed rate. Replaced with `output_rate`
//     (period $ ÷ output tokens) and `cache_savings_usd` (the dollar
//     value of cache_read traffic priced at input rate).
//  2. The old "LC tier surcharge" tile reported $0 for users on
//     Anthropic Opus, where the pricing table has no LC tier. The
//     literal claim "no turns crossed an LC threshold" was false when
//     thousands of >200K-prompt turns existed. Replaced with
//     `high_context` (model-agnostic turn counts at 100K / 200K +
//     attributed $) and `lc_surcharge_usd` retained as a sibling only
//     for users on LC-eligible models.
//  3. The old surcharge/savings attribution silently dropped to $0
//     whenever `recorded > 0` (upstream proxy populated cost_usd),
//     because rowStdCost/rowAltCost were set equal to rowCost — a
//     row can never show a delta against itself. Since proxy-recorded
//     turns are the majority of spend on a wired-up install, this
//     under-reported cache_savings by ~3× on the operator's corpus
//     (2026-07-30 audit). Fixed: when the pricing table has an entry
//     for the model, we still keep `recorded` as the ACTUAL cost
//     (never overridden — it's the ground truth), but derive the
//     counterfactual/standard-rate DELTA from a same-bundle Compute()
//     pair and apply that delta relative to `recorded`
//     (rowAltCost = recorded + (computedAlt-computedCost) when
//     positive; rowStdCost = recorded - (computedCost-computedStd)
//     when positive). This decomposes recorded rows using the pricing
//     table's *shape* (which tokens are discounted, which tier
//     applies) without discarding the proxy's authoritative total.
//     Only when the model has NO pricing entry do we fall back to
//     the fully-opaque rowStdCost=rowAltCost=recorded (no invented
//     counterfactual without a pricing basis). `recorded_cost_share_pct`
//     still shows how much of period cost came from recorded rows, but
//     it no longer implies those rows contribute zero to the LC/cache
//     tiles.
//
// Tiles emitted in this version (subset; JS picks which to render):
//
//   - period:        cost_usd / prior_cost_usd / delta_pct / recorded_share_pct
//   - month:         to_date_usd / projection_usd / prior_month_same_day_usd /
//     vs_prior_month_pct / budget_usd / budget_pct
//   - output_rate:   tokens / rate_per_million ($/M output — the clean rate)
//   - cache_savings: usd / cache_read_tokens (counterfactual: cache_read
//     priced at input rate vs cache_read rate)
//   - cache:         read_tokens / write_tokens / efficacy
//   - high_context:  turns_over_100k / turns_over_200k / cost_over_100k_usd /
//     cost_over_200k_usd / lc_eligible_turns / lc_surcharge_usd
//   - per_turn:      count / mean_usd / p95_usd (variance signal)
//   - burn_rate:     active_hours / cost_per_hour_usd
//   - top_model:     key / cost_usd / concentration_pct
//   - waste:         usd / tokens / blended_rate_per_million
//
// All numbers come from one per-turn-deduped scan of api_turns +
// token_usage over [min(period_start, month_start, prior_month_start), now].
// LC surcharge / cache savings / per-row pricing run in Go because the
// cost engine's LongContext dispatch is per-turn — aggregating tokens
// at SQL then pricing once would false-trip the LC threshold whenever
// a session's summed prompt cleared it.
// periodWindow resolves an analysis handler's period [start, end] from the
// global window - windowRange's tiers (since / hours / days, plus until) -
// and the equal-length prior period that ends where it starts. A days-only
// request keeps the handler's own clock and day arithmetic byte-for-byte
// (start = now - days); a sub-day or custom window uses the window itself,
// so a 1h window never serves 30 days.
func periodWindow(r *http.Request, now time.Time, days int) (start, end, priorStart time.Time) {
	since, until := windowRange(r, days, 1, 36500)
	lowerNew, upperNew := windowBoundsResolved(r)
	end = now
	if upperNew && until.Before(now) {
		end = until
	}
	start = now.Add(-time.Duration(days) * 24 * time.Hour)
	if lowerNew {
		start = since
	}
	span := end.Sub(start)
	if span < 0 {
		span = 0
	}
	return start, end, start.Add(-span)
}

func (s *Server) handleAnalysisHeadline(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")

	now := s.now()
	periodStart, periodEnd, priorStart := periodWindow(r, now, days)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	// Prior-month-same-day comparison: [first-of-prior-month, +daysIntoMonth)
	// e.g. on May 12 we compare against April 1..April 12. Honest month-
	// over-month signal that linear MTD projection can't give.
	priorMonthStart := time.Date(now.Year(), now.Month()-1, 1, 0, 0, 0, 0, time.UTC)
	priorMonthSameDayEnd := priorMonthStart.Add(now.Sub(monthStart))
	// Clamp to monthStart: when the prior month is shorter than today's
	// day-of-month (e.g. now=May 31 → priorMonthStart+30d overflows into
	// May), the window would otherwise leak past first-of-current-month
	// and double-count MTD turns in the prior-month baseline.
	if priorMonthSameDayEnd.After(monthStart) {
		priorMonthSameDayEnd = monthStart
	}

	// Pull rows from whichever boundary is earliest so a single scan
	// covers MTD, period+prior windows, AND prior-month-same-day.
	queryStart := priorStart
	if monthStart.Before(queryStart) {
		queryStart = monthStart
	}
	if priorMonthStart.Before(queryStart) {
		queryStart = priorMonthStart
	}
	turns, err := s.spendTurns(r.Context(), queryStart, time.Time{}, tool, project, nil)
	if err != nil {
		writeErr(w, err)
		return
	}

	var (
		periodCost, priorCost, mtdCost, priorMonthSameDayCost float64
		periodRecordedCost                                    float64
		periodOutput, periodCacheRead, periodCacheWrite       int64
		periodLCEligibleTurns                                 int64
		periodLCSurcharge                                     float64
		periodHC100k, periodHC200k                            int64
		periodCostHC100k, periodCostHC200k                    float64
		periodCacheSavings                                    float64
		perTurnCosts                                          []float64
		modelCost                                             = map[string]float64{}
		activeHours                                           = map[string]struct{}{}
	)

	for _, turn := range turns {
		model, bundle, ts, recorded := turn.Model, turn.Bundle, turn.At, turn.Recorded

		// rowCost   — actual cost for this turn (LC-aware if applicable).
		//             Always `recorded` when the proxy/JSONL populated a
		//             cost — that's the ground-truth observed spend and
		//             is never overridden by a modeled figure.
		// rowStdCost — what the turn would have cost at standard (non-LC) rates
		// rowAltCost — counterfactual cost if cache_read tokens had been
		//              raw input tokens (used for cache_savings_usd)
		// modelHasLC — model has an LC tier defined in pricing
		//
		// For recorded rows we still need rowStdCost/rowAltCost to be
		// genuine counterfactuals (not just `recorded` again), or the
		// later `rowAltCost > rowCost` / `rowCost > rowStdCost` checks
		// can never fire and cache_savings / lc_surcharge silently drop
		// to $0 for every proxy-recorded turn. When the pricing table
		// has an entry we price the SAME bundle twice (actual shape vs
		// counterfactual shape) and apply the resulting delta relative
		// to `recorded`, so the authoritative total is preserved while
		// still surfacing the attribution. Without a pricing entry there
		// is no basis for a counterfactual, so all three stay equal to
		// `recorded` (today's behavior, unchanged).
		//
		// Both deltas are clamped so a modeled figure can never claim
		// more than the row's own recorded spend. The pricing table is
		// a MODEL, not the ground truth for this specific row — a
		// discounted lane, a since-changed rate table, or any other
		// drift between the table's assumed rates and what this row
		// actually paid can make the modeled LC delta
		// (computedCost-computedStd) exceed `recorded` itself. Left
		// unclamped, rowStdCost = recorded - delta goes negative and the
		// LC surcharge tile would report a surcharge larger than the
		// row's entire recorded cost — an impossible, dishonest number.
		// Clamping at zero means the attribution is capped at "this row
		// cost $0 at standard rates" (i.e. the whole recorded amount is
		// attributed to the LC premium) rather than reporting a
		// fabricated negative-cost counterfactual. The cache-savings
		// delta (rowAltCost = recorded + delta) can't go negative from
		// addition alone since we only apply it when computedAlt >
		// computedCost, but we clamp rowStdCost's delta the same way
		// for symmetry and because a future pricing-table change could
		// otherwise make the "always non-negative" assumption silently
		// stop holding.
		//
		// DATE-EFFECTIVE: this is a HISTORICAL analysis over a past
		// window, so the row is priced at the rate in force at its own
		// timestamp (LookupAt), not at today's. With no dated timeline
		// for the model — the default — LookupAt(ts) is byte-identical
		// to Lookup(). `ts` is already parsed above; a malformed stamp
		// leaves it zero, which LookupAt treats as "use current rates".
		var rowCost, rowStdCost, rowAltCost float64
		p, priced := s.opts.CostEngine.LookupAt(model, ts)
		var modelHasLC bool
		if priced && p.LongContextThreshold > 0 {
			modelHasLC = true
		}
		switch {
		case recorded > 0:
			rowCost = recorded
			rowStdCost = recorded
			rowAltCost = recorded
			if priced {
				computedCost := cost.Compute(p, bundle)
				computedStd := cost.Compute(stripLongContext(p), bundle)
				if computedCost > computedStd {
					lcDelta := computedCost - computedStd
					if lcDelta > recorded {
						lcDelta = recorded
					}
					rowStdCost = recorded - lcDelta
				}
				if bundle.CacheRead > 0 {
					altBundle := bundle
					altBundle.Input += bundle.CacheRead
					altBundle.CacheRead = 0
					computedAlt := cost.Compute(p, altBundle)
					if computedAlt > computedCost {
						cacheDelta := computedAlt - computedCost
						rowAltCost = recorded + cacheDelta
					}
				}
			}
		case priced:
			rowCost = cost.Compute(p, bundle)
			rowStdCost = cost.Compute(stripLongContext(p), bundle)
			if bundle.CacheRead > 0 {
				altBundle := bundle
				altBundle.Input += bundle.CacheRead
				altBundle.CacheRead = 0
				rowAltCost = cost.Compute(p, altBundle)
			} else {
				rowAltCost = rowCost
			}
		}

		promptWindow := bundle.Input + bundle.CacheRead + bundle.CacheCreation

		switch {
		case !ts.Before(periodStart) && !ts.After(periodEnd):
			periodCost += rowCost
			periodOutput += bundle.Output
			periodCacheRead += bundle.CacheRead
			periodCacheWrite += bundle.CacheCreation
			if recorded > 0 {
				periodRecordedCost += recorded
			}
			if modelHasLC && rowCost > rowStdCost {
				periodLCEligibleTurns++
				periodLCSurcharge += rowCost - rowStdCost
			}
			if promptWindow > 100_000 {
				periodHC100k++
				periodCostHC100k += rowCost
			}
			if promptWindow > 200_000 {
				periodHC200k++
				periodCostHC200k += rowCost
			}
			if rowAltCost > rowCost {
				periodCacheSavings += rowAltCost - rowCost
			}
			if rowCost > 0 {
				perTurnCosts = append(perTurnCosts, rowCost)
			}
			if model != "" {
				modelCost[model] += rowCost
			}
			activeHours[ts.Format("2006-01-02T15")] = struct{}{}
		case !ts.Before(priorStart) && ts.Before(periodStart):
			priorCost += rowCost
		}
		if !ts.Before(monthStart) && !ts.After(now) {
			mtdCost += rowCost
		}
		if !ts.Before(priorMonthStart) && ts.Before(priorMonthSameDayEnd) {
			priorMonthSameDayCost += rowCost
		}
	}

	// Linear projection to month-end: scale MTD by (days_in_month /
	// days_elapsed). days_elapsed is at least 1 to avoid div-by-zero
	// on the first calendar day of the month.
	daysElapsed := int(now.Sub(monthStart).Hours()/24) + 1
	if daysElapsed < 1 {
		daysElapsed = 1
	}
	daysInMonth := time.Date(now.Year(), now.Month()+1, 0, 0, 0, 0, 0, time.UTC).Day()
	var projection float64
	if daysElapsed > 0 {
		projection = mtdCost * float64(daysInMonth) / float64(daysElapsed)
	}
	// Budget: prefer the live config.toml value so a budget edit from
	// the Cost page's Budget card (P6.3) is reflected here on the next
	// load without a daemon restart. The boot-time Options value is the
	// fallback for servers constructed without a config path (tests).
	budgetUSD := s.opts.MonthlyBudgetUSD
	if s.opts.ConfigPath != "" {
		if cfg, err := loadConfigForDashboard(s.opts.ConfigPath); err == nil {
			budgetUSD = cfg.Intelligence.MonthlyBudgetUSD
		}
	}
	var budgetPct float64
	if budgetUSD > 0 {
		budgetPct = mtdCost / budgetUSD * 100
	}
	var vsPriorMonthPct float64
	priorMonthIsZero := priorMonthSameDayCost == 0
	if !priorMonthIsZero {
		vsPriorMonthPct = (mtdCost - priorMonthSameDayCost) / priorMonthSameDayCost * 100
	}

	// Cache efficacy = read / (read + write).
	var cacheEfficacy float64
	if total := periodCacheRead + periodCacheWrite; total > 0 {
		cacheEfficacy = float64(periodCacheRead) / float64(total)
	}

	// $ per million output tokens — clean rate, independent of cache
	// overhead. Output tokens are the unambiguous value the user gets
	// per dollar; including cache_write (which is paid-for setup) in
	// the denominator masked inefficiency in the prior formulation.
	var outputRate float64
	if periodOutput > 0 {
		outputRate = periodCost * 1_000_000 / float64(periodOutput)
	}

	// Period delta. Prior-zero is a sentinel so JS renders "first period"
	// rather than +∞%.
	priorIsZero := priorCost == 0
	var deltaPct float64
	if !priorIsZero {
		deltaPct = (periodCost - priorCost) / priorCost * 100
	}

	// Recorded-share disclosure: % of period cost that came from upstream
	// `recorded` paths (proxy / JSONL `estimated_cost_usd`). LC surcharge
	// and cache_savings DO decompose these rows when the model has a
	// pricing-table entry (see the rowStdCost/rowAltCost derivation
	// above); a high share mainly signals that rows priced under an
	// UNKNOWN model (no pricing entry) still contribute $0 to those tiles.
	var recordedSharePct float64
	if periodCost > 0 {
		recordedSharePct = periodRecordedCost / periodCost * 100
	}

	// Per-turn cost distribution. p95 uses ceil(0.95 × N) - 1 index (1-based
	// 95th percentile, then 0-based array lookup). Mean is the simple
	// arithmetic mean across non-zero-cost turns.
	var perTurnMean, perTurnP95 float64
	if len(perTurnCosts) > 0 {
		sort.Float64s(perTurnCosts)
		sum := 0.0
		for _, c := range perTurnCosts {
			sum += c
		}
		perTurnMean = sum / float64(len(perTurnCosts))
		p95Idx := int(0.95*float64(len(perTurnCosts))+0.5) - 1
		if p95Idx < 0 {
			p95Idx = 0
		}
		if p95Idx >= len(perTurnCosts) {
			p95Idx = len(perTurnCosts) - 1
		}
		perTurnP95 = perTurnCosts[p95Idx]
	}

	// Burn rate $/active-hour. An "active hour" is any (date, hour) bucket
	// with at least one turn in the period. This is the user's hourly
	// AI bill while engaged — not a steady-state per-clock-hour rate.
	var burnRate float64
	activeHoursCount := len(activeHours)
	if activeHoursCount > 0 {
		burnRate = periodCost / float64(activeHoursCount)
	}

	// Top model by $ + concentration. Single-iteration scan since the map
	// is bounded by the number of distinct models seen (typically <20).
	var topModelKey string
	var topModelCost float64
	for k, c := range modelCost {
		if c > topModelCost {
			topModelKey = k
			topModelCost = c
		}
	}
	var topModelConcentrationPct float64
	if periodCost > 0 {
		topModelConcentrationPct = topModelCost / periodCost * 100
	}

	// Waste $: stale-read tokens × blended input rate. Uses the lighter
	// WastedTokens helper that runs only the stale-reads pass (v1.4.50
	// — Run was overkill since the headline only needs the aggregate).
	wasteTokens := int64(0)
	wasteUSD := 0.0
	blendedRate, brErr := s.opts.CostEngine.BlendedInputRate(r.Context(), s.db(), 30)
	if brErr != nil {
		s.opts.Logger.Warn("analysis: blended input rate", "err", brErr)
		blendedRate = cost.DefaultBlendedInputRate
	}
	if est, dErr := discover.New(s.db()).WastedTokens(r.Context(), discover.Options{Since: periodStart, Limit: 500, Tool: tool, ProjectRoot: project}); dErr != nil {
		s.opts.Logger.Warn("analysis: discover wasted tokens", "err", dErr)
	} else {
		wasteTokens = est
		wasteUSD = float64(wasteTokens) * blendedRate / 1_000_000
	}

	writeJSON(w, map[string]any{
		"days": days,
		"period": map[string]any{
			"cost_usd":                periodCost,
			"prior_cost_usd":          priorCost,
			"prior_is_zero":           priorIsZero,
			"delta_pct":               deltaPct,
			"recorded_cost_share_pct": recordedSharePct,
			"period_start":            periodStart.Format(time.RFC3339),
			"prior_start":             priorStart.Format(time.RFC3339),
		},
		"month": map[string]any{
			"to_date_usd":              mtdCost,
			"projection_usd":           projection,
			"prior_month_same_day_usd": priorMonthSameDayCost,
			"prior_month_is_zero":      priorMonthIsZero,
			"vs_prior_month_pct":       vsPriorMonthPct,
			"budget_usd":               budgetUSD,
			"budget_pct":               budgetPct,
			"days_elapsed":             daysElapsed,
			"days_in_month":            daysInMonth,
		},
		"output_rate": map[string]any{
			"output_tokens":    periodOutput,
			"rate_per_million": outputRate,
		},
		"cache_savings": map[string]any{
			"usd":               periodCacheSavings,
			"cache_read_tokens": periodCacheRead,
			"source_note":       "cache_read priced at input rate vs cache_read rate, summed per-turn",
		},
		"cache": map[string]any{
			"read_tokens":  periodCacheRead,
			"write_tokens": periodCacheWrite,
			"efficacy":     cacheEfficacy,
		},
		"high_context": map[string]any{
			"turns_over_100k":    periodHC100k,
			"turns_over_200k":    periodHC200k,
			"cost_over_100k_usd": periodCostHC100k,
			"cost_over_200k_usd": periodCostHC200k,
			"lc_eligible_turns":  periodLCEligibleTurns,
			"lc_surcharge_usd":   periodLCSurcharge,
		},
		"per_turn": map[string]any{
			"count":    len(perTurnCosts),
			"mean_usd": perTurnMean,
			"p95_usd":  perTurnP95,
		},
		"burn_rate": map[string]any{
			"active_hours":      activeHoursCount,
			"cost_per_hour_usd": burnRate,
			"method_note":       "period $ ÷ distinct (date, hour) buckets with traffic",
		},
		"top_model": map[string]any{
			"key":               topModelKey,
			"cost_usd":          topModelCost,
			"concentration_pct": topModelConcentrationPct,
		},
		"waste": map[string]any{
			"usd":                      wasteUSD,
			"tokens":                   wasteTokens,
			"blended_rate_per_million": blendedRate,
			"source_note":              "stale-read tokens × blended input rate",
		},
	})
}

// handleAnalysisTrend serves /api/analysis/trend?dim=model|project|tool
// &days=N — one point per (day, dim_value) cross-section so the
// Analysis tab can render a daily-stacked-bar drilldown across any of
// three dimensions. Same dedup + reliability as /api/cost (cost engine
// SourceAuto: proxy preferred, JSONL fallback).
//
// dim=model is functionally equivalent to /api/timeseries/tokens-by-model
// — duplicated under the analysis namespace so the JS only needs one
// fetch path regardless of dimension. dim=project and dim=tool are
// new groupings powered by GroupByDayProject / GroupByDayTool added
// to the cost engine alongside this endpoint.
func (s *Server) handleAnalysisTrend(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	projectFilter := r.URL.Query().Get("project")
	toolFilter := r.URL.Query().Get("tool")
	dim := r.URL.Query().Get("dim")
	if dim == "" {
		dim = "model"
	}
	var groupBy cost.GroupBy
	switch dim {
	case "model":
		groupBy = cost.GroupByDayModel
	case "project":
		groupBy = cost.GroupByDayProject
	case "tool":
		groupBy = cost.GroupByDayTool
	default:
		http.Error(w, "dim must be one of: model, project, tool", http.StatusBadRequest)
		return
	}
	// The global window (days / hours / since+until), not days alone: a
	// 1h / 12h / custom window used to silently serve 30 days here.
	since, until := windowRange(r, 30, 1, 36500)
	spec, err := bucketSpec(r, since, until)
	if err != nil {
		writeBucketErr(w, err)
		return
	}

	summary, err := s.opts.CostEngine.Summary(r.Context(), s.db(), cost.Options{
		Days:        days,
		Since:       since,
		Until:       until,
		GroupBy:     groupBy,
		BucketKey:   tsBucketKeyer(spec),
		Source:      cost.SourceAuto,
		ProjectRoot: projectFilter,
		Tool:        toolFilter,
		// One row per (bucket, key); the bucket count is capped
		// (sub-day) or data-bounded (day/week), so this never truncates.
		Limit: 1 << 20,
	})
	if err != nil {
		writeErr(w, err)
		return
	}

	type point struct {
		Bucket      string  `json:"bucket"`
		T           int64   `json:"t"`
		Key         string  `json:"key"`
		TotalTokens int64   `json:"total_tokens"`
		CostUSD     float64 `json:"cost_usd"`
		TurnCount   int     `json:"turn_count"`
	}
	series := make([]point, 0, len(summary.Rows))
	starts := map[string]time.Time{}
	for _, row := range summary.Rows {
		var bucket, key string
		switch groupBy {
		case cost.GroupByDayModel:
			bucket, key = cost.SplitDayModelKey(row.Key)
		case cost.GroupByDayProject:
			bucket, key = cost.SplitDayProjectKey(row.Key)
		case cost.GroupByDayTool:
			bucket, key = cost.SplitDayToolKey(row.Key)
		}
		st, ok := starts[bucket]
		if !ok {
			st = keyStart(spec, bucket)
			starts[bucket] = st
		}
		series = append(series, point{
			Bucket:      bucket,
			T:           millis(st),
			Key:         key,
			TotalTokens: row.Tokens.Input + row.Tokens.Output + row.Tokens.CacheRead + row.Tokens.CacheCreation,
			CostUSD:     row.CostUSD,
			TurnCount:   row.TurnCount,
		})
	}
	// Cost engine returns rows sorted by cost DESC. Re-sort
	// chronologically (then by key for a stable stacking order within
	// a bucket) so the chart axis reads left-to-right.
	sort.SliceStable(series, func(i, j int) bool {
		if series[i].T != series[j].T {
			return series[i].T < series[j].T
		}
		if series[i].Bucket != series[j].Bucket {
			return series[i].Bucket < series[j].Bucket
		}
		return series[i].Key < series[j].Key
	})
	writeJSON(w, withBucketMeta(spec, map[string]any{
		"metric": "trend",
		"dim":    dim,
		"days":   days,
		"series": series,
		"grid":   gridJSON(bucketSlots(spec, starts)),
	}))
}

// handleAnalysisMovers serves /api/analysis/movers?dim=model|project|tool
// &days=N — period-over-period diff for the chosen dimension. Returns
// top 5 cost increases, top 5 decreases, and "new entrants" (keys
// present in the current period but not the prior). Used by the
// Analysis tab's "What changed" band.
//
// Drives the same dim toggle as /api/analysis/trend so a user clicking
// "Project" on the trend chart automatically rerolls the movers table
// onto the same dimension.
func (s *Server) handleAnalysisMovers(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	projectFilter := r.URL.Query().Get("project")
	toolFilter := r.URL.Query().Get("tool")
	dim := r.URL.Query().Get("dim")
	if dim == "" {
		dim = "model"
	}
	var groupBy cost.GroupBy
	switch dim {
	case "model":
		groupBy = cost.GroupByModel
	case "project":
		groupBy = cost.GroupByProject
	case "tool":
		groupBy = cost.GroupByTool
	default:
		http.Error(w, "dim must be one of: model, project, tool", http.StatusBadRequest)
		return
	}

	periodStart, periodEnd, priorStart := periodWindow(r, time.Now().UTC(), days)

	current, err := s.opts.CostEngine.Summary(r.Context(), s.db(), cost.Options{
		Since: periodStart, Until: periodEnd,
		GroupBy: groupBy, Source: cost.SourceAuto,
		ProjectRoot: projectFilter, Tool: toolFilter, Limit: 5000,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	prior, err := s.opts.CostEngine.Summary(r.Context(), s.db(), cost.Options{
		Since: priorStart, Until: periodStart,
		GroupBy: groupBy, Source: cost.SourceAuto,
		ProjectRoot: projectFilter, Tool: toolFilter, Limit: 5000,
	})
	if err != nil {
		writeErr(w, err)
		return
	}

	priorByKey := map[string]float64{}
	for _, row := range prior.Rows {
		priorByKey[row.Key] = row.CostUSD
	}
	currentByKey := map[string]float64{}
	for _, row := range current.Rows {
		currentByKey[row.Key] = row.CostUSD
	}

	type mover struct {
		Key        string  `json:"key"`
		PriorUSD   float64 `json:"prior_usd"`
		CurrentUSD float64 `json:"current_usd"`
		DeltaUSD   float64 `json:"delta_usd"`
		DeltaPct   float64 `json:"delta_pct"`
	}
	type entrant struct {
		Key        string  `json:"key"`
		CurrentUSD float64 `json:"current_usd"`
	}

	allMovers := []mover{}
	newEntrants := []entrant{}
	// Keys present in current — emit either as a mover (had a prior)
	// or as a new entrant (no prior cost).
	for _, row := range current.Rows {
		priorCost, hadPrior := priorByKey[row.Key]
		if !hadPrior || priorCost == 0 {
			if row.CostUSD > 0 {
				newEntrants = append(newEntrants, entrant{Key: row.Key, CurrentUSD: row.CostUSD})
			}
			continue
		}
		delta := row.CostUSD - priorCost
		var deltaPct float64
		if priorCost > 0 {
			deltaPct = delta / priorCost * 100
		}
		allMovers = append(allMovers, mover{
			Key: row.Key, PriorUSD: priorCost, CurrentUSD: row.CostUSD,
			DeltaUSD: delta, DeltaPct: deltaPct,
		})
	}
	// Keys present only in prior — usage went to zero this period.
	// These count as decreases (negative delta) and surface in the
	// movers list so users see "we stopped using X."
	for key, priorCost := range priorByKey {
		if _, ok := currentByKey[key]; ok {
			continue
		}
		allMovers = append(allMovers, mover{
			Key: key, PriorUSD: priorCost, CurrentUSD: 0,
			DeltaUSD: -priorCost, DeltaPct: -100,
		})
	}

	// Top 5 increases (largest positive Δ$) and top 5 decreases
	// (largest negative Δ$). Sorted by signed delta — head of the list
	// is the biggest jump up, tail is the biggest drop.
	sort.SliceStable(allMovers, func(i, j int) bool {
		return allMovers[i].DeltaUSD > allMovers[j].DeltaUSD
	})
	const topN = 5
	increases := []mover{}
	decreases := []mover{}
	for _, m := range allMovers {
		if m.DeltaUSD > 0 && len(increases) < topN {
			increases = append(increases, m)
		}
	}
	for i := len(allMovers) - 1; i >= 0; i-- {
		if allMovers[i].DeltaUSD < 0 && len(decreases) < topN {
			decreases = append(decreases, allMovers[i])
		}
	}
	// New entrants sorted by current cost DESC, capped at topN.
	sort.SliceStable(newEntrants, func(i, j int) bool {
		return newEntrants[i].CurrentUSD > newEntrants[j].CurrentUSD
	})
	if len(newEntrants) > topN {
		newEntrants = newEntrants[:topN]
	}

	writeJSON(w, map[string]any{
		"dim":          dim,
		"days":         days,
		"period_start": periodStart.Format(time.RFC3339),
		"prior_start":  priorStart.Format(time.RFC3339),
		"increases":    increases,
		"decreases":    decreases,
		"new_entrants": newEntrants,
	})
}

// handleAnalysisTopSessions serves /api/analysis/top-sessions?days=N&limit=10
// — the most expensive sessions in the window, with explanatory badges
// describing why each landed in the top.
//
// Per-turn-deduped scan (mirrors handleAnalysisHeadline) so LC dispatch
// runs on each turn before per-session aggregation. Badge logic:
//
//   - opus       → any turn used an Opus-class model (model name contains "opus")
//   - lc_tier    → at least one turn crossed an LC threshold (rowCost > rowStdCost)
//   - many_turns → > 30 turns (heuristic for verbose sessions)
//   - large_prompt → max single-turn prompt > 100K tokens (cache-heavy or LC-adjacent)
//
// Top-N enrichment: a second pass against the sessions table fills in
// tool + started_at + ended_at for the surviving session ids.
func (s *Server) handleAnalysisTopSessions(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	limit := intArg(r, "limit", 10, 1, 100)
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")

	now := time.Now().UTC()
	since, end, _ := periodWindow(r, now, days)
	var until time.Time // open-ended unless the window has a past until
	if end.Before(now) {
		until = end
	}

	turns, err := s.spendTurns(r.Context(), since, until, tool, project, nil)
	if err != nil {
		writeErr(w, err)
		return
	}

	type sessionAgg struct {
		ID          string
		Models      map[string]bool
		Turns       int
		CostUSD     float64
		MaxPrompt   int64
		LCTurnCount int
		HasOpus     bool
	}
	agg := map[string]*sessionAgg{}

	for _, turn := range turns {
		sid, model, bundle := turn.SessionID, turn.Model, turn.Bundle
		if sid == "" {
			continue // unattributed row, can't bucket by session
		}
		rowCost, rowStdCost := s.turnCostAndStandard(turn)

		a, ok := agg[sid]
		if !ok {
			a = &sessionAgg{ID: sid, Models: map[string]bool{}}
			agg[sid] = a
		}
		if model != "" {
			a.Models[model] = true
			if containsCI(model, "opus") {
				a.HasOpus = true
			}
		}
		a.Turns++
		a.CostUSD += rowCost
		prompt := bundle.Input + bundle.CacheRead + bundle.CacheCreation
		if prompt > a.MaxPrompt {
			a.MaxPrompt = prompt
		}
		if rowCost > rowStdCost {
			a.LCTurnCount++
		}
	}

	// Sort by cost DESC and trim to limit.
	ranked := make([]*sessionAgg, 0, len(agg))
	for _, a := range agg {
		if a.CostUSD <= 0 {
			continue
		}
		ranked = append(ranked, a)
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		return ranked[i].CostUSD > ranked[j].CostUSD
	})
	if len(ranked) > limit {
		ranked = ranked[:limit]
	}

	// Enrich with sessions metadata (tool / started_at / ended_at) for
	// the survivors. One IN-list query is fine for a list capped at 100.
	type sessionMeta struct {
		Tool      string
		StartedAt string
		EndedAt   string
	}
	meta := map[string]sessionMeta{}
	if len(ranked) > 0 {
		placeholders := make([]string, 0, len(ranked))
		args := make([]any, 0, len(ranked))
		for _, a := range ranked {
			placeholders = append(placeholders, "?")
			args = append(args, a.ID)
		}
		//nolint:gosec // G202: SQL structure is code-constant and the IN(...) placeholder list is code-built (?,?,…); all values are bound via ? args.
		mq := `SELECT id, COALESCE(tool, ''), COALESCE(started_at, ''),
		              COALESCE(ended_at, '')
		       FROM sessions WHERE id IN (` + joinStrings(placeholders, ",") + `)`
		mrows, mErr := s.db().QueryContext(r.Context(), mq, args...)
		if mErr != nil {
			writeErr(w, mErr)
			return
		}
		for mrows.Next() {
			var id, tool, startedAt, endedAt string
			if err := mrows.Scan(&id, &tool, &startedAt, &endedAt); err != nil {
				mrows.Close()
				writeErr(w, err)
				return
			}
			meta[id] = sessionMeta{Tool: tool, StartedAt: startedAt, EndedAt: endedAt}
		}
		mrows.Close()
	}

	type session struct {
		ID        string   `json:"id"`
		Tool      string   `json:"tool"`
		StartedAt string   `json:"started_at"`
		EndedAt   string   `json:"ended_at,omitempty"`
		Models    []string `json:"models"`
		Turns     int      `json:"turns"`
		MaxPrompt int64    `json:"max_prompt_tokens"`
		LCTurns   int      `json:"lc_turn_count"`
		CostUSD   float64  `json:"cost_usd"`
		Badges    []string `json:"badges"`
	}
	out := make([]session, 0, len(ranked))
	for _, a := range ranked {
		modelList := make([]string, 0, len(a.Models))
		for m := range a.Models {
			modelList = append(modelList, m)
		}
		sort.Strings(modelList)

		badges := []string{}
		if a.HasOpus {
			badges = append(badges, "opus")
		}
		if a.LCTurnCount > 0 {
			badges = append(badges, "lc_tier")
		}
		if a.Turns > 30 {
			badges = append(badges, "many_turns")
		}
		if a.MaxPrompt > 100_000 {
			badges = append(badges, "large_prompt")
		}

		m := meta[a.ID]
		out = append(out, session{
			ID: a.ID, Tool: m.Tool,
			StartedAt: m.StartedAt, EndedAt: m.EndedAt,
			Models: modelList, Turns: a.Turns,
			MaxPrompt: a.MaxPrompt, LCTurns: a.LCTurnCount,
			CostUSD: a.CostUSD, Badges: badges,
		})
	}

	writeJSON(w, map[string]any{
		"days":     days,
		"limit":    limit,
		"sessions": out,
	})
}

// containsCI reports whether s contains substr, case-insensitive. Local
// helper because strings.Contains is case-sensitive and the model id
// case isn't normalized at ingest.
func containsCI(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			a := s[i+j]
			b := substr[j]
			if a >= 'A' && a <= 'Z' {
				a += 32
			}
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// joinStrings is a 0-allocation strings.Join for the placeholder list.
// Avoids importing strings just for this single use.
func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	n := (len(parts) - 1) * len(sep)
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	out = append(out, parts[0]...)
	for _, p := range parts[1:] {
		out = append(out, sep...)
		out = append(out, p...)
	}
	return string(out)
}

// handleAnalysisRoutingSuggestions serves /api/analysis/routing-suggestions
// — the softened "you might have used a cheaper model" signal for the
// Analysis tab's Band 4. Heuristic-driven and intentionally
// conservative: only flag sessions whose work profile is unambiguously
// trivial (small prompt, low output, no LC-tier turns, single
// expensive-model usage), and only suggest a single sibling switch
// per family.
//
// Surfaced as an informational table. Framing is "could have saved $X"
// rather than "you wasted $X" — model choice may be deliberate (user
// wanted Opus's reasoning quality), so the panel is opt-in for the
// price-sensitive user, not a correction.
//
// Sibling map (v1, Anthropic only — cross-provider routing is more
// debatable):
//
//	claude-opus-* → claude-sonnet-4-6 (1/5 the standard rate)
//
// The cheaper sibling is intentionally the current Sonnet flagship
// (no LC tier, predictable pricing) so projected savings don't depend
// on the LC dispatch logic.
func (s *Server) handleAnalysisRoutingSuggestions(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	limit := intArg(r, "limit", 20, 1, 100)
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")

	now := time.Now().UTC()
	since, end, _ := periodWindow(r, now, days)
	var until time.Time // open-ended unless the window has a past until
	if end.Before(now) {
		until = end
	}

	// Conservative thresholds — only flag unambiguously trivial profiles.
	const (
		maxTrivialPromptTokens = 30_000
		maxTrivialOutputTokens = 5_000
		minSavingsUSD          = 0.05
	)

	turns, err := s.spendTurns(r.Context(), since, until, tool, project, nil)
	if err != nil {
		writeErr(w, err)
		return
	}

	type sessionAgg struct {
		ID       string
		Models   map[string]bool
		Bundle   cost.TokenBundle
		CostUSD  float64
		LCTurns  int
		HasOpus  bool
		AnyTurns int
	}
	agg := map[string]*sessionAgg{}

	for _, turn := range turns {
		sid, model, bundle := turn.SessionID, turn.Model, turn.Bundle
		if sid == "" {
			continue
		}

		// Date-effective pricing ladder (recorded cost wins; otherwise the
		// rate in force on the row's own timestamp). The forward-looking
		// "cheaper sibling" projection below stays on the undated Lookup —
		// it's a what-if for switching TODAY.
		rowCost, rowStdCost := s.turnCostAndStandard(turn)

		a, ok := agg[sid]
		if !ok {
			a = &sessionAgg{ID: sid, Models: map[string]bool{}}
			agg[sid] = a
		}
		if model != "" {
			a.Models[model] = true
			if containsCI(model, "opus") {
				a.HasOpus = true
			}
		}
		a.Bundle.Add(bundle)
		a.CostUSD += rowCost
		a.AnyTurns++
		if rowCost > rowStdCost {
			a.LCTurns++
		}
	}

	type suggestion struct {
		SessionID        string   `json:"session_id"`
		CurrentModel     string   `json:"current_model"`
		SuggestedModel   string   `json:"suggested_model"`
		CurrentCostUSD   float64  `json:"current_cost_usd"`
		SuggestedCostUSD float64  `json:"suggested_cost_usd"`
		SavingsUSD       float64  `json:"savings_usd"`
		Reasons          []string `json:"reasons"`
	}
	out := []suggestion{}

	const cheaperSibling = "claude-sonnet-4-6"
	cheaperPricing, cheaperOK := s.opts.CostEngine.Lookup(cheaperSibling)

	for _, a := range agg {
		if !cheaperOK || a.AnyTurns == 0 {
			continue
		}
		// Filter to trivial Opus-only sessions. Mixed-model sessions
		// are intentional (often haiku+opus by design) so we leave
		// them alone.
		if !a.HasOpus || len(a.Models) != 1 {
			continue
		}
		if a.LCTurns > 0 {
			continue // any LC turn signals real work
		}
		promptTokens := a.Bundle.Input + a.Bundle.CacheRead + a.Bundle.CacheCreation
		if promptTokens >= maxTrivialPromptTokens {
			continue
		}
		if a.Bundle.Output >= maxTrivialOutputTokens {
			continue
		}
		projected := cost.Compute(cheaperPricing, a.Bundle)
		savings := a.CostUSD - projected
		if savings < minSavingsUSD {
			continue
		}

		// Resolve the current model to a single id (set has length 1).
		var currentModel string
		for m := range a.Models {
			currentModel = m
		}

		reasons := []string{}
		if promptTokens < maxTrivialPromptTokens {
			reasons = append(reasons, "small prompt")
		}
		if a.Bundle.Output < maxTrivialOutputTokens {
			reasons = append(reasons, "low output")
		}
		reasons = append(reasons, "no LC tier", "single-model session")

		out = append(out, suggestion{
			SessionID:        a.ID,
			CurrentModel:     currentModel,
			SuggestedModel:   cheaperSibling,
			CurrentCostUSD:   a.CostUSD,
			SuggestedCostUSD: projected,
			SavingsUSD:       savings,
			Reasons:          reasons,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].SavingsUSD > out[j].SavingsUSD
	})
	if len(out) > limit {
		out = out[:limit]
	}

	totalSavings := 0.0
	for _, s := range out {
		totalSavings += s.SavingsUSD
	}

	writeJSON(w, map[string]any{
		"days":              days,
		"suggestions":       out,
		"total_savings_usd": totalSavings,
		"sibling_map": map[string]string{
			"opus": cheaperSibling,
		},
		"thresholds": map[string]any{
			"max_trivial_prompt_tokens": maxTrivialPromptTokens,
			"max_trivial_output_tokens": maxTrivialOutputTokens,
			"min_savings_usd":           minSavingsUSD,
		},
		"framing_note": "informational only — model choice may be deliberate",
	})
}

// handleAnalysisCostByHour serves /api/analysis/cost-by-hour — one bucket
// per hour-of-day (0..23) summed across the global window (days / hours /
// since+until). Used by the Analysis tab's "When you spend" chart to
// surface daily-rhythm patterns (e.g. heaviest hours are 14:00–17:00
// local).
//
// Mirrors the headline scan's dedup pattern (proxy preferred, JSONL
// fallback) and the per-turn LC dispatch so per-row cost matches
// /api/cost exactly. Returns buckets sorted by hour ascending so the
// chart axis reads left-to-right.
//
// The hour is the VIEWER's wall-clock hour: `tz=<IANA>` (UTC when absent
// or unknown, echoed as `timezone`). Each turn is placed by its own
// instant in that zone, so a DST change inside the window is exact.
func (s *Server) handleAnalysisCostByHour(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")
	since, until := windowRange(r, 30, 1, 36500)
	loc, tzName, tzFallback := timebucket.LoadZone(r.URL.Query().Get("tz"))

	turns, err := s.spendTurns(r.Context(), since, until, tool, project, nil)
	if err != nil {
		writeErr(w, err)
		return
	}

	type bucket struct {
		Hour      int     `json:"hour"`
		CostUSD   float64 `json:"cost_usd"`
		TurnCount int     `json:"turn_count"`
	}
	buckets := make([]bucket, 24)
	for i := range buckets {
		buckets[i].Hour = i
	}

	for _, turn := range turns {
		// The engine's price: recorded cost when captured, else the rate in
		// force at the row's own timestamp (date-effective).
		ts, rowCost := turn.At.In(loc), turn.CostUSD
		h := ts.Hour()
		if h < 0 || h > 23 {
			continue
		}
		buckets[h].CostUSD += rowCost
		buckets[h].TurnCount++
	}

	sinceStr, untilStr := windowMeta(since, until)
	resp := map[string]any{
		"days":     days,
		"timezone": tzName,
		"tz":       tzName,
		"since":    sinceStr,
		"until":    untilStr,
		"buckets":  buckets,
	}
	if tzFallback {
		resp["tz_fallback"] = true
	}
	writeJSON(w, resp)
}

// handleAnalysisCostByDowHour serves /api/analysis/cost-by-dow-hour — 168
// cells (7 days × 24 hours) summed across the global window (days / hours
// / since+until). Used by the Analysis tab's "When you spend" 2D heatmap
// (day-of-week rows × hour-of-day columns) for surfacing weekly rhythm
// (e.g. light on Mondays, heavy 14:00–17:00 mid-week). The grid stays
// cyclic by design (a DOW × hour matrix, not a time series).
//
// Mirrors handleAnalysisCostByHour's dedup pattern (proxy preferred,
// JSONL fallback) and per-turn cost computation so the totals tie out
// to /api/cost. Day-of-week is Go's time.Weekday() integer (Sun=0 …
// Sat=6) and the hour is the wall-clock hour, both in the viewer's
// `tz=<IANA>` (UTC when absent or unknown, echoed as `timezone`).
func (s *Server) handleAnalysisCostByDowHour(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")
	since, until := windowRange(r, 30, 1, 36500)
	loc, tzName, tzFallback := timebucket.LoadZone(r.URL.Query().Get("tz"))

	turns, err := s.spendTurns(r.Context(), since, until, tool, project, nil)
	if err != nil {
		writeErr(w, err)
		return
	}

	type cell struct {
		Dow       int     `json:"dow"`
		Hour      int     `json:"hour"`
		CostUSD   float64 `json:"cost_usd"`
		TurnCount int     `json:"turn_count"`
	}
	// Pre-allocate the full 7×24 grid so the frontend can render a
	// stable layout even when many cells are zero. Index = dow*24+hour.
	cells := make([]cell, 7*24)
	for d := 0; d < 7; d++ {
		for h := 0; h < 24; h++ {
			cells[d*24+h] = cell{Dow: d, Hour: h}
		}
	}

	for _, turn := range turns {
		// The engine's price: recorded cost when captured, else the rate in
		// force at the row's own timestamp (date-effective).
		ts, rowCost := turn.At.In(loc), turn.CostUSD
		dow := int(ts.Weekday())
		h := ts.Hour()
		if dow < 0 || dow > 6 || h < 0 || h > 23 {
			continue
		}
		cells[dow*24+h].CostUSD += rowCost
		cells[dow*24+h].TurnCount++
	}

	sinceStr, untilStr := windowMeta(since, until)
	resp := map[string]any{
		"days":     days,
		"timezone": tzName,
		"tz":       tzName,
		"since":    sinceStr,
		"until":    untilStr,
		"cells":    cells,
	}
	if tzFallback {
		resp["tz_fallback"] = true
	}
	writeJSON(w, resp)
}

// handleAnalysisCacheSavingsTrend serves
// /api/analysis/cache-savings-trend?days=N|hours=|since=&until=&gran=&tz=
// — one bucket per granularity step (zero-filled) in the global window with the dollar value of cache_read traffic priced
// at (input_rate − cache_read_rate). High savings days are days where
// the user benefited most from cache reuse; flat days are days with
// little cache traffic or all-miss patterns.
//
// Counterfactual: for each turn, the savings is `cost(input += cache_read,
// cache_read = 0) − cost(actual)`. This handles LC dispatch correctly
// because Compute's lcAdjusted runs on the prompt window (input + cache_read +
// cache_creation), which is invariant under the input ↔ cache_read swap.
func (s *Server) handleAnalysisCacheSavingsTrend(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")
	since, until := windowRange(r, 30, 1, 36500)
	spec, err := bucketSpec(r, since, until)
	if err != nil {
		writeBucketErr(w, err)
		return
	}

	turns, err := s.spendTurns(r.Context(), since, until, tool, project, nil)
	if err != nil {
		writeErr(w, err)
		return
	}

	// Day keeps its historical name for the chart's dataKey; it now holds
	// the bucket key of the requested granularity (a UTC day key is
	// byte-identical to before). T is the bucket start, epoch ms.
	type point struct {
		Day             string  `json:"day"`
		T               int64   `json:"t"`
		SavingsUSD      float64 `json:"savings_usd"`
		CacheReadTokens int64   `json:"cache_read_tokens"`
	}
	byDay := map[string]*point{}
	starts := map[string]time.Time{}

	for _, turn := range turns {
		model, bundle, ts := turn.Model, turn.Bundle, turn.At
		if bundle.CacheRead <= 0 {
			continue
		}

		// Same defect class as handleAnalysisHeadline's cache_savings tile
		// (see the comment above that handler): skipping every recorded
		// row here means proxy-tier turns — typically the majority of a
		// wired-up install's traffic — never appear in the daily trend at
		// all. Unlike the headline tile, this endpoint's output (SavingsUSD)
		// is ALREADY a pure delta, not a total cost — there's no `recorded`
		// actual to preserve as ground truth here, so once a pricing entry
		// exists we can price the same bundle twice (actual shape vs the
		// cache-read-as-input counterfactual shape) and report the delta
		// directly, regardless of whether the proxy also recorded a cost
		// for the row. Only when there's no pricing entry do we skip (no
		// invented counterfactual without a pricing basis).
		//
		// bundle.Fast (scanned from the fast column, F6 fix) must be set
		// BEFORE either Compute() call — the fast multiplier applies to
		// both the actual and counterfactual price, so a fast-tier row's
		// delta is itself computed at fast rates, not silently priced at
		// standard rates.
		p, ok := s.opts.CostEngine.LookupAt(model, ts)
		if !ok {
			continue
		}
		actual := cost.Compute(p, bundle)
		alt := bundle
		alt.Input += bundle.CacheRead
		alt.CacheRead = 0
		altCost := cost.Compute(p, alt)
		var savings float64
		if altCost > actual {
			savings = altCost - actual
		}

		// Bucketed in Go from the turn's own instant: exact in the
		// viewer's zone, DST included.
		bstart := spec.Floor(ts)
		day := spec.Key(bstart)
		pt, exists := byDay[day]
		if !exists {
			pt = &point{Day: day}
			byDay[day] = pt
			starts[day] = bstart
		}
		pt.SavingsUSD += savings
		pt.CacheReadTokens += bundle.CacheRead
	}

	slots := bucketSlots(spec, starts)
	out := make([]point, 0, len(slots))
	for _, sl := range slots {
		pt := byDay[sl.Key]
		if pt == nil {
			pt = &point{Day: sl.Key}
		}
		pt.T = millis(sl.T)
		out = append(out, *pt)
	}
	writeJSON(w, withBucketMeta(spec, map[string]any{
		"days":   days,
		"points": out,
	}))
}

// stripLongContext zeros every long-context field on a Pricing entry so
// Compute reverts to the standard tier. Used to compute "what this turn
// would have cost without LC repricing" so the headline can attribute
// the surcharge.
func stripLongContext(p cost.Pricing) cost.Pricing {
	p.LongContextThreshold = 0
	p.LongContextInput = 0
	p.LongContextOutput = 0
	p.LongContextCacheRead = 0
	p.LongContextCacheCreation = 0
	p.LongContextCacheCreation1h = 0
	return p
}
