package main

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// orgPushPricer bridges the dashboard's cost.Engine to the org-push seam's
// store.OrgPushPricer (G1-COST(b)). It reproduces, step for step, the
// per-row math cost.Summary applies when a token_usage row's stored cost
// is $0 (internal/intelligence/cost/summary.go rollup loop):
//
//   - date-aware lookup ONLY when the table carries dated pricing
//     (HasDatedPricing); otherwise a zero `at` → current rate card, so an
//     install without dated overrides prices identically to Lookup;
//   - ComputeBreakdown(...).Total — the 3-way input/cached/output split
//     with reasoning billed at the output rate, cache_creation split into
//     the 5m/1h subsets, the flat web_search fee, and the fast-mode
//     multiplier;
//   - unknown model → ok=false (the seam then keeps the stored $0).
//
// One engine, one pricing truth: the engine is built from the same
// cfg.Intelligence the node dashboard, `observer cost`, the proxy's
// insert-time pricer and every other cost surface use.
func orgPushPricer(engine *cost.Engine) store.OrgPushPricer {
	return func(model string, at time.Time, s store.PushTokenSplit) (float64, bool) {
		usd, _, ok := priceWithCostEngine(engine, model, at, s)
		return usd, ok
	}
}

// guardBudgetPricer bridges the shared cost.Engine to the guard's bounded
// read-time accounting seam. It returns the same source-aware price as the
// push-time pricer, while retaining the provenance needed to report exact,
// org, local, family, and miss rows honestly.
func guardBudgetPricer(engine *cost.Engine) store.GuardBudgetPricer {
	var table *cost.Table
	if engine != nil {
		table = engine.Table()
	}
	return guardBudgetTablePricer(table)
}

// guardBudgetTablePricer pins one table for every row of the bounded read.
// Concurrent org delivery or local repricing cannot mix rate revisions in a
// single budget total.
func guardBudgetTablePricer(table *cost.Table) store.GuardBudgetPricer {
	return func(model string, at time.Time, s store.PushTokenSplit) (float64, string, bool) {
		usd, source, ok := priceWithCostTable(table, model, at, s)
		return usd, string(source), ok
	}
}

// managedBudgetTablePricer accepts an org rate only when this exact table was
// authenticated for the enrollment that owns the budget being evaluated.
func managedBudgetTablePricer(table *cost.Table, binding string) store.GuardBudgetPricer {
	price := guardBudgetTablePricer(table)
	return func(model string, at time.Time, split store.PushTokenSplit) (float64, string, bool) {
		usd, source, ok := price(model, at, split)
		if source == string(cost.PricingSourceOrg) && (binding == "" || table.EnrollmentBinding() != binding) {
			return 0, "unverified_org", false
		}
		return usd, source, ok
	}
}

// priceWithCostEngine is the one adapter for read-time and push-time token
// pricing. Historical timestamps are used only when the active engine carries
// dated pricing; otherwise the zero timestamp preserves the current-rate
// behavior of the ordinary cost surfaces.
func priceWithCostEngine(
	engine *cost.Engine,
	model string,
	at time.Time,
	s store.PushTokenSplit,
) (float64, cost.PricingSource, bool) {
	if engine == nil {
		return 0, cost.PricingSourceMiss, false
	}
	return priceWithCostTable(engine.Table(), model, at, s)
}

func priceWithCostTable(table *cost.Table, model string, at time.Time, s store.PushTokenSplit) (float64, cost.PricingSource, bool) {
	if table == nil {
		return 0, cost.PricingSourceMiss, false
	}
	if !table.HasDated() {
		at = time.Time{}
	}
	pricing, source, ok := table.LookupWithSourceAt(model, at)
	if !ok {
		return 0, source, false
	}
	return cost.ComputeBreakdown(pricing, cost.TokenBundle{
		Input:             s.Input,
		Output:            s.Output,
		CacheRead:         s.CacheRead,
		CacheCreation:     s.CacheCreation,
		CacheCreation1h:   s.CacheCreation1h,
		Reasoning:         s.Reasoning,
		WebSearchRequests: s.WebSearchRequests,
		Fast:              s.Fast,
	}).Total, source, true
}
