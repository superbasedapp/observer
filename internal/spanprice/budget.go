package spanprice

import "strings"

// budget.go - what a Plane A app budget counts (ruling D29: findings A-02
// and E-27). One rule for every place an app cap is measured against trace
// spans: the org Budgets page (rollup.appBudgetCandidate), the org SDK
// admit (rollup.AppSpendSince) and the machine's admission check
// (internal/obs/store.AppSpend).
//
//   - Cost: only an EXACT or COMPUTED cost counts (the org price book, D27).
//     A reported cost is the instrumentor's own figure on a model the price
//     book does not know; it is shown on the trace but never charged to a
//     budget, so an app that reports 0 cannot stay under a dollar cap and
//     one that reports a wrong figure cannot trip it (E-27).
//   - Tokens: uncached input plus output, the rule Plane B and the AI
//     gateway already use (the org spend CTE's `tokens`, the gateway's
//     billableTokens). A stored span's input is GROSS (it includes the
//     cache read and cache write tokens, the internal/genaiattr bucket
//     definition), so the uncached part is input minus both cache buckets,
//     floored at 0; output already includes reasoning (A-02).
//
// Only a model-call span counts (CostKind), the L-03 rule.

// BudgetCostSources are the cost sources a budget charges, in order.
var BudgetCostSources = []Source{SourceGatewayExact, SourceProxyExact, SourceComputed}

// BudgetCounts reports whether a span's cost counts toward a budget: a
// model-call kind whose cost source is exact or computed.
func BudgetCounts(kind string, source Source) bool {
	if !CostKind(kind) {
		return false
	}
	for _, s := range BudgetCostSources {
		if source == s {
			return true
		}
	}
	return false
}

// BudgetTokens is a span's budget token count: uncached input plus output
// (input gross of both cache buckets, floored at 0). Zero for a span that is
// not a model call.
func BudgetTokens(kind string, input, output, cacheRead, cacheWrite int64) int64 {
	if !CostKind(kind) {
		return 0
	}
	in := input - cacheRead - cacheWrite
	if in < 0 {
		in = 0
	}
	return in + output
}

// BudgetCostSQL is the SQL expression of a span's budget cost over a span
// row with alias a (for example "s"): its cost_usd when BudgetCounts, else 0.
// Wrap it in SUM.
func BudgetCostSQL(a string) string {
	p := aliasPrefix(a)
	quoted := make([]string, len(BudgetCostSources))
	for i, s := range BudgetCostSources {
		quoted[i] = "'" + string(s) + "'"
	}
	return "CASE WHEN " + CostKindSQL(p+"kind") + " AND COALESCE(" + p + "cost_source,'') IN (" +
		strings.Join(quoted, ",") + ") THEN COALESCE(" + p + "cost_usd,0) ELSE 0 END"
}

// BudgetTokensSQL is the SQL expression of BudgetTokens over a span row with
// alias a. Wrap it in SUM. The floor is a CASE, not GREATEST/MAX, so the one
// spelling runs on SQLite and PostgreSQL.
func BudgetTokensSQL(a string) string {
	p := aliasPrefix(a)
	uncached := "COALESCE(" + p + "input_tokens,0) - COALESCE(" + p + "cache_read_tokens,0) - COALESCE(" + p + "cache_write_tokens,0)"
	return "CASE WHEN " + CostKindSQL(p+"kind") + " THEN (CASE WHEN " + uncached + " > 0 THEN " + uncached +
		" ELSE 0 END) + COALESCE(" + p + "output_tokens,0) ELSE 0 END"
}

func aliasPrefix(a string) string {
	if a == "" {
		return ""
	}
	return a + "."
}
