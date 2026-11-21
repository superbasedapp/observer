package store

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// GuardBudgetObservedPriced is GuardBudgetObserved over the PRICED substrate,
// plus what that read could not price.
type GuardBudgetObservedPriced struct {
	GuardBudgetObserved
	// UnpricedRows counts rows in the window the read counted as $0
	// (nothing in the ladder priced them, or they are invalid).
	UnpricedRows int
}

// GuardBudgetObservedStatsPriced is GuardBudgetObservedStats computed through
// the read the guard's own budget rules compare against: the advisory
// GuardBudgetSpendPriced substrate (the stored sessionmsg dedup verdicts,
// a recorded cost when the source recorded one, otherwise the price table).
//
// WHY IT EXISTS (demo bug #6, 2026-11-10). The Security page's Budget
// guardrails card sized its suggestions from GuardBudgetObservedStats, which
// sums only the RECORDED cost columns (api_turns.cost_usd,
// token_usage.estimated_cost_usd). Transcript rows are priced at read time
// and carry no recorded cost, so on a node whose Claude Code traffic is not
// proxied the card saw "n=3 days" and "$0.00 today" while the Cost page,
// pricing the same rows, showed ~$3,469 over 30 days. The guard's own budget
// lookup already prices these rows (cmd/observer/guardwire.go), so the card
// measured a different substrate from the rule it claimed to size.
//
// Days are UTC calendar days, as GuardBudgetObservedStats buckets them.
// Zero-cost sessions and days are excluded the same way. pricer must be
// non-nil.
func (s *Store) GuardBudgetObservedStatsPriced(ctx context.Context, since time.Time, pricer GuardBudgetPricer) (GuardBudgetObservedPriced, error) {
	var out GuardBudgetObservedPriced
	if pricer == nil {
		return out, fmt.Errorf("store.GuardBudgetObservedStatsPriced: a pricer is required")
	}
	since = since.UTC()
	now := time.Now()
	args := append(guardBudgetUsageArgs(false, "", since, now), guardBudgetUsageArgs(false, "", since, now)...)
	s.refreshSpendVerdictsBounded(ctx)
	//nolint:gosec // G202: the statement is closed constant SQL; all caller values are bound in args.
	rows, err := s.db.QueryContext(ctx, guardBudgetSpendPricedSQL(false), args...)
	if err != nil {
		return out, fmt.Errorf("store.GuardBudgetObservedStatsPriced: query: %w", err)
	}
	defer rows.Close()

	bySession := map[string]float64{}
	byDay := map[string]float64{}
	for rows.Next() {
		var r guardBudgetSpendRow
		var source, fast, lift, incomplete, unverified int
		if err := rows.Scan(
			&source, &r.sessionID, &r.timestamp, &r.tool, &r.model,
			&r.inputTokens, &r.outputTokens, &r.cacheReadTokens,
			&r.cacheCreation, &r.cacheCreation1h, &r.reasoningTokens,
			&r.webSearchRequest, &r.storedUSD, &fast, &lift, &incomplete, &unverified,
		); err != nil {
			return out, fmt.Errorf("store.GuardBudgetObservedStatsPriced: scan: %w", err)
		}
		r.fast = fast != 0
		r.incomplete = incomplete != 0
		r.unverified = unverified != 0
		if lift != 0 && !r.fast {
			r.fast = true
			r.storedUSD = 0
		}
		usd, _, priced, _ := priceGuardBudgetRow(r, pricer, false)
		if !priced {
			if hasGuardBudgetBillableUsage(r) {
				out.UnpricedRows++
			}
			continue
		}
		bySession[r.sessionID] += usd
		day := guardBudgetOrderedAt(r.timestamp)
		if at, err := time.Parse(time.RFC3339Nano, r.timestamp); err == nil {
			day = at.UTC().Format("2006-01-02")
		} else if len(day) >= 10 {
			day = day[:10]
		}
		byDay[day] += usd
	}
	if err := rows.Err(); err != nil {
		return out, fmt.Errorf("store.GuardBudgetObservedStatsPriced: rows: %w", err)
	}
	sessVals := positiveValues(bySession)
	dayVals := positiveValues(byDay)
	out.Sessions = len(sessVals)
	out.SessionP95USD, out.SessionMaxUSD = p95AndMax(sessVals)
	out.Days = len(dayVals)
	out.DailyP95USD, out.DailyMaxUSD = p95AndMax(dayVals)
	return out, nil
}

// positiveValues returns the map's positive values in a stable order.
func positiveValues(m map[string]float64) []float64 {
	keys := make([]string, 0, len(m))
	for k, v := range m {
		if v > 0 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := make([]float64, 0, len(keys))
	for _, k := range keys {
		out = append(out, m[k])
	}
	return out
}
