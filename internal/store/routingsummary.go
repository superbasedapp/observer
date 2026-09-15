package store

import (
	"context"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/routing"
)

// §R19.4 org rollup aggregation. This file — NOT orgpush.go — owns the
// router_decisions read (the privacy sentinel forbids that table name
// from ever appearing in orgpush.go; the push path composes this
// aggregate via a function call). The output is AGGREGATE ONLY:
// counts + dollars by (day, tier, reason, mode). Tier is the ORIGINAL
// model's class resolved through the seed table — model ids never
// enter the wire shape.

// routingSummaryWindowDays bounds the aggregate to the recent window;
// the server upserts by natural key, so re-pushing a window is
// idempotent.
const routingSummaryWindowDays = 7

// SelectRoutingSummaries aggregates the decision log into the §R19.4
// wire rows.
func (s *Store) SelectRoutingSummaries(ctx context.Context) ([]orgcontract.RoutingSummaryRow, error) {
	since := time.Now().UTC().AddDate(0, 0, -routingSummaryWindowDays)
	rows, err := s.db.QueryContext(ctx, `
		SELECT substr(ts, 1, 10), original_model, COALESCE(reason_codes, '[]'), mode, applied,
		       COUNT(*), SUM(est_savings_usd), SUM(cache_forfeit_usd)
		FROM router_decisions
		WHERE ts >= ?
		GROUP BY 1, 2, 3, 4, 5`, timestamp(since))
	if err != nil {
		return nil, fmt.Errorf("store.SelectRoutingSummaries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	tiers := routing.NewTierResolver().Table()
	agg := map[orgcontract.RoutingSummaryRow]*orgcontract.RoutingSummaryRow{}
	var order []orgcontract.RoutingSummaryRow
	for rows.Next() {
		var (
			day, model, codes, mode string
			applied                 int64
			n                       int64
			savings, forfeit        float64
		)
		if err := rows.Scan(&day, &model, &codes, &mode, &applied, &n, &savings, &forfeit); err != nil {
			return nil, fmt.Errorf("store.SelectRoutingSummaries: scan: %w", err)
		}
		tier, _ := tiers.Lookup(model)
		key := orgcontract.RoutingSummaryRow{
			Day: day, Tier: string(tier), Reason: firstReasonCode(codes), Mode: mode,
		}
		cell, ok := agg[key]
		if !ok {
			cell = &orgcontract.RoutingSummaryRow{Day: key.Day, Tier: key.Tier, Reason: key.Reason, Mode: key.Mode}
			agg[key] = cell
			order = append(order, key)
		}
		cell.Decisions += n
		if applied != 0 {
			cell.Applied += n
		}
		cell.EstSavingsUSD += savings
		cell.CacheForfeitUSD += forfeit
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]orgcontract.RoutingSummaryRow, 0, len(order))
	for _, key := range order {
		out = append(out, *agg[key])
	}
	return out, nil
}

// firstReasonCode extracts the primary code from the stored JSON array
// without a full unmarshal dependency loop: ["a","b"] → a.
func firstReasonCode(codes string) string {
	const min = len(`["x"]`)
	if len(codes) < min || codes[0] != '[' || codes[1] != '"' {
		return ""
	}
	for i := 2; i < len(codes); i++ {
		if codes[i] == '"' {
			return codes[2:i]
		}
	}
	return ""
}

// probeRouterDecisions is the Track R2 change-detection probe SHARED by every
// wire fed from the routing decision log: routing_summary (this file),
// routing_detail (routingdetail.go) and routing_dev (routingdevorgrows.go).
// It lives here — with the other router_decisions SQL — so orgsnapgate.go and
// orgpush.go stay free of the table name.
//
// PROBE: COALESCE(MAX(id),0) over the whole table — a single index-endpoint
// seek on the AUTOINCREMENT primary key, O(1) regardless of history depth.
//
// WHY THAT REFLECTS MUTATION: router_decisions is append-only. The only writes
// are InsertRouterDecisions and the retention sweep's DELETE; there is no
// UPDATE path, so a new decision always advances MAX(id).
//
// RESIDUAL, BOUNDED BY THE FRESHNESS FLOOR: a retention DELETE inside the
// 7-day aggregate window (only reachable with a retention cutoff at or below
// that window) shrinks a bucket without moving MAX(id). AUTOINCREMENT means
// ids are never reused, so the value can only fall if the newest rows
// themselves are deleted. Either way snapGate's maxSkipAge forces a full
// recompute within the hour.
func (s *Store) probeRouterDecisions(ctx context.Context) (string, error) {
	return s.snapProbeScalar(ctx, `SELECT 'rd' || COALESCE(MAX(id), 0) FROM router_decisions`)
}
