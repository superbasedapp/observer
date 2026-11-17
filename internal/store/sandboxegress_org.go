package store

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// The sandbox egress refusal COUNTS for the org (audit finding CG-15,
// decision D-11). This file, not orgpush.go, owns the read of the node-local
// sandbox_egress_refusals and sandbox_egress_refusal_drops tables for the
// wire (the privacy sentinel forbids both names in orgpush.go; decision D6
// keeps the per-refusal rows on the node), and orgpush.go composes the
// result through composeSandboxEgressCounts, the sandboxposture.go pattern.
//
// What leaves the node is a count per (UTC day x egress tier x closed rule),
// plus the refusals the recorded counts miss (Dropped). Never a host, an
// address, a port, a deciding key, a project root or a run id: the rows are
// built from those three columns and two counts, and clamped through the
// closed vocabularies (orgcontract.ClampSandboxEgressRefusalDay) before they
// are sent. Only a managed node composes them (ShareOptions.Managed).
//
// The node recomputes every day of the window from its source on each
// recompute, so the latest push is the truth for a day and the org replaces
// by key (a day's recorded count can legitimately fall: a run past its
// per-run bound has its oldest rows evicted, and those move into Dropped).

// sandboxEgressOrgWindowDays is how many days back the counts cover: the
// node keeps refusal rows for SandboxEgressRefusalRetention, so the window
// is the whole of what it holds.
const sandboxEgressOrgWindowDays = int(SandboxEgressRefusalRetention / (24 * time.Hour))

// SelectSandboxEgressRefusalDays aggregates the refusal audit into per-day
// counts by tier and closed rule. Refusals count on the day they happened.
// Dropped counts (dropped before written, or evicted past the per-run bound)
// carry no rule and no per-refusal time, so they land on Rule "" on the day
// their run's count last grew, under the run's stored egress tier. The
// uncertain count is left out: it may be charged to more than one run.
func (s *Store) SelectSandboxEgressRefusalDays(ctx context.Context) ([]orgcontract.SandboxEgressRefusalDayRow, error) {
	since := time.Now().UTC().AddDate(0, 0, -sandboxEgressOrgWindowDays).Format(sandboxEgressTimeLayout)
	type key struct{ day, tier, rule string }
	acc := map[key]*orgcontract.SandboxEgressRefusalDayRow{}
	add := func(r orgcontract.SandboxEgressRefusalDayRow) {
		r, ok := orgcontract.ClampSandboxEgressRefusalDay(r)
		if !ok {
			return
		}
		k := key{r.Day, r.Tier, r.Rule}
		if cur, ok := acc[k]; ok {
			cur.Refusals += r.Refusals
			cur.Dropped += r.Dropped
			return
		}
		acc[k] = &r
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT substr(refused_at, 1, 10) AS day, tier, rule, COUNT(*)
		FROM sandbox_egress_refusals
		WHERE refused_at >= ?
		GROUP BY day, tier, rule`, since)
	if err != nil {
		return nil, fmt.Errorf("store.SelectSandboxEgressRefusalDays: %w", err)
	}
	for rows.Next() {
		var r orgcontract.SandboxEgressRefusalDayRow
		if err := rows.Scan(&r.Day, &r.Tier, &r.Rule, &r.Refusals); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store.SelectSandboxEgressRefusalDays: scan: %w", err)
		}
		add(r)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("store.SelectSandboxEgressRefusalDays: %w", err)
	}
	_ = rows.Close()

	drops, err := s.db.QueryContext(ctx, `
		SELECT substr(d.updated_at, 1, 10) AS day, COALESCE(tr.egress_tier, '') AS tier,
		       SUM(d.dropped + d.evicted)
		FROM sandbox_egress_refusal_drops d
		LEFT JOIN terminal_run tr ON tr.run_id = d.run_id
		WHERE d.updated_at >= ?
		GROUP BY day, tier`, since)
	if err != nil {
		return nil, fmt.Errorf("store.SelectSandboxEgressRefusalDays: drops: %w", err)
	}
	defer func() { _ = drops.Close() }()
	for drops.Next() {
		var r orgcontract.SandboxEgressRefusalDayRow
		if err := drops.Scan(&r.Day, &r.Tier, &r.Dropped); err != nil {
			return nil, fmt.Errorf("store.SelectSandboxEgressRefusalDays: drops scan: %w", err)
		}
		add(r)
	}
	if err := drops.Err(); err != nil {
		return nil, fmt.Errorf("store.SelectSandboxEgressRefusalDays: drops: %w", err)
	}

	out := make([]orgcontract.SandboxEgressRefusalDayRow, 0, len(acc))
	for _, r := range acc {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Day != b.Day {
			return a.Day < b.Day
		}
		if a.Tier != b.Tier {
			return a.Tier < b.Tier
		}
		return a.Rule < b.Rule
	})
	return out, nil
}

// probeSandboxEgressCounts is the snapshot gate's change probe for the
// sandbox egress counts (orgsnapgate.go). It lives here, with the wire's
// own read, so orgsnapgate.go and orgpush.go stay free of the table names.
//
// PROBE: MAX(id) and COUNT(*) over the refusals (an insert raises the
// first; an eviction or a prune deletes rows the first cannot see), and
// MAX(updated_at) with the summed counts over the drops (a drop add rewrites
// a row in place). A run's tier stamped after its refusals is the one
// change the probe cannot see; the gate's freshness floor bounds that lag
// to an hour.
func (s *Store) probeSandboxEgressCounts(ctx context.Context) (string, error) {
	return s.snapProbeScalar(ctx, `
		SELECT 'er' || (SELECT COALESCE(MAX(id), 0) || '/' || COUNT(*) FROM sandbox_egress_refusals) ||
		       ':ed' || (SELECT COALESCE(MAX(updated_at), '') || '/' || COALESCE(SUM(dropped + evicted), 0)
		                  FROM sandbox_egress_refusal_drops)`)
}

// composeSandboxEgressCounts returns the day rows for one push envelope when
// the family changed (nothing otherwise), stamped with the attribution and
// fitted to the envelope's snapshot budget (fitSnapshot charges every row
// it keeps against the same budget as every other wire family).
func (s *Store) composeSandboxEgressCounts(ctx context.Context, budget *envelopeBudget, orgID, userEmail string) ([]orgcontract.SandboxEgressRefusalDayRow, error) {
	if !s.snapChanged(ctx, snapFamSandboxEgressCounts) {
		return nil, nil
	}
	rows, err := s.SelectSandboxEgressRefusalDays(ctx)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i].OrgID, rows[i].UserEmail = orgID, userEmail
	}
	kept := fitSnapshot(s, budget, snapFamSandboxEgressCounts, rows)
	if len(kept) == 0 {
		// nil, not empty: the batch's emptiness checks and the wire's
		// omitempty both read "nothing to send".
		return nil, nil
	}
	return kept, nil
}
