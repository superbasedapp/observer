package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/entitlements"
)

// plangen.go generates the plans rows from the entitlements plan catalog
// (plan 07 M7b.1; plan 06 17.2 "the cloud plans and account_plans tables
// stop being an authored source"; 8.5 "the plans v5 rows become capability
// documents"). The catalog (internal/entitlements) is the one authored
// source: every account-kind template projects to exactly one plans row,
// and this file is the only code that writes the table. Cloud migration
// 0084 makes that structural: a BEFORE INSERT trigger refuses any insert
// whose transaction has not set sbci.plan_writer = 'generator', which only
// GeneratePlans does.
//
// Rows are immutable (0012's trigger), so the generator inserts a missing
// (name, version) and CHECKS an existing one: a row that differs from its
// template is drift, refused, never rewritten. Versions below the catalog's
// (free and plus_beta v1-v4) are migration history and stay as they are.

// planGenWriterSetting is the transaction setting the 0084 trigger reads.
const planGenWriterSetting = "sbci.plan_writer"

// ErrPlanDrift means a plans row differs from the catalog template of the
// same (name, version), or a template does not project to a row.
var ErrPlanDrift = errors.New("cloudserver/store: plans row differs from the entitlements catalog")

// planColumn is one row of the projection table: how one plans column is
// read from an account-kind template. A required cap or term that the
// template lacks, or an Unlimited cap (the columns hold finite counts), is
// a projection error.
type planColumn struct {
	column string
	set    func(p *Plan, b entitlements.Body) error
}

func capColumn(column string, n entitlements.CapName, dst func(*Plan) *int) planColumn {
	return planColumn{column: column, set: func(p *Plan, b entitlements.Body) error {
		v, ok := b.Caps[n]
		if !ok {
			return fmt.Errorf("%s: the template sets no %s", column, n)
		}
		if v < 0 || v > 1<<31-1 {
			return fmt.Errorf("%s: %s = %d does not fit the column (Unlimited has no plans form)", column, n, v)
		}
		*dst(p) = int(v)
		return nil
	}}
}

func termColumn(column string, n entitlements.TermName, required bool, dst func(*Plan) *string) planColumn {
	return planColumn{column: column, set: func(p *Plan, b entitlements.Body) error {
		v, ok := b.Terms[n]
		if !ok && required {
			return fmt.Errorf("%s: the template sets no %s", column, n)
		}
		*dst(p) = v
		return nil
	}}
}

// planColumns is the projection table, one row per generated column.
func planColumns() []planColumn {
	return []planColumn{
		{column: "name", set: func(p *Plan, b entitlements.Body) error { p.Name = b.Plan.Name; return nil }},
		{column: "version", set: func(p *Plan, b entitlements.Body) error { p.Version = b.Plan.Version; return nil }},
		{column: "label", set: func(p *Plan, b entitlements.Body) error { p.Label = b.Plan.Label; return nil }},
		capColumn("daily_cap", entitlements.CapEnrichmentDaily, func(p *Plan) *int { return &p.DailyCap }),
		capColumn("monthly_cap", entitlements.CapEnrichmentMonthly, func(p *Plan) *int { return &p.MonthlyCap }),
		capColumn("concurrency_cap", entitlements.CapEnrichmentConcurrency, func(p *Plan) *int { return &p.ConcurrencyCap }),
		capColumn("results_retention_days", entitlements.CapEnrichmentResultsRetentionDays, func(p *Plan) *int { return &p.ResultsRetentionDays }),
		termColumn("budget_pool", entitlements.TermEnrichmentBudgetPool, true, func(p *Plan) *string { return &p.BudgetPool }),
		termColumn("route_id", entitlements.TermEnrichmentRoute, false, func(p *Plan) *string { return &p.RouteID }),
		termColumn("enrichment_tier", entitlements.TermEnrichmentTier, false, func(p *Plan) *string { return &p.EnrichmentTier }),
		{column: "digest_weekly", set: func(p *Plan, b entitlements.Body) error {
			// The weekly project digest is the org.digest capability (the
			// price card sells "digest email" on Personal Pro).
			for _, id := range b.Capabilities {
				if id == planDigestCapability {
					p.DigestWeekly = true
				}
			}
			return nil
		}},
	}
}

// planDigestCapability is the capability digest_weekly projects from.
const planDigestCapability = "org.digest"

// PlanFromTemplate projects one account-kind catalog template to its plans
// row (ID empty). It is pure.
func PlanFromTemplate(b entitlements.Body) (Plan, error) {
	if b.Kind != entitlements.KindAccount {
		return Plan{}, fmt.Errorf("store.PlanFromTemplate: %s v%d is kind %s, only %s templates are plans rows: %w",
			b.Plan.Name, b.Plan.Version, b.Kind, entitlements.KindAccount, ErrPlanDrift)
	}
	var p Plan
	var probs []string
	for _, c := range planColumns() {
		if err := c.set(&p, b); err != nil {
			probs = append(probs, err.Error())
		}
	}
	if len(probs) > 0 {
		return Plan{}, fmt.Errorf("store.PlanFromTemplate: %s v%d: %s: %w", b.Plan.Name, b.Plan.Version, strings.Join(probs, "; "), ErrPlanDrift)
	}
	return p, nil
}

// GeneratedPlans returns the plans rows the catalog generates, in catalog
// order.
func GeneratedPlans() ([]Plan, error) {
	var out []Plan
	for _, b := range entitlements.PlansOfKind(entitlements.KindAccount) {
		p, err := PlanFromTemplate(b)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// PlanDrift is one catalog plan whose row is missing or differs.
type PlanDrift struct {
	Name    string
	Version int
	// Missing reports that no row exists yet (GeneratePlans would insert
	// it); otherwise Diff names the columns that differ.
	Missing bool
	Diff    []string
}

func (d PlanDrift) String() string {
	if d.Missing {
		return fmt.Sprintf("%s v%d: missing", d.Name, d.Version)
	}
	return fmt.Sprintf("%s v%d: %s", d.Name, d.Version, strings.Join(d.Diff, ", "))
}

// PlanGenReport is what GeneratePlans did.
type PlanGenReport struct {
	// Inserted are the (name vN) rows written.
	Inserted []string
	// Unchanged are the rows that already matched their template.
	Unchanged []string
}

// TxBeginner is the one method the generator needs (a *pgxpool.Pool, the
// migrating login's pool).
type TxBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// planDiff names the generated columns where got differs from want.
func planDiff(want, got Plan) []string {
	var d []string
	add := func(col string, w, g any) {
		if w != g {
			d = append(d, fmt.Sprintf("%s %v != catalog %v", col, g, w))
		}
	}
	add("label", want.Label, got.Label)
	add("daily_cap", want.DailyCap, got.DailyCap)
	add("monthly_cap", want.MonthlyCap, got.MonthlyCap)
	add("concurrency_cap", want.ConcurrencyCap, got.ConcurrencyCap)
	add("budget_pool", want.BudgetPool, got.BudgetPool)
	add("digest_weekly", want.DigestWeekly, got.DigestWeekly)
	add("results_retention_days", want.ResultsRetentionDays, got.ResultsRetentionDays)
	add("route_id", want.RouteID, got.RouteID)
	add("enrichment_tier", want.EnrichmentTier, got.EnrichmentTier)
	return d
}

// checkPlansTx compares every generated row with the table.
func checkPlansTx(ctx context.Context, tx pgx.Tx, plans []Plan) ([]PlanDrift, error) {
	var out []PlanDrift
	for _, want := range plans {
		got, err := loadPlanTx(ctx, tx, want.Name, want.Version)
		if errors.Is(err, ErrPlanNotFound) {
			out = append(out, PlanDrift{Name: want.Name, Version: want.Version, Missing: true})
			continue
		}
		if err != nil {
			return nil, err
		}
		if d := planDiff(want, got); len(d) > 0 {
			out = append(out, PlanDrift{Name: want.Name, Version: want.Version, Diff: d})
		}
	}
	return out, nil
}

// CheckPlans reports, read-only, every catalog plan whose plans row is
// missing or differs. Empty means the table holds the catalog.
func CheckPlans(ctx context.Context, db TxBeginner) ([]PlanDrift, error) {
	plans, err := GeneratedPlans()
	if err != nil {
		return nil, err
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("store.CheckPlans: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	return checkPlansTx(ctx, tx, plans)
}

// GeneratePlans writes the catalog's plans rows: it inserts every missing
// (name, version) and checks every existing one, in one transaction. Any
// drift fails the whole run and writes nothing. It runs as the migrating
// login (the table's owner; the application roles hold SELECT only), from
// `observer-cloud migrate`, after the migrations.
func GeneratePlans(ctx context.Context, db TxBeginner) (PlanGenReport, error) {
	plans, err := GeneratedPlans()
	if err != nil {
		return PlanGenReport{}, err
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return PlanGenReport{}, fmt.Errorf("store.GeneratePlans: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config($1, 'generator', true), set_config('lock_timeout', '5s', true)`, planGenWriterSetting); err != nil {
		return PlanGenReport{}, fmt.Errorf("store.GeneratePlans: mark the writer: %w", err)
	}
	drift, err := checkPlansTx(ctx, tx, plans)
	if err != nil {
		return PlanGenReport{}, fmt.Errorf("store.GeneratePlans: %w", err)
	}
	var rep PlanGenReport
	missing := map[string]bool{}
	var probs []string
	for _, d := range drift {
		if d.Missing {
			missing[fmt.Sprintf("%s v%d", d.Name, d.Version)] = true
			continue
		}
		probs = append(probs, d.String())
	}
	if len(probs) > 0 {
		return PlanGenReport{}, fmt.Errorf("store.GeneratePlans: %s: %w", strings.Join(probs, "; "), ErrPlanDrift)
	}
	for _, p := range plans {
		key := fmt.Sprintf("%s v%d", p.Name, p.Version)
		if !missing[key] {
			rep.Unchanged = append(rep.Unchanged, key)
			continue
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO plans (name, version, label, daily_cap, monthly_cap, concurrency_cap, budget_pool,
			                    digest_weekly, results_retention_days, route_id, enrichment_tier)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, nullif($10, ''), nullif($11, ''))
			 ON CONFLICT (name, version) DO NOTHING`,
			p.Name, p.Version, p.Label, p.DailyCap, p.MonthlyCap, p.ConcurrencyCap, p.BudgetPool,
			p.DigestWeekly, p.ResultsRetentionDays, p.RouteID, p.EnrichmentTier); err != nil {
			return PlanGenReport{}, fmt.Errorf("store.GeneratePlans: insert %s: %w", key, err)
		}
		rep.Inserted = append(rep.Inserted, key)
	}
	// A concurrent generator may have inserted a row between the check and
	// the insert (DO NOTHING); re-check so what commits is the catalog.
	after, err := checkPlansTx(ctx, tx, plans)
	if err != nil {
		return PlanGenReport{}, fmt.Errorf("store.GeneratePlans: %w", err)
	}
	if len(after) > 0 {
		var s []string
		for _, d := range after {
			s = append(s, d.String())
		}
		return PlanGenReport{}, fmt.Errorf("store.GeneratePlans: after insert: %s: %w", strings.Join(s, "; "), ErrPlanDrift)
	}
	if err := tx.Commit(ctx); err != nil {
		return PlanGenReport{}, fmt.Errorf("store.GeneratePlans: commit: %w", err)
	}
	return rep, nil
}
