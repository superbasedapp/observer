package main

import (
	"context"
	"database/sql"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// PRICING COVERAGE IS REPORTED, NOT ENFORCED (ruling A3, 2026-09-15).
//
// The managed accounting read now prices every row it can through the same
// ladder the dashboard uses (org > exact > date-stripped > family > local >
// the adapter's own stored cost) and counts it against the cap. What it can no
// longer do is DENY over a model the org never quoted - that was the defect
// this arc reverses, where a developer's Muse and OpenCode processes were
// TERMed at "$0.26 of $2" while the node's own dashboard priced the same day at
// $0.97.
//
// A gap an admin cannot see is a gap an admin cannot close, so the read's
// coverage evidence is recorded here and travels two ways: onto the node's
// enum-only budget posture (the org Budgets page's coverage note) and onto
// `observer guard status`. Neither is a gate.
//
// It is recorded as TWO classes, not one (BUDGET-COV-3): rows priced by a rung
// the org did not author, whose dollars DO count against the cap, and rows
// nothing priced at all, which count as $0. Only the second is a hole in the
// cap, and only the first is closed by quoting a rate the developer is already
// being charged at.
//
// ONE OWNER, ONE FEED. The value is produced by the ONE read that priced the
// cap's own windows (cmd/observer/guardwire.go's accounting lookup) and stored
// here keyed by database path - the processGuards / processCostEngine
// arrangement, for the same reason: the daemon composes the proxy and the
// watcher through separate store handles over one SQLite file, and the posture
// must not depend on which of them asked last. Recomputing it in the posture
// provider would be a second accounting truth over the same rows.

// budgetPricingCoverage is what one managed accounting read observed about the
// rates behind the dollars it just totalled.
type budgetPricingCoverage struct {
	// FallbackRows counts rows that WERE priced, but through a rung the org did
	// not author (date-stripped / family / local / the adapter's stored cost).
	// Their dollars count against the cap.
	FallbackRows int
	// FallbackModels names the distinct models behind those rows, sorted and
	// already bounded by the store read.
	FallbackModels []string
	// UnpricedRows counts TRUE MISSES only: rows nothing priced (including
	// invalid rows, whose counters or timestamp are broken). They contribute $0.
	UnpricedRows int
	// UnpricedModels names the distinct models behind the true-miss rows (an
	// invalid row names none), sorted and already bounded by the store read.
	UnpricedModels []string
	// Coverage is the orgcontract.PricingCoverage* enum, or "" when nothing
	// was measured.
	Coverage string
}

// budgetPricingCoverageOf classifies one spend result. It is the ONE place the
// three-value vocabulary is decided, so the posture, the status line and the
// org coverage note can never disagree about what "fallback" means.
//
// THE TWO CLASSES TRAVEL SEPARATELY (BUDGET-COV-3, 2026-09-15 later). A
// fallback-priced row and a true miss are opposite facts about a cap: the first
// counts toward it at an estimated rate, the second silently under-reads it at
// $0. They were once summed into one count with one model list, and the first
// live cap crossing proved why that is wrong - a model priced at its family rate
// that had just correctly tripped a $0.75 cap was reported as having "no rate at
// all", because a single true miss elsewhere in the corpus chose the wording for
// the whole list. So each class keeps its own count and its own models here, and
// only the ENUM is worst-case: one true miss still makes the coverage `partial`,
// because a cap that under-reads is the fact an admin must see first.
//
// Invalid rows (broken counters, a timestamp belonging to no window) count with
// the true misses - they also contribute $0 - which is why the sentence this
// feeds says "count as $0" rather than naming a cause the row cannot prove.
func budgetPricingCoverageOf(spend store.GuardBudgetSpendResult) budgetPricingCoverage {
	orgPriced := spend.PricingSources["exact"] + spend.PricingSources["org"]
	fallbackPriced := spend.PricedRows - orgPriced
	if fallbackPriced < 0 {
		fallbackPriced = 0
	}
	out := budgetPricingCoverage{
		FallbackRows:   fallbackPriced,
		FallbackModels: spend.FallbackModels,
		UnpricedRows:   spend.UnpricedRows,
		UnpricedModels: spend.UnpricedModels,
		Coverage:       orgcontract.PricingCoverageComplete,
	}
	switch {
	case spend.UnpricedRows > 0:
		out.Coverage = orgcontract.PricingCoveragePartial
	case fallbackPriced > 0:
		out.Coverage = orgcontract.PricingCoverageFallback
	}
	return out
}

// budgetPricingCoverages holds the last observation per database path.
var budgetPricingCoverages = struct {
	mu sync.Mutex
	m  map[string]budgetPricingCoverage
}{m: map[string]budgetPricingCoverage{}}

// recordBudgetPricingCoverage publishes one managed read's observation.
func recordBudgetPricingCoverage(dbPath string, cov budgetPricingCoverage) {
	if dbPath == "" {
		return
	}
	budgetPricingCoverages.mu.Lock()
	defer budgetPricingCoverages.mu.Unlock()
	budgetPricingCoverages.m[dbPath] = cov
}

// lookupBudgetPricingCoverage returns the last observation, or the zero value
// (Coverage == "") when no managed read has run in this process. ABSENCE IS
// NEVER FABRICATED: an unmeasured node reports nothing and the server renders
// it as "not determined", never as complete coverage.
func lookupBudgetPricingCoverage(dbPath string) budgetPricingCoverage {
	budgetPricingCoverages.mu.Lock()
	defer budgetPricingCoverages.mu.Unlock()
	return budgetPricingCoverages.m[dbPath]
}

// nodeBudgetPricingPostureProvider stamps the observed coverage onto the
// posture row on its way to the org.
//
// It decorates rather than reaching into orgbudget.Posture for the reason the
// direct-control decorator does (cmd/observer/nodeintervention_posture.go):
// internal/orgbudget composes CAPS, and what a price table managed to resolve
// is a different subsystem's answer that only meets the caps here, at the
// daemon boundary. It is read at PUSH time rather than at budget-fetch time so
// the row describes the accounting that is actually running, not the accounting
// that was running when the org's document last arrived.
func nodeBudgetPricingPostureProvider(dbPath string, base store.BudgetPostureProvider) store.BudgetPostureProvider {
	return func() (orgcontract.BudgetPostureRow, bool) {
		if base == nil {
			return orgcontract.BudgetPostureRow{}, false
		}
		row, ok := base()
		if !ok {
			return row, false
		}
		cov := lookupBudgetPricingCoverage(dbPath)
		if cov.Coverage == "" {
			return row, true
		}
		row.PricingCoverage = cov.Coverage
		row.FallbackRows = cov.FallbackRows
		row.FallbackModels = cov.FallbackModels
		row.UnpricedRows = cov.UnpricedRows
		row.UnpricedModels = cov.UnpricedModels
		return row, true
	}
}

// budgetPricingCoverageLine renders the coverage for `observer guard status`.
// It returns "" when nothing was measured, so the status line never claims
// coverage this process did not observe.
//
// The two classes are printed as two pairs, never merged, for the reason
// budgetPricingCoverageOf keeps them apart: `fallback_rows=112
// fallback_models=muse-spark-1.3-contributor unpriced_rows=3
// unpriced_models=big-pickle` says two different things an operator acts on
// differently, where one merged count said neither. A pair whose count is 0 is
// omitted rather than printed as a zero, so the line carries only facts that
// exist.
func budgetPricingCoverageLine(cov budgetPricingCoverage) string {
	switch cov.Coverage {
	case orgcontract.PricingCoverageComplete:
		return " pricing_coverage=complete"
	case orgcontract.PricingCoverageFallback, orgcontract.PricingCoveragePartial:
		line := " pricing_coverage=" + cov.Coverage
		if cov.FallbackRows > 0 {
			line += " fallback_rows=" + strconv.Itoa(cov.FallbackRows)
			if len(cov.FallbackModels) > 0 {
				line += " fallback_models=" + strings.Join(cov.FallbackModels, ",")
			}
		}
		if cov.UnpricedRows > 0 {
			line += " unpriced_rows=" + strconv.Itoa(cov.UnpricedRows)
			if len(cov.UnpricedModels) > 0 {
				line += " unpriced_models=" + strings.Join(cov.UnpricedModels, ",")
			}
		}
		return line
	default:
		return ""
	}
}

// cliBudgetPricingCoverage measures coverage from the CLI process.
//
// `observer guard status` is not the daemon: it has no recorded read of its
// own, and the daemon's observation lives in the daemon's memory. So it does
// what guardBudgetPostureLine already does for the posture itself - recompose
// from the durable inputs, through the same functions the daemon uses
// (acquireProcessCostEngine for the price table, the same managed pricer, the
// same bounded read) rather than a second implementation.
//
// The ONE honest gap: the windows are resolved in UTC, because the cap's own
// timezone travels with the verified body and this line is a display. A cap on
// a non-UTC calendar can therefore straddle a boundary differently from the
// daemon's own count. Every failure path returns the zero value, which prints
// nothing - never a fabricated "complete".
func cliBudgetPricingCoverage(ctx context.Context, cfg config.Config, database *sql.DB) budgetPricingCoverage {
	if database == nil {
		return budgetPricingCoverage{}
	}
	engine := acquireProcessCostEngine(ctx, cfg, database, slog.Default())
	if engine == nil {
		return budgetPricingCoverage{}
	}
	table := engine.Table()
	if table == nil {
		return budgetPricingCoverage{}
	}
	st := store.New(database)
	binding := ""
	if identity, active, err := orgclient.CurrentBudgetIdentity(ctx, st); err == nil && active {
		binding = identity.Binding
	}
	now := time.Now().UTC()
	dayStart, weekStart, monthStart := budgetWindowStarts(now, guard.BudgetCalendars{})
	spend, err := st.GuardBudgetSpendPriced(ctx, "", dayStart, weekStart, monthStart,
		managedBudgetTablePricer(table, binding), store.GuardBudgetReadOptions{Managed: true})
	if err != nil {
		return budgetPricingCoverage{}
	}
	return budgetPricingCoverageOf(spend)
}
