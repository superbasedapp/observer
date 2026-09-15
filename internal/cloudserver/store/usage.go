package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ledgerEntry is one append-only analysis_usage_ledger row. Distinguishes user
// units (a reservation) from internal units (a provider attempt/retry, added by
// CI-P4).
type ledgerEntry struct {
	JobID         string // "" ⇒ NULL
	Event         string
	UserUnits     int
	InternalUnits int
	RouteVersion  *int64
	Attempts      *int
	TokensIn      *int64
	TokensOut     *int64
	Detail        string // raw JSON; "" ⇒ '{}'
}

func appendLedgerTx(ctx context.Context, tx pgx.Tx, accountID string, e ledgerEntry) error {
	detail := e.Detail
	if detail == "" {
		detail = "{}"
	}
	var jobID any
	if e.JobID != "" {
		jobID = e.JobID
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO analysis_usage_ledger
		   (account_id, job_id, event, user_units, internal_units, route_version, attempts, tokens_in, tokens_out, detail)
		 VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)`,
		accountID, jobID, e.Event, e.UserUnits, e.InternalUnits, e.RouteVersion, e.Attempts, e.TokensIn, e.TokensOut, detail)
	if err != nil {
		return fmt.Errorf("cloudserver/store.appendLedger: %w", err)
	}
	return nil
}

// Usage-warning levels and the used-fraction thresholds that produce them
// (W4: warn at 70/90/100% per feature window).
const (
	// UsageLevelWarn is emitted from 70% of a window's cap.
	UsageLevelWarn = "warn"
	// UsageLevelCritical is emitted from 90%.
	UsageLevelCritical = "critical"
	// UsageLevelExhausted is emitted at 100% — the next reservation in that
	// window will be refused.
	UsageLevelExhausted = "exhausted"

	usageWarnPercent     = 70
	usageCriticalPercent = 90
)

// UsageWarning is one window's allowance warning. Windows below the warn
// threshold produce no entry at all, so an empty list means "nothing close".
type UsageWarning struct {
	// Window is the cycle kind: daily, monthly or concurrency.
	Window       string  `json:"window"`
	Level        string  `json:"level"`
	Used         int     `json:"used"`
	Cap          int     `json:"cap"`
	UsedFraction float64 `json:"used_fraction"`
}

// UsageSnapshot is the GET /v1/usage view for one feature.
//
// The plan/pool/warning fields are ADDITIVE (W4): every field that existed
// before keeps its name, type and meaning, so an older client reading this
// response is unaffected.
type UsageSnapshot struct {
	Feature         string `json:"feature"`
	DailyUsed       int    `json:"daily_used"`
	DailyCap        int    `json:"daily_cap"`
	MonthlyUsed     int    `json:"monthly_used"`
	MonthlyCap      int    `json:"monthly_cap"`
	ConcurrencyUsed int    `json:"concurrency_used"`
	ConcurrencyCap  int    `json:"concurrency_cap"`

	// Plan is the resolved plan's name (e.g. "free", "plus_beta").
	Plan string `json:"plan"`
	// PlanLabel is the plan's user-facing copy, verbatim — for plus_beta that
	// was the honest R4 string "Plus beta entitlement simulation" (keeping a
	// beta grant from reading as a purchased subscription) until the
	// 2026-09-15 ruling made Plus a real purchasable plan; migration 0037
	// updates the seeded label to plain "Plus".
	PlanLabel   string `json:"plan_label"`
	PlanVersion int    `json:"plan_version"`
	// BudgetPool is the pool this account's reservations draw from. Plus never
	// draws the free pool (R4).
	BudgetPool string `json:"budget_pool"`
	// PlanOverridden reports that an explicit per-account entitlement override
	// supplied the caps instead of the plan.
	PlanOverridden bool `json:"plan_overridden"`
	// Warnings holds one entry per window at or past 70% of its cap. Never
	// null: an empty list is encoded as [].
	Warnings []UsageWarning `json:"warnings"`

	// DigestWeekly reports whether the resolved plan includes the weekly
	// project digest job kind (migration 0037, W5).
	DigestWeekly bool `json:"digest_weekly"`
	// ResultsRetentionDays is how long the resolved plan keeps hosted results
	// before the retention sweep ages them out.
	ResultsRetentionDays int `json:"results_retention_days"`
	// DigestsThisWeek is the count of project_digest results created in the
	// current ISO week (Mon-Sun UTC). Present (computed) only when
	// DigestWeekly is true; zero otherwise.
	DigestsThisWeek int `json:"digests_this_week,omitempty"`
}

// Usage returns the current daily/monthly/concurrency counters for a feature,
// the plan those caps were resolved from, and a warning per window at or past
// 70% of its cap. Absent cycle rows read as 0 used against the resolved cap.
func (s *Store) Usage(ctx context.Context, accountID, feature string, now time.Time) (UsageSnapshot, error) {
	snap := UsageSnapshot{Feature: feature, Warnings: []UsageWarning{}}
	daily := DailyWindowKey(now)
	monthly := MonthlyWindowKey(now)
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		allow, e := resolveAllowanceTx(ctx, tx, accountID, feature, now)
		if e != nil {
			return e
		}
		snap.DailyCap, snap.MonthlyCap, snap.ConcurrencyCap = allow.DailyCap, allow.MonthlyCap, allow.ConcurrencyCap
		snap.Plan, snap.PlanLabel, snap.PlanVersion = allow.Plan.Name, allow.Plan.Label, allow.Plan.Version
		snap.BudgetPool, snap.PlanOverridden = allow.BudgetPool, allow.Overridden
		snap.DailyUsed = cycleUsed(ctx, tx, accountID, feature, "daily", daily)
		snap.MonthlyUsed = cycleUsed(ctx, tx, accountID, feature, "monthly", monthly)
		snap.ConcurrencyUsed = cycleUsed(ctx, tx, accountID, feature, "concurrency", concurrencyWindowKey)
		snap.Warnings = usageWarnings(snap)
		snap.DigestWeekly = allow.Plan.DigestWeekly
		snap.ResultsRetentionDays = allow.Plan.ResultsRetentionDays
		if snap.DigestWeekly {
			n, e := countDigestsThisWeekTx(ctx, tx, accountID, now)
			if e != nil {
				return e
			}
			snap.DigestsThisWeek = n
		}
		return nil
	})
	return snap, err
}

// usageWarnings builds the per-window warning list. Thresholds are compared in
// INTEGER arithmetic (used*100 vs cap*threshold) so a boundary like 70/100 is
// exact rather than at the mercy of binary floating point; the reported
// used_fraction is float only because it is display data.
func usageWarnings(s UsageSnapshot) []UsageWarning {
	out := []UsageWarning{}
	for _, w := range []struct {
		window    string
		used, cap int
	}{
		{"daily", s.DailyUsed, s.DailyCap},
		{"monthly", s.MonthlyUsed, s.MonthlyCap},
		{"concurrency", s.ConcurrencyUsed, s.ConcurrencyCap},
	} {
		if warn, ok := usageWarningFor(w.window, w.used, w.cap); ok {
			out = append(out, warn)
		}
	}
	return out
}

func usageWarningFor(window string, used, cap int) (UsageWarning, bool) {
	if used < 0 {
		used = 0
	}
	// A non-positive cap admits nothing, so it is exhausted by definition —
	// and dividing by it for the fraction would be undefined.
	if cap <= 0 {
		return UsageWarning{Window: window, Level: UsageLevelExhausted, Used: used, Cap: cap, UsedFraction: 1}, true
	}
	var level string
	switch {
	case used >= cap:
		level = UsageLevelExhausted
	case used*100 >= cap*usageCriticalPercent:
		level = UsageLevelCritical
	case used*100 >= cap*usageWarnPercent:
		level = UsageLevelWarn
	default:
		return UsageWarning{}, false
	}
	return UsageWarning{
		Window: window, Level: level, Used: used, Cap: cap,
		UsedFraction: float64(used) / float64(cap),
	}, true
}

func cycleUsed(ctx context.Context, tx pgx.Tx, accountID, feature, kind, windowKey string) int {
	var used int
	err := tx.QueryRow(ctx,
		`SELECT used FROM usage_cycles
		  WHERE account_id = $1::uuid AND feature = $2 AND cycle_kind = $3 AND window_key = $4`,
		accountID, feature, kind, windowKey).Scan(&used)
	if err != nil {
		return 0
	}
	return used
}
