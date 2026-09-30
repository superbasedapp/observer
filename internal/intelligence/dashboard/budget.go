package dashboard

import (
	"net/http"
	"time"
)

// Budget guardrails v2 (usability arc P6.3 / review §8.2): month-to-
// date spend vs the operator's self-set budgets — global and
// per-project — with a linear month-end forecast and 80/100%
// threshold levels. ADVISORY ONLY by design (P1): this surface renders
// banners and progress bars; nothing here, or anywhere else, gates
// proxy traffic.
//
// Budgets are read FRESH from config.toml on every request (the
// loadConfigForDashboard pattern), so edits from the Cost page's
// Budget card apply on the next poll without a daemon restart.

// budgetScope is the budget state for one scope (global or a project).
type budgetScope struct {
	Root        string  `json:"root,omitempty"`
	BudgetUSD   float64 `json:"budget_usd"`
	MTDUSD      float64 `json:"mtd_usd"`
	Pct         float64 `json:"pct"`
	ForecastUSD float64 `json:"forecast_usd"`
	// Threshold is "" (under 80%), "warn80", or "over100" — the
	// banner's firing level.
	Threshold string `json:"threshold,omitempty"`
}

// handleBudget serves GET /api/budget. When no budget is configured
// anywhere it reports configured=false after one config read — zero
// DB work for installs that never set a budget (the banner polls
// this).
func (s *Server) handleBudget(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}

	globalBudget := s.opts.MonthlyBudgetUSD
	var projectBudgets map[string]float64
	if cfg, err := loadConfigForDashboard(s.opts.ConfigPath); err == nil {
		globalBudget = cfg.Intelligence.MonthlyBudgetUSD
		projectBudgets = cfg.Intelligence.ProjectBudgetsUSD
	}
	configured := globalBudget > 0
	for _, b := range projectBudgets {
		if b > 0 {
			configured = true
		}
	}

	now := time.Now().UTC()
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	daysElapsed := int(now.Sub(monthStart).Hours()/24) + 1
	daysInMonth := time.Date(now.Year(), now.Month()+1, 0, 0, 0, 0, 0, time.UTC).Day()

	resp := map[string]any{
		"configured":    configured,
		"month":         now.Format("2006-01"),
		"days_elapsed":  daysElapsed,
		"days_in_month": daysInMonth,
	}
	if !configured || s.db() == nil {
		writeJSON(w, resp)
		return
	}

	globalMTD, perRoot, err := s.monthToDateCostByProject(r, monthStart)
	if err != nil {
		writeErr(w, err)
		return
	}

	project := float64(daysInMonth) / float64(daysElapsed)
	if globalBudget > 0 {
		resp["global"] = scopeFor("", globalBudget, globalMTD, project)
	}
	projects := []budgetScope{}
	for root, budget := range projectBudgets {
		if budget <= 0 {
			continue
		}
		projects = append(projects, scopeFor(root, budget, perRoot[root], project))
	}
	// Deterministic order: highest budget consumption first.
	for i := 1; i < len(projects); i++ {
		for j := i; j > 0 && projects[j].Pct > projects[j-1].Pct; j-- {
			projects[j], projects[j-1] = projects[j-1], projects[j]
		}
	}
	resp["projects"] = projects
	writeJSON(w, resp)
}

// scopeFor assembles one budget scope with pct, linear forecast, and
// threshold level.
func scopeFor(root string, budget, mtd, projection float64) budgetScope {
	sc := budgetScope{
		Root:        root,
		BudgetUSD:   budget,
		MTDUSD:      mtd,
		Pct:         mtd / budget * 100,
		ForecastUSD: mtd * projection,
	}
	switch {
	case sc.Pct >= 100:
		sc.Threshold = "over100"
	case sc.Pct >= 80:
		sc.Threshold = "warn80"
	}
	return sc
}

// monthToDateCostByProject returns the month-to-date spend, total and
// grouped by project root, over the node's deduped spend substrate
// (spendTurns: the one session dedup rule, sessionmsg.DeriveVerdicts, applied
// by the cost engine), so the budget card agrees with the Cost page and the
// Sessions list. Rows without a resolvable project count toward the global
// total only.
func (s *Server) monthToDateCostByProject(r *http.Request, monthStart time.Time) (float64, map[string]float64, error) {
	turns, err := s.spendTurns(r.Context(), monthStart, time.Time{}, "", "", nil)
	if err != nil {
		return 0, nil, err
	}
	var total float64
	perRoot := map[string]float64{}
	for _, t := range turns {
		total += t.CostUSD
		if t.ProjectPath != "" {
			perRoot[t.ProjectPath] += t.CostUSD
		}
	}
	return total, perRoot, nil
}
