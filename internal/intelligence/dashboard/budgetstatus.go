package dashboard

import (
	"fmt"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/budgetwarnfile"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
)

// handleBudgetStatus serves GET /api/budget/status - the node's org budget
// warnings (2026-10-02 budget-latency arc): every org-authored window's
// current reading and the active warn notices, read from the daemon-owned
// budget-status.json beside the DB (budgetwarnfile). The dashboard's global
// banner and toast (every page, Terminals included) poll it.
//
// It is a cross-cutting View route (secNone): a warning about the
// developer's own spend must never be hidden by a governance section
// directive. It carries no content - windows, percentages and amounts only.
// Each active notice names the budget it measures (budget_id, T-522) when
// the node's budget rail names one, so the banner can open a request for
// exactly that budget.
func (s *Server) handleBudgetStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, fmt.Errorf("load config: %w", err))
		return
	}
	writeJSON(w, budgetStatusPayload(budgetwarnfile.StatusPath(cfg.Observer.DBPath), s.requestableBudgets()))
}

// requestableBudgets lists the budgets the node's verified budget rail names
// (nil on a solo node).
func (s *Server) requestableBudgets() []orgclient.RequestableBudget {
	if s.opts.Requests == nil {
		return nil
	}
	return s.opts.Requests.RequestableBudgets()
}

// budgetStatusFile reads the node's budget-status.json, nil when it cannot.
func (s *Server) budgetStatusFile() *budgetwarnfile.File {
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		return nil
	}
	file, err := budgetwarnfile.Read(budgetwarnfile.StatusPath(cfg.Observer.DBPath))
	if err != nil {
		return nil
	}
	return file
}

// budgetStatusPayload renders the status file for the API. available=false
// means no org budget warning service has written here (an unenrolled node,
// or a node whose org authored no budget) - never "under budget". budgets
// name each active notice's budget (nil names none).
func budgetStatusPayload(path string, budgets []orgclient.RequestableBudget) map[string]any {
	file, err := budgetwarnfile.Read(path)
	if err != nil || file == nil {
		return map[string]any{"available": false, "windows": []any{}, "active": []any{}}
	}
	windows := any(file.Windows)
	if file.Windows == nil {
		windows = []any{}
	}
	out := map[string]any{
		"available":  true,
		"written_at": file.WrittenAt,
		"windows":    windows,
		"active":     budgetNoticeViews(file.Active, budgets),
	}
	// The last organization budget pull, so the banner can say when this
	// machine cannot get its budgets (budget enforce consistency, 2026-11-19).
	if file.Fetch != nil {
		out["fetch"] = file.Fetch
	}
	return out
}

// budgetNoticeView is one active warning notice with the budget it measures,
// so the banner can open a request for exactly that budget (T-522).
type budgetNoticeView struct {
	budgetwarnfile.Notice
	BudgetID string `json:"budget_id,omitempty"`
}

// budgetNoticeViews names each active notice's budget.
func budgetNoticeViews(notices []budgetwarnfile.Notice, budgets []orgclient.RequestableBudget) []budgetNoticeView {
	out := make([]budgetNoticeView, 0, len(notices))
	for _, n := range notices {
		out = append(out, budgetNoticeView{Notice: n, BudgetID: budgetIDForWindow(budgets, n.Scope, n.Window, n.Unit, n.Subject)})
	}
	return out
}
