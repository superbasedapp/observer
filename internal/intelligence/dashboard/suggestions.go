package dashboard

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/advisor"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// handleDiscover serves /api/discover. Paginates the stale_reads and
// repeated_commands panels independently — stale_page/stale_limit and
// repeated_page/repeated_limit query params, defaulting to 20 rows per
// page. Backend caps total results at 500 per panel (discover SQL runs
// once per request and the dashboard surfaces top-N anyway); both
// panels expose stale_total / repeated_total for the pager UI.
// handleSuggestions — GET /api/suggestions?days=N&project=R
// [&category=cost|latency|quality|hygiene][&severity=…][&detector=…]
// [&page=P&limit=L]. Computed on read by the advisor engine (spec §15.7;
// thresholds per docs/plans/advisor-calibration-2026-06-10.md). Filters
// and pagination are presentation concerns and live here, not in the
// engine; totals and the per-category rollup reflect the FILTERED set
// (pre-pagination) so the header reconciles with what the list shows.
func (s *Server) handleSuggestions(w http.ResponseWriter, r *http.Request) {
	// Max 36500 (~100y) so the global "all" window (36500 days) isn't
	// clamped to a year — matches the other dashboard endpoints' all-time.
	days := intArg(r, "days", 14, 1, 36500)
	// The evidence window follows the global window (since / hours / days,
	// and a closed range's until): REVIEW-3 P3-19.
	since, until := windowRange(r, 14, 1, 36500)
	days = windowSpanDays(since, until, days)
	page := intArg(r, "page", 1, 1, 1_000_000)
	limit := intArg(r, "limit", 20, 1, 200)
	proj := r.URL.Query().Get("project")
	tool := r.URL.Query().Get("tool")
	category := r.URL.Query().Get("category")
	severity := r.URL.Query().Get("severity")
	detector := r.URL.Query().Get("detector")

	// X3.1 posture inputs: effective modes from the on-disk config plus
	// the §R22 shadow signal through the one gate owner. Best-effort —
	// neither a config-load nor a shadow-read failure may take down the
	// suggestions report.
	guardMode, routingMode := "off", "off"
	var shadow *advisor.ShadowSignal
	if cfg, cerr := loadConfigForDashboard(s.opts.ConfigPath); cerr == nil {
		if cfg.Guard.Enabled {
			guardMode = cfg.Guard.Mode
		}
		if cfg.Routing.Enabled {
			routingMode = cfg.Routing.Mode
		}
		st := store.New(s.opts.DB)
		if sh, serr := st.AdviseShadowSignal(r.Context(), days, s.opts.CostEngine.RoutingPriceFn()); serr == nil {
			shadow = &advisor.ShadowSignal{
				AdviseDecisions: sh.AdviseDecisions,
				WouldReroute:    sh.WouldReroute,
				WouldSaveUSD:    sh.WouldSaveUSD,
				QualityFlags:    sh.QualityFlags,
				MinDecisions:    sh.MinDecisions,
				Ready:           sh.ReadyToPromote,
			}
		}
	}
	rep, err := advisor.Run(r.Context(), s.db(), advisor.Options{
		WindowDays:    days,
		Since:         since,
		Until:         until,
		ProjectRoot:   proj,
		Tool:          tool,
		Model:         modelParam(r),
		CostEngine:    s.opts.CostEngine,
		GuardMode:     guardMode,
		RoutingMode:   routingMode,
		RoutingShadow: shadow,
		ContextWindow: s.modelWindows(r.Context()).Resolve,
	})
	if err != nil {
		writeErr(w, err)
		return
	}

	filtered := rep.Suggestions[:0:0]
	byCategory := map[string]float64{}
	byDetector := map[string]int{}
	var totUSD, totMin float64
	for _, sg := range rep.Suggestions {
		if (category != "" && sg.Category != category) ||
			(severity != "" && sg.Severity != severity) ||
			(detector != "" && sg.Detector != detector) {
			continue
		}
		filtered = append(filtered, sg)
		byCategory[sg.Category] += sg.SavingsUSD
		byDetector[sg.Detector]++
		totUSD += sg.SavingsUSD
		totMin += sg.SavingsMin
	}
	total := len(filtered)
	start := (page - 1) * limit
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}

	writeJSON(w, map[string]any{
		"suggestions":       filtered[start:end],
		"total_count":       total,
		"page":              page,
		"limit":             limit,
		"total_savings_usd": round2f(totUSD),
		"total_savings_min": round2f(totMin),
		"by_category":       byCategory,
		"by_detector":       byDetector,
		"window_days":       rep.WindowDays,
		"generated_at":      rep.GeneratedAt,
		"sessions_scanned":  rep.SessionsScanned,
	})
}

func round2f(v float64) float64 { return float64(int64(v*100+0.5)) / 100 }

// handleSuggestionState — POST /api/suggestions/state with JSON
// {dedup_key, status: dismissed|snoozed|acted, snooze_days?}. State is
// node-local (advisor_state, migration 039; never org-pushed).
func (s *Server) handleSuggestionState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		DedupKey   string `json:"dedup_key"`
		Status     string `json:"status"`
		SnoozeDays int    `json:"snooze_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DedupKey == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	var until time.Time
	if req.Status == advisor.StatusSnoozed {
		d := req.SnoozeDays
		if d <= 0 {
			d = 7
		}
		until = now.AddDate(0, 0, d)
	}
	if err := advisor.SetState(r.Context(), s.db(), req.DedupKey, req.Status, until, now); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}
