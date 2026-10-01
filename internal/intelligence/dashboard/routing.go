package dashboard

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/intelligence/modelvalue"
	"github.com/marmutapp/superbased-observer/internal/routing"
	"github.com/marmutapp/superbased-observer/internal/routingconfig"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Routing page backend (model-routing spec §R17.1–17.2): live policy,
// decisions feed with reason filters, savings-to-date, tier map with
// calibration overlays, health board. Read-layer only — every endpoint
// is a point-in-time view over the decision log / calibration tables /
// api_turns; nothing here mutates routing state.

// routingRuleView is one expanded rule-table row (the §R17.1 "never a
// black box" surface).
type routingRuleView struct {
	Name   string `json:"name"`
	When   string `json:"when"`
	Action string `json:"action"`
	Reason string `json:"reason"`
}

// handleRoutingStatus — GET /api/routing/status.
func (s *Server) handleRoutingStatus(w http.ResponseWriter, r *http.Request) {
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, err)
		return
	}
	policy, issues := routing.Compile(routingconfig.Spec(cfg.Routing))
	st := store.New(s.opts.DB)
	stats, err := st.SelectRouterDecisionStats(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	calibRows, err := st.CountModelCalibrations(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}

	rules := make([]routingRuleView, 0, len(policy.Rules))
	for _, rule := range policy.Rules {
		rules = append(rules, routingRuleView{
			Name:   rule.Name,
			When:   describeWhen(rule.When),
			Action: describeAction(rule.Action),
			Reason: string(rule.Reason),
		})
	}
	type lintView struct {
		Check    string `json:"check"`
		Rule     string `json:"rule,omitempty"`
		Severity string `json:"severity"`
		Message  string `json:"message"`
	}
	lint := make([]lintView, 0, len(issues))
	for _, i := range issues {
		lint = append(lint, lintView{Check: i.Check, Rule: i.RuleName, Severity: string(i.Severity), Message: i.Message})
	}
	// §R18.3 demotion visibility (R2.4): demotions are in-memory state
	// of the live router — only the daemon process hosting it can
	// answer. demotions_live=false (standalone dashboard process,
	// routing disabled) means "can't see from here", which the UI must
	// never render as "none demoted". The CLI has the same structural
	// limit: `observer routing status` runs in its own process and
	// cannot see the daemon's demotion set.
	demoted := map[string]string{}
	demotionsLive := s.opts.RoutingDemotions != nil
	if demotionsLive {
		demoted = s.opts.RoutingDemotions()
	}

	out := map[string]any{
		"enabled":          cfg.Routing.Enabled,
		"mode":             cfg.Routing.Mode,
		"policy":           policy.Name,
		"policy_hash":      policy.Hash(),
		"min_turns":        policy.MinTurnsBetweenSwitches,
		"respect_cache":    policy.RespectCache,
		"bases":            policy.Bases,
		"rules":            rules,
		"lint":             lint,
		"decisions":        stats.Count,
		"calibration_rows": calibRows,
		"demoted_rules":    demoted,
		"demotions_live":   demotionsLive,
	}
	if !stats.LastTS.IsZero() {
		out["last_decision_at"] = stats.LastTS.Format(time.RFC3339)
	}
	writeJSON(w, out)
}

// handleRoutingDecisions — GET /api/routing/decisions?days&reason&session&applied&limit.
func (s *Server) handleRoutingDecisions(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	limit := intArg(r, "limit", 100, 1, 1000)
	reason := r.URL.Query().Get("reason")
	session := r.URL.Query().Get("session")
	applied := r.URL.Query().Get("applied") // "", "true", "false"

	st := store.New(s.opts.DB)
	rows, err := st.SelectRouterDecisions(r.Context(), time.Now().AddDate(0, 0, -days), 0)
	if err != nil {
		writeErr(w, err)
		return
	}
	filtered := rows[:0:0]
	for _, d := range rows {
		if session != "" && d.SessionID != session {
			continue
		}
		if applied == "true" && !d.Applied {
			continue
		}
		if applied == "false" && d.Applied {
			continue
		}
		if reason != "" && !slices.Contains(d.ReasonCodes, reason) {
			continue
		}
		filtered = append(filtered, d)
		if len(filtered) >= limit {
			break
		}
	}
	// Reason vocabulary for the filter dropdown — the closed enum, so
	// the UI never invents codes.
	reasons := make([]string, 0)
	for _, rc := range routing.KnownReasonCodes() {
		reasons = append(reasons, string(rc))
	}
	writeJSON(w, map[string]any{
		"decisions": filtered,
		"total":     len(rows),
		"reasons":   reasons,
	})
}

// handleRoutingSavings — GET /api/routing/savings?days.
func (s *Server) handleRoutingSavings(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, err)
		return
	}
	st := store.New(s.opts.DB)
	rows, err := st.SelectRouterDecisions(r.Context(), time.Now().AddDate(0, 0, -days), 0)
	if err != nil {
		writeErr(w, err)
		return
	}
	resolver := routing.NewTierResolver()
	if overrides := routingconfig.TierOverrides(cfg.Routing); overrides != nil {
		resolver.Reload(overrides)
	}
	writeJSON(w, store.BuildRouterSavingsReport(rows, days, resolver.Table()))
}

// handleRoutingTiers — GET /api/routing/tiers: the tier map with
// per-(model, turn-kind) calibration overlays (§R17.1). Calibration
// cells display always-on; whether they ACT is the §R7.2 evidence
// gate's business, not this view's.
func (s *Server) handleRoutingTiers(w http.ResponseWriter, r *http.Request) {
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, err)
		return
	}
	resolver := routing.NewTierResolver()
	if overrides := routingconfig.TierOverrides(cfg.Routing); overrides != nil {
		resolver.Reload(overrides)
	}
	table := resolver.Table()

	byTier := map[string][]string{}
	for _, model := range table.Known() {
		tier, _ := table.Lookup(model)
		byTier[string(tier)] = append(byTier[string(tier)], model)
	}
	for _, models := range byTier {
		sort.Strings(models)
	}

	st := store.New(s.opts.DB)
	calib, err := st.SelectModelCalibrations(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	type calibView struct {
		Model       string  `json:"model"`
		TurnKind    string  `json:"turn_kind"`
		ProjectID   int64   `json:"project_id"`
		N           int64   `json:"n"`
		ErrorRate   float64 `json:"error_rate"`
		ErrorGraded int64   `json:"error_graded"`
		ToolFailPct float64 `json:"tool_failure_rate"`
		LatencyP50  int64   `json:"latency_p50_ms"`
	}
	overlays := make([]calibView, 0, len(calib))
	for _, c := range calib {
		v := calibView{
			Model: c.Model, TurnKind: c.TurnKind, ProjectID: c.ProjectID,
			N: c.N, ErrorGraded: c.ErrorGraded, LatencyP50: c.LatencyP50Ms,
		}
		if c.ErrorGraded > 0 {
			v.ErrorRate = float64(c.ErrorCount) / float64(c.ErrorGraded)
		}
		if c.ToolActionCount > 0 {
			v.ToolFailPct = float64(c.ToolFailureCount) / float64(c.ToolActionCount)
		}
		overlays = append(overlays, v)
	}
	writeJSON(w, map[string]any{
		"tiers":       byTier,
		"calibration": overlays,
	})
}

// handleRoutingHealth — GET /api/routing/health: observed per-model
// error rates over the last hour and day, straight from api_turns.
// Display-only — live circuit-breaker STATE belongs to the proxy-side
// snapshot refresher (one owner); this board shows the observations
// the breakers act on.
func (s *Server) handleRoutingHealth(w http.ResponseWriter, r *http.Request) {
	type healthRow struct {
		Model     string  `json:"model"`
		Turns1h   int64   `json:"turns_1h"`
		Errors1h  int64   `json:"errors_1h"`
		Turns24h  int64   `json:"turns_24h"`
		Errors24h int64   `json:"errors_24h"`
		Rate24h   float64 `json:"error_rate_24h"`
	}
	rows, err := s.opts.DB.QueryContext(r.Context(), `
		SELECT COALESCE(model, ''),
		       SUM(CASE WHEN timestamp >= ? THEN 1 ELSE 0 END),
		       SUM(CASE WHEN timestamp >= ? AND (http_status >= 500 OR http_status = 429) THEN 1 ELSE 0 END),
		       COUNT(*),
		       SUM(CASE WHEN http_status >= 500 OR http_status = 429 THEN 1 ELSE 0 END)
		FROM api_turns
		WHERE timestamp >= ?
		GROUP BY 1
		ORDER BY 4 DESC`,
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano),
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano),
		time.Now().Add(-24*time.Hour).UTC().Format(time.RFC3339Nano))
	if err != nil {
		writeErr(w, err)
		return
	}
	defer func() { _ = rows.Close() }()
	out := []healthRow{}
	for rows.Next() {
		var h healthRow
		if err := rows.Scan(&h.Model, &h.Turns1h, &h.Errors1h, &h.Turns24h, &h.Errors24h); err != nil {
			writeErr(w, err)
			return
		}
		if h.Turns24h > 0 {
			h.Rate24h = float64(h.Errors24h) / float64(h.Turns24h)
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"models": out})
}

// describeWhen renders a when clause for the rule table.
func describeWhen(wh routing.RuleWhen) string {
	parts := []string{}
	if len(wh.TurnKinds) > 0 {
		kinds := make([]string, len(wh.TurnKinds))
		for i, k := range wh.TurnKinds {
			kinds[i] = string(k)
		}
		parts = append(parts, "kind∈{"+joinStr(kinds, ",")+"}")
	}
	if wh.Phase != "" {
		parts = append(parts, "phase="+wh.Phase)
	}
	if wh.TierAtLeast != "" {
		parts = append(parts, "tier≥"+string(wh.TierAtLeast))
	}
	if wh.ModelGlob != "" {
		parts = append(parts, "model~"+wh.ModelGlob)
	}
	if wh.Project != "" {
		parts = append(parts, "project="+wh.Project)
	}
	if wh.PathClass != "" {
		parts = append(parts, "path_class="+wh.PathClass)
	}
	if wh.MaxToolUses > 0 {
		parts = append(parts, "tools≤"+strconv.Itoa(wh.MaxToolUses))
	}
	if wh.Entitlement != "" {
		parts = append(parts, "entitlement="+wh.Entitlement)
	}
	if wh.Sidechain != nil {
		if *wh.Sidechain {
			parts = append(parts, "sidechain")
		} else {
			parts = append(parts, "!sidechain")
		}
	}
	if len(parts) == 0 {
		return "(always)"
	}
	return joinStr(parts, " ∧ ")
}

// describeAction renders a rule action for the rule table.
func describeAction(a routing.RuleAction) string {
	switch {
	case a.NoRoute:
		return "no_route (pin to original)"
	case a.RouteToTier != "":
		return "route → " + string(a.RouteToTier)
	case a.RouteToModel != "":
		return "route → " + a.RouteToModel
	case a.PinTier != "":
		return "pin → " + string(a.PinTier)
	case a.SetEffort != "":
		return "effort → " + a.SetEffort
	case len(a.SetFallbackChain) > 0:
		return "fallback chain → " + joinStr(a.SetFallbackChain, " → ")
	case len(a.DenyProviders) > 0 || len(a.AllowProviders) > 0:
		return "provider filter (deny " + joinStr(a.DenyProviders, ",") + "; allow " + joinStr(a.AllowProviders, ",") + ")"
	default:
		return "(none)"
	}
}

func joinStr(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}

// handleRoutingShadow — GET /api/routing/shadow?days: the §R18.2
// advise-shadow promotion surface (would-have savings vs quality
// flags). Parity evidence comes from the Model Value Report over the
// same window.
func (s *Server) handleRoutingShadow(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	st := store.New(s.opts.DB)
	rows, err := st.SelectRouterDecisions(r.Context(), time.Now().AddDate(0, 0, -days), 0)
	if err != nil {
		writeErr(w, err)
		return
	}
	facts, err := st.LoadModelValueFacts(r.Context(), modelvalue.LoadOptions{WindowDays: days})
	if err != nil {
		writeErr(w, err)
		return
	}
	if fn := enginePriceFn(s.opts.CostEngine); fn != nil {
		facts.Price = fn
	}
	evidence := modelvalue.Build(facts, modelvalue.Options{}).EvidenceByKindTier()
	writeJSON(w, store.BuildAdviseShadowReport(rows, evidence, routing.NewTierResolver().Table(), days))
}

// enginePriceFn adapts the dashboard's cost engine to the routing
// package's injected pricing seam (the same adaptation the CLI's
// routingPriceFn makes). Nil engine → nil, so callers keep the facts'
// default pricing.
func enginePriceFn(engine *cost.Engine) routing.PriceFn {
	if engine == nil {
		return nil
	}
	return func(model string, u routing.PromptUsage) (float64, bool) {
		return engine.Compute(model, cost.TokenBundle{
			Input: u.Input, Output: u.Output, CacheRead: u.CacheRead,
			CacheCreation: u.CacheCreation, CacheCreation1h: u.CacheCreation1h,
			Reasoning: u.Reasoning, WebSearchRequests: u.WebSearchRequests, Fast: u.Fast,
		})
	}
}

// handleRoutingSimulate — POST /api/routing/simulate (R1.2): the
// §R18.1 counterfactual replay as a dashboard surface — the backend
// of the Routing page's "preview what routing would have saved"
// CTA. Wraps the exact seam `observer routing simulate` uses
// (LoadModelValueFacts → modelvalue.Build / AssembleSimTurns →
// routing.Simulate) so the two surfaces can never drift; like the
// CLI, the tier table is the seed resolver (no config overlays).
// Read-only and deterministic given (data, policy): the engine is
// pure, nothing persists, no live request is touched. POST rather
// than GET because this is a compute request over the window's full
// turn substrate, not a cacheable view.
func (s *Server) handleRoutingSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	req := struct {
		Policy   string `json:"policy"`
		Days     int    `json:"days"`
		Project  string `json:"project"`
		TurnKind string `json:"turn_kind"`
	}{Policy: "value", Days: 30}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if req.Days <= 0 {
		req.Days = 30
	}
	if req.Days > 36500 {
		req.Days = 36500
	}
	policy, ok := routing.TemplateByName(req.Policy)
	if !ok {
		http.Error(w, fmt.Sprintf("unknown policy template %q (have: %v)", req.Policy, routing.TemplateNames()),
			http.StatusBadRequest)
		return
	}
	if req.TurnKind != "" && !slices.Contains(routing.AllTurnKinds(), routing.TurnKind(req.TurnKind)) {
		http.Error(w, fmt.Sprintf("unknown turn kind %q (have: %v)", req.TurnKind, routing.AllTurnKinds()),
			http.StatusBadRequest)
		return
	}

	st := store.New(s.opts.DB)
	facts, err := st.LoadModelValueFacts(r.Context(), modelvalue.LoadOptions{
		WindowDays: req.Days, ProjectRoot: req.Project,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	if fn := enginePriceFn(s.opts.CostEngine); fn != nil {
		facts.Price = fn
	}
	mvReport := modelvalue.Build(facts, modelvalue.Options{})
	turns := modelvalue.AssembleSimTurns(facts, modelvalue.Options{})
	turns = modelvalue.FilterSimTurnsByKind(turns, routing.TurnKind(req.TurnKind))
	// Context windows: the same Tokenomics window table the live
	// router reads (store.LoadModelContextWindows); a load error leaves
	// the seed rung, and an unknown window never excludes a candidate.
	windows, _ := st.LoadModelContextWindows(r.Context())
	snap := &routing.Snapshot{
		GeneratedAt:   facts.GeneratedAt,
		Price:         facts.Price,
		Tiers:         routing.NewTierResolver().Table(),
		ContextWindow: windows.Resolve,
	}
	rep := routing.Simulate(policy, snap, turns, mvReport.EvidenceByKindTier())

	writeJSON(w, map[string]any{
		"window_days": req.Days,
		"report":      rep,
		"note": "Advisory replay over recorded turns — deterministic and read-only; " +
			"no live traffic was touched and nothing was persisted.",
	})
}
