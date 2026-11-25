package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/intelligence/modelvalue"
	"github.com/marmutapp/superbased-observer/internal/routingcore"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Model-routing P0 advisory tools (model-routing spec §R17.5): the agent
// itself can ask for an evidence-backed model recommendation before
// spawning sub-agents or switching models, and can read the routing
// layer's state. Both are read-only — P0 routes nothing.

// -----------------------------------------------------------------------------
// get_model_recommendation
// -----------------------------------------------------------------------------

// The published bounds of get_model_recommendation's `days` argument.
// ONE owner for both the advertised input schema and the boundary clamp,
// so the documented `maximum` and the enforced maximum cannot drift.
const (
	modelRecommendationDefaultDays = 30
	modelRecommendationMaxDays     = 365
)

type getModelRecommendationTool struct {
	db     *sql.DB
	engine *cost.Engine
}

func newGetModelRecommendationTool(db *sql.DB, engine *cost.Engine) Tool {
	return &getModelRecommendationTool{db: db, engine: engine}
}

func (*getModelRecommendationTool) Name() string { return "get_model_recommendation" }
func (*getModelRecommendationTool) Description() string {
	return "Evidence-backed model recommendation per turn-kind from this node's own Model Value Report: the observed baseline model, any cheaper alternative graded parity on outcomes (with sample sizes and confidence basis), and cost-per-turn comparison. Advisory only - attribution is correlational and the response says so. Use before spawning sub-agents or switching models."
}

func (*getModelRecommendationTool) InputSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"turn_kind": map[string]any{
				"type":        "string",
				"description": "Optional filter: plan, read_only, edit, test_run, housekeeping, subagent, long_context. Omit for every kind with evidence.",
			},
			"project_root": map[string]any{
				"type":        "string",
				"description": "Optional project filter.",
			},
			"days": map[string]any{
				"type":        "integer",
				"description": "Evidence window in days. Default 30.",
				"minimum":     1,
				"maximum":     modelRecommendationMaxDays,
			},
		},
	}
}

// modelRecommendation is one per-turn-kind recommendation row.
type modelRecommendation struct {
	TurnKind       string  `json:"turn_kind"`
	BaselineModel  string  `json:"baseline_model"`
	BaselineTier   string  `json:"baseline_tier"`
	BaselineTurns  int64   `json:"baseline_turns"`
	BaselineCost   float64 `json:"baseline_cost_per_turn_usd"`
	SuggestedModel string  `json:"suggested_model,omitempty"`
	SuggestedTier  string  `json:"suggested_tier,omitempty"`
	SuggestedTurns int64   `json:"suggested_turns,omitempty"`
	SuggestedCost  float64 `json:"suggested_cost_per_turn_usd,omitempty"`
	Verdict        string  `json:"verdict,omitempty"`
	VerdictBasis   string  `json:"verdict_basis,omitempty"`
	Note           string  `json:"note"`
}

func (t *getModelRecommendationTool) Invoke(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		TurnKind    string `json:"turn_kind"`
		ProjectRoot string `json:"project_root"`
		Days        int    `json:"days"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, fmt.Errorf("invalid arguments: %w", err)
		}
	}

	// Silent limit clamping (docs/mcp-contract.md, "Server-level
	// invariants"): an out-of-range `days` is capped at the documented
	// maximum instead of erroring, the same way get_file_history clamps
	// `limit` to 100 and get_failure_context clamps it to 50. Absent /
	// zero / negative means "use the documented default"; anything above
	// the schema's `maximum` is silently pinned to it, so an oversized
	// request succeeds with the documented window rather than sending an
	// absurd cutoff date down to LoadModelValueFacts.
	days := args.Days
	if days <= 0 {
		days = modelRecommendationDefaultDays
	}
	if days > modelRecommendationMaxDays {
		days = modelRecommendationMaxDays
	}

	st := store.New(t.db)
	facts, err := st.LoadModelValueFacts(ctx, modelvalue.LoadOptions{
		WindowDays: days, ProjectRoot: args.ProjectRoot,
	})
	if err != nil {
		return nil, fmt.Errorf("load facts: %w", err)
	}
	facts.Price = t.engine.RoutingPriceFn()
	rep := modelvalue.Build(facts, modelvalue.Options{})

	recs := buildRecommendations(rep, args.TurnKind)
	return map[string]any{
		"caveat":          rep.Caveat,
		"window_days":     rep.WindowDays,
		"recommendations": recs,
		"note":            "Advisory only (routing P0): nothing is enforced; recommendations come from this node's own observed turns.",
	}, nil
}

// buildRecommendations projects the report's global deltas into
// per-turn-kind recommendations: the highest-tier baseline plus the
// cheapest candidate graded parity-or-better. Kinds without such a
// candidate keep the baseline with an honest note.
func buildRecommendations(rep modelvalue.Report, kindFilter string) []modelRecommendation {
	type kindGroup struct {
		baseline *modelvalue.Delta
		best     *modelvalue.Delta
	}
	groups := map[string]*kindGroup{}
	order := []string{}
	for i := range rep.Deltas {
		d := rep.Deltas[i]
		if d.ProjectID != 0 {
			continue // global evidence only
		}
		kind := string(d.TurnKind)
		if kindFilter != "" && kind != kindFilter {
			continue
		}
		g, ok := groups[kind]
		if !ok {
			g = &kindGroup{baseline: &rep.Deltas[i]}
			groups[kind] = g
			order = append(order, kind)
		}
		if d.Verdict != modelvalue.VerdictParity && d.Verdict != modelvalue.VerdictCandidateBetter {
			continue
		}
		if d.CostPerTurnCandidate >= d.CostPerTurnBaseline {
			continue
		}
		if g.best == nil || d.CostPerTurnCandidate < g.best.CostPerTurnCandidate {
			g.best = &rep.Deltas[i]
		}
	}

	// Kinds with only one observed model still deserve a row: surface
	// the global cell as baseline with a no-comparison note.
	seen := map[string]bool{}
	for _, k := range order {
		seen[k] = true
	}
	for _, c := range rep.GlobalCells {
		kind := string(c.TurnKind)
		if seen[kind] || (kindFilter != "" && kind != kindFilter) {
			continue
		}
		seen[kind] = true
		order = append(order, kind)
		groups[kind] = nil // marker: single-model kind, cell-backed
	}

	cellFor := func(kind string) *modelvalue.Cell {
		for i := range rep.GlobalCells {
			if string(rep.GlobalCells[i].TurnKind) == kind {
				return &rep.GlobalCells[i]
			}
		}
		return nil
	}

	out := make([]modelRecommendation, 0, len(order))
	for _, kind := range order {
		g := groups[kind]
		if g == nil {
			c := cellFor(kind)
			if c == nil {
				continue
			}
			out = append(out, modelRecommendation{
				TurnKind:      kind,
				BaselineModel: c.Model, BaselineTier: string(c.Tier),
				BaselineTurns: c.Turns, BaselineCost: c.CostPerTurn,
				Note: "only one model observed for this turn-kind - no comparison evidence yet",
			})
			continue
		}
		rec := modelRecommendation{
			TurnKind:      kind,
			BaselineModel: g.baseline.BaselineModel, BaselineTier: string(g.baseline.BaselineTier),
			BaselineTurns: g.baseline.NBaseline, BaselineCost: g.baseline.CostPerTurnBaseline,
		}
		if g.best != nil {
			rec.SuggestedModel = g.best.CandidateModel
			rec.SuggestedTier = string(g.best.CandidateTier)
			rec.SuggestedTurns = g.best.NCandidate
			rec.SuggestedCost = g.best.CostPerTurnCandidate
			rec.Verdict = g.best.Verdict
			rec.VerdictBasis = g.best.VerdictBasis
			rec.Note = fmt.Sprintf("%s graded %s vs %s on %s (n=%d vs %d) at lower cost/turn",
				g.best.CandidateModel, g.best.Verdict, g.best.BaselineModel,
				g.best.VerdictBasis, g.best.NCandidate, g.best.NBaseline)
		} else {
			rec.Note = "no cheaper alternative graded parity on outcomes - evidence below the sample floor or candidates graded worse; stay on the baseline"
		}
		out = append(out, rec)
	}
	return out
}

// -----------------------------------------------------------------------------
// get_routing_status
// -----------------------------------------------------------------------------

type getRoutingStatusTool struct{ db *sql.DB }

func newGetRoutingStatusTool(db *sql.DB) Tool { return &getRoutingStatusTool{db: db} }

func (*getRoutingStatusTool) Name() string { return "get_routing_status" }
func (*getRoutingStatusTool) Description() string {
	return "Model-routing layer state: phase (P0 advisory - nothing enforced), available policy templates with content hashes, tier-table size, and decision-log / calibration counters. Use to learn whether routing recommendations exist before asking for them."
}

func (*getRoutingStatusTool) InputSchema() map[string]any {
	return map[string]any{
		"type":       "object",
		"properties": map[string]any{},
	}
}

func (t *getRoutingStatusTool) Invoke(ctx context.Context, _ json.RawMessage) (any, error) {
	st := store.New(t.db)
	decisions, err := st.SelectRouterDecisionStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("decision stats: %w", err)
	}
	calibrations, err := st.CountModelCalibrations(ctx)
	if err != nil {
		return nil, fmt.Errorf("calibration count: %w", err)
	}

	// The policy templates come from proxy.routing (tools_routing_templates.go);
	// a build without it reports none.
	templates := routingTemplateInfos()

	out := map[string]any{
		"phase":                  "P0",
		"mode":                   string(routingcore.ModeOff),
		"enforcement_available":  false,
		"templates":              templates,
		"tier_table_entries":     len(routingcore.NewTierResolver().Table().Known()),
		"router_decisions":       decisions.Count,
		"model_calibration_rows": calibrations,
		"note":                   "P0 is advisory intelligence: simulate + reports only; no live request is ever touched.",
	}
	if !decisions.LastTS.IsZero() {
		out["last_decision_at"] = decisions.LastTS
	}
	return out, nil
}
