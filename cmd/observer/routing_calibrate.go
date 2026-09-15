package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/modelvalue"
	"github.com/marmutapp/superbased-observer/internal/routing"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Per-project calibration job (§R7.2 / §R18.3): a background ticker
// (pure SQL through the store seam — no network) that refreshes
// model_calibration through the EXISTING UpsertModelCalibrations
// one-owner seam, then grades the active policy's downshift rules
// against the evidence. A rule whose (turn-kind, target-tier) shows a
// candidate_worse verdict — which the Model Value Report only assigns
// past the §R7.2 evidence gate (n ≥ min_samples, CI excludes zero) —
// is DEMOTED to advise for that node, loudly. Escalation decision rows
// (§R7.4) feed in as negative evidence: a kind that keeps escalating
// demotes its downshift rules too.
//
// Display stays always-on (the dashboard tier map shows every cell);
// only ACTING is evidence-gated — the §R7.2 honesty split.

const (
	routingCalibrationInterval = time.Hour
	routingCalibrationWindow   = 30 // days
	// escalationDemoteThreshold is the §R7.4 negative-evidence bar: this
	// many escalation rows for a turn-kind in the window demote the
	// kind's downshift rules.
	escalationDemoteThreshold = 5
)

// routingCalibrationLoop drives the job until ctx cancels. lr may be
// nil (calibration still persists cells; demotion needs the live
// router).
func routingCalibrationLoop(ctx context.Context, st *store.Store, cfg config.Config, lr *liveRouter, logger *slog.Logger) {
	run := func() {
		if err := runRoutingCalibration(ctx, st, cfg, lr, logger); err != nil {
			logger.Warn("routing: calibration pass failed", "err", err)
		}
	}
	// First pass shortly after start (let the daemon settle), then the
	// steady cadence.
	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Minute):
		run()
	}
	t := time.NewTicker(routingCalibrationInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

// runRoutingCalibration executes one pass: recompute cells, persist,
// grade, demote.
func runRoutingCalibration(ctx context.Context, st *store.Store, cfg config.Config, lr *liveRouter, logger *slog.Logger) error {
	facts, err := st.LoadModelValueFacts(ctx, modelvalue.LoadOptions{WindowDays: routingCalibrationWindow})
	if err != nil {
		return fmt.Errorf("load facts: %w", err)
	}
	facts.Price = routingPriceFn(acquireProcessCostEngine(ctx, cfg, nil, logger))
	rep := modelvalue.Build(facts, modelvalue.Options{
		MinSample: int64(cfg.Routing.Calibration.MinSamples),
	})
	if err := st.UpsertModelCalibrations(ctx, calibrationRows(rep)); err != nil {
		return fmt.Errorf("persist cells: %w", err)
	}

	if !cfg.Routing.Calibration.AutoDemote || lr == nil {
		return nil
	}
	escalations, err := st.CountEscalationsByKind(ctx, time.Now().AddDate(0, 0, -routingCalibrationWindow))
	if err != nil {
		return fmt.Errorf("escalation counts: %w", err)
	}
	demotions := computeRuleDemotions(*lr.policy.Load(), rep, escalations)
	lr.SetDemotedRules(demotions)
	for rule, why := range demotions {
		// The loud surface (§R18.3): every demotion is a WARN the
		// operator sees, plus calibration_demoted reason codes on the
		// affected decisions in the feed.
		logger.Warn("routing: rule demoted to advise by calibration", "rule", rule, "why", why)
	}
	return nil
}

// computeRuleDemotions grades the policy's downshift rules against the
// report's evidence-gated verdicts plus the §R7.4 escalation counts.
// Pure — one test per behavior row.
func computeRuleDemotions(p routing.Policy, rep modelvalue.Report, escalationsByKind map[string]int) map[string]string {
	// Regressions: GLOBAL deltas only (the per-project groups inform
	// the dashboard; node-level demotion acts on the node-level
	// evidence), already evidence-gated by the report's verdict
	// assignment (§R7.2: n ≥ min_samples AND CI excludes zero).
	regressed := map[routing.EvidenceKey]bool{}
	for _, d := range rep.Deltas {
		if d.ProjectID != 0 {
			continue
		}
		if d.Verdict == modelvalue.VerdictCandidateWorse {
			regressed[routing.EvidenceKey{Kind: d.TurnKind, Tier: d.CandidateTier}] = true
		}
	}

	out := map[string]string{}
	for _, r := range p.Rules {
		if r.Action.RouteToTier == "" {
			continue // only downshift rules demote
		}
		kinds := r.When.TurnKinds
		if len(kinds) == 0 {
			kinds = routing.AllTurnKinds() // an unbounded rule is graded against every kind
		}
		for _, kind := range kinds {
			if regressed[routing.EvidenceKey{Kind: kind, Tier: r.Action.RouteToTier}] {
				out[r.Name] = fmt.Sprintf("calibration regression: %s at %s graded candidate_worse (§R18.3)", kind, r.Action.RouteToTier)
				break
			}
			if escalationsByKind[string(kind)] >= escalationDemoteThreshold {
				out[r.Name] = fmt.Sprintf("escalation pressure: %d §R7.4 escalations on %s in %dd", escalationsByKind[string(kind)], kind, routingCalibrationWindow)
				break
			}
		}
	}
	return out
}
