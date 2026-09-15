package guard

import (
	"context"
	"errors"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// InterventionBudgetInput supplies native accounting coverage separately from
// stored totals. A successful empty SQL result cannot establish source health.
// The daemon must set SourceReady only after verifying the governed source;
// this method does not discover processes or establish capture completeness.
type InterventionBudgetInput struct {
	SessionID string
	// Tool is the adapter whose process is being decided. It scopes the SOURCE
	// readiness input below and names the tool in an operator-facing denial.
	//
	// It no longer composes any per-tool PRICING unavailability onto the
	// decision (ruling A2, 2026-09-15): an unpriced model is a reporting fact,
	// never a denial. Only a broken capture SOURCE - which really does mean
	// this tool's spend is unknown rather than merely estimated - is scoped
	// here.
	Tool string
	// SourceReason is the machine-readable reason behind SourceReady. It is
	// operator-facing denial context only; the decision uses SourceReady.
	//
	// The daemon sets SourceReady=true for both a KNOWN and a DELAYED source
	// (ruling 2026-09-15). Delayed means the strict tail catch-up did not
	// finish this pass while the source stayed intact - the measured total in
	// the store stands, and reading the newest bytes late can only delay a
	// stop, never manufacture one. SourceReady is false only for a
	// STRUCTURALLY unavailable source: one nothing on this node can read.
	SourceReason  string
	SourceReady   bool
	Now           time.Time
	BudgetBinding string
}

// InterventionBudgetDecision is a managed budget decision for future billable
// work. It does not perform or attest process control. Available=true with
// Required=false means no applicable managed hard budget is composed in this
// guard; the caller must
// independently verify the enrollment authority and supervisor readiness.
type InterventionBudgetDecision struct {
	// AccountingEvidence carries the immutable pricing inputs of this check.
	AccountingEvidence *BudgetAccountingEvidence
	// DocumentWitness binds this decision to the exact durable signed-document
	// or known-absence state which produced the immutable numeric engine.
	DocumentWitness BudgetDocumentWitness
	// PricingDocumentWitness is required only when a USD decision consumed a
	// successfully loaded price-table snapshot. Source/read-unavailable denials
	// have no price input and remain independently fail closed.
	PricingDocumentWitness  BudgetDocumentWitness
	PricingDocumentRequired bool
	// ValidUntil is the exclusive time horizon of the accounting decision.
	// Calendar totals can reset without a policy or database write, so a signal
	// must begin before this boundary. A measured rolling-window denial uses the
	// exact snapshot's next row-expiry timestamp; without one it returns the
	// decision time itself and refuses process control on stale aggregate
	// evidence. Unavailable-accounting denials do not clear at a time boundary.
	ValidUntil time.Time
	// Revision binds the result to the exact installed policy snapshot.
	Revision  uint64
	Available bool
	Required  bool
	Deny      bool
	RuleID    string
	Reason    string
}

// CheckInterventionBudget checks the existing shared budget rules against a
// fresh accounting snapshot without inventing an API request or audit record.
// The policy event uses the prospective-request applicability set so B-625
// and the same protected USD/token rules govern both transport and process
// admission. No per-adapter thresholds, price tables or comparison rules live
// here. Local/individual and soft-only budgets never authorize intervention.
func (g *Guard) CheckInterventionBudget(in InterventionBudgetInput) InterventionBudgetDecision {
	if g == nil {
		return InterventionBudgetDecision{Deny: true, Reason: "budget guard is unavailable"}
	}
	return g.checkInterventionBudgetWith(g.set.Load(), in)
}

// checkInterventionBudgetWith evaluates against one already-loaded immutable
// engine snapshot. Keeping the enrollment binding beside that engine prevents
// a concurrent budget publication from tearing identity and numeric policy.
func (g *Guard) checkInterventionBudgetWith(es *engineSet, in InterventionBudgetInput) InterventionBudgetDecision {
	if es == nil || es.base == nil {
		return InterventionBudgetDecision{Deny: true, Reason: "budget policy engine is unavailable"}
	}
	document := es.budgetWitness
	if in.BudgetBinding != "" && in.BudgetBinding != es.budgetBinding {
		return InterventionBudgetDecision{
			Revision:        es.revision,
			DocumentWitness: document,
			Available:       true,
			Required:        true,
			Deny:            true,
			RuleID:          "B-625",
			Reason:          "organization budget is unavailable for the current enrollment",
		}
	}
	if !es.base.ManagedBudgetRequired() {
		return InterventionBudgetDecision{Available: true, Revision: es.revision, DocumentWitness: document}
	}
	out := InterventionBudgetDecision{Available: true, Required: true, Revision: es.revision, DocumentWitness: document}
	if es.base.Mode() != policy.ModeEnforce {
		out.Deny, out.Reason = true, "managed budget guard is not enforcing"
		return out
	}
	if in.Now.IsZero() {
		out.Deny, out.Reason = true, "budget decision time is unavailable"
		return out
	}
	ev := policy.Event{Kind: policy.KindAPIRequest, SessionID: in.SessionID, Now: in.Now}
	if !in.SourceReady {
		ev.USDUnavailable = policy.BudgetUnavailableWindows{Session: true, Daily: true, Weekly: true, Monthly: true}
		ev.TokensUnavailable = ev.USDUnavailable
	} else {
		// The snapshot's own unavailable windows are whatever the accounting
		// owner could not establish AT ALL (no verified price table, a read
		// error). Unpriced ROWS are deliberately not among them any more: a
		// model with no org or exact rate is priced by the same fallback ladder
		// the node's dashboard uses, counted against the cap, and reported -
		// never turned into a stopped process (ruling A2, 2026-09-15).
		out.AccountingEvidence = g.stampBudgetSnapshot(&ev, true, es.accountingContext(true))
	}
	if in.SessionID == "" {
		// Node-wide budgets do not need a guessed session join. A session cap
		// does, and must not see a fabricated empty-session total of zero.
		ev.USDUnavailable.Session = true
		ev.TokensUnavailable.Session = true
	}
	verdict, err := g.evaluateManagedBudgetWith(es, ev)
	if err != nil {
		out.Deny, out.Reason = true, "managed budget evaluation failed"
		return out
	}
	if verdict.Decision >= policy.DecisionDeny && es.base.BudgetRuleProtected(verdict.RuleID) {
		out.Deny, out.RuleID, out.Reason = true, verdict.RuleID, verdict.Reason
		if interventionBudgetEvidenceUnavailable(verdict.RuleID, ev) {
			// The rule's own reason states only that accounting is unavailable.
			// Name WHICH input is missing so an operator can act on it.
			if detail := interventionUnavailableDetail(in); detail != "" {
				out.Reason += "; " + detail
			}
		}
		if interventionUSDBudgetRule(verdict.RuleID) && out.AccountingEvidence != nil {
			out.PricingDocumentWitness = out.AccountingEvidence.PricingDocumentWitness
			// An unavailable-rate verdict consumes no numeric price authority.
			// Preserve its observed witness as evidence when one exists, but do
			// not let a missing witness disable the required physical cutoff.
			out.PricingDocumentRequired = !interventionBudgetEvidenceUnavailable(verdict.RuleID, ev)
		}
		if !interventionBudgetEvidenceUnavailable(verdict.RuleID, ev) {
			out.ValidUntil = interventionBudgetHorizon(verdict.RuleID, in.Now, es.budgetCalendars, out.AccountingEvidence)
		}
	}
	return out
}

func interventionUSDBudgetRule(ruleID string) bool {
	switch ruleID {
	case "B-601", "B-602", "B-603", "B-604":
		return true
	default:
		return false
	}
}

func interventionBudgetEvidenceUnavailable(ruleID string, ev policy.Event) bool {
	if interventionUSDBudgetRule(ruleID) {
		return interventionBudgetWindowUnavailable(ruleID, ev.USDUnavailable)
	}
	return interventionBudgetWindowUnavailable(ruleID, ev.TokensUnavailable)
}

// interventionBudgetWindowUnavailable maps a budget rule onto the window it
// compares. The $ rows and their token siblings share one mapping; only the
// windows they read differ.
func interventionBudgetWindowUnavailable(ruleID string, windows policy.BudgetUnavailableWindows) bool {
	switch ruleID {
	case "B-601", "B-621":
		return windows.Session
	case "B-602", "B-622":
		return windows.Daily
	case "B-603", "B-623":
		return windows.Monthly
	case "B-604", "B-624":
		return windows.Weekly
	default:
		return false
	}
}

// interventionUnavailableDetail names the missing accounting input behind an
// unavailable-window denial.
//
// There is exactly ONE such input left: a broken capture source for this tool,
// which means this tool's spend is genuinely unknown. The second detail this
// function used to render - "unpriced usage for <tool> (a model it used has no
// exact or org rate); add an org price for that model" - is GONE with the
// denial that produced it (ruling A2, 2026-09-15). Unpriced usage is now priced
// by the fallback ladder and reported through the budget posture, so there is
// no denial for it to explain.
func interventionUnavailableDetail(in InterventionBudgetInput) string {
	if in.SourceReady {
		return ""
	}
	tool := in.Tool
	if tool == "" {
		tool = "unknown tool"
	}
	reason := in.SourceReason
	if reason == "" {
		reason = "unknown"
	}
	return "accounting source unavailable for " + tool + ": " + reason
}

func interventionBudgetHorizon(ruleID string, now time.Time, calendars BudgetCalendars, evidence *BudgetAccountingEvidence) time.Time {
	if now.IsZero() {
		return now
	}
	switch ruleID {
	case "B-602", "B-622":
		return nextBudgetCalendarBoundary(now, calendars.DailyTimezone, false)
	case "B-603", "B-623":
		return nextBudgetCalendarBoundary(now, calendars.MonthlyTimezone, true)
	case "B-604":
		if evidence != nil && evidence.WeeklyUSDExpiresAt.After(now) {
			return evidence.WeeklyUSDExpiresAt
		}
		return now
	case "B-624":
		if evidence != nil && evidence.WeeklyTokensExpiresAt.After(now) {
			return evidence.WeeklyTokensExpiresAt
		}
		return now
	default:
		// Session totals do not reset with wall time, and B-625 is independent
		// of accounting windows. The authority's short validity remains the
		// bound for those decisions.
		return time.Time{}
	}
}

func nextBudgetCalendarBoundary(now time.Time, zone string, monthly bool) time.Time {
	if zone == "" {
		zone = "UTC"
	}
	loc, err := time.LoadLocation(zone)
	if err != nil {
		return now
	}
	local := now.In(loc)
	year, month, day := local.Date()
	if monthly {
		day = 1
		month++
	} else {
		day++
	}
	return time.Date(year, month, day, 0, 0, 0, 0, loc).UTC()
}

// WithInterventionRevision runs a bounded OS operation only while the policy
// snapshot which authorized it remains installed. It never waits for a reload
// lock: callers may already hold the durable authority fence, and a contended
// publication must abort this action instead of creating a lock-order cycle.
// The callback must not query the store, price usage or re-enter the guard.
func (g *Guard) WithInterventionRevision(ctx context.Context, revision uint64, action func() error) error {
	if g == nil || ctx == nil || revision == 0 || action == nil {
		return errors.New("guard.WithInterventionRevision: missing inputs")
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return errors.New("guard.WithInterventionRevision: deadline required")
	}
	if !g.reloadMu.TryLock() {
		return errors.New("guard.WithInterventionRevision: policy publication in progress")
	}
	defer g.reloadMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	current := g.set.Load()
	if current == nil || current.revision != revision {
		return errors.New("guard.WithInterventionRevision: policy changed")
	}
	return action()
}
