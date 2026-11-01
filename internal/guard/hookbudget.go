package guard

import (
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// THE HOOK PATH STOPS AT AN EXHAUSTED MANAGED BUDGET (T-519, D-332).
//
// Before this file a hook process never consulted a budget: the spend lookup
// lives in the daemon (budget.go's header), so every B-6xx row saw an unstamped
// event and matched nothing. That was fine while the proxy was the only budget
// chokepoint anyone expected, and wrong for every tool whose model calls go to
// its vendor directly: on the demo estate a Cursor session kept answering
// prompts at 133% of a blocking $0.30/day cap while its beforeSubmitPrompt and
// preToolUse hooks fired on every turn and answered allow.
//
// The hook path still measures nothing. The daemon publishes the managed
// decision its process controller and launch gate already take
// (CheckInterventionBudget - one owner for the number, the managed accounting
// over every captured row, proxied or not), and the hook boundary hands it in
// through HookBudgetLookup. This file only turns a published stop into a
// verdict on the event the hook is judging, so every pre-send seam that already
// calls EvaluateHook or EvaluatePrompt - every adapter's prompt gate and tool
// gate - stops the same way, with no per-tool code (CLAUDE.md #3). What the
// developer sees is the seam's own deny shape, resolved by the existing tables
// (ResolveEmission for tool calls, promptaction.go for prompts; D-030).

// HookBudgetStop is one managed budget denial as the hook path consumes it.
type HookBudgetStop struct {
	// RuleID is the budget rule that denied (B-602, B-622, B-626, B-625, ...).
	RuleID string
	// Reason is the daemon-rendered, developer-facing reason (organization
	// terms, developer cost display).
	Reason string
}

// HookBudgetLookup returns the managed budget stop in force for tool at now.
// ok=false means nothing stops this tool: no decision was published, the
// published one has expired, or it is scoped to another tool.
type HookBudgetLookup func(tool string, now time.Time) (HookBudgetStop, bool)

// SetHookBudgetLookup wires the hook path's budget stop lookup. Set once at
// hook composition (cmd/observer buildHookGuard); nil leaves the hook path
// without a budget stop, which is what the daemon wants (its own chokepoints
// measure spend first-hand).
func (g *Guard) SetHookBudgetLookup(fn HookBudgetLookup) {
	if g == nil {
		return
	}
	g.hookBudget = fn
}

// hookBudgetVerdict returns the deny verdict for ev when a published managed
// budget stop covers ev's tool.
//
// It acts only in ENFORCE mode. Outside it the guard never blocks (D2), and a
// flag per hook call would re-record the same breach on every prompt and tool
// call of the session; the daemon's budget-warning service already tells the
// developer once per rung (budgetwarn_wire.go), and the watcher records the
// post-hoc flag once per session.
func (g *Guard) hookBudgetVerdict(ev policy.Event) (policy.Verdict, bool) {
	if g == nil || g.hookBudget == nil || !g.cfg.Enabled || g.cfg.Mode != "enforce" {
		return policy.Verdict{}, false
	}
	now := ev.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	stop, ok := g.hookBudget(ev.Tool, now)
	if !ok || strings.TrimSpace(stop.RuleID) == "" {
		return policy.Verdict{}, false
	}
	return policy.Verdict{
		Decision: policy.DecisionDeny,
		RuleID:   stop.RuleID,
		Severity: policy.SeverityHigh,
		Reason:   HookBudgetMessage(stop, g.requestBase),
		Source:   policy.SourceOrgBudget,
	}, true
}

// HookBudgetStopper is the optional evaluator capability a tool gate uses for
// a call its policy extractor could not classify (an unknown tool name, a
// class the event leaves to a sibling event): the budget is the one verdict
// that does not depend on what the call is. *Guard implements it.
type HookBudgetStopper interface {
	HookBudgetStopFor(ev policy.Event) (ActionVerdict, bool)
}

// HookBudgetStopFor returns the budget-only deny for a pre-send event, on a
// channel that can block. It runs no policy rule: the caller has nothing a
// rule could judge.
func (g *Guard) HookBudgetStopFor(ev policy.Event) (ActionVerdict, bool) {
	if !ev.Caps.CanBlock {
		return ActionVerdict{}, false
	}
	if ev.Now.IsZero() {
		ev.Now = time.Now().UTC()
	}
	bv, ok := g.hookBudgetVerdict(ev)
	if !ok {
		return ActionVerdict{}, false
	}
	return ActionVerdict{
		Input: ActionInput{
			SessionID: ev.SessionID, ProjectRoot: ev.ProjectRoot, Tool: ev.Tool,
			ActionType: ev.ActionType, Target: ev.Target, Timestamp: ev.Now,
		},
		Kind:     ev.Kind,
		Category: string(policy.CategoryBudget),
		Verdict:  bv,
	}, true
}

// hookBudgetTails is what the developer can do about each kind of stop, keyed
// by rule id (table, CLAUDE.md #5). B-625 is not a spend: the node has no
// verified organization budget, so asking for more money would not help.
// Every other budget row is a spend that more budget, or the next period,
// clears.
var hookBudgetTails = []struct {
	ruleID string
	tail   func(ruleID, base string) string
}{
	{"B-625", func(string, string) string {
		return "Prompts and tool calls are blocked until this node verifies its organization budget; " +
			"check `observer org status` or contact your org admin."
	}},
	{"", func(ruleID, base string) string {
		return "Prompts and tool calls are blocked until the period resets or an admin raises the cap. " +
			budgetRequestLine(ruleID, base)
	}},
}

// HookBudgetMessage renders the one line a developer reads when the hook path
// stops a prompt or a tool call on a managed budget: which budget, how far
// over, and how to get more (the request flow, D-085/D-232).
func HookBudgetMessage(stop HookBudgetStop, requestBase string) string {
	reason := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(stop.Reason), "."))
	if reason == "" {
		reason = "the organization budget is exhausted"
	}
	for _, row := range hookBudgetTails {
		if row.ruleID == "" || row.ruleID == stop.RuleID {
			return "Organization budget " + stop.RuleID + ": " + reason + ". " + row.tail(stop.RuleID, requestBase)
		}
	}
	return "Organization budget " + stop.RuleID + ": " + reason + "."
}

// BudgetIncreaseRequestPath is the node dashboard route that opens the budget
// increase request. It is the ONE place the link lives (D-334): the Requests
// page's stable budget deep link (T-522, web/src/lib/requestEntry.ts
// budgetRequestLink), which opens the request on the budget that ran out.
// It carries no `&budget=<id>` because the hook-path stop does not know one:
// budget-admission.json publishes the rule and the reason, not a budget id
// (T-529). Both halves are pinned against each other
// (TestT529DenyLinkOpensTheBudgetRequest and requestEntry.test.ts).
const BudgetIncreaseRequestPath = "/requests?new=budget"

// BudgetIncreaseRequestLabel is the dashboard path a developer follows by hand.
const BudgetIncreaseRequestLabel = "Requests > Ask for a budget increase"

// budgetRequestLine names the request flow for more budget: the node
// dashboard's budget request by its menu path (and as a link when the
// dashboard origin is known), and the CLI command, in the unit the denying
// rule measures.
func budgetRequestLine(ruleID, base string) string {
	amount := "--tokens <amount>"
	if interventionUSDBudgetRule(ruleID) {
		amount = "--usd <amount>"
	}
	// No URL in band (WINNODE2 16d): the agent relays the instruction; the
	// desktop notification carries the link (RequestAccessLink).
	dash := "the Observer dashboard under " + BudgetIncreaseRequestLabel
	return "Ask for more in " + dash + ", or run `observer request budget " + amount + " \"<why>\"`."
}

// IsBudgetRule reports whether ruleID is one of the budget / usage-limit rows
// (the "B-6" family). The prompt lane's house message reads it: a budget stop
// is not a finding in the prompt, so "edit it out" is the wrong advice.
func IsBudgetRule(ruleID string) bool { return isBudgetRuleID(ruleID) }

// RenderBudgetReason renders a budget rule's engine reason the way a developer
// reads it on every other surface: in the organization's terms for a window
// the org authored, and without dollars when the developer cost display is
// tokens. The daemon's admission publisher calls it, so a hook process never
// needs the origin table or the display policy.
func (g *Guard) RenderBudgetReason(ruleID, reason string) string {
	if g == nil {
		return reason
	}
	return g.labelOrgBudgetVerdict(policy.Verdict{RuleID: ruleID, Reason: reason}).Reason
}
