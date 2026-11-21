package planebadmission

import (
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policyfam/admission"
	"github.com/marmutapp/superbased-observer/internal/promptadmit"
)

// authoring.go is what the org admin's authoring form reads (lane adm-p2):
// the publish-time warnings a compiled body earns and the node lane's judge
// budget, both owned here so the org server's lint, the simulate route and
// the node lane can never disagree with the compiler.

// NodeLaneRelayDefaultBudgetMS is the node lane's judge budget when the body
// set no latency_budget_ms: the relay path is node to org server to provider,
// and the gateway's 1500 ms default made every relayed judge call time out
// (the 2026-08-31 demo estate).
const NodeLaneRelayDefaultBudgetMS = 10_000

// NodeLaneJudgeBudget is the node lane's judge budget: the body's
// latency_budget_ms when the admin set one, else NodeLaneRelayDefaultBudgetMS.
// s is compiled from the signed canonical bytes, where an absent budget stays
// absent (CompileBody).
func NodeLaneJudgeBudget(s PolicySpec) time.Duration {
	if !s.LatencyBudgetExplicit {
		return NodeLaneRelayDefaultBudgetMS * time.Millisecond
	}
	return time.Duration(s.LatencyBudgetMS) * time.Millisecond
}

// GatewayJudgeBudget is the AI gateway's judge budget (the body's value, or
// DefaultLatencyBudgetMS).
func GatewayJudgeBudget(s PolicySpec) time.Duration {
	return time.Duration(s.LatencyBudgetMS) * time.Millisecond
}

// AllCallsJudgeMultiplier is the conservative judge-call multiplier of
// all_calls over user_prompts on a coding agent's tool loop: one typed prompt
// fans out to a median of about 15 to 20 model calls
// (docs/plans/discovery-admission-2026-11-03.md section 1).
const AllCallsJudgeMultiplier = 15

// lintRow is one publish-time warning: when it applies and what it says.
type lintRow struct {
	when func(PolicySpec) bool
	text func(PolicySpec) string
}

// lintTable is walked top-down; every matching row adds its line. A warning
// never stops publication (the compiler is the only gate).
var lintTable = []lintRow{
	{
		when: func(s PolicySpec) bool { return s.Scope == promptadmit.ScopeAllCalls && RequiresJudge(s) },
		text: func(PolicySpec) string {
			return fmt.Sprintf("scope all_calls judges every model call of a tool loop, tool results included: expect about %dx the judge calls, judge cost and added latency of user_prompts, and tool output (file contents, command output) sent to the judge", AllCallsJudgeMultiplier)
		},
	},
	{
		when: func(s PolicySpec) bool { return s.Scope == promptadmit.ScopeAllCalls && !RequiresJudge(s) },
		text: func(PolicySpec) string {
			return "scope all_calls runs the deterministic layers on every model call of a tool loop, tool results included; with no judged criteria this costs no judge calls, but a tool result that matches a deny pattern refuses the call"
		},
	},
	{
		when: func(s PolicySpec) bool { return s.Admission.Strict && Enforces(s) && RequiresJudge(s) },
		text: func(PolicySpec) string {
			return "strict + enforce: while the judge cannot answer (no route, outage, timeout) every judged prompt is refused; non-strict admits and flags instead"
		},
	},
	{
		when: func(s PolicySpec) bool { return Enforces(s) && s.NodeLane },
		text: func(PolicySpec) string {
			return "enforce with node_lane on refuses prompts on every managed machine that holds enforce.admission; run it in observe first and check the verdicts with Simulate"
		},
	},
	{
		when: func(s PolicySpec) bool { return s.Admission.Mode != admission.ModeOff && NodeLaneOnly(s) },
		text: func(PolicySpec) string {
			return "node lane only: no AI gateway judge upstream is named, so the gateway applies only the deterministic layers (pre-filter, denied topics, jailbreak) and skips the LLM-judged criteria; managed machines judge them through the organization's judge relay (the provider bound to coding_admission_judge)"
		},
	},
	{
		when: func(s PolicySpec) bool { return s.Admission.Mode != admission.ModeOff && !s.NodeLane },
		text: func(PolicySpec) string {
			return "node_lane is off: only requests through the organization's AI gateway are judged; developer machines in Node Mode run no prompt judge"
		},
	},
}

// LintWarnings is the authoring form's publish-time warnings for a compiled
// body, in table order.
func LintWarnings(s PolicySpec) []string {
	var out []string
	for _, r := range lintTable {
		if r.when(s) {
			out = append(out, r.text(s))
		}
	}
	return out
}

// Vocab is the closed authoring vocabulary of the body, for the form's
// pickers (one owner: the values the compiler accepts).
type Vocab struct {
	Modes      []string `json:"modes"`
	Scopes     []string `json:"scopes"`
	Decisions  []string `json:"decisions"`
	Severities []string `json:"severities"`
	// CriterionTypes are the inner criterion types; JudgedTypes the subset
	// that calls the judge.
	CriterionTypes          []string `json:"criterion_types"`
	JudgedTypes             []string `json:"judged_types"`
	DefaultLatencyBudgetMS  int      `json:"default_latency_budget_ms"`
	NodeLaneDefaultBudgetMS int      `json:"node_lane_default_budget_ms"`
	AllCallsMultiplier      int      `json:"all_calls_multiplier"`
}

// AuthoringVocab returns the closed vocabulary.
func AuthoringVocab() Vocab {
	return Vocab{
		Modes:      []string{admission.ModeOff.String(), admission.ModeObserve.String(), admission.ModeEnforce.String()},
		Scopes:     []string{string(promptadmit.ScopeUserPrompts), string(promptadmit.ScopeAllCalls)},
		Decisions:  []string{admission.DecisionAllow.String(), admission.DecisionFlag.String(), admission.DecisionAsk.String(), admission.DecisionDeny.String()},
		Severities: []string{admission.SeverityInfo.String(), admission.SeverityWarn.String(), admission.SeverityHigh.String(), admission.SeverityCritical.String()},
		CriterionTypes: []string{
			string(admission.TypeValidUseCase), string(admission.TypeDeniedTopics),
			string(admission.TypeJailbreak), string(admission.TypeCustom),
		},
		JudgedTypes:             []string{string(admission.TypeValidUseCase), string(admission.TypeCustom)},
		DefaultLatencyBudgetMS:  DefaultLatencyBudgetMS,
		NodeLaneDefaultBudgetMS: NodeLaneRelayDefaultBudgetMS,
		AllCallsMultiplier:      AllCallsJudgeMultiplier,
	}
}
