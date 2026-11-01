package controlcoverage

import (
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Per-tool rule coverage (guard enforcement fix, 2026-10-15): for every
// advertised tool, what a developer EXPERIENCES when a guard rule resolves
// to flag, ask or deny, on the prompt lane (R-172 / R-190 on the
// developer's own prompt) and on the tool-call lane (a rule judged on a
// tool call). It is the admin-facing honesty surface the org guard form
// renders per rule, generated into shared/lib/guardToolCoverage.generated.ts
// by tools/guardcoveragegen.
//
// Everything is DERIVED from capability data, never from a tool name
// (CLAUDE.md rules 3 and 5): the registry's hook bindings (which gate is
// wired, its decisions, session key, WarnField, AdminCaveat), the prompt
// dialect rows' seam capabilities walked through guard.ResolvePromptAction
// (the one decision x capability ladder the prompt lanes use), and the
// conformance matrix's tool-gate capabilities walked through the same rules
// guard.ResolveEmission applies. The per-dialect facts that live in
// internal/hook are injected (RuleSeamFacts) so this package stays a pure
// join.

// RuleOutcome is what the developer experiences for one rule decision on
// one tool. Closed vocabulary; RuleOutcomes lists it strongest first.
type RuleOutcome string

const (
	// RuleBlocks: the prompt or call is stopped.
	RuleBlocks RuleOutcome = "blocks"
	// RuleRedacts: the prompt goes through with the secret masked.
	RuleRedacts RuleOutcome = "redacts"
	// RuleAsks: the host's own native confirm.
	RuleAsks RuleOutcome = "asks"
	// RuleAsksResend: the prompt is stopped with a message; sending it again
	// unchanged confirms (the reconsider-once flow).
	RuleAsksResend RuleOutcome = "asks_resend"
	// RuleWarns: a notice the developer sees; nothing is stopped.
	RuleWarns RuleOutcome = "warns"
	// RuleWarnsModel: the notice reaches the model, not the developer (who
	// gets a desktop notice); nothing is stopped.
	RuleWarnsModel RuleOutcome = "warns_model"
	// RuleRecordsOnly: nothing is shown or stopped before it happens; the
	// finding is recorded after the fact.
	RuleRecordsOnly RuleOutcome = "records_only"
	// RuleNotCovered: no lane sees this kind of activity on the tool.
	RuleNotCovered RuleOutcome = "not_covered"
)

// ruleOutcomeOrder is the closed vocabulary, strongest first.
var ruleOutcomeOrder = []RuleOutcome{
	RuleBlocks, RuleRedacts, RuleAsks, RuleAsksResend, RuleWarns, RuleWarnsModel, RuleRecordsOnly, RuleNotCovered,
}

// RuleOutcomes returns the closed outcome vocabulary, strongest first.
func RuleOutcomes() []RuleOutcome {
	out := make([]RuleOutcome, len(ruleOutcomeOrder))
	copy(out, ruleOutcomeOrder)
	return out
}

// RuleSeam is the lane that produces a tool's outcome.
type RuleSeam string

const (
	// RuleSeamHook: a wired hook or plugin gate.
	RuleSeamHook RuleSeam = "hook"
	// RuleSeamProxy: the Observer proxy, only while the tool's traffic
	// routes through it.
	RuleSeamProxy RuleSeam = "proxy"
	// RuleSeamCapture: the post-hoc capture lane (transcript, database).
	RuleSeamCapture RuleSeam = "capture"
	// RuleSeamNone: nothing sees this activity.
	RuleSeamNone RuleSeam = "none"
)

// RuleLaneCoverage is one lane's answer for one tool.
type RuleLaneCoverage struct {
	Seam RuleSeam
	// Event is the native event of the gate that answers (hook seam only).
	Event string
	// Flag, Ask and Deny are the outcomes of the three rule decisions. An
	// overridable deny resolves as an ask before it reaches the lane.
	Flag RuleOutcome
	Ask  RuleOutcome
	Deny RuleOutcome
	// Caveats are short capability facts that qualify the outcomes, in a
	// stable order.
	Caveats []string
}

// For returns the lane's outcome for decision d (flag, ask or deny);
// RuleNotCovered for any other decision.
func (l RuleLaneCoverage) For(d policy.Decision) RuleOutcome {
	switch d {
	case policy.DecisionFlag:
		return l.Flag
	case policy.DecisionAsk:
		return l.Ask
	case policy.DecisionDeny:
		return l.Deny
	}
	return RuleNotCovered
}

// ToolRuleCoverage is one tool's rule coverage on both lanes.
type ToolRuleCoverage struct {
	Tool     string
	Name     string
	Prompt   RuleLaneCoverage
	ToolCall RuleLaneCoverage
}

// RuleSeamFacts are the per-dialect facts internal/hook owns, injected so
// this package stays pure. Both funcs are required.
type RuleSeamFacts struct {
	// PromptCaps returns a prompt dialect's seam capabilities as its row
	// declares them and whether the row narrows them per invocation
	// (hook.PromptDialectSeamCaps). ok=false for an unknown dialect.
	PromptCaps func(dialect string) (caps guard.PromptSeamCaps, probed, ok bool)
	// ToolAskProbed reports whether a tool-gate dialect offers its native
	// ask only when the running host can show it (hook.ToolGateAskProbed).
	ToolAskProbed func(dialect string) bool
}

// ruleDecisions are the three decisions a lane answers, in display order.
var ruleDecisions = []policy.Decision{policy.DecisionFlag, policy.DecisionAsk, policy.DecisionDeny}

// RuleCoverage returns the rule coverage of every advertised registry tool,
// sorted by tool id. A dead or deprecated row is skipped: the guard form
// lists the tools a developer can still be using.
func RuleCoverage(f RuleSeamFacts) []ToolRuleCoverage {
	caps := integration.Capabilities()
	sort.Slice(caps, func(i, j int) bool { return caps[i].Tool < caps[j].Tool })
	matrix := guard.ConformanceMatrix()
	out := make([]ToolRuleCoverage, 0, len(caps))
	for _, c := range caps {
		if !c.Advertised() {
			continue
		}
		out = append(out, ToolRuleCoverage{
			Tool:     c.Tool,
			Name:     integration.DisplayName(c.Tool),
			Prompt:   promptRuleCoverage(c, f),
			ToolCall: toolCallRuleCoverage(c, matrix, f),
		})
	}
	return out
}

// --- prompt lane -------------------------------------------------------------

// promptActionOutcome maps a resolved prompt action onto the outcome
// vocabulary. A warn on a seam whose notice reaches the model is
// RuleWarnsModel (promptOutcome).
var promptActionOutcome = map[guard.PromptAction]RuleOutcome{
	guard.PromptActionWarn:      RuleWarns,
	guard.PromptActionConfirm:   RuleAsks,
	guard.PromptActionReenter:   RuleAsksResend,
	guard.PromptActionBlock:     RuleBlocks,
	guard.PromptActionRedact:    RuleRedacts,
	guard.PromptActionFlagAfter: RuleRecordsOnly,
}

func promptOutcome(a guard.PromptAction, caps guard.PromptSeamCaps) RuleOutcome {
	if a == guard.PromptActionWarn && caps.WarnIndirect {
		return RuleWarnsModel
	}
	if o, ok := promptActionOutcome[a]; ok {
		return o
	}
	return RuleRecordsOnly
}

// laneFromPromptCaps resolves the three decisions through the one prompt
// decision ladder (guard.ResolvePromptAction).
func laneFromPromptCaps(seam RuleSeam, event string, caps guard.PromptSeamCaps) RuleLaneCoverage {
	l := RuleLaneCoverage{Seam: seam, Event: event}
	for _, d := range ruleDecisions {
		a, _ := guard.ResolvePromptAction(d, caps)
		o := promptOutcome(a, caps)
		switch d {
		case policy.DecisionFlag:
			l.Flag = o
		case policy.DecisionAsk:
			l.Ask = o
		case policy.DecisionDeny:
			l.Deny = o
		}
	}
	return l
}

// Prompt-lane caveats derived from capability facts.
const (
	caveatNoSessionKey = "The hook payload carries no session id, so an ask cannot be confirmed by resending: it blocks."
	caveatProbedWarns  = "Stops only on a host version proven to honour the stop; an older host gets a warning instead."
	caveatProbedRecord = "Stops only on a host version proven to honour the stop; an older host only records the prompt."
	caveatBlockSilent  = "A block shows no reason in the tool; the developer gets a desktop notice."
	caveatProxyRouted  = "Only while the tool's traffic routes through the Observer proxy; otherwise the prompt is recorded after it was sent."
)

// wiredPromptGate returns the tool's first wired prompt-gate binding whose
// dialect has a row in the prompt dialect table.
func wiredPromptGate(c integration.Capability, f RuleSeamFacts) (integration.HookBinding, guard.PromptSeamCaps, bool, bool) {
	for _, b := range c.Hook.Bindings {
		if b.Cap != integration.HookCapPromptGate || !b.Wired || b.Dialect == "" {
			continue
		}
		if caps, probed, ok := f.PromptCaps(b.Dialect); ok {
			return b, caps, probed, true
		}
	}
	return integration.HookBinding{}, guard.PromptSeamCaps{}, false, false
}

// promptRuleCoverage walks the prompt lanes in the order they act: a wired
// prompt hook, else the proxy route, else the post-hoc capture lane.
func promptRuleCoverage(c integration.Capability, f RuleSeamFacts) RuleLaneCoverage {
	if b, caps, probed, ok := wiredPromptGate(c, f); ok {
		var cav []string
		if caps.Reenter && !b.SessionKey {
			caps.Reenter = false
			cav = append(cav, caveatNoSessionKey)
		}
		l := laneFromPromptCaps(RuleSeamHook, b.NativeEvent, caps)
		rules := []struct {
			when bool
			text string
		}{
			{probed && caps.Warn, caveatProbedWarns},
			{probed && !caps.Warn, caveatProbedRecord},
			{caps.BlockSilent, caveatBlockSilent},
			{c.Hook.PromptScope != "", c.Hook.PromptScope},
			{b.AdminCaveat != "", b.AdminCaveat},
			{c.Hook.SurfaceCaveat() != "", c.Hook.SurfaceCaveat()},
		}
		for _, r := range rules {
			if r.when {
				cav = append(cav, r.text)
			}
		}
		l.Caveats = cav
		return l
	}
	if c.Proxy != nil {
		l := laneFromPromptCaps(RuleSeamProxy, "", guard.PromptSeamProxy)
		l.Caveats = []string{caveatProxyRouted}
		if c.Proxy.PromptScope != "" {
			l.Caveats = append(l.Caveats, c.Proxy.PromptScope)
		}
		return l
	}
	return RuleLaneCoverage{Seam: RuleSeamCapture, Flag: RuleRecordsOnly, Ask: RuleRecordsOnly, Deny: RuleRecordsOnly}
}

// --- tool-call lane ----------------------------------------------------------

// Tool-lane caveats derived from capability facts.
const (
	caveatToolAskProbed = "The native ask is offered only where the running host can show it; elsewhere an ask blocks and says how to confirm."
)

// toolDecisionOutcome is guard.ResolveEmission's capability table as
// outcomes, plus the flag notice: deny blocks where the channel can block;
// ask asks natively where it can ask, else blocks where it can block (F5);
// a flag is a notice only where the binding declares a developer-visible
// warn field. Anything the channel cannot do is recorded after the fact.
func toolDecisionOutcome(d policy.Decision, caps policy.Capabilities, b integration.HookBinding) RuleOutcome {
	switch d {
	case policy.DecisionDeny:
		if caps.CanBlock {
			return RuleBlocks
		}
	case policy.DecisionAsk:
		if caps.CanAsk {
			return RuleAsks
		}
		if caps.CanBlock {
			return RuleBlocks
		}
	case policy.DecisionFlag:
		if b.WarnField != "" {
			return RuleWarns
		}
	}
	return RuleRecordsOnly
}

// toolGateLane is one wired tool-gate binding's lane.
type toolGateLane struct {
	b    integration.HookBinding
	caps policy.Capabilities
	lane RuleLaneCoverage
}

// wiredToolGates returns the tool's wired tool-gate bindings that the
// conformance matrix lists as enforcement channels, registry order.
func wiredToolGates(c integration.Capability, matrix []guard.ConformanceEntry) []toolGateLane {
	var out []toolGateLane
	for _, b := range c.Hook.Bindings {
		if b.Cap != integration.HookCapToolGate || !b.Wired {
			continue
		}
		caps, ok := conformanceCaps(matrix, c.Tool, "hook:"+b.NativeEvent)
		if !ok || !caps.CanBlock {
			continue
		}
		l := RuleLaneCoverage{
			Seam: RuleSeamHook, Event: b.NativeEvent,
			Flag: toolDecisionOutcome(policy.DecisionFlag, caps, b),
			Ask:  toolDecisionOutcome(policy.DecisionAsk, caps, b),
			Deny: toolDecisionOutcome(policy.DecisionDeny, caps, b),
		}
		out = append(out, toolGateLane{b: b, caps: caps, lane: l})
	}
	return out
}

func conformanceCaps(matrix []guard.ConformanceEntry, tool, channel string) (policy.Capabilities, bool) {
	for _, e := range matrix {
		if e.Client == tool && e.Channel == channel {
			return e.Caps, true
		}
	}
	return policy.Capabilities{}, false
}

// outcomePhrase is how a caveat names an outcome after "a flag" / "an ask"
// / "a deny".
var outcomePhrase = map[RuleOutcome]string{
	RuleBlocks:      "blocks",
	RuleRedacts:     "masks the secret",
	RuleAsks:        "asks natively",
	RuleAsksResend:  "asks for a resend",
	RuleWarns:       "warns",
	RuleWarnsModel:  "warns the model only",
	RuleRecordsOnly: "is only recorded",
	RuleNotCovered:  "is not covered",
}

var decisionArticle = map[policy.Decision]string{
	policy.DecisionFlag: "a flag",
	policy.DecisionAsk:  "an ask",
	policy.DecisionDeny: "a deny",
}

// differenceCaveat names, for a secondary gate, every decision whose
// outcome differs from the primary gate's ("" when none does).
func differenceCaveat(primary, other RuleLaneCoverage) string {
	var parts []string
	for _, d := range ruleDecisions {
		if o := other.For(d); o != primary.For(d) {
			parts = append(parts, decisionArticle[d]+" "+outcomePhrase[o])
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "On " + other.Event + " " + strings.Join(parts, " and ") + "."
}

// toolCallRuleCoverage answers from the tool's first wired tool gate, with
// a caveat for every other gate that answers differently; with no gate, the
// post-hoc lane records (or nothing sees tool calls at all).
func toolCallRuleCoverage(c integration.Capability, matrix []guard.ConformanceEntry, f RuleSeamFacts) RuleLaneCoverage {
	gates := wiredToolGates(c, matrix)
	if len(gates) == 0 {
		if c.Hook.Mechanism == integration.HookBrowserExtension {
			return RuleLaneCoverage{Seam: RuleSeamNone, Flag: RuleNotCovered, Ask: RuleNotCovered, Deny: RuleNotCovered}
		}
		return RuleLaneCoverage{Seam: RuleSeamCapture, Flag: RuleRecordsOnly, Ask: RuleRecordsOnly, Deny: RuleRecordsOnly}
	}
	l := gates[0].lane
	var cav []string
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			cav = append(cav, s)
		}
	}
	for i, g := range gates {
		if i > 0 {
			add(differenceCaveat(l, g.lane))
		}
		if g.caps.CanAsk && f.ToolAskProbed(g.b.Dialect) {
			add(caveatToolAskProbed)
		}
		add(g.b.AdminCaveat)
	}
	add(c.Hook.SurfaceCaveat())
	l.Caveats = cav
	return l
}
