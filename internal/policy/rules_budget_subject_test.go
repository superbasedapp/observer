package policy

import (
	"strings"
	"testing"
	"time"
)

// Bundle BUD-N rule tests: the cross-machine baseline on the node-wide rows,
// and the four per-subject rows.

func subjectTestEvent(tool, model string) Event {
	return Event{Kind: KindAPIRequest, Target: "anthropic:m", Now: time.Now()}.withSubject(tool, model)
}

// withSubject is a tiny builder so each case reads as data rather than as six
// lines of struct literal.
func (e Event) withSubject(tool, model string) Event {
	e.Tool, e.Model = tool, model
	return e
}

// TestBudgetRules_OrgBaselineIsAddedToLocalSpend pins the P1-9 rule on the
// node-wide rows: the comparison is `org spend on the OTHER machines + this
// machine's own`, so a developer's laptop trips a cap their devbox has already
// half-consumed.
func TestBudgetRules_OrgBaselineIsAddedToLocalSpend(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		local       float64
		baseline    float64
		wantHit     bool
		wantMention bool
	}{
		{name: "local alone is under the cap", local: 6, wantHit: false},
		{name: "local alone crosses the cap", local: 11, wantHit: true},
		{name: "local plus baseline crosses it", local: 6, baseline: 5, wantHit: true, wantMention: true},
		{name: "baseline alone crosses it", baseline: 12, wantHit: true, wantMention: true},
		{name: "a zero baseline changes nothing", local: 6, baseline: 0, wantHit: false},
	}
	eng, err := New(Config{Mode: ModeObserve, BudgetDailyUSD: 10})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev := Event{Kind: KindAPIRequest, Now: time.Now(), DailyCostUSD: tc.local}
			ev.OrgBaseline.DailyUSD = tc.baseline
			v := eng.Evaluate(ev)
			hit := v.RuleID == "B-602"
			if hit != tc.wantHit {
				t.Fatalf("Evaluate = %s/%s, want B-602 hit=%v", v.RuleID, v.Decision, tc.wantHit)
			}
			if !hit {
				return
			}
			mentions := strings.Contains(v.Reason, "other machines")
			if mentions != tc.wantMention {
				t.Errorf("reason %q mentions the baseline = %v, want %v", v.Reason, mentions, tc.wantMention)
			}
		})
	}
}

// TestTokenBudgetRules_OrgBaseline is the same property in the other unit —
// asserted separately because the two matchers are two implementations.
func TestTokenBudgetRules_OrgBaseline(t *testing.T) {
	t.Parallel()
	eng, err := New(Config{Mode: ModeObserve, BudgetMonthlyTokens: 1000})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ev := Event{Kind: KindAPIRequest, Now: time.Now(), MonthlyTokens: 400}
	if v := eng.Evaluate(ev); v.RuleID == "B-623" {
		t.Fatalf("local 400 of 1000 tripped B-623: %s", v.Reason)
	}
	ev.OrgBaseline.MonthlyTokens = 700
	v := eng.Evaluate(ev)
	if v.RuleID != "B-623" {
		t.Fatalf("400 local + 700 org = 1100 of 1000 did not trip B-623 (got %q)", v.RuleID)
	}
	if !strings.Contains(v.Reason, "1100") {
		t.Errorf("reason %q does not state the combined figure", v.Reason)
	}
}

// TestSubjectBudgetRules_ToolCap drives the per-tool rows with TWO tools, which
// is the case that matters: the capped tool trips and the uncapped one does
// not, from the same engine and the same stamped snapshot.
func TestSubjectBudgetRules_ToolCap(t *testing.T) {
	t.Parallel()
	cfg := Config{Mode: ModeEnforce, BudgetSubjectCaps: []BudgetSubjectCap{
		{Kind: BudgetSubjectKindTool, ID: "claude-code", Window: BudgetWindowDaily, CapUSD: 3, Hard: true},
	}}
	eng, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cases := []struct {
		name     string
		tool     string
		usage    BudgetWindowAmounts
		wantRule string
		wantDec  Decision
	}{
		{
			name: "the capped tool over its ceiling denies",
			tool: "claude-code", usage: BudgetWindowAmounts{DailyUSD: 3.5},
			wantRule: "B-626", wantDec: DecisionDeny,
		},
		{
			name: "the capped tool AT its ceiling denies (a hard cap is exhausted at the limit)",
			tool: "claude-code", usage: BudgetWindowAmounts{DailyUSD: 3},
			wantRule: "B-626", wantDec: DecisionDeny,
		},
		{
			name: "the capped tool under its ceiling passes",
			tool: "claude-code", usage: BudgetWindowAmounts{DailyUSD: 2.99},
		},
		{
			name: "a DIFFERENT tool with the same spend passes",
			tool: "codex", usage: BudgetWindowAmounts{DailyUSD: 99},
		},
		{
			name: "the cap matches case-insensitively",
			tool: "Claude-Code", usage: BudgetWindowAmounts{DailyUSD: 4},
			wantRule: "B-626", wantDec: DecisionDeny,
		},
		{
			name:  "an event with no tool cannot match a tool cap",
			usage: BudgetWindowAmounts{DailyUSD: 99},
		},
		{
			name: "a different WINDOW of the same tool is not the capped one",
			tool: "claude-code", usage: BudgetWindowAmounts{MonthlyUSD: 99},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev := subjectTestEvent(tc.tool, "")
			ev.ToolUsage = tc.usage
			v := eng.Evaluate(ev)
			if tc.wantRule == "" {
				if v.Decision >= DecisionFlag {
					t.Fatalf("unexpected verdict %s/%s: %s", v.RuleID, v.Decision, v.Reason)
				}
				return
			}
			if v.RuleID != tc.wantRule || v.Decision != tc.wantDec {
				t.Fatalf("Evaluate = %s/%s, want %s/%s (%s)", v.RuleID, v.Decision, tc.wantRule, tc.wantDec, v.Reason)
			}
			if !strings.Contains(v.Reason, "claude-code") {
				t.Errorf("reason %q does not name the capped subject", v.Reason)
			}
		})
	}
}

// TestSubjectBudgetRules_ModelCapInTokens exercises the model rows, the token
// unit, and the baseline on a subject cap.
func TestSubjectBudgetRules_ModelCapInTokens(t *testing.T) {
	t.Parallel()
	eng, err := New(Config{Mode: ModeEnforce, BudgetSubjectCaps: []BudgetSubjectCap{
		{
			Kind: BudgetSubjectKindModel, ID: "gpt-5", Window: BudgetWindowMonthly,
			CapTokens: 1000, BaselineTokens: 600, Hard: true,
		},
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ev := subjectTestEvent("codex", "GPT-5")
	ev.ModelUsage = BudgetWindowAmounts{MonthlyTokens: 300}
	if v := eng.Evaluate(ev); v.Decision >= DecisionFlag {
		t.Fatalf("300 local + 600 org = 900 of 1000 tripped %s: %s", v.RuleID, v.Reason)
	}
	ev.ModelUsage = BudgetWindowAmounts{MonthlyTokens: 400}
	v := eng.Evaluate(ev)
	if v.RuleID != "B-629" || v.Decision != DecisionDeny {
		t.Fatalf("Evaluate = %s/%s, want B-629/deny (%s)", v.RuleID, v.Decision, v.Reason)
	}
	if !strings.Contains(v.Reason, "1000") || !strings.Contains(v.Reason, "other machines") {
		t.Errorf("reason %q should state the ceiling and the cross-machine caveat", v.Reason)
	}
	// The tool rows must stay out of it: this event's TOOL is uncapped.
	if strings.Contains(v.Reason, "codex") {
		t.Errorf("a model cap named the tool: %q", v.Reason)
	}
}

// TestSubjectBudgetRules_SoftCapStaysAFlagUnderNodeHard is the MEDIUM-3
// property, applied to subjects: [guard.budget].hard is the NODE's posture
// about the node's own ceilings and must not turn an organization's `soft`
// per-tool cap into a denial.
func TestSubjectBudgetRules_SoftCapStaysAFlagUnderNodeHard(t *testing.T) {
	t.Parallel()
	eng, err := New(Config{Mode: ModeEnforce, BudgetHard: true, BudgetSubjectCaps: []BudgetSubjectCap{
		{Kind: BudgetSubjectKindTool, ID: "cline", Window: BudgetWindowDaily, CapUSD: 2, Hard: false},
		{Kind: BudgetSubjectKindTool, ID: "codex", Window: BudgetWindowDaily, CapUSD: 2, Hard: true},
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	soft := subjectTestEvent("cline", "")
	soft.ToolUsage = BudgetWindowAmounts{DailyUSD: 5}
	if v := eng.Evaluate(soft); v.RuleID != "B-626" || v.Decision != DecisionFlag {
		t.Fatalf("soft cap = %s/%s, want B-626/flag (%s)", v.RuleID, v.Decision, v.Reason)
	}
	hard := subjectTestEvent("codex", "")
	hard.ToolUsage = BudgetWindowAmounts{DailyUSD: 5}
	if v := eng.Evaluate(hard); v.RuleID != "B-626" || v.Decision != DecisionDeny {
		t.Fatalf("hard cap = %s/%s, want B-626/deny (%s)", v.RuleID, v.Decision, v.Reason)
	}
	// AT the limit the soft cap must NOT match at all (only a hard ceiling is
	// exhausted at its limit), and the hard one must.
	softAt := subjectTestEvent("cline", "")
	softAt.ToolUsage = BudgetWindowAmounts{DailyUSD: 2}
	if v := eng.Evaluate(softAt); v.Decision >= DecisionFlag {
		t.Errorf("soft cap matched exactly at its limit: %s/%s", v.RuleID, v.Reason)
	}
}

// TestSubjectBudgetRules_UnavailableAccountingDoesNotAdmit: a configured
// subject cap whose window's accounting could not be established matches, for
// the same reason its node-wide siblings do — a hard ceiling must not admit on
// a fabricated zero.
func TestSubjectBudgetRules_UnavailableAccountingDoesNotAdmit(t *testing.T) {
	t.Parallel()
	eng, err := New(Config{Mode: ModeEnforce, BudgetSubjectCaps: []BudgetSubjectCap{
		{Kind: BudgetSubjectKindTool, ID: "claude-code", Window: BudgetWindowDaily, CapUSD: 3, Hard: true},
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ev := subjectTestEvent("claude-code", "")
	ev.USDUnavailable = BudgetUnavailableWindows{Daily: true}
	v := eng.Evaluate(ev)
	if v.RuleID != "B-626" || v.Decision != DecisionDeny {
		t.Fatalf("Evaluate = %s/%s, want B-626/deny on unavailable accounting", v.RuleID, v.Decision)
	}
	if !strings.Contains(v.Reason, "unavailable") {
		t.Errorf("reason %q should say the accounting is unavailable", v.Reason)
	}
}

// TestSubjectBudgetRules_InertWithoutCaps pins the pre-feature behaviour: an
// engine with no subject caps evaluates exactly as it did before, whatever the
// event carries.
func TestSubjectBudgetRules_InertWithoutCaps(t *testing.T) {
	t.Parallel()
	eng, err := New(Config{Mode: ModeEnforce, BudgetHard: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ev := subjectTestEvent("claude-code", "gpt-5")
	ev.ToolUsage = BudgetWindowAmounts{DailyUSD: 9999, MonthlyTokens: 9999}
	ev.ModelUsage = ev.ToolUsage
	if v := eng.Evaluate(ev); v.Decision >= DecisionFlag {
		t.Fatalf("subject rows fired with no caps configured: %s/%s (%s)", v.RuleID, v.Decision, v.Reason)
	}
}

// TestSubjectBudgetRules_ProtectionAndAdmissionRegistration pins the two
// registries a new budget rule ID must join, because forgetting either is
// silent: the admission filter (or the row never reaches the proxy's
// budget-only evaluation) and the protection map (or a managed hard cap cannot
// authorize a process intervention).
func TestSubjectBudgetRules_ProtectionAndAdmissionRegistration(t *testing.T) {
	t.Parallel()
	for _, id := range []string{"B-626", "B-627", "B-628", "B-629"} {
		if !budgetAdmissionRuleID(id) {
			t.Errorf("%s is not a budget admission rule — the proxy's EvaluateBudget would skip it", id)
		}
		if !subjectBudgetRuleID(id) {
			t.Errorf("%s is not registered as a subject row — the hard-upgrade exemption would sweep it up", id)
		}
	}
	full := BudgetProtection{ToolUSD: true, ToolTokens: true, ModelUSD: true, ModelTokens: true}
	for id, want := range map[string]bool{
		"B-626": true, "B-627": true, "B-628": true, "B-629": true, "B-601": false,
	} {
		if got := full.ProtectsRule(id); got != want {
			t.Errorf("ProtectsRule(%q) = %v, want %v", id, got, want)
		}
	}
	none := BudgetProtection{}
	for _, id := range []string{"B-626", "B-627", "B-628", "B-629"} {
		if none.ProtectsRule(id) {
			t.Errorf("an empty protection protected %s", id)
		}
	}
}

// TestBudgetRules_FlagOnlyBaselineNeverDenies is the P1-2 table: a baseline the
// server flagged as including unattributed rows may WARN and may not deny. On a
// [guard.budget].hard node the node-wide rows drop it; on a flagging node they
// keep it.
func TestBudgetRules_FlagOnlyBaselineNeverDenies(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		hard     bool
		flagOnly bool
		wantHit  bool
		wantDec  Decision
	}{
		{name: "flagging node composes an attributed baseline", wantHit: true, wantDec: DecisionFlag},
		{
			name:     "flagging node composes a flag-only baseline too",
			flagOnly: true, wantHit: true, wantDec: DecisionFlag,
		},
		{
			name: "hard node composes an attributed baseline and denies",
			hard: true, wantHit: true, wantDec: DecisionDeny,
		},
		{
			name: "hard node WITHHOLDS a flag-only baseline, so nothing crosses",
			hard: true, flagOnly: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			eng, err := New(Config{Mode: ModeEnforce, BudgetDailyUSD: 10, BudgetHard: tc.hard})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			// 6 local + 5 org = 11 of 10: it crosses only when the baseline counts.
			ev := Event{Kind: KindAPIRequest, Now: time.Now(), DailyCostUSD: 6}
			ev.OrgBaseline.DailyUSD = 5
			ev.OrgBaselineFlagOnly = tc.flagOnly
			v := eng.Evaluate(ev)
			hit := v.RuleID == "B-602"
			if hit != tc.wantHit {
				t.Fatalf("Evaluate = %s/%s, want B-602 hit=%v", v.RuleID, v.Decision, tc.wantHit)
			}
			if hit && v.Decision != tc.wantDec {
				t.Errorf("decision = %s, want %s", v.Decision, tc.wantDec)
			}
		})
	}
}

// TestSubjectBudgetRules_FlagOnlyBaselineIsPerCapHardness is the subject half:
// hardness is per cap, so the flag-only baseline is withheld from the HARD cap
// and kept for the SOFT one, in the same engine.
func TestSubjectBudgetRules_FlagOnlyBaselineIsPerCapHardness(t *testing.T) {
	t.Parallel()
	eng, err := New(Config{Mode: ModeEnforce, BudgetSubjectCaps: []BudgetSubjectCap{
		{
			Kind: BudgetSubjectKindTool, ID: "codex", Window: BudgetWindowDaily, CapUSD: 10,
			BaselineUSD: 5, BaselineFlagOnly: true, Hard: true,
		},
		{
			Kind: BudgetSubjectKindTool, ID: "cline", Window: BudgetWindowDaily, CapUSD: 10,
			BaselineUSD: 5, BaselineFlagOnly: true,
		},
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// 6 local + 5 flag-only baseline = 11 of 10.
	hardEv := subjectTestEvent("codex", "")
	hardEv.ToolUsage = BudgetWindowAmounts{DailyUSD: 6}
	if v := eng.Evaluate(hardEv); v.RuleID == "B-626" {
		t.Errorf("a HARD cap denied on a flag-only baseline: %s / %s", v.Decision, v.Reason)
	}
	softEv := subjectTestEvent("cline", "")
	softEv.ToolUsage = BudgetWindowAmounts{DailyUSD: 6}
	v := eng.Evaluate(softEv)
	if v.RuleID != "B-626" || v.Decision != DecisionFlag {
		t.Fatalf("a SOFT cap did not flag on a flag-only baseline: %s / %s", v.RuleID, v.Decision)
	}
	if !strings.Contains(v.Reason, "other machines") {
		t.Errorf("reason %q does not name the baseline it counted", v.Reason)
	}
	// The hard cap still denies on LOCAL spend alone — withholding the baseline
	// is not disarming the cap.
	hardEv.ToolUsage = BudgetWindowAmounts{DailyUSD: 10}
	if v := eng.Evaluate(hardEv); v.RuleID != "B-626" || v.Decision != DecisionDeny {
		t.Fatalf("hard cap did not deny on local spend at the limit: %s / %s", v.RuleID, v.Decision)
	}
}

// TestSubjectBudgetRules_ResolvedIdentityMatches is the P1-3 alias pair: the org
// composed the cap onto the family key and the event carries the dated model, so
// they match only because the guard stamped the resolved id beside it.
func TestSubjectBudgetRules_ResolvedIdentityMatches(t *testing.T) {
	t.Parallel()
	eng, err := New(Config{Mode: ModeEnforce, BudgetSubjectCaps: []BudgetSubjectCap{
		{
			Kind: BudgetSubjectKindModel, ID: "claude-sonnet-5", Window: BudgetWindowDaily,
			CapUSD: 2, Hard: true,
		},
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// The pre-fix shape: the raw dated id alone never equals the family cap.
	raw := subjectTestEvent("", "claude-sonnet-5-20260501")
	raw.ModelUsage = BudgetWindowAmounts{DailyUSD: 9}
	if v := eng.Evaluate(raw); v.RuleID == "B-628" {
		t.Errorf("an unresolved dated id matched a family cap by accident: %s", v.Reason)
	}
	// With the resolved id stamped, the same event is the same subject.
	resolved := raw
	resolved.ModelSubjectID = "Claude-Sonnet-5" // normalized here, as any stamp is
	v := eng.Evaluate(resolved)
	if v.RuleID != "B-628" || v.Decision != DecisionDeny {
		t.Fatalf("resolved identity did not match the cap: %s / %s", v.RuleID, v.Decision)
	}
	if !strings.Contains(v.Reason, "claude-sonnet-5") {
		t.Errorf("reason %q does not name the cap that bit", v.Reason)
	}
}

// TestSubjectBudgetRules_DisableReachesTheSoftRowOnly is the P2-5 fix: protection
// is per (rule id, HARD). A local `[guard.rules] disable` must still not remove
// the org's hard deny row, and must no longer be ignored for the flag row of a
// cap the admin authored soft.
func TestSubjectBudgetRules_DisableReachesTheSoftRowOnly(t *testing.T) {
	t.Parallel()
	cfg := Config{
		Mode:     ModeEnforce,
		Disabled: []string{"B-626"},
		// Protection is per kind+unit: the org holds tool-USD authority.
		BudgetProtection: BudgetProtection{ToolUSD: true},
		BudgetSubjectCaps: []BudgetSubjectCap{
			{Kind: BudgetSubjectKindTool, ID: "codex", Window: BudgetWindowDaily, CapUSD: 2, Hard: true},
			{Kind: BudgetSubjectKindTool, ID: "cline", Window: BudgetWindowDaily, CapUSD: 2},
		},
	}
	eng, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	hardEv := subjectTestEvent("codex", "")
	hardEv.ToolUsage = BudgetWindowAmounts{DailyUSD: 9}
	if v := eng.Evaluate(hardEv); v.RuleID != "B-626" || v.Decision != DecisionDeny {
		t.Fatalf("a local disable removed the org's HARD subject row: %s / %s", v.RuleID, v.Decision)
	}
	softEv := subjectTestEvent("cline", "")
	softEv.ToolUsage = BudgetWindowAmounts{DailyUSD: 9}
	if v := eng.Evaluate(softEv); v.RuleID == "B-626" {
		t.Errorf("a local disable was ignored for the SOFT row of a soft cap: %s", v.Reason)
	}
	// And the soft row carries no protection, so a local override may weaken it
	// while the hard row stays untouchable.
	if eng.BudgetRuleProtected("B-626") != true {
		t.Errorf("BudgetRuleProtected(B-626) = false; the surviving hard row is still protected")
	}
}
