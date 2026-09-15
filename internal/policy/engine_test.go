package policy

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// testEngine builds an engine with deterministic test config.
func testEngine(t *testing.T, mode Mode) *Engine {
	t.Helper()
	eng, err := New(Config{Mode: mode, Home: "/home/u"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return eng
}

// shellEvent builds a shell_exec event rooted in the standard test
// project.
func shellEvent(cmd string) Event {
	return Event{
		Kind:        KindShellExec,
		ActionType:  "run_command",
		Target:      cmd,
		Cwd:         "/home/u/proj",
		ProjectRoot: "/home/u/proj",
		SessionID:   "s1",
		Now:         time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
	}
}

// TestNew_DefaultsAndValidation pins construction behavior.
func TestNew_DefaultsAndValidation(t *testing.T) {
	t.Parallel()

	eng, err := New(Config{})
	if err != nil {
		t.Fatalf("New(zero): %v", err)
	}
	if eng.Mode() != ModeObserve {
		t.Errorf("default mode = %q, want observe (D2)", eng.Mode())
	}
	if eng.RuleCount() == 0 {
		t.Error("no rules loaded")
	}

	if _, err := New(Config{Mode: "bogus"}); err == nil {
		t.Error("unknown mode must error")
	}

	// Disabled filtering removes rows.
	all := testEngine(t, ModeObserve).RuleCount()
	less, err := New(Config{Disabled: []string{"R-152"}})
	if err != nil {
		t.Fatalf("New(disabled): %v", err)
	}
	if less.RuleCount() >= all {
		t.Errorf("disabling R-152 did not shrink the table: %d vs %d", less.RuleCount(), all)
	}
}

// TestValidateRules pins every construction-time table check.
func TestValidateRules(t *testing.T) {
	t.Parallel()
	match := func(*MatchContext) (bool, string) { return false, "" }
	base := Rule{
		ID: "T-1", Category: CategoryDestructive, Severity: SeverityHigh,
		AppliesTo: []EventKind{KindShellExec}, Match: match,
		Observe: DecisionFlag, Enforce: DecisionAsk, Doc: "test rule",
	}
	cases := []struct {
		name   string
		mutate func(r *Rule)
	}{
		{"empty ID", func(r *Rule) { r.ID = "" }},
		{"empty category", func(r *Rule) { r.Category = "" }},
		{"empty doc", func(r *Rule) { r.Doc = "" }},
		{"empty applies-to", func(r *Rule) { r.AppliesTo = nil }},
		{"no matcher", func(r *Rule) { r.Match = nil }},
		{"both matchers", func(r *Rule) { r.MatchCmd = func(*MatchContext, *Command) (bool, string) { return false, "" } }},
		{"enforce weaker than observe", func(r *Rule) { r.Observe = DecisionDeny; r.Enforce = DecisionFlag }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := base
			tc.mutate(&r)
			if err := validateRules([]Rule{r}); err == nil {
				t.Error("want validation error, got nil")
			}
		})
	}

	t.Run("same-ID rows must agree", func(t *testing.T) {
		t.Parallel()
		a, b := base, base
		b.Severity = SeverityCritical
		if err := validateRules([]Rule{a, b}); err == nil {
			t.Error("mismatched same-ID severity must error")
		}
		b = base // consistent duplicate is fine (approved deviation 3)
		if err := validateRules([]Rule{a, b}); err != nil {
			t.Errorf("consistent same-ID rows must validate: %v", err)
		}
	})

	t.Run("shipped tables validate", func(t *testing.T) {
		t.Parallel()
		if err := validateRules(builtinRules()); err != nil {
			t.Errorf("builtin tables invalid: %v", err)
		}
	})
}

// TestEvaluate_Modes pins the off/observe/enforce decision selection
// on one rule (R-101).
func TestEvaluate_Modes(t *testing.T) {
	t.Parallel()
	ev := shellEvent("rm -rf /")

	if v := testEngine(t, ModeOff).Evaluate(ev); v.Decision != DecisionAllow || v.RuleID != "" {
		t.Errorf("off mode: %+v", v)
	}
	if v := testEngine(t, ModeObserve).Evaluate(ev); v.Decision != DecisionFlag || v.RuleID != "R-101" {
		t.Errorf("observe mode: %+v", v)
	}
	if v := testEngine(t, ModeEnforce).Evaluate(ev); v.Decision != DecisionDeny || v.RuleID != "R-101" {
		t.Errorf("enforce mode: %+v", v)
	}
}

// TestEvaluate_VerdictShape pins Reason/Advice/Source/Severity
// population.
func TestEvaluate_VerdictShape(t *testing.T) {
	t.Parallel()
	v := testEngine(t, ModeEnforce).Evaluate(shellEvent("git push --force origin main"))
	if v.RuleID != "R-110" || v.Decision != DecisionDeny || v.Severity != SeverityCritical {
		t.Fatalf("verdict = %+v", v)
	}
	if v.Source != SourceBuiltin {
		t.Errorf("source = %q", v.Source)
	}
	if v.Reason == "" || v.Advice == "" {
		t.Errorf("reason/advice empty: %+v", v)
	}
	if !strings.Contains(v.Reason, "main") {
		t.Errorf("reason should name the branch: %q", v.Reason)
	}
	if !strings.Contains(v.Advice, "--force-with-lease") {
		t.Errorf("advice should offer the safe variant: %q", v.Advice)
	}
}

// TestEvaluate_WinnerSelection pins multi-hit resolution: strictest
// decision first, then severity, then table order.
func TestEvaluate_WinnerSelection(t *testing.T) {
	t.Parallel()

	t.Run("severity breaks flag ties", func(t *testing.T) {
		t.Parallel()
		// Observe mode: R-104 (high) and R-142 (critical) both Flag;
		// the later-table critical row must win.
		v := testEngine(t, ModeObserve).Evaluate(shellEvent("git clean -f && mkfs.ext4 /dev/sda1"))
		if v.RuleID != "R-142" || v.Severity != SeverityCritical {
			t.Errorf("verdict = %+v, want R-142 critical", v)
		}
	})

	t.Run("decision outranks severity", func(t *testing.T) {
		t.Parallel()
		// Enforce mode: R-130 asks (critical), R-101 denies
		// (critical) — deny wins.
		v := testEngine(t, ModeEnforce).Evaluate(shellEvent("terraform destroy && rm -rf /"))
		if v.RuleID != "R-101" || v.Decision != DecisionDeny {
			t.Errorf("verdict = %+v, want R-101 deny", v)
		}
	})

	t.Run("full tie keeps earlier row", func(t *testing.T) {
		t.Parallel()
		// Enforce: R-120 and R-142 are both deny/critical; R-120 is
		// the earlier table row.
		v := testEngine(t, ModeEnforce).Evaluate(shellEvent(`psql -c "DROP TABLE x" && diskpart`))
		if v.RuleID != "R-120" {
			t.Errorf("verdict = %+v, want R-120 (earlier row)", v)
		}
	})
}

// TestEvaluate_NoHit pins the allow verdict shape for benign events
// and unevaluated kinds.
func TestEvaluate_NoHit(t *testing.T) {
	t.Parallel()
	eng := testEngine(t, ModeEnforce)
	for _, cmd := range []string{"go test ./...", "ls -la", "git status", "make build"} {
		if v := eng.Evaluate(shellEvent(cmd)); v.Decision != DecisionAllow || v.RuleID != "" {
			t.Errorf("%q: %+v", cmd, v)
		}
	}
	if v := eng.Evaluate(Event{Kind: KindMCPCall, Target: "rm -rf /"}); v.Decision != DecisionAllow {
		t.Errorf("mcp_call has no G1 rules: %+v", v)
	}
	if v := eng.Evaluate(Event{}); v.Decision != DecisionAllow {
		t.Errorf("zero event: %+v", v)
	}
}

// TestEvaluate_DisabledRule pins [guard.rules].disable semantics.
func TestEvaluate_DisabledRule(t *testing.T) {
	t.Parallel()
	eng, err := New(Config{Mode: ModeEnforce, Home: "/home/u", Disabled: []string{"R-101"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if v := eng.Evaluate(shellEvent("rm -rf /etc/nginx")); v.RuleID != "" {
		t.Errorf("disabled rule still fired: %+v", v)
	}
}

// TestManagedBudgetProtection pins the policy engine's trust boundary: rows
// that came from an organization-authoritative hard budget survive local
// disables and weakening overrides. The internal soft-window override remains
// able to preserve the administrator's advisory decision.
func TestManagedBudgetProtection(t *testing.T) {
	t.Parallel()
	flag := DecisionFlag
	allow := DecisionAllow

	t.Run("hard cost and token rows survive local policy", func(t *testing.T) {
		t.Parallel()
		eng, err := New(Config{
			Mode: ModeEnforce, BudgetHard: true,
			BudgetProtection: BudgetProtection{DailyUSD: true, DailyTokens: true},
			BudgetDailyUSD:   1, BudgetDailyTokens: 100,
			Disabled:  []string{"B-602"},
			Overrides: []Override{{RuleID: "B-622", Decision: &allow, Source: "user"}},
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		for _, tc := range []struct {
			name string
			ev   Event
			id   string
		}{
			{name: "disabled cost row", ev: Event{Kind: KindAPIRequest, DailyCostUSD: 2}, id: "B-602"},
			{name: "overridden token row", ev: Event{Kind: KindAPIRequest, DailyTokens: 101}, id: "B-622"},
		} {
			v := eng.Evaluate(tc.ev)
			if v.RuleID != tc.id || v.Decision != DecisionDeny {
				t.Errorf("%s = %s/%s, want %s/deny", tc.name, v.RuleID, v.Decision, tc.id)
			}
			if !eng.BudgetRuleProtected(tc.id) {
				t.Errorf("%s is not reported as protected", tc.id)
			}
		}
	})

	t.Run("armed B-625 survives local policy", func(t *testing.T) {
		t.Parallel()
		eng, err := New(Config{
			Mode: ModeEnforce, BudgetRequired: true,
			Disabled:  []string{"B-625"},
			Overrides: []Override{{RuleID: "B-625", Decision: &allow, Source: "user"}},
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		v := eng.Evaluate(Event{Kind: KindAPIRequest})
		if v.RuleID != "B-625" || v.Decision != DecisionDeny {
			t.Fatalf("B-625 = %s/%s, want B-625/deny", v.RuleID, v.Decision)
		}
		if !eng.BudgetRuleProtected("B-625") {
			t.Error("armed B-625 is not reported as protected")
		}
	})

	t.Run("organization soft window stays advisory", func(t *testing.T) {
		t.Parallel()
		eng, err := New(Config{
			Mode:              ModeEnforce,
			BudgetHard:        true,
			BudgetDailyTokens: 100,
			Overrides:         []Override{{RuleID: "B-622", Decision: &flag, Source: SourceOrgBudget}},
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		v := eng.Evaluate(Event{Kind: KindAPIRequest, DailyTokens: 101})
		if v.RuleID != "B-622" || v.Decision != DecisionFlag {
			t.Fatalf("soft B-622 = %s/%s, want B-622/flag", v.RuleID, v.Decision)
		}
		if eng.BudgetRuleProtected("B-622") {
			t.Error("an organization-authored soft row must remain approval/advisory behavior")
		}
	})

	t.Run("local hard budget remains customizable", func(t *testing.T) {
		t.Parallel()
		eng, err := New(Config{
			Mode: ModeEnforce, BudgetHard: true, BudgetDailyTokens: 100,
			Overrides: []Override{{RuleID: "B-622", Decision: &flag, Source: "user"}},
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		v := eng.Evaluate(Event{Kind: KindAPIRequest, DailyTokens: 101})
		if v.RuleID != "B-622" || v.Decision != DecisionFlag {
			t.Fatalf("local B-622 = %s/%s, want B-622/flag", v.RuleID, v.Decision)
		}
		if eng.BudgetRuleProtected("B-622") {
			t.Error("a local hard budget must not be reported as organization-protected")
		}
	})
}

// TestEvaluate_ConcurrencySafe hammers one engine from many
// goroutines; the race detector (gates run with -race) pins the
// immutability claim.
func TestEvaluate_ConcurrencySafe(t *testing.T) {
	t.Parallel()
	eng := testEngine(t, ModeEnforce)
	events := []Event{
		shellEvent("rm -rf /"),
		shellEvent("go build ./..."),
		{Kind: KindFileAccess, ActionType: "read_file", Target: "~/.ssh/id_rsa", ProjectRoot: "/home/u/proj"},
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				for _, ev := range events {
					_ = eng.Evaluate(ev)
				}
			}
		}()
	}
	wg.Wait()
}

// TestParsers pins the string round trips for the config-facing
// enums.
func TestParsers(t *testing.T) {
	t.Parallel()
	for _, d := range []Decision{DecisionAllow, DecisionFlag, DecisionAsk, DecisionDeny} {
		got, err := ParseDecision(d.String())
		if err != nil || got != d {
			t.Errorf("decision round trip %v: %v/%v", d, got, err)
		}
	}
	if _, err := ParseDecision("nope"); err == nil {
		t.Error("unknown decision must error")
	}
	for _, s := range []Severity{SeverityInfo, SeverityWarn, SeverityHigh, SeverityCritical} {
		got, err := ParseSeverity(s.String())
		if err != nil || got != s {
			t.Errorf("severity round trip %v: %v/%v", s, got, err)
		}
	}
	if _, err := ParseSeverity("nope"); err == nil {
		t.Error("unknown severity must error")
	}
	for _, m := range []Mode{ModeOff, ModeObserve, ModeEnforce} {
		got, err := ParseMode(string(m))
		if err != nil || got != m {
			t.Errorf("mode round trip %v: %v/%v", m, got, err)
		}
	}
	if _, err := ParseMode("nope"); err == nil {
		t.Error("unknown mode must error")
	}
	if StricterOf(DecisionFlag, DecisionDeny) != DecisionDeny || StricterOf(DecisionAsk, DecisionFlag) != DecisionAsk {
		t.Error("StricterOf ordering wrong")
	}
}

// TestTaintState pins the (G1-minimal) taint snapshot type.
func TestTaintState(t *testing.T) {
	t.Parallel()
	var ts TaintState
	if ts.Tainted() {
		t.Error("zero TaintState must be untainted")
	}
	ts.Marks = append(ts.Marks, TaintMark{Source: "web_fetch", Origin: "example.com", Turn: 3})
	if !ts.Tainted() {
		t.Error("marked TaintState must be tainted")
	}
}
