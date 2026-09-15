package guard

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

func TestInterventionBudgetUsesFreshManagedDecision(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		protected  bool
		soft       bool
		source     bool
		lookup     bool
		sessionCap bool
		wantDeny   bool
	}{
		{"exhausted managed daily", true, false, true, true, false, true},
		{"unknown native source", true, false, false, true, false, true},
		{"accounting lookup failed", true, false, true, false, false, true},
		{"session identity missing", true, false, true, true, true, true},
		{"individual budget has no intervention authority", false, false, true, true, false, false},
		{"org soft window stays advisory", true, true, true, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := guardCfg()
			cfg.Mode = "enforce"
			g := newTestGuard(t, cfg, nil)
			eff := config.GuardBudgetConfig{DailyUSD: 0.35, Hard: true}
			if tc.sessionCap {
				eff = config.GuardBudgetConfig{SessionUSD: 0.35, Hard: true}
			}
			var soft []string
			if tc.soft {
				soft = []string{"daily"}
			}
			protection := policy.BudgetProtection{}
			if tc.protected && tc.sessionCap {
				protection.SessionUSD = true
			}
			if tc.protected && !tc.sessionCap && !tc.soft {
				protection.DailyUSD = true
			}
			if err := g.ApplyOrgBudget(eff, soft, false, protection, ""); err != nil {
				t.Fatal(err)
			}
			spend, calls := 0.34, 0
			g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) {
				calls++
				return BudgetSnapshot{DailyUSD: spend}, tc.lookup
			})
			in := InterventionBudgetInput{SourceReady: true, Now: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)}
			if tc.lookup && !tc.sessionCap {
				if first := g.CheckInterventionBudget(in); first.Deny {
					t.Fatalf("under-cap decision denied: %+v", first)
				}
			}
			spend, in.SourceReady = 0.35, tc.source
			got := g.CheckInterventionBudget(in)
			if got.Deny != tc.wantDeny {
				t.Fatalf("decision = %+v, want deny=%v", got, tc.wantDeny)
			}
			if tc.name == "exhausted managed daily" && (calls != 2 || got.RuleID != "B-602") {
				t.Fatalf("freshness/shared rule: calls=%d decision=%+v", calls, got)
			}
		})
	}
}

func TestInterventionBudgetDecisionExpiresAtAccountingWindowBoundary(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)
	weeklyExpiry := time.Date(2026, 9, 16, 5, 0, 0, 0, time.UTC)
	g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) {
		return BudgetSnapshot{
			DailyUSD: 1, MonthlyTokens: 10, WeeklyUSD: 1,
			WeeklyUSDExpiresAt: weeklyExpiry,
		}, true
	})

	losAngeles := BudgetCalendars{DailyTimezone: "America/Los_Angeles", MonthlyTimezone: "Asia/Calcutta"}
	apply := func(budget config.GuardBudgetConfig, protection policy.BudgetProtection) {
		t.Helper()
		if err := g.ApplyOrgBudgetWithWitness(budget, nil, false, protection, "binding",
			BudgetDocumentWitness{Known: true}, losAngeles); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 9, 15, 6, 59, 59, 0, time.UTC) // 23:59:59 Sep 14 in Los Angeles.
	in := InterventionBudgetInput{SourceReady: true, Now: now, BudgetBinding: "binding"}

	apply(config.GuardBudgetConfig{DailyUSD: 1, Hard: true}, policy.BudgetProtection{DailyUSD: true})
	if got := g.CheckInterventionBudget(in); !got.Deny || got.RuleID != "B-602" ||
		!got.ValidUntil.Equal(time.Date(2026, 9, 15, 7, 0, 0, 0, time.UTC)) {
		t.Fatalf("daily horizon=%+v", got)
	}

	// 18:29:59 UTC is 23:59:59 on Sep 30 in Asia/Calcutta.
	in.Now = time.Date(2026, 9, 30, 18, 29, 59, 0, time.UTC)
	apply(config.GuardBudgetConfig{MonthlyTokens: 10, Hard: true}, policy.BudgetProtection{MonthlyTokens: true})
	if got := g.CheckInterventionBudget(in); !got.Deny || got.RuleID != "B-623" ||
		!got.ValidUntil.Equal(time.Date(2026, 9, 30, 18, 30, 0, 0, time.UTC)) {
		t.Fatalf("monthly horizon=%+v", got)
	}

	// Rolling aggregates expire when their earliest included row ages out.
	in.Now = now
	apply(config.GuardBudgetConfig{WeeklyUSD: 1, Hard: true}, policy.BudgetProtection{WeeklyUSD: true})
	if got := g.CheckInterventionBudget(in); !got.Deny || got.RuleID != "B-604" || !got.ValidUntil.Equal(weeklyExpiry) {
		t.Fatalf("rolling horizon=%+v", got)
	}

	// A deny caused by missing weekly accounting remains a deny after row or
	// calendar expiry, so it uses the authority horizon rather than pretending
	// that a clock boundary restores evidence.
	in.SourceReady = false
	if got := g.CheckInterventionBudget(in); !got.Deny || got.RuleID != "B-604" || !got.ValidUntil.IsZero() || got.PricingDocumentRequired {
		t.Fatalf("unavailable rolling evidence horizon=%+v", got)
	}

	// A successful source/read can still report an unknown rate. That is an
	// accounting-unavailable policy denial, not a measured dollar breach, and
	// it must not require price-document authority it did not consume.
	g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) {
		return BudgetSnapshot{USDUnavailable: policy.BudgetUnavailableWindows{Weekly: true}}, true
	})
	in.SourceReady = true
	if got := g.CheckInterventionBudget(in); !got.Deny || got.RuleID != "B-604" || got.PricingDocumentRequired || !got.ValidUntil.IsZero() {
		t.Fatalf("unknown-rate evidence=%+v", got)
	}
}

func TestInterventionBudgetUnavailableGuardDoesNotAdmit(t *testing.T) {
	t.Parallel()
	var g *Guard
	if got := g.CheckInterventionBudget(InterventionBudgetInput{}); !got.Deny {
		t.Fatal("missing guard admitted")
	}
}

func TestInterventionBudgetIgnoresExhaustedLocalSibling(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)
	eff := config.GuardBudgetConfig{
		SessionUSD: 0.35, MonthlyTokens: 100, Hard: true,
	}
	if err := g.ApplyOrgBudget(eff, nil, false,
		policy.BudgetProtection{MonthlyTokens: true}, ""); err != nil {
		t.Fatal(err)
	}

	snapshot := BudgetSnapshot{SessionUSD: 0.36, MonthlyTokens: 99}
	g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) { return snapshot, true })
	in := InterventionBudgetInput{
		SessionID: "session-1", SourceReady: true,
		Now: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC),
	}
	if got := g.CheckInterventionBudget(in); !got.Available || !got.Required || got.Deny {
		t.Fatalf("exhausted local session cap authorized a managed stop: %+v", got)
	}

	snapshot.MonthlyTokens = 100
	if got := g.CheckInterventionBudget(in); !got.Deny || got.RuleID != "B-623" {
		t.Fatalf("exhausted managed monthly cap = %+v, want B-623 stop", got)
	}
}

func TestInterventionBudgetBindingIsSealedWithEngineSnapshot(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)
	g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) {
		return BudgetSnapshot{DailyUSD: 1}, true
	})

	oldBudget := config.GuardBudgetConfig{DailyUSD: 1, Hard: true}
	if err := g.ApplyOrgBudget(oldBudget, nil, false,
		policy.BudgetProtection{DailyUSD: true}, "member-one"); err != nil {
		t.Fatal(err)
	}
	oldSnapshot := g.set.Load()

	newBudget := config.GuardBudgetConfig{DailyUSD: 2, Hard: true}
	if err := g.ApplyOrgBudget(newBudget, nil, false,
		policy.BudgetProtection{DailyUSD: true}, "member-two"); err != nil {
		t.Fatal(err)
	}
	in := InterventionBudgetInput{
		SourceReady: true,
		Now:         time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC),
	}

	in.BudgetBinding = "member-two"
	if got := g.checkInterventionBudgetWith(oldSnapshot, in); !got.Deny || got.RuleID != "B-625" {
		t.Fatalf("new identity paired with old numeric snapshot: %+v", got)
	}
	in.BudgetBinding = "member-one"
	if got := g.checkInterventionBudgetWith(oldSnapshot, in); !got.Deny || got.RuleID != "B-602" {
		t.Fatalf("old coherent snapshot = %+v, want its protected B-602", got)
	}
	if got := g.CheckInterventionBudget(in); !got.Deny || got.RuleID != "B-625" {
		t.Fatalf("old identity paired with new live snapshot: %+v", got)
	}
}

func TestInterventionBudgetBindingMismatchPrecedesExplicitNone(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)
	if err := g.ApplyOrgBudget(config.GuardBudgetConfig{}, nil, false,
		policy.BudgetProtection{}, "member-one"); err != nil {
		t.Fatal(err)
	}
	got := g.CheckInterventionBudget(InterventionBudgetInput{
		BudgetBinding: "member-two", SourceReady: true,
		Now: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC),
	})
	if !got.Available || !got.Required || !got.Deny || got.RuleID != "B-625" {
		t.Fatalf("stale explicit-none snapshot admitted current member: %+v", got)
	}
}

// TestInterventionBudgetScopesUnavailableAccountingToItsTool pins what a
// tool-scoped accounting failure may and may not do.
//
// REVERSED 2026-09-15 (ruling A2). The row this test used to lead with - a
// tool whose model no exact or org rate could price - is now ALLOWED, because
// the accounting prices it through the same fallback ladder the node's own
// dashboard uses and counts it against the cap. Stopping a developer's process
// over an unquoted model was the live defect: Muse and OpenCode were TERMed at
// "$0.26 of $2" while the dashboard priced the day at $0.97.
//
// What survives is the ONE failure that really does make a tool's spend
// unknowable rather than merely estimated: a broken capture SOURCE. That still
// denies, and still names the tool.
func TestInterventionBudgetScopesUnavailableAccountingToItsTool(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name        string
		tool        string
		sourceReady bool
		sourceWhy   string
		wantDeny    bool
		wantDetail  string
	}{
		// The reversal itself: a fallback-priced tool, under cap, RUNS.
		{"tool priced by a fallback rate", "muse", true, "", false, ""},
		{"tool priced under the same cap", "opencode", true, "", false, ""},
		{"unattributed decision keeps node-wide windows", "", true, "", false, ""},
		{"tool with a broken source", "muse", false, "parse_error", true, "accounting source unavailable for muse: parse_error"},
		{"healthy tool with a broken source", "opencode", false, "scan_canceled", true, "accounting source unavailable for opencode: scan_canceled"},
		{"broken source without a named tool", "", false, "", true, "accounting source unavailable for unknown tool: unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := guardCfg()
			cfg.Mode = "enforce"
			g := newTestGuard(t, cfg, nil)
			if err := g.ApplyOrgBudget(config.GuardBudgetConfig{DailyUSD: 0.35, Hard: true}, nil, false,
				policy.BudgetProtection{DailyUSD: true}, ""); err != nil {
				t.Fatal(err)
			}
			// $0.10 of a $0.35 cap, with NO unavailable window: the
			// accounting priced every row it read, some of them through a
			// fallback rung. There is no per-tool unavailability input left to
			// supply - the field that carried it is gone.
			g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) {
				return BudgetSnapshot{DailyUSD: 0.10}, true
			})
			got := g.CheckInterventionBudget(InterventionBudgetInput{
				Tool: tc.tool, SourceReady: tc.sourceReady, SourceReason: tc.sourceWhy, Now: now,
			})
			if got.Deny != tc.wantDeny {
				t.Fatalf("decision = %+v, want deny=%v", got, tc.wantDeny)
			}
			if !tc.wantDeny {
				return
			}
			if got.RuleID != "B-602" {
				t.Fatalf("rule = %q, want the protected daily row", got.RuleID)
			}
			if !strings.Contains(got.Reason, tc.wantDetail) {
				t.Fatalf("reason = %q, want it to name %q", got.Reason, tc.wantDetail)
			}
			if !strings.Contains(got.Reason, "accounting is unavailable") {
				t.Fatalf("reason = %q, want the rule's own unavailable wording retained", got.Reason)
			}
			if got.PricingDocumentRequired {
				t.Fatalf("unavailable-accounting denial demanded price authority: %+v", got)
			}
		})
	}
}

// TestInterventionBudgetToolScopeNeverWidensAMeasuredBreach keeps the
// tool-scoped windows additive: they can only add unavailability, never
// suppress a measured over-cap denial for an unrelated tool.
func TestInterventionBudgetToolScopeNeverWidensAMeasuredBreach(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)
	if err := g.ApplyOrgBudget(config.GuardBudgetConfig{DailyUSD: 0.35, Hard: true}, nil, false,
		policy.BudgetProtection{DailyUSD: true}, ""); err != nil {
		t.Fatal(err)
	}
	g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) {
		return BudgetSnapshot{DailyUSD: 0.40}, true
	})
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	got := g.CheckInterventionBudget(InterventionBudgetInput{Tool: "opencode", SourceReady: true, Now: now})
	if !got.Deny || got.RuleID != "B-602" {
		t.Fatalf("exhausted cap = %+v, want a measured B-602 stop", got)
	}
	if strings.Contains(got.Reason, "unpriced usage") {
		t.Fatalf("measured breach reported as unavailable accounting: %q", got.Reason)
	}
	if !got.PricingDocumentRequired {
		t.Fatalf("measured dollar denial dropped its price-authority requirement: %+v", got)
	}
}
