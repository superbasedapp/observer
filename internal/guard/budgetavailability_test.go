package guard

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

func TestProxyBudgetUnavailableAccounting(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		budget   config.GuardBudgetConfig
		lookup   BudgetLookup
		soft     []string
		wantRule string
		wantDeny bool
	}{
		{
			name: "failed USD read", budget: config.GuardBudgetConfig{DailyUSD: 0.35, Hard: true},
			lookup:   func(string) (BudgetSnapshot, bool) { return BudgetSnapshot{}, false },
			wantRule: "B-602", wantDeny: true,
		},
		{
			name: "missing lookup", budget: config.GuardBudgetConfig{DailyTokens: 10, Hard: true},
			wantRule: "B-622", wantDeny: true,
		},
		{
			name: "unpriced daily usage", budget: config.GuardBudgetConfig{DailyUSD: 0.35, Hard: true},
			lookup: func(string) (BudgetSnapshot, bool) {
				return BudgetSnapshot{USDUnavailable: policy.BudgetUnavailableWindows{Daily: true}}, true
			}, wantRule: "B-602", wantDeny: true,
		},
		{
			name: "token cap needs no price", budget: config.GuardBudgetConfig{DailyTokens: 10, Hard: true},
			lookup: func(string) (BudgetSnapshot, bool) {
				return BudgetSnapshot{DailyTokens: 9, USDUnavailable: policy.BudgetUnavailableWindows{Daily: true}}, true
			},
		},
		{
			name: "unknown previous month irrelevant to daily cap", budget: config.GuardBudgetConfig{DailyUSD: 0.35, Hard: true},
			lookup: func(string) (BudgetSnapshot, bool) {
				return BudgetSnapshot{DailyUSD: 0.1, USDUnavailable: policy.BudgetUnavailableWindows{Monthly: true}}, true
			},
		},
		{
			name: "measured zero admitted", budget: config.GuardBudgetConfig{DailyUSD: 0.35, Hard: true},
			lookup: func(string) (BudgetSnapshot, bool) { return BudgetSnapshot{}, true },
		},
		{
			name: "no cap admitted", lookup: func(string) (BudgetSnapshot, bool) { return BudgetSnapshot{}, false },
		},
		{
			name: "soft window stays advisory", budget: config.GuardBudgetConfig{DailyUSD: 0.35, MonthlyUSD: 50, Hard: true},
			lookup: func(string) (BudgetSnapshot, bool) {
				return BudgetSnapshot{USDUnavailable: policy.BudgetUnavailableWindows{Daily: true}}, true
			}, soft: []string{"daily"}, wantRule: "B-602",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := guardCfg()
			cfg.Mode = "enforce"
			cfg.Budget = tc.budget
			g := newTestGuard(t, cfg, nil)
			g.SetBudgetLookup(tc.lookup)
			if err := g.ApplyOrgBudget(tc.budget, tc.soft, false, policy.BudgetProtection{}, ""); err != nil {
				t.Fatal(err)
			}
			// No session identity is still subject to node-wide windows.
			res := g.ScanProxyRequest("openai", []byte(`{"model":"test","messages":[]}`), "", time.Now().UTC())
			if res.Deny != tc.wantDeny {
				t.Fatalf("deny = %v, want %v: %+v", res.Deny, tc.wantDeny, res)
			}
			if tc.wantRule == "" {
				if len(res.Verdicts) != 0 {
					t.Fatalf("unexpected verdicts: %+v", res.Verdicts)
				}
				return
			}
			if len(res.Verdicts) != 1 || res.Verdicts[0].Verdict.RuleID != tc.wantRule ||
				!strings.Contains(res.Verdicts[0].Verdict.Reason, "accounting is unavailable") {
				t.Fatalf("unavailable accounting verdict = %+v", res)
			}
		})
	}
}

func TestProxyBudgetLookupFailureAfterTTL(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	cfg.Budget = config.GuardBudgetConfig{DailyUSD: 0.35, Hard: true}
	g := newTestGuard(t, cfg, nil)
	ok := true
	g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) {
		return BudgetSnapshot{DailyUSD: 0.1}, ok
	})
	now := time.Now().UTC()
	body := []byte(`{"model":"test","messages":[]}`)
	if res := g.ScanProxyRequest("openai", body, "session", now); res.Deny {
		t.Fatalf("under cap denied: %+v", res)
	}
	ok = false
	res := g.ScanProxyRequest("openai", body, "session", now.Add(budgetCacheTTL+time.Second))
	if !res.Deny || !strings.Contains(res.DenyReason, "accounting is unavailable") {
		t.Fatalf("stale successful lookup masked the error: %+v", res)
	}
}
