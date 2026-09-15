package guard

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

func TestManagedBudgetUsesAccountingModeFromDecisionSnapshot(t *testing.T) {
	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)
	old := g.set.Load()
	if err := g.ApplyOrgBudget(config.GuardBudgetConfig{DailyUSD: 0.35, Hard: true}, nil, false, policy.BudgetProtection{DailyUSD: true}, "binding"); err != nil {
		t.Fatal(err)
	}
	managed := g.set.Load()
	var modes []bool
	g.SetBudgetAccountingLookup(func(_ string, accounting BudgetAccountingContext) (BudgetSnapshot, bool) {
		modes = append(modes, accounting.Managed)
		if accounting.Managed {
			return BudgetSnapshot{USDUnavailable: policy.BudgetUnavailableWindows{Daily: true}}, true
		}
		return BudgetSnapshot{}, true
	})
	// Publish removal after an in-flight decision loaded the hard policy.
	g.set.Store(old)
	got := g.checkInterventionBudgetWith(managed, InterventionBudgetInput{SourceReady: true, Now: time.Now(), BudgetBinding: "binding"})
	if !got.Deny || len(modes) != 1 || !modes[0] {
		t.Fatalf("snapshot lost managed evidence requirement: %+v modes=%v", got, modes)
	}
	var proxy ProxyRequestResult
	g.scanBudget(managed, &proxy, "", "fixture", time.Now())
	// No binding read was installed, so proxy must refuse even before pricing.
	if !proxy.Deny {
		t.Fatal("proxy admitted absent binding")
	}
	g.SetBudgetBindingLookup(func() (string, bool) { return "binding", true })
	proxy = ProxyRequestResult{}
	g.scanBudget(managed, &proxy, "", "fixture", time.Now())
	if !proxy.Deny || len(modes) != 2 || !modes[1] {
		t.Fatalf("proxy used weaker accounting: %+v modes=%v", proxy, modes)
	}
}

func TestBudgetAccountingCacheSeparatesEvidenceModes(t *testing.T) {
	g := newTestGuard(t, guardCfg(), nil)
	calls := 0
	g.SetBudgetAccountingLookup(func(_ string, accounting BudgetAccountingContext) (BudgetSnapshot, bool) {
		calls++
		return BudgetSnapshot{USDUnavailable: policy.BudgetUnavailableWindows{Daily: accounting.Managed}}, true
	})
	ev := policy.Event{Kind: policy.KindAPIRequest, Now: time.Now()}
	g.stampBudgetAccounting(&ev, false, false)
	g.stampBudgetAccounting(&ev, false, true)
	if calls != 2 || !ev.USDUnavailable.Daily {
		t.Fatalf("advisory cache reused for managed cap: calls=%d event=%+v", calls, ev)
	}
}

func TestBudgetAccountingCalendarsRemainWithInflightCap(t *testing.T) {
	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)
	cap := config.GuardBudgetConfig{DailyUSD: 0.35, Hard: true}
	protected := policy.BudgetProtection{DailyUSD: true}
	la := BudgetCalendars{DailyTimezone: "America/Los_Angeles", MonthlyTimezone: "UTC"}
	if err := g.ApplyOrgBudget(cap, nil, false, protected, "binding", la); err != nil {
		t.Fatal(err)
	}
	old := g.set.Load()
	if err := g.ApplyOrgBudget(cap, nil, false, protected, "binding", BudgetCalendars{}); err != nil {
		t.Fatal(err)
	}
	if g.set.Load().revision == old.revision {
		t.Fatal("calendar-only update did not publish a new revision")
	}
	var observed []BudgetCalendars
	g.SetBudgetAccountingLookup(func(_ string, accounting BudgetAccountingContext) (BudgetSnapshot, bool) {
		observed = append(observed, accounting.Calendars)
		return BudgetSnapshot{}, true
	})
	in := InterventionBudgetInput{SourceReady: true, Now: time.Now(), BudgetBinding: "binding"}
	g.checkInterventionBudgetWith(old, in)
	g.CheckInterventionBudget(in)
	if len(observed) != 2 || observed[0] != la || observed[1] != (BudgetCalendars{DailyTimezone: "UTC", MonthlyTimezone: "UTC"}) {
		t.Fatalf("calendar mixed across policies: %+v", observed)
	}
	// Cached advisory accounting must also be invalidated by a calendar change.
	ev := policy.Event{Kind: policy.KindAPIRequest, Now: time.Now()}
	g.stampBudgetAccounting(&ev, false, false, la)
	g.stampBudgetAccounting(&ev, false, false, BudgetCalendars{})
	if len(observed) != 4 {
		t.Fatalf("calendar change reused cached accounting: %+v", observed)
	}
}
