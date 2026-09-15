package guard

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

func TestInterventionRevisionExcludesPolicyPublication(t *testing.T) {
	g := newTestGuard(t, guardCfg(), nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	revision := g.set.Load().revision
	err := g.WithInterventionRevision(ctx, revision, func() error {
		// An ApplyOrgBudget/ReloadOrgLayer publisher must acquire this same
		// lock. Test the lock directly to avoid a timing-based blocked check.
		if g.reloadMu.TryLock() {
			g.reloadMu.Unlock()
			t.Fatal("policy publication was possible during the operation")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !g.reloadMu.TryLock() {
		t.Fatal("publication lock was not released")
	}
	// A pending publisher cannot deadlock a caller which holds a store fence.
	err = g.WithInterventionRevision(ctx, revision, func() error { t.Fatal("contended publication reached OS action"); return nil })
	g.reloadMu.Unlock()
	if err == nil {
		t.Fatal("contended publication accepted")
	}
}

func TestInterventionRevisionRejectsCapRemovalAndOtherGuard(t *testing.T) {
	g := newTestGuard(t, guardCfg(), nil)
	if err := g.ApplyOrgBudget(config.GuardBudgetConfig{DailyUSD: 0.35, Hard: true}, nil, false, policy.BudgetProtection{DailyUSD: true}, "binding"); err != nil {
		t.Fatal(err)
	}
	revision := g.set.Load().revision
	if err := g.ApplyOrgBudget(config.GuardBudgetConfig{}, nil, false, policy.BudgetProtection{}, "binding"); err != nil {
		t.Fatal(err)
	}
	other := newTestGuard(t, guardCfg(), nil)
	for _, current := range []*Guard{g, other} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := current.WithInterventionRevision(ctx, revision, func() error { t.Fatal("stale policy reached OS action"); return nil })
		cancel()
		if err == nil {
			t.Fatal("old policy revision accepted")
		}
	}
}
