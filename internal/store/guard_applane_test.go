package store

import (
	"context"
	"testing"
	"time"
)

// TestGuardBudgetExcludesAppLaneTurns pins the hosted AI gateway plan's L7
// gap 3 (APPLANE-1): a turn an app spent through a local app lane
// (api_turns.upstream_lane set) never counts in the developer's
// [guard.budget] windows, in every reader the guard uses: the plain
// spend, the priced spend and the token windows.
func TestGuardBudgetExcludesAppLaneTurns(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	guardBudgetTestSession(t, s, "dev")
	ctx := context.Background()
	at := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	insertGuardBudgetAPI(t, db, "dev", "claude-x", at, 100, 50, 1.25)
	// The app's lane turn: same window, no session (an app call), a lane.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO api_turns(session_id, timestamp, provider, model, input_tokens, output_tokens, cost_usd, upstream_lane)
		VALUES (NULL, ?, 'openai', 'gpt-5-nano', 1000, 1000, 9.00, 'openai')`, timestamp(at)); err != nil {
		t.Fatalf("insert lane turn: %v", err)
	}
	day, week, month := guardBudgetTestWindows()

	spend, err := s.GuardBudgetSpend(ctx, "dev", day, week, month)
	if err != nil {
		t.Fatalf("GuardBudgetSpend: %v", err)
	}
	assertGuardBudgetNear(t, "plain daily", spend.DailyUSD, 1.25)
	assertGuardBudgetNear(t, "plain monthly", spend.MonthlyUSD, 1.25)

	priced, err := s.GuardBudgetSpendPriced(ctx, "dev", day, week, month,
		func(string, time.Time, PushTokenSplit) (float64, string, bool) { return 0, "", false })
	if err != nil {
		t.Fatalf("GuardBudgetSpendPriced: %v", err)
	}
	assertGuardBudgetNear(t, "priced daily", priced.DailyUSD, 1.25)

	tok, err := s.GuardBudgetTokens(ctx, "dev", day, week, month)
	if err != nil {
		t.Fatalf("GuardBudgetTokens: %v", err)
	}
	if tok.DailyTokens != 150 {
		t.Fatalf("daily tokens = %d, want 150 (the lane turn's 2000 excluded)", tok.DailyTokens)
	}
}
