package store

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// TestGuardBudgetSpendPriced_NamesWhyRowsAreInvalid pins demo bug #5: the
// status line printed "unpriced_rows=17777 unpriced_models=none-named
// (invalid-rows)" on a node whose Claude Code transcript rows (reliability
// "unreliable") a MANAGED read refuses, and nothing said why. The read now
// splits invalid rows by reason and names the tools behind them; an advisory
// read prices the same rows and reports nothing invalid. One row per reason.
func TestGuardBudgetSpendPriced_NamesWhyRowsAreInvalid(t *testing.T) {
	at := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	type row struct {
		reliability, source string
		input, output       int64
		storedUSD           float64
	}
	cases := []struct {
		name        string
		row         row
		managed     bool
		wantReasons map[string]int
		wantTools   []string
		wantPriced  int
	}{
		{
			"managed: transcript tokens are unverified",
			row{"unreliable", "jsonl", 10, 5, 0},
			true,
			map[string]int{GuardBudgetUnverifiedTokens: 1},
			[]string{"claude-code"},
			0,
		},
		{"advisory: the same row is priced", row{"unreliable", "jsonl", 10, 5, 0}, false, nil, nil, 1},
		{
			"managed: a non-capture source is unverified",
			row{"accurate", "session_summary", 10, 5, 0},
			true,
			map[string]int{GuardBudgetUnverifiedTokens: 1},
			[]string{"claude-code"},
			0,
		},
		{
			"managed: negative counters",
			row{"accurate", "jsonl", -1, 5, 0},
			true,
			map[string]int{GuardBudgetInvalidCounters: 1},
			[]string{"claude-code"},
			0,
		},
		{
			"advisory: negative counters too",
			row{"accurate", "jsonl", -1, 5, 0},
			false,
			map[string]int{GuardBudgetInvalidCounters: 1},
			[]string{"claude-code"},
			0,
		},
		{
			"managed: a stored cost with no usage",
			row{"accurate", "jsonl", 0, 0, 0.5},
			true,
			map[string]int{GuardBudgetStoredWithoutUsage: 1},
			[]string{"claude-code"},
			0,
		},
		{"managed: a verified row is valid", row{"accurate", "jsonl", 10, 5, 0}, true, nil, nil, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, db := newTestStore(t)
			guardBudgetTestSession(t, s, "sess")
			if _, err := db.ExecContext(context.Background(), `
				INSERT INTO token_usage(
					session_id, timestamp, tool, model, input_tokens, output_tokens,
					cache_read_tokens, cache_creation_tokens, reasoning_tokens,
					estimated_cost_usd, source, reliability, source_event_id)
				VALUES ('sess', ?, 'claude-code', 'known-model', ?, ?, 0, 0, 0, ?, ?, ?, 'e1')`,
				timestamp(at), c.row.input, c.row.output, c.row.storedUSD, c.row.source, c.row.reliability); err != nil {
				t.Fatal(err)
			}
			day, week, month := guardBudgetTestWindows()
			spend, err := s.GuardBudgetSpendPriced(context.Background(), "", day, week, month,
				func(string, time.Time, PushTokenSplit) (float64, string, bool) { return 0.01, "exact", true },
				GuardBudgetReadOptions{Managed: c.managed})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(spend.InvalidReasons, c.wantReasons) {
				t.Errorf("reasons = %v, want %v", spend.InvalidReasons, c.wantReasons)
			}
			if !reflect.DeepEqual(spend.InvalidTools, c.wantTools) {
				t.Errorf("tools = %v, want %v", spend.InvalidTools, c.wantTools)
			}
			wantInvalid := 0
			for _, n := range c.wantReasons {
				wantInvalid += n
			}
			if spend.InvalidRows != wantInvalid || spend.PricedRows != c.wantPriced {
				t.Errorf("invalid %d priced %d, want %d and %d", spend.InvalidRows, spend.PricedRows, wantInvalid, c.wantPriced)
			}
			if len(spend.UnpricedModels) != 0 {
				t.Errorf("an invalid row named a model: %v", spend.UnpricedModels)
			}
		})
	}
}
