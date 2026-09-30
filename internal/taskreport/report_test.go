package taskreport

// report_test.go is a pure (no DB) unit test suite over
// composeSessionTaskReport and TaskCostBucket.addRow — the exact shapes
// 2026-09-22 review round 4 finding #9 named: task reporting collapsed
// any number of unpriced turns down to a bare bool. These tests build
// the taskflow.Transition/store.TaskItemRow/store.TaskTokenRow inputs
// directly (no store/DB machinery needed — composeSessionTaskReport
// takes already-loaded rows) so they run in milliseconds and pin the
// exact count, not just "some are unpriced".

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/taskflow"
)

// TestTaskCostBucket_AddRow_AccumulatesExactUnpricedCount pins the core
// of finding #9 at the lowest level: addRow must SUM the unpriced-turn
// count across every contribution, never clamp it to 0/1.
func TestTaskCostBucket_AddRow_AccumulatesExactUnpricedCount(t *testing.T) {
	var b TaskCostBucket
	b.addRow(TaskTokenTotals{InputTokens: 10}, 0, 1)
	b.addRow(TaskTokenTotals{InputTokens: 20}, 0, 1)
	b.addRow(TaskTokenTotals{InputTokens: 30}, 5.0, 0) // a priced row must NOT add to the count
	b.addRow(TaskTokenTotals{InputTokens: 40}, 0, 1)

	if b.UnpricedTurns != 3 {
		t.Errorf("UnpricedTurns = %d, want 3 (three unpriced contributions, one priced one must not count)", b.UnpricedTurns)
	}
	if !b.Unpriced {
		t.Errorf("Unpriced = false, want true (UnpricedTurns > 0)")
	}
	if b.CostUSD != 5.0 {
		t.Errorf("CostUSD = %v, want 5.0 (only the priced row's cost)", b.CostUSD)
	}

	// Merging an already-aggregated sub-bucket's OWN UnpricedTurns (the
	// rollup-merge call-site shape) must ADD its count, not re-derive a
	// fresh 0/1 from a bool.
	var rollup TaskCostBucket
	rollup.addRow(TaskTokenTotals{}, 0, b.UnpricedTurns)
	if rollup.UnpricedTurns != 3 {
		t.Errorf("rollup.UnpricedTurns = %d, want 3 (merged from the sub-bucket's exact count)", rollup.UnpricedTurns)
	}
}

// TestComposeSessionTaskReport_MultipleUnpricedTurnsNotCollapsedToOne is
// the review's own headline shape (finding #9): a single task with 4
// unpriced token_usage rows attributed to it must report
// unpriced_turns=4 on that task's ReportItem, never 1 — the collapse the
// review found at the OLD dashboard/projects.go call site
// (item.Unpriced ? 1 : 0) is only fixed if TaskCostBucket itself carries
// the real count through composeSessionTaskReport → attributeTokenRows.
func TestComposeSessionTaskReport_MultipleUnpricedTurnsNotCollapsedToOne(t *testing.T) {
	base := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)

	items := []store.TaskItemRow{
		{
			Key: "t1", KeyKind: taskflow.KeyNative, Content: "fix the thing", Status: taskflow.StatusCompleted,
			FirstSeenAt: base, LastSeenAt: base.Add(time.Hour),
		},
	}
	transitions := []taskflow.Transition{
		{Key: "t1", ToStatus: taskflow.StatusInProgress, Ts: base},
		{Key: "t1", ToStatus: taskflow.StatusCompleted, Ts: base.Add(time.Hour)},
	}
	// 4 token rows inside t1's [in_progress, completed) window, an
	// unrecognized model and no recorded cost — with costEngine=nil,
	// priceTaskTokenRow unconditionally reports each one unpriced.
	var tokenRows []store.TaskTokenRow
	for i := 0; i < 4; i++ {
		tokenRows = append(tokenRows, store.TaskTokenRow{
			Ts: base.Add(time.Duration(i+1) * time.Minute), Model: "totally-unknown-model",
			InputTokens: 100, OutputTokens: 50,
		})
	}

	rep := composeSessionTaskReport("sess1", items, 0, transitions, tokenRows, "",
		nil, nil, taskflow.Options{}, nil)

	if len(rep.Items) != 1 {
		t.Fatalf("len(rep.Items) = %d, want 1", len(rep.Items))
	}
	item := rep.Items[0]
	if item.UnpricedTurns != 4 {
		t.Errorf("item.UnpricedTurns = %d, want 4 (all four turns unpriced, never collapsed to 1)", item.UnpricedTurns)
	}
	if !item.Unpriced {
		t.Errorf("item.Unpriced = false, want true")
	}
	if item.CostUSD != 0 {
		t.Errorf("item.CostUSD = %v, want 0 (nothing priced)", item.CostUSD)
	}
	if item.Tokens.InputTokens != 400 {
		t.Errorf("item.Tokens.InputTokens = %d, want 400 (4 × 100, tokens still counted even though unpriced)", item.Tokens.InputTokens)
	}
}
