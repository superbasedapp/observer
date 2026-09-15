package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestIngestBudgetUsageHealsNullCountersAndPreservesMonotonicValues(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st, database := newTestStore(t)
	at := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	projectRoot := t.TempDir()
	events := []models.ToolEvent{{
		SessionID: "native-null-session", ProjectRoot: projectRoot,
		Tool: models.ToolMuse, Model: "muse-model", Timestamp: at,
		ActionType: models.ActionReadFile, Target: "source.go",
		SourceFile: "muse-session.jsonl", SourceEventID: "action-1",
	}}

	// Budget catchup must be able to bootstrap the native session without
	// replaying the historical action. The row below represents an older
	// capture whose nullable usage dimensions were all missing.
	if result, err := st.IngestBudgetUsage(ctx, events, nil, nil); err != nil {
		t.Fatalf("bootstrap budget usage: %v", err)
	} else if result.ActionsInserted != 0 || result.SessionsTouched != 1 {
		t.Fatalf("bootstrap result = %+v, want one session and no action", result)
	}
	if _, err := database.ExecContext(ctx, `
		INSERT INTO token_usage (
			session_id, timestamp, tool, model,
			input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens,
			reasoning_tokens, estimated_cost_usd, source, reliability,
			source_file, source_event_id
		) VALUES (?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, ?, ?, ?, ?)`,
		"native-null-session", timestamp(at), models.ToolMuse, "muse-model",
		models.TokenSourceJSONL, models.ReliabilityApproximate,
		"muse-session.jsonl", "usage-1"); err != nil {
		t.Fatalf("seed nullable usage row: %v", err)
	}

	read := func() (input, output, cacheRead, cacheCreation, reasoning sql.NullInt64, cost sql.NullFloat64) {
		t.Helper()
		if err := database.QueryRowContext(ctx, `
			SELECT input_tokens, output_tokens, cache_read_tokens,
			       cache_creation_tokens, reasoning_tokens, estimated_cost_usd
			FROM token_usage WHERE source_file = ? AND source_event_id = ?`,
			"muse-session.jsonl", "usage-1").Scan(
			&input, &output, &cacheRead, &cacheCreation, &reasoning, &cost,
		); err != nil {
			t.Fatalf("read usage row: %v", err)
		}
		return
	}

	input, output, cacheRead, cacheCreation, reasoning, cost := read()
	for name, value := range map[string]sql.NullInt64{
		"input": input, "output": output, "cache_read": cacheRead,
		"cache_creation": cacheCreation, "reasoning": reasoning,
	} {
		if value.Valid {
			t.Fatalf("seed %s counter = %d, want NULL", name, value.Int64)
		}
	}
	if cost.Valid {
		t.Fatalf("seed cost = %v, want NULL", cost.Float64)
	}

	known := models.TokenEvent{
		SessionID: "native-null-session", Timestamp: at, Tool: models.ToolMuse,
		Model: "muse-model", InputTokens: 120, OutputTokens: 34,
		CacheReadTokens: 56, CacheCreationTokens: 78, ReasoningTokens: 12,
		EstimatedCostUSD: 2.50, Source: models.TokenSourceJSONL,
		Reliability: models.ReliabilityApproximate,
		SourceFile:  "muse-session.jsonl", SourceEventID: "usage-1",
	}
	result, err := st.IngestBudgetUsage(ctx, events, []models.TokenEvent{known}, nil)
	if err != nil || result.TokensInserted != 1 {
		t.Fatalf("known reparse: result=%+v err=%v", result, err)
	}
	input, output, cacheRead, cacheCreation, reasoning, cost = read()
	if !input.Valid || input.Int64 != 120 || !output.Valid || output.Int64 != 34 ||
		!cacheRead.Valid || cacheRead.Int64 != 56 || !cacheCreation.Valid || cacheCreation.Int64 != 78 ||
		!reasoning.Valid || reasoning.Int64 != 12 || !cost.Valid || cost.Float64 != 2.50 {
		t.Fatalf("healed usage = %v/%v/%v/%v/%v/$%v, want 120/34/56/78/12/$2.50",
			input, output, cacheRead, cacheCreation, reasoning, cost)
	}

	// A later partial read is lower in every dimension. The canonical upsert
	// must retain the healed complete snapshot, including its stored cost.
	partial := known
	partial.InputTokens = 1
	partial.OutputTokens = 2
	partial.CacheReadTokens = 3
	partial.CacheCreationTokens = 4
	partial.ReasoningTokens = 5
	partial.EstimatedCostUSD = 0.25
	result, err = st.IngestBudgetUsage(ctx, events, []models.TokenEvent{partial}, nil)
	if err != nil || result.TokensInserted != 1 {
		t.Fatalf("partial reparse: result=%+v err=%v", result, err)
	}
	input, output, cacheRead, cacheCreation, reasoning, cost = read()
	if input.Int64 != 120 || output.Int64 != 34 || cacheRead.Int64 != 56 ||
		cacheCreation.Int64 != 78 || reasoning.Int64 != 12 || cost.Float64 != 2.50 {
		t.Fatalf("partial reparse regressed usage = %v/%v/%v/%v/%v/$%v, want 120/34/56/78/12/$2.50",
			input, output, cacheRead, cacheCreation, reasoning, cost)
	}
}
