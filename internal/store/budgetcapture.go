package store

import (
	"context"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// IngestBudgetUsage reconciles native usage through the normal session,
// lineage and token-ingestion owner without replaying historical actions,
// content, classifiers or advisory guard events. Tool events supply session
// bootstrap context only. It does not advance parser cursors.
//
// Every BILLABLE token event must reach the canonical token upsert. The
// ordinary ingest path tolerates an unattachable event; a budget catchup must
// report missing BILLABLE accounting instead of claiming readiness. The count
// is measured before canonical cross-source deduplication and is not a claim
// that the resulting rows represent exact or immediately complete usage.
//
// A zero-usage event with no session id is dropped by the ingest owner by
// construction (there is nothing to attach it to) and carries no spend, so it
// is tolerated: the caller learns about it through the returned count and
// reports it as a warning. Treating it as a hard error made one empty adapter
// event mark a tool's accounting permanently unavailable - and, on a managed
// node, stop that tool's processes forever (accounting-readiness correction,
// 2026-09-14).
func (s *Store) IngestBudgetUsage(ctx context.Context, events []models.ToolEvent, tokens []models.TokenEvent, lineages []models.SessionLineage) (IngestResult, error) {
	result, err := s.ingest(ctx, events, tokens, IngestOptions{SessionLineages: lineages}, true)
	if err != nil {
		return result, fmt.Errorf("store.IngestBudgetUsage: %w", err)
	}
	if required := len(tokens) - budgetCaptureTolerableDrops(tokens); result.TokensInserted < required {
		return result, fmt.Errorf("store.IngestBudgetUsage: accepted %d of %d token events (%d required); accounting is incomplete",
			result.TokensInserted, len(tokens), required)
	}
	return result, nil
}

// budgetCaptureTolerableDrops counts the submitted events the ingest owner is
// guaranteed to drop and which cannot hide spend: a token event with no
// session id and no billable counter. Every other event must land.
func budgetCaptureTolerableDrops(tokens []models.TokenEvent) int {
	var n int
	for _, tk := range tokens {
		if tk.SessionID == "" && !budgetCaptureTokenIsBillable(tk) {
			n++
		}
	}
	return n
}

func budgetCaptureTokenIsBillable(tk models.TokenEvent) bool {
	return tk.InputTokens != 0 || tk.OutputTokens != 0 || tk.CacheReadTokens != 0 ||
		tk.CacheCreationTokens != 0 || tk.CacheCreation1hTokens != 0 ||
		tk.ReasoningTokens != 0 || tk.WebSearchRequests != 0 || tk.EstimatedCostUSD != 0
}
