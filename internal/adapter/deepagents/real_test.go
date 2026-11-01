package deepagents

import (
	"context"
	"os"
	"sort"
	"testing"
)

// TestRealStore parses a live dcode sessions.db named by DEEPAGENTS_REAL_DB
// (a path on either OS, native or foreign mount) and logs the counts. It is
// an opt-in grounding aid, skipped when the variable is unset:
//
//	DEEPAGENTS_REAL_DB=~/.deepagents/.state/sessions.db go test -run TestRealStore -v ./internal/adapter/deepagents/
func TestRealStore(t *testing.T) {
	path := os.Getenv("DEEPAGENTS_REAL_DB")
	if path == "" {
		t.Skip("DEEPAGENTS_REAL_DB not set")
	}
	a := New()
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	sessions := map[string]bool{}
	models := map[string]bool{}
	actions := map[string]int{}
	sideActions, turnIndexed := 0, 0
	for _, e := range res.ToolEvents {
		sessions[e.SessionID] = true
		actions[e.ActionType]++
		if e.IsSidechain {
			sideActions++
		}
		if e.TurnIndex > 0 {
			turnIndexed++
		}
	}
	var in, out, cr, cw, rs int64
	sideTokens, genMs, turnIDs := 0, 0, 0
	for _, e := range res.TokenEvents {
		sessions[e.SessionID] = true
		models[e.Model] = true
		in += e.InputTokens
		out += e.OutputTokens
		cr += e.CacheReadTokens
		cw += e.CacheCreationTokens
		rs += e.ReasoningTokens
		if e.IsSidechain {
			sideTokens++
		}
		if e.GenMs > 0 {
			genMs++
		}
		if e.TurnID != "" {
			turnIDs++
		}
	}
	var names []string
	for m := range models {
		names = append(names, m)
	}
	sort.Strings(names)
	t.Logf("sessions=%d tool_events=%d token_events=%d cache_obs=%d outcome_updates=%d warnings=%d offset=%d",
		len(sessions), len(res.ToolEvents), len(res.TokenEvents), len(res.CacheObservations), len(res.OutcomeUpdates), len(res.Warnings), res.NewOffset)
	t.Logf("tokens: net_in=%d out=%d cache_read=%d cache_write=%d reasoning=%d models=%v", in, out, cr, cw, rs, names)
	t.Logf("sidechain: actions=%d tokens=%d; gen_ms rows=%d; turn_id rows=%d; turn_index actions=%d",
		sideActions, sideTokens, genMs, turnIDs, turnIndexed)
	t.Logf("surfaces=%v versions=%v", res.SessionSurfaces, res.SessionToolVersions)
	t.Logf("actions: %v", actions)
	for _, w := range res.Warnings {
		t.Logf("warning: %s", w)
	}
}
