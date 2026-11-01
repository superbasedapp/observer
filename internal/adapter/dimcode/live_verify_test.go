package dimcode

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestLiveVerify_RealStore is a manual audit tool, not part of the regular
// suite: it re-parses a REAL DimCode v2 directory (never a fixture) and logs
// what came out, so a regression against real DimCode output is visible
// without hand-copying real data into testdata/. Skipped unless
// DIMCODE_LIVE_ROOT points at a real `.../.dimcode/v2` directory (never
// committed, never required for `go test ./...`).
func TestLiveVerify_RealStore(t *testing.T) {
	root := os.Getenv("DIMCODE_LIVE_ROOT")
	if root == "" {
		t.Skip("set DIMCODE_LIVE_ROOT=$HOME/.dimcode/v2 to run against a real store")
	}
	a := NewWithOptions(nil, []string{root})
	path := filepath.Join(root, storeFile)
	if !a.IsSessionFile(path) {
		t.Fatalf("%s is not claimed by the adapter", path)
	}
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	sessions := map[string]bool{}
	byAction := map[string]int{}
	for _, e := range res.ToolEvents {
		sessions[e.SessionID] = true
		byAction[e.ActionType]++
	}
	modelsSeen := map[string]int{}
	for _, tk := range res.TokenEvents {
		sessions[tk.SessionID] = true
		modelsSeen[tk.Model]++
		t.Logf("session=%s id=%s model=%q input(net)=%d output=%d cache_read=%d cache_write=%d cost=$%.4f",
			tk.SessionID, tk.SourceEventID, tk.Model, tk.InputTokens, tk.OutputTokens,
			tk.CacheReadTokens, tk.CacheCreationTokens, tk.EstimatedCostUSD)
	}
	t.Logf("sessions=%d actions=%d by_action=%v token_rows=%d models=%v lineages=%d offset=%d",
		len(sessions), len(res.ToolEvents), byAction, len(res.TokenEvents), modelsSeen, len(res.SessionLineages), res.NewOffset)

	// The dimensions added with the 2026-10-21 parity pass.
	var sidechain, branch, perm, sub int
	for _, e := range res.ToolEvents {
		if e.IsSidechain {
			sidechain++
		}
		if e.GitBranch != "" {
			branch++
		}
		if e.Metadata != nil && e.Metadata.PermissionMode != "" {
			perm++
		}
		if e.Metadata != nil && e.Metadata.IsSubagent {
			sub++
		}
	}
	versions := map[string]int{}
	for _, v := range res.SessionToolVersions {
		versions[v.Version]++
	}
	t.Logf("sidechain_actions=%d subagent_marked=%d with_branch=%d with_permission_mode=%d tool_versions=%v user_prompts=%d api_errors=%d turn_aborted=%d prompt_context=%d",
		sidechain, sub, branch, perm, versions, byAction["user_prompt"], byAction["api_error"], byAction["turn_aborted"], byAction["prompt_context"])

	second, err := a.ParseSessionFile(context.Background(), path, res.NewOffset)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if len(second.ToolEvents) != 0 || len(second.TokenEvents) != 0 {
		t.Errorf("re-parse at the watermark yielded %d tool / %d token events, want 0", len(second.ToolEvents), len(second.TokenEvents))
	}
	if len(sessions) == 0 {
		t.Errorf("DIMCODE_LIVE_ROOT=%s produced zero sessions", root)
	}
}
