package cortexcode

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestLiveVerify_RealStore is a manual audit tool, not part of the regular
// suite: it re-parses a REAL Cortex Code conversations directory (never a
// fixture) and logs what came out, so a regression against real cortex
// output is visible without copying real data into testdata/. Skipped
// unless CORTEXCODE_LIVE_ROOT points at a real `.../cortex/conversations`
// directory.
func TestLiveVerify_RealStore(t *testing.T) {
	root := os.Getenv("CORTEXCODE_LIVE_ROOT")
	if root == "" {
		t.Skip("set CORTEXCODE_LIVE_ROOT=$HOME/.snowflake/cortex/conversations to run against a real store")
	}
	a := NewWithOptions(nil, root)
	ctx := context.Background()

	sessions := map[string]bool{}
	actionsByType := map[string]int{}
	rawNames := map[string]int{}
	var actions, tokenRows, outcomeUpdates int
	modelsSeen := map[string]bool{}
	versions, surfaces := map[string]bool{}, map[string]bool{}
	var accounts, lineages int

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !a.IsSessionFile(path) {
			return nil
		}
		res, perr := a.ParseSessionFile(ctx, path, 0)
		if perr != nil {
			t.Errorf("ParseSessionFile(%s): %v", path, perr)
			return nil
		}
		for _, w := range res.Warnings {
			t.Logf("warning %s: %s", filepath.Base(path), w)
		}
		sessions[sessionIDFromPath(path)] = true
		for _, v := range res.SessionToolVersions {
			versions[v.SessionID[:8]+"="+v.Version] = true
		}
		for _, sf := range res.SessionSurfaces {
			surfaces[sf.SessionID[:8]+"="+sf.Surface+"/"+sf.SurfaceHost] = true
		}
		for _, sd := range res.SessionProcessSeeds {
			t.Logf("seed %s pid=%d", sd.SessionID[:8], sd.PID)
		}
		accounts += len(res.ToolAccounts)
		lineages += len(res.SessionLineages)
		actions += len(res.ToolEvents)
		outcomeUpdates += len(res.OutcomeUpdates)
		for _, ev := range res.ToolEvents {
			actionsByType[ev.ActionType]++
			if ev.RawToolName != "" {
				rawNames[ev.RawToolName]++
			}
			if ev.Model != "" {
				modelsSeen[ev.Model] = true
			}
			eff := ""
			if ev.Metadata != nil {
				eff = ev.Metadata.EffortLevel
			}
			t.Logf("%s %s %s raw=%s ok=%v pending=%v dur=%d effort=%s root=%s target=%.60q",
				ev.Timestamp.Format("15:04:05"), ev.SessionID[:8], ev.ActionType, ev.RawToolName,
				ev.Success, ev.OutcomePending, ev.DurationMs, eff, ev.ProjectRoot, ev.Target)
		}
		for _, tk := range res.TokenEvents {
			tokenRows++
			modelsSeen[tk.Model] = true
			t.Logf("tokens session=%s model=%s net_in=%d out=%d cache_read=%d cache_write=%d root=%s",
				tk.SessionID, tk.Model, tk.InputTokens, tk.OutputTokens, tk.CacheReadTokens, tk.CacheCreationTokens, tk.ProjectRoot)
		}
		// Re-parse from the returned offset: zero new history events.
		if classifyLayout(path) == layoutHistory {
			second, serr := a.ParseSessionFile(ctx, path, res.NewOffset)
			if serr != nil || len(second.ToolEvents) != 0 {
				t.Errorf("re-parse(%s) from %d: err=%v events=%d, want 0", path, res.NewOffset, serr, len(second.ToolEvents))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for m := range modelsSeen {
		names = append(names, m)
	}
	sort.Strings(names)
	t.Logf("sessions=%d actions=%d token_rows=%d outcome_updates=%d models=%v", len(sessions), actions, tokenRows, outcomeUpdates, names)
	t.Logf("by action=%v raw tools=%v", actionsByType, rawNames)
	t.Logf("versions=%v surfaces=%v account_obs=%d lineages=%d", versions, surfaces, accounts, lineages)
	transcripts := 0
	for id := range sessions {
		if msgs, terr := a.ReadTranscript(ctx, models.Session{ID: id}, nil); terr == nil {
			transcripts++
			t.Logf("transcript %s: %d messages", id[:8], len(msgs))
		}
	}
	t.Logf("transcripts readable=%d/%d", transcripts, len(sessions))
	if len(sessions) == 0 {
		t.Errorf("CORTEXCODE_LIVE_ROOT=%s matched zero session files", root)
	}
}
