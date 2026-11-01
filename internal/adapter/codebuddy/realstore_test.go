package codebuddy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// TestRealStoreReparse re-parses a live CodeBuddy data home read-only and
// logs what the adapter recovers. It is skipped unless CODEBUDDY_REAL_ROOT
// names a `<data home>/projects` directory; it asserts only that nothing
// errors and that every dimension this adapter fills is exercised.
func TestRealStoreReparse(t *testing.T) {
	root := os.Getenv("CODEBUDDY_REAL_ROOT")
	if root == "" {
		t.Skip("set CODEBUDDY_REAL_ROOT=<data home>/projects to re-parse a real store")
	}
	a := NewWithOptions(scrub.New(), root)
	var files []string
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && a.IsSessionFile(p) {
			files = append(files, p)
		}
		return nil
	})
	var sessions, actions, tokens, withModel, withVersion, withSurface, withSeed, withGen, pending, compact, blocked int
	byAction := map[string]int{}
	for _, p := range files {
		res, err := a.ParseSessionFile(context.Background(), p, 0)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		sessions++
		actions += len(res.ToolEvents)
		tokens += len(res.TokenEvents)
		for _, ev := range res.ToolEvents {
			byAction[ev.ActionType]++
			if ev.OutcomePending {
				pending++
			}
			if ev.ActionType == "permission_denied" {
				blocked++
			}
			if ev.ActionType == "context_compacted" {
				compact++
			}
		}
		for _, tok := range res.TokenEvents {
			if tok.Model != "" {
				withModel++
			}
			if tok.GenMs > 0 {
				withGen++
			}
		}
		withVersion += len(res.SessionToolVersions)
		withSurface += len(res.SessionSurfaces)
		withSeed += len(res.SessionProcessSeeds)
	}
	t.Logf("root=%s sessions=%d actions=%d tokens=%d (model=%d gen_ms=%d) versions=%d surfaces=%d pid_seeds=%d pending=%d hook_blocked=%d compactions=%d",
		root, sessions, actions, tokens, withModel, withGen, withVersion, withSurface, withSeed, pending, blocked, compact)
	t.Logf("actions by type: %v", byAction)
}
