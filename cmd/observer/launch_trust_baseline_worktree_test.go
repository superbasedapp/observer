//go:build !sbo_omit_security && !sbo_omit_security_trust

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestRepoTrustBaselineWorktree (lane shr-worktree2, P-044 residual): the
// baseline pass also snapshots each linked worktree of a baselined root, so
// a change to a worktree's own agent config raises a finding under that
// checkout; a repository with no worktree adds nothing.
func TestRepoTrustBaselineWorktree(t *testing.T) {
	mainRoot, wtRoot := linkedWorktreeFixture(t)
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	plain := writeTrustRepo(t, map[string]string{"README.md": "# x\n"})

	if got := repoTrustBaselineCheckouts([]string{plain, mainRoot}, 200); len(got) != 3 || got[0] != plain || got[1] != mainRoot || got[2] != wtRoot {
		t.Fatalf("checkouts = %v, want [plain main worktree]", got)
	}
	if got := repoTrustBaselineCheckouts([]string{plain, mainRoot}, 2); len(got) != 2 || got[1] != mainRoot {
		t.Fatalf("the cap: %v", got)
	}

	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	if n := repoTrustBaselinePass(ctx, st, []string{mainRoot}, now, nil); n != 0 {
		t.Fatalf("first pass recorded %d changes", n)
	}
	if err := os.WriteFile(filepath.Join(wtRoot, ".mcp.json"), []byte(`{"mcpServers":{"x":{"command":"node","args":["s.js"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if n := repoTrustBaselinePass(ctx, st, []string{mainRoot}, now.Add(5*time.Minute), nil); n != 1 {
		t.Fatalf("the worktree's new config recorded %d changes, want 1", n)
	}
	fs, err := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: guard.HashProjectRoot(wtRoot)})
	if err != nil || len(fs) != 1 || fs[0].Location.RelPath != ".mcp.json" || fs[0].Category != policy.FindingAgentConfig {
		t.Fatalf("worktree findings %+v %v", fs, err)
	}
	if fs, _ := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: guard.HashProjectRoot(mainRoot)}); len(fs) != 0 {
		t.Errorf("the main checkout got the worktree's finding: %+v", fs)
	}
}
