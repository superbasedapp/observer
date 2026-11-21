package store

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// fakeRootResolver resolves the roots in table and counts every call.
func fakeRootResolver(table map[string]git.Identity, calls map[string]int) ProjectRootResolver {
	return func(root string) (git.Identity, bool) {
		calls[root]++
		id, ok := table[root]
		return id, ok
	}
}

// TestResolveIngestRoots: a resolved event takes the identity's root and
// fills only the identity fields its builder left empty; an unresolved one
// keeps what it came with; each distinct root is resolved once; the caller's
// slices are never changed.
func TestResolveIngestRoots(t *testing.T) {
	main := git.Identity{
		Info:           git.Info{Root: "/repo", IsGit: true, Remote: "github.com/acme/repo"},
		UpstreamRemote: "github.com/up/repo", RemoteOwner: "github.com/acme", Workspace: "web", IsWorktree: true,
	}
	calls := map[string]int{}
	resolve := fakeRootResolver(map[string]git.Identity{"/repo/.claude/worktrees/wt/web": main}, calls)

	events := []models.ToolEvent{
		{SessionID: "s1", ProjectRoot: "/repo/.claude/worktrees/wt/web"},
		{SessionID: "s1", ProjectRoot: "/repo/.claude/worktrees/wt/web", GitRemote: "github.com/builder/known", Workspace: "kept"},
		{SessionID: "s2", ProjectRoot: "/elsewhere"},
		{SessionID: "s3", ProjectRoot: ""},
	}
	tokens := []models.TokenEvent{{SessionID: "s1", ProjectRoot: "/repo/.claude/worktrees/wt/web"}}
	origEvents := append([]models.ToolEvent(nil), events...)
	origTokens := append([]models.TokenEvent(nil), tokens...)

	gotEvents, gotTokens := resolveIngestRoots(resolve, events, tokens)

	cases := []struct {
		name                    string
		got                     models.ToolEvent
		root, remote, workspace string
		upstream                string
		worktree                bool
	}{
		{"resolved, empty fields filled", gotEvents[0], "/repo", "github.com/acme/repo", "web", "github.com/up/repo", true},
		{"resolved, builder values kept", gotEvents[1], "/repo", "github.com/builder/known", "kept", "github.com/up/repo", true},
		{"not a git tree: unchanged", gotEvents[2], "/elsewhere", "", "", "", false},
		{"no root: unchanged", gotEvents[3], "", "", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := tc.got
			if e.ProjectRoot != tc.root || e.GitRemote != tc.remote || e.Workspace != tc.workspace ||
				e.GitUpstreamRemote != tc.upstream || e.IsWorktree != tc.worktree {
				t.Fatalf("event = %+v, want root %q remote %q workspace %q upstream %q worktree %v",
					e, tc.root, tc.remote, tc.workspace, tc.upstream, tc.worktree)
			}
		})
	}
	if gotTokens[0].ProjectRoot != "/repo" || gotTokens[0].GitRemote != "github.com/acme/repo" || !gotTokens[0].IsWorktree {
		t.Errorf("token event = %+v, want it resolved like the tool events", gotTokens[0])
	}
	if calls["/repo/.claude/worktrees/wt/web"] != 1 || calls["/elsewhere"] != 1 || calls[""] != 0 {
		t.Errorf("resolver calls = %v, want each distinct non-empty root once", calls)
	}
	for i := range events {
		if !reflect.DeepEqual(events[i], origEvents[i]) {
			t.Fatalf("caller's tool event %d changed: %+v", i, events[i])
		}
	}
	if !reflect.DeepEqual(tokens[0], origTokens[0]) {
		t.Fatalf("caller's token event changed: %+v", tokens[0])
	}
}

// TestIngestAppliesProjectRootResolver: with a resolver wired, Ingest files
// the session and its action under the resolved root; without one (the New()
// default, the watcher's store) the root is used as it came.
func TestIngestAppliesProjectRootResolver(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ev := models.ToolEvent{
		SessionID: "s-wt", ProjectRoot: "/repo/.claude/worktrees/wt", Tool: models.ToolClaudeCode,
		ActionType: models.ActionReadFile, Target: "a.go", Timestamp: time.Date(2026, 11, 7, 6, 0, 0, 0, time.UTC),
		SourceFile: "claude-code:hook", SourceEventID: "s-wt:1",
	}
	root := func(t *testing.T, st *Store) string {
		t.Helper()
		var got string
		if err := st.db.QueryRowContext(ctx,
			`SELECT p.root_path FROM sessions s JOIN projects p ON p.id = s.project_id WHERE s.id = 's-wt'`).Scan(&got); err != nil {
			t.Fatal(err)
		}
		var actionRoot string
		if err := st.db.QueryRowContext(ctx,
			`SELECT p.root_path FROM actions a JOIN projects p ON p.id = a.project_id WHERE a.session_id = 's-wt'`).Scan(&actionRoot); err != nil {
			t.Fatal(err)
		}
		if actionRoot != got {
			t.Fatalf("action filed under %q, session under %q", actionRoot, got)
		}
		return got
	}

	wired, _ := newTestStore(t)
	wired.SetProjectRootResolver(fakeRootResolver(map[string]git.Identity{
		"/repo/.claude/worktrees/wt": {Info: git.Info{Root: "/repo", IsGit: true}, IsWorktree: true},
	}, map[string]int{}))
	if _, err := wired.Ingest(ctx, []models.ToolEvent{ev}, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := root(t, wired); got != canonicalProjectRoot("/repo") {
		t.Errorf("with a resolver the session is under %q, want the main repository", got)
	}

	plain, _ := newTestStore(t)
	if _, err := plain.Ingest(ctx, []models.ToolEvent{ev}, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := root(t, plain); got != canonicalProjectRoot("/repo/.claude/worktrees/wt") {
		t.Errorf("without a resolver the session is under %q, want the root as it came", got)
	}
}
