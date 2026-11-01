package sandbox

import "testing"

// TestWorkspaceExecStateListsGitExecutionPaths pins that the one table every
// driver and the org-bind rows read lists every git-dir path that steers the
// host's git, so the live Mac D1 escape (a planted .git/commondir) cannot
// recur by a path quietly dropping off the table (ledger SBX-BE-21).
func TestWorkspaceExecStateListsGitExecutionPaths(t *testing.T) {
	byRel := map[string]ProtectedPath{}
	for _, pp := range WorkspaceExecState {
		byRel[pp.Rel] = pp
	}
	wantFiles := []string{
		".git/config",
		".git/commondir",
		".git/config.worktree",
		".git/info/attributes",
		".git/objects/info/alternates",
	}
	for _, rel := range wantFiles {
		pp, ok := byRel[rel]
		if !ok {
			t.Errorf("WorkspaceExecState is missing %s (a git-dir execution path; live Mac D1)", rel)
			continue
		}
		if pp.Dir {
			t.Errorf("%s must be a file row, not a directory row", rel)
		}
	}
	hooks, ok := byRel[".git/hooks"]
	if !ok || !hooks.Dir {
		t.Errorf(".git/hooks must be a directory row in WorkspaceExecState")
	}
}

// TestPlaceholderContentCommondirIsNeutral pins the one content that is not an
// empty file: an empty .git/commondir is fatal to git ("failed to read
// commondir"), while "." points the common dir back at the git dir itself and
// reads as a non-worktree repository's own layout, so the placeholder the box
// cannot replace or create does not break the box's own git either.
func TestPlaceholderContentCommondirIsNeutral(t *testing.T) {
	if got := string(PlaceholderContent("/ws/.git/commondir")); got != ".\n" {
		t.Errorf("commondir placeholder = %q, want %q", got, ".\n")
	}
	for _, p := range []string{
		"/ws/.git/config.worktree",
		"/ws/.git/info/attributes",
		"/ws/.git/objects/info/alternates",
	} {
		if got := PlaceholderContent(p); len(got) != 0 {
			t.Errorf("%s placeholder = %q, want empty", p, got)
		}
	}
	if got := string(PlaceholderContent("/x/settings.json")); got != "{}\n" {
		t.Errorf("json placeholder = %q, want %q", got, "{}\n")
	}
}
