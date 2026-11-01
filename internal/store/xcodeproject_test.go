package store

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/xcodehost"
)

// TestXcodeAgentCwdIsFiledAsProjectUnknown (FU-193): Xcode 26.6 runs its
// Claude Agent, Codex and Gemini with cwd ~/Library/Autosave Information
// (MAC-6). Such a session is filed under the explicit "Xcode (project
// unknown)" project, never one named after that folder; every other root
// keeps its own project.
func TestXcodeAgentCwdIsFiledAsProjectUnknown(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	for _, tc := range []struct{ id, tool, root, want string }{
		{"x1", models.ToolClaudeCode, "/Users/lume/Library/Autosave Information", xcodehost.ProjectUnknown},
		{"x2", models.ToolCodex, "/Users/lume/Library/Autosave Information", xcodehost.ProjectUnknown},
		{"x3", models.ToolGeminiCLI, "/Users/lume/Library/Autosave Information/", xcodehost.ProjectUnknown},
		{"x4", models.ToolClaudeCode, "/Users/lume/superbasedtest", "/Users/lume/superbasedtest"},
	} {
		if _, err := s.Ingest(ctx, []models.ToolEvent{{
			Tool: tc.tool, SourceFile: "/t/" + tc.id + ".jsonl", SourceEventID: tc.id + ":1",
			SessionID: tc.id, ProjectRoot: tc.root, Timestamp: time.Now().UTC(),
			ActionType: models.ActionRunCommand, Target: "ls", RawToolName: "Bash", Success: true,
		}}, nil, IngestOptions{}); err != nil {
			t.Fatal(err)
		}
		var root string
		if err := s.db.QueryRowContext(ctx,
			`SELECT p.root_path FROM sessions s JOIN projects p ON p.id = s.project_id WHERE s.id = ?`, tc.id).Scan(&root); err != nil {
			t.Fatal(err)
		}
		if root != tc.want {
			t.Errorf("%s (%s): project %q, want %q", tc.id, tc.root, root, tc.want)
		}
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM projects WHERE root_path LIKE '%Autosave Information%'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("projects named after the autosave folder: %d (%v)", n, err)
	}
}

// TestNonPathProjectRootIsLeftOut (audit row 8): FU-193's "Xcode (project
// unknown)" root, stored in projects.root_path, is not a directory, so the
// project-root sets every directory consumer reads (ProjectRoots: the
// policy bleed set, codeintel, the security scanners; RecentProjectRoots:
// the hook-switch scan) leave it out, and the loc rekey never asks git
// about it relative to the working directory.
func TestNonPathProjectRootIsLeftOut(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	for _, root := range []string{"/Users/lume/Library/Autosave Information", "/Users/lume/superbasedtest"} {
		if _, err := s.UpsertProject(ctx, root, ""); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.ProjectRoots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	recent, err := s.RecentProjectRoots(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string][]string{"ProjectRoots": all, "RecentProjectRoots": recent} {
		if len(got) != 1 || got[0] != "/Users/lume/superbasedtest" {
			t.Errorf("%s = %q, want only the real project", name, got)
		}
	}

	// loc rekey: a working directory holding a folder of that name with
	// linked worktrees is never consulted.
	cwd := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cwd, xcodehost.ProjectUnknown, ".git", "worktrees"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	if _, legacy := locPathHashes(xcodehost.ProjectUnknown, "a.go"); legacy != "" {
		t.Errorf("locPathHashes used the working directory's %q as a git root", xcodehost.ProjectUnknown)
	}
}

// TestAudienceAndGuidanceRootsLeaveOutANonPathRoot (audit row 7 on the w13
// hand-back): the project audience matcher's and the guidance scanner's
// root sets never list the non-path "Xcode (project unknown)" root; each
// consumer reads every root as a directory.
func TestAudienceAndGuidanceRootsLeaveOutANonPathRoot(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	for _, root := range []string{"/Users/lume/Library/Autosave Information", "/Users/lume/superbasedtest"} {
		if _, err := s.UpsertProject(ctx, root, ""); err != nil {
			t.Fatal(err)
		}
	}
	audience, err := s.ProjectAudienceRoots(ctx, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	scan, err := s.GuidanceScanRoots(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	never, err := s.GuidanceNeverScannedRoots(ctx, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string][]string{"ProjectAudienceRoots": audience, "GuidanceScanRoots": scan, "GuidanceNeverScannedRoots": never} {
		if slices.Contains(got, xcodehost.ProjectUnknown) || !slices.Contains(got, "/Users/lume/superbasedtest") {
			t.Errorf("%s = %q, want the real project only", name, got)
		}
	}
}
