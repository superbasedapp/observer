package store

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// codexPatchOf is a codex apply_patch edit whose header names path as given.
func codexPatchOf(session, root, header, ev string) models.ToolEvent {
	e := locEvent(session, root, header, models.ActionEditFile,
		"*** Begin Patch\n*** Update File: "+header+"\n@@\n-var a = 1\n+var a = 2\n*** End Patch", ev, false)
	e.Tool = models.ToolCodex
	return e
}

// TestLOCRelativePatchHeaderJoinsItsCommit (lane LEFT-SHARED, the SHR-8
// patch-header residual): a codex patch whose header is relative hashes
// like the commit's path whether the header is written from the worktree's
// own top level (`pkg/a.go`), from the main checkout into an in-tree
// worktree (`.worktrees/in/pkg/a.go`) or into an out-of-tree one
// (`../<dir>/out/pkg/a.go`); a relative header in the main checkout, and
// in a project with no linked worktree, hashes exactly as before.
func TestLOCRelativePatchHeaderJoinsItsCommit(t *testing.T) {
	repo, inTree, outTree, _ := locWorktreeRepo(t)
	s, _ := newTestStore(t)
	ctx := context.Background()
	commit := loc.PathHash("", "pkg/a.go")
	toOut, err := filepath.Rel(repo, outTree)
	if err != nil {
		t.Fatal(err)
	}
	toIn, err := filepath.Rel(repo, inTree)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		session, header string
	}{
		{"cwd-worktree", "pkg/a.go"},
		{"cwd-worktree-dot", "./pkg/a.go"},
		{"in-tree", filepath.ToSlash(filepath.Join(toIn, "pkg", "a.go"))},
		{"out-of-tree", filepath.ToSlash(filepath.Join(toOut, "pkg", "a.go"))},
	}
	for _, tc := range cases {
		if _, err := s.Ingest(ctx, []models.ToolEvent{codexPatchOf(tc.session, repo, tc.header, "e-"+tc.session)}, nil, IngestOptions{}); err != nil {
			t.Fatal(err)
		}
		if got := locHashOf(t, s, tc.session); len(got) != 1 || got[0] != commit {
			t.Errorf("%s (%s): hashed %v, want the commit's %s", tc.session, tc.header, got, commit)
		}
	}
	// Relative headers outside every worktree keep the old key.
	for _, header := range []string{"pkg//a.go", "docs/x.md"} {
		if h, legacy := locPathHashes(repo, header); h != loc.PathHash(repo, header) || legacy != "" {
			t.Errorf("%q: hash %s legacy %q, want the old key", header, h, legacy)
		}
	}
	plain := t.TempDir()
	if h, legacy := locPathHashes(plain, "../elsewhere/a.go"); h != loc.PathHash(plain, "../elsewhere/a.go") || legacy != "" {
		t.Errorf("plain repository: hash %s legacy %q", h, legacy)
	}
	// A row an earlier build keyed under the raw relative header is moved
	// onto the commit key by a re-ingest, never counted twice.
	in := filepath.ToSlash(filepath.Join(toIn, "pkg", "a.go"))
	if h, legacy := locPathHashes(repo, in); h != commit || legacy != loc.PathHash(repo, in) {
		t.Errorf("in-tree legacy key: hash %s legacy %s", h, legacy)
	}
}

// TestLOCPatchHeadersRelativeToASubdirectory (lane LEFT2-SEC item R-024):
// a codex patch written from a subdirectory of the project names its files
// relative to that subdirectory. The adapter stores the first header
// resolved there as the target (`sub/pkg/a.go`), and every relative header
// of the envelope then hashes under the subdirectory, like the commit that
// carries the files; a row whose target is the raw header (an older build,
// or a session at the root) hashes exactly as before; and the post-write
// scan is told the file under the subdirectory.
func TestLOCPatchHeadersRelativeToASubdirectory(t *testing.T) {
	root := t.TempDir()
	s, _ := newTestStore(t)
	ctx := context.Background()
	envelope := "*** Begin Patch\n*** Update File: pkg/a.go\n@@\n-var a = 1\n+var a = 2\n*** Add File: pkg/b.go\n+package pkg\n*** End Patch"
	cases := []struct {
		session, target string
		want            []string
	}{
		{"subdir", "sub/pkg/a.go", []string{loc.PathHash("", "sub/pkg/a.go"), loc.PathHash("", "sub/pkg/b.go")}},
		{"root", "pkg/a.go", []string{loc.PathHash("", "pkg/a.go"), loc.PathHash("", "pkg/b.go")}},
		{"older-row", "pkg/a.go", []string{loc.PathHash(root, "pkg/a.go"), loc.PathHash(root, "pkg/b.go")}},
	}
	for _, tc := range cases {
		e := locEvent(tc.session, root, tc.target, models.ActionEditFile, envelope, "e-"+tc.session, false)
		e.Tool = models.ToolCodex
		if _, err := s.Ingest(ctx, []models.ToolEvent{e}, nil, IngestOptions{}); err != nil {
			t.Fatal(err)
		}
		got := locHashOf(t, s, tc.session)
		if len(got) != len(tc.want) {
			t.Fatalf("%s: hashed %v, want %v", tc.session, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: file %d hashed %s, want %s", tc.session, i, got[i], tc.want[i])
			}
		}
	}
	if w, ok := PostWriteFor(root, "sub/pkg/a.go", envelope); !ok || w.Path != "sub/pkg/a.go" {
		t.Errorf("post-write of the resolved target: %+v %v, want sub/pkg/a.go", w, ok)
	}
}

// TestLOCHeaderBaseRows: the directory locHeaderBase reads from an action's
// target, one case per shape.
func TestLOCHeaderBaseRows(t *testing.T) {
	stats := func(paths ...string) []loc.FileStats {
		out := make([]loc.FileStats, 0, len(paths))
		for _, p := range paths {
			out = append(out, loc.FileStats{Path: p})
		}
		return out
	}
	for _, c := range []struct {
		name, target string
		stats        []loc.FileStats
		want         string
	}{
		{"a subdirectory", "sub/pkg/a.go", stats("pkg/a.go", "pkg/b.go"), "sub/"},
		{"the root", "pkg/a.go", stats("pkg/a.go"), ""},
		{"absolute headers", "/repo/pkg/a.go", stats("/repo/pkg/a.go"), ""},
		{"no header is the target's tail", "sub/x.go", stats("pkg/a.go"), ""},
		{"no stats", "sub/x.go", nil, ""},
	} {
		if got := locHeaderBase(c.target, c.stats); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
