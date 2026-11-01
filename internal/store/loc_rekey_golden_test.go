package store

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

var updateLOCPlainGolden = flag.Bool("update-loc-plain", false, "rewrite testdata/loc_plain_repo.golden")

// locPlainCase is one edit whose file_path_hash the plain-repository golden
// pins: the root and path are written with "<R>" for the temp repository.
type locPlainCase struct {
	name, root, path string
}

// locPlainCases are edits in a plain repository (no linked worktree) and
// in the MAIN checkout of a repository that has linked worktrees, plus the
// spellings the hash normalizes (relative, "./", Windows separators and
// drive-letter case, an outside path, a pseudo-path).
var locPlainCases = []locPlainCase{
	{"plain abs", "<R>", "<R>/pkg/a.go"},
	{"plain top", "<R>", "<R>/README.md"},
	{"plain relative", "<R>", "pkg/b.go"},
	{"plain dot relative", "<R>", "./pkg/c.go"},
	{"plain outside", "<R>", "/opt/elsewhere/x.go"},
	{"plain pseudo", "<R>", "[external]/y.go"},
	{"windows case", `C:\Repo`, `c:\repo\src\a.go`},
	{"main checkout of a repo with worktrees", "<W>", "<W>/pkg/a.go"},
	{"main checkout nested", "<W>", "<W>/cmd/tool/main.go"},
}

// TestLOCPathHashPlainRepoGolden (lane SHR-FOLLOWUPS, SHR-8): the
// file_path_hash of every edit outside a linked worktree is byte-identical
// to what it was before the re-key through the checkout seam. The golden
// was taken from the code BEFORE that change.
func TestLOCPathHashPlainRepoGolden(t *testing.T) {
	s, database := newTestStore(t)
	ctx := context.Background()
	plain := t.TempDir()
	if err := os.MkdirAll(filepath.Join(plain, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	withWT := t.TempDir()
	if err := os.MkdirAll(filepath.Join(withWT, ".git", "worktrees", "wt1"), 0o755); err != nil {
		t.Fatal(err)
	}
	sub := func(s string) string {
		return strings.NewReplacer("<R>", plain, "<W>", withWT).Replace(s)
	}
	var got strings.Builder
	for i, c := range locPlainCases {
		root, path := sub(c.root), sub(c.path)
		raw := fmt.Sprintf(`{"file_path":%q,"old_string":"a := 1","new_string":"a := 2"}`, path)
		ev := locEvent(fmt.Sprintf("s%d", i), root, path, models.ActionEditFile, raw, fmt.Sprintf("ev%d", i), false)
		if _, err := s.Ingest(ctx, []models.ToolEvent{ev}, nil, IngestOptions{}); err != nil {
			t.Fatalf("%s: Ingest: %v", c.name, err)
		}
		var hash string
		if err := database.QueryRowContext(ctx, `SELECT file_path_hash FROM file_changes WHERE session_id = ?`, ev.SessionID).Scan(&hash); err != nil {
			t.Fatalf("%s: read hash: %v", c.name, err)
		}
		fmt.Fprintf(&got, "%s\t%s\n", c.name, hash)
	}
	golden := filepath.Join("testdata", "loc_plain_repo.golden")
	if *updateLOCPlainGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(got.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != string(want) {
		t.Fatalf("plain-repository path hashes changed:\n got:\n%s\nwant:\n%s", got.String(), want)
	}
}
