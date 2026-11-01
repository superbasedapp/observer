package publictree

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIn(t *testing.T) {
	for _, tc := range []struct {
		name   string
		layout func(root string) error
		public bool
	}{
		{"marker directory present", func(root string) error {
			return os.MkdirAll(filepath.Join(root, "cmd", "observer-org"), 0o755)
		}, false},
		{"marker absent", func(string) error { return nil }, true},
		{"marker is a file", func(root string) error {
			if err := os.MkdirAll(filepath.Join(root, "cmd"), 0o755); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(root, "cmd", "observer-org"), nil, 0o644)
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := tc.layout(root); err != nil {
				t.Fatal(err)
			}
			if got := In(root); got != tc.public {
				t.Errorf("In = %v, want %v", got, tc.public)
			}
		})
	}
}

func TestRepoRootHoldsGoMod(t *testing.T) {
	root := RepoRoot(t)
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("RepoRoot %s has no go.mod: %v", root, err)
	}
}

func TestSkipAt(t *testing.T) {
	public := t.TempDir()
	ran := false
	t.Run("public", func(t *testing.T) {
		SkipAt(t, public, "x")
		ran = true
	})
	if ran {
		t.Error("SkipAt did not skip on a tree without the marker")
	}
	private := t.TempDir()
	if err := os.MkdirAll(filepath.Join(private, filepath.FromSlash(Marker)), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Run("private", func(t *testing.T) {
		SkipAt(t, private, "x")
		ran = true
	})
	if !ran {
		t.Error("SkipAt skipped on a tree with the marker")
	}
}
