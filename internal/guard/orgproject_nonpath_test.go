package guard

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/xcodehost"
)

// TestMatchRecordRootsNeverResolvesANonPathRoot (audit row 8, FU-193): the
// org-project match lookup looks a root that is not rooted on this host up
// as given, never through git against the working directory (which here
// holds a repository of that name).
func TestMatchRecordRootsNeverResolvesANonPathRoot(t *testing.T) {
	cwd := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cwd, xcodehost.ProjectUnknown, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, xcodehost.ProjectUnknown, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	if got := matchRecordRoots(xcodehost.ProjectUnknown); !slices.Equal(got, []string{xcodehost.ProjectUnknown}) {
		t.Errorf("matchRecordRoots = %q", got)
	}
}
