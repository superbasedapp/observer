//go:build windows

package agentconfigsvc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProjectLinkEscapesRootedWindowsTarget: a dangling link whose target is
// rooted without a volume (`\elsewhere\x.json`, not filepath.IsAbs) lands on
// the link's own volume root, outside the project, so it escapes; it is
// never read as relative to the link's directory.
func TestProjectLinkEscapesRootedWindowsTarget(t *testing.T) {
	root := t.TempDir()
	vol := filepath.VolumeName(root)
	if vol == "" {
		t.Skip("the temp dir has no volume")
	}
	outside := `\observer-test-not-here-` + strings.ReplaceAll(filepath.Base(root), " ", "") + `\x.json`
	if _, err := os.Lstat(vol + outside); err == nil {
		t.Skipf("%s exists", vol+outside)
	}
	at := filepath.Join(root, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(at), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, at); err != nil {
		t.Skipf("symlink (needs developer mode or the privilege): %v", err)
	}
	if !projectLinkEscapes(at, root) {
		t.Fatalf("a dangling link to the rooted target %q reads inside %s", outside, root)
	}
}
