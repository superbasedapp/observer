package guidance

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOSFSProjectRefusesSymlinkIntoHome is the SR27-A3 regression (security
// review 2026-09-27). The project-scope guidance pass used OSFS(root), which
// also anchors $HOME, so a repository could commit `CLAUDE.md ->
// ../../../.pgpass`: the target resolved "inside" the home anchor, and its
// first line became the stored description returned by get_project_guidance
// (the scrubber does not recognise a .pgpass line). OSFSProject anchors the
// project root alone, so the same link is refused and surfaced.
func TestOSFSProjectRefusesSymlinkIntoHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	root := filepath.Join(home, "src", "p")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	secret := filepath.Join(home, ".pgpass")
	if err := os.WriteFile(secret, []byte("db.internal:5432:*:alice:S3cretPassw0rd!\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	if err := os.Symlink("../../.pgpass", filepath.Join(root, "CLAUDE.md")); err != nil {
		t.Skipf("symlinks unavailable on this host: %v", err)
	}
	opts := Options{MaxFileBytes: 1 << 20, MaxDepth: 2}

	leaks := func(res Result) bool {
		for _, f := range res.Files {
			if strings.Contains(f.Description, "S3cret") || strings.Contains(f.Name, "S3cret") {
				return true
			}
		}
		return false
	}

	// The pre-fix shape: home is an anchor, so the link reads the secret.
	resHome, err := Scan(context.Background(), root, OSFS(root), opts)
	if err != nil {
		t.Fatalf("Scan(OSFS): %v", err)
	}
	if !leaks(resHome) {
		t.Log("note: OSFS(root) no longer reads through the home symlink on this host")
	}

	res, err := Scan(context.Background(), root, OSFSProject(root), opts)
	if err != nil {
		t.Fatalf("Scan(OSFSProject): %v", err)
	}
	if leaks(res) {
		t.Fatalf("a repo symlink into $HOME leaked the target's content into guidance metadata: %+v", res.Files)
	}
	var refused bool
	for _, e := range res.Errors {
		if strings.Contains(e, "CLAUDE.md") {
			refused = true
		}
	}
	if !refused {
		t.Errorf("the refusal was not surfaced in Result.Errors: %v", res.Errors)
	}
}
