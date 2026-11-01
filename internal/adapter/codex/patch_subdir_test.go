package codex

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestPatchHeaderRelativeToASubdirectory (lane LEFT2-SEC item R-024): a
// patch header is written relative to the session's working directory.
// When that is a subdirectory of the project the stored target names the
// file under the subdirectory, not a same-named file at the project root;
// at the root, with no working directory, or with an absolute header the
// target is what it was before.
func TestPatchHeaderRelativeToASubdirectory(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "repo")
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New()
	patch := func(header string) responseItemCustomToolCall {
		return responseItemCustomToolCall{CallID: "c1", Name: "apply_patch", Input: "*** Begin Patch\n*** Update File: " + header + "\n@@\n+x\n*** End Patch\n"}
	}
	cases := []struct {
		name, cwd, header, want string
	}{
		{"a subdirectory working directory", filepath.Join(root, "sub"), "pkg/a.go", "sub/pkg/a.go"},
		{"a header reaching up from the subdirectory", filepath.Join(root, "sub"), "../lib/b.go", "lib/b.go"},
		{"the project root", root, "pkg/a.go", "pkg/a.go"},
		{"no working directory known", "", "pkg/a.go", "pkg/a.go"},
		{"an absolute header", filepath.Join(root, "sub"), filepath.Join(root, "pkg", "a.go"), "pkg/a.go"},
	}
	for _, c := range cases {
		evt, _ := a.buildCustomToolCallEvent("/r.jsonl", "c1", sessionContext{Cwd: c.cwd}, root, time.Unix(0, 0), patch(c.header), "")
		if evt.Target != c.want {
			t.Errorf("%s: Target = %q, want %q", c.name, evt.Target, c.want)
		}
	}
}
