package git

import (
	"strings"
	"testing"
)

// TestResolveUpperCasesDriveLetter (WINNODE2 item 11): a cwd reported with a
// lower-case drive letter resolves to the upper-case root git and Go's
// EvalSymlinks use, also when the directory does not exist (the Abs
// fallback), so it lands on the same project as the upper-case spelling.
func TestResolveUpperCasesDriveLetter(t *testing.T) {
	dir := t.TempDir()
	lower := strings.ToLower(dir[:1]) + dir[1:]
	for _, p := range []string{lower, lower + `\does-not-exist`} {
		info, err := Resolve(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Root[0] < 'A' || info.Root[0] > 'Z' {
			t.Fatalf("Resolve(%q).Root = %q, want an upper-case drive letter", p, info.Root)
		}
	}
}
