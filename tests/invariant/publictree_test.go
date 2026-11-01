package invariant

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/publictree"
)

// publictree_test.go holds the one answer to "is this the public tree?" for
// the invariant suite. scripts/release.sh strips the private-only paths
// (the org server binary, internal/orgserver, web2, docs/ ...) before it
// runs `go test ./tests/invariant/` on the staged public tree, so a guard
// that reads one of those paths has nothing to check there. The private
// tree always carries cmd/observer-org, so a guard that skips only in the
// public tree keeps full strength where the private code lives.

// The definition is shared with every other package's tests through
// internal/testsupport/publictree, so the two cannot disagree.

// inPublicTree reports whether root is the stripped public tree.
func inPublicTree(root string) bool {
	return publictree.In(root)
}

// skipInPublicTree skips t when root is the public tree, naming what the
// public tree does not carry.
func skipInPublicTree(t *testing.T, root, what string) {
	t.Helper()
	publictree.SkipAt(t, root, what)
}

var markOmittedRe = regexp.MustCompile(`components\.MarkOmitted\("([^"]+)"\)`)

// forcedOmitted returns the component ids a binary's main package marks
// compiled out from a file with no build line: the public tree strips the
// build line of the obs stubs (release.sh PUBLIC_UNCONDITIONAL_STUBS), so
// there the component is out of every build. The private tree has no such
// file, so the set is empty there.
func forcedOmitted(t *testing.T, root, cmdPath string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	dir := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(cmdPath, "./")))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		if strings.HasPrefix(src, "//go:build") {
			continue
		}
		for _, m := range markOmittedRe.FindAllStringSubmatch(src, -1) {
			out[m[1]] = true
		}
	}
	return out
}
