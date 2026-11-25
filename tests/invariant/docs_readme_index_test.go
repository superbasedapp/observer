package invariant

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// docs_readme_index_test.go keeps docs/README.md, the categorized index
// CLAUDE.md tells every agent to open first, complete for the docs/ root:
// every .md file at the root is linked from it, so a new root doc cannot land
// unindexed (docs/README.md Conventions, "Index every root doc here"). The
// dated folders (plans/, audits/, handovers/) are indexed by
// tools/docsindexgen instead, whose drift check keeps their INDEX.md files
// current; this test also holds the README to linking those three indexes.
//
// docs/ is private-only, so the public tree skips.

// docsLinkRe matches the target of an inline Markdown link, "](target)" or
// "](<target with spaces>)".
var docsLinkRe = regexp.MustCompile(`\]\(\s*(?:<([^>]+)>|([^)\s]+))`)

// readmeLinkedPaths returns the docs-relative paths docs/README.md links,
// with any fragment or query dropped and the path cleaned.
func readmeLinkedPaths(readme string) map[string]bool {
	out := map[string]bool{}
	for _, m := range docsLinkRe.FindAllStringSubmatch(readme, -1) {
		target := m[1] + m[2]
		if i := strings.IndexAny(target, "#?"); i >= 0 {
			target = target[:i]
		}
		if target == "" || strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
			continue
		}
		out[path.Clean(target)] = true
	}
	return out
}

func TestEveryRootDocIsLinkedFromDocsReadme(t *testing.T) {
	root := repoRoot(t)
	skipInPublicTree(t, root, "docs/")
	docsDir := filepath.Join(root, "docs")
	raw, err := os.ReadFile(filepath.Join(docsDir, "README.md"))
	if err != nil {
		t.Fatalf("read docs/README.md: %v", err)
	}
	linked := readmeLinkedPaths(string(raw))

	entries, err := os.ReadDir(docsDir)
	if err != nil {
		t.Fatalf("read docs/: %v", err)
	}
	var missing []string
	seen := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".md") || name == "README.md" {
			continue
		}
		seen++
		if !linked[name] {
			missing = append(missing, name)
		}
	}
	// The root held 235 docs on 2026-11-24; far fewer means the walk is
	// looking in the wrong place, not that the index is complete.
	if seen < 100 {
		t.Fatalf("found only %d .md files at the docs/ root; the docs tree moved, update this test", seen)
	}
	sort.Strings(missing)
	for _, name := range missing {
		t.Errorf("docs/%s is not linked from docs/README.md: add a row for it in the section it belongs to (a dated record belongs in docs/plans/, docs/audits/ or docs/handovers/ instead)", name)
	}

	for _, index := range []string{"plans/INDEX.md", "audits/INDEX.md", "handovers/INDEX.md"} {
		if !linked[index] {
			t.Errorf("docs/README.md does not link the generated index %s (Subdirs section)", index)
		}
		if _, err := os.Stat(filepath.Join(docsDir, filepath.FromSlash(index))); err != nil {
			t.Errorf("docs/%s: %v (run `make docs-index`)", index, err)
		}
	}
}

func TestReadmeLinkedPaths(t *testing.T) {
	got := readmeLinkedPaths("| [`a.md`](a.md) | [b](./b.md#part) | [c](<c d.md>) | [w](https://x/y.md) | [s](plans/INDEX.md?x) | [up](../x.md) |")
	for _, want := range []string{"a.md", "b.md", "c d.md", "plans/INDEX.md", "../x.md"} {
		if !got[want] {
			t.Errorf("readmeLinkedPaths missed %q: %v", want, got)
		}
	}
	if got["https:/x/y.md"] || got["https://x/y.md"] {
		t.Errorf("readmeLinkedPaths kept an absolute URL: %v", got)
	}
}
