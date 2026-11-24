package invariant

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// public_docs_links_test.go: SR-29 (ship-readiness audit, 2026-11-23). The
// CLI and the node dashboard point users at https://superbased.app/docs/...
// instead of the repository's docs/*.md, which users cannot open. A link to
// a page the site does not publish is as broken as the private path it
// replaced (`observer apps` printed .../getting-started/ai-apps, a 404), so
// this test resolves every such link offline against the pages
// website/docs-src/nav.toml publishes, with the URL rule the docs generator
// uses (website/docs-tools/gen: loadNav, locate, publishedPath).

// publicDocsScanRoots are the trees whose non-test sources are scanned.
var publicDocsScanRoots = []struct {
	dir  string
	exts []string
}{
	{"cmd", []string{".go"}},
	{"internal", []string{".go"}},
	{filepath.Join("web", "src"), []string{".ts", ".tsx"}},
}

// publicDocsURLRe matches a link into the published docs. The path stops at
// a fragment, a query or anything that cannot be part of a page path.
var publicDocsURLRe = regexp.MustCompile(`https?://(?:www\.)?superbased\.app(/docs(?:/[A-Za-z0-9_./-]*)?)`)

// docsNav is the part of nav.toml the URL rule reads.
type docsNav struct {
	Roots   map[string]string `toml:"roots"`
	Section []struct {
		Page []struct {
			File  string `toml:"file"`
			Index bool   `toml:"index"`
		} `toml:"page"`
	} `toml:"section"`
}

// publishedDocsPaths returns every URL path the docs site publishes
// ("/docs/getting-started/install", "/docs/sdk/overview", "/docs"), checking
// that each page's source file exists.
func publishedDocsPaths(t *testing.T, root string) map[string]bool {
	t.Helper()
	srcDir := filepath.Join(root, "website", "docs-src")
	var nav docsNav
	if _, err := toml.DecodeFile(filepath.Join(srcDir, "nav.toml"), &nav); err != nil {
		t.Fatalf("nav.toml: %v", err)
	}
	out := map[string]bool{}
	for _, sec := range nav.Section {
		for _, pg := range sec.Page {
			src, rel := filepath.Join(srcDir, filepath.FromSlash(pg.File)), strings.TrimSuffix(pg.File, ".md")
			if name, p, ok := strings.Cut(pg.File, ":"); ok {
				dir, known := nav.Roots[name]
				if !known {
					t.Fatalf("nav.toml page %q names an undeclared root", pg.File)
				}
				src = filepath.Join(srcDir, filepath.FromSlash(dir), filepath.FromSlash(p))
				rel = name + "/" + docsPublishedPath(p)
			}
			if _, err := os.Stat(src); err != nil {
				t.Errorf("nav.toml page %q: source missing: %v", pg.File, err)
				continue
			}
			out["/docs/"+rel] = true
			if pg.Index {
				out["/docs"] = true
			}
		}
	}
	if len(out) < 50 {
		t.Fatalf("nav.toml publishes only %d pages; the rule is not reading it", len(out))
	}
	return out
}

// docsPublishedPath mirrors gen's publishedPath: a root file's output path
// without .md, except that a README is its directory's page (the root's own
// README is "overview").
func docsPublishedPath(p string) string {
	stem := strings.TrimSuffix(p, ".md")
	if path.Base(stem) != "README" {
		return stem
	}
	if d := path.Dir(stem); d != "." {
		return d
	}
	return "overview"
}

// normalizeDocsURLPath trims what a sentence or a pretty URL adds around a
// page path: trailing dots and slashes, and an .html suffix.
func normalizeDocsURLPath(p string) string {
	p = strings.TrimRight(p, "./")
	p = strings.TrimSuffix(p, ".html")
	if p == "" {
		return "/docs"
	}
	return p
}

func TestPublicDocsLinksResolve(t *testing.T) {
	root := repoRoot(t)
	if _, err := os.Stat(filepath.Join(root, "website", "docs-src", "nav.toml")); err != nil {
		skipInPublicTree(t, root, "website/docs-src (the docs site source is private-only)")
		t.Fatalf("website/docs-src/nav.toml: %v", err)
	}
	pages := publishedDocsPaths(t, root)
	var bad []string
	seen := 0
	for _, sr := range publicDocsScanRoots {
		base := filepath.Join(root, sr.dir)
		err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name := d.Name()
			if d.IsDir() {
				if name == "testdata" || name == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(name, "_test.go") || strings.Contains(name, ".test.") || !hasAnySuffix(name, sr.exts) {
				return nil
			}
			raw, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for _, m := range publicDocsURLRe.FindAllStringSubmatch(string(raw), -1) {
				seen++
				if !pages[normalizeDocsURLPath(m[1])] {
					rel, _ := filepath.Rel(root, p)
					bad = append(bad, filepath.ToSlash(rel)+": "+m[0])
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if seen == 0 {
		t.Fatal("no superbased.app/docs links found; the scan is not reading the sources")
	}
	sort.Strings(bad)
	for _, b := range bad {
		t.Errorf("%s: no page under website/docs-src publishes this path (see nav.toml)", b)
	}
}

// hasAnySuffix reports whether name ends in one of exts.
func hasAnySuffix(name string, exts []string) bool {
	for _, e := range exts {
		if strings.HasSuffix(name, e) {
			return true
		}
	}
	return false
}

// TestNormalizeDocsURLPath pins the trimming rule on the shapes copy uses.
func TestNormalizeDocsURLPath(t *testing.T) {
	cases := map[string]string{
		"/docs":                              "/docs",
		"/docs/":                             "/docs",
		"/docs/teams/getting-started.":       "/docs/teams/getting-started",
		"/docs/guides/terminals/":            "/docs/guides/terminals",
		"/docs/sdk/overview.html":            "/docs/sdk/overview",
		"/docs/reference/configuration":      "/docs/reference/configuration",
		"/docs/sdk/python/README.md":         "/docs/sdk/python/README.md",
		"/docs/getting-started/install.html": "/docs/getting-started/install",
	}
	for in, want := range cases {
		if got := normalizeDocsURLPath(in); got != want {
			t.Errorf("normalizeDocsURLPath(%q) = %q, want %q", in, got, want)
		}
	}
	if docsPublishedPath("README.md") != "overview" || docsPublishedPath("python/README.md") != "python" || docsPublishedPath("destination.md") != "destination" {
		t.Error("docsPublishedPath drifted from the generator's README rule")
	}
}
