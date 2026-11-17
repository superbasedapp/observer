package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestClassifyPrecise has a row per preciseRules row, and the cases the
// rule exists for: a test-file edit and a rebuilt dashboard bundle stay in
// their package, a web source or a doc selects its path readers, and
// everything the push rule sends to ALL for a reason other than "a test
// may read it" still goes to ALL.
func TestClassifyPrecise(t *testing.T) {
	pkgs := map[string]bool{
		"internal/store": true, "cmd/observer": true, "tests/invariant": true,
		"internal/intelligence/dashboard": true, "internal/intelligence/dashboard/webapp": true,
		"web/taxgen": true, "tools/testrunner": true,
	}
	cases := []struct {
		name     string
		changed  []string
		wantAll  bool
		wantDirs []string
		wantLeaf []string
		wantRead []string
	}{
		{"shared input falls back", []string{"go.sum", "cmd/observer/a_test.go"}, true, nil, nil, nil},
		{"scripts/ci falls back", []string{"scripts/ci/gate-commands.tsv"}, true, nil, nil, nil},
		{"unread doc is ignored", []string{"docs/handovers/x.md"}, false, nil, nil, nil},
		{"test file stays in its package", []string{"internal/store/x_test.go"}, false, nil, []string{"internal/store"}, nil},
		{"test file and source file of one package: the package reaches its importers", []string{"internal/store/x_test.go", "internal/store/x.go"}, false, []string{"internal/store"}, []string{"internal/store"}, nil},
		{"embedded bundle stays in its package and is read by path", []string{"internal/intelligence/dashboard/webapp/dist/assets/index-abc.js"}, false, nil, []string{"internal/intelligence/dashboard/webapp"}, []string{"internal/intelligence/dashboard/webapp/dist/assets/index-abc.js"}},
		{"package testdata reaches the importers, as on a push", []string{"internal/store/testdata/a.json"}, false, []string{"internal/store"}, nil, nil},
		{"package README reaches the importers, as on a push", []string{"tools/testrunner/README.md"}, false, []string{"tools/testrunner"}, nil, nil},
		{"shared web source selects its readers", []string{"shared/components/guard/CustomRuleEditor.tsx"}, false, nil, nil, []string{"shared/components/guard/CustomRuleEditor.tsx"}},
		{"web source selects its readers", []string{"web/src/pages/x.tsx", "web2/src/y.test.tsx", "webcloud/package.json"}, false, nil, nil, []string{"web/src/pages/x.tsx", "web2/src/y.test.tsx", "webcloud/package.json"}},
		{"a Go package under web/ is a package", []string{"web/taxgen/main.go"}, false, []string{"web/taxgen"}, nil, nil},
		{"read doc selects its readers", []string{"docs/guard.md", "docs/plans/managed-saas/06.md"}, false, nil, nil, []string{"docs/guard.md", "docs/plans/managed-saas/06.md"}},
		{"top-level testdata falls back", []string{"testdata/hermes/a.db"}, true, nil, nil, nil},
		{"a script outside every package falls back", []string{"scripts/release.sh"}, true, nil, nil, nil},
		{"a root file outside every package falls back", []string{".golangci.yml"}, true, nil, nil, nil},
	}
	for _, c := range cases {
		cs, all, why := classifyPrecise(c.changed, pkgs)
		if all != c.wantAll {
			t.Errorf("%s: all = %v (%s), want %v", c.name, all, why, c.wantAll)
			continue
		}
		if all {
			continue
		}
		if got := strings.Join(keys(cs.dirs), " "); got != strings.Join(c.wantDirs, " ") {
			t.Errorf("%s: dirs = %q, want %q", c.name, got, c.wantDirs)
		}
		if got := strings.Join(keys(cs.leaf), " "); got != strings.Join(c.wantLeaf, " ") {
			t.Errorf("%s: leaf = %q, want %q", c.name, got, c.wantLeaf)
		}
		if got := strings.Join(cs.read, " "); got != strings.Join(c.wantRead, " ") {
			t.Errorf("%s: read = %q, want %q", c.name, got, c.wantRead)
		}
	}
}

// TestPreciseNeverWidensOrNarrowsThePushFallbacks: every path the push rule
// sends to ALL through fallbackRules, and every path it ignores through
// unreadRules, is decided the same way by --precise.
func TestPreciseNeverWidensOrNarrowsThePushFallbacks(t *testing.T) {
	pkgs := map[string]bool{"cmd/observer": true}
	for _, c := range []string{"go.mod", "go.sum", ".github/workflows/ci.yml", ".github/actions/x/action.yml", "scripts/ci/x.sh", "scripts/omit-tag-check.sh", "testdata/a/b", "Makefile", "Makefile.private"} {
		if _, all, _ := classifyPrecise([]string{c}, pkgs); !all {
			t.Errorf("%s: precise did not fall back to everything", c)
		}
		if _, all, _ := classify([]string{c}, pkgs); !all {
			t.Errorf("%s: the push rule no longer falls back (update this test's list)", c)
		}
	}
	for _, c := range []string{"docs/handovers/x.md", "docs/plans/x.md", "CHANGELOG.md", "website/index.html", "PROGRESS.md", ".github/workflows/npm-release.yml"} {
		cs, all, _ := classifyPrecise([]string{c}, pkgs)
		if all || len(cs.dirs)+len(cs.leaf)+len(cs.read) != 0 {
			t.Errorf("%s: precise selects something for an unread path: all=%v %+v", c, all, cs)
		}
	}
}

func TestReadsFile(t *testing.T) {
	cases := []struct {
		name, src, pkg, file string
		want                 bool
	}{
		{"the file by a climbing join", `func f() { _ = filepath.Join("..", "..", "web", "src", "components", "A.tsx") }`, "cmd/observer", "web/src/components/A.tsx", true},
		{"another file of the directory is not the file", `func f() { _ = filepath.Join("..", "..", "web", "src", "components", "A.tsx") }`, "cmd/observer", "web/src/components/B.tsx", false},
		{"a directory above the file, then a variable", `func f(n string) { _ = filepath.Join("..", "..", "web", "src", "components", n) }`, "cmd/observer", "web/src/components/B.tsx", true},
		{"a root variable then one literal", `func f(root, n string) { _ = filepath.Join(root, "shared", n) }`, "internal/x", "shared/lib/a.ts", true},
		{"a module-relative literal", `var p = "docs/guard.md"`, "internal/guard", "docs/guard.md", true},
		{"a module-relative directory literal", `var p = "web/src"`, "tests/x", "web/src/pages/a.tsx", true},
		{"a glob under the directory", `var g = "../../shared/lib/*.ts"`, "internal/x", "shared/lib/a.ts", true},
		{"a bare word outside a join is not a path", `var surface = "web"`, "internal/x", "web/src/a.tsx", false},
		{"a bare word in a list is not a path", `var s = []string{"shared", "docs"}`, "internal/x", "shared/lib/a.ts", false},
		{"a sibling tree is not the tree", `var p = "web2/src"`, "internal/x", "web/src/a.tsx", false},
		{"a path of the package's own tree is not the file", `var p = "testdata/web/a.tsx"`, "internal/x", "web/a.tsx", false},
		{"a climb to the module root names every file", `func f() { _ = filepath.Join("..", "..") }`, "tests/x", "shared/lib/a.ts", true},
		{"a dot from the package is the package, not the module", `func f() { _ = filepath.Join(".", "x") }`, "internal/x", "shared/lib/a.ts", false},
		{"an absolute path is not a tree path", `var p = "/web/src"`, "internal/x", "web/src/a.tsx", false},
		{"the embedded bundle by a climbing literal", `var d = "../webapp/dist"`, "internal/intelligence/dashboard/x", "internal/intelligence/dashboard/webapp/dist/assets/i.js", true},
	}
	for _, c := range cases {
		f, err := parser.ParseFile(token.NewFileSet(), "x_test.go", "package p\n"+c.src, 0)
		if err != nil {
			t.Fatalf("%s: parse: %v", c.name, err)
		}
		lits := fileTreeLiterals(f)
		if got := readsFile(c.pkg, lits, []string{c.file}); got != c.want {
			t.Errorf("%s: reads %s = %v, want %v (literals %q)", c.name, c.file, got, c.want, lits)
		}
	}
}

// TestFileReadersFindTheKnownReaders scans real test files that read a web
// source by path, one row each, so a reader the scan stops seeing fails
// here instead of silently dropping out of a web-only rerun.
func TestFileReadersFindTheKnownReaders(t *testing.T) {
	rows := []struct{ reader, file string }{
		{"cmd/observer", "web/src/components/SandboxSettingsCard.tsx"},
		{"cmd/observer", "web2/src/components/SandboxManagedSection.tsx"},
		{"internal/config", "web/src/pages/settings/CloudIntelligenceSection.tsx"},
	}
	root := filepath.Join("..", "..", "..")
	for _, r := range rows {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(r.file))); err != nil {
			// The public tree leaves some web sources out; the private
			// tree holds every row.
			continue
		}
		dir := filepath.Join(root, filepath.FromSlash(r.reader))
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("%s: %v", r.reader, err)
		}
		var files []string
		for _, e := range ents {
			files = append(files, e.Name())
		}
		lits, err := treePathLiterals(dir, files)
		if err != nil {
			t.Fatalf("%s: %v", r.reader, err)
		}
		if !readsFile(r.reader, lits, []string{r.file}) {
			t.Errorf("%s: the scan no longer sees it read %s by path", r.reader, r.file)
		}
	}
}
