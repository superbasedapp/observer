package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// sweepLikeName matches an exported method name that looks like a sweep: a
// sweep verb as its prefix (the review's Sweep|Prune|Expire|Purge|Reap, plus
// the minimise and cleanup verbs) or an expiry or retention word anywhere.
var sweepLikeName = regexp.MustCompile(`^(Sweep|Prune|Expire|Purge|Reap|Minimi[sz]e|Evict|Vacuum|Cleanup|GC)|Expired|Retention`)

// repoRoot is the repository root relative to this package's directory, the
// working directory of its tests.
const repoRoot = "../../.."

// parseNonTestDir parses every non-test Go file of dir.
func parseNonTestDir(t *testing.T, dir string) []*ast.File {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", filepath.Join(dir, name), err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatalf("%s holds no non-test Go file", dir)
	}
	return files
}

// exportedMethods returns every exported method declared in files, keyed by
// method name, with its receiver type name.
func exportedMethods(files []*ast.File) map[string][]string {
	out := map[string][]string{}
	for _, f := range files {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 || !fn.Name.IsExported() {
				continue
			}
			recv := fn.Recv.List[0].Type
			if star, ok := recv.(*ast.StarExpr); ok {
				recv = star.X
			}
			if id, ok := recv.(*ast.Ident); ok {
				out[fn.Name.Name] = append(out[fn.Name.Name], id.Name)
			}
		}
	}
	return out
}

// selectorNames returns every selector name in files: x.Name, whether it is
// called or passed as a method value (SweepOIDCCodes is passed, not called).
func selectorNames(files []*ast.File) map[string]bool {
	out := map[string]bool{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				out[sel.Sel.Name] = true
			}
			return true
		})
	}
	return out
}

// TestEveryStoreSweepHasASweeperRow pins the sweepers table (CLOUD-01): every
// exported sweep-like method of this package has exactly one row; every row
// names a method of *Store that exists; every row says how it runs; a
// conditional or operator row says why; and the package a row names as its
// site references the method in non-test code. Before CLOUD-01 the row for
// SweepExpiredEvidence could not be written truthfully: no package called it.
func TestEveryStoreSweepHasASweeperRow(t *testing.T) {
	methods := exportedMethods(parseNonTestDir(t, "."))

	rows := map[string]sweeper{}
	for _, r := range sweepers {
		if _, dup := rows[r.method]; dup {
			t.Errorf("sweepers: %s has two rows", r.method)
		}
		rows[r.method] = r
	}

	var names []string
	for name := range methods {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !sweepLikeName.MatchString(name) {
			continue
		}
		if _, ok := rows[name]; !ok {
			t.Errorf("%s.%s looks like a sweep but has no row in sweepers (sweepers.go): name the process and package that schedule it, or why it is not on a timer",
				strings.Join(methods[name], "/"), name)
		}
	}

	sites := map[string]map[string]bool{}
	for _, r := range sweepers {
		recvs, ok := methods[r.method]
		if !ok {
			t.Errorf("sweepers row %s names no exported method of this package (stale row)", r.method)
			continue
		}
		if len(recvs) != 1 || recvs[0] != "Store" {
			t.Errorf("sweepers row %s: receivers %v, want the one *Store method", r.method, recvs)
		}
		switch r.run {
		case sweeperLoop:
		case sweeperConditionalLoop, sweeperOperator:
			if strings.TrimSpace(r.note) == "" {
				t.Errorf("sweepers row %s (%s) needs a note saying why it is not an always-on loop", r.method, r.run)
			}
		default:
			t.Errorf("sweepers row %s: unknown run %q", r.method, r.run)
		}
		if strings.TrimSpace(r.process) == "" || strings.TrimSpace(r.cadence) == "" {
			t.Errorf("sweepers row %s needs a process and a cadence", r.method)
		}
		if strings.TrimSpace(r.site) == "" {
			t.Errorf("sweepers row %s names no site", r.method)
			continue
		}
		refs, ok := sites[r.site]
		if !ok {
			refs = selectorNames(parseNonTestDir(t, filepath.Join(repoRoot, filepath.FromSlash(r.site))))
			sites[r.site] = refs
		}
		if !refs[r.method] {
			t.Errorf("sweepers row %s says %s runs it, but no non-test code in %s references .%s (a call or a method value): the sweep is not scheduled",
				r.method, r.site, r.site, r.method)
		}
	}
}
