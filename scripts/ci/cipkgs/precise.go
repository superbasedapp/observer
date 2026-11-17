package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// precise.go is `cipkgs affected --precise`: the affected set for a local
// gate rerun (tools/testrunner), narrower than the push rule in two places
// where the push rule is deliberately coarse. ci.yml never passes
// --precise, so what CI tests is unchanged.
//
//  1. A change that cannot leave its package. A _test.go file is compiled
//     into its own package's test binary only (no package can import
//     another's test files), and an embedded dashboard bundle
//     (webapp/dist) is data of the package that embeds it. The push rule
//     treats both like any package file and adds every package that
//     imports the package (a cmd/observer test edit is harmless there, an
//     internal/store test edit selects several hundred packages). Here
//     such a file selects its own package, plus the packages whose test
//     files name the file or a directory above it by path (fileReaders).
//  2. A file outside every package in a tree Go tests read only by path
//     (readerTreeRules: the web sources and docs). The push rule answers
//     ALL because a test may read it. Here the readers are found the way
//     pathReaders finds the readers of a migrations directory: the
//     packages whose test files hold a path literal naming the file or a
//     directory above it. tests/invariant, which walks the tree, is always
//     selected (alwaysRun).
//
// What the scan cannot see is a test that reaches a file with no literal
// naming it or a directory above it (a walk from a computed root).
// tests/invariant is the package that does that by design and always runs;
// the full gate (--full, and every push in CI) remains the backstop.

// leafRules: changed files inside a package whose effect stays in that
// package (see 1 above). Patterns as fallbackRules.
var leafRules = []string{
	"**/*_test.go",
	"**/webapp/dist/**",
}

// leafReaderRules: the leafRules files other packages' tests may read from
// disk, so their path readers are selected too. A _test.go file is not on
// it: tests that read test sources walk the tree (tests/invariant,
// tools/testrunner/srcarchive) and assert on the tree's shape, not on one
// test's body.
var leafReaderRules = []string{
	"**/webapp/dist/**",
}

// readerTreeRules: trees outside every package that Go tests read only by
// path (see 2 above). A changed file under one selects its path readers
// instead of everything.
var readerTreeRules = []string{
	"shared/**",
	"web/**",
	"web2/**",
	"webcloud/**",
	"docs/**",
}

// changeSet is what classifyPrecise makes of a diff.
type changeSet struct {
	// dirs: packages whose change reaches the packages that import them.
	dirs map[string]bool
	// leaf: packages whose change stays in the package.
	leaf map[string]bool
	// read: changed files whose path readers are selected.
	read []string
}

// preciseRule is one row of preciseRules: the first row whose match
// accepts a changed file decides it.
type preciseRule struct {
	name  string
	match func(c, pkg string) bool
	apply func(cs *changeSet, c, pkg string) (all bool)
}

// preciseRules classify one changed file, in order. pkg is the package
// directory holding the file ("" when it is in none).
var preciseRules = []preciseRule{
	{
		"a shared input: test everything",
		func(c, _ string) bool { return anyRule(fallbackRules, c) },
		func(*changeSet, string, string) bool { return true },
	},
	{
		"a path no Go test reads: nothing",
		func(c, _ string) bool { return anyRule(unreadRules, c) },
		func(*changeSet, string, string) bool { return false },
	},
	{
		"a file that cannot leave its package: the package, and its path readers when tests may read it from disk",
		func(c, pkg string) bool { return pkg != "" && anyRule(leafRules, c) },
		func(cs *changeSet, c, pkg string) bool {
			cs.leaf[pkg] = true
			if anyRule(leafReaderRules, c) {
				cs.read = append(cs.read, c)
			}
			return false
		},
	},
	{
		"any other file of a package: the package and everything that imports it",
		func(_, pkg string) bool { return pkg != "" },
		func(cs *changeSet, _, pkg string) bool {
			cs.dirs[pkg] = true
			return false
		},
	},
	{
		"a file of a tree tests read only by path: its path readers",
		func(c, _ string) bool { return anyRule(readerTreeRules, c) },
		func(cs *changeSet, c, _ string) bool {
			cs.read = append(cs.read, c)
			return false
		},
	},
	{
		"a file outside every package that a test may read: test everything",
		func(string, string) bool { return true },
		func(*changeSet, string, string) bool { return true },
	},
}

// owningPkg returns the package directory holding the file c ("" when no
// directory above it is a package).
func owningPkg(c string, pkgDirs map[string]bool) string {
	d := path.Dir(c)
	for {
		if pkgDirs[d] {
			return d
		}
		if d == "." || d == "/" {
			return ""
		}
		d = path.Dir(d)
	}
}

// classifyPrecise is classify for --precise: preciseRules over every
// changed file. all is true when the run must test everything.
func classifyPrecise(changed []string, pkgDirs map[string]bool) (cs changeSet, all bool, why string) {
	cs = changeSet{dirs: map[string]bool{}, leaf: map[string]bool{}}
	for _, c := range changed {
		pkg := owningPkg(c, pkgDirs)
		for _, r := range preciseRules {
			if !r.match(c, pkg) {
				continue
			}
			if r.apply(&cs, c, pkg) {
				return changeSet{}, true, r.name + ": " + c
			}
			break
		}
	}
	return cs, false, ""
}

// fileReaders returns the module-relative directories of the packages
// whose _test.go files name one of the changed files, or a directory above
// one, in a path literal (treePathLiterals, readsFile). It parses nothing
// when files is empty.
func fileReaders(root string, pkgs []pkgInfo, files []string) ([]string, error) {
	if len(files) == 0 {
		return nil, nil
	}
	var res []string
	for _, p := range pkgs {
		lits, err := treePathLiterals(filepath.Join(root, filepath.FromSlash(p.rel)), p.files)
		if err != nil {
			return nil, err
		}
		if readsFile(p.rel, lits, files) {
			res = append(res, p.rel)
		}
	}
	sort.Strings(res)
	if len(res) > 0 {
		fmt.Fprintf(os.Stderr, "cipkgs: %d package(s) read a changed file by path: %s\n", len(res), strings.Join(res, " "))
	}
	return res, nil
}

// treePathLiterals returns the path candidates in the package's _test.go
// files for readsFile: every string literal that holds a slash, and every
// run of string literal arguments of a Join call joined with "/" (a single
// literal argument too: filepath.Join(root, "web", name) names "web"). A
// bare word outside a Join call is not a path candidate: "web" and "docs"
// are also surface and tab names.
func treePathLiterals(dir string, files []string) ([]string, error) {
	fset := token.NewFileSet()
	var res []string
	for _, name := range files {
		if !strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			// As testPathLiterals: the package's own compile failure is
			// what the run reports.
			continue
		}
		res = append(res, fileTreeLiterals(f)...)
	}
	return res, nil
}

func fileTreeLiterals(f *ast.File) []string {
	var res []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				if v := strings.Trim(x.Value, "`\""); strings.Contains(v, "/") {
					res = append(res, v)
				}
			}
		case *ast.CallExpr:
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Join" {
				return true
			}
			var run []string
			flush := func() {
				if len(run) > 0 {
					res = append(res, strings.Join(run, "/"))
				}
				run = nil
			}
			for _, a := range x.Args {
				if lit, ok := a.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					run = append(run, strings.Trim(lit.Value, "`\""))
					continue
				}
				flush()
			}
			flush()
		}
		return true
	})
	return res
}

// readsFile reports whether one of the literals, read from package pkgRel,
// names one of the files or a directory above one. A literal is resolved
// like readsAny resolves it: relative to the package directory and, when
// it does not climb, relative to the module root; a glob segment ends the
// path. A literal that resolves to the module root names every file.
func readsFile(pkgRel string, lits, files []string) bool {
	for _, l := range lits {
		l = filepath.ToSlash(l)
		if l == "" || strings.ContainsAny(l, " \t\n") || path.IsAbs(l) {
			continue
		}
		segs := strings.Split(l, "/")
		for i, sg := range segs {
			if strings.ContainsAny(sg, "*?[") {
				segs = segs[:i]
				break
			}
		}
		l = strings.Join(segs, "/")
		if l == "" {
			continue
		}
		cands := []string{path.Join(pkgRel, l)}
		if c := path.Clean(l); !strings.HasPrefix(l, "..") && c != "." {
			// "." from the module root would name every file; from the
			// package directory (above) it names the package's own.
			cands = append(cands, c)
		}
		for _, c := range cands {
			if strings.HasPrefix(c, "..") {
				continue // climbs out of the module
			}
			for _, f := range files {
				if c == "." || c == f || strings.HasPrefix(f, c+"/") {
					return true
				}
			}
		}
	}
	return false
}
