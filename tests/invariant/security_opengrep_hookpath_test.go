package invariant

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// security_opengrep_hookpath_test.go closes lane SEC-G2 audit finding 7:
// TestSecurityOpengrepNeverOnTheHookPath checks the hook packages' import
// graphs, but `observer hook` lives in cmd/observer, the one package that
// links the code rules, so an import graph cannot see it. This test walks
// cmd/observer's own declarations instead: from the hook command's entry
// (newHookCmd), every package-level function, variable and method it can
// name, transitively, and fails when that set names a declaration of the
// code rules' cmd files (security_opengrep*.go) or calls into the driver
// and network packages (internal/secscan/opengrep...).
//
// The walk is by name and without types, so it over-approximates calls: a
// selector x.M follows every method named M declared outside the code
// rules' files (a method of a code rules type is reached only through a
// value of that type, which the walk sees as a reference to the type or to
// the function that builds it). It under-approximates nothing a package
// main identifier can reach, except calls through interface values whose
// implementations live in other packages.

const hookPathEntry = "newHookCmd"

// opengrepCmdFile reports whether a cmd/observer file is one of the code
// rules' own.
func opengrepCmdFile(name string) bool { return strings.HasPrefix(name, "security_opengrep") }

type hookDecl struct {
	file string
	node ast.Node
}

func TestSecurityOpengrepNotReachedFromTheHookCommand(t *testing.T) {
	dir := filepath.Join("..", "..", "cmd", "observer")
	fset := token.NewFileSet()
	// Every non-test Go file of cmd/observer, whatever its build tags (the
	// file list go/parser.ParseDir read before it was deprecated).
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]*ast.File{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		if f.Name.Name != "main" {
			continue
		}
		files[path] = f
	}
	if len(files) == 0 {
		t.Fatal("cmd/observer: no package main")
	}
	funcs := map[string][]hookDecl{}   // package-level funcs, vars and types by name
	methods := map[string][]hookDecl{} // methods by name, outside the code rules' files
	opengrepNames := map[string]string{}
	opengrepImports := map[string]map[string]bool{} // file -> import names of the driver packages
	for path, f := range files {
		base := filepath.Base(path)
		own := opengrepCmdFile(base)
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if !strings.HasPrefix(p, modulePath+"internal/secscan/opengrep") {
				continue
			}
			name := filepath.Base(p)
			if imp.Name != nil {
				name = imp.Name.Name
			}
			if opengrepImports[base] == nil {
				opengrepImports[base] = map[string]bool{}
			}
			opengrepImports[base][name] = true
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv != nil {
					if !own {
						methods[d.Name.Name] = append(methods[d.Name.Name], hookDecl{base, d})
					}
					continue
				}
				funcs[d.Name.Name] = append(funcs[d.Name.Name], hookDecl{base, d})
				if own {
					opengrepNames[d.Name.Name] = base
				}
			case *ast.GenDecl:
				for _, sp := range d.Specs {
					var names []*ast.Ident
					switch sp := sp.(type) {
					case *ast.ValueSpec:
						names = sp.Names
					case *ast.TypeSpec:
						names = []*ast.Ident{sp.Name}
					}
					for _, n := range names {
						funcs[n.Name] = append(funcs[n.Name], hookDecl{base, sp})
						if own {
							opengrepNames[n.Name] = base
						}
					}
				}
			}
		}
	}
	if len(funcs[hookPathEntry]) == 0 {
		t.Fatalf("cmd/observer declares no %s; update the hook path entry", hookPathEntry)
	}
	type item struct {
		key, via string
	}
	seen := map[string]bool{}
	from := map[string]string{}
	queue := []item{{"func:" + hookPathEntry, ""}}
	var bad []string
	chain := func(k string) string {
		parts := []string{k}
		for from[k] != "" && len(parts) < 12 {
			k = from[k]
			parts = append(parts, k)
		}
		return strings.Join(parts, " <- ")
	}
	visit := func(key string, decls []hookDecl) {
		for _, d := range decls {
			imports := opengrepImports[d.file]
			var fn func(ast.Node) bool
			fn = func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.SelectorExpr:
					if x, ok := n.X.(*ast.Ident); ok && x.Obj == nil && imports[x.Name] {
						bad = append(bad, chain(key)+" -> "+x.Name+"."+n.Sel.Name)
					}
					if len(methods[n.Sel.Name]) > 0 {
						k := "method:" + n.Sel.Name
						if !seen[k] {
							seen[k], from[k] = true, key
							queue = append(queue, item{k, key})
						}
					}
					// The selected name is a field or method, never a
					// package-level name: only the operand is walked on.
					ast.Inspect(n.X, fn)
					return false
				case *ast.Ident:
					if n.Obj != nil && n.Obj.Kind != ast.Fun && n.Obj.Kind != ast.Typ {
						if _, local := n.Obj.Decl.(*ast.ValueSpec); !local {
							return true
						}
					}
					if file, ok := opengrepNames[n.Name]; ok && len(funcs[n.Name]) > 0 {
						bad = append(bad, chain(key)+" -> "+n.Name+" ("+file+")")
						return true
					}
					if len(funcs[n.Name]) > 0 {
						k := "func:" + n.Name
						if !seen[k] {
							seen[k], from[k] = true, key
							queue = append(queue, item{k, key})
						}
					}
				}
				return true
			}
			ast.Inspect(d.node, fn)
		}
	}
	seen[queue[0].key] = true
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		kind, name, _ := strings.Cut(it.key, ":")
		if kind == "func" {
			visit(it.key, funcs[name])
		} else {
			visit(it.key, methods[name])
		}
	}
	if len(seen) < 20 {
		t.Fatalf("the walk from %s reached only %d declarations; it is vacuous", hookPathEntry, len(seen))
	}
	sort.Strings(bad)
	for i, b := range bad {
		if i >= 20 {
			t.Errorf("... and %d more", len(bad)-i)
			break
		}
		t.Errorf("the hook command reaches the code rules: %s", b)
	}
}
