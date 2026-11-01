package invariant

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/govern"
)

// enforce_touchlist_test.go is the managed enforce.* authority touch-list
// drift test (roadmap F0-7, lane shr-kit; JSP-1 R12; security plan 7.2).
// A new enforce sibling must reach every closed table that enumerates its
// siblings, and missing one can make the token remotely grantable, inert or
// silently accepted. Rather than a remembered list of tables, the test walks
// every non-test Go declaration under cmd/ and internal/ with go/ast: a
// declaration that names at least four enforce siblings (by constant or by
// literal) is a table of them, and it must name every member of
// govern.EnforcementAuthorities(). The TypeScript admin picker
// (web2/src/lib/authorities.ts, its "Enforcement" group) is checked the same
// way.
//
// enforceTouchlistExempt names a declaration that enumerates the siblings and
// deliberately leaves some out, with the reason; an entry nothing matches
// fails too, so the table cannot rot.
var enforceTouchlistExempt = map[string]string{
	// The authority-to-family table: the two module enforce tokens map to no
	// resource family by their own ruling and sit in exemptFromFamilyMapping
	// with that reason instead (security plan 7.2 row 7, sandbox plan 8.2).
	"internal/govern/authorityfamilies.go:var authorityFamilyTable": "enforce.security and enforce.sandbox gate a managed pull, not a resource family (exemptFromFamilyMapping)",
}

// enforceTouchlistMin is how many enforce siblings a declaration names before
// it counts as a table of them.
const enforceTouchlistMin = 4

func TestEnforceAuthorityTouchList(t *testing.T) {
	root := repoRoot(t)
	family := govern.EnforcementAuthorities()
	if len(family) < enforceTouchlistMin {
		t.Fatalf("EnforcementAuthorities() has %d tokens; the walk is vacuous", len(family))
	}
	byConst := enforceConstNames(t, filepath.Join(root, "internal", "govern", "types.go"), family)
	if len(byConst) != len(family) {
		t.Fatalf("found %d enforce constants in internal/govern/types.go for %d tokens: %v", len(byConst), len(family), byConst)
	}
	isToken := map[string]bool{}
	for _, tok := range family {
		isToken[tok] = true
	}
	fset := token.NewFileSet()
	matched := map[string]bool{}
	tables := 0
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				n := d.Name()
				if n == "testdata" || n == "node_modules" || strings.HasPrefix(n, "_") || strings.HasPrefix(n, ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			if perr != nil {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			for _, decl := range f.Decls {
				names := map[string]bool{}
				ast.Inspect(decl, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.Ident:
						if v, ok := byConst[x.Name]; ok {
							names[v] = true
						}
					case *ast.SelectorExpr:
						if v, ok := byConst[x.Sel.Name]; ok {
							names[v] = true
						}
					case *ast.BasicLit:
						if x.Kind == token.STRING {
							if s, uerr := strconv.Unquote(x.Value); uerr == nil && isToken[s] {
								names[s] = true
							}
						}
					}
					return true
				})
				if len(names) < enforceTouchlistMin {
					continue
				}
				tables++
				t.Logf("enforce table: %s:%d %s (%d siblings)", rel, fset.Position(decl.Pos()).Line, touchlistDeclName(decl), len(names))
				key := rel + ":" + touchlistDeclName(decl)
				if _, exempt := enforceTouchlistExempt[key]; exempt {
					matched[key] = true
					continue
				}
				var missing []string
				for _, tok := range family {
					if !names[tok] {
						missing = append(missing, tok)
					}
				}
				if len(missing) > 0 {
					t.Errorf("%s:%d %s names %d enforce siblings but not %v: add them (or record why in enforceTouchlistExempt)",
						rel, fset.Position(decl.Pos()).Line, touchlistDeclName(decl), len(names), missing)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// JSP-1 counted nine tables. Two of them live in the org server
	// (internal/orgserver, cmd/observer-org), which the public tree does not
	// carry (scripts/release.sh PRIVATE_ONLY_PATHS), so there the floor is
	// the seven node-side ones.
	minTables := 9
	if inPublicTree(root) {
		minTables = 7
	}
	if tables < minTables {
		t.Fatalf("found %d enforce tables; want at least %d (JSP-1 counted nine, seven of them node side), so the walk is broken", tables, minTables)
	}
	for key := range enforceTouchlistExempt {
		if !matched[key] {
			t.Errorf("enforceTouchlistExempt names %s, which no longer enumerates the siblings", key)
		}
	}

	// The admin picker's Enforcement group (web2 is private-only).
	t.Run("web2 picker", func(t *testing.T) {
		skipInPublicTree(t, root, "web2/src/lib/authorities.ts")
		raw, err := os.ReadFile(filepath.Join(root, "web2", "src", "lib", "authorities.ts"))
		if err != nil {
			t.Fatal(err)
		}
		src := string(raw)
		start := strings.Index(src, `group: "Enforcement"`)
		if start < 0 {
			t.Fatal(`authorities.ts has no "Enforcement" group`)
		}
		end := strings.Index(src[start:], "\n  },")
		if end < 0 {
			t.Fatal("authorities.ts Enforcement group is not terminated")
		}
		group := src[start : start+end]
		offered := map[string]bool{}
		for _, m := range regexp.MustCompile(`tok: "([^"]+)"`).FindAllStringSubmatch(group, -1) {
			offered[m[1]] = true
		}
		for _, tok := range family {
			if !offered[tok] {
				t.Errorf("web2/src/lib/authorities.ts Enforcement group does not offer %s", tok)
			}
		}
	})
}

// enforceConstNames maps each Go constant name in govern/types.go whose value
// is an enforce.* token of family onto that token.
func enforceConstNames(t *testing.T, path string, family []string) map[string]string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, tok := range family {
		want[tok] = true
	}
	out := map[string]string{}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if s, uerr := strconv.Unquote(lit.Value); uerr == nil && want[s] {
					out[name.Name] = s
				}
			}
		}
	}
	return out
}

func touchlistDeclName(d ast.Decl) string {
	switch x := d.(type) {
	case *ast.FuncDecl:
		if x.Recv != nil && len(x.Recv.List) > 0 {
			return "func (" + touchlistRecv(x.Recv.List[0].Type) + ") " + x.Name.Name
		}
		return "func " + x.Name.Name
	case *ast.GenDecl:
		var names []string
		for _, s := range x.Specs {
			if vs, ok := s.(*ast.ValueSpec); ok && len(vs.Names) > 0 {
				names = append(names, vs.Names[0].Name)
			}
		}
		sort.Strings(names)
		if len(names) > 1 {
			return x.Tok.String() + " block"
		}
		if len(names) == 1 {
			return x.Tok.String() + " " + names[0]
		}
		return x.Tok.String()
	}
	return "?"
}

func touchlistRecv(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return "*" + touchlistRecv(x.X)
	case *ast.Ident:
		return x.Name
	}
	return "?"
}
