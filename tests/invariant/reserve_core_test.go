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

// The structural row of plan 07 M7a.5: reservation arithmetic lives in ONE
// place, the pure core internal/reserve. A ledger keeps its storage (its
// SQL, its row locks, its error vocabulary) and hands the core values; it
// never compares a counter to a cap itself.
//
// "Reservation arithmetic" is defined narrowly and concretely: an ordering
// comparison (<, <=, >, >=) in non-test Go of a ledger package one of whose
// operands is a counter or cap the old ledger code compared - a value named
// in reserveArithmeticOperands, seen through parentheses, numeric
// conversions, index expressions, selectors and sums.

// reserveLedgerDirs are the ledger packages scanned.
var reserveLedgerDirs = []string{
	"internal/cloudserver/store",
	"internal/aigateway/gwstore",
	"internal/aigateway/gwhttp",
}

// reserveAdoptedFiles must import the core: they are the callers whose own
// reservation arithmetic was deleted.
var reserveAdoptedFiles = []string{
	"internal/cloudserver/store/reserve.go",
	"internal/cloudserver/store/spend.go",
	"internal/aigateway/gwstore/budgetstore.go",
	"internal/aigateway/budget.go",
}

// reserveArithmeticOperands are the counter and cap names the deleted
// arithmetic compared (cloud: used >= cap, gUsed >= gCap, spent >= lim;
// gateway: projected <= capValue over committed + worst case).
var reserveArithmeticOperands = map[string]bool{
	"used": true, "gUsed": true, "cap": true, "gCap": true, "spent": true, "lim": true,
	"capValue": true, "projected": true, "committedUSD": true, "committedTokens": true,
}

// reservePending are the functions that still hold such a comparison, each
// with the reason it is not yet in the core. A row that no longer matches
// anything fails, so the list only shrinks.
var reservePending = map[string]string{
	"internal/cloudserver/store/usage.go:usageWarningFor": "the usage snapshot's display bands (warn/critical/exhausted), not a reservation " +
		"decision; its exhausted band restates reserve's over-cap rule for a one-unit hold",
}

const reserveCoreImport = "github.com/marmutapp/superbased-observer/internal/reserve"

// TestReservationArithmeticLivesInTheCore fails when a ledger package
// compares a counter to a cap outside the pending list, when a pending row
// is stale, or when an adopted caller stops importing the core.
func TestReservationArithmeticLivesInTheCore(t *testing.T) {
	skipInPublicTree(t, repoRoot(t), "internal/aigateway")
	t.Parallel()
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	matched := map[string]bool{}
	for _, dir := range reserveLedgerDirs {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			rel := dir + "/" + name
			f, err := parser.ParseFile(fset, filepath.Join(root, dir, name), nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", rel, err)
			}
			for _, hit := range reserveArithmeticHits(fset, f) {
				key := rel + ":" + hit.fn
				if _, ok := reservePending[key]; ok {
					matched[key] = true
					continue
				}
				t.Errorf("%s:%d (%s) compares %q to a cap: reservation arithmetic belongs in internal/reserve (plan 07 M7a.5); call reserve.Check/Admit/Settle instead",
					rel, hit.line, hit.fn, hit.operand)
			}
		}
	}
	for key, reason := range reservePending {
		if !matched[key] {
			t.Errorf("pending row %s (%s) no longer matches: delete it", key, reason)
		}
	}
	for _, rel := range reserveAdoptedFiles {
		f, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(rel)), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		found := false
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == reserveCoreImport {
				found = true
			}
		}
		if !found {
			t.Errorf("%s no longer imports %s: an adopted ledger decides through the core", rel, reserveCoreImport)
		}
	}
}

// TestReservationArithmeticHits proves the detector bites on the deleted
// shapes and passes their replacements.
func TestReservationArithmeticHits(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{name: "cloud cycle", src: "func f(used, cap int) bool { return used >= cap }", want: []string{"f:cap", "f:used"}},
		{name: "cloud pool", src: "func f(gUsed, gCap int64) bool { return gUsed >= gCap }", want: []string{"f:gCap", "f:gUsed"}},
		{name: "cloud ceiling", src: "func f(spent map[string]float64, lim float64) bool { return lim > 0 && spent[\"d\"] >= lim }", want: []string{"f:lim", "f:lim", "f:spent"}},
		{name: "gateway sum", src: "func f(committedUSD, wc, capValue float64) bool { return committedUSD+wc > capValue }", want: []string{"f:capValue", "f:committedUSD"}},
		{name: "conversion", src: "func f(used int, c float64) bool { return float64(used) > c }", want: []string{"f:used"}},
		{name: "selector", src: "type r struct{ used int }\nfunc f(x r) bool { return x.used < 3 }", want: []string{"f:used"}},
		{name: "equality is not ordering", src: "func f(used int) bool { return used == 0 }"},
		{name: "unrelated names", src: "func f(n, max int) bool { return n > max }"},
		{name: "a call to the core", src: "func f(used int) bool { return check(used) }"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "x.go", "package x\n"+c.src+"\n", 0)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, h := range reserveArithmeticHits(fset, f) {
				got = append(got, h.fn+":"+h.operand)
			}
			sort.Strings(got)
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Fatalf("hits = %v, want %v", got, c.want)
			}
		})
	}
}

type reserveHit struct {
	fn, operand string
	line        int
}

// reserveArithmeticHits returns every ordering comparison in f's functions
// with an operand named in reserveArithmeticOperands (one hit per operand).
func reserveArithmeticHits(fset *token.FileSet, f *ast.File) []reserveHit {
	var hits []reserveHit
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			be, ok := n.(*ast.BinaryExpr)
			if !ok {
				return true
			}
			switch be.Op {
			case token.LSS, token.LEQ, token.GTR, token.GEQ:
			default:
				return true
			}
			seen := map[string]bool{}
			for _, side := range []ast.Expr{be.X, be.Y} {
				for _, name := range reserveOperandNames(side) {
					if reserveArithmeticOperands[name] && !seen[name] {
						seen[name] = true
						hits = append(hits, reserveHit{fn: fd.Name.Name, operand: name, line: fset.Position(be.Pos()).Line})
					}
				}
			}
			return true
		})
	}
	return hits
}

// reserveOperandNames names what an operand is: through parentheses,
// single-argument conversions, index expressions, selectors (the field
// name) and arithmetic.
func reserveOperandNames(e ast.Expr) []string {
	switch v := e.(type) {
	case *ast.Ident:
		return []string{v.Name}
	case *ast.ParenExpr:
		return reserveOperandNames(v.X)
	case *ast.SelectorExpr:
		return []string{v.Sel.Name}
	case *ast.IndexExpr:
		return reserveOperandNames(v.X)
	case *ast.BinaryExpr:
		return append(reserveOperandNames(v.X), reserveOperandNames(v.Y)...)
	case *ast.CallExpr:
		if fn, ok := v.Fun.(*ast.Ident); ok && len(v.Args) == 1 && reserveNumericConversions[fn.Name] {
			return reserveOperandNames(v.Args[0])
		}
	}
	return nil
}

// reserveNumericConversions are the conversions the detector sees through.
var reserveNumericConversions = map[string]bool{
	"int": true, "int32": true, "int64": true, "uint": true, "uint64": true, "float32": true, "float64": true,
}
