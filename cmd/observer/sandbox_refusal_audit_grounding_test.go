package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"
	"testing"
)

// sandbox_refusal_audit_grounding_test.go pins the code facts behind the
// registry's Net.RefusalAuditTiers (lane N4): every egress gateway a launch
// serves hands its refusals to the daemon (lane N1) and closes its egress
// when the org requires the audit and the link is lost (F-012), and every
// launch path composes its run's relay, the only channel those refusals
// travel on. It parses the source (tracker F-012, audit finding N4-A5: the
// pins were text matches before), so it covers every platform's files from
// one build and judges the syntax tree, not the spelling.

// gatewayWithoutReport names the gateways that do not report, and why.
var gatewayWithoutReport = map[string]string{}

// sandboxFiles parses the non-test Go files of this package (every build
// tag: the parser ignores constraints).
func sandboxFiles(t *testing.T) (map[string]*ast.File, *token.FileSet) {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	out := map[string]*ast.File{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		out[f] = af
	}
	return out, fset
}

// isSel reports whether e is the selector pkg.name.
func isSel(e ast.Expr, pkg, name string) bool {
	s, ok := e.(*ast.SelectorExpr)
	if !ok || s.Sel.Name != name {
		return false
	}
	id, ok := s.X.(*ast.Ident)
	return ok && id.Name == pkg
}

// litField returns the value of key in a keyed composite literal.
func litField(lit *ast.CompositeLit, key string) ast.Expr {
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if id, ok := kv.Key.(*ast.Ident); ok && id.Name == key {
			return kv.Value
		}
	}
	return nil
}

// hookVars returns the names a function body assigns from a call of
// sandboxEgressRefusalHooks (x := sandboxEgressRefusalHooks(...)).
func hookVars(body *ast.BlockStmt) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		if fn, ok := call.Fun.(*ast.Ident); ok && fn.Name == "sandboxEgressRefusalHooks" {
			if id, ok := as.Lhs[0].(*ast.Ident); ok {
				out[id.Name] = true
			}
		}
		return true
	})
	return out
}

// fromHooks reports whether e is <v>.<field> for a hooks variable v.
func fromHooks(e ast.Expr, vars map[string]bool, field string) bool {
	s, ok := e.(*ast.SelectorExpr)
	if !ok || s.Sel.Name != field {
		return false
	}
	id, ok := s.X.(*ast.Ident)
	return ok && vars[id.Name]
}

// gatewaySite is one place a function makes a sandboxnet.Gateway.
type gatewaySite struct {
	file string
	pos  token.Position
	ok   string // "" when it carries both hooks, else what is missing
}

// makesGateway reports whether e makes a gateway: a literal, its address,
// or new(sandboxnet.Gateway).
func makesGateway(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.CompositeLit:
		return isSel(x.Type, "sandboxnet", "Gateway")
	case *ast.UnaryExpr:
		return makesGateway(x.X)
	case *ast.CallExpr:
		id, ok := x.Fun.(*ast.Ident)
		return ok && id.Name == "new" && len(x.Args) == 1 && isSel(x.Args[0], "sandboxnet", "Gateway")
	}
	return false
}

// gatewaySites finds every gateway a function makes: a composite literal
// (or its address), new(sandboxnet.Gateway) or a var of the type. Each
// must get Report and Closed from the run's hooks, in the literal or by an
// assignment to THAT gateway's own variable in the same function
// (x.Report = h.Report): an assignment to another receiver never counts
// (audit finding FU5-A6).
func gatewaySites(files map[string]*ast.File, fset *token.FileSet) []gatewaySite {
	var out []gatewaySite
	for name, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			vars := hookVars(fn.Body)
			// assigned[receiver][field]: hook fields set by assignment.
			assigned := map[string]map[string]bool{}
			// named maps a gateway-making node to the variable it is bound to.
			named := map[ast.Node]string{}
			bind := func(lhs ast.Expr, rhs ast.Expr) {
				if !makesGateway(rhs) {
					return
				}
				n := types.ExprString(lhs)
				named[rhs] = n
				if u, ok := rhs.(*ast.UnaryExpr); ok {
					named[u.X] = n
				}
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.AssignStmt:
					for i, l := range x.Lhs {
						if i >= len(x.Rhs) {
							continue
						}
						bind(l, x.Rhs[i])
						s, ok := l.(*ast.SelectorExpr)
						if !ok || (s.Sel.Name != "Report" && s.Sel.Name != "Closed") || !fromHooks(x.Rhs[i], vars, s.Sel.Name) {
							continue
						}
						recv := types.ExprString(s.X)
						if assigned[recv] == nil {
							assigned[recv] = map[string]bool{}
						}
						assigned[recv][s.Sel.Name] = true
					}
				case *ast.ValueSpec:
					for i, id := range x.Names {
						if i < len(x.Values) {
							bind(id, x.Values[i])
						} else if x.Type != nil && isSel(x.Type, "sandboxnet", "Gateway") {
							named[id] = id.Name
						}
					}
				}
				return true
			})
			missing := func(recv string, lit *ast.CompositeLit) string {
				var m []string
				for _, field := range []string{"Report", "Closed"} {
					if lit != nil {
						if v := litField(lit, field); v != nil && fromHooks(v, vars, field) {
							continue
						}
					}
					if recv != "" && assigned[recv][field] {
						continue
					}
					m = append(m, field)
				}
				return strings.Join(m, ", ")
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CompositeLit:
					if isSel(x.Type, "sandboxnet", "Gateway") {
						out = append(out, gatewaySite{name, fset.Position(x.Pos()), missing(named[x], x)})
					}
				case *ast.CallExpr:
					if makesGateway(x) {
						out = append(out, gatewaySite{name, fset.Position(x.Pos()), missing(named[x], nil)})
					}
				case *ast.ValueSpec:
					if x.Type != nil && isSel(x.Type, "sandboxnet", "Gateway") {
						for i, id := range x.Names {
							if i >= len(x.Values) {
								out = append(out, gatewaySite{name, fset.Position(id.Pos()), missing(named[id], nil)})
							}
						}
					}
				}
				return true
			})
		}
	}
	return out
}

func TestEveryLocalGatewayReportsRefusals(t *testing.T) {
	files, fset := sandboxFiles(t)
	sites := gatewaySites(files, fset)
	if len(sites) == 0 {
		t.Fatal("no gateway found")
	}
	byFile := map[string]int{}
	for _, s := range sites {
		byFile[s.file]++
		if _, ok := gatewayWithoutReport[s.file]; ok {
			continue
		}
		if s.ok != "" {
			t.Errorf("%s: a gateway that does not take %s from the run's refusal audit hooks (sandboxEgressRefusalHooks)", s.pos, s.ok)
		}
	}
	// The files N1 wired, and the first-start install step (F-009, audit
	// finding N1-A11): a gateway moving elsewhere fails here until this
	// list and the registry grounding say where.
	for _, f := range []string{"sandbox_helpers_linux.go", "terminal_sandbox_macdriver_darwin.go", "terminal_sandbox_mxc_run.go", "terminal_sandbox_oci_install_linux.go"} {
		if byFile[f] == 0 {
			t.Errorf("%s: no gateway (the registry's RefusalAuditSource names it)", f)
		}
	}
}

// TestGatewayPinCatchesFieldByField proves the pin judges structure: a
// literal without the hooks, a gateway built field by field without them,
// and one built field by field with them.
func TestGatewayPinCatchesFieldByField(t *testing.T) {
	cases := []struct {
		name, src, want string
	}{
		{"literal with both", `package p
func f() { a := sandboxEgressRefusalHooks(ctx, d, r); _ = &sandboxnet.Gateway{Report: a.Report, Closed: a.Closed} }`, ""},
		{"literal with the old sink", `package p
func f() { _ = &sandboxnet.Gateway{Report: sandboxEgressRefusalSink(ctx, d, r)} }`, "Report, Closed"},
		{"literal with a hooks field from elsewhere", `package p
func f() { a := other(); _ = &sandboxnet.Gateway{Report: a.Report, Closed: a.Closed} }`, "Report, Closed"},
		{"field by field without hooks", `package p
func f() { g := new(sandboxnet.Gateway); g.Report = nil }`, "Report, Closed"},
		{"field by field with hooks", `package p
func f() { a := sandboxEgressRefusalHooks(ctx, d, r); var g sandboxnet.Gateway; g.Report = a.Report; g.Closed = a.Closed }`, ""},
		{"hooks assigned to another gateway's receiver", `package p
func f() { a := sandboxEgressRefusalHooks(ctx, d, r); g := &sandboxnet.Gateway{Report: a.Report}; other.Closed = a.Closed; _ = g }`, "Closed"},
		{"literal completed by assignment to its own variable", `package p
func f() { a := sandboxEgressRefusalHooks(ctx, d, r); g := &sandboxnet.Gateway{Report: a.Report}; g.Closed = a.Closed }`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "x.go", c.src, 0)
			if err != nil {
				t.Fatal(err)
			}
			sites := gatewaySites(map[string]*ast.File{"x.go": f}, fset)
			if len(sites) != 1 || sites[0].ok != c.want {
				t.Fatalf("sites %+v, want one missing %q", sites, c.want)
			}
		})
	}
}

// constNames returns every constant name declared in files, at package
// level or inside a function.
func constNames(files map[string]*ast.File) map[string]bool {
	out := map[string]bool{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if gd, ok := n.(*ast.GenDecl); ok && gd.Tok == token.CONST {
				for _, sp := range gd.Specs {
					for _, id := range sp.(*ast.ValueSpec).Names { //nolint:forcetypeassert // a const GenDecl holds ValueSpecs
						out[id.Name] = true
					}
				}
			}
			return true
		})
	}
	return out
}

// isConstExpr reports whether e is a constant: a literal, a constant name,
// or an expression of only those (audit finding FU5-A6).
func isConstExpr(e ast.Expr, consts map[string]bool) bool {
	switch x := e.(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		return consts[x.Name]
	case *ast.ParenExpr:
		return isConstExpr(x.X, consts)
	case *ast.UnaryExpr:
		return isConstExpr(x.X, consts)
	case *ast.BinaryExpr:
		return isConstExpr(x.X, consts) && isConstExpr(x.Y, consts)
	}
	return false
}

// relayRunValue returns why a sandbox.RelayRequest literal's RunID is not
// a run (no field, a constant), "" when it names one.
func relayRunValue(lit *ast.CompositeLit, consts map[string]bool) string {
	v := litField(lit, "RunID")
	switch {
	case v == nil:
		return "no RunID"
	case isConstExpr(v, consts):
		return "RunID is the constant " + types.ExprString(v)
	}
	return ""
}

// TestRelayRunPinCatchesConstants: one row per RunID shape.
func TestRelayRunPinCatchesConstants(t *testing.T) {
	cases := []struct {
		name, src string
		bad       bool
	}{
		{"a run's id", `package p
func f() { _ = sandbox.RelayRequest{RunID: run.ID} }`, false},
		{"a string literal", `package p
func f() { _ = sandbox.RelayRequest{RunID: ""} }`, true},
		{"a named constant", `package p
const fixedRun = "r1"
func f() { _ = sandbox.RelayRequest{RunID: fixedRun} }`, true},
		{"a constant expression", `package p
const prefix = "r"
func f() { _ = sandbox.RelayRequest{RunID: prefix + "1"} }`, true},
		{"no RunID", `package p
func f() { _ = sandbox.RelayRequest{} }`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "x.go", c.src, 0)
			if err != nil {
				t.Fatal(err)
			}
			files := map[string]*ast.File{"x.go": f}
			consts := constNames(files)
			var why string
			ast.Inspect(f, func(n ast.Node) bool {
				if lit, ok := n.(*ast.CompositeLit); ok && isSel(lit.Type, "sandbox", "RelayRequest") {
					why = relayRunValue(lit, consts)
				}
				return true
			})
			if (why != "") != c.bad {
				t.Fatalf("verdict %q, want bad %v", why, c.bad)
			}
		})
	}
}

func TestEveryLaunchComposesItsRelayRun(t *testing.T) {
	files, fset := sandboxFiles(t)
	consts := constNames(files)
	n := 0
	for _, f := range files {
		ast.Inspect(f, func(node ast.Node) bool {
			lit, ok := node.(*ast.CompositeLit)
			if !ok || !isSel(lit.Type, "sandbox", "RelayRequest") {
				return true
			}
			n++
			if why := relayRunValue(lit, consts); why != "" {
				t.Errorf("%s: a launch without its relay run: %s", fset.Position(lit.Pos()), why)
			}
			return true
		})
	}
	// bwrap, process_lite, oci, the microVM, Seatbelt, Apple container and
	// the hosted rows (the MXC helper reads the run from its own plan, and
	// its gateway's hooks name plan.RunID: the gateway pin above).
	if n < 7 {
		t.Errorf("found %d relay requests, want at least 7", n)
	}
}
