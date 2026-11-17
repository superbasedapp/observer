package planlint

import (
	"go/ast"
	"go/token"
	"sort"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/entitlements"
)

// mentionsPlan reports whether e names a plan or tier: an identifier or
// field whose lower-cased name starts or ends with "plan" or contains
// "tier".
func mentionsPlan(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok {
			return !found
		}
		l := strings.ToLower(id.Name)
		if strings.HasPrefix(l, "plan") || strings.HasSuffix(l, "plan") || strings.Contains(l, "tier") {
			found = true
		}
		return !found
	})
	return found
}

// PlanLiterals returns the string literals of f that hard-code a plan name,
// in source order: a distinctive spelling anywhere, any other only where it
// is compared with (== or !=) or switched on an expression naming a plan
// or tier.
func PlanLiterals(f *ast.File) []*ast.BasicLit {
	var out []*ast.BasicLit
	seen := map[*ast.BasicLit]bool{}
	add := func(e ast.Expr, inPlanContext bool) {
		lit, ok := e.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING || seen[lit] {
			return
		}
		v, err := strconv.Unquote(lit.Value)
		if err != nil {
			return
		}
		if p, anywhere := entitlements.PlanName(v); p != "" && (anywhere || inPlanContext) {
			seen[lit] = true
			out = append(out, lit)
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.BinaryExpr:
			if n.Op == token.EQL || n.Op == token.NEQ {
				add(n.X, mentionsPlan(n.Y))
				add(n.Y, mentionsPlan(n.X))
			}
		case *ast.SwitchStmt:
			if n.Tag != nil && mentionsPlan(n.Tag) {
				for _, s := range n.Body.List {
					if cc, ok := s.(*ast.CaseClause); ok {
						for _, e := range cc.List {
							add(e, true)
						}
					}
				}
			}
		case *ast.BasicLit:
			add(n, false)
		}
		return true
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Pos() < out[j].Pos() })
	return out
}
