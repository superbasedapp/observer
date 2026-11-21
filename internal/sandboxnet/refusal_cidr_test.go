package sandboxnet

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxcidr"
)

// TestEveryPolicyRuleIsMapped (tracker F-009, audit finding N1-A7): every
// rule the policy can return is mapped to the closed vocabulary by its own
// row, read from the compiled tables (policyRules and the private ranges
// internal/sandboxcidr owns), so a rule added there without a mapping row
// fails here instead of being recorded by the fallback as ssrf-floor.
func TestEveryPolicyRuleIsMapped(t *testing.T) {
	t.Parallel()
	var names []string
	for _, r := range policyRules {
		names = append(names, r.name)
	}
	for _, r := range sandboxcidr.PrivateRanges() {
		names = append(names, r.Rule)
	}
	for _, n := range names {
		if _, _, ok := MapGatewayRule(n); !ok {
			t.Errorf("policy rule %q has no row in gatewayRuleRows", n)
		}
	}
	// Each private range's rule is a policy row too (the policy refuses
	// it), so a range added in sandboxcidr without a policy row fails.
	rows := map[string]bool{}
	for _, r := range policyRules {
		rows[r.name] = true
	}
	for _, r := range sandboxcidr.PrivateRanges() {
		if !rows[r.Rule] {
			t.Errorf("private range rule %q has no policy row", r.Rule)
		}
	}
}

// TestSandboxCIDRRuleConstantsAreMapped parses internal/sandboxcidr and
// fails when it declares a Rule constant whose value has no mapping row
// (the source half of N1-A7: the re-export list in policy.go is not where
// a new rule is declared).
func TestSandboxCIDRRuleConstantsAreMapped(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob(filepath.Join("..", "sandboxcidr", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no sandboxcidr source: %v", err)
	}
	fset := token.NewFileSet()
	n := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec) //nolint:forcetypeassert // a const GenDecl holds ValueSpecs
				for i, name := range vs.Names {
					if !ruleConstName.MatchString(name.Name) || i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						t.Errorf("%s: %s is not a string literal", fset.Position(name.Pos()), name.Name)
						continue
					}
					v, _ := strconv.Unquote(lit.Value)
					n++
					if _, _, ok := MapGatewayRule(v); !ok {
						t.Errorf("sandboxcidr.%s (%q) has no row in gatewayRuleRows", name.Name, v)
					}
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("no rule constant found in internal/sandboxcidr")
	}
}
