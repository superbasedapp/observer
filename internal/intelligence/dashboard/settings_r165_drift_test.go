package dashboard

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/configschema"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// sectionWriterR165Exceptions are the section writers that may change a
// D19 or confirm-tier key with no R-165 row, each with the rule that judges
// them instead. Keep it the only escape.
var sectionWriterR165Exceptions = map[string]string{
	// [terminal.sandbox] is R-167's (rules_sandboxallow.go): it denies the
	// writes that loosen the sandbox and lets a tightening through.
	"terminal.sandbox": "R-167",
}

// TestEverySectionWriterOfAnApprovalKeyIsR165 closes review finding R-B01
// for every section, not only the ones the review named: it walks every case
// of applySectionUpdate (read from the source, so a new section is covered
// the day it lands), finds each D19-family or confirm-tier leaf the section
// can change, and requires an agent's loopback PUT of that body to be an
// R-165 denial. MCP set_setting only proposes those keys, so this route must
// not apply them for an agent either.
func TestEverySectionWriterOfAnApprovalKeyIsR165(t *testing.T) {
	sections := applySectionUpdateCases(t)
	if len(sections) < 20 {
		t.Fatalf("read only %d section cases from settings.go; the AST walk is broken", len(sections))
	}
	engine, err := policy.New(policy.Config{Mode: policy.ModeEnforce, Home: "/home/u"})
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	defaults := config.Default()
	defaultsJSON := decodedConfig(t, defaults)
	cfgPath := filepath.Join(t.TempDir(), "config.toml")

	var leaves []configschema.Leaf
	for _, l := range configschema.Leaves() {
		if l.FieldPath == "" || l.Secret {
			continue
		}
		if policy.SelfLoweringConfigKey(l.Path) || configschema.CheckKey(l.Path, nil).NeedsConfirm {
			leaves = append(leaves, l)
		}
	}
	covered := 0
	for _, name := range sections {
		if _, ok := sectionWriterR165Exceptions[name]; ok {
			continue
		}
		for _, l := range leaves {
			body, ok := writableBody(name, l, defaults, defaultsJSON, cfgPath)
			if !ok {
				continue
			}
			covered++
			line := fmt.Sprintf(`curl -X PUT http://127.0.0.1:8081/api/config/section/%s -H 'Content-Type: application/json' -d '%s'`, name, body)
			v := engine.Evaluate(policy.Event{Kind: policy.KindShellExec, Target: line, Cwd: "/home/u/p", ProjectRoot: "/home/u/p", SessionID: "s", Now: time.Now()})
			if v.RuleID != "R-165" || v.Decision != policy.DecisionDeny {
				t.Errorf("PUT /api/config/section/%s with %s changes %s (a key MCP set_setting only proposes), but R-165 does not deny it (got %s/%s): add a sectionRoute row in internal/policy/rules_selfapproval.go", name, body, l.Path, v.RuleID, v.Decision)
			}
		}
	}
	if covered == 0 {
		t.Fatal("no section wrote any approval key; the probe is broken")
	}
}

// applySectionUpdateCases reads applySectionUpdate's case labels from
// settings.go.
func applySectionUpdateCases(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "settings.go", nil, 0)
	if err != nil {
		t.Fatalf("parse settings.go: %v", err)
	}
	var out []string
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "applySectionUpdate" {
			continue
		}
		for _, st := range fn.Body.List {
			sw, ok := st.(*ast.SwitchStmt)
			if !ok {
				continue
			}
			for _, c := range sw.Body.List {
				for _, e := range c.(*ast.CaseClause).List {
					if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						s, _ := strconv.Unquote(lit.Value)
						out = append(out, s)
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func decodedConfig(t *testing.T, cfg config.Config) map[string]any {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// writableBody finds a body for section name that changes leaf l: the
// leaf's field path with its leading parts dropped one at a time (a section
// body is its own struct, nested somewhere under Config), carrying a value
// that differs from the default. ok is false when no shape changes it.
func writableBody(name string, l configschema.Leaf, defaults config.Config, defaultsJSON map[string]any, cfgPath string) (string, bool) {
	parts := strings.Split(l.FieldPath, ".")
	cur := valueAt(defaultsJSON, parts)
	for _, v := range otherValues(l, cur) {
		for i := 0; i < len(parts); i++ {
			body := nest(parts[i:], v)
			raw, err := json.Marshal(body)
			if err != nil {
				continue
			}
			cfg := config.Default()
			if err := applySectionUpdate(&cfg, name, raw, cfgPath); err != nil {
				continue
			}
			if !reflect.DeepEqual(configschema.Get(&cfg, l), configschema.Get(&defaults, l)) {
				return string(raw), true
			}
		}
	}
	return "", false
}

func valueAt(m map[string]any, path []string) any {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	return cur
}

func nest(path []string, v any) any {
	for i := len(path) - 1; i >= 0; i-- {
		v = map[string]any{path[i]: v}
	}
	return v
}

// otherValues proposes values of the leaf's kind that differ from cur.
func otherValues(l configschema.Leaf, cur any) []any {
	switch l.Kind {
	case configschema.KindBool:
		b, _ := cur.(bool)
		return []any{!b}
	case configschema.KindInt, configschema.KindFloat:
		n, _ := cur.(float64)
		return []any{n + 7}
	case configschema.KindString:
		s, _ := cur.(string)
		var out []any
		for _, e := range l.Enum {
			if e != s {
				out = append(out, e)
			}
		}
		return append(out, s+"x", "127.0.0.1:1")
	case configschema.KindStringList:
		return []any{[]any{"x"}}
	case configschema.KindStringMap:
		return []any{map[string]any{"x": "y"}}
	default:
		return []any{map[string]any{"x": map[string]any{}}, []any{map[string]any{"Name": "x"}}}
	}
}
