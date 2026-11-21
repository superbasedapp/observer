package complexity

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
	"github.com/marmutapp/superbased-observer/internal/codeintel/parse"
)

func fn(kind string, sb, eb int) codeintel.Node {
	return codeintel.Node{Kind: kind, Name: kind, StartByte: sb, EndByte: eb, StartLine: 1, EndLine: 2}
}

func TestCount(t *testing.T) {
	cases := []struct {
		name    string
		nodes   []codeintel.Node
		offsets []int
		want    []int
	}{
		{"no decisions is 1", []codeintel.Node{fn("function", 0, 100)}, nil, []int{1}},
		{"decisions inside", []codeintel.Node{fn("function", 0, 100)}, []int{10, 20, 30}, []int{4}},
		{"end is exclusive", []codeintel.Node{fn("function", 0, 100)}, []int{0, 99, 100}, []int{3}},
		{"repeated offset counts once", []codeintel.Node{fn("function", 0, 100)}, []int{10, 10}, []int{2}},
		{"outside every function", []codeintel.Node{fn("function", 10, 20)}, []int{5, 25}, []int{1}},
		{
			"innermost wins (nested function)",
			[]codeintel.Node{fn("function", 0, 100), fn("function", 20, 50)},
			[]int{10, 30, 40, 60},
			[]int{3, 3},
		},
		{
			"method inside a class",
			[]codeintel.Node{fn("class", 0, 200), fn("method", 10, 90), fn("method", 100, 190)},
			[]int{5, 20, 110, 120, 195},
			[]int{0, 2, 3},
		},
		{
			"siblings then a later decision",
			[]codeintel.Node{fn("function", 0, 10), fn("function", 10, 20), fn("function", 30, 40)},
			[]int{5, 15, 25, 35},
			[]int{2, 2, 2},
		},
		{"unsorted input", []codeintel.Node{fn("function", 50, 60), fn("function", 0, 40)}, []int{55, 5, 6}, []int{2, 3}},
		{"no exact span is not counted", []codeintel.Node{fn("function", 10, 0)}, []int{5}, []int{0}},
		{"type is not counted", []codeintel.Node{fn("type", 0, 100)}, []int{5}, []int{0}},
		{"same start: outer first, inner innermost", []codeintel.Node{fn("function", 0, 50), fn("method", 0, 100)}, []int{10, 70}, []int{2, 2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodes := append([]codeintel.Node(nil), tc.nodes...)
			Count(nodes, tc.offsets)
			for i, n := range nodes {
				if n.Complexity != tc.want[i] {
					t.Errorf("node %d (%s %d-%d): complexity %d, want %d", i, n.Kind, n.StartByte, n.EndByte, n.Complexity, tc.want[i])
				}
			}
		})
	}
}

func TestGoDecision(t *testing.T) {
	for _, r := range GoRules() {
		if !GoDecision(r.Node, r.Token) {
			t.Errorf("row %s %q not found", r.Node, r.Token)
		}
	}
	for _, miss := range [][2]string{{"IfStmt", "else"}, {"BinaryExpr", "+"}, {"CaseClause", "default"}, {"SwitchStmt", "switch"}} {
		if GoDecision(miss[0], miss[1]) {
			t.Errorf("%v must not be a decision", miss)
		}
	}
}

// TestRuleTableShape pins every row: a node kind, a token, a construct
// from the closed vocabulary, a pattern that captures the decision as the
// extraction harness expects, and no repeated row within a language.
func TestRuleTableShape(t *testing.T) {
	constructs := map[Construct]bool{Branch: true, Loop: true, Case: true, Catch: true, Logical: true, Ternary: true}
	check := func(lang string, rules []Rule) {
		seen := map[string]bool{}
		for _, r := range rules {
			if r.Node == "" || r.Token == "" {
				t.Errorf("%s: row %+v has no node or token", lang, r)
			}
			if !constructs[r.Construct] {
				t.Errorf("%s: row %s %q: construct %q not in the vocabulary", lang, r.Node, r.Token, r.Construct)
			}
			k := r.Node + "\x00" + r.Token
			if seen[k] {
				t.Errorf("%s: row %s %q repeated", lang, r.Node, r.Token)
			}
			seen[k] = true
		}
	}
	check("go", GoRules())
	for _, lang := range TreeSitterLanguages() {
		rules := TreeSitterRules(lang)
		check(string(lang), rules)
		for _, r := range rules {
			if q := RuleQuery(r); !strings.Contains(q, "@name @reference.call") {
				t.Errorf("%s: row %s %q: pattern %q must capture @name @reference.call", lang, r.Node, r.Token, q)
			}
		}
		if q := Query(lang); strings.Count(q, "\n") != len(rules) {
			t.Errorf("%s: query has %d patterns, want %d", lang, strings.Count(q, "\n"), len(rules))
		}
	}
}

func TestSupported(t *testing.T) {
	for _, lang := range []codeintel.Language{parse.LangGo, parse.LangRust, parse.LangPython, parse.LangTypeScript, parse.LangTSX, parse.LangJSX, parse.LangLua} {
		if !Supported(lang) {
			t.Errorf("%s: want supported", lang)
		}
	}
	if Supported("cobol") || Query("cobol") != "" || Query(parse.LangGo) != "" {
		t.Error("an unknown language and Go have no tree-sitter query")
	}
}
