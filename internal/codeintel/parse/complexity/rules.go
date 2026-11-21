package complexity

import (
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
	"github.com/marmutapp/superbased-observer/internal/codeintel/parse"
)

// Construct names what a rule counts. Closed vocabulary, for the docs and
// the tests; Count does not branch on it.
type Construct string

// The closed Construct vocabulary.
const (
	// Branch: if, else if / elif / elsif / elseif, unless, guard, a match
	// guard, a comprehension's if.
	Branch Construct = "branch"
	// Loop: for, foreach, for-in/of, while, until, do-while, repeat.
	Loop Construct = "loop"
	// Case: one switch case or match arm (a default arm is not counted
	// where the grammar tells it apart; see the row notes).
	Case Construct = "case"
	// Catch: catch, except, rescue.
	Catch Construct = "catch"
	// Logical: a short-circuit operator (&&, ||, and, or) or a
	// null-coalescing one (??, ?:).
	Logical Construct = "logical"
	// Ternary: a conditional expression (a ? b : c, b if a else c).
	Ternary Construct = "ternary"
)

// Rule is one decision point of one language: a grammar node kind and the
// token inside it that marks the decision. For a tree-sitter language Node
// is the grammar's node kind and Token an anonymous token child; the
// generated query is `(Node "Token" @name @reference.call)`, which the
// extraction harness (parse/treesitter/grammars/extract.c) emits as a
// record at the token's position. For Go, Node is the go/ast type name and
// Token the keyword or operator the go/ast backend reports for it.
type Rule struct {
	Node      string
	Token     string
	Construct Construct
	// Query replaces the generated pattern when the rule needs a child or a
	// text predicate (it must capture the decision token as
	// `@name @reference.call`).
	Query string
	// Note says what the row deliberately counts or leaves out.
	Note string
}

// pattern is the tree-sitter query pattern of r.
func (r Rule) pattern() string {
	if r.Query != "" {
		return r.Query
	}
	return fmt.Sprintf("(%s %q @name @reference.call)", r.Node, r.Token)
}

// Kinds are the node kinds a figure is counted for.
var Kinds = []string{"function", "method"}

// goRules are Go's decision points, matched by the go/ast backend
// (gocyclo's set). Go has no ternary and no catch.
var goRules = []Rule{
	{Node: "IfStmt", Token: "if", Construct: Branch, Note: "an else-if is a nested IfStmt"},
	{Node: "ForStmt", Token: "for", Construct: Loop, Note: "a bare for {} counts, as gocyclo does"},
	{Node: "RangeStmt", Token: "for", Construct: Loop},
	{Node: "CaseClause", Token: "case", Construct: Case, Note: "default is not counted"},
	{Node: "CommClause", Token: "case", Construct: Case, Note: "a select case; default is not counted"},
	{Node: "BinaryExpr", Token: "&&", Construct: Logical},
	{Node: "BinaryExpr", Token: "||", Construct: Logical},
}

// jsRules serve JavaScript, JSX, TypeScript and TSX (one grammar family).
var jsRules = []Rule{
	{Node: "if_statement", Token: "if", Construct: Branch, Note: "an else-if is a nested if_statement"},
	{Node: "for_statement", Token: "for", Construct: Loop},
	{Node: "for_in_statement", Token: "for", Construct: Loop, Note: "for-in and for-of"},
	{Node: "while_statement", Token: "while", Construct: Loop},
	{Node: "do_statement", Token: "do", Construct: Loop},
	{Node: "switch_case", Token: "case", Construct: Case, Note: "switch_default is not counted"},
	{Node: "catch_clause", Token: "catch", Construct: Catch},
	{Node: "ternary_expression", Token: "?", Construct: Ternary},
	{Node: "binary_expression", Token: "&&", Construct: Logical},
	{Node: "binary_expression", Token: "||", Construct: Logical},
	{Node: "binary_expression", Token: "??", Construct: Logical},
}

// cRules serve C; cppRules extend them for C++.
var cRules = []Rule{
	{Node: "if_statement", Token: "if", Construct: Branch, Note: "an else-if is a nested if_statement"},
	{Node: "for_statement", Token: "for", Construct: Loop},
	{Node: "while_statement", Token: "while", Construct: Loop},
	{Node: "do_statement", Token: "do", Construct: Loop},
	{Node: "case_statement", Token: "case", Construct: Case, Note: "a default label has no case token"},
	{Node: "conditional_expression", Token: "?", Construct: Ternary},
	{Node: "binary_expression", Token: "&&", Construct: Logical},
	{Node: "binary_expression", Token: "||", Construct: Logical},
}

var cppRules = append(append([]Rule(nil), cRules...),
	Rule{Node: "for_range_loop", Token: "for", Construct: Loop},
	Rule{Node: "catch_clause", Token: "catch", Construct: Catch},
)

// treeSitterRules are the decision points of every tree-sitter language,
// keyed by language. A language absent here gets no figure.
var treeSitterRules = map[codeintel.Language][]Rule{
	parse.LangRust: {
		{Node: "if_expression", Token: "if", Construct: Branch, Note: "if and if let; an else-if is a nested if_expression"},
		{Node: "match_pattern", Token: "if", Construct: Branch, Note: "a match arm's guard"},
		{Node: "while_expression", Token: "while", Construct: Loop},
		{Node: "for_expression", Token: "for", Construct: Loop},
		{
			Node: "match_arm", Token: "=>", Construct: Case, Note: "a `_` arm is not counted",
			Query: `(match_arm pattern: (match_pattern) @_p "=>" @name @reference.call (#not-eq? @_p "_"))`,
		},
		{Node: "binary_expression", Token: "&&", Construct: Logical},
		{Node: "binary_expression", Token: "||", Construct: Logical},
	},
	parse.LangTypeScript: jsRules,
	parse.LangTSX:        jsRules,
	parse.LangJavaScript: jsRules,
	parse.LangJSX:        jsRules,
	parse.LangPython: {
		{Node: "if_statement", Token: "if", Construct: Branch},
		{Node: "elif_clause", Token: "elif", Construct: Branch},
		{Node: "conditional_expression", Token: "if", Construct: Ternary},
		{Node: "if_clause", Token: "if", Construct: Branch, Note: "a comprehension's if"},
		{Node: "while_statement", Token: "while", Construct: Loop},
		{Node: "for_statement", Token: "for", Construct: Loop},
		{Node: "for_in_clause", Token: "for", Construct: Loop, Note: "a comprehension's for"},
		{Node: "case_clause", Token: "case", Construct: Case, Note: "every arm, a `case _` included"},
		{Node: "except_clause", Token: "except", Construct: Catch, Note: "except and except*"},
		{Node: "boolean_operator", Token: "and", Construct: Logical},
		{Node: "boolean_operator", Token: "or", Construct: Logical},
	},
	parse.LangJava: {
		{Node: "if_statement", Token: "if", Construct: Branch, Note: "an else-if is a nested if_statement"},
		{Node: "for_statement", Token: "for", Construct: Loop},
		{Node: "enhanced_for_statement", Token: "for", Construct: Loop},
		{Node: "while_statement", Token: "while", Construct: Loop},
		{Node: "do_statement", Token: "do", Construct: Loop},
		{Node: "switch_label", Token: "case", Construct: Case, Note: "statement and arrow forms; default is not counted"},
		{Node: "catch_clause", Token: "catch", Construct: Catch},
		{Node: "ternary_expression", Token: "?", Construct: Ternary},
		{Node: "binary_expression", Token: "&&", Construct: Logical},
		{Node: "binary_expression", Token: "||", Construct: Logical},
	},
	parse.LangC:   cRules,
	parse.LangCPP: cppRules,
	parse.LangCSharp: {
		{Node: "if_statement", Token: "if", Construct: Branch, Note: "an else-if is a nested if_statement"},
		{Node: "for_statement", Token: "for", Construct: Loop},
		{Node: "foreach_statement", Token: "foreach", Construct: Loop},
		{Node: "while_statement", Token: "while", Construct: Loop},
		{Node: "do_statement", Token: "do", Construct: Loop},
		{Node: "switch_section", Token: "case", Construct: Case, Note: "each case label; default is not counted"},
		{Node: "when_clause", Token: "when", Construct: Branch, Note: "a case guard"},
		{Node: "switch_expression_arm", Token: "=>", Construct: Case, Note: "every arm, a `_` arm included"},
		{Node: "catch_clause", Token: "catch", Construct: Catch},
		{Node: "conditional_expression", Token: "?", Construct: Ternary},
		{Node: "binary_expression", Token: "&&", Construct: Logical},
		{Node: "binary_expression", Token: "||", Construct: Logical},
		{Node: "binary_expression", Token: "??", Construct: Logical},
	},
	parse.LangRuby: {
		{Node: "if", Token: "if", Construct: Branch},
		{Node: "elsif", Token: "elsif", Construct: Branch},
		{Node: "unless", Token: "unless", Construct: Branch},
		{Node: "if_modifier", Token: "if", Construct: Branch},
		{Node: "unless_modifier", Token: "unless", Construct: Branch},
		{Node: "while", Token: "while", Construct: Loop},
		{Node: "until", Token: "until", Construct: Loop},
		{Node: "for", Token: "for", Construct: Loop},
		{Node: "while_modifier", Token: "while", Construct: Loop},
		{Node: "until_modifier", Token: "until", Construct: Loop},
		{Node: "when", Token: "when", Construct: Case, Note: "a case's else is not counted"},
		{Node: "rescue", Token: "rescue", Construct: Catch},
		{Node: "conditional", Token: "?", Construct: Ternary},
		{Node: "binary", Token: "&&", Construct: Logical},
		{Node: "binary", Token: "||", Construct: Logical},
		{Node: "binary", Token: "and", Construct: Logical},
		{Node: "binary", Token: "or", Construct: Logical},
	},
	parse.LangPHP: {
		{Node: "if_statement", Token: "if", Construct: Branch, Note: "an `else if` is a nested if_statement"},
		{Node: "else_if_clause", Token: "elseif", Construct: Branch},
		{Node: "for_statement", Token: "for", Construct: Loop},
		{Node: "foreach_statement", Token: "foreach", Construct: Loop},
		{Node: "while_statement", Token: "while", Construct: Loop},
		{Node: "do_statement", Token: "do", Construct: Loop},
		{Node: "case_statement", Token: "case", Construct: Case, Note: "default is a separate node, not counted"},
		{Node: "match_conditional_expression", Token: "=>", Construct: Case, Note: "a match arm; the default arm is a separate node, not counted"},
		{Node: "catch_clause", Token: "catch", Construct: Catch},
		{Node: "conditional_expression", Token: "?", Construct: Ternary},
		{Node: "binary_expression", Token: "&&", Construct: Logical},
		{Node: "binary_expression", Token: "||", Construct: Logical},
		{Node: "binary_expression", Token: "and", Construct: Logical},
		{Node: "binary_expression", Token: "or", Construct: Logical},
		{Node: "binary_expression", Token: "??", Construct: Logical},
	},
	parse.LangKotlin: {
		{Node: "if_expression", Token: "if", Construct: Branch, Note: "an else-if is a nested if_expression"},
		{Node: "for_statement", Token: "for", Construct: Loop},
		{Node: "while_statement", Token: "while", Construct: Loop},
		{Node: "do_while_statement", Token: "do", Construct: Loop},
		{
			Node: "when_entry", Token: "->", Construct: Case, Note: "an entry with a condition; the else entry is not counted",
			Query: `(when_entry (when_condition) "->" @name @reference.call)`,
		},
		{Node: "catch_block", Token: "catch", Construct: Catch},
		{Node: "conjunction_expression", Token: "&&", Construct: Logical},
		{Node: "disjunction_expression", Token: "||", Construct: Logical},
		{Node: "elvis_expression", Token: "?:", Construct: Logical},
	},
	parse.LangSwift: {
		{Node: "if_statement", Token: "if", Construct: Branch, Note: "an else-if is a nested if_statement"},
		{Node: "guard_statement", Token: "guard", Construct: Branch},
		{Node: "for_statement", Token: "for", Construct: Loop},
		{Node: "while_statement", Token: "while", Construct: Loop},
		{Node: "repeat_while_statement", Token: "repeat", Construct: Loop},
		{Node: "switch_entry", Token: "case", Construct: Case, Note: "default uses default_keyword, not counted"},
		{
			Node: "catch_keyword", Token: "catch", Construct: Catch, Note: "the grammar's catch keyword is a named node",
			Query: `(catch_keyword) @name @reference.call`,
		},
		{Node: "ternary_expression", Token: "?", Construct: Ternary},
		{Node: "conjunction_expression", Token: "&&", Construct: Logical},
		{Node: "disjunction_expression", Token: "||", Construct: Logical},
		{Node: "nil_coalescing_expression", Token: "??", Construct: Logical},
	},
	parse.LangScala: {
		{Node: "if_expression", Token: "if", Construct: Branch, Note: "an else-if is a nested if_expression"},
		{Node: "while_expression", Token: "while", Construct: Loop},
		{Node: "for_expression", Token: "for", Construct: Loop},
		{Node: "case_clause", Token: "case", Construct: Case, Note: "every arm, a `case _` and a catch's cases included"},
		{Node: "catch_clause", Token: "catch", Construct: Catch},
		{
			Node: "infix_expression", Token: "&&", Construct: Logical, Note: "an operator_identifier, matched by text",
			Query: `(infix_expression operator: (operator_identifier) @name @reference.call (#eq? @name "&&"))`,
		},
		{
			Node: "infix_expression", Token: "||", Construct: Logical, Note: "an operator_identifier, matched by text",
			Query: `(infix_expression operator: (operator_identifier) @name @reference.call (#eq? @name "||"))`,
		},
	},
	parse.LangBash: {
		{Node: "if_statement", Token: "if", Construct: Branch},
		{Node: "elif_clause", Token: "elif", Construct: Branch},
		{Node: "while_statement", Token: "while", Construct: Loop},
		{Node: "while_statement", Token: "until", Construct: Loop, Note: "until shares while_statement"},
		{Node: "for_statement", Token: "for", Construct: Loop},
		{Node: "c_style_for_statement", Token: "for", Construct: Loop},
		{Node: "case_item", Token: ")", Construct: Case, Note: "every item, a `*)` included"},
		{Node: "list", Token: "&&", Construct: Logical},
		{Node: "list", Token: "||", Construct: Logical},
	},
	parse.LangLua: {
		{Node: "if_statement", Token: "if", Construct: Branch},
		{Node: "elseif_statement", Token: "elseif", Construct: Branch},
		{Node: "while_statement", Token: "while", Construct: Loop},
		{Node: "repeat_statement", Token: "repeat", Construct: Loop},
		{Node: "for_statement", Token: "for", Construct: Loop, Note: "numeric and generic for"},
		{Node: "binary_expression", Token: "and", Construct: Logical},
		{Node: "binary_expression", Token: "or", Construct: Logical},
	},
}

// goDecisions is goRules keyed by node and token.
var goDecisions = func() map[[2]string]bool {
	m := make(map[[2]string]bool, len(goRules))
	for _, r := range goRules {
		m[[2]string{r.Node, r.Token}] = true
	}
	return m
}()

// GoRules returns a copy of Go's rule rows.
func GoRules() []Rule { return append([]Rule(nil), goRules...) }

// GoDecision reports whether the go/ast node of type name node (for example
// "IfStmt") with token tok is a decision point.
func GoDecision(node, tok string) bool { return goDecisions[[2]string{node, tok}] }

// TreeSitterRules returns a copy of lang's tree-sitter rule rows (nil when
// the language has none).
func TreeSitterRules(lang codeintel.Language) []Rule {
	return append([]Rule(nil), treeSitterRules[lang]...)
}

// TreeSitterLanguages lists the languages with tree-sitter rows.
func TreeSitterLanguages() []codeintel.Language {
	out := make([]codeintel.Language, 0, len(treeSitterRules))
	for l := range treeSitterRules {
		out = append(out, l)
	}
	return out
}

// Supported reports whether lang has a counter (Go's go/ast rows or a
// tree-sitter row set). An exact-span file in an unsupported language gets
// no figure.
func Supported(lang codeintel.Language) bool {
	if lang == parse.LangGo {
		return true
	}
	return len(treeSitterRules[lang]) > 0
}

// Query is lang's tree-sitter decision query: one pattern per row, every
// one capturing its decision token as `@name @reference.call`. "" when the
// language has no tree-sitter rows.
func Query(lang codeintel.Language) string {
	rules := treeSitterRules[lang]
	if len(rules) == 0 {
		return ""
	}
	var b strings.Builder
	for _, r := range rules {
		b.WriteString(r.pattern())
		b.WriteByte('\n')
	}
	return b.String()
}

// RuleQuery is the single-row query of r (the per-row tests run each row
// alone).
func RuleQuery(r Rule) string { return r.pattern() }
