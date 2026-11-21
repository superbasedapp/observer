package treesitter

import (
	"context"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
	"github.com/marmutapp/superbased-observer/internal/codeintel/parse"
	"github.com/marmutapp/superbased-observer/internal/codeintel/parse/complexity"
)

// complexitySample is one language's sample function and, per row of
// parse/complexity's rule table (keyed "node token"), how many decisions
// of that row the sample holds.
type complexitySample struct {
	src  string
	fn   string
	rows map[string]int
}

// sharedBackend compiles the grammar set once for the complexity tests.
var sharedBackend = sync.OnceValue(func() *backend {
	p, _ := New()
	return p.(*backend)
})

func (s complexitySample) total() int {
	n := 1
	for _, c := range s.rows {
		n += c
	}
	return n
}

// complexitySamples covers every language with tree-sitter rows; every row
// has a count here (TestComplexityRows fails on a row without one).
var complexitySamples = map[codeintel.Language]complexitySample{
	parse.LangRust: {fn: "f", src: `fn f(x: i32) -> i32 {
    if x > 0 && x < 10 || x == 99 { return 1; } else if x < 0 { return 2; }
    while x > 0 { }
    for i in 0..3 { }
    loop { break; }
    match x { 1 => 1, y if y > 5 => 2, _ => 3 };
    if let Some(y) = g() { }
    0
}
`, rows: map[string]int{
		"if_expression if":       3,
		"match_pattern if":       1,
		"while_expression while": 1,
		"for_expression for":     1,
		"match_arm =>":           2,
		"binary_expression &&":   1,
		"binary_expression ||":   1,
	}},
	parse.LangJavaScript: {src: jsSample, fn: "f", rows: jsRows},
	parse.LangJSX:        {src: jsSample, fn: "f", rows: jsRows},
	parse.LangTypeScript: {src: jsSample, fn: "f", rows: jsRows},
	parse.LangTSX:        {src: jsSample, fn: "f", rows: jsRows},
	parse.LangPython: {fn: "f", src: `def f(x):
    if x > 0 and x < 10 or x == 99:
        return 1
    elif x < 0:
        return 2
    while x > 0:
        x -= 1
    for i in range(3):
        pass
    try:
        g()
    except ValueError:
        pass
    except* TypeError:
        pass
    y = 1 if x else 2
    z = [a for a in b if a]
    match x:
        case 1:
            pass
        case _:
            pass
    return 0
`, rows: map[string]int{
		"if_statement if":           1,
		"elif_clause elif":          1,
		"conditional_expression if": 1,
		"if_clause if":              1,
		"while_statement while":     1,
		"for_statement for":         1,
		"for_in_clause for":         1,
		"case_clause case":          2,
		"except_clause except":      2,
		"boolean_operator and":      1,
		"boolean_operator or":       1,
	}},
	parse.LangJava: {fn: "f", src: `class A {
  int f(int x) {
    if (x > 0 && x < 10 || x == 99) { return 1; } else if (x < 0) { return 2; }
    while (x > 0) { x--; }
    do { x++; } while (x < 3);
    for (int i = 0; i < 3; i++) {}
    for (int v : a) {}
    switch (x) { case 1: break; case 2: break; default: break; }
    int w = switch (x) { case 1 -> 1; default -> 2; };
    try { g(); } catch (Exception e) { }
    int y = x > 0 ? 1 : 2;
    return 0;
  }
}
`, rows: map[string]int{
		"if_statement if":            2,
		"for_statement for":          1,
		"enhanced_for_statement for": 1,
		"while_statement while":      1,
		"do_statement do":            1,
		"switch_label case":          3,
		"catch_clause catch":         1,
		"ternary_expression ?":       1,
		"binary_expression &&":       1,
		"binary_expression ||":       1,
	}},
	parse.LangC: {fn: "f", src: `int f(int x) {
  if (x > 0 && x < 10 || x == 99) { return 1; } else if (x < 0) { return 2; }
  while (x > 0) { x--; }
  do { x++; } while (x < 3);
  for (int i = 0; i < 3; i++) {}
  switch (x) { case 1: break; case 2: break; default: break; }
  int y = x > 0 ? 1 : 2;
  return 0;
}
`, rows: map[string]int{
		"if_statement if":          2,
		"for_statement for":        1,
		"while_statement while":    1,
		"do_statement do":          1,
		"case_statement case":      2,
		"conditional_expression ?": 1,
		"binary_expression &&":     1,
		"binary_expression ||":     1,
	}},
	parse.LangCPP: {fn: "f", src: `int f(int x) {
  if (x > 0 && x < 10 || x == 99) { return 1; } else if (x < 0) { return 2; }
  while (x > 0) { x--; }
  do { x++; } while (x < 3);
  for (int i = 0; i < 3; i++) {}
  for (auto v : a) {}
  switch (x) { case 1: break; case 2: break; default: break; }
  try { g(); } catch (int e) { }
  int y = x > 0 ? 1 : 2;
  return 0;
}
`, rows: map[string]int{
		"if_statement if":          2,
		"for_statement for":        1,
		"while_statement while":    1,
		"do_statement do":          1,
		"case_statement case":      2,
		"conditional_expression ?": 1,
		"binary_expression &&":     1,
		"binary_expression ||":     1,
		"for_range_loop for":       1,
		"catch_clause catch":       1,
	}},
	parse.LangCSharp: {fn: "F", src: `class A {
  int F(int x) {
    if (x > 0 && x < 10 || x == 99) { return 1; } else if (x < 0) { return 2; }
    while (x > 0) { x--; }
    do { x++; } while (x < 3);
    for (int i = 0; i < 3; i++) {}
    foreach (var v in a) {}
    switch (x) { case 1: break; case 2 when y: break; default: break; }
    var w = x switch { 1 => 1, _ => 2 };
    try { G(); } catch (Exception e) { }
    var y = x > 0 ? 1 : 2;
    var z = a ?? b;
    return 0;
  }
}
`, rows: map[string]int{
		"if_statement if":           2,
		"for_statement for":         1,
		"foreach_statement foreach": 1,
		"while_statement while":     1,
		"do_statement do":           1,
		"switch_section case":       2,
		"when_clause when":          1,
		"switch_expression_arm =>":  2,
		"catch_clause catch":        1,
		"conditional_expression ?":  1,
		"binary_expression &&":      1,
		"binary_expression ||":      1,
		"binary_expression ??":      1,
	}},
	parse.LangRuby: {fn: "f", src: `def f(x)
  if x > 0 && x < 10 || x == 99 and y or z
    return 1
  elsif x < 0
    return 2
  end
  unless x then end
  while x > 0 do x -= 1 end
  until x > 0 do x += 1 end
  for i in 0..3 do end
  case x
  when 1 then 1
  when 2 then 2
  else 3
  end
  begin
    g
  rescue StandardError
  end
  y = x ? 1 : 2
  z = 1 if x
  z = 1 unless x
  z += 1 while x
  z += 1 until x
  0
end
`, rows: map[string]int{
		"if if":                  1,
		"elsif elsif":            1,
		"unless unless":          1,
		"if_modifier if":         1,
		"unless_modifier unless": 1,
		"while while":            1,
		"until until":            1,
		"for for":                1,
		"while_modifier while":   1,
		"until_modifier until":   1,
		"when when":              2,
		"rescue rescue":          1,
		"conditional ?":          1,
		"binary &&":              1,
		"binary ||":              1,
		"binary and":             1,
		"binary or":              1,
	}},
	parse.LangPHP: {fn: "f", src: `<?php
function f($x) {
  if ($x > 0 && $x < 10 || $x == 99 and $y or $z) { return 1; } elseif ($x < 0) { return 2; } else if ($x) {}
  while ($x > 0) { $x--; }
  do { $x++; } while ($x < 3);
  for ($i = 0; $i < 3; $i++) {}
  foreach ($a as $v) {}
  switch ($x) { case 1: break; case 2: break; default: break; }
  $w = match($x) { 1 => 1, default => 2 };
  try { g(); } catch (Exception $e) { }
  $y = $x ? 1 : 2;
  $z = $a ?? $b;
  return 0;
}
`, rows: map[string]int{
		"if_statement if":                 2,
		"else_if_clause elseif":           1,
		"for_statement for":               1,
		"foreach_statement foreach":       1,
		"while_statement while":           1,
		"do_statement do":                 1,
		"case_statement case":             2,
		"match_conditional_expression =>": 1,
		"catch_clause catch":              1,
		"conditional_expression ?":        1,
		"binary_expression &&":            1,
		"binary_expression ||":            1,
		"binary_expression and":           1,
		"binary_expression or":            1,
		"binary_expression ??":            1,
	}},
	parse.LangKotlin: {fn: "f", src: `fun f(x: Int): Int {
    if (x > 0 && x < 10 || x == 99) { return 1 } else if (x < 0) { return 2 }
    while (x > 0) { }
    do { } while (x < 3)
    for (i in 0..3) { }
    when (x) { 1 -> 1; 2 -> 2; else -> 3 }
    try { g() } catch (e: Exception) { }
    val z = a ?: b
    return 0
}
`, rows: map[string]int{
		"if_expression if":          2,
		"for_statement for":         1,
		"while_statement while":     1,
		"do_while_statement do":     1,
		"when_entry ->":             2,
		"catch_block catch":         1,
		"conjunction_expression &&": 1,
		"disjunction_expression ||": 1,
		"elvis_expression ?:":       1,
	}},
	parse.LangSwift: {fn: "f", src: `func f(x: Int) -> Int {
    if x > 0 && x < 10 || x == 99 { return 1 } else if x < 0 { return 2 }
    guard x > 0 else { return 3 }
    while x > 0 { }
    repeat { } while x < 3
    for i in 0..<3 { }
    switch x { case 1: break; case 2: break; default: break }
    do { try g() } catch { }
    let y = x > 0 ? 1 : 2
    let z = a ?? b
    return 0
}
`, rows: map[string]int{
		"if_statement if":               2,
		"guard_statement guard":         1,
		"for_statement for":             1,
		"while_statement while":         1,
		"repeat_while_statement repeat": 1,
		"switch_entry case":             2,
		"catch_keyword catch":           1,
		"ternary_expression ?":          1,
		"conjunction_expression &&":     1,
		"disjunction_expression ||":     1,
		"nil_coalescing_expression ??":  1,
	}},
	parse.LangScala: {fn: "f", src: `object A {
  def f(x: Int): Int = {
    if (x > 0 && x < 10 || x == 99) { 1 } else if (x < 0) { 2 }
    while (x > 0) { }
    for (i <- 0 to 3) { }
    x match { case 1 => 1; case _ => 2 }
    try { g() } catch { case e: Exception => () }
    0
  }
}
`, rows: map[string]int{
		"if_expression if":       2,
		"while_expression while": 1,
		"for_expression for":     1,
		"case_clause case":       3,
		"catch_clause catch":     1,
		"infix_expression &&":    1,
		"infix_expression ||":    1,
	}},
	parse.LangBash: {fn: "f", src: `f() {
  if [ "$x" -gt 0 ] && [ "$x" -lt 10 ] || [ "$x" = 99 ]; then echo 1; elif [ "$x" ]; then echo 2; fi
  while true; do :; done
  until true; do :; done
  for i in 1 2; do :; done
  for ((i=0;i<3;i++)); do :; done
  case "$x" in a) echo a;; b|c) echo b;; *) echo d;; esac
}
`, rows: map[string]int{
		"if_statement if":           1,
		"elif_clause elif":          1,
		"while_statement while":     1,
		"while_statement until":     1,
		"for_statement for":         1,
		"c_style_for_statement for": 1,
		"case_item )":               3,
		"list &&":                   1,
		"list ||":                   1,
	}},
	parse.LangLua: {fn: "f", src: `function f(x)
  if x > 0 and x < 10 or x == 99 then return 1 elseif x < 0 then return 2 end
  while x > 0 do x = x - 1 end
  repeat x = x + 1 until x > 3
  for i = 1, 3 do end
  for k, v in pairs(t) do end
  return 0
end
`, rows: map[string]int{
		"if_statement if":         1,
		"elseif_statement elseif": 1,
		"while_statement while":   1,
		"repeat_statement repeat": 1,
		"for_statement for":       2,
		"binary_expression and":   1,
		"binary_expression or":    1,
	}},
}

// jsSample serves JavaScript, JSX, TypeScript and TSX (it is valid in all
// four grammars).
const jsSample = `function f(x) {
  if (x > 0 && x < 10 || x == 99) { return 1; } else if (x < 0) { return 2; }
  while (x > 0) { x--; }
  do { x++; } while (x < 3);
  for (let i = 0; i < 3; i++) {}
  for (const k in o) {}
  for (const v of a) {}
  switch (x) { case 1: break; case 2: break; default: break; }
  try { g(); } catch (e) { }
  const y = x ? 1 : 2;
  const z = a ?? b;
  return 0;
}
`

var jsRows = map[string]int{
	"if_statement if":       2,
	"for_statement for":     1,
	"for_in_statement for":  2,
	"while_statement while": 1,
	"do_statement do":       1,
	"switch_case case":      2,
	"catch_clause catch":    1,
	"ternary_expression ?":  1,
	"binary_expression &&":  1,
	"binary_expression ||":  1,
	"binary_expression ??":  1,
}

// TestComplexityRows runs every row of every language's rule table ALONE
// against the real embedded grammar: one subtest per row, asserting the
// row compiles and finds exactly the sample's decisions of that row.
func TestComplexityRows(t *testing.T) {
	b := sharedBackend()
	for _, lang := range complexity.TreeSitterLanguages() {
		sample, ok := complexitySamples[lang]
		if !ok {
			t.Errorf("%s: no sample", lang)
			continue
		}
		lm := b.modules[lang]
		if lm == nil {
			t.Errorf("%s: grammar not compiled", lang)
			continue
		}
		rules := complexity.TreeSitterRules(lang)
		for _, r := range rules {
			key := r.Node + " " + r.Token
			t.Run(string(lang)+"/"+key, func(t *testing.T) {
				want, ok := sample.rows[key]
				if !ok || want < 1 {
					t.Fatalf("no sample count for this row")
				}
				in := lm.get()
				if in == nil {
					t.Fatal("instantiate failed")
				}
				q := complexity.RuleQuery(r)
				out, err := in.runExtract(context.Background(), []byte(sample.src), []byte(q))
				if err != nil {
					in.close()
					t.Fatalf("query %q: %v", q, err)
				}
				lm.put(in)
				if got := len(decisionOffsets(out)); got != want {
					t.Errorf("query %q: %d decisions, want %d", q, got, want)
				}
			})
		}
		for key := range sample.rows {
			found := false
			for _, r := range rules {
				found = found || r.Node+" "+r.Token == key
			}
			if !found {
				t.Errorf("%s: sample row %q is not in the rule table", lang, key)
			}
		}
	}
}

// TestComplexityPerLanguage parses each sample through the backend and
// checks the sample function's figure is 1 + every row's decisions, and
// that no other kind is counted.
func TestComplexityPerLanguage(t *testing.T) {
	p := sharedBackend()
	for lang, sample := range complexitySamples {
		t.Run(string(lang), func(t *testing.T) {
			res, err := p.ParseWith(context.Background(), []byte(sample.src), lang, "sample", parse.Options{Complexity: true})
			if err != nil {
				t.Fatal(err)
			}
			var got []codeintel.Node
			for _, n := range res.Nodes {
				if n.Name == sample.fn && (n.Kind == "function" || n.Kind == "method") {
					got = append(got, n)
				}
			}
			if len(got) != 1 {
				t.Fatalf("want one function %q, got %+v", sample.fn, res.Nodes)
			}
			if got[0].Complexity != sample.total() {
				t.Errorf("complexity %d, want %d", got[0].Complexity, sample.total())
			}
			for _, n := range res.Nodes {
				if n.Kind != "function" && n.Kind != "method" && n.Complexity != 0 {
					t.Errorf("%s %s must not be counted (%d)", n.Kind, n.Name, n.Complexity)
				}
			}
		})
	}
}

// TestComplexityNested: a nested function takes its own decisions, and a
// plain Parse (no option) counts nothing.
func TestComplexityNested(t *testing.T) {
	p := sharedBackend()
	src := "def outer(x):\n    if x:\n        pass\n    def inner(y):\n        if y and x:\n            pass\n    return inner\n"
	res, err := p.ParseWith(context.Background(), []byte(src), parse.LangPython, "n.py", parse.Options{Complexity: true})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, n := range res.Nodes {
		got[n.Name] = n.Complexity
	}
	if got["outer"] != 2 || got["inner"] != 3 {
		t.Errorf("outer %d inner %d, want 2 and 3", got["outer"], got["inner"])
	}
	plain, err := p.Parse(context.Background(), []byte(src), parse.LangPython, "n.py")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range plain.Nodes {
		if n.Complexity != 0 {
			t.Errorf("Parse without the option counted %s: %d", n.Name, n.Complexity)
		}
	}
}
