package main

import (
	"strings"
	"testing"
)

func TestParseAssignedReadsTheSubsetUpstreamUses(t *testing.T) {
	src := `// leading comment
/* block
   comment */
var ignored = 1
thing = {
  // a comment inside
  "quoted": 1.5,
  'single': 'it\'s',
  bare: { 0: 7, 1: [ "a", 'b', ], },
  3: -2,
  "esc": "x\"y\nz\u0041\“curly\”",
  "empty": {},
}
other = { "x": 1 }
`
	n, err := parseAssigned("t.js", src, "thing")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(n.keys, ","); got != "quoted,single,bare,3,esc,empty" {
		t.Errorf("keys in source order = %s", got)
	}
	if v, _ := n.lookup("quoted"); v.kind != kindNumber || v.str != "1.5" {
		t.Errorf("quoted = %+v", v)
	}
	if v, _ := n.lookup("single"); v.str != "it's" {
		t.Errorf("single = %q", v.str)
	}
	if v, _ := n.lookup("esc"); v.str != "x\"y\nzA“curly”" {
		t.Errorf("esc = %q", v.str)
	}
	bare, _ := n.lookup("bare")
	if one, ok := bare.lookup("1"); !ok || one.kind != kindArray || len(one.vals) != 2 || one.vals[1].str != "b" {
		t.Errorf("bare[1] = %+v", one)
	}
	if v, _ := n.lookup("3"); v.str != "-2" {
		t.Errorf("3 = %q", v.str)
	}
	if v, _ := n.lookup("empty"); v.kind != kindObject || len(v.keys) != 0 {
		t.Errorf("empty = %+v", v)
	}
	if _, ok := n.lookup("missing"); ok {
		t.Error("lookup found an absent key")
	}
}

func TestParseAssignedRefusals(t *testing.T) {
	cases := []struct {
		name, src, want string
	}{
		{"absent", "other = {}", "found 0"},
		{"twice", "x = {}\nx = {}\n", "found 2"},
		{"a comment is not an assignment", "// x = {}\n", "found 0"},
		{"unterminated object", "x = { \"a\": 1", "unterminated object"},
		{"unterminated string", "x = { \"a\": \"b", "unterminated string"},
		{"newline in a string", "x = { \"a\": \"b\nc\" }", "newline inside a string"},
		{"duplicate key", "x = { \"a\": 1, \"a\": 2 }", "duplicate key"},
		{"missing colon", "x = { \"a\" 1 }", "expected ':'"},
		{"missing comma", "x = { \"a\": 1 \"b\": 2 }", "expected ',' or '}'"},
		{"an identifier value", "x = { \"a\": N }", "unsupported value"},
		{"a function value", "x = { \"a\": function() {} }", "unsupported value"},
		{"an exponent", "x = { \"a\": 1e3 }", "plain decimal"},
		{"a hex number", "x = { \"a\": 0x10 }", "plain decimal"},
		{"unsupported escape", "x = { \"a\": \"\\q\" }", "unsupported escape"},
		{"short unicode escape", "x = { \"a\": \"\\u00\" }", "bad \\u escape"},
		{"unterminated array", "x = { \"a\": [1, 2", "unterminated array"},
		{"unterminated block comment", "x = { /* \"a\": 1 }", "unterminated block comment"},
		{"bad key", "x = { : 1 }", "expected an object key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseAssigned("t.js", c.src, "x")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want one mentioning %q", err, c.want)
			}
		})
	}
}

func TestParseErrorsNameTheLine(t *testing.T) {
	_, err := parseAssigned("t.js", "x = {\n  \"a\": 1,\n  \"b\": N\n}\n", "x")
	if err == nil || !strings.Contains(err.Error(), "t.js:3:") {
		t.Errorf("error = %v, want the line 3 in it", err)
	}
}
