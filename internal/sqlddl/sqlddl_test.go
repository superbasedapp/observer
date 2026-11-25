package sqlddl

import (
	"reflect"
	"testing"
)

func TestHasPrefixFold(t *testing.T) {
	cases := []struct {
		s, prefix string
		want      bool
	}{
		{"ADD COLUMN x", "add", true},
		{"add constraint", "ADD CONSTRAINT", true},
		{"AD", "ADD", false},
		{"DROP x", "ADD", false},
		{"", "", true},
	}
	for _, c := range cases {
		if got := HasPrefixFold(c.s, c.prefix); got != c.want {
			t.Errorf("HasPrefixFold(%q, %q) = %v, want %v", c.s, c.prefix, got, c.want)
		}
	}
}

func TestParenBody(t *testing.T) {
	cases := []struct {
		name, in, want string
		wantErr        bool
	}{
		{"simple", "(a, b) rest", "a, b", false},
		{"nested", "(a int, CHECK (a > 0)), x", "a int, CHECK (a > 0)", false},
		{"paren in a literal", "(a text DEFAULT ')') tail", "a text DEFAULT ')'", false},
		{"paren in a quoted identifier", `("a)" int)`, `"a)" int`, false},
		{"doubled quote", "(a text DEFAULT 'it''s (x)')", "a text DEFAULT 'it''s (x)'", false},
		{"unbalanced", "(a, (b)", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParenBody(c.in)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
			if got != c.want {
				t.Errorf("ParenBody(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestSplitTopLevel(t *testing.T) {
	cases := []struct {
		name, in string
		want     []string
	}{
		{"flat", "a, b,c", []string{"a", " b", "c"}},
		{"nested parens", "a numeric(10, 2), b", []string{"a numeric(10, 2)", " b"}},
		{"comma in a literal", "a DEFAULT ',', b", []string{"a DEFAULT ','", " b"}},
		{"comma in a quoted identifier", `"a,b" int, c`, []string{`"a,b" int`, " c"}},
		{"no comma", "a", []string{"a"}},
		{"empty", "", []string{""}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := SplitTopLevel(c.in); !reflect.DeepEqual(got, c.want) {
				t.Errorf("SplitTopLevel(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestStripComments(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"line comment", "a -- note\nb", "a \nb"},
		{"block comment", "a /* x */b", "a  b"},
		{"dashes in a literal", "DEFAULT '--x'", "DEFAULT '--x'"},
		{"block opener in a quoted identifier", `"/*a" int`, `"/*a" int`},
		{"unterminated block", "a /* never closed", "a "},
		{"no comment", "CREATE TABLE t (a int)", "CREATE TABLE t (a int)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := StripComments(c.in); got != c.want {
				t.Errorf("StripComments(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
