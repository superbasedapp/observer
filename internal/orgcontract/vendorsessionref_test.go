package orgcontract

import (
	"strings"
	"testing"
)

func TestValidVendorSessionRef(t *testing.T) {
	cases := []struct {
		name string
		ref  string
		want bool
	}{
		{"claude code cse id", "cse_01HZX9Q2V7K3M8N4P5R6S7T8U9", true},
		{"uuid", "3f2b9c1e-7a4d-4e5f-9b8a-1c2d3e4f5a6b", true},
		{"cursor bc id", "bc-3f2b9c1e-7a4d-4e5f-9b8a-1c2d3e4f5a6b", true},
		{"dotted", "run.42", true},
		{"colon namespaced", "devin:abc123", true},
		{"max length", strings.Repeat("a", MaxVendorSessionRefRunes), true},
		{"empty", "", false},
		{"too long", strings.Repeat("a", MaxVendorSessionRefRunes+1), false},
		{"leading dash", "-abc", false},
		{"leading underscore", "_abc", false},
		{"whitespace", "abc def", false},
		{"slash path", "home/dev/repo", false},
		{"url", "https://example.com/x", false},
		{"email", "dev@example.com", false},
		{"query", "abc?x=1", false},
		{"non ascii", "séance", false},
		{"newline", "abc\n", false},
	}
	for _, c := range cases {
		if got := ValidVendorSessionRef(c.ref); got != c.want {
			t.Errorf("%s: ValidVendorSessionRef(%q) = %v, want %v", c.name, c.ref, got, c.want)
		}
	}
}
