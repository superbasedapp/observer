package orgcontract

import (
	"strings"
	"testing"
)

func TestOrgNameProblem(t *testing.T) {
	cases := []struct {
		name, in string
		ok       bool
	}{
		{"plain", "SuperBased Demo", true},
		{"unicode", "Acmé GmbH", true},
		{"at the cap", strings.Repeat("a", MaxOrgNameBytes), true},
		{"empty", "", false},
		{"over the cap", strings.Repeat("a", MaxOrgNameBytes+1), false},
		{"untrimmed", " Acme", false},
		{"newline", "Acme\nEvil", false},
		{"escape", "Acme\x1b[31m", false},
	}
	for _, tc := range cases {
		if got := OrgNameProblem(tc.in) == ""; got != tc.ok {
			t.Errorf("%s: OrgNameProblem(%q) = %q, want ok=%v", tc.name, tc.in, OrgNameProblem(tc.in), tc.ok)
		}
	}
}
