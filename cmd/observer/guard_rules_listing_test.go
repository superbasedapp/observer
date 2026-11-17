package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// orgCustomRulesBundle is the byte-pinned org bundle with custom [[rule]]
// entries (ORG-1, ORG-2) the org form composes (testdata/guard).
func orgCustomRulesBundle(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "guard", "org-custom-rules-bundle.toml"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return string(raw)
}

// TestGuardRulesListsOrgCustomRules (round-3 finding): `observer guard rules`
// prints the same listing the dashboard's Rules tab shows
// (guard.Guard.RuleListing), so an org bundle's own [[rule]] entries are
// listed with source "org"; --catalog alone is the built-in table.
func TestGuardRulesListsOrgCustomRules(t *testing.T) {
	n := newPostureOrgNode(t, "[guard]\nenabled = true\nmode = \"observe\"")
	writeOrgBundle(t, n.bundle, orgCustomRulesBundle(t))

	cases := []struct {
		name    string
		args    []string
		want    []string
		wantNot []string
	}{
		{"default is the effective listing", []string{"rules"}, []string{"ORG-1", "ORG-2", "R-101"}, nil},
		{"--effective is the same listing", []string{"rules", "--effective"}, []string{"ORG-1", "ORG-2"}, nil},
		{"json carries the org source", []string{"rules", "--json"}, []string{`"id": "ORG-1"`, `"source": "org"`, `"id": "ORG-2"`}, nil},
		{"--catalog is the built-in table", []string{"rules", "--catalog"}, []string{"R-101"}, []string{"ORG-1", "ORG-2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runGuardCmd(t, append(tc.args, "--config", n.cp)...)
			if err != nil {
				t.Fatalf("guard %v: %v\n%s", tc.args, err, out)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("output missing %q:\n%s", w, out)
				}
			}
			for _, w := range tc.wantNot {
				if strings.Contains(out, w) {
					t.Errorf("output carries %q, want it absent", w)
				}
			}
		})
	}

	// The text table names the source and scope of the org rule.
	out, err := runGuardCmd(t, "rules", "--config", n.cp)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "ORG-1 ") {
			if !strings.Contains(line, " org ") || !strings.Contains(line, " all ") {
				t.Errorf("ORG-1 row = %q, want source org and scope all", line)
			}
			return
		}
	}
	t.Errorf("no ORG-1 row:\n%s", out)
}
