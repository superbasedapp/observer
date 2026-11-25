package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestResolveRuleTargets pins the --target resolution learn and suggest
// share: the file names, the renderer each one gets, the directory fallback
// and each command's unknown-target error text.
func TestResolveRuleTargets(t *testing.T) {
	md := func(string, time.Time) string { return "md" }
	cur := func(string, time.Time) string { return "cursor" }
	dir := t.TempDir()
	cases := []struct {
		name    string
		raw     string
		out     string
		project string
		want    []string // path:rendered
	}{
		{"default is claude", "", dir, "", []string{"CLAUDE.md:md"}},
		{"csv with spaces and case", " Claude , cursor ", dir, "", []string{"CLAUDE.md:md", ".cursorrules:cursor"}},
		{"all expands to three", "agents,ALL", dir, "", []string{"CLAUDE.md:md", "AGENTS.md:md", ".cursorrules:cursor"}},
		{"project root when no output dir", "agents", "", dir, []string{"AGENTS.md:md"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveRuleTargets(tc.raw, tc.out, tc.project, md, cur, "")
			if err != nil {
				t.Fatal(err)
			}
			var rows []string
			for _, g := range got {
				if filepath.Dir(g.path) != dir {
					t.Errorf("path %s is not under %s", g.path, dir)
				}
				rows = append(rows, filepath.Base(g.path)+":"+g.render("", time.Time{}))
			}
			if strings.Join(rows, " ") != strings.Join(tc.want, " ") {
				t.Errorf("targets = %v, want %v", rows, tc.want)
			}
		})
	}
	for _, tc := range []struct{ hint, want string }{
		{" (want claude, agents, cursor, all)", `unknown --target "vim" (want claude, agents, cursor, all)`},
		{"", `unknown --target "vim"`},
	} {
		_, err := resolveRuleTargets("claude,vim", dir, "", md, cur, tc.hint)
		if err == nil || err.Error() != tc.want {
			t.Errorf("error = %v, want %q", err, tc.want)
		}
	}
	if got := joinTargetPaths([]ruleTarget[string]{{path: "a"}, {path: "b"}}); got != "a, b" {
		t.Errorf("joinTargetPaths = %q", got)
	}
}
