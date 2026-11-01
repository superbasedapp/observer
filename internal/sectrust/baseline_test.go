package sectrust

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// TestBaselineSnapshotAndDiff: the check's snapshot lists every table file
// it read with its digest, and Diff reports added, changed and removed
// files, never a removal from an incomplete snapshot.
func TestBaselineSnapshotAndDiff(t *testing.T) {
	snap := func(files map[string]string) Result {
		m := map[string][]byte{}
		for p, b := range files {
			m[p] = []byte(b)
		}
		res, err := Check(context.Background(), MemFS(m), Request{})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	first := snap(map[string]string{".mcp.json": `{}`, "CLAUDE.md": "# a\n", "src/x.go": "package x"})
	if len(first.Files) != 2 {
		t.Fatalf("snapshot %+v, want the two table files", first.Files)
	}
	second := snap(map[string]string{".mcp.json": `{"mcpServers":{}}`, ".claude/settings.json": `{}`})
	got := Diff(first.Files, second.Files, true)
	want := []FileChange{
		{Rel: ".claude/settings.json", Class: "structured", Kind: ChangeAdded},
		{Rel: ".mcp.json", Class: "structured", Kind: ChangeChanged},
		{Rel: "CLAUDE.md", Class: "prose", Kind: ChangeRemoved},
	}
	if len(got) != len(want) {
		t.Fatalf("diff %+v", got)
	}
	for i := range want {
		if got[i].Rel != want[i].Rel || got[i].Kind != want[i].Kind || got[i].Class != want[i].Class {
			t.Errorf("change %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	for _, c := range Diff(first.Files, second.Files, false) {
		if c.Kind == ChangeRemoved {
			t.Errorf("an incomplete snapshot reported a removal: %+v", c)
		}
	}
	if d := Diff(first.Files, first.Files, true); len(d) != 0 {
		t.Errorf("no change reported %+v", d)
	}
}

// TestInTable: a write is matched to the snapshot's table the way the check
// reads it, one row shape per case.
func TestInTable(t *testing.T) {
	paths := []agentconfig.TrustPath{
		{Rel: ".claude/settings.json", Class: agentconfig.TrustStructured},
		{Rel: ".claude/", Class: agentconfig.TrustConfigDir},
		{Rel: ".github/hooks/", Class: agentconfig.TrustStructured},
		{Rel: ".opencode/plugin/", Class: agentconfig.TrustCode},
		{Rel: ".claude/skills/*/SKILL.md", Class: agentconfig.TrustProse},
	}
	cases := []struct {
		rel  string
		want bool
	}{
		{".claude/settings.json", true},
		{"./.claude/settings.json", true},
		{`.claude\settings.json`, true},
		{".claude/other.json", false},
		{".github/hooks/a.json", true},
		{".github/hooks/sub/a.json", false},
		{".github/hooks/", false},
		{".opencode/plugin/x.ts", true},
		{".opencode/plugin/pkg/index.ts", true},
		{".opencode/plugin/pkg/deep/index.ts", false},
		{".claude/skills/review/SKILL.md", true},
		{".claude/skills/review/other.md", false},
		{"sub/.claude/settings.json", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := InTable(tc.rel, paths); got != tc.want {
			t.Errorf("InTable(%q) = %v, want %v", tc.rel, got, tc.want)
		}
	}
}
