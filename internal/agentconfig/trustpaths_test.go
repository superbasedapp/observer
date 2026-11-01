package agentconfig

import (
	"strings"
	"testing"
)

// TestTrustPathsCoverTheJSP7Table: the paths the JSP-7 spike found missing,
// and the extra rows the plan moved into this package, are all in the
// table with the class the trust check reads them as (security pillar plan
// section 5.1, revision 2.4 change (c)).
func TestTrustPathsCoverTheJSP7Table(t *testing.T) {
	want := []struct {
		rel   string
		class TrustClass
	}{
		{".claude/settings.json", TrustStructured},
		{".claude/settings.local.json", TrustStructured},
		{".mcp.json", TrustStructured},
		{".codex/config.toml", TrustStructured},
		{".codex/hooks.json", TrustStructured},
		{".github/hooks/", TrustStructured},
		{".opencode/opencode.json", TrustStructured},
		{".opencode/opencode.jsonc", TrustStructured},
		{".opencode/plugin/", TrustCode},
		{".opencode/plugins/", TrustCode},
		{".opencode/tool/", TrustCode},
		{".kilo/plugin/", TrustCode},
		{".kilocode/mcp.json", TrustStructured},
		{".gemini/commands/*.toml", TrustProse},
		{".agents/skills/*/SKILL.md", TrustProse},
		{".codex/skills/*/SKILL.md", TrustProse},
		{".qwen/skills/*/SKILL.md", TrustProse},
		{".gemini/skills/*/SKILL.md", TrustProse},
		{"CLAUDE.md", TrustProse},
		{"AGENTS.md", TrustProse},
		{".vscode/settings.json", TrustStructured},
		{".vscode/mcp.json", TrustStructured},
		{".env", TrustEnv},
		{".env.local", TrustEnv},
		{".gemini/.env", TrustEnv},
		{".git/config", TrustGitConfig},
		{".gitattributes", TrustGitAttributes},
		{".vscode/tasks.json", TrustTasks},
		{".claude/", TrustConfigDir},
		{".vscode/", TrustConfigDir},
		{".github/", TrustConfigDir},
		{".opencode/", TrustConfigDir},
	}
	got := map[string]TrustPath{}
	for _, p := range TrustPaths() {
		got[p.Rel] = p
	}
	for _, w := range want {
		p, ok := got[w.rel]
		switch {
		case !ok:
			t.Errorf("%s: not in the trust path table", w.rel)
		case p.Class != w.class:
			t.Errorf("%s: class %q, want %q", w.rel, p.Class, w.class)
		}
	}
	if !got[".git/config"].RepoRootOnly {
		t.Error(".git/config must be read at the repository root only")
	}
}

// TestTrustPathsAreBounded: no row needs a walk, every row names its
// sources, and tool state (credentials, caches) is never read.
func TestTrustPathsAreBounded(t *testing.T) {
	known := map[TrustClass]bool{
		TrustStructured: true, TrustCode: true, TrustProse: true, TrustEnv: true,
		TrustGitConfig: true, TrustGitAttributes: true, TrustTasks: true, TrustConfigDir: true,
	}
	seen := map[string]bool{}
	for _, p := range TrustPaths() {
		switch {
		case seen[p.Rel]:
			t.Errorf("%s: repeated", p.Rel)
		case strings.Contains(p.Rel, "**"):
			t.Errorf("%s: a ** glob needs a walk", p.Rel)
		case strings.HasPrefix(p.Rel, "/") || strings.HasPrefix(p.Rel, "~") || strings.Contains(p.Rel, ".."):
			t.Errorf("%s: not relative to a root", p.Rel)
		case !known[p.Class]:
			t.Errorf("%s: unknown class %q", p.Rel, p.Class)
		case len(p.Sources) == 0:
			t.Errorf("%s: no source", p.Rel)
		case p.Class == TrustConfigDir && !strings.HasSuffix(p.Rel, "/"):
			t.Errorf("%s: a config directory row must end in /", p.Rel)
		}
		seen[p.Rel] = true
	}
	toolState := map[string]bool{}
	for _, f := range Files() {
		if f.Kind == KindToolState {
			toolState[f.ID] = true
		}
	}
	for _, p := range TrustPaths() {
		for _, s := range p.Sources {
			if toolState[s] {
				t.Errorf("%s: read from tool-state row %s", p.Rel, s)
			}
		}
	}
}

// TestRepositoryFilesGrounded: every extra row is grounded and unique.
func TestRepositoryFilesGrounded(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range RepositoryFiles() {
		if !strings.HasPrefix(r.ID, "repo/") || seen[r.ID] || r.Rel == "" || r.Grounding.Source == "" || r.Class == "" {
			t.Errorf("%+v: malformed repository row", r)
		}
		seen[r.ID] = true
	}
}

// TestTrustUserPaths: the user-scope table is resolved per OS and relative
// to the home directory, keeps settings, hooks, MCP, code and prose rows,
// and leaves out tool state (credentials), rows outside the home directory,
// unexpandable tokens and walks.
func TestTrustUserPaths(t *testing.T) {
	cases := []struct {
		name    string
		env     PathEnv
		want    map[string]TrustClass
		missing []string
	}{
		{
			name: "linux",
			env:  PathEnv{GOOS: "linux", Home: "/home/dev"},
			want: map[string]TrustClass{
				".claude/settings.json":                TrustStructured,
				".codex/config.toml":                   TrustStructured,
				".codex/hooks.json":                    TrustStructured,
				".claude/skills/*/SKILL.md":            TrustProse,
				".claude/CLAUDE.md":                    TrustProse,
				".config/crush/crushrc":                TrustCode,
				".grok/hooks/":                         TrustStructured,
				".hermes/plugins/superbased-observer/": TrustCode,
			},
			missing: []string{".claude.json", ".cline/data/secrets.json", ".hermes/.env", ".claude/commands/**/*.md"},
		},
		{
			name: "windows appdata under home, mixed case",
			env: PathEnv{GOOS: "windows", Home: `C:\Users\Dev`, Getenv: func(k string) string {
				if k == "APPDATA" {
					return `c:\users\dev\AppData\Roaming`
				}
				return ""
			}},
			want: map[string]TrustClass{
				".claude/settings.json":             TrustStructured,
				"AppData/Roaming/Zed/settings.json": TrustStructured,
			},
		},
		{
			name: "windows appdata elsewhere",
			env: PathEnv{GOOS: "windows", Home: `C:\Users\Dev`, Getenv: func(k string) string {
				if k == "APPDATA" {
					return `D:\Roaming`
				}
				return ""
			}},
			want:    map[string]TrustClass{".claude/settings.json": TrustStructured},
			missing: []string{"Roaming/Zed/settings.json", "AppData/Roaming/Zed/settings.json"},
		},
		{name: "no home", env: PathEnv{GOOS: "linux"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := map[string]TrustPath{}
			for _, p := range TrustUserPaths(tc.env) {
				if p.RepoRootOnly || strings.HasPrefix(p.Rel, "/") || strings.Contains(p.Rel, `\`) {
					t.Errorf("%+v: not a plain home-relative row", p)
				}
				got[p.Rel] = p
			}
			for rel, class := range tc.want {
				if p, ok := got[rel]; !ok || p.Class != class {
					t.Errorf("%s: got %+v (present %v), want class %q", rel, p, ok, class)
				}
			}
			for _, rel := range tc.missing {
				if _, ok := got[rel]; ok {
					t.Errorf("%s: in the user table, want it left out", rel)
				}
			}
			if tc.env.Home == "" && len(got) != 0 {
				t.Errorf("no home: %d rows", len(got))
			}
		})
	}
}
