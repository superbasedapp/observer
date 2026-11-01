package agentconfigsvc

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// layerService builds a Service over a throwaway home and system root: no
// real file outside them is read.
func layerService(t *testing.T, home string, env map[string]string) *Service {
	t.Helper()
	return New(Options{
		Home: home, GOOS: runtime.GOOS, SystemRoot: t.TempDir(),
		Getenv: func(k string) string { return env[k] },
	})
}

// place writes body at the path the service resolves for a catalogue row.
func place(t *testing.T, s *Service, id, project, body string) string {
	t.Helper()
	env := s.env(project)
	env.Relocate = true
	r, err := agentconfig.ResolveArtifact(id, env)
	if err != nil || r.Status != agentconfig.PathResolved {
		t.Fatalf("resolve %s: %+v %v", id, r, err)
	}
	if err := os.MkdirAll(filepath.Dir(r.Path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.Path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return r.Path
}

func ownCmd(c string) bool { return strings.Contains(c, "observer hook") }

// findingsOf keeps one family's findings.
func findingsOf(rep LayerReport, family string) []agentconfig.LayerFinding {
	var out []agentconfig.LayerFinding
	for _, f := range rep.Findings {
		if f.Family == family {
			out = append(out, f)
		}
	}
	return out
}

// TestEffectiveLayersFlagsTheSettingsLocalFixture is the Wave 4 acceptance
// criterion (review section 3.5, CC-4, OBS-9): the committed fixture repo
// carries env.ANTHROPIC_BASE_URL=https://api.anthropic.com in
// .claude/settings.local.json, and the evaluator flags it over the fixture
// home's loopback route.
func TestEffectiveLayersFlagsTheSettingsLocalFixture(t *testing.T) {
	home, err := filepath.Abs(filepath.Join("testdata", "layers", "cc4", "home"))
	if err != nil {
		t.Fatal(err)
	}
	repo, _ := filepath.Abs(filepath.Join("testdata", "layers", "cc4", "repo"))
	s := layerService(t, home, nil)
	rep, err := s.EffectiveLayers(context.Background(), LayerOptions{Projects: []string{repo}, Tools: []string{"claude-code"}})
	if err != nil {
		t.Fatal(err)
	}
	fs := findingsOf(rep, "claude-code/env")
	if len(fs) != 1 {
		t.Fatalf("findings = %+v, want one claude-code/env finding", rep.Findings)
	}
	f := fs[0]
	if f.Code != agentconfig.FindingProjectRouteOverride || f.Project != repo || f.Winning.FileID != "claude-code/project-local-settings" || f.Class != "vendor_host" {
		t.Fatalf("finding = %+v", f)
	}
	if p := rep.Path(f); !strings.HasSuffix(filepath.ToSlash(p), ".claude/settings.local.json") {
		t.Fatalf("path = %q", p)
	}
	if strings.Contains(f.String(), "api.anthropic.com") {
		t.Fatalf("a finding carries the value: %s", f)
	}
}

// TestEffectiveLayersBoundary has one case per boundary rule: relocation
// (Relocate: true), the injected launch environment, OPENCODE_CONFIG_CONTENT,
// .env key presence, TOML decoding, and a never-read file.
func TestEffectiveLayersBoundary(t *testing.T) {
	type tc struct {
		name   string
		tools  []string
		setup  func(t *testing.T, home, proj string) (*Service, map[string]string)
		family string
		want   []agentconfig.FindingCode
	}
	cases := []tc{
		{
			name: "CLAUDE_CONFIG_DIR moves the user file the pass reads (relocation)", tools: []string{"claude-code"},
			family: "claude-code/disableAllHooks", want: []agentconfig.FindingCode{agentconfig.FindingHooksDisabled},
			setup: func(t *testing.T, home, _ string) (*Service, map[string]string) {
				moved := filepath.Join(t.TempDir(), "cc")
				env := map[string]string{"CLAUDE_CONFIG_DIR": moved}
				s := layerService(t, home, env)
				// The default home file says hooks are on; the moved one off.
				place(t, layerService(t, home, nil), "claude-code/user-settings", "", `{"disableAllHooks":false}`)
				if p := place(t, s, "claude-code/user-settings", "", `{"disableAllHooks":true}`); !strings.HasPrefix(p, moved) {
					t.Fatalf("relocated path %s is not under %s", p, moved)
				}
				return s, env
			},
		},
		{
			name: "the injected launch environment shadows the settings route", tools: []string{"claude-code"},
			family: "claude-code/env", want: []agentconfig.FindingCode{agentconfig.FindingRouteShadowed},
			setup: func(t *testing.T, home, _ string) (*Service, map[string]string) {
				env := map[string]string{"ANTHROPIC_BASE_URL": "https://gateway.example.com"}
				s := layerService(t, home, env)
				place(t, s, "claude-code/user-settings", "", `{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8820"}}`)
				return s, env
			},
		},
		{
			name: "CLI-2: a project opencode.json overrides OPENAI_BASE_URL", tools: []string{"opencode"},
			family: "opencode/provider.openai.options.baseURL", want: []agentconfig.FindingCode{agentconfig.FindingProjectRouteOverride},
			setup: func(t *testing.T, home, proj string) (*Service, map[string]string) {
				env := map[string]string{"OPENAI_BASE_URL": "http://127.0.0.1:8820/v1"}
				s := layerService(t, home, env)
				place(t, s, "opencode/project-config", proj, `{"provider":{"openai":{"options":{"baseURL":"https://llm.example.com/v1"}}}}`)
				return s, env
			},
		},
		{
			name: "CLI-2/CLI-3: OPENCODE_CONFIG_CONTENT from the injected env carries the route", tools: []string{"opencode"},
			family: "opencode/provider.openai.options.baseURL",
			setup: func(t *testing.T, home, proj string) (*Service, map[string]string) {
				env := map[string]string{"OPENCODE_CONFIG_CONTENT": `{"provider":{"openai":{"options":{"baseURL":"http://127.0.0.1:8820/v1"}}}}`}
				s := layerService(t, home, env)
				place(t, s, "opencode/project-config", proj, `{"provider":{"openai":{"options":{"baseURL":"https://llm.example.com/v1"}}}}`)
				return s, env
			},
		},
		{
			name: "CLI-7: a home .env setting OPENAI_API_BASE shadows the launcher (by key name)", tools: []string{"aider"},
			family: "aider/openai-api-base", want: []agentconfig.FindingCode{agentconfig.FindingRouteShadowed},
			setup: func(t *testing.T, home, _ string) (*Service, map[string]string) {
				env := map[string]string{"OPENAI_API_BASE": "http://127.0.0.1:8820/v1"}
				if err := os.WriteFile(filepath.Join(home, ".env"), []byte("OPENAI_API_KEY=sk-test\nOPENAI_API_BASE=https://llm.example.com/v1\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				return layerService(t, home, env), env
			},
		},
		{
			name: "W-6: a TOML workspace array without Observer's group replaces the user array", tools: []string{"vtcode"},
			family: "vtcode/hooks.lifecycle.pre_tool_use", want: []agentconfig.FindingCode{agentconfig.FindingHookArrayReplaced},
			setup: func(t *testing.T, home, proj string) (*Service, map[string]string) {
				s := layerService(t, home, nil)
				place(t, s, "vtcode/user-config", "", "[[hooks.lifecycle.pre_tool_use]]\nmatcher = \"*\"\n[[hooks.lifecycle.pre_tool_use.hooks]]\ntype = \"command\"\ncommand = \"observer hook vtcode PreToolUse\"\n")
				place(t, s, "vtcode/workspace-config", proj, "[hooks.lifecycle]\npre_tool_use = []\n")
				return s, nil
			},
		},
		{
			name: "CLI-5: the system (managed) Gemini settings file is read and wins", tools: []string{"gemini-cli"},
			family: "gemini-cli/hooksConfig.enabled", want: []agentconfig.FindingCode{agentconfig.FindingHooksDisabled},
			setup: func(t *testing.T, home, _ string) (*Service, map[string]string) {
				s := layerService(t, home, nil)
				place(t, s, "gemini-cli/user-settings", "", `{"hooksConfig":{"enabled":true}}`)
				place(t, s, "gemini-cli/system-settings", "", "{\n // admin\n \"hooksConfig\": {\"enabled\": false},\n}")
				return s, nil
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home, proj := t.TempDir(), t.TempDir()
			s, _ := c.setup(t, home, proj)
			rep, err := s.EffectiveLayers(context.Background(), LayerOptions{Projects: []string{proj}, Tools: c.tools, OwnHookCommand: ownCmd})
			if err != nil {
				t.Fatal(err)
			}
			var got []agentconfig.FindingCode
			for _, f := range findingsOf(rep, c.family) {
				got = append(got, f.Code)
			}
			if len(got) != len(c.want) {
				t.Fatalf("codes = %v, want %v (all: %+v)", got, c.want, rep.Findings)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("codes = %v, want %v", got, c.want)
				}
			}
		})
	}
}

// TestLayerProjectsBounded pins the project cap.
func TestLayerProjectsBounded(t *testing.T) {
	var ps []string
	for i := 0; i < LayerMaxProjects+10; i++ {
		ps = append(ps, filepath.Join("/w", strings.Repeat("p", i+1)))
	}
	ps = append([]string{"", ps[0]}, ps...)
	if got := boundedProjects(ps); len(got) != LayerMaxProjects {
		t.Fatalf("bounded to %d, want %d", len(got), LayerMaxProjects)
	}
}
