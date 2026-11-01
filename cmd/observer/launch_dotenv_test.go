package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestLaunchRouteShadows pins CLI-7: a launch of a tool with the
// DotenvOverride capability (aider) whose own .env, --env-file or config
// file sets the base URL is not routed, and the sources are named by file
// and key only. On the old code every such launch printed "routing via".
// One case per source the evaluator ranks above the launch environment,
// plus the clean and the no-capability rows.
func TestLaunchRouteShadows(t *testing.T) {
	const secret = "https://value-not-shown.example"
	env := []string{"OPENAI_API_BASE=http://127.0.0.1:8820/v1"}
	cases := []struct {
		name  string
		tool  string
		args  []string
		setup func(t *testing.T, home, project string)
		want  []string
	}{
		{name: "clean: the launch route holds", tool: "aider", setup: func(*testing.T, string, string) {}},
		{
			name: "~/.env sets OPENAI_API_BASE", tool: "aider",
			setup: func(t *testing.T, home, _ string) {
				writeLaunchFile(t, filepath.Join(home, ".env"), "OPENAI_API_BASE="+secret+"\n")
			},
			want: []string{".env: OPENAI_API_BASE"},
		},
		{
			name: "the project's .env sets AIDER_OPENAI_API_BASE", tool: "aider",
			setup: func(t *testing.T, _, project string) {
				writeLaunchFile(t, filepath.Join(project, ".env"), "export AIDER_OPENAI_API_BASE="+secret+"\n")
			},
			want: []string{".env: AIDER_OPENAI_API_BASE"},
		},
		{
			name: "--env-file names a file that sets OPENAI_API_BASE", tool: "aider",
			args: []string{"--env-file", "custom.env"},
			setup: func(t *testing.T, _, project string) {
				writeLaunchFile(t, filepath.Join(project, "custom.env"), "OPENAI_API_BASE="+secret+"\n")
			},
			want: []string{"custom.env: OPENAI_API_BASE"},
		},
		{
			name: "~/.aider.conf.yml sets openai-api-base", tool: "aider",
			setup: func(t *testing.T, home, _ string) {
				writeLaunchFile(t, filepath.Join(home, ".aider.conf.yml"), "openai-api-base: "+secret+"\n")
			},
			want: []string{".aider.conf.yml: openai-api-base"},
		},
		{
			name: "a tool with no DotenvOverride capability is not read", tool: "opencode",
			setup: func(t *testing.T, home, _ string) {
				writeLaunchFile(t, filepath.Join(home, ".env"), "OPENAI_API_BASE="+secret+"\n")
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home, project, _ := pinLaunchFiles(t)
			tc.setup(t, home, project)
			got := launchRouteShadows(tc.tool, tc.args, project, env)
			if len(tc.want) == 0 {
				if len(got) != 0 {
					t.Fatalf("shadows = %v, want none", got)
				}
				return
			}
			all := strings.Join(got, "\n")
			for _, w := range tc.want {
				if !strings.Contains(all, w) {
					t.Errorf("shadows %v miss %q", got, w)
				}
			}
			notice := routeShadowNotice("aider", got)
			if strings.Contains(notice, secret) || strings.Contains(notice, "value-not-shown") {
				t.Fatalf("notice carries the value: %s", notice)
			}
			if !strings.Contains(notice, "not routed through the proxy") {
				t.Fatalf("notice %q does not say the launch is not routed", notice)
			}
		})
	}
}
