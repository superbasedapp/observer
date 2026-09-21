package proxyroute

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestInspectClaudeRoute(t *testing.T) {
	cases := []struct {
		name string
		body string
		want RouteState
	}{
		{"ours", `{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8820"}}`, RouteOurs},
		{"ours other port", `{"env":{"ANTHROPIC_BASE_URL":"http://localhost:18820"}}`, RouteOurs},
		{"drifted", `{"env":{"ANTHROPIC_BASE_URL":"https://api.anthropic.com"}}`, RouteDrifted},
		{"absent key", `{"env":{"OTHER":"x"}}`, RouteAbsent},
		{"absent env", `{}`, RouteAbsent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			writeFile(t, filepath.Join(home, ".claude"), "settings.json", tc.body)
			if got := InspectClaudeRoute(home).State; got != tc.want {
				t.Fatalf("state = %q want %q", got, tc.want)
			}
		})
	}
}

// Missing file → Absent (tool not routed, not drift).
func TestInspectClaudeRoute_MissingFile(t *testing.T) {
	if got := InspectClaudeRoute(t.TempDir()).State; got != RouteAbsent {
		t.Fatalf("state = %q want %q", got, RouteAbsent)
	}
}

func TestInspectCodexRoute(t *testing.T) {
	cases := []struct {
		name string
		body string
		want RouteState
	}{
		{
			"ours",
			"model_provider = \"openai-observer\"\n[model_providers.openai-observer]\nbase_url = \"http://127.0.0.1:8820/v1\"\n",
			RouteOurs,
		},
		{
			"drifted third-party provider",
			"model_provider = \"acme\"\n[model_providers.acme]\nbase_url = \"https://acme.example/v1\"\n",
			RouteDrifted,
		},
		{
			"absent no model_provider",
			"[model_providers.openai-observer]\nbase_url = \"http://127.0.0.1:8820/v1\"\n",
			RouteAbsent,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			writeFile(t, filepath.Join(home, ".codex"), "config.toml", tc.body)
			if got := InspectCodexRoute(home).State; got != tc.want {
				t.Fatalf("state = %q want %q", got, tc.want)
			}
		})
	}
}

func TestInspectRoutes(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".claude"), "settings.json",
		`{"env":{"ANTHROPIC_BASE_URL":"https://api.anthropic.com"}}`)
	got := InspectRoutes(home)
	// One status per inspection-table row (Track C item 2 widened this from
	// the original hard-coded claude+codex pair to every tool whose
	// persisted route proxyroute writes).
	if len(got) != len(InspectedTools()) {
		t.Fatalf("want %d statuses, got %d", len(InspectedTools()), len(got))
	}
	var drift int
	for _, s := range got {
		if s.State == RouteDrifted {
			drift++
		}
	}
	if drift != 1 {
		t.Fatalf("want 1 drifted (claude repointed), got %d", drift)
	}
}
