package proxyroute

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// relRelocValue is a relative relocation value: the tool would read it
// against its own working directory, which Observer cannot know.
const relRelocValue = "observer-r188-rel"

// TestRelativeRelocationRefusesRouteWritersAndInspector pins R-188 F6: a
// relocation variable holding a relative path (CLAUDE_CONFIG_DIR,
// CODEX_HOME, and KIMI_CODE_HOME for a probe-lane tool) makes the route
// writer refuse naming the variable and write nothing, and makes the
// inspector report the route unknown rather than read the vendor default
// under the home. The default file below carries an Observer route; before
// the fix the native writers and every inspector fell back to it, so a
// relative CODEX_HOME routed ~/.codex (which Codex does not read) and the
// inspection reported that route present.
func TestRelativeRelocationRefusesRouteWritersAndInspector(t *testing.T) {
	const (
		claudeRoute = `{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8820"}}`
		codexRoute  = "model_provider = \"openai-observer\"\n\n[model_providers.openai-observer]\nname = \"observer\"\nbase_url = \"http://127.0.0.1:8820/v1\"\nwire_api = \"responses\"\n"
		kimiRoute   = "[providers.openai]\nbase_url = \"http://127.0.0.1:8820/v1\"\n"
	)
	cases := []struct {
		name, tool, env string
		def             []string // the vendor default under the home
		body            string   // an Observer route at the default
		act             func(*Registrar) RegistrationResult
	}{
		{"claude-code register", "claude-code", "CLAUDE_CONFIG_DIR", []string{".claude", "settings.json"}, claudeRoute, (*Registrar).RegisterClaudeCode},
		{"claude-code unregister", "claude-code", "CLAUDE_CONFIG_DIR", []string{".claude", "settings.json"}, claudeRoute, (*Registrar).UnregisterClaudeCode},
		{"codex register", "codex", "CODEX_HOME", []string{".codex", "config.toml"}, codexRoute, (*Registrar).RegisterCodex},
		{"codex unregister", "codex", "CODEX_HOME", []string{".codex", "config.toml"}, codexRoute, (*Registrar).UnregisterCodex},
		{"kimi-code register", "kimi-code", "KIMI_CODE_HOME", []string{".kimi-code", "config.toml"}, kimiRoute, (*Registrar).RegisterKimiCode},
		{"kimi-code lane register", "kimi-code", "KIMI_CODE_HOME", []string{".kimi-code", "config.toml"}, kimiRoute, (*Registrar).RegisterKimiCodeLane},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			def := filepath.Join(append([]string{home}, tc.def...)...)
			if err := os.MkdirAll(filepath.Dir(def), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(def, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			getenv := func(k string) string {
				if k == tc.env {
					return relRelocValue
				}
				return ""
			}
			r, err := NewRegistrar(RegisterOptions{ProxyPort: 8821, HomeDir: home, Getenv: getenv})
			if err != nil {
				t.Fatal(err)
			}
			res := tc.act(r)
			if res.Error == nil || !strings.Contains(res.Error.Error(), tc.env) {
				t.Errorf("writer: got %+v, want a refusal naming %s", res, tc.env)
			}
			if res.ConfigPath != "" || res.Added {
				t.Errorf("writer: ConfigPath %q, Added %v; want no file named and nothing added", res.ConfigPath, res.Added)
			}
			if got, err := os.ReadFile(def); err != nil || string(got) != tc.body {
				t.Errorf("the vendor default %s changed (%v): %q", def, err, got)
			}
			if _, err := os.Stat(filepath.Join(home, ".observer", ProvenanceFileName)); err == nil {
				t.Errorf("a route provenance record was written for a refused route")
			}
			if _, err := os.Stat(relRelocValue); err == nil {
				t.Errorf("the relative %s was created in the test's working directory", relRelocValue)
			}

			var row *RouteStatus
			statuses := InspectRoutesWith(home, InspectOptions{Getenv: getenv})
			for i := range statuses {
				if statuses[i].Tool == tc.tool {
					row = &statuses[i]
				}
			}
			if row == nil {
				t.Fatalf("no inspection row for %s", tc.tool)
			}
			if row.State != RouteState("unknown") || row.ArtifactPresent || row.ConfigPath != "" {
				t.Errorf("inspector: got %+v, want state unknown, artifact not present, no config path", *row)
			}
			if row.UnresolvedBy != tc.env { // r188f6:new-api
				t.Errorf("inspector: UnresolvedBy %q, want %s", row.UnresolvedBy, tc.env) // r188f6:new-api
			} // r188f6:new-api
			if got := DriftedTools(statuses, DriftPolicy{Mode: DriftModeMaintained}); len(got) != 0 {
				t.Errorf("an unknown route read as drift: %v", got)
			}
		})
	}
}
