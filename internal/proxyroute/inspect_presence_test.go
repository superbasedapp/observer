package proxyroute

import (
	"path/filepath"
	"testing"
)

// inspect_presence_test.go — the tri-state half of the route inspectors
// (adversarial finding P1-2 on Track C item 2,
// docs/plans/org-guardrail-control-wave-2026-09-21.md).
//
// Every reader must tell "this tool is not installed on this host" apart from
// "this tool is installed here and its route key is gone". Before the
// tri-state, a managed node holding any enforce.* authority reported every
// tool the developer had never installed as drift — a developer who only runs
// Claude Code reported drifted_tools=[codex crush kimi-code qwen-code] and
// opened an integrity_risk finding on every node in the fleet.
//
// One row per reader, three outcomes each:
//
//	missing artifact   → absent, never drift (any drift mode)
//	artifact, no key   → absent, drift ONLY where routes are maintained
//	artifact, wrong host → drifted where routes are maintained; with
//	                       maintenance off, or no posture and no route the
//	                       organization wrote, the developer's own setup
func TestRouteReaderArtifactPresence(t *testing.T) {
	// A third-party host, not any tool's stock default (qwen-code's default
	// api.openai.com/v1 reads as "not routed yet", see readQwenCodeBaseURL).
	const remote = "https://llm.example.com/v1"

	cases := []struct {
		tool string
		// writeNoKey lays down the tool's own config WITHOUT any route key.
		writeNoKey func(t *testing.T, home string)
		// writeRemote lays it down pointing at a third-party host.
		writeRemote func(t *testing.T, home string)
	}{
		{
			tool: "claude-code",
			writeNoKey: func(t *testing.T, home string) {
				writeFile(t, filepath.Join(home, ".claude"), "settings.json", `{"env":{"OTHER":"x"}}`)
			},
			writeRemote: func(t *testing.T, home string) {
				writeFile(t, filepath.Join(home, ".claude"), "settings.json",
					`{"env":{"ANTHROPIC_BASE_URL":"https://api.anthropic.com"}}`)
			},
		},
		{
			tool: "codex",
			writeNoKey: func(t *testing.T, home string) {
				writeFile(t, filepath.Join(home, ".codex"), "config.toml", "model = \"gpt-5\"\n")
			},
			writeRemote: func(t *testing.T, home string) {
				writeFile(t, filepath.Join(home, ".codex"), "config.toml",
					"model_provider = \"acme\"\n[model_providers.acme]\nbase_url = \""+remote+"\"\n")
			},
		},
		{
			tool: "kimi-code",
			writeNoKey: func(t *testing.T, home string) {
				writeFile(t, filepath.Join(home, ".kimi-code"), "config.toml",
					"[providers.openai]\napi_key = \"redacted\"\n")
			},
			writeRemote: func(t *testing.T, home string) {
				writeFile(t, filepath.Join(home, ".kimi-code"), "config.toml",
					"[providers.openai]\nbase_url = \""+remote+"\"\n")
			},
		},
		{
			tool: "qwen-code",
			writeNoKey: func(t *testing.T, home string) {
				writeFile(t, filepath.Join(home, ".qwen"), "settings.json", `{"model":{"name":"qwen3","baseUrl":"https://api.openai.com/v1"}}`)
			},
			writeRemote: func(t *testing.T, home string) {
				writeFile(t, filepath.Join(home, ".qwen"), "settings.json",
					`{"model":{"baseUrl":"`+remote+`"}}`)
			},
		},
		{
			tool: "crush",
			writeNoKey: func(t *testing.T, home string) {
				writeFile(t, filepath.Join(home, ".config", "crush"), "crush.json",
					`{"providers":{"openai":{"api_key":"redacted"}}}`)
			},
			writeRemote: func(t *testing.T, home string) {
				writeFile(t, filepath.Join(home, ".config", "crush"), "crush.json",
					`{"providers":{"openai":{"base_url":"`+remote+`"}}}`)
			},
		},
	}

	// newHome isolates every tool's env-var config override so one reader
	// can never pick up another case's directory.
	newHome := func(t *testing.T) string {
		t.Helper()
		home := t.TempDir()
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
		t.Setenv("CRUSH_GLOBAL_CONFIG", "")
		t.Setenv("KIMI_CODE_HOME", "")
		t.Setenv("QWEN_HOME", "")
		return home
	}

	driftedUnder := func(t *testing.T, home, tool string, mode DriftMode) bool {
		t.Helper()
		for _, got := range DriftedTools(InspectRoutes(home), DriftPolicy{Mode: mode}) {
			if got == tool {
				return true
			}
		}
		return false
	}
	allModes := []DriftMode{DriftModeOff, DriftModeOrgRoutes, DriftModeMaintained}

	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			t.Run("artifact missing is never drift", func(t *testing.T) {
				home := newHome(t)
				got := statusFor(InspectRoutes(home), tc.tool)
				if got.State != RouteAbsent {
					t.Fatalf("state = %q, want %q", got.State, RouteAbsent)
				}
				if got.ArtifactPresent {
					t.Fatal("ArtifactPresent = true with nothing on disk")
				}
				for _, mode := range allModes {
					if driftedUnder(t, home, tc.tool, mode) {
						t.Fatalf("%s: an uninstalled tool must never be drift", mode)
					}
				}
			})

			t.Run("artifact present without the route key", func(t *testing.T) {
				home := newHome(t)
				tc.writeNoKey(t, home)
				got := statusFor(InspectRoutes(home), tc.tool)
				if got.State != RouteAbsent {
					t.Fatalf("state = %q, want %q", got.State, RouteAbsent)
				}
				if !got.ArtifactPresent {
					t.Fatal("ArtifactPresent = false although the config file exists")
				}
				for _, mode := range []DriftMode{DriftModeOff, DriftModeOrgRoutes} {
					if driftedUnder(t, home, tc.tool, mode) {
						t.Fatalf("%s: a missing route key the organization never wrote must not be drift", mode)
					}
				}
				if !driftedUnder(t, home, tc.tool, DriftModeMaintained) {
					t.Fatal("maintained: a config present with the route key gone IS drift")
				}
			})

			t.Run("artifact present pointing at a third-party host", func(t *testing.T) {
				home := newHome(t)
				tc.writeRemote(t, home)
				got := statusFor(InspectRoutes(home), tc.tool)
				if got.State != RouteDrifted {
					t.Fatalf("state = %q, want %q", got.State, RouteDrifted)
				}
				if !got.ArtifactPresent {
					t.Fatal("ArtifactPresent = false although the config file exists")
				}
				if !driftedUnder(t, home, tc.tool, DriftModeMaintained) {
					t.Fatal("maintained: a repointed route is drift")
				}
				for _, mode := range []DriftMode{DriftModeOff, DriftModeOrgRoutes} {
					if driftedUnder(t, home, tc.tool, mode) {
						t.Fatalf("%s: a host the organization never routed is the developer's own setup", mode)
					}
				}
			})
		})
	}
}
