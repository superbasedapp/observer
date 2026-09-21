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
//	missing artifact   → absent, never drift (either tenancy)
//	artifact, no key   → absent, drift ONLY on a managed enforcing node
//	artifact, wrong host → drifted under BOTH tenancies
func TestRouteReaderArtifactPresence(t *testing.T) {
	const remote = "https://api.openai.com/v1"

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
					"[providers.anthropic]\napi_key = \"redacted\"\n")
			},
			writeRemote: func(t *testing.T, home string) {
				writeFile(t, filepath.Join(home, ".kimi-code"), "config.toml",
					"[providers.openai]\nbase_url = \""+remote+"\"\n")
			},
		},
		{
			tool: "qwen-code",
			writeNoKey: func(t *testing.T, home string) {
				writeFile(t, filepath.Join(home, ".qwen"), "settings.json", `{"model":{"name":"qwen3"}}`)
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
					`{"providers":{"anthropic":{}}}`)
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
		t.Setenv("CRUSH_CONFIG", "")
		t.Setenv("KIMI_CODE_HOME", "")
		t.Setenv("QWEN_HOME", "")
		return home
	}

	driftedUnder := func(t *testing.T, home, tool string, absentIsDrift bool) bool {
		t.Helper()
		for _, got := range DriftedTools(InspectRoutes(home), absentIsDrift) {
			if got == tool {
				return true
			}
		}
		return false
	}

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
				for _, absentIsDrift := range []bool{false, true} {
					if driftedUnder(t, home, tc.tool, absentIsDrift) {
						t.Fatalf("absentIsDrift=%v: an uninstalled tool must never be drift", absentIsDrift)
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
				if driftedUnder(t, home, tc.tool, false) {
					t.Fatal("individual node: a missing route key must not be drift")
				}
				if !driftedUnder(t, home, tc.tool, true) {
					t.Fatal("managed + enforce: a config present with the route key gone IS drift")
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
				for _, absentIsDrift := range []bool{false, true} {
					if !driftedUnder(t, home, tc.tool, absentIsDrift) {
						t.Fatalf("absentIsDrift=%v: a repointed route is drift under both tenancies", absentIsDrift)
					}
				}
			})
		})
	}
}
