package proxyroute

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestProbeRouteWritersReadTheInjectedGetenv (audit finding 3's note, lane
// w4-homes-b): the crush, kimi-code and qwen-code route writers resolve
// their file through RegisterOptions.Getenv, as Cline does, never through
// os.Getenv. A pinned home with nil Getenv ignores the developer's shell
// variable; an injected variable moves the write; a relative one names no
// file. Red on the old writers, which read os.Getenv directly.
func TestProbeRouteWritersReadTheInjectedGetenv(t *testing.T) {
	type writer func(*Registrar) RegistrationResult
	rows := []struct {
		tool, env string
		write     writer
		rel       []string // the file under the relocated directory
		def       []string // the default file under the home
	}{
		{"crush", "CRUSH_GLOBAL_CONFIG", (*Registrar).RegisterCrush, []string{"crush.json"}, []string{".config", "crush", "crush.json"}},
		{"kimi-code", "KIMI_CODE_HOME", (*Registrar).RegisterKimiCode, []string{"config.toml"}, []string{".kimi-code", "config.toml"}},
		{"kimi-code lane", "KIMI_CODE_HOME", (*Registrar).RegisterKimiCodeLane, []string{"config.toml"}, []string{".kimi-code", "config.toml"}},
		{"qwen-code", "QWEN_HOME", (*Registrar).RegisterQwenCode, []string{"settings.json"}, []string{".qwen", "settings.json"}},
		{"qwen-code lane", "QWEN_HOME", (*Registrar).RegisterQwenCodeLane, []string{"settings.json"}, []string{".qwen", "settings.json"}},
	}
	for _, tc := range rows {
		t.Run(tc.tool, func(t *testing.T) {
			home := t.TempDir()
			shell := filepath.Join(t.TempDir(), "shell")
			moved := filepath.Join(t.TempDir(), "moved")
			t.Setenv(tc.env, shell) // the developer's shell, which a pinned home must not follow

			pinned, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home, DryRun: true})
			if err != nil {
				t.Fatal(err)
			}
			if got, want := tc.write(pinned).ConfigPath, filepath.Join(append([]string{home}, tc.def...)...); got != want {
				t.Errorf("pinned home, nil Getenv: ConfigPath = %q, want %q (the shell's %s leaked)", got, want, tc.env)
			}

			injected, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home, DryRun: true, Getenv: func(k string) string {
				if k == tc.env {
					return moved
				}
				return ""
			}})
			if err != nil {
				t.Fatal(err)
			}
			if got, want := tc.write(injected).ConfigPath, filepath.Join(append([]string{moved}, tc.rel...)...); got != want {
				t.Errorf("injected %s: ConfigPath = %q, want %q", tc.env, got, want)
			}

			relative, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home, DryRun: true, Getenv: func(k string) string {
				if k == tc.env {
					return "rel"
				}
				return ""
			}})
			if err != nil {
				t.Fatal(err)
			}
			if res := tc.write(relative); res.Error == nil || res.ConfigPath != "" {
				t.Errorf("relative %s: got %+v, want an error and no file", tc.env, res)
			}
		})
	}
}

// TestRouteArtifactsResolve pins that the route files resolve through their
// agentconfig rows on this OS, so routeArtifactPath's no-file error is
// unreachable with no relocation variable set.
func TestRouteArtifactsResolve(t *testing.T) {
	for _, ri := range routeInspectors() {
		got, err := agentconfig.ResolveArtifact(ri.artifact, agentconfig.PathEnv{GOOS: runtime.GOOS, Home: "/h"})
		if err != nil || got.Status != agentconfig.PathResolved {
			t.Errorf("%s: artifact %q = %+v, %v", ri.tool, ri.artifact, got, err)
		}
	}
}

// TestRouteInspectorArtifactsMatchTheWriters: with no relocation variable
// set, every inspector row's path is its artifact's default, so the row's
// artifact id names the file its writer writes.
func TestRouteInspectorArtifactsMatchTheWriters(t *testing.T) {
	for _, k := range []string{"KIMI_CODE_HOME", "QWEN_HOME", "CRUSH_GLOBAL_CONFIG", "XDG_CONFIG_HOME"} {
		t.Setenv(k, "")
	}
	home := t.TempDir()
	for _, ri := range routeInspectors() {
		got, err := agentconfig.ResolveArtifact(ri.artifact, agentconfig.PathEnv{GOOS: runtime.GOOS, Home: home})
		if err != nil {
			t.Fatalf("%s: %v", ri.tool, err)
		}
		rowPath, rowErr := ri.path(inspectEnv{home: home, getenv: crossmount.NoEnv})
		if want := filepath.Clean(got.Path); rowErr != nil || rowPath != want {
			t.Errorf("%s: row path %q (%v), artifact %q default %q", ri.tool, rowPath, rowErr, ri.artifact, want)
		}
	}
}

// TestRelocatedRouteHomes pins CC-8 (CLAUDE_CONFIG_DIR) and CX-4
// (CODEX_HOME) for the route writers and the inspector together: the writer
// writes the relocated file, InspectRoutesWith reads that same file (and
// reports it as the row's ConfigPath, the address route maintenance and
// managed integrity use), and the default home is left alone. The old code
// hard-coded ~/.claude and ~/.codex in both.
func TestRelocatedRouteHomes(t *testing.T) {
	cases := []struct {
		name  string
		tool  string
		env   string
		file  string
		write func(r *Registrar) RegistrationResult
	}{
		{"CLAUDE_CONFIG_DIR", "claude-code", "CLAUDE_CONFIG_DIR", "settings.json", (*Registrar).RegisterClaudeCode},
		{"CODEX_HOME", "codex", "CODEX_HOME", "config.toml", (*Registrar).RegisterCodex},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			moved := filepath.Join(t.TempDir(), "profile")
			if err := os.MkdirAll(moved, 0o755); err != nil {
				t.Fatal(err)
			}
			if tc.tool == "claude-code" {
				// RegisterClaudeCode routes an existing settings.json only.
				if err := os.WriteFile(filepath.Join(moved, tc.file), []byte("{}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			env := map[string]string{tc.env: moved}
			getenv := func(k string) string { return env[k] }
			r, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home, Getenv: getenv})
			if err != nil {
				t.Fatal(err)
			}
			want := filepath.Join(moved, tc.file)
			res := tc.write(r)
			if res.Error != nil || res.ConfigPath != want || !(res.Added || res.AlreadySet) {
				t.Fatalf("write = %+v, want a route at %s", res, want)
			}
			var row RouteStatus
			for _, rs := range InspectRoutesWith(home, InspectOptions{Getenv: getenv}) {
				if rs.Tool == tc.tool {
					row = rs
				}
			}
			if row.ConfigPath != want || row.State != RouteOurs || !row.ArtifactPresent {
				t.Errorf("inspected %+v, want ours at %s", row, want)
			}
			if !row.WasRouted {
				t.Error("the provenance record is not keyed by the relocated path")
			}
			for _, d := range []string{".claude", ".codex"} {
				if _, err := os.Stat(filepath.Join(home, d)); err == nil {
					t.Errorf("the default home's %s was written", d)
				}
			}
		})
	}
}

// TestInspectDefaultEnvKeepsAPinnedHome: InspectRoutes over a home that is
// not this process's own reads no relocation variable, so a test or sandbox
// home never follows the developer's shell (the RegisterOptions.Getenv rule).
func TestInspectDefaultEnvKeepsAPinnedHome(t *testing.T) {
	t.Setenv("CODEX_HOME", t.TempDir())
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	home := t.TempDir()
	for _, rs := range InspectRoutes(home) {
		switch rs.Tool {
		case "claude-code":
			if want := filepath.Join(home, ".claude", "settings.json"); rs.ConfigPath != want {
				t.Errorf("claude-code ConfigPath = %q, want %q", rs.ConfigPath, want)
			}
		case "codex":
			if want := filepath.Join(home, ".codex", "config.toml"); rs.ConfigPath != want {
				t.Errorf("codex ConfigPath = %q, want %q", rs.ConfigPath, want)
			}
		}
	}
}
