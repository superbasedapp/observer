package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// pinLaunchFiles points the launcher's file boundary at temp directories:
// home, the launch directory and a system root, so no launch-gate read
// leaves the test.
func pinLaunchFiles(t *testing.T) (home, project, system string) {
	t.Helper()
	home, project, system = t.TempDir(), t.TempDir(), t.TempDir()
	saved := launchFiles
	t.Cleanup(func() { launchFiles = saved })
	launchFiles.home = func() (string, error) { return home, nil }
	launchFiles.cwd = func() (string, error) { return project, nil }
	launchFiles.read = os.ReadFile
	launchFiles.systemRoot = system
	return home, project, system
}

func writeLaunchFile(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestGeminiAuthPinnedCaveat pins CLI-6: a routed Gemini launch names the
// saved sign-in source that may outrank the route (a settings key, a .env
// variable, an exported variable) by file and key only, never its value.
// On the old code every routed launch printed only the generic caveat. One
// case per RouteGate source (AuthSettingKeys, DotenvKeys in a file and in
// the environment), plus the nothing-saved row.
func TestGeminiAuthPinnedCaveat(t *testing.T) {
	const secret = "oauth-personal-not-a-secret"
	cases := []struct {
		name    string
		setup   func(t *testing.T, home, project, system string) []string
		want    []string
		generic bool
	}{
		{
			name:    "nothing saved: the generic caveat",
			setup:   func(*testing.T, string, string, string) []string { return nil },
			generic: true,
		},
		{
			name: "user settings: saved selectedType (JSONC)",
			setup: func(t *testing.T, home, _, _ string) []string {
				writeLaunchFile(t, filepath.Join(home, ".gemini", "settings.json"), "// saved by /auth\n{\"security\":{\"auth\":{\"selectedType\":\""+secret+"\"}}}")
				return nil
			},
			want: []string{filepath.Join(".gemini", "settings.json") + ": security.auth.selectedType"},
		},
		{
			name: "project settings: saved selectedType",
			setup: func(t *testing.T, _, project, _ string) []string {
				writeLaunchFile(t, filepath.Join(project, ".gemini", "settings.json"), `{"security":{"auth":{"selectedType":"`+secret+`"}}}`)
				return nil
			},
			want: []string{"security.auth.selectedType"},
		},
		{
			name: "system settings: an administrator's enforcedType",
			setup: func(t *testing.T, home, _, system string) []string {
				r, err := agentconfig.ResolveArtifact("gemini-cli/system-settings", agentconfig.PathEnv{GOOS: launchFiles.goos, Home: home, SystemRoot: system, Relocate: true})
				if err != nil || r.Path == "" || !strings.HasPrefix(r.Path, system) {
					t.Fatalf("system settings resolve to %q (%v), want under %s", r.Path, err, system)
				}
				writeLaunchFile(t, r.Path, `{"security":{"auth":{"enforcedType":"`+secret+`"}}}`)
				return nil
			},
			want: []string{"security.auth.enforcedType"},
		},
		{
			name: "project .env: GOOGLE_GENAI_USE_GCA",
			setup: func(t *testing.T, _, project, _ string) []string {
				writeLaunchFile(t, filepath.Join(project, ".env"), "GOOGLE_GENAI_USE_GCA="+secret+"\n")
				return nil
			},
			want: []string{".env: GOOGLE_GENAI_USE_GCA"},
		},
		{
			name: "launch environment: GOOGLE_GENAI_USE_VERTEXAI exported",
			setup: func(*testing.T, string, string, string) []string {
				return []string{"GOOGLE_GENAI_USE_VERTEXAI=" + secret}
			},
			want: []string{"GOOGLE_GENAI_USE_VERTEXAI (launch environment)"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home, project, system := pinLaunchFiles(t)
			environ := append([]string{"GEMINI_API_KEY=x"}, tc.setup(t, home, project, system)...)
			r := resolveGatedRoute("gemini-cli", "gemini", "http://127.0.0.1:8820", "", nil, environ)
			if !r.routed || r.err != nil {
				t.Fatalf("routed=%v err=%v: a saved sign-in never refuses the route", r.routed, r.err)
			}
			if tc.generic {
				if !strings.Contains(r.caveat, "sign in with Google") || strings.Contains(r.caveat, "saved sign-in choice") {
					t.Fatalf("caveat %q, want the generic one", r.caveat)
				}
				return
			}
			if !strings.Contains(r.caveat, "saved sign-in choice") {
				t.Fatalf("caveat %q does not name the saved sign-in", r.caveat)
			}
			for _, w := range tc.want {
				if !strings.Contains(r.caveat, w) {
					t.Errorf("caveat %q misses %q", r.caveat, w)
				}
			}
			if strings.Contains(r.caveat, secret) {
				t.Fatalf("caveat carries the value: %q", r.caveat)
			}
		})
	}
}

// TestGateAuthPinsUngated: a gate with no saved sign-in sources reads no
// file (copilot-cli's gate, an ungated route).
func TestGateAuthPinsUngated(t *testing.T) {
	saved := launchFiles
	t.Cleanup(func() { launchFiles = saved })
	launchFiles.read = func(p string) ([]byte, error) {
		t.Fatalf("read %s for a gate with no saved sign-in sources", p)
		return nil, nil
	}
	_ = resolveGatedRoute("copilot-cli", "copilot-cli", "http://127.0.0.1:8820", "m", nil, []string{"COPILOT_PROVIDER_API_KEY=x"})
	_ = resolveGatedRoute("opencode", "opencode", "http://127.0.0.1:8820", "", nil, nil)
}

func TestExpandLaunchFile(t *testing.T) {
	cases := []struct{ entry, home, project, want string }{
		{"~/.env", "/h", "/p", filepath.Join("/h", ".env")},
		{"<project>/.gemini/.env", "/h", "/p", filepath.Join("/p", ".gemini", ".env")},
		{"~/.env", "", "/p", ""},
		{"<project>/.env", "/h", "", ""},
		{"x.env", "/h", "/p", "x.env"},
	}
	for _, tc := range cases {
		if got := expandLaunchFile(tc.entry, tc.home, tc.project); got != tc.want {
			t.Errorf("expandLaunchFile(%q) = %q, want %q", tc.entry, got, tc.want)
		}
	}
}
