// gemini_route_test.go — the conditional route of `observer gemini` (T-345):
// GOOGLE_GEMINI_BASE_URL is honoured only by Gemini's API-key and gateway
// auth types, so the launcher routes only with GEMINI_API_KEY in the
// environment and otherwise launches UNROUTED, saying so. A recording stub
// stands in for `gemini`; no real binary is spawned.

package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

var geminiGateEnv = []string{
	"GEMINI_API_KEY", "GOOGLE_GEMINI_BASE_URL", "GOOGLE_GENAI_USE_GCA", "GOOGLE_GENAI_USE_VERTEXAI",
}

func TestGeminiRouteDecision(t *testing.T) {
	const fakeKey = "fake-test-key-not-a-secret"
	cases := []struct {
		name        string
		env         map[string]string
		wantRouted  bool
		wantNotice  string
		forbidInErr string
	}{
		{
			name:        "Google sign-in (no key): unrouted, says why, sets nothing",
			wantNotice:  "observer gemini: not routed through the proxy: Gemini CLI has no GEMINI_API_KEY in this environment, so it uses your Google sign-in (or Vertex AI), which talks to Google directly; set GEMINI_API_KEY to route it",
			forbidInErr: "routing via",
		},
		{
			name:       "API key exported: routed",
			env:        map[string]string{"GEMINI_API_KEY": fakeKey},
			wantRouted: true,
		},
		{
			name:        "own endpoint: left alone, not claimed",
			env:         map[string]string{"GEMINI_API_KEY": fakeKey, "GOOGLE_GEMINI_BASE_URL": "https://my-gateway.example.com"},
			wantNotice:  "GOOGLE_GEMINI_BASE_URL is already set to your own endpoint",
			forbidInErr: "routing via",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantRouted {
				requireComponents(t, "capture.proxy")
			}
			unsetEnvForTest(t, geminiGateEnv...)
			pinLaunchFiles(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			dir := t.TempDir()
			cfgPath := writeCopilotCLITestConfig(t, dir)
			argvPath := filepath.Join(dir, "argv.out")
			envPath := filepath.Join(dir, "env.out")
			stub := writeArgvEnvRecorderStub(t, dir, argvPath, envPath)

			cmd := newGeminiCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs([]string{"--config", cfgPath, "--gemini-path", stub})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("Execute: %v (stderr=%q)", err, out.String())
			}
			baseURL, _ := readRecordedEnvValue(t, envPath, "GOOGLE_GEMINI_BASE_URL")
			routed := strings.HasPrefix(baseURL, "http://127.0.0.1:")
			if routed != tc.wantRouted {
				t.Fatalf("routed = %v (GOOGLE_GEMINI_BASE_URL=%q), want %v", routed, baseURL, tc.wantRouted)
			}
			if own := tc.env["GOOGLE_GEMINI_BASE_URL"]; own != "" && baseURL != own {
				t.Fatalf("own endpoint overwritten: %q, want %q", baseURL, own)
			}
			if !tc.wantRouted && tc.env["GOOGLE_GEMINI_BASE_URL"] == "" && baseURL != "" {
				t.Fatalf("unrouted launch set GOOGLE_GEMINI_BASE_URL=%q", baseURL)
			}
			if tc.wantNotice != "" && !strings.Contains(out.String(), tc.wantNotice) {
				t.Fatalf("stderr %q missing %q", out.String(), tc.wantNotice)
			}
			if tc.forbidInErr != "" && strings.Contains(out.String(), tc.forbidInErr) {
				t.Fatalf("stderr %q must not contain %q", out.String(), tc.forbidInErr)
			}
			if strings.Contains(out.String(), fakeKey) {
				t.Fatal("launcher output leaks the key value")
			}
		})
	}
}

// TestGeminiRoutedCaveat: a routed Gemini launch names the lane the gate cannot
// see (a saved Google sign-in or Vertex choice), so "routing via" never
// over-claims; an ungated route carries no caveat.
func TestGeminiRoutedCaveat(t *testing.T) {
	pinLaunchFiles(t)
	environ := []string{"GEMINI_API_KEY=x"}
	r := resolveGatedRoute("gemini-cli", "gemini", "http://127.0.0.1:8820", "", nil, environ)
	if !r.routed {
		t.Fatalf("key present: routed = false")
	}
	for _, want := range []string{"observer gemini: note:", "sign in with Google", "Vertex AI", "talks to Google directly"} {
		if !strings.Contains(r.caveat, want) {
			t.Errorf("caveat %q misses %q", r.caveat, want)
		}
	}
	// The developer pointed the base URL at the proxy by hand: still routed,
	// still caveated.
	r = resolveGatedRoute("gemini-cli", "gemini", "http://127.0.0.1:8820", "", nil, []string{"GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:8820"})
	if !r.routed || r.caveat == "" {
		t.Errorf("hand-set proxy URL: routed=%v caveat=%q", r.routed, r.caveat)
	}
	if r := resolveGatedRoute("opencode", "opencode", "http://127.0.0.1:8820", "", nil, nil); !r.routed || r.caveat != "" {
		t.Errorf("ungated route: routed=%v caveat=%q", r.routed, r.caveat)
	}
}

func TestGeminiLaunchEnv(t *testing.T) {
	if got := geminiLaunchEnv(false, "http://127.0.0.1:8820"); len(got) != 0 {
		t.Errorf("unrouted env = %v, want empty", got)
	}
	got := geminiLaunchEnv(true, "http://127.0.0.1:8820/")
	if got["GOOGLE_GEMINI_BASE_URL"] != "http://127.0.0.1:8820" || len(got) != 1 {
		t.Errorf("routed env = %v", got)
	}
}
