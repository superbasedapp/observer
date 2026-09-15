package routeattest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// fakeTraffic is a table-driven TrafficSource stub for tests.
type fakeTraffic struct {
	counts map[string][2]int // tool -> [native, proxied]
}

func (f fakeTraffic) NativeAndProxiedCounts(tool string) (native, proxied int) {
	c, ok := f.counts[tool]
	if !ok {
		return 0, 0
	}
	return c[0], c[1]
}

func TestIsExempt(t *testing.T) {
	cases := []struct {
		name       string
		cap        integration.Capability
		wantExempt bool
	}{
		{
			name:       "native_exempt routability",
			cap:        integration.Capability{Tool: "kiro-cli", Routability: integration.RouteStatusNativeExempt},
			wantExempt: true,
		},
		{
			name:       "browser extension hook",
			cap:        integration.Capability{Tool: "claude-web", Hook: integration.HookSpec{Mechanism: integration.HookBrowserExtension}},
			wantExempt: true,
		},
		{
			name:       "routable now, nil proxy — NOT exempt (e.g. cline manual-paste)",
			cap:        integration.Capability{Tool: "cline", Proxy: nil, Routability: integration.RouteStatusRoutableNow},
			wantExempt: false,
		},
		{
			name:       "probe required — NOT exempt",
			cap:        integration.Capability{Tool: "copilot", Proxy: nil, Routability: integration.RouteStatusProbeRequired},
			wantExempt: false,
		},
		{
			name:       "routed now with live proxy — NOT exempt",
			cap:        integration.Capability{Tool: "claude-code", Proxy: &integration.ProxyRoute{Kind: integration.RouteEnvSettings}, Routability: integration.RouteStatusRoutableNow},
			wantExempt: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := IsExempt(tc.cap)
			if got != tc.wantExempt {
				t.Fatalf("IsExempt(%s) = %v (reason %q), want %v", tc.cap.Tool, got, reason, tc.wantExempt)
			}
			if got && reason == "" {
				t.Errorf("IsExempt(%s) = true with empty reason", tc.cap.Tool)
			}
		})
	}
}

func TestKindOf(t *testing.T) {
	cases := []struct {
		name     string
		cap      integration.Capability
		wantKind integration.RouteKind
		wantOK   bool
	}{
		{
			name:     "verified Proxy wins",
			cap:      integration.Capability{Proxy: &integration.ProxyRoute{Kind: integration.RouteEnvSettings}, ProxyProbe: &integration.ProxyRoute{Kind: integration.RouteConfigFile}},
			wantKind: integration.RouteEnvSettings,
			wantOK:   true,
		},
		{
			name:     "falls back to ProxyProbe when Proxy is nil",
			cap:      integration.Capability{Proxy: nil, ProxyProbe: &integration.ProxyRoute{Kind: integration.RouteProviderJSON}},
			wantKind: integration.RouteProviderJSON,
			wantOK:   true,
		},
		{
			name:     "neither set — no kind",
			cap:      integration.Capability{Proxy: nil, ProxyProbe: nil},
			wantKind: "",
			wantOK:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, ok := kindOf(tc.cap)
			if kind != tc.wantKind || ok != tc.wantOK {
				t.Fatalf("kindOf() = (%q, %v), want (%q, %v)", kind, ok, tc.wantKind, tc.wantOK)
			}
		})
	}
}

func TestMapRouteState(t *testing.T) {
	cases := []struct {
		state proxyroute.RouteState
		want  Verdict
	}{
		{proxyroute.RouteOurs, VerdictRoutedLoopback},
		{proxyroute.RouteOrgGateway, VerdictRoutedOrgGateway},
		{proxyroute.RouteDrifted, VerdictDrifted},
		{proxyroute.RouteAbsent, VerdictUnrouted},
		{proxyroute.RouteState("something-unrecognized"), VerdictUnrouted},
	}
	for _, tc := range cases {
		t.Run(string(tc.state), func(t *testing.T) {
			got, reason := mapRouteState(tc.state)
			if got != tc.want {
				t.Fatalf("mapRouteState(%q) = %q (reason %q), want %q", tc.state, got, reason, tc.want)
			}
			if reason == "" {
				t.Errorf("mapRouteState(%q) returned empty reason", tc.state)
			}
		})
	}
}

func TestAttestByTraffic(t *testing.T) {
	cases := []struct {
		name     string
		traffic  TrafficSource
		tool     string
		wantVerd Verdict
	}{
		{
			name:     "nil traffic source",
			traffic:  nil,
			tool:     "grok",
			wantVerd: VerdictUnrouted,
		},
		{
			name:     "native and proxied both observed",
			traffic:  fakeTraffic{counts: map[string][2]int{"grok": {5, 3}}},
			tool:     "grok",
			wantVerd: VerdictAttestedByTraffic,
		},
		{
			name:     "native only — bypass suspect",
			traffic:  fakeTraffic{counts: map[string][2]int{"grok": {5, 0}}},
			tool:     "grok",
			wantVerd: VerdictBypassSuspect,
		},
		{
			name:     "no native activity",
			traffic:  fakeTraffic{counts: map[string][2]int{"grok": {0, 0}}},
			tool:     "grok",
			wantVerd: VerdictUnrouted,
		},
		{
			name:     "tool absent from traffic source",
			traffic:  fakeTraffic{counts: map[string][2]int{}},
			tool:     "grok",
			wantVerd: VerdictUnrouted,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := AttestByTraffic(tc.tool, tc.traffic)
			if got != tc.wantVerd {
				t.Fatalf("AttestByTraffic(%s) = %q (reason %q), want %q", tc.tool, got, reason, tc.wantVerd)
			}
			if reason == "" {
				t.Errorf("AttestByTraffic(%s) returned empty reason", tc.tool)
			}
		})
	}
}

// TestConfigInspectorsCoverEveryRouteKind pins that every RouteKind
// constant declared in internal/integration has an entry in
// configInspectors — even if that entry is an honest stub. A future
// RouteKind added without a corresponding row here is a build-time-
// invisible coverage gap; this test makes it a test failure instead.
func TestConfigInspectorsCoverEveryRouteKind(t *testing.T) {
	allKinds := []integration.RouteKind{
		integration.RouteLauncher,
		integration.RouteEnvSettings,
		integration.RouteConfigFile,
		integration.RouteProviderJSON,
		integration.RouteVSCodeSettings,
		integration.RouteManual,
	}
	for _, kind := range allKinds {
		if _, ok := configInspectors[kind]; !ok {
			t.Errorf("configInspectors has no entry for RouteKind %q (add a real inspector or an honest stubInspector)", kind)
		}
	}
	if len(configInspectors) != len(allKinds) {
		t.Errorf("configInspectors has %d entries, want exactly %d (one per known RouteKind) — a stray or duplicate key?", len(configInspectors), len(allKinds))
	}
}

func TestEnvSettingsInspector(t *testing.T) {
	t.Run("claude-code loopback route", func(t *testing.T) {
		home := t.TempDir()
		writeClaudeSettings(t, home, "http://127.0.0.1:8820")
		verdict, reason, ok := envSettingsInspector("claude-code", home, nil)
		if !ok {
			t.Fatalf("envSettingsInspector(claude-code) ok = false, want true (reason %q)", reason)
		}
		if verdict != VerdictRoutedLoopback {
			t.Fatalf("verdict = %q, want %q", verdict, VerdictRoutedLoopback)
		}
	})

	t.Run("claude-code drifted route", func(t *testing.T) {
		home := t.TempDir()
		writeClaudeSettings(t, home, "https://third-party.example.com")
		verdict, _, ok := envSettingsInspector("claude-code", home, nil)
		if !ok || verdict != VerdictDrifted {
			t.Fatalf("verdict = %q ok=%v, want %q true", verdict, ok, VerdictDrifted)
		}
	})

	t.Run("claude-code absent config — unrouted", func(t *testing.T) {
		home := t.TempDir()
		verdict, _, ok := envSettingsInspector("claude-code", home, nil)
		if !ok || verdict != VerdictUnrouted {
			t.Fatalf("verdict = %q ok=%v, want %q true", verdict, ok, VerdictUnrouted)
		}
	})

	t.Run("unrelated tool sharing the kind — ok false, no misattribution", func(t *testing.T) {
		home := t.TempDir()
		writeClaudeSettings(t, home, "http://127.0.0.1:8820")
		_, reason, ok := envSettingsInspector("some-future-tool", home, nil)
		if ok {
			t.Fatalf("envSettingsInspector(some-future-tool) ok = true, want false — must not read claude-code's config for another tool")
		}
		if reason == "" {
			t.Errorf("expected a non-empty reason explaining the fall-through")
		}
	})
}

func TestConfigFileInspector(t *testing.T) {
	t.Run("codex loopback route", func(t *testing.T) {
		home := t.TempDir()
		writeCodexConfig(t, home, "http://127.0.0.1:8820/v1")
		verdict, _, ok := configFileInspector("codex", home, nil)
		if !ok || verdict != VerdictRoutedLoopback {
			t.Fatalf("verdict = %q ok=%v, want %q true", verdict, ok, VerdictRoutedLoopback)
		}
	})

	t.Run("codex org gateway route", func(t *testing.T) {
		home := t.TempDir()
		writeCodexConfig(t, home, "https://gateway.example.org/v1")
		verdict, _, ok := configFileInspector("codex", home, []string{"https://gateway.example.org"})
		if !ok || verdict != VerdictRoutedOrgGateway {
			t.Fatalf("verdict = %q ok=%v, want %q true", verdict, ok, VerdictRoutedOrgGateway)
		}
	})

	t.Run("qwen-code shares RouteConfigFile but has no reader — ok false", func(t *testing.T) {
		home := t.TempDir()
		writeCodexConfig(t, home, "http://127.0.0.1:8820/v1")
		_, reason, ok := configFileInspector("qwen-code", home, nil)
		if ok {
			t.Fatalf("configFileInspector(qwen-code) ok = true, want false — must not read codex's config.toml for qwen-code")
		}
		if reason == "" {
			t.Errorf("expected a non-empty reason explaining the fall-through")
		}
	})
}

func TestStubInspector(t *testing.T) {
	insp := stubInspector(integration.RouteProviderJSON, "test reason")
	verdict, reason, ok := insp("crush", "/nonexistent", nil)
	if ok {
		t.Fatalf("stubInspector ok = true, want false")
	}
	if verdict != VerdictUnrouted {
		t.Errorf("verdict = %q, want %q", verdict, VerdictUnrouted)
	}
	if reason == "" {
		t.Errorf("expected a non-empty reason")
	}
}

func TestAttestOne(t *testing.T) {
	claudeHome := t.TempDir()
	writeClaudeSettings(t, claudeHome, "http://127.0.0.1:8820")

	codexHome := t.TempDir()
	writeCodexConfig(t, codexHome, "http://127.0.0.1:8820/v1")

	traffic := fakeTraffic{counts: map[string][2]int{
		"qwen-code": {4, 2},
		"cline":     {3, 0},
	}}

	cases := []struct {
		name       string
		cap        integration.Capability
		homeDir    string
		wantMethod Method
		wantState  Verdict
	}{
		{
			name:       "claude-code config attested",
			cap:        integration.Capability{Tool: "claude-code", Proxy: &integration.ProxyRoute{Kind: integration.RouteEnvSettings}, Routability: integration.RouteStatusRoutableNow},
			homeDir:    claudeHome,
			wantMethod: MethodConfig,
			wantState:  VerdictRoutedLoopback,
		},
		{
			name:       "codex config attested",
			cap:        integration.Capability{Tool: "codex", Proxy: &integration.ProxyRoute{Kind: integration.RouteConfigFile}, Routability: integration.RouteStatusRoutableNow},
			homeDir:    codexHome,
			wantMethod: MethodConfig,
			wantState:  VerdictRoutedLoopback,
		},
		{
			name:       "qwen-code shares kind with codex but falls to traffic",
			cap:        integration.Capability{Tool: "qwen-code", Proxy: &integration.ProxyRoute{Kind: integration.RouteConfigFile}, Routability: integration.RouteStatusRoutableNow},
			homeDir:    codexHome, // deliberately codex's home — must NOT be read for qwen-code
			wantMethod: MethodTraffic,
			wantState:  VerdictAttestedByTraffic,
		},
		{
			name:       "cline: no Proxy/ProxyProbe kind, routable via manual paste — traffic bypass suspect",
			cap:        integration.Capability{Tool: "cline", Proxy: nil, Routability: integration.RouteStatusRoutableNow},
			homeDir:    "",
			wantMethod: MethodTraffic,
			wantState:  VerdictBypassSuspect,
		},
		{
			name:       "claude-web exempt (browser extension)",
			cap:        integration.Capability{Tool: "claude-web", Hook: integration.HookSpec{Mechanism: integration.HookBrowserExtension}, Routability: integration.RouteStatusNativeExempt},
			homeDir:    "",
			wantMethod: MethodExempt,
			wantState:  VerdictExempt,
		},
		{
			name:       "kiro-cli exempt (native_exempt)",
			cap:        integration.Capability{Tool: "kiro-cli", Routability: integration.RouteStatusNativeExempt},
			homeDir:    "",
			wantMethod: MethodExempt,
			wantState:  VerdictExempt,
		},
		{
			name:       "crush: RouteProviderJSON stub, no traffic evidence — unrouted",
			cap:        integration.Capability{Tool: "crush", ProxyProbe: &integration.ProxyRoute{Kind: integration.RouteProviderJSON}, Routability: integration.RouteStatusRoutableNow},
			homeDir:    "",
			wantMethod: MethodTraffic,
			wantState:  VerdictUnrouted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := attestOne(tc.cap, tc.homeDir, nil, traffic)
			if got.Tool != tc.cap.Tool {
				t.Errorf("Tool = %q, want %q", got.Tool, tc.cap.Tool)
			}
			if got.Method != tc.wantMethod {
				t.Errorf("Method = %q, want %q", got.Method, tc.wantMethod)
			}
			if got.State != tc.wantState {
				t.Errorf("State = %q, want %q", got.State, tc.wantState)
			}
			if got.Reason == "" {
				t.Errorf("Reason is empty")
			}
		})
	}
}

// TestEveryAdapterAttestedOrExempt is the HG1 registry golden: every tool
// in the closed integration.Tools() vocabulary must come back from
// AttestAll with a recognized Method and a recognized, non-empty State.
// Because attestOne dispatches on RouteKind SHAPE (never tool name) and
// always falls through exempt -> config -> traffic, coverage holds by
// construction — this test is the enforcement that a future code change
// (or a P7-added adapter landing with an unrecognized RouteKind AND a
// broken dispatch path) cannot silently regress that guarantee. A failure
// here names the offending tool and its derived RouteKind.
func TestEveryAdapterAttestedOrExempt(t *testing.T) {
	validMethods := map[Method]bool{MethodConfig: true, MethodTraffic: true, MethodExempt: true}
	validStates := map[Verdict]bool{
		VerdictRoutedLoopback:    true,
		VerdictRoutedOrgGateway:  true,
		VerdictDrifted:           true,
		VerdictUnrouted:          true,
		VerdictAttestedByTraffic: true,
		VerdictBypassSuspect:     true,
		VerdictExempt:            true,
	}

	// No traffic evidence supplied — the golden must hold even in the
	// worst case (a fresh node with zero observed activity yet), since
	// "unrouted" is itself a valid, non-gap attestation.
	got := AttestAll(t.TempDir(), nil, nil)

	wantTools := integration.Tools()
	if len(got) != len(wantTools) {
		t.Fatalf("AttestAll returned %d attestations, want %d (one per registered tool)", len(got), len(wantTools))
	}

	seen := make(map[string]bool, len(got))
	for _, a := range got {
		if seen[a.Tool] {
			t.Errorf("tool %q attested more than once", a.Tool)
		}
		seen[a.Tool] = true

		if !validMethods[a.Method] {
			t.Errorf("tool %q kind %q: unrecognized Method %q — coverage gap", a.Tool, a.Kind, a.Method)
		}
		if !validStates[a.State] {
			t.Errorf("tool %q kind %q: unrecognized State %q — coverage gap", a.Tool, a.Kind, a.State)
		}
		if a.Method == "" || a.State == "" {
			t.Errorf("tool %q kind %q: empty Method/State — silently unattested", a.Tool, a.Kind)
		}
		if a.Reason == "" {
			t.Errorf("tool %q kind %q: empty Reason", a.Tool, a.Kind)
		}
		// Exempt <=> the registry actually says so; a tool must never be
		// silently marked exempt by a bug in attestOne's dispatch, nor
		// left un-exempt when the registry says it has no routable surface.
		row, _ := integration.For(a.Tool)
		wantExempt, _ := IsExempt(row)
		gotExempt := a.Method == MethodExempt
		if wantExempt != gotExempt {
			t.Errorf("tool %q: exempt mismatch — IsExempt()=%v but attestation Method=%q", a.Tool, wantExempt, a.Method)
		}
	}

	sort.Strings(wantTools)
	for _, tool := range wantTools {
		if !seen[tool] {
			t.Errorf("registry tool %q missing from AttestAll output — coverage gap", tool)
		}
	}
}

// --- small helpers -----------------------------------------------------

func writeClaudeSettings(t *testing.T, home, baseURL string) {
	t.Helper()
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"env": map[string]string{"ANTHROPIC_BASE_URL": baseURL},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), body, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func writeCodexConfig(t *testing.T, home, baseURL string) {
	t.Helper()
	dir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	toml := "model_provider = \"observer\"\n\n[model_providers.observer]\nbase_url = \"" + baseURL + "\"\n"
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(toml), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}
