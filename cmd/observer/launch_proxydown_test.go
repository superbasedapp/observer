package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// closedLoopbackURL returns an http URL on a loopback port nothing listens on:
// the port is taken and released, so a dial is refused at once.
func closedLoopbackURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return "http://" + addr
}

// openLoopbackURL returns an http URL on a loopback port that accepts (and
// at once closes) connections, standing in for a running proxy for the
// reachability dial.
func openLoopbackURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return "http://" + ln.Addr().String()
}

// stubOrgOwnsRoute pins launchOrgOwnsRoute for one test.
func stubOrgOwnsRoute(t *testing.T, owns bool) {
	t.Helper()
	prev := launchOrgOwnsRoute
	launchOrgOwnsRoute = func(context.Context, string) bool { return owns }
	t.Cleanup(func() { launchOrgOwnsRoute = prev })
}

// TestEnvLauncherRouteKinds pins the registry RouteKind of every launcher this
// seam serves, so a registry change that moves a tool to another kind shows
// up here (the fallback is decided by kind, never by tool).
func TestEnvLauncherRouteKinds(t *testing.T) {
	for tool, want := range map[string]integration.RouteKind{
		"aider":       integration.RouteLauncher,
		"copilot-cli": integration.RouteLauncher,
		"gemini-cli":  integration.RouteLauncher,
		"goose":       integration.RouteLauncher,
		"grok":        integration.RouteLauncher,
		"prime-agent": integration.RouteLauncher,
		"opencode":    integration.RouteLauncher,
		"cline-cli":   integration.RouteProviderJSON,
		"hermes":      integration.RouteProviderJSON,
		"pi":          integration.RouteProviderJSON,
		"openclaw":    "", // no registry route yet (probe_required)
	} {
		if got := envRouteKind(tool); got != want {
			t.Errorf("envRouteKind(%q) = %q, want %q", tool, got, want)
		}
	}
}

// TestDecideEnvProxyFallbackByRouteKind walks the pure decision per RouteKind:
// a pinned route fails closed, a file pin counts only for a kind whose
// carrier is a file, an org-owned route fails closed, a reachable proxy
// always proceeds and everything else neutralizes.
func TestDecideEnvProxyFallbackByRouteKind(t *testing.T) {
	file := []string{"cfg"}
	env := []string{"BASE_URL"}
	cases := []struct {
		name   string
		facts  envProxyDownFacts
		action proxyFallbackAction
		reason proxyFallbackReason
	}{
		{"launcher: down, nothing pinned", envProxyDownFacts{kind: integration.RouteLauncher}, proxyNeutralize, reasonProxyDownClean},
		{"launcher: down, caller env pins the proxy", envProxyDownFacts{kind: integration.RouteLauncher, presetToProxy: env}, proxyFailClosed, reasonProxyDownConflict},
		{"launcher: a file pin is not this kind's carrier", envProxyDownFacts{kind: integration.RouteLauncher, fileToProxy: file}, proxyNeutralize, reasonProxyDownClean},
		{"provider_json: down, nothing pinned", envProxyDownFacts{kind: integration.RouteProviderJSON}, proxyNeutralize, reasonProxyDownClean},
		{"provider_json: down, the tool's config pins the proxy", envProxyDownFacts{kind: integration.RouteProviderJSON, fileToProxy: file}, proxyFailClosed, reasonProxyDownConflict},
		{"provider_json: down, caller env pins the proxy", envProxyDownFacts{kind: integration.RouteProviderJSON, presetToProxy: env}, proxyFailClosed, reasonProxyDownConflict},
		{"no route: down, nothing pinned", envProxyDownFacts{}, proxyNeutralize, reasonProxyDownClean},
		{"no route: a file pin is not this kind's carrier", envProxyDownFacts{fileToProxy: file}, proxyNeutralize, reasonProxyDownClean},
		{"no route: caller env pins the proxy", envProxyDownFacts{presetToProxy: env}, proxyFailClosed, reasonProxyDownConflict},
		{"launcher: down, organization owns the route", envProxyDownFacts{kind: integration.RouteLauncher, orgRequiresRoute: true}, proxyFailClosed, reasonProxyDownOrgRoute},
		{"provider_json: down, organization owns the route", envProxyDownFacts{kind: integration.RouteProviderJSON, orgRequiresRoute: true}, proxyFailClosed, reasonProxyDownOrgRoute},
		{"pinned beats the org row (names the pin)", envProxyDownFacts{kind: integration.RouteLauncher, presetToProxy: env, orgRequiresRoute: true}, proxyFailClosed, reasonProxyDownConflict},
		{"up: proceeds even when pinned and org-owned", envProxyDownFacts{kind: integration.RouteProviderJSON, proxyReachable: true, presetToProxy: env, fileToProxy: file, orgRequiresRoute: true}, proxyRouteProceed, reasonRouteHealthy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideEnvProxyFallback(tc.facts)
			if got.action != tc.action || got.reason != tc.reason {
				t.Fatalf("decideEnvProxyFallback(%+v) = {%d %d}, want {%d %d}", tc.facts, got.action, got.reason, tc.action, tc.reason)
			}
		})
	}
}

// TestEnvLauncherProxyGateClosedPort runs the gate against a real closed
// loopback port, one case per RouteKind the env launchers use (and opencode's
// own inject set), plus the org-owned and open-port rows.
func TestEnvLauncherProxyGateClosedPort(t *testing.T) {
	t.Setenv(envDaemonChild, "")
	down := closedLoopbackURL(t)
	up := openLoopbackURL(t)
	pinned := func() []string { return []string{"the tool's config"} }
	cases := []struct {
		name       string
		req        envProxyGateRequest
		orgOwns    bool
		want       envProxyGateOutcome
		wantErr    []string
		wantNotice bool
	}{
		{
			name: "launcher kind (gemini-cli): neutralized",
			req: envProxyGateRequest{
				label: "gemini", tool: "gemini-cli", proxyURL: down,
				inject: map[string]string{"GOOGLE_GEMINI_BASE_URL": down},
			},
			want: envProxyGateNeutralize, wantNotice: true,
		},
		{
			name: "launcher kind (aider): caller's own base URL pins the dead port",
			req: envProxyGateRequest{
				label: "aider", proxyURL: down,
				inject:    map[string]string{"OPENAI_API_BASE": down + "/v1"},
				parentEnv: []string{"OPENAI_API_BASE=" + down + "/v1"},
			},
			wantErr: []string{"refusing to launch", "OPENAI_API_BASE in your environment", "unset OPENAI_API_BASE"},
		},
		{
			name: "launcher kind (aider): caller's own base URL elsewhere is a working launch",
			req: envProxyGateRequest{
				label: "aider", proxyURL: down,
				inject:    map[string]string{"OPENAI_API_BASE": down + "/v1"},
				parentEnv: []string{"OPENAI_API_BASE=https://api.example.test/v1"},
			},
			want: envProxyGateNeutralize, wantNotice: true,
		},
		{
			name: "launcher kind (grok lane): caller's lane URL pins the dead port",
			req: envProxyGateRequest{
				label: "grok", proxyURL: down,
				inject:    map[string]string{"GROK_CLI_CHAT_PROXY_BASE_URL": down + "/up/grok/v1"},
				parentEnv: []string{"GROK_CLI_CHAT_PROXY_BASE_URL=" + down + "/up/grok/v1"},
			},
			wantErr: []string{"GROK_CLI_CHAT_PROXY_BASE_URL in your environment"},
		},
		{
			name: "provider_json kind (pi): neutralized",
			req:  envProxyGateRequest{label: "pi", proxyURL: down},
			want: envProxyGateNeutralize, wantNotice: true,
		},
		{
			name:    "provider_json kind (cline-cli): the tool's config pins the dead port",
			req:     envProxyGateRequest{label: "cline-cli", proxyURL: down, fileRoutes: pinned},
			wantErr: []string{"refusing to launch", "the tool's config already routes cline-cli", "point the tool's config away from the proxy"},
		},
		{
			name: "no registry route (openclaw): a file probe is ignored, neutralized",
			req:  envProxyGateRequest{label: "openclaw", proxyURL: down, fileRoutes: pinned},
			want: envProxyGateNeutralize, wantNotice: true,
		},
		{
			name: "opencode: neutralized",
			req: envProxyGateRequest{
				label: "opencode", proxyURL: down,
				inject: map[string]string{"OPENAI_BASE_URL": down + "/v1"},
			},
			want: envProxyGateNeutralize, wantNotice: true,
		},
		{
			name: "opencode: a caller's config content pins the dead port",
			req: envProxyGateRequest{
				label: "opencode", proxyURL: down,
				inject:     map[string]string{"OPENAI_BASE_URL": down + "/v1"},
				callerPins: func() []string { return []string{"OPENCODE_CONFIG_CONTENT"} },
			},
			wantErr: []string{"OPENCODE_CONFIG_CONTENT in your environment"},
		},
		{
			name:    "organization owns the routes: refused",
			req:     envProxyGateRequest{label: "gemini", tool: "gemini-cli", proxyURL: down},
			orgOwns: true,
			wantErr: []string{"your organization routes AI tools through the Observer proxy", "observer start"},
		},
		{
			name:    "open port: proceeds silently, whatever is pinned",
			req:     envProxyGateRequest{label: "pi", proxyURL: up, fileRoutes: pinned},
			orgOwns: true,
			want:    envProxyGateProceed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubOrgOwnsRoute(t, tc.orgOwns)
			var stderr bytes.Buffer
			tc.req.stderr = &stderr
			got, err := envLauncherProxyGate(context.Background(), tc.req)
			if len(tc.wantErr) > 0 {
				var visible launcherMessageError
				if !errors.As(err, &visible) {
					t.Fatalf("err = %v, want a visible refusal", err)
				}
				for _, w := range tc.wantErr {
					if w == "observer start" && proxyNotInBuild() {
						w = "not in this build" // the advice names the build (D-514)
					}
					if !strings.Contains(visible.launcherMessage(), w) {
						t.Errorf("refusal %q missing %q", visible.launcherMessage(), w)
					}
				}
				if stderr.Len() != 0 {
					t.Errorf("a refusal printed a launch notice too: %q", stderr.String())
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if got != tc.want {
				t.Fatalf("outcome = %d, want %d", got, tc.want)
			}
			if tc.wantNotice != (stderr.Len() > 0) {
				t.Fatalf("notice printed = %v, want %v: %q", stderr.Len() > 0, tc.wantNotice, stderr.String())
			}
			if tc.wantNotice && strings.Count(strings.TrimRight(stderr.String(), "\n"), "\n") != 0 {
				t.Errorf("notice spans more than one line: %q", stderr.String())
			}
		})
	}
}

// TestEnvProxyDownNoticeSaysWhatHappens pins the neutralize line: the URL it
// dialled, that the launch goes unrouted, what is still captured and what is
// not, and the advice for this process (one line).
func TestEnvProxyDownNoticeSaysWhatHappens(t *testing.T) {
	for _, daemonChild := range []bool{false, true} {
		got := envProxyDownNotice("hermes", "http://127.0.0.1:18898", daemonChild)
		if strings.Contains(got, "\n") {
			t.Fatalf("notice spans multiple lines: %q", got)
		}
		want := []string{"observer hermes:", "without proxy routing", "transcript is still captured", "token and cost detail"}
		if !proxyNotInBuild() {
			want = append(want, "http://127.0.0.1:18898")
		}
		// The advice clause (proxyDownAdvice): the build when the proxy is
		// not in it, the daemon's [proxy] block for a daemon-spawned
		// terminal, else `observer start`.
		var adviceWant, adviceDeny []string
		switch {
		case proxyNotInBuild():
			adviceWant, adviceDeny = []string{"not in this build"}, []string{"observer start"}
		case daemonChild:
			adviceWant, adviceDeny = []string{"[proxy]"}, []string{"observer start"}
		default:
			adviceWant = []string{"observer start"}
		}
		for _, w := range append(want, adviceWant...) {
			if !strings.Contains(got, w) {
				t.Errorf("daemonChild=%v: notice %q missing %q", daemonChild, got, w)
			}
		}
		for _, d := range adviceDeny {
			if strings.Contains(got, d) {
				t.Errorf("daemonChild=%v: notice %q must not contain %q", daemonChild, got, d)
			}
		}
		for _, d := range []string{"warning", "routing via"} {
			if strings.Contains(got, d) {
				t.Errorf("notice %q must not contain %q", got, d)
			}
		}
	}
}

// TestProxyListenerURL pins the "would this hit the proxy's port" test: path
// is ignored, loopback spellings at the same port match, another host or port
// does not.
func TestProxyListenerURL(t *testing.T) {
	const proxy = "http://127.0.0.1:8820"
	for raw, want := range map[string]bool{
		"http://127.0.0.1:8820/v1":                   true,
		"http://localhost:8820/up/grok/v1":           true,
		"http://[::1]:8820/up/openrouter/api/v1":     true,
		"http://127.0.0.1:8820/t/abc/v1":             true,
		"http://127.0.0.1:8821/v1":                   false,
		"https://api.openai.com/v1":                  false,
		"http://10.0.0.5:8820/v1":                    false,
		"not a url":                                  false,
		"":                                           false,
		"http://127.0.0.1:8820":                      true,
		"http://proxy.internal.example:8820/v1":      false,
		"http://127.0.0.1/v1":                        false,
		"http://127.0.0.1:8820/v1?x=1#frag":          true,
		"http://user:pw@127.0.0.1:8820/v1":           true,
		"http://127.0.0.1:8820/up/route-host.tld/v1": true,
	} {
		if got := proxyListenerURL(raw, proxy); got != want {
			t.Errorf("proxyListenerURL(%q) = %v, want %v", raw, got, want)
		}
	}
	if !proxyListenerURL("https://gw.example/v1", "https://gw.example") {
		t.Error("same non-loopback host must match")
	}
}

// TestToolConfigProbes pins the three per-tool "the tool's own config already
// routes to the proxy" readers the provider_json launchers hand the gate.
func TestToolConfigProbes(t *testing.T) {
	const proxy = "http://127.0.0.1:8820"
	t.Run("cline providers.json", func(t *testing.T) {
		for body, pinned := range map[string]bool{
			`{"lastUsedProvider":"openai-compatible","providers":{"openai-compatible":{"settings":{"baseUrl":"http://127.0.0.1:8820/v1","apiKey":"x"}}}}`: true,
			`{"providers":{"openai-compatible":{"settings":{"baseUrl":"http://127.0.0.1:8820/v1"}}}}`:                                                     true,
			`{"lastUsedProvider":"anthropic","providers":{"openai-compatible":{"settings":{"baseUrl":"http://127.0.0.1:8820/v1"}}}}`:                      false,
			`{"lastUsedProvider":"openai-compatible","providers":{"openai-compatible":{"settings":{"baseUrl":"https://openrouter.ai/api/v1"}}}}`:          false,
			`{"lastUsedProvider":"openai-compatible","providers":{"openai-compatible":{"settings":{}}}}`:                                                  false,
			`{oops`: false,
		} {
			if got := len(clineFileRoutesToProxyIn([]byte(body), proxy)) > 0; got != pinned {
				t.Errorf("%s: pinned = %v, want %v", body, got, pinned)
			}
		}
	})
	t.Run("pi models.json", func(t *testing.T) {
		models := []byte(`{"providers":{"observer":{"baseUrl":"http://127.0.0.1:8820/v1","apiKey":"OPENAI_API_KEY"},"openai":{"baseUrl":"https://api.openai.com/v1"}}}`)
		for def, pinned := range map[string]bool{"observer": true, "openai": false, "missing": false} {
			if got := len(piFileRoutesToProxyIn(models, def, proxy)) > 0; got != pinned {
				t.Errorf("defaultProvider %q: pinned = %v, want %v", def, got, pinned)
			}
		}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{"defaultProvider":"observer"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "models.json"), models, 0o600); err != nil {
			t.Fatal(err)
		}
		if got := piFileRoutesToProxy(dir, proxy); len(got) != 1 || !strings.Contains(got[0], piModelsDisplay) {
			t.Errorf("piFileRoutesToProxy = %v, want the models.json display name", got)
		}
	})
	t.Run("hermes config.yaml", func(t *testing.T) {
		for body, pinned := range map[string]bool{
			"model:\n  provider: observer\n  default: x\nproviders:\n  observer:\n    base_url: http://127.0.0.1:8820/up/openrouter/api/v1\n": true,
			"model:\n  provider: openrouter\nproviders:\n  observer:\n    base_url: http://127.0.0.1:8820/up/openrouter/api/v1\n":             false,
			"model: some-model\nproviders:\n  observer:\n    base_url: http://127.0.0.1:8820/up/openrouter/api/v1\n":                          false,
			"model:\n  provider: observer\nproviders:\n  observer:\n    base_url: https://openrouter.ai/api/v1\n":                             false,
			":\n  - [": false,
		} {
			if got := len(hermesFileRoutesToProxyIn([]byte(body), proxy)) > 0; got != pinned {
				t.Errorf("%q: pinned = %v, want %v", body, got, pinned)
			}
		}
		if got := hermesFileRoutesToProxy("", errors.New("no home"), proxy); got != nil {
			t.Errorf("an unresolved config path must read as no pin, got %v", got)
		}
	})
	t.Run("opencode config content", func(t *testing.T) {
		for content, pinned := range map[string]bool{
			`{"provider":{"openai":{"options":{"baseURL":"http://127.0.0.1:8820/v1"}}}}`:                   true,
			`{"provider":{"opencode":{"options":{"baseURL":"http://127.0.0.1:8820/up/opencode-zen/v1"}}}}`: true,
			`{"provider":{"openai":{"options":{"baseURL":"https://api.openai.com/v1"}}}}`:                  false,
			`not json`: false,
		} {
			if got := len(opencodeContentPins([]string{"OPENCODE_CONFIG_CONTENT=" + content}, proxy)) > 0; got != pinned {
				t.Errorf("%s: pinned = %v, want %v", content, got, pinned)
			}
		}
		if opencodeContentPins(nil, proxy) != nil {
			t.Error("absent content must read as no pin")
		}
	})
}

// envLaunchRecording is what a recorded stub child saw.
type envLaunchRecording struct {
	started bool
	argv    []string
	envPath string
	stderr  string
	err     error
}

// runRecordedEnvLaunch runs runEnvLauncher against a recording stub on a
// throwaway config, with the given proxy URL.
func runRecordedEnvLaunch(t *testing.T, spec envLauncherSpec) envLaunchRecording {
	t.Helper()
	prevRuntime, prevLogin := agentRuntimeDir, daemonLoginPathDirs
	agentRuntimeDir = func() string { return "" }
	daemonLoginPathDirs = func() []string { return nil }
	t.Cleanup(func() { agentRuntimeDir, daemonLoginPathDirs = prevRuntime, prevLogin })
	dir := t.TempDir()
	argvPath, envPath := filepath.Join(dir, "argv.out"), filepath.Join(dir, "env.out")
	spec.bin = writeArgvEnvRecorderStub(t, dir, argvPath, envPath)
	spec.configPath = writeCopilotCLITestConfig(t, dir)
	var stderr bytes.Buffer
	spec.stderr = &stderr
	err := runEnvLauncher(spec)
	rec := envLaunchRecording{envPath: envPath, stderr: stderr.String(), err: err}
	if _, statErr := os.Stat(argvPath); statErr == nil {
		rec.started = true
		rec.argv = readRecordedArgv(t, argvPath)
	}
	return rec
}

// assertNoProxiedMarker fails when the child env carries the T-536 OTel
// "proxied" marker (a no-op in a build without the vendor OTLP ingest).
func assertNoProxiedMarker(t *testing.T, envPath, tool string) {
	t.Helper()
	marker := envValue(withOTelRouteMarker(nil, tool), otelResourceAttributesEnvName)
	if marker == "" {
		return
	}
	if got, _ := readRecordedEnvValue(t, envPath, otelResourceAttributesEnvName); strings.Contains(got, marker) {
		t.Errorf("neutralized launch carries the proxied marker: %q", got)
	}
}

// otelResourceAttributesEnvName is spelled here so the test builds whether or
// not the vendor OTLP ingest (which owns the constant) is compiled in.
const otelResourceAttributesEnvName = "OTEL_RESOURCE_ATTRIBUTES"

// TestRunEnvLauncherProxyDown walks the whole launch against a closed
// loopback port, one case per RouteKind the env launchers use: the env route
// is dropped, the provider selection is dropped (routeArgs), no proxied
// marker, a working launch; a caller value pinning the dead port is refused
// before anything starts.
func TestRunEnvLauncherProxyDown(t *testing.T) {
	t.Setenv(envDaemonChild, "")
	stubOrgOwnsRoute(t, false)
	down := closedLoopbackURL(t)

	t.Run("launcher kind: env route dropped", func(t *testing.T) {
		t.Setenv("OPENAI_API_BASE", "")
		os.Unsetenv("OPENAI_API_BASE") //nolint:errcheck // t.Setenv restores it
		rec := runRecordedEnvLaunch(t, envLauncherSpec{
			tool: "aider", args: []string{"--yes"}, proxyURL: down,
			env: map[string]string{"OPENAI_API_BASE": down + "/v1"},
		})
		if rec.err != nil || !rec.started {
			t.Fatalf("launch failed: %v\n%s", rec.err, rec.stderr)
		}
		if !equalArgs(rec.argv, []string{"--yes"}) {
			t.Errorf("argv = %v", rec.argv)
		}
		if v, ok := readRecordedEnvValue(t, rec.envPath, "OPENAI_API_BASE"); ok {
			t.Errorf("child still points at the dead port: OPENAI_API_BASE=%s", v)
		}
		assertNoProxiedMarker(t, rec.envPath, "aider")
		if !strings.Contains(rec.stderr, "without proxy routing") || strings.Contains(rec.stderr, "routing via") {
			t.Errorf("stderr must carry only the proxy-down notice:\n%s", rec.stderr)
		}
	})

	t.Run("launcher kind: caller's own base URL at the dead port is refused", func(t *testing.T) {
		t.Setenv("OPENAI_API_BASE", down+"/v1")
		rec := runRecordedEnvLaunch(t, envLauncherSpec{
			tool: "aider", proxyURL: down,
			env: map[string]string{"OPENAI_API_BASE": down + "/v1"},
		})
		if rec.started || rec.err == nil {
			t.Fatalf("started=%v err=%v; want a refusal before the child starts", rec.started, rec.err)
		}
	})

	t.Run("provider_json kind: provider selection dropped", func(t *testing.T) {
		rec := runRecordedEnvLaunch(t, envLauncherSpec{
			tool: "cline-cli", proxyURL: down,
			args:      []string{"-P", clineCompatProvider, "--verbose"},
			routeArgs: []string{"--verbose"},
			routeFile: func() (string, bool) { return down + "/v1", true },
		})
		if rec.err != nil || !rec.started {
			t.Fatalf("launch failed: %v\n%s", rec.err, rec.stderr)
		}
		if !equalArgs(rec.argv, []string{"--verbose"}) {
			t.Errorf("argv = %v, want the operator's own args without -P", rec.argv)
		}
		assertNoProxiedMarker(t, rec.envPath, "cline-cli")
	})

	t.Run("provider_json kind: the tool's own config pins the dead port", func(t *testing.T) {
		rec := runRecordedEnvLaunch(t, envLauncherSpec{
			tool: "pi", proxyURL: down,
			args:       []string{"--provider", "observer", "--model", "gpt-4o"},
			routeArgs:  []string{},
			fileRoutes: func() []string { return []string{`pi's default provider "observer" (` + piModelsDisplay + `)`} },
		})
		if rec.started || rec.err == nil {
			t.Fatalf("started=%v err=%v; want a refusal", rec.started, rec.err)
		}
	})

	t.Run("organization owns the routes: refused", func(t *testing.T) {
		stubOrgOwnsRoute(t, true)
		rec := runRecordedEnvLaunch(t, envLauncherSpec{
			tool: "grok", proxyURL: down,
			env: map[string]string{"GROK_CLI_CHAT_PROXY_BASE_URL": down + "/up/grok/v1"},
		})
		if rec.started || rec.err == nil {
			t.Fatalf("started=%v err=%v; want a refusal on an org-owned managed node", rec.started, rec.err)
		}
	})

	t.Run("caller already unrouted: the gate is not consulted", func(t *testing.T) {
		stubOrgOwnsRoute(t, true)
		rec := runRecordedEnvLaunch(t, envLauncherSpec{
			tool: "gemini", seedTool: "gemini-cli", proxyURL: down, unrouted: true,
		})
		if rec.err != nil || !rec.started {
			t.Fatalf("an unrouted launch must not be judged by the gate: %v\n%s", rec.err, rec.stderr)
		}
	})
}

// TestOpencodeLauncherProxyDown is the same walk for `observer opencode`.
func TestOpencodeLauncherProxyDown(t *testing.T) {
	t.Setenv(envDaemonChild, "")
	stubOrgOwnsRoute(t, false)
	prevRuntime, prevLogin := agentRuntimeDir, daemonLoginPathDirs
	agentRuntimeDir = func() string { return "" }
	daemonLoginPathDirs = func() []string { return nil }
	t.Cleanup(func() { agentRuntimeDir, daemonLoginPathDirs = prevRuntime, prevLogin })
	down := closedLoopbackURL(t)

	run := func(t *testing.T) envLaunchRecording {
		t.Helper()
		dir := t.TempDir()
		argvPath, envPath := filepath.Join(dir, "argv.out"), filepath.Join(dir, "env.out")
		stub := writeArgvEnvRecorderStub(t, dir, argvPath, envPath)
		var stderr bytes.Buffer
		err := runOpencodeLauncher(opencodeLauncherOptions{
			configPath: writeCopilotCLITestConfig(t, dir), proxyURL: down,
			opencodePath: stub, opencodeArgs: []string{"--print-logs"}, stderr: &stderr,
		})
		rec := envLaunchRecording{envPath: envPath, stderr: stderr.String(), err: err}
		if _, statErr := os.Stat(argvPath); statErr == nil {
			rec.started, rec.argv = true, readRecordedArgv(t, argvPath)
		}
		return rec
	}
	unset := func(t *testing.T, keys ...string) {
		for _, k := range keys {
			t.Setenv(k, "")
			os.Unsetenv(k) //nolint:errcheck // t.Setenv restores it
		}
	}

	t.Run("neutralized: no route variables, no marker", func(t *testing.T) {
		unset(t, "OPENAI_BASE_URL", "OPENCODE_CONFIG_CONTENT")
		rec := run(t)
		if rec.err != nil || !rec.started {
			t.Fatalf("launch failed: %v\n%s", rec.err, rec.stderr)
		}
		for _, k := range []string{"OPENAI_BASE_URL", "OPENCODE_CONFIG_CONTENT"} {
			if v, ok := readRecordedEnvValue(t, rec.envPath, k); ok {
				t.Errorf("child still carries %s=%s", k, v)
			}
		}
		assertNoProxiedMarker(t, rec.envPath, "opencode")
		if !strings.Contains(rec.stderr, "without proxy routing") || strings.Contains(rec.stderr, "routing via") {
			t.Errorf("stderr must carry only the proxy-down notice:\n%s", rec.stderr)
		}
	})

	t.Run("caller OPENAI_BASE_URL at the dead port is refused", func(t *testing.T) {
		unset(t, "OPENCODE_CONFIG_CONTENT")
		t.Setenv("OPENAI_BASE_URL", down+"/v1")
		if rec := run(t); rec.started || rec.err == nil {
			t.Fatalf("started=%v err=%v; want a refusal", rec.started, rec.err)
		}
	})

	t.Run("caller config content at the dead port is refused", func(t *testing.T) {
		unset(t, "OPENAI_BASE_URL")
		t.Setenv("OPENCODE_CONFIG_CONTENT", `{"provider":{"openai":{"options":{"baseURL":"`+down+`/v1"}}}}`)
		if rec := run(t); rec.started || rec.err == nil {
			t.Fatalf("started=%v err=%v; want a refusal", rec.started, rec.err)
		}
	})
}

// appendTestConfig appends a TOML fragment to a test config file.
func appendTestConfig(t *testing.T, path, fragment string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close() //nolint:errcheck // test fixture
	if _, err := f.WriteString(fragment); err != nil {
		t.Fatalf("append %s: %v", path, err)
	}
}
