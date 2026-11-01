//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// TestDecideSandboxRoute: one case per row of sandboxRouteRules, plus the
// routed fall-through (audit finding P-006 (2)).
func TestDecideSandboxRoute(t *testing.T) {
	routed := sandboxRouteInput{HasRoute: true, ProxyServing: true}
	for _, tc := range []struct {
		name   string
		in     sandboxRouteInput
		routed bool
		rule   string
	}{
		{"routed", routed, true, ""},
		{"no registry route", sandboxRouteInput{ProxyServing: true}, false, "no-route"},
		{"proxy compiled out or off", sandboxRouteInput{HasRoute: true}, false, "proxy-not-serving"},
		{"gated route", sandboxRouteInput{HasRoute: true, ProxyServing: true, Gated: true}, false, "route-gated"},
		{"deliberate third-party route", sandboxRouteInput{HasRoute: true, ProxyServing: true, PersistedElsewhere: true}, false, "persisted-elsewhere"},
		{"effective third-party route", sandboxRouteInput{HasRoute: true, ProxyServing: true, EffectiveThirdParty: true}, false, "effective-third-party"},
		{"effective route unreadable", sandboxRouteInput{HasRoute: true, ProxyServing: true, EffectiveUnknown: true}, false, "effective-unknown"},
	} {
		got, rule := decideSandboxRoute(tc.in)
		if got != tc.routed || rule != tc.rule {
			t.Errorf("%s: routed %v rule %q, want %v %q", tc.name, got, rule, tc.routed, tc.rule)
		}
	}
	if len(sandboxRouteRules) != 6 {
		t.Fatalf("sandboxRouteRules has %d rows; add a case above for each new row", len(sandboxRouteRules))
	}
}

// TestLaunchRoutedFollowsTheRoute: the evidence and the provider block come
// from the route the launch gets. A runtime that does not serve the proxy,
// or a tool pointed at another provider, computes an unrouted run: no
// provider block and never full capture.
func TestLaunchRoutedFollowsTheRoute(t *testing.T) {
	r := &sandboxRuntime{proxyServing: true}
	if ok, _ := r.launchRouted("claude-code", "", nil); !ok {
		t.Fatal("claude-code with the proxy serving computed unrouted")
	}
	r.inspectRoutes = func() []proxyroute.RouteStatus {
		return []proxyroute.RouteStatus{{Tool: "claude-code", State: proxyroute.RouteDrifted}}
	}
	if ok, rule := r.launchRouted("claude-code", "", nil); ok || rule != "persisted-elsewhere" {
		t.Fatalf("a drifted claude-code route: routed %v rule %q", ok, rule)
	}
	off := &sandboxRuntime{}
	if ok, rule := off.launchRouted("claude-code", "", nil); ok || rule != "proxy-not-serving" {
		t.Fatalf("no proxy: routed %v rule %q", ok, rule)
	}
	c := sandboxRunCapture(false, vocab.TierInternet, "")
	if c.ProviderBlock || c.Level == vocab.CaptureFull {
		t.Fatalf("an unrouted internet run computed %+v", c)
	}
}

// The bwrap runtime is a sandbox lifecycle driver (sandbox plan v2 section
// 4.6) and still satisfies the shipped Sandboxer seam.
var (
	_ termsvc.SandboxLifecycle = (*sandboxRuntime)(nil)
	_ termsvc.Sandboxer        = (*sandboxRuntime)(nil)
)

// TestBwrapLifecycleVerdicts: the operations bwrap does not own report a
// typed verdict, never a fake success.
func TestBwrapLifecycleVerdicts(t *testing.T) {
	r := &sandboxRuntime{}
	ctx := context.Background()
	run := termsvc.SandboxRun{ID: "w"}
	for name, op := range map[string]func() (termsvc.LifecycleResult, error){
		"resize":     func() (termsvc.LifecycleResult, error) { return r.Resize(ctx, run, 24, 80) },
		"signal":     func() (termsvc.LifecycleResult, error) { return r.Signal(ctx, run, "TERM") },
		"copy":       func() (termsvc.LifecycleResult, error) { return r.Copy(ctx, termsvc.CopyRequest{Run: run}) },
		"checkpoint": func() (termsvc.LifecycleResult, error) { return r.Checkpoint(ctx, run) },
		"stop":       func() (termsvc.LifecycleResult, error) { return r.Stop(ctx, run, time.Second) },
		"destroy":    func() (termsvc.LifecycleResult, error) { return r.Destroy(ctx, run) },
	} {
		res, err := op()
		if err != nil || res.Verdict == termsvc.VerdictDone || res.Verdict == "" || res.Detail == "" {
			t.Errorf("%s: %+v %v", name, res, err)
		}
	}
}

// TestLaunchRoutedReadsTheProjectScope (P-017 (a)): a third-party route in
// the workspace's own project or local settings, or in the operator's
// --settings, makes the launch unrouted, through the same resolver the inner
// claude launcher uses; an Observer route there keeps it routed.
func TestLaunchRoutedReadsTheProjectScope(t *testing.T) {
	setTestHome(t, t.TempDir())
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	write := func(dir, name, url string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(dir, ".claude"), 0o700); err != nil {
			t.Fatal(err)
		}
		body := `{"env":{"ANTHROPIC_BASE_URL":"` + url + `"}}`
		if err := os.WriteFile(filepath.Join(dir, ".claude", name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r := &sandboxRuntime{proxyServing: true, proxyPort: 8820, effectiveRoute: readEffectiveRoute}
	for _, tc := range []struct {
		name   string
		file   string
		url    string
		args   func(dir string) []string
		routed bool
		rule   string
	}{
		{"nothing set", "", "", nil, true, ""},
		{"project third party", "settings.json", "https://gw.corp.example", nil, false, "effective-third-party"},
		{"local third party", "settings.local.json", "https://gw.corp.example", nil, false, "effective-third-party"},
		{"project observer route", "settings.json", "http://127.0.0.1:8820", nil, true, ""},
		{"cli settings third party", "", "", func(string) []string {
			return []string{"--settings", `{"env":{"ANTHROPIC_BASE_URL":"https://other.example"}}`}
		}, false, "effective-third-party"},
		{"cli settings unreadable", "", "", func(dir string) []string {
			return []string{"--settings", filepath.Join(dir, "missing.json")}
		}, false, "effective-unknown"},
	} {
		dir := t.TempDir()
		if tc.file != "" {
			write(dir, tc.file, tc.url)
		}
		var args []string
		if tc.args != nil {
			args = tc.args(dir)
		}
		got, rule := r.launchRouted("claude-code", dir, args)
		if got != tc.routed || rule != tc.rule {
			t.Errorf("%s: routed %v rule %q, want %v %q", tc.name, got, rule, tc.routed, tc.rule)
		}
	}
	// A tool whose route shape has no reader is unaffected.
	if c := readEffectiveRoute(integration.Capability{Proxy: &integration.ProxyRoute{Kind: integration.RouteLauncher, EnvVar: "OPENAI_BASE_URL"}}, "", t.TempDir(), nil); c != effectiveRouteOurs {
		t.Fatalf("a launcher route read %v", c)
	}
}

// TestRequireLiveProxy (P-017 (b)): the CLI path is routed only while the
// proxy answers now.
func TestRequireLiveProxy(t *testing.T) {
	r := &sandboxRuntime{proxyServing: true, proxyPort: 8820}
	asked := 0
	r.requireLiveProxy(func(port int) bool { asked = port; return true })
	if !r.proxyServing || asked != 8820 {
		t.Fatalf("a live proxy: serving %v asked %d", r.proxyServing, asked)
	}
	r.requireLiveProxy(func(int) bool { return false })
	if r.proxyServing {
		t.Fatal("a dead proxy kept the launch routed")
	}
	if ok, rule := r.launchRouted("claude-code", "", nil); ok || rule != "proxy-not-serving" {
		t.Fatalf("routed %v rule %q", ok, rule)
	}
	// Something else listening on the port is not the proxy: the probe is
	// the proxy's own liveness path.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	other := &sandboxRuntime{proxyServing: true, proxyPort: ln.Addr().(*net.TCPAddr).Port}
	other.requireLiveProxy(func(port int) bool { return proxyServing(context.Background(), port) })
	if other.proxyServing {
		t.Fatal("a non-proxy listener counted as a live proxy")
	}
}

// TestSandboxObserverDirFor (P-017 (c)): the CLI uses the directory of the
// configured DB, as the dashboard does.
func TestSandboxObserverDirFor(t *testing.T) {
	var cfg config.Config
	cfg.Observer.DBPath = "/srv/obs/observer.db"
	if got := sandboxObserverDirFor(cfg); got != filepath.Clean("/srv/obs") {
		t.Fatalf("got %q", got)
	}
}

// TestDestroyRemovesAnUnattachedWorkspace (P-017 (f)): a managed workspace
// Create made and Attach never took is removed by Destroy (the
// ComposePrepare failure path); one an agent ran in is kept; and a recorded
// path outside the managed root is refused, never removed.
func TestDestroyRemovesAnUnattachedWorkspace(t *testing.T) {
	root := t.TempDir()
	r := &sandboxRuntime{managedRoot: root}
	runDir := filepath.Join(root, "id1")
	if err := os.MkdirAll(filepath.Join(runDir, "repo"), 0o700); err != nil {
		t.Fatal(err)
	}
	r.unattached.Store("id1", runDir)
	res, err := r.Destroy(context.Background(), termsvc.SandboxRun{ID: "id1"})
	if err != nil || res.Verdict != termsvc.VerdictDone {
		t.Fatalf("destroy: %+v %v", res, err)
	}
	if _, err := os.Stat(runDir); !os.IsNotExist(err) {
		t.Fatalf("the unattached workspace survived: %v", err)
	}
	kept := filepath.Join(root, "id2")
	if err := os.MkdirAll(kept, 0o700); err != nil {
		t.Fatal(err)
	}
	if res, err := r.Destroy(context.Background(), termsvc.SandboxRun{ID: "id2"}); err != nil || res.Verdict != termsvc.VerdictNothingToRelease {
		t.Fatalf("an attached run: %+v %v", res, err)
	}
	if _, err := os.Stat(kept); err != nil {
		t.Fatalf("an attached run's workspace was removed: %v", err)
	}
	outside := t.TempDir()
	r.unattached.Store("id3", outside)
	if _, err := r.Destroy(context.Background(), termsvc.SandboxRun{ID: "id3"}); err == nil {
		t.Fatal("a workspace outside the managed root was accepted")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("a path outside the managed root was removed: %v", err)
	}
}

// TestSandboxRelayReachable: the CLI path refuses without the daemon's
// relay endpoint (lane sbx-p2); a served endpoint is found.
func TestSandboxRelayReachable(t *testing.T) {
	// t.TempDir, never a literal /tmp, which Windows has not (RERUN2 D6).
	obs := t.TempDir()
	if sandboxRelayReachable(obs) {
		t.Fatal("no daemon, yet the relay counted as reachable")
	}
	ep, err := sandboxRelayEndpoint(obs)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := localipc.DefaultTransport().Listen(ep)
	if err != nil {
		t.Skipf("no local IPC here: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	if !sandboxRelayReachable(obs) {
		t.Fatal("a served endpoint counted as unreachable")
	}
}
