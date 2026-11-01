package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/supervisor"
)

// route_maintenance_test.go: the cmd boundary of lane P1.

// routeHome isolates HOME and every tool config override for one test.
func routeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("CRUSH_GLOBAL_CONFIG", "")
	t.Setenv("KIMI_CODE_HOME", "")
	t.Setenv("QWEN_HOME", "")
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte("{\"permissions\":{\"allow\":[\"Bash(ls:*)\"]}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

// healthyProxy serves the proxy's liveness path on a loopback port.
func healthyProxy(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == proxyHealthzPath {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// deadPort returns a loopback address nothing listens on.
func deadPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// routeMaintenanceTools are the AI tools these tests give a config to.
var routeMaintenanceTools = []string{"claude-code", "codex", "qwen-code", "kimi-code"}

// routeWriterCompiled reports whether this build offers the route writer
// (integration.proxy-route). The minimal distro leaves it out.
func routeWriterCompiled() bool {
	for _, id := range components.Compiled(components.BinaryNode) {
		if id == "integration.proxy-route" {
			return true
		}
	}
	return false
}

// routeMaintenanceConfig writes the daemon config a route maintenance test
// runs with and returns its path. Maintenance routes only a tool whose
// adapter is active (comps.AdapterActive). A plain build has every adapter
// active with no [components] block, but a stamped distro build (managed,
// minimal) leaves every adapter off until it is selected locally or by
// policy, so the config selects the adapters the tests drive, as a managed
// node's selection would. A build without the route writer skips; there
// TestRouteMaintenanceInertWithoutRouteWriter pins that nothing is written.
func routeMaintenanceConfig(t *testing.T, home string) string {
	t.Helper()
	ids := []string{"integration.proxy-route"}
	add := make([]string, 0, len(routeMaintenanceTools))
	for _, tool := range routeMaintenanceTools {
		id := components.AdapterID(tool)
		ids = append(ids, id)
		add = append(add, strconv.Quote(id))
	}
	requireCompiled(t, ids...)
	return writeRouteComponentsConfig(t, home, add)
}

// writeRouteComponentsConfig writes a config whose [components] block adds
// the quoted ids in add.
func writeRouteComponentsConfig(t *testing.T, home string, add []string) string {
	t.Helper()
	cfg := filepath.Join(home, "observer-config.toml")
	body := "[components]\nadd = [" + strings.Join(add, ", ") + "]\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestRouteMaintenanceInertWithoutRouteWriter: in a build without the route
// writer (the minimal distro) a managed maintain pass writes no route, even
// with the tool's adapter selected and the proxy serving.
func TestRouteMaintenanceInertWithoutRouteWriter(t *testing.T) {
	if routeWriterCompiled() {
		t.Skip("this build offers integration.proxy-route; the other route maintenance tests cover it")
	}
	home := routeHome(t)
	requireCompiled(t, components.AdapterID("claude-code"))
	cfg := writeRouteComponentsConfig(t, home, []string{strconv.Quote(components.AdapterID("claude-code"))})
	var out, errOut bytes.Buffer
	step := newRouteMaintenance(cfg, healthyProxy(t), fixedPosture(govern.RoutePostureMaintain), nil, &out, &errOut)
	if step(context.Background(), true) || claudeRouted(t, home) {
		t.Fatalf("a build without the route writer wrote a route (stdout %q stderr %q)", out.String(), errOut.String())
	}
}

func claudeRouted(t *testing.T, home string) bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Contains(string(b), "ANTHROPIC_BASE_URL")
}

// TestRouteMaintenanceStepDecisions pins the boundary rows: a managed node
// whose org needs the proxy writes when the proxy serves; an individual node,
// an org without a proxy enforcement point, and a proxy that is not listening
// write nothing.
func TestRouteMaintenanceStepDecisions(t *testing.T) {
	cases := []struct {
		name      string
		managed   bool
		posture   govern.RoutePosture
		live      bool
		wantWrite bool
	}{
		{"managed, posture maintain, proxy serving: write", true, govern.RoutePostureMaintain, true, true},
		{"individual node: never writes", false, govern.RoutePostureNone, true, false},
		{"individual node even if the posture said so: never writes", false, govern.RoutePostureMaintain, true, false},
		{"managed, posture none: no write", true, govern.RoutePostureNone, true, false},
		{"managed, posture release: no write", true, govern.RoutePostureRelease, true, false},
		{"managed, proxy not listening: no write", true, govern.RoutePostureMaintain, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := routeHome(t)
			addr := deadPort(t)
			if tc.live {
				addr = healthyProxy(t)
			}
			var out, errOut bytes.Buffer
			step := newRouteMaintenance(routeMaintenanceConfig(t, home), addr,
				fixedPosture(tc.posture), nil, &out, &errOut)
			wrote := step(context.Background(), tc.managed)
			if wrote != tc.wantWrite || claudeRouted(t, home) != tc.wantWrite {
				t.Fatalf("wrote=%v routed=%v, want %v (stdout %q stderr %q)", wrote, claudeRouted(t, home), tc.wantWrite, out.String(), errOut.String())
			}
			if tc.wantWrite {
				if !strings.Contains(out.String(), "route maintenance claude-code") {
					t.Fatalf("no route maintenance line on stdout: %q", out.String())
				}
				// Idempotent: a second pass writes nothing.
				if step(context.Background(), tc.managed) {
					t.Fatal("second pass wrote again")
				}
			}
		})
	}
}

// TestHookMaintenanceRunsRoutesThenReports: the heartbeat runs route
// maintenance after the hook pass and before the report, on every node the
// step exists for (the step itself refuses an individual node), and the
// start pass reports at once only when it wrote.
func TestHookMaintenanceRunsRoutesThenReports(t *testing.T) {
	var order []string
	m := hookMaintenance{
		mode: "managed", autoRegister: true,
		managed:    func(context.Context) bool { return true },
		reregister: func(bool) { order = append(order, "hooks") },
		routes:     func(_ context.Context, managed bool) bool { order = append(order, "routes"); return managed },
		report:     func(context.Context) { order = append(order, "report") },
	}
	m.tick(context.Background())
	if got := strings.Join(order, ","); got != "hooks,routes,report" {
		t.Fatalf("tick order = %s, want hooks,routes,report", got)
	}

	order = nil
	waited := false
	m.waitProxy = func(context.Context) { waited = true }
	m.startRoutes(context.Background())
	if !waited || strings.Join(order, ",") != "routes,report" {
		t.Fatalf("start pass: waited=%v order=%v, want a wait then routes,report", waited, order)
	}

	order = nil
	m.routes = func(context.Context, bool) bool { order = append(order, "routes"); return false }
	m.startRoutes(context.Background())
	if strings.Join(order, ",") != "routes" {
		t.Fatalf("a start pass that wrote nothing reported anyway: %v", order)
	}

	order = nil
	m.routes = nil
	m.startRoutes(context.Background())
	if len(order) != 0 {
		t.Fatalf("no route step (individual node): %v", order)
	}
}

// TestAddRouteActs: a repair is the route_repaired capture risk located on
// the tool and a home-relative file label with the repair time; a first write
// is the informational routes_written label. Both survive the wire.
func TestAddRouteActs(t *testing.T) {
	home := t.TempDir()
	at := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	rep := orgcontract.ManagedIntegrityReport{CaptureCheckVersion: orgcontract.ManagedCaptureCheckVersion}
	addRouteActs(&rep, home, []proxyroute.RouteAct{
		{Tool: "claude-code", ConfigPath: filepath.Join(home, ".claude", "settings.json"), Kind: proxyroute.RouteActRepaired, At: at},
		{Tool: "codex", ConfigPath: filepath.Join(home, ".codex", "config.toml"), Kind: proxyroute.RouteActWritten, At: at},
	})
	norm := rep.NormalizeLabels()
	if len(norm.CaptureRisks) != 1 || norm.CaptureRisks[0] != orgcontract.CaptureRiskRouteRepaired {
		t.Fatalf("CaptureRisks = %v, want [route_repaired]", norm.CaptureRisks)
	}
	if len(norm.CaptureRiskItems) != 1 {
		t.Fatalf("items = %+v", norm.CaptureRiskItems)
	}
	it := norm.CaptureRiskItems[0]
	if it.Tool != "claude-code" || it.File != "~/.claude/settings.json" || it.At != "2026-10-18T12:00:00Z" {
		t.Fatalf("route_repaired item = %+v", it)
	}
	if len(norm.RoutesWritten) != 1 || norm.RoutesWritten[0] != "codex" {
		t.Fatalf("RoutesWritten = %v, want [codex]", norm.RoutesWritten)
	}
}

// fixedPosture is a posture func that always answers p.
func fixedPosture(p govern.RoutePosture) func(context.Context) govern.RoutePostureVerdict {
	return func(context.Context) govern.RoutePostureVerdict { return govern.RoutePostureVerdict{Posture: p} }
}

// TestRouteMaintenanceAdminOffReleases: the admin turning maintenance OFF
// removes exactly the route the managed daemon wrote, and a route the
// developer set (here Codex's, set by `observer init`) is kept.
func TestRouteMaintenanceAdminOffReleases(t *testing.T) {
	home := routeHome(t)
	addr := healthyProxy(t)
	port, _ := proxyPortFromAddr(addr)
	codexDir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	initReg, err := proxyroute.NewRegistrar(proxyroute.RegisterOptions{ProxyPort: port, HomeDir: home, Writer: "init"})
	if err != nil {
		t.Fatal(err)
	}
	if res := initReg.RegisterCodex(); res.Error != nil || !res.Added {
		t.Fatalf("init codex route: %+v", res)
	}
	codexBefore, _ := os.ReadFile(filepath.Join(codexDir, "config.toml"))

	var out, errOut bytes.Buffer
	cfg := routeMaintenanceConfig(t, home)
	if !newRouteMaintenance(cfg, addr, fixedPosture(govern.RoutePostureMaintain), nil, &out, &errOut)(context.Background(), true) {
		t.Fatalf("maintain pass wrote nothing: %q %q", out.String(), errOut.String())
	}
	if !claudeRouted(t, home) {
		t.Fatal("claude-code not routed by the maintain pass")
	}
	if !newRouteMaintenance(cfg, addr, fixedPosture(govern.RoutePostureRelease), nil, &out, &errOut)(context.Background(), true) {
		t.Fatalf("release pass removed nothing: %q %q", out.String(), errOut.String())
	}
	if claudeRouted(t, home) {
		t.Fatal("the managed claude-code route survived admin OFF")
	}
	if !strings.Contains(out.String(), "turned route maintenance off") {
		t.Fatalf("no release line: %q", out.String())
	}
	codexAfter, _ := os.ReadFile(filepath.Join(codexDir, "config.toml"))
	if !bytes.Equal(codexBefore, codexAfter) {
		t.Fatal("admin OFF touched a route the developer set with observer init")
	}
	// Idempotent: nothing left to release.
	if newRouteMaintenance(cfg, addr, fixedPosture(govern.RoutePostureRelease), nil, &out, &errOut)(context.Background(), true) {
		t.Fatal("second release pass removed something")
	}
}

// fakeLaneProxy records the route lanes the daemon installs.
type fakeLaneProxy struct{ lanes map[string]string }

func (f *fakeLaneProxy) SetRouteLanes(l map[string]string) error {
	f.lanes = map[string]string{}
	for k, v := range l {
		f.lanes[k] = v
	}
	return nil
}

func (f *fakeLaneProxy) ResolvableLanes() map[string]bool {
	out := map[string]bool{}
	for k := range f.lanes {
		out[k] = true
	}
	return out
}

// TestRouteMaintenanceLaneRoute: a Qwen Code on a third-party provider host
// is routed through a route lane the proxy resolves BEFORE the file changes;
// the lane is re-installed from provenance at the next start; admin OFF puts
// the original host back and drops the lane.
func TestRouteMaintenanceLaneRoute(t *testing.T) {
	home := routeHome(t)
	addr := healthyProxy(t)
	port, _ := proxyPortFromAddr(addr)
	qwenDir := filepath.Join(home, ".qwen")
	if err := os.MkdirAll(qwenDir, 0o755); err != nil {
		t.Fatal(err)
	}
	orig := "{\n  \"model\": {\"name\": \"qwen/qwen3-coder\", \"baseUrl\": \"https://openrouter.ai/api/v1\"},\n  \"modelProviders\": {\"openai\": [{\"id\": \"qwen/qwen3-coder\", \"baseUrl\": \"https://openrouter.ai/api/v1\", \"envKey\": \"OPENROUTER_API_KEY\"}]}\n}\n"
	settings := filepath.Join(qwenDir, "settings.json")
	if err := os.WriteFile(settings, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	fp := &fakeLaneProxy{}
	lanes := installRouteLanesAtStart(fp, port, &bytes.Buffer{})
	var out, errOut bytes.Buffer
	cfg := routeMaintenanceConfig(t, home)
	newRouteMaintenance(cfg, addr, fixedPosture(govern.RoutePostureMaintain), lanes, &out, &errOut)(context.Background(), true)
	got, _ := os.ReadFile(settings)
	wantURL := "http://127.0.0.1:" + strconv.Itoa(port) + "/up/route-openrouter-ai/api/v1"
	if !strings.Contains(string(got), wantURL) || strings.Contains(string(got), "https://openrouter.ai") {
		t.Fatalf("qwen not lane-routed: %s (stderr %q)", got, errOut.String())
	}
	if !strings.Contains(string(got), "OPENROUTER_API_KEY") {
		t.Fatal("the envKey was touched")
	}
	if fp.lanes["route-openrouter-ai"] != "https://openrouter.ai" {
		t.Fatalf("lane not installed: %v", fp.lanes)
	}

	// A fresh start re-installs the recorded lane before serving.
	fp2 := &fakeLaneProxy{}
	_ = installRouteLanesAtStart(fp2, port, &bytes.Buffer{})
	if fp2.lanes["route-openrouter-ai"] != "https://openrouter.ai" {
		t.Fatalf("restart did not re-install the lane: %v", fp2.lanes)
	}

	newRouteMaintenance(cfg, addr, fixedPosture(govern.RoutePostureRelease), lanes, &out, &errOut)(context.Background(), true)
	back, _ := os.ReadFile(settings)
	var wantDoc, gotDoc any
	_ = json.Unmarshal([]byte(orig), &wantDoc)
	_ = json.Unmarshal(back, &gotDoc)
	if !reflect.DeepEqual(wantDoc, gotDoc) {
		t.Fatalf("admin OFF did not restore the original host:\n%s\nwant\n%s", back, orig)
	}
	if len(fp.lanes) != 0 {
		t.Fatalf("lane kept after release: %v", fp.lanes)
	}
}

// TestIntegrityReportsMissingSupervisor: the supervisor warning is set only
// when routes are maintained (the strict posture) and no supervisor was
// found; it never appears on a node whose routes are not maintained.
func TestIntegrityReportsMissingSupervisor(t *testing.T) {
	home := routeHome(t)
	orig := detectSupervisor
	t.Cleanup(func() { detectSupervisor = orig })
	db := filepath.Join(home, ".observer", "observer.db")
	for _, tc := range []struct {
		name       string
		maintained bool
		found      bool
		want       bool
	}{
		{"maintained, none found", true, false, true},
		{"maintained, supervisor found", true, true, false},
		{"not maintained, none found", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			detectSupervisor = func() supervisor.Result { return supervisor.Result{Detected: tc.found} }
			policy := noPostureRoutes
			if tc.maintained {
				policy = maintainedRoutes
			}
			rep := collectIntegritySignalsWith(db, home, "/current/observer", nil, policy, hookIntegrityInputs{})
			if rep.SupervisorMissing != tc.want {
				t.Fatalf("SupervisorMissing = %v, want %v", rep.SupervisorMissing, tc.want)
			}
		})
	}
}

// TestAdminOffReportsNoDriftForRestoredProviders reproduces RETEST5 F4
// (T-900): with maintenance ON the daemon carries qwen-code and kimi-code on
// their own providers through route lanes; the admin turns it OFF and the
// daemon puts each original provider host back. Those restored hosts are the
// setup the admin chose, so the report the same posture drives names no
// drift (before the fix it reported both as "not pointing at the managed
// proxy"). Back ON, the same hosts are drift until the daemon routes them.
func TestAdminOffReportsNoDriftForRestoredProviders(t *testing.T) {
	home := routeHome(t)
	addr := healthyProxy(t)
	port, _ := proxyPortFromAddr(addr)
	write := func(dir, name, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(home, dir), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(".qwen", "settings.json", "{\n  \"model\": {\"name\": \"qwen/qwen3-coder\", \"baseUrl\": \"https://openrouter.ai/api/v1\"},\n  \"modelProviders\": {\"openai\": [{\"id\": \"qwen/qwen3-coder\", \"baseUrl\": \"https://openrouter.ai/api/v1\", \"envKey\": \"OPENROUTER_API_KEY\"}]}\n}\n")
	write(".kimi-code", "config.toml", "default_model = \"flash\"\n\n[models.flash]\nprovider = \"baseten\"\nmodel = \"flash-1\"\n\n[providers.baseten]\ntype = \"openai\"\nbase_url = \"https://inference.baseten.co/v1\"\napi_key = \"sk-test-not-real\"\n")
	db := filepath.Join(home, ".observer", "observer.db")
	report := func(p govern.RoutePosture) []string {
		t.Helper()
		v := govern.RoutePostureVerdict{Posture: p}
		return collectIntegritySignalsWith(db, home, "/current/observer", nil, routeDriftPolicy(v, port, proxyroute.Selection{}), hookIntegrityInputs{}).DriftedTools
	}
	providers := []string{"kimi-code", "qwen-code"}
	if got := report(govern.RoutePostureMaintain); !containsAll(got, providers) {
		t.Fatalf("maintain, before routing: drift = %v, want %v", got, providers)
	}

	fp := &fakeLaneProxy{}
	lanes := installRouteLanesAtStart(fp, port, &bytes.Buffer{})
	var out, errOut bytes.Buffer
	cfg := routeMaintenanceConfig(t, home)
	newRouteMaintenance(cfg, addr, fixedPosture(govern.RoutePostureMaintain), lanes, &out, &errOut)(context.Background(), true)
	if got := report(govern.RoutePostureMaintain); containsAny(got, providers) {
		t.Fatalf("maintain, lane-routed: drift = %v (stderr %q)", got, errOut.String())
	}

	newRouteMaintenance(cfg, addr, fixedPosture(govern.RoutePostureRelease), lanes, &out, &errOut)(context.Background(), true)
	qwen, _ := os.ReadFile(filepath.Join(home, ".qwen", "settings.json"))
	kimi, _ := os.ReadFile(filepath.Join(home, ".kimi-code", "config.toml"))
	if !strings.Contains(string(qwen), "https://openrouter.ai/api/v1") || !strings.Contains(string(kimi), "https://inference.baseten.co/v1") {
		t.Fatalf("release did not restore the provider hosts:\n%s\n%s", qwen, kimi)
	}
	if got := report(govern.RoutePostureRelease); len(got) != 0 {
		t.Fatalf("admin OFF: drift = %v, want none (the restored provider hosts are the admin's choice)", got)
	}
	// The pin removed with no proxy enforcement point (D-738): the
	// organization's routes are gone and the hosts are the developer's own.
	if got := report(govern.RoutePostureNone); len(got) != 0 {
		t.Fatalf("no posture: drift = %v, want none", got)
	}
	if got := report(govern.RoutePostureMaintain); !containsAll(got, providers) {
		t.Fatalf("admin ON again: drift = %v, want %v until the daemon routes them", got, providers)
	}
}

func containsAll(have, want []string) bool {
	for _, w := range want {
		if !containsAny(have, []string{w}) {
			return false
		}
	}
	return true
}

// unselectedRouteConfig writes a config that selects the claude-code adapter
// and the route writer and leaves the codex adapter unselected (removed from
// a full build's everything-compiled base; never added in a distro build).
func unselectedRouteConfig(t *testing.T, home string) string {
	t.Helper()
	claude, codex := components.AdapterID("claude-code"), components.AdapterID("codex")
	requireCompiled(t, "integration.proxy-route", claude, codex)
	cfg := filepath.Join(home, "observer-config.toml")
	body := "[components]\nadd = [" + strconv.Quote("integration.proxy-route") + ", " + strconv.Quote(claude) + "]\nremove = [" + strconv.Quote(codex) + "]\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// routingOffConfig writes a config whose route writer component is not
// active: removed from the base where this build carries it, absent anyway
// from a build that does not (the minimal distro), so the D-771 tests run in
// every build.
func routingOffConfig(t *testing.T, home string) string {
	t.Helper()
	cfg := filepath.Join(home, "observer-config.toml")
	body := "[components]\nremove = [" + strconv.Quote(routeWriterComponent) + "]\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestRouteSelectionPredicate pins the one component selection (T-915,
// D-770, D-771) on resolved snapshots: a selected adapter, an unselected one,
// a cross-OS target, and the route writer component on or off.
func TestRouteSelectionPredicate(t *testing.T) {
	home := routeHome(t)
	sel := routeSelection(componentSnapshotFor(unselectedRouteConfig(t, home)))
	if sel.RoutingOff {
		t.Fatal("the route writer is selected, yet the selection says routing is off")
	}
	for _, tc := range []struct {
		tool string
		want bool
	}{
		{"claude-code", true},
		{"codex", false},
		// A cross-OS registration target resolves to its base tool.
		{"claude-code-windows", true},
	} {
		if got := sel.Tool(tc.tool); got != tc.want {
			t.Errorf("routeSelection(...).Tool(%q) = %v, want %v", tc.tool, got, tc.want)
		}
	}
	if off := routeSelection(componentSnapshotFor(routingOffConfig(t, routeHome(t)))); !off.RoutingOff {
		t.Fatal("the route writer component is removed (or not in this build), yet the selection says routing is on")
	}
}

// TestRoutingSwitchedOffIsNotDrift is D-771 ("Routing switched off"): with
// the route writer component (integration.proxy-route) not active, switched
// off by policy or not in this build at all (the minimal distro, where this
// test runs too), route maintenance writes nothing, so no tool's route is
// drift under any posture. The report says routing is switched off and names
// the installed tools; the supervisor warning does not apply (no route is
// kept); under release nothing changes.
func TestRoutingSwitchedOffIsNotDrift(t *testing.T) {
	home := routeHome(t)
	addr := healthyProxy(t)
	port, _ := proxyPortFromAddr(addr)
	orig := detectSupervisor
	t.Cleanup(func() { detectSupervisor = orig })
	detectSupervisor = func() supervisor.Result { return supervisor.Result{} }
	codexDir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := routingOffConfig(t, home)
	sel := routeSelection(componentSnapshotFor(cfg))
	if !sel.RoutingOff {
		t.Fatal("precondition: the route writer component must not be active")
	}
	db := filepath.Join(home, ".observer", "observer.db")
	report := func(p govern.RoutePosture, s proxyroute.Selection) orgcontract.ManagedIntegrityReport {
		t.Helper()
		v := govern.RoutePostureVerdict{Posture: p}
		return collectIntegritySignalsWith(db, home, "/current/observer", nil, routeDriftPolicy(v, port, s), hookIntegrityInputs{})
	}

	var out, errOut bytes.Buffer
	step := newRouteMaintenance(cfg, addr, fixedPosture(govern.RoutePostureMaintain), nil, &out, &errOut)
	if step(context.Background(), true) || claudeRouted(t, home) {
		t.Fatalf("routing is switched off, yet maintenance wrote a route (stdout %q stderr %q)", out.String(), errOut.String())
	}
	installed := []string{"claude-code", "codex"}
	for _, p := range []govern.RoutePosture{govern.RoutePostureMaintain, govern.RoutePostureNone} {
		rep := report(p, sel)
		if len(rep.DriftedTools) != 0 || rep.RouteDrift != 0 {
			t.Fatalf("%s: drift = %v (%d), want none", p, rep.DriftedTools, rep.RouteDrift)
		}
		if !rep.RoutingOff || !reflect.DeepEqual(rep.RoutingOffTools, installed) {
			t.Fatalf("%s: routing_off = %v tools %v, want true %v", p, rep.RoutingOff, rep.RoutingOffTools, installed)
		}
		if len(rep.UnselectedTools) != 0 || len(rep.UnroutableTools) != 0 {
			t.Fatalf("%s: unselected %v unroutable %v, want none (routing off says it once)", p, rep.UnselectedTools, rep.UnroutableTools)
		}
		if rep.SupervisorMissing {
			t.Fatalf("%s: supervisor warning on a node that keeps no routes", p)
		}
	}
	// Read without the selection (before D-771), the same host is drift.
	if got := report(govern.RoutePostureMaintain, proxyroute.Selection{}).DriftedTools; !reflect.DeepEqual(got, installed) {
		t.Fatalf("without the selection the probe should read both tools as drift, got %v", got)
	}
	// Release: nothing changes.
	if rep := report(govern.RoutePostureRelease, sel); rep.RoutingOff || len(rep.RoutingOffTools) != 0 || len(rep.DriftedTools) != 0 {
		t.Fatalf("release: routing_off %v tools %v drift %v, want none", rep.RoutingOff, rep.RoutingOffTools, rep.DriftedTools)
	}
	wire, err := json.Marshal(report(govern.RoutePostureMaintain, sel).NormalizeLabels())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"routing_off":true`, `"routing_off_tools":["claude-code","codex"]`} {
		if !strings.Contains(string(wire), key) {
			t.Fatalf("the managed-integrity wire lacks %s: %s", key, wire)
		}
	}
}

// TestUnselectedInstalledToolIsNotDrift is T-915 (operator decision D-770,
// "Show as a separate item"): on a managed node under the route posture
// maintain, an AI tool that is installed but not selected by policy is never
// routed by maintenance, so it must not read as route drift forever. It is
// reported as unselected_tools instead; under release nothing changes, and
// with no posture it is still unselected, never drift. In a managed distro
// build this is the shape of every adapter the policy left available.
func TestUnselectedInstalledToolIsNotDrift(t *testing.T) {
	home := routeHome(t)
	addr := healthyProxy(t)
	port, _ := proxyPortFromAddr(addr)
	codexDir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := unselectedRouteConfig(t, home)
	db := filepath.Join(home, ".observer", "observer.db")
	report := func(p govern.RoutePosture, s proxyroute.Selection) orgcontract.ManagedIntegrityReport {
		t.Helper()
		v := govern.RoutePostureVerdict{Posture: p}
		return collectIntegritySignalsWith(db, home, "/current/observer", nil, routeDriftPolicy(v, port, s), hookIntegrityInputs{})
	}
	policy := routeSelection(componentSnapshotFor(cfg))

	var out, errOut bytes.Buffer
	step := newRouteMaintenance(cfg, addr, fixedPosture(govern.RoutePostureMaintain), nil, &out, &errOut)
	for pass := 1; pass <= 2; pass++ {
		step(context.Background(), true)
		if !claudeRouted(t, home) {
			t.Fatalf("pass %d: the selected tool was not routed (stderr %q)", pass, errOut.String())
		}
		codex, _ := os.ReadFile(filepath.Join(codexDir, "config.toml"))
		if strings.Contains(string(codex), "127.0.0.1") {
			t.Fatalf("pass %d: maintenance routed codex, which the policy did not select:\n%s", pass, codex)
		}
		rep := report(govern.RoutePostureMaintain, policy)
		if len(rep.DriftedTools) != 0 || rep.RouteDrift != 0 {
			t.Fatalf("pass %d, maintain: drift = %v (%d), want none", pass, rep.DriftedTools, rep.RouteDrift)
		}
		if !reflect.DeepEqual(rep.UnselectedTools, []string{"codex"}) {
			t.Fatalf("pass %d, maintain: unselected = %v, want [codex]", pass, rep.UnselectedTools)
		}
		if containsAny(rep.UnroutableTools, []string{"codex"}) {
			t.Fatalf("pass %d: codex is both unselected and unroutable: %v", pass, rep.UnroutableTools)
		}
	}
	// The bug: read without the selection, the same host keeps codex as
	// drift although maintenance never routes it.
	if got := report(govern.RoutePostureMaintain, proxyroute.Selection{}).DriftedTools; !reflect.DeepEqual(got, []string{"codex"}) {
		t.Fatalf("without the selection the probe should read codex as drift (the T-915 bug), got %v", got)
	}
	// No posture: still unselected, never drift.
	if rep := report(govern.RoutePostureNone, policy); len(rep.DriftedTools) != 0 || !reflect.DeepEqual(rep.UnselectedTools, []string{"codex"}) {
		t.Fatalf("no posture: drift %v unselected %v, want none and [codex]", rep.DriftedTools, rep.UnselectedTools)
	}
	// Release: nothing changes, no drift and no unselected list.
	if rep := report(govern.RoutePostureRelease, policy); len(rep.DriftedTools) != 0 || len(rep.UnselectedTools) != 0 {
		t.Fatalf("release: drift %v unselected %v, want none", rep.DriftedTools, rep.UnselectedTools)
	}
	// The wire keeps the label.
	wire, err := json.Marshal(report(govern.RoutePostureMaintain, policy).NormalizeLabels())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wire), `"unselected_tools":["codex"]`) {
		t.Fatalf("the managed-integrity wire lacks unselected_tools: %s", wire)
	}
}

func containsAny(have, wanted []string) bool {
	for _, h := range have {
		for _, a := range wanted {
			if h == a {
				return true
			}
		}
	}
	return false
}
