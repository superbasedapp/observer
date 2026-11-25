package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
	"github.com/marmutapp/superbased-observer/internal/service"
)

// routehold_stop_test.go: L-168 (i). A deliberate stop of the daemon takes
// the routes that reach its proxy off and journals them; the next daemon
// puts back exactly those once its own proxy serves, and never onto a port
// nobody serves. Everything runs on a throwaway HOME: the real ~/.claude and
// ~/.codex are never touched.

// stopHoldPort is the fake daemon's proxy port.
const stopHoldPort = 19871

// stopHoldHome is a throwaway HOME with Claude Code and Codex configs the
// developer owns. claudeOwn names a base URL the developer set for Claude
// Code ("" = none; Observer's init then routes it).
type stopHoldHome struct {
	home, claude, codex string
}

func newStopHoldHome(t *testing.T, claudeOwn string) stopHoldHome {
	t.Helper()
	home := t.TempDir()
	setTestHome(t, home)
	h := stopHoldHome{
		home:   home,
		claude: filepath.Join(home, ".claude", "settings.json"),
		codex:  filepath.Join(home, ".codex", "config.toml"),
	}
	claudeBody := `{"env":{"KEEP_ME":"1"},"model":"x"}`
	if claudeOwn != "" {
		claudeBody = `{"env":{"ANTHROPIC_BASE_URL":"` + claudeOwn + `","KEEP_ME":"1"},"model":"x"}`
	}
	writeStopHoldFile(t, h.claude, claudeBody)
	writeStopHoldFile(t, h.codex, "# my codex config\nmodel = \"gpt-x\"\nmodel_provider = \"mine\"\n\n[model_providers.mine]\nname = \"mine\"\nbase_url = \"https://example.invalid/v1\"\n")
	reg := h.registrar(t, true)
	if claudeOwn == "" {
		if res := reg.RegisterClaudeCode(); res.Error != nil || !res.Added {
			t.Fatalf("route claude: %+v", res)
		}
	}
	if res := reg.RegisterCodex(); res.Error != nil || !res.Added {
		t.Fatalf("route codex: %+v", res)
	}
	return h
}

func writeStopHoldFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// registrar is `observer init`'s writer (forced, so Codex switches from the
// developer's own provider and records it) or, with init=false, the
// daemon's.
func (h stopHoldHome) registrar(t *testing.T, init bool) *proxyroute.Registrar {
	t.Helper()
	opts := proxyroute.RegisterOptions{ProxyPort: stopHoldPort, HomeDir: h.home}
	if init {
		opts.Writer, opts.Force = routeprov.WriterInit, true
	}
	reg, err := proxyroute.NewRegistrar(opts)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func (h stopHoldHome) read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var stopHoldProxyURL = "127.0.0.1:" + strconv.Itoa(stopHoldPort)

func (h stopHoldHome) claudeRouted(t *testing.T) bool {
	return strings.Contains(h.read(t, h.claude), stopHoldProxyURL)
}

func (h stopHoldHome) codexRouted(t *testing.T) bool {
	s := h.read(t, h.codex)
	return strings.Contains(s, proxyroute.ProviderName) && strings.Contains(s, stopHoldProxyURL)
}

// stop runs the daemon's hold at the end of a run.
func (h stopHoldHome) stop(t *testing.T, ev service.StopEvent, served bool, owner service.RouteOwner) (service.StopRoutesPlan, string) {
	t.Helper()
	var out bytes.Buffer
	s := routeHoldOnStop{
		port:      stopHoldPort,
		registrar: func(port int) (*proxyroute.Registrar, error) { return h.registrar(t, false), nil },
		event:     func() service.StopEvent { return ev },
		served:    func() bool { return served },
		owner:     func() service.RouteOwner { return owner },
		stdout:    &out, stderr: &out,
	}
	return s.run(), out.String()
}

// start runs the next daemon's put-back; servingAfter is how many readiness
// probes fail before its proxy answers, and during runs at each failed one.
func (h stopHoldHome) start(t *testing.T, servingAfter int, during func()) string {
	t.Helper()
	var out bytes.Buffer
	probes := 0
	p := routeHoldPutBack{
		port:      stopHoldPort,
		registrar: func(port int) (*proxyroute.Registrar, error) { return h.registrar(t, false), nil },
		serving: func(_ context.Context, port int) bool {
			if port != stopHoldPort {
				t.Errorf("probed :%d, want the daemon's own :%d", port, stopHoldPort)
			}
			probes++
			return probes > servingAfter
		},
		wait: func(context.Context, time.Duration) bool {
			if during != nil {
				during()
			}
			return true
		},
		stdout: &out, stderr: &out,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p.run(ctx)
	return out.String()
}

// TestDaemonStopAndStartRoundTrip: a deliberate stop takes off the Claude
// Code and Codex routes that reach this proxy, journals exactly those, and
// leaves a route the developer pointed elsewhere byte for byte; the next
// daemon puts back exactly those, only once its proxy answers.
func TestDaemonStopAndStartRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		claudeOwn string
		wantHeld  []string
	}{
		{"claude-code and codex routed by Observer", "", []string{"claude-code", "codex"}},
		{"claude-code pointed at the developer's own gateway", "https://llm-gateway.corp.example", []string{"codex"}},
		{"claude-code pointed at another proxy port", "http://127.0.0.1:" + strconv.Itoa(stopHoldPort+1), []string{"codex"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newStopHoldHome(t, c.claudeOwn)
			claudeBefore, codexBefore := h.read(t, h.claude), h.read(t, h.codex)

			plan, out := h.stop(t, service.StopEventStop, true, service.RouteOwnerNode)
			if plan.Action != service.StopRoutesTakeOff {
				t.Fatalf("plan = %+v\n%s", plan, out)
			}
			if h.codexRouted(t) {
				t.Fatalf("the codex route is still on after the stop:\n%s", h.read(t, h.codex))
			}
			if !strings.Contains(h.read(t, h.codex), `model_provider = "mine"`) {
				t.Fatalf("the developer's own codex provider is not selected while the daemon is down:\n%s", h.read(t, h.codex))
			}
			if c.claudeOwn == "" {
				if h.claudeRouted(t) {
					t.Fatal("the claude-code route is still on after the stop")
				}
			} else if got := h.read(t, h.claude); got != claudeBefore {
				t.Fatalf("a route the developer set elsewhere changed:\n%s\nwant\n%s", got, claudeBefore)
			}

			// The journal holds exactly what came off, for this port.
			pending, err := proxyroute.PendingRouteHoldAt(h.home)
			if err != nil {
				t.Fatal(err)
			}
			if pending.Port != stopHoldPort || len(pending.Routes) != len(c.wantHeld) {
				t.Fatalf("journal = %+v, want %v on :%d", pending, c.wantHeld, stopHoldPort)
			}
			for i, tool := range c.wantHeld {
				if pending.Routes[i].Tool != tool {
					t.Fatalf("journal = %+v, want %v", pending.Routes, c.wantHeld)
				}
			}

			// The next daemon: nothing goes back while its proxy does not
			// answer; exactly the journaled routes go back once it does.
			waited := 0
			out = h.start(t, 3, func() {
				waited++
				if h.codexRouted(t) || (c.claudeOwn == "" && h.claudeRouted(t)) {
					t.Fatal("a route went back onto a port nobody serves")
				}
			})
			if waited != 3 {
				t.Fatalf("the put-back waited %d times, want 3 (until the proxy answered)\n%s", waited, out)
			}
			if got := h.read(t, h.codex); got != codexBefore {
				t.Fatalf("codex after the put-back:\n%s\nwant\n%s\n%s", got, codexBefore, out)
			}
			if got := h.read(t, h.claude); got != claudeBefore {
				t.Fatalf("claude-code after the put-back:\n%s\nwant\n%s\n%s", got, claudeBefore, out)
			}
			if p, _ := proxyroute.PendingRouteHoldAt(h.home); !p.Empty() {
				t.Fatalf("the journal still lists routes after the put-back: %+v", p)
			}
		})
	}
}

// TestDaemonStopLeavesTheRoutes: every end of a run that is not a
// deliberate stop on a node that owns its routes leaves both files as they
// were and writes no journal.
func TestDaemonStopLeavesTheRoutes(t *testing.T) {
	cases := []struct {
		name   string
		ev     service.StopEvent
		served bool
		owner  service.RouteOwner
		verb   bool
	}{
		{"a restart that hands the socket over", service.StopEventRestartHandover, true, service.RouteOwnerNode, false},
		{"an update hand-over", service.StopEventUpdateHandover, true, service.RouteOwnerNode, false},
		{"a failure", service.StopEventFailure, true, service.RouteOwnerNode, false},
		{"a daemon whose proxy never bound its port", service.StopEventStop, false, service.RouteOwnerNode, false},
		{"the organization maintains the routes", service.StopEventStop, true, service.RouteOwnerOrg, false},
		{"the organization's posture is unreadable", service.StopEventStop, true, service.RouteOwnerUnknown, false},
		{"an `observer service stop` holds the routes", service.StopEventStop, true, service.RouteOwnerNode, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newStopHoldHome(t, "")
			claudeBefore, codexBefore := h.read(t, h.claude), h.read(t, h.codex)
			if c.verb {
				release, ok, err := h.registrar(t, false).LockRouteHold()
				if err != nil || !ok {
					t.Fatalf("lock: %v %v", ok, err)
				}
				defer release()
			}
			plan, out := h.stop(t, c.ev, c.served, c.owner)
			if plan.Action != service.StopRoutesLeave {
				t.Fatalf("plan = %+v\n%s", plan, out)
			}
			if h.read(t, h.claude) != claudeBefore || h.read(t, h.codex) != codexBefore {
				t.Fatalf("a route changed:\n%s", out)
			}
			if p, _ := proxyroute.PendingRouteHoldAt(h.home); !p.Empty() {
				t.Fatalf("journal written: %+v", p)
			}
		})
	}
}

// TestDaemonStopKeepsTheOrganizationsRoutes: on a node whose organization
// does not maintain the routes, a route the organization wrote stays on
// through a deliberate stop (the hold table), while the developer's own
// init route comes off.
func TestDaemonStopKeepsTheOrganizationsRoutes(t *testing.T) {
	h := newStopHoldHome(t, "")
	// Claude Code's route was written by the organization's enrolment.
	reg, err := proxyroute.NewRegistrar(proxyroute.RegisterOptions{ProxyPort: stopHoldPort, HomeDir: h.home, Writer: routeprov.WriterEnrolment})
	if err != nil {
		t.Fatal(err)
	}
	writeStopHoldFile(t, h.claude, `{"env":{"KEEP_ME":"1"},"model":"x"}`)
	if res := reg.RegisterClaudeCode(); res.Error != nil || !res.Added {
		t.Fatalf("org route: %+v", res)
	}
	claudeBefore := h.read(t, h.claude)
	plan, out := h.stop(t, service.StopEventStop, true, service.RouteOwnerNode)
	if plan.Action != service.StopRoutesTakeOff {
		t.Fatalf("plan = %+v", plan)
	}
	if h.read(t, h.claude) != claudeBefore {
		t.Fatalf("the organization's route changed on a stop:\n%s", out)
	}
	if !strings.Contains(out, "kept  claude-code") {
		t.Fatalf("the kept route is not reported:\n%s", out)
	}
	if h.codexRouted(t) {
		t.Fatal("the developer's own codex route stayed on")
	}
}

// TestDaemonStopEvent: how the end of a run is read.
func TestDaemonStopEvent(t *testing.T) {
	cases := []struct {
		signalled, restart, handover, update bool
		want                                 service.StopEvent
	}{
		{true, false, false, false, service.StopEventStop},
		{false, false, false, false, service.StopEventFailure},
		{true, true, true, false, service.StopEventRestartHandover},
		{true, true, false, false, service.StopEventRestart},
		{false, false, false, true, service.StopEventUpdateHandover},
		{true, true, true, true, service.StopEventUpdateHandover},
	}
	for _, c := range cases {
		if got := daemonStopEvent(c.signalled, c.restart, c.handover, c.update); got != c.want {
			t.Errorf("daemonStopEvent(%v, %v, %v, %v) = %s, want %s", c.signalled, c.restart, c.handover, c.update, got, c.want)
		}
	}
}

// TestDaemonRouteOwner: who decides about the routes at the end of a run.
func TestDaemonRouteOwner(t *testing.T) {
	maintain := func(context.Context) govern.RoutePostureVerdict {
		return govern.RoutePostureVerdict{Posture: govern.RoutePostureMaintain}
	}
	none := func(context.Context) govern.RoutePostureVerdict {
		return govern.RoutePostureVerdict{Posture: govern.RoutePostureNone}
	}
	cases := []struct {
		name    string
		lock    config.GuardOrgLock
		loaded  bool
		posture func(context.Context) govern.RoutePostureVerdict
		want    service.RouteOwner
	}{
		{"the config did not load", config.GuardOrgLock{}, false, none, service.RouteOwnerUnknown},
		{"an individual node by its verified lock", config.GuardOrgLock{State: "valid", TenancyKnown: true}, true, maintain, service.RouteOwnerNode},
		{"a lock that does not verify", config.GuardOrgLock{State: "tampered"}, true, none, service.RouteOwnerUnknown},
		{"a managed node, posture maintain", config.GuardOrgLock{State: "valid", TenancyKnown: true, Managed: true}, true, maintain, service.RouteOwnerOrg},
		{"a managed node, no posture", config.GuardOrgLock{State: "valid", TenancyKnown: true, Managed: true}, true, none, service.RouteOwnerNode},
		{"no lock, not enrolled", config.GuardOrgLock{}, true, none, service.RouteOwnerNode},
		{"no governance handle", config.GuardOrgLock{}, true, nil, service.RouteOwnerUnknown},
	}
	for _, c := range cases {
		if got := daemonRouteOwner(c.lock, c.loaded, c.posture); got != c.want {
			t.Errorf("%s: daemonRouteOwner = %s, want %s", c.name, got, c.want)
		}
	}
}
