package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/firstrunstate"
	"github.com/marmutapp/superbased-observer/internal/planechoice"
	sdkcatalog "github.com/marmutapp/superbased-observer/shared/lib"
)

// appscmd_test.go covers `observer apps on|off|status` (lane POLISH-F2,
// first-run plan revision 2 sections 3.5 and 4.4). Every test runs over a
// fake HOME with its own free receiver ports and auto_register = false; the
// daemon is either absent (resolveDaemonHandoff answers none) or a fake
// dashboard serving F1's /api/apps routes. The real in-process daemon checks
// are in appscmd_obs_test.go.

// appsCLIEnv is one test's world.
type appsCLIEnv struct {
	cfgPath string
	dbPath  string
	browser []string
	started int
}

// newAppsCLIEnv sets HOME and the seams. Nothing dials a real daemon,
// starts a service or opens a browser.
func newAppsCLIEnv(t *testing.T) *appsCLIEnv {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	e := &appsCLIEnv{cfgPath: writeAppsTestConfig(t, dir, appsFreeAddr(t), appsFreeAddr(t), false)}
	e.dbPath = filepath.Join(dir, ".observer", "observer.db")
	saved := struct {
		resolve func(context.Context, string) daemonTarget
		inBuild func() bool
		open    func(string)
		inter   func(*cobra.Command) bool
		start   func(context.Context) (bool, string)
		svcWait time.Duration
		nowFn   func() time.Time
	}{resolveDaemonHandoff, appsInBuild, appsOpenBrowser, appsInteractive, appsStartService, appsServiceWait, appsNow}
	t.Cleanup(func() {
		resolveDaemonHandoff, appsInBuild, appsOpenBrowser = saved.resolve, saved.inBuild, saved.open
		appsInteractive, appsStartService, appsServiceWait, appsNow = saved.inter, saved.start, saved.svcWait, saved.nowFn
	})
	resolveDaemonHandoff = func(context.Context, string) daemonTarget { return daemonTarget{} }
	appsOpenBrowser = func(u string) { e.browser = append(e.browser, u) }
	appsInteractive = func(*cobra.Command) bool { return false }
	appsStartService = func(context.Context) (bool, string) { e.started++; return false, "" }
	return e
}

// run executes `observer apps <args>` with stdin in.
func (e *appsCLIEnv) run(t *testing.T, in string, args ...string) (string, error) {
	t.Helper()
	cmd := newAppsCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader(in))
	cmd.SetArgs(append(args, "--config", e.cfgPath))
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func (e *appsCLIEnv) configOn(t *testing.T) bool {
	t.Helper()
	cfg, err := config.Load(config.LoadOptions{GlobalPath: e.cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Observability.Enabled
}

func (e *appsCLIEnv) intent() *firstrunstate.Intent {
	return firstrunstate.New(firstrunstate.Path(e.dbPath)).Load().Intent
}

// skipWithoutObs skips a test that needs this build to carry AI Apps (the
// edition test below covers the refusal in the builds that do not).
func skipWithoutObs(t *testing.T) {
	t.Helper()
	if !appObsCompiledIn() {
		t.Skip("AI Apps is not in this build; covered by the refusal tests")
	}
}

// TestAppsOnRefusesPerEdition: minimal and managed refuse with the
// reinstall line; developer and full turn AI Apps on (plan 3.5, 4.4).
func TestAppsOnRefusesPerEdition(t *testing.T) {
	obs, ok := components.Get("obs")
	if !ok {
		t.Fatal("obs is not in the component catalog")
	}
	want := map[components.Distro]bool{ // true: refuses
		components.DistroMinimal: true, components.DistroManaged: true,
		components.DistroDeveloper: false, components.DistroFull: false,
	}
	for _, d := range components.Distros() {
		t.Run(string(d), func(t *testing.T) {
			compiled := obs.Distros[d].Compiled()
			if compiled == want[d] {
				t.Fatalf("edition %s: obs compiled=%v, the plan expects it to refuse=%v", d, compiled, want[d])
			}
			if compiled {
				skipWithoutObs(t)
			}
			e := newAppsCLIEnv(t)
			appsInBuild = func() bool { return compiled }
			out, err := e.run(t, "", "on", "--yes")
			if !want[d] {
				if err != nil {
					t.Fatalf("%s refused: %v\n%s", d, err, out)
				}
				if !e.configOn(t) {
					t.Fatalf("%s: config not written", d)
				}
				return
			}
			if err == nil {
				t.Fatalf("%s did not refuse:\n%s", d, out)
			}
			for _, s := range []string{"This edition does not include AI Apps", "developer and full", "install.sh --edition developer", "install.ps1 -Edition developer"} {
				if !strings.Contains(err.Error(), s) {
					t.Errorf("%s refusal lacks %q: %v", d, s, err)
				}
			}
			if e.configOn(t) {
				t.Fatalf("%s: refusal wrote the config", d)
			}
		})
	}
}

// TestAppsOnRefusesInThisBuild runs the real build fact: in a build without
// AI Apps (the minimal and managed editions, no_obs) the command refuses;
// with it, this is covered by the tests below.
func TestAppsOnRefusesInThisBuild(t *testing.T) {
	if appObsCompiledIn() {
		t.Skip("AI Apps is in this build")
	}
	e := newAppsCLIEnv(t)
	appsInBuild = appObsCompiledIn
	_, err := e.run(t, "", "on", "--yes")
	if err == nil || !strings.Contains(err.Error(), "install.sh --edition developer") {
		t.Fatalf("want the reinstall refusal, got %v", err)
	}
	out, err := e.run(t, "", "status")
	if err != nil || !strings.Contains(out, "not in this edition") {
		t.Fatalf("status: %v\n%s", err, out)
	}
}

// TestAppsOnWithNoDaemonWritesConfigAndSaysStart: no daemon, so it writes
// the config, records the intent and prints `observer start`; it never
// daemonizes.
func TestAppsOnWithNoDaemonWritesConfigAndSaysStart(t *testing.T) {
	skipWithoutObs(t)
	e := newAppsCLIEnv(t)
	out, err := e.run(t, "", "on", "--yes")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !e.configOn(t) {
		t.Fatal("config not written")
	}
	for _, s := range []string{"Turning on AI Apps on this machine:", "Stays on this machine.", "(this machine only)", "No daemon is running here", "observer start", "Send a trace from your app:", "Python", "TypeScript", appsDocsURL} {
		if !strings.Contains(out, s) {
			t.Errorf("output lacks %q:\n%s", s, out)
		}
	}
	if strings.Contains(out, "AI Apps is on.") {
		t.Fatalf("says on with nothing listening:\n%s", out)
	}
	if e.started != 1 {
		t.Fatalf("installed-service check ran %d times, want 1", e.started)
	}
	if len(e.browser) != 0 {
		t.Fatalf("opened %v with no daemon", e.browser)
	}
	if in := e.intent(); in == nil || in.Choice != planechoice.ChoiceApps || in.Source != planechoice.SourceAppsOn {
		t.Fatalf("intent = %+v, want apps from apps_on", in)
	}
	// Status reads the saved state with no daemon.
	out, err = e.run(t, "", "status")
	if err != nil || !strings.Contains(out, "set to on; starts with `observer start`") || !strings.Contains(out, "Daemon      not running") {
		t.Fatalf("status: %v\n%s", err, out)
	}
	// Off writes it back.
	out, err = e.run(t, "", "off")
	if err != nil || e.configOn(t) || !strings.Contains(out, "AI Apps is off") {
		t.Fatalf("off: %v on=%v\n%s", err, e.configOn(t), out)
	}
}

// TestAppsOnInstallerRecordsTheInstallerIntent: the installer's run opens
// nothing, starts no service and records the installer as the source.
func TestAppsOnInstallerRecordsTheInstallerIntent(t *testing.T) {
	skipWithoutObs(t)
	e := newAppsCLIEnv(t)
	out, err := e.run(t, "", "on", "--yes", "--installer")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if e.started != 0 || len(e.browser) != 0 {
		t.Fatalf("installer run started %d services, opened %v", e.started, e.browser)
	}
	if in := e.intent(); in == nil || in.Source != planechoice.SourceInstaller {
		t.Fatalf("intent = %+v, want the installer's", in)
	}
}

// TestAppsOnStartsAnInstalledServiceAndReportsItsReceiver: with no daemon
// but an installed service, it starts the service and reports the
// receiver the started daemon recorded.
func TestAppsOnStartsAnInstalledServiceAndReportsItsReceiver(t *testing.T) {
	skipWithoutObs(t)
	e := newAppsCLIEnv(t)
	fd := newFakeAppsDaemon(t)
	fd.statusBody = func() string {
		return `{"in_build":true,"component":"active","on":true,"configured_on":true,"receiver":{"state":"listening","http_addr":"127.0.0.1:4318"},"consent":{"sentence":"Stays on this machine.","receiver_note":"(this machine only)"},"confirm_token":"tok"}`
	}
	appsStartService = func(context.Context) (bool, string) {
		e.started++
		resolveDaemonHandoff = fd.resolve
		return true, ""
	}
	out, err := e.run(t, "", "on", "--yes", "--no-open")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, s := range []string{"Started the installed observer service", "AI Apps is on.", "listening on 127.0.0.1:4318"} {
		if !strings.Contains(out, s) {
			t.Errorf("output lacks %q:\n%s", s, out)
		}
	}
}

// TestAppsOnWithNoDaemonReportsATakenPort: 4318 held by another program
// (a collector, Jaeger) fails loudly with the fix, never "on".
func TestAppsOnWithNoDaemonReportsATakenPort(t *testing.T) {
	skipWithoutObs(t)
	e := newAppsCLIEnv(t)
	cfg, err := config.Load(config.LoadOptions{GlobalPath: e.cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	held, err := net.Listen("tcp", cfg.Ingest.OTel.HTTPAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	out, err := e.run(t, "", "on", "--yes")
	if err == nil {
		t.Fatalf("a taken port was not reported:\n%s", out)
	}
	for _, s := range []string{"could not listen on " + cfg.Ingest.OTel.HTTPAddr, "[ingest.otel] http_addr"} {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("error lacks %q: %v", s, err)
		}
	}
	if strings.Contains(out, "AI Apps is on") {
		t.Fatalf("said on:\n%s", out)
	}
}

// TestAppsOnAsks: a non-terminal without --yes refuses; "n" changes
// nothing; Enter means yes.
func TestAppsOnAsks(t *testing.T) {
	skipWithoutObs(t)
	e := newAppsCLIEnv(t)
	if _, err := e.run(t, "", "on"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("non-terminal: %v", err)
	}
	appsInteractive = func(*cobra.Command) bool { return true }
	out, err := e.run(t, "n\n", "on")
	if err != nil || !strings.Contains(out, "Nothing changed.") || e.configOn(t) {
		t.Fatalf("n: %v on=%v\n%s", err, e.configOn(t), out)
	}
	out, err = e.run(t, "\n", "on")
	if err != nil || !strings.Contains(out, "Continue? [Y/n]") || !e.configOn(t) {
		t.Fatalf("enter: %v on=%v\n%s", err, e.configOn(t), out)
	}
}

// fakeAppsDaemon is a dashboard serving F1's /api/apps routes.
type fakeAppsDaemon struct {
	srv        *httptest.Server
	mu         sync.Mutex
	statusCode int
	statusBody func() string
	enableCode int
	enableBody string
	disables   int
	enables    int
	badConfirm int
}

func newFakeAppsDaemon(t *testing.T) *fakeAppsDaemon {
	t.Helper()
	fd := &fakeAppsDaemon{statusCode: http.StatusOK, enableCode: http.StatusOK}
	fd.statusBody = func() string {
		return `{"in_build":true,"component":"active","on":false,"configured_on":false,"hot_enable":true,"receiver":{"state":"not_running"},"consent":{"sentence":"Stays on this machine.","receiver_note":"(this machine only)","loopback_only":true},"confirm_token":"tok"}`
	}
	fd.enableBody = `{"outcome":"on","ok":true,"rule":"on and listening","message":"AI Apps is on.","receiver":{"state":"listening","http_addr":"127.0.0.1:4318"}}`
	mux := http.NewServeMux()
	mux.HandleFunc("/api/apps/status", func(w http.ResponseWriter, _ *http.Request) {
		fd.mu.Lock()
		defer fd.mu.Unlock()
		if fd.statusCode != http.StatusOK {
			http.Error(w, "x", fd.statusCode)
			return
		}
		_, _ = io.WriteString(w, fd.statusBody())
	})
	confirmed := func(r *http.Request) bool {
		c, err := r.Cookie("sb_remote_confirm")
		var body struct {
			Source string `json:"source"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		return err == nil && c.Value == "tok" && r.Header.Get("X-Observer-Confirm") == "tok" && body.Source == "cli"
	}
	mux.HandleFunc("/api/apps/enable", func(w http.ResponseWriter, r *http.Request) {
		fd.mu.Lock()
		defer fd.mu.Unlock()
		fd.enables++
		if !confirmed(r) {
			fd.badConfirm++
			http.Error(w, "confirm", http.StatusForbidden)
			return
		}
		w.WriteHeader(fd.enableCode)
		_, _ = io.WriteString(w, fd.enableBody)
	})
	mux.HandleFunc("/api/apps/disable", func(w http.ResponseWriter, r *http.Request) {
		fd.mu.Lock()
		defer fd.mu.Unlock()
		fd.disables++
		if !confirmed(r) {
			fd.badConfirm++
			http.Error(w, "confirm", http.StatusForbidden)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true,"effective":"next_start","message":"AI Apps is set to off. It stops at the next start of the daemon."}`)
	})
	fd.srv = httptest.NewServer(mux)
	t.Cleanup(fd.srv.Close)
	return fd
}

func (fd *fakeAppsDaemon) resolve(context.Context, string) daemonTarget {
	return daemonTarget{Base: fd.srv.URL, Use: true, Listening: true}
}

// TestAppsOnWithADaemonUsesTheEnableSeam: the CLI calls the daemon's one
// seam with the confirm token, writes nothing itself, and prints the
// receiver and the SDK rows.
func TestAppsOnWithADaemonUsesTheEnableSeam(t *testing.T) {
	skipWithoutObs(t)
	e := newAppsCLIEnv(t)
	fd := newFakeAppsDaemon(t)
	resolveDaemonHandoff = fd.resolve
	out, err := e.run(t, "", "on", "--yes")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if fd.enables != 1 || fd.badConfirm != 0 {
		t.Fatalf("enables=%d badConfirm=%d", fd.enables, fd.badConfirm)
	}
	for _, s := range []string{"AI Apps is on.  Dashboard: " + fd.srv.URL + "/apps   (opening)", "Receiver: listening on 127.0.0.1:4318 (this machine only)", "Send a trace from your app:"} {
		if !strings.Contains(out, s) {
			t.Errorf("output lacks %q:\n%s", s, out)
		}
	}
	if len(e.browser) != 1 || e.browser[0] != fd.srv.URL+"/apps" {
		t.Fatalf("browser = %v", e.browser)
	}
	if e.configOn(t) {
		t.Fatal("the CLI wrote the config itself; the daemon's seam owns it")
	}
	// --no-open opens nothing.
	e.browser = nil
	if _, err := e.run(t, "", "on", "--yes", "--no-open"); err != nil || len(e.browser) != 0 {
		t.Fatalf("--no-open: %v %v", err, e.browser)
	}
}

// TestAppsOnWithADaemonReportsABindFailure: the seam's bind_failed report
// is a loud failure with the fix (plan 3.5), never "on".
func TestAppsOnWithADaemonReportsABindFailure(t *testing.T) {
	skipWithoutObs(t)
	e := newAppsCLIEnv(t)
	fd := newFakeAppsDaemon(t)
	resolveDaemonHandoff = fd.resolve
	rep := planechoice.ClassifyEnable(planechoice.EnableFacts{
		InBuild: true, Component: planechoice.ComponentActive,
		Receiver: planechoice.Receiver{State: planechoice.ReceiverBindFailed, HTTPAddr: "127.0.0.1:4318", Error: "bind: address already in use"},
	})
	b, _ := json.Marshal(rep)
	fd.enableCode, fd.enableBody = http.StatusConflict, string(b)
	out, err := e.run(t, "", "on", "--yes")
	if err == nil {
		t.Fatalf("bind failure not reported:\n%s", out)
	}
	if !strings.Contains(err.Error(), "could not listen on 127.0.0.1:4318") || !strings.Contains(err.Error(), "[ingest.otel] http_addr") {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(out, "AI Apps is on") || len(e.browser) != 0 {
		t.Fatalf("said on or opened %v:\n%s", e.browser, out)
	}
}

// TestAppsOnWithADaemonWithoutTheSeam: a daemon older than the seam (404)
// or a process without it (501) is told to finish with `observer service
// restart`, the safe restart that takes the proxy routes off first and puts
// them back (SR-12, docs/daemon-restart-runbook.md); the config is written
// and nothing is restarted.
func TestAppsOnWithADaemonWithoutTheSeam(t *testing.T) {
	skipWithoutObs(t)
	for name, set := range map[string]func(*fakeAppsDaemon){
		"status 404": func(fd *fakeAppsDaemon) { fd.statusCode = http.StatusNotFound },
		"enable 501": func(fd *fakeAppsDaemon) { fd.enableCode, fd.enableBody = http.StatusNotImplemented, "no seam" },
	} {
		t.Run(name, func(t *testing.T) {
			e := newAppsCLIEnv(t)
			fd := newFakeAppsDaemon(t)
			set(fd)
			resolveDaemonHandoff = fd.resolve
			out, err := e.run(t, "", "on", "--yes")
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			for _, want := range []string{"Restart the daemon to finish: observer service restart", "takes the proxy routes off first", "Nothing was restarted."} {
				if !strings.Contains(out, want) {
					t.Fatalf("output lacks %q:\n%s", want, out)
				}
			}
			if strings.Count(out, "Turning on AI Apps") != 1 {
				t.Fatalf("asked twice:\n%s", out)
			}
			if !e.configOn(t) || e.started != 0 || len(e.browser) != 0 {
				t.Fatalf("on=%v started=%d browser=%v", e.configOn(t), e.started, e.browser)
			}
		})
	}
}

// TestAppsOnWithADaemonRefusesAnAbsentComponent: the daemon says the
// edition has no obs component; the CLI refuses before asking.
func TestAppsOnWithADaemonRefusesAnAbsentComponent(t *testing.T) {
	skipWithoutObs(t)
	e := newAppsCLIEnv(t)
	fd := newFakeAppsDaemon(t)
	fd.statusBody = func() string { return `{"in_build":true,"component":"absent","confirm_token":"tok"}` }
	resolveDaemonHandoff = fd.resolve
	_, err := e.run(t, "", "on", "--yes")
	if err == nil || !strings.Contains(err.Error(), "install.sh --edition developer") || fd.enables != 0 {
		t.Fatalf("err=%v enables=%d", err, fd.enables)
	}
}

// TestAppsOffAndStatusWithADaemon: off goes through the daemon's route and
// says it takes effect at the next start; status prints the daemon's facts.
func TestAppsOffAndStatusWithADaemon(t *testing.T) {
	skipWithoutObs(t)
	e := newAppsCLIEnv(t)
	fd := newFakeAppsDaemon(t)
	resolveDaemonHandoff = fd.resolve
	out, err := e.run(t, "", "off")
	if err != nil || fd.disables != 1 || fd.badConfirm != 0 || !strings.Contains(out, "next start") {
		t.Fatalf("off: %v disables=%d\n%s", err, fd.disables, out)
	}
	fd.statusBody = func() string {
		return `{"in_build":true,"component":"active","on":true,"configured_on":true,"receiver":{"state":"listening","http_addr":"127.0.0.1:4318"},"latest_trace":{"trace_id":"abc","name":"answer","service":"my-app","started_at":"2026-11-20T10:00:00Z"},"consent":{"sentence":"Also sent to Acme (summaries).","receiver_note":"(this machine only)"},"pending_next_start":["alerts"],"confirm_token":"tok"}`
	}
	out, err = e.run(t, "", "status")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"AI Apps     on", "Daemon      running", "listening 127.0.0.1:4318 (this machine only)", "Last trace  abc answer (my-app)", "Also sent to Acme (summaries).", "Next start  alerts"} {
		if !strings.Contains(out, s) {
			t.Errorf("status lacks %q:\n%s", s, out)
		}
	}
	out, err = e.run(t, "", "status", "--json")
	if err != nil || strings.Contains(out, `"confirm_token"`) || !strings.Contains(out, `"daemon_running": true`) {
		t.Fatalf("status --json: %v\n%s", err, out)
	}
}

// TestAppsStatusLines: one case per status row.
func TestAppsStatusLines(t *testing.T) {
	skipWithoutObs(t)
	c := planechoice.Consent{Sentence: "Stays on this machine.", ReceiverNote: "(this machine only)"}
	cases := []struct {
		name    string
		st      appsStatusBody
		running bool
		want    string
	}{
		{"not in build", appsStatusBody{InBuild: false}, false, "not in this edition"},
		{"absent", appsStatusBody{InBuild: true, Component: planechoice.ComponentAbsent}, false, "not in this edition"},
		{"blocked", appsStatusBody{InBuild: true, Component: planechoice.ComponentBlocked}, false, "blocked on this machine"},
		{"on", appsStatusBody{InBuild: true, Component: planechoice.ComponentActive, On: true, ConfiguredOn: true, Consent: c}, true, "AI Apps     on"},
		{"on, set off", appsStatusBody{InBuild: true, Component: planechoice.ComponentActive, On: true, Consent: c}, true, "set to off; stops at the next start"},
		{"set on, daemon waiting", appsStatusBody{InBuild: true, Component: planechoice.ComponentActive, ConfiguredOn: true, Consent: c}, true, "not serving yet"},
		{"set on, no daemon", appsStatusBody{InBuild: true, Component: planechoice.ComponentActive, ConfiguredOn: true, Consent: c}, false, "starts with `observer start`"},
		{"off", appsStatusBody{InBuild: true, Component: planechoice.ComponentAvailable, Consent: c}, false, "off (turn it on: observer apps on)"},
	}
	for _, tc := range cases {
		got := strings.Join(appsStatusLines(tc.st, tc.running), "\n")
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s: want %q in\n%s", tc.name, tc.want, got)
		}
	}
}

// TestSnippetHeadStopsAtInit: the CLI prints each SDK's snippet up to its
// init call, every catalog row has one.
func TestSnippetHeadStopsAtInit(t *testing.T) {
	got := snippetHead([]string{"import x", "", "x.init(a)", "", "more"})
	if strings.Join(got, "|") != "import x|x.init(a)" {
		t.Fatalf("got %v", got)
	}
	var out bytes.Buffer
	printAppsNextSteps(&out)
	for _, s := range []string{"Python", "TypeScript", "Go", "Java"} {
		if !strings.Contains(out.String(), "  "+s) {
			t.Errorf("SDK rows lack %s:\n%s", s, out.String())
		}
	}
}

// TestAppsNextStepsLeadWithSetup: a language with a setup command prints it
// first (in the install line's place, since setup installs the SDK), then
// its init line; a language without one keeps its install line.
func TestAppsNextStepsLeadWithSetup(t *testing.T) {
	var out bytes.Buffer
	printAppsNextSteps(&out)
	lines := strings.Split(out.String(), "\n")
	at := func(prefix string) int {
		for i, l := range lines {
			if strings.HasPrefix(l, prefix) {
				return i
			}
		}
		t.Fatalf("no line starts with %q in\n%s", prefix, out.String())
		return -1
	}
	cases := []struct{ label, first, init string }{
		{"Python", "uvx superbased-sdk setup", "superbased_sdk.init()"},
		{"TypeScript", "npx @superbased/sdk setup", `require("@superbased/sdk").init()`},
	}
	for _, c := range cases {
		i := at(fmt.Sprintf("  %-11s %s", c.label, c.first))
		if i+1 >= len(lines) || !strings.Contains(lines[i+1], c.init) {
			t.Errorf("%s: the setup line is not followed by the init line:\n%s", c.label, out.String())
		}
	}
	if strings.Contains(out.String(), "pip install superbased-sdk") || strings.Contains(out.String(), "npm install @superbased/sdk") {
		t.Errorf("a language with setup still prints its install line:\n%s", out.String())
	}
	// Go has no setup of its own: its install line stays.
	at(fmt.Sprintf("  %-11s %s", "Go", "go get github.com/superbasedapp/observer/sdk/go"))

	// The rule, on rows of its own: setup when set, else the install line.
	var b bytes.Buffer
	printSDKNextSteps(&b, []sdkcatalog.SDK{
		{Label: "A", Published: true, InstallPublished: "a install", Setup: "a setup", Snippet: []string{"a.init()"}},
		{Label: "B", Published: true, InstallPublished: "b install", Snippet: []string{"b.init()"}},
	})
	want := fmt.Sprintf("\nSend a trace from your app:\n  %-11s a setup\n  %-11s a.init()\n  %-11s b install\n  %-11s b.init()\n", "A", "", "B", "")
	if b.String() != want {
		t.Fatalf("got\n%q\nwant\n%q", b.String(), want)
	}
}

// TestWelcomeAppsLine: bare `observer` names `observer apps on` only in a
// build that has AI Apps (plan 3.4).
func TestWelcomeAppsLine(t *testing.T) {
	if got := welcomeAppsLine(true); !strings.HasPrefix(got, "observer apps on   ") || !strings.Contains(got, "trace the AI apps you build") {
		t.Fatalf("line = %q", got)
	}
	if got := welcomeAppsLine(false); got != "" {
		t.Fatalf("a build without AI Apps advertises %q", got)
	}
}

// TestAppsCmdIsRegistered: `observer apps` is on the root.
func TestAppsCmdIsRegistered(t *testing.T) {
	root := newRootCmd()
	c, _, err := root.Find([]string{"apps", "on"})
	if err != nil || c.Name() != "on" {
		t.Fatalf("observer apps on not found: %v", err)
	}
}
