package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/planechoice"
)

// TestAppsGateIs404UntilOn: every gated route answers 404 while AI Apps is
// off in the process, and the installed handler once the gate opens.
func TestAppsGateIs404UntilOn(t *testing.T) {
	a := newAppsRuntime(appsRuntimeOptions{})
	a.inBuild = true
	routes := a.gatedRoutes(nil)
	if appObsCompiledIn() && len(routes) == 0 {
		t.Fatal("no gated routes in a build with obs")
	}
	if !appObsCompiledIn() {
		return
	}
	var enabled http.HandlerFunc
	for _, r := range routes {
		if r.Pattern == "GET /api/obs/enabled" {
			enabled = r.Handler
		}
	}
	if enabled == nil {
		t.Fatal("GET /api/obs/enabled is not gated")
	}
	serve := func() int {
		rr := httptest.NewRecorder()
		enabled(rr, httptest.NewRequest(http.MethodGet, "/api/obs/enabled", nil))
		return rr.Code
	}
	if serve() != http.StatusNotFound {
		t.Fatal("served while off")
	}
	a.install([]dashapi.ExtraRoute{{Pattern: "GET /api/obs/enabled", Handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }}})
	if serve() != http.StatusNotFound {
		t.Fatal("served before the gate opened")
	}
	a.gate.Store(true)
	if serve() != http.StatusTeapot {
		t.Fatal("not served once on")
	}
}

// TestAppsGateBootOnOpensAtOnce: a daemon started with AI Apps on serves the
// boot routes with no enable.
func TestAppsGateBootOnOpensAtOnce(t *testing.T) {
	if !appObsCompiledIn() {
		t.Skip("obs not in this build")
	}
	a := newAppsRuntime(appsRuntimeOptions{BootOn: true})
	routes := a.gatedRoutes([]dashapi.ExtraRoute{{Pattern: "GET /api/obs/enabled", Handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }}})
	if !a.on() {
		t.Fatal("gate closed with boot routes")
	}
	for _, r := range routes {
		if r.Pattern == "GET /api/obs/enabled" {
			rr := httptest.NewRecorder()
			r.Handler(rr, httptest.NewRequest(http.MethodGet, "/api/obs/enabled", nil))
			if rr.Code != http.StatusAccepted {
				t.Fatalf("code %d", rr.Code)
			}
		}
	}
}

// TestReceiverCtlListeningAnswersAtOnce: an enable on a daemon whose
// receiver already listens (vendor ingest on) does not wait.
func TestReceiverCtlListeningAnswersAtOnce(t *testing.T) {
	c := newReceiverCtl()
	c.report(planechoice.Receiver{State: planechoice.ReceiverListening, HTTPAddr: "127.0.0.1:1"})
	start := time.Now()
	if r := c.ensure(context.Background(), 5*time.Second); r.State != planechoice.ReceiverListening || time.Since(start) > time.Second {
		t.Fatalf("got %+v after %s", r, time.Since(start))
	}
}

// TestReceiverCtlNoGoroutineIsNoAnswer: nobody serving the request reads as
// no answer, never as on.
func TestReceiverCtlNoGoroutineIsNoAnswer(t *testing.T) {
	c := newReceiverCtl()
	if r := c.ensure(context.Background(), 200*time.Millisecond); r.State != planechoice.ReceiverNoAnswer {
		t.Fatalf("got %+v", r)
	}
}

// writeAppsTestConfig writes a minimal isolated config: its own DB, its own
// receiver ports, hooks never auto-registered.
func writeAppsTestConfig(t *testing.T, dir, grpcAddr, httpAddr string, obsOn bool) string {
	t.Helper()
	cfg := config.Default()
	cfg.Observer.DBPath = filepath.Join(dir, ".observer", "observer.db")
	cfg.Observer.LogLevel = "error"
	cfg.Observer.Hooks.AutoRegister = false
	cfg.Ingest.OTel.GRPCAddr = grpcAddr
	cfg.Ingest.OTel.HTTPAddr = httpAddr
	cfg.Observability.Enabled = obsOn
	if err := os.MkdirAll(filepath.Dir(cfg.Observer.DBPath), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ".observer", "config.toml")
	if err := config.WriteToml(path, cfg); err != nil {
		t.Fatal(err)
	}
	return path
}

// appsFreeAddr returns a loopback address with a port nothing holds.
func appsFreeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// TestReceiverWaitsThenBindsLateAndReportsABindFailure drives the real
// receiver goroutine: with nothing on it waits instead of returning; an
// enable request with the port held by another program is answered
// bind_failed (and recorded for doctor); once the port is free the next
// request binds.
func TestReceiverWaitsThenBindsLateAndReportsABindFailure(t *testing.T) {
	if !appObsCompiledIn() {
		t.Skip("obs not in this build")
	}
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	// Hold the HTTP port, as a local collector or Jaeger would.
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpAddr := held.Addr().String()
	grpcAddr := appsFreeAddr(t)
	cfgPath := writeAppsTestConfig(t, dir, grpcAddr, httpAddr, false)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	apps := newAppsRuntime(appsRuntimeOptions{Ctx: ctx, ConfigPath: cfgPath})
	done := make(chan error, 1)
	go func() { done <- runOTLPReceiver(ctx, cfgPath, io.Discard, apps) }()

	// With nothing on, the goroutine reports not_running and waits.
	// The first pass opens (and migrates) the database: slow under -race.
	deadline := time.Now().Add(90 * time.Second)
	for apps.recv.current().State != planechoice.ReceiverNotRunning {
		if time.Now().After(deadline) {
			t.Fatalf("receiver never reported; state %+v", apps.recv.current())
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("the receiver goroutine returned instead of waiting for an enable")
	default:
	}

	// AI Apps turned on in the config (the enable seam's write), the port
	// still held: the request is answered bind_failed.
	writeAppsTestConfig(t, dir, grpcAddr, httpAddr, true)
	r := apps.recv.ensure(ctx, 60*time.Second)
	if r.State != planechoice.ReceiverBindFailed || r.Error == "" || r.HTTPAddr != httpAddr {
		t.Fatalf("held port: %+v", r)
	}
	rep := planechoice.ClassifyEnable(planechoice.EnableFacts{InBuild: true, Component: planechoice.ComponentActive, Receiver: r})
	if rep.OK || rep.Outcome != planechoice.OutcomeBindFailed {
		t.Fatalf("classified %+v", rep)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if st, ok, _ := loadOTLPReceiverStatus(cfg); !ok || st.State != otlpReceiverBindFailed {
		t.Fatalf("doctor record: %+v ok=%v", st, ok)
	}

	// The port is freed: the next enable binds without a restart.
	_ = held.Close()
	r = apps.recv.ensure(ctx, 60*time.Second)
	if r.State != planechoice.ReceiverListening || r.HTTPAddr != httpAddr {
		t.Fatalf("after freeing the port: %+v", r)
	}
	resp, err := http.Post("http://"+httpAddr+"/v1/traces", "application/x-protobuf", nil)
	if err != nil {
		t.Fatalf("receiver not reachable: %v", err)
	}
	_ = resp.Body.Close()
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("receiver goroutine did not stop")
	}
}
