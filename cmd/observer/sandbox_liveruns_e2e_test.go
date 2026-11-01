//go:build !sbo_omit_ui_dashboard && !sbo_omit_org_update && !sbo_omit_terminals

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/quiesce"
	"github.com/marmutapp/superbased-observer/internal/service"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// sourceManager is the terminal manager the update drain reads, counting
// the same live sandboxed runs the gate does.
type sourceManager struct{ src *fakeLiveSource }

func (sourceManager) LiveCount() int            { return 0 }
func (m sourceManager) LiveSandboxedCount() int { return m.src.LiveSandboxedCount() }

// TestLiveSandboxedRunEndToEnd walks one live fake sandboxed run (lane
// SBX-UPD) through the three paths that used to end it without asking: the
// dashboard restart asks (409) and restarts only when the run finishes; the
// `observer service restart` client sees the run over loopback, refuses,
// then ends it through the daemon with --end-sandboxed-runs; an update apply
// defers (posture deferred_live_sandbox), the restart report raises it as
// the same question, and "apply when they finish" applies it once the run
// is gone.
func TestLiveSandboxedRunEndToEnd(t *testing.T) {
	fastLivePoll(t)
	src := &fakeLiveSource{}
	src.set(1)
	installLiveSource(t, src)

	// The daemon's seam, with the update runtime's hooks.
	var restarts atomic.Int32
	seam := newDaemonLiveRuns(func() error { restarts.Add(1); return nil }, func() string { return liveRunPolicyAskImmediately }, nil)
	saved := updateLiveDeferredHook.Load()
	t.Cleanup(func() { updateLiveDeferredHook.Store(saved) })
	cfg := config.Default()
	cfg.Update.Enabled = true
	u := newUpdateRuntime(cfg, "", store.New(nil), nil, sourceManager{src: src}, nil)
	var applied atomic.Int32
	h := updateLiveDeferredHook.Load()
	updateLiveDeferredHook.Store(&liveDeferredHooks{pending: h.pending, apply: func(context.Context) error {
		applied.Add(1)
		u.liveDeferred.Store(nil)
		return nil
	}})
	wireLiveRunUpdateHooks(seam)

	dir := t.TempDir()
	database, err := db.Open(context.Background(), db.Options{Path: filepath.Join(dir, "observer.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	srv, err := dashboard.New(dashboard.Options{
		DB: database, ConfigPath: filepath.Join(dir, "config.toml"),
		RestartFunc: seam.restart, LiveSandboxRuns: seam,
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	post := func(body string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/admin/restart", strings.NewReader(body))
		req.Host = "127.0.0.1:8080"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}

	// 1. The dashboard restart asks, then restarts when the run finishes.
	if r := post(""); r.StatusCode != http.StatusConflict || restarts.Load() != 0 {
		t.Fatalf("restart with a live run = %d (restarts %d)", r.StatusCode, restarts.Load())
	}
	seam.pendingStopped = make(chan struct{}, 1)
	if r := post(`{"live_runs":"when_finished"}`); r.StatusCode != http.StatusAccepted {
		t.Fatalf("when_finished = %d", r.StatusCode)
	}
	if restarts.Load() != 0 {
		t.Fatal("restarted while the run was live")
	}
	src.set(0)
	select {
	case <-seam.pendingStopped:
	case <-time.After(3 * time.Second):
		t.Fatal("the pending restart never fired")
	}
	if restarts.Load() != 1 {
		t.Fatalf("restarts = %d after the run finished", restarts.Load())
	}

	// 2. observer service restart, over loopback to the same daemon.
	src.set(1)
	client := httpLiveRunsClient(ts.URL + "/api/admin/restart")
	savedSD, savedCtl, savedClient := systemdAvailable, serviceSystemctl, newDaemonLiveRunsClient
	t.Cleanup(func() { systemdAvailable, serviceSystemctl, newDaemonLiveRunsClient = savedSD, savedCtl, savedClient })
	systemdAvailable = func() bool { return true }
	var ctl []string
	serviceSystemctl = func(c service.Command) error { ctl = append(ctl, strings.Join(c.Args, " ")); return nil }
	newDaemonLiveRunsClient = func(string) daemonLiveRunsClient { return client }
	if out, err := runServiceRestart(t); err == nil || len(ctl) != 0 || !strings.Contains(err.Error(), "claude-code on bwrap") {
		t.Fatalf("service restart with a live run: %v %v %q", err, ctl, out)
	}
	if out, err := runServiceRestart(t, "--end-sandboxed-runs"); err != nil || len(ctl) != 1 || src.LiveSandboxedCount() != 0 || len(src.ended) == 0 {
		t.Fatalf("--end-sandboxed-runs: %v %v %q (live %d)", err, ctl, out, src.LiveSandboxedCount())
	}

	// 3. A deferred update apply: the drain holds it for the run (the gate
	// and the drain are one rule), the posture names the sandbox, the report
	// raises the question at once (ask_immediately), and the answer applies
	// it when the run is gone.
	src.set(1)
	var sandboxWork *quiesce.LiveWork
	for i := range u.quiescence.Live {
		if u.quiescence.Live[i].Name == liveSandboxWorkName {
			sandboxWork = &u.quiescence.Live[i]
		}
	}
	if sandboxWork == nil || sandboxWork.Forcible || sandboxWork.Count() != 1 {
		t.Fatalf("the drain does not hold the live sandboxed run: %+v", sandboxWork)
	}
	u.noteLiveDeferral(updateApplyRequest{Version: "9.9.9"}, applyOutcome{State: update.StateAvailable, Reason: update.ReasonDeferredLiveSandbox, Deferred: true})
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/admin/restart", nil)
	req.Host = "127.0.0.1:8080"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var body strings.Builder
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	body.Write(buf[:n])
	_ = resp.Body.Close()
	for _, want := range []string{`"update_deferred_live_sandbox":true`, `"update_question":true`} {
		if !strings.Contains(body.String(), want) {
			t.Fatalf("report lacks %s: %s", want, body.String())
		}
	}
	seam.pendingStopped = make(chan struct{}, 1)
	if r := post(`{"live_runs":"apply_when_finished"}`); r.StatusCode != http.StatusAccepted {
		t.Fatalf("apply_when_finished = %d", r.StatusCode)
	}
	src.set(0)
	select {
	case <-seam.pendingStopped:
	case <-time.After(3 * time.Second):
		t.Fatal("the pending apply never ran")
	}
	if applied.Load() != 1 || sandboxWork.Count() != 0 {
		t.Fatalf("applied %d, drain count %d", applied.Load(), sandboxWork.Count())
	}
}
