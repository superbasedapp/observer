//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxsetup"
)

// runSetupEnable runs the bwrap Enable step (or its undo) through the setup
// seam the dashboard route calls, against the passive plan's fingerprint.
func runSetupEnable(t *testing.T, r *setupRig, action string) {
	t.Helper()
	p := r.plan(t, sandboxbackend.BackendBwrap)
	if _, err := r.svc.Run(context.Background(), sandboxbackend.BackendBwrap, dashapi.SandboxSetupRunRequest{Step: sandboxsetup.PrereqEnable, Action: action, Fingerprint: p.Fingerprint}, "dashboard"); err != nil {
		t.Fatalf("%s enable: %v", action, err)
	}
}

// TestSandboxSetupEnableTakesEffectLive (item 1): with the daemon's sandbox
// holder built while the sandbox was off, Enable through the route makes a
// sandboxed bwrap launch pass the launch's own backend gate with no restart,
// and its undo makes the same launch refused as not enabled.
func TestSandboxSetupEnableTakesEffectLive(t *testing.T) {
	requireComponents(t, sandboxComponent)
	r := newSetupRig(t, "[terminal.launch]\nallow_install = true\n[terminal.sandbox]\nenabled = false\nbackends = [\"oci-runc\"]\n")
	r.svc.run.applyLive = sandboxLiveApplyFor("dashboard", r.cfgPath)
	h := newTestSandboxHolder(t, r.cfgPath, t.TempDir())
	ctx := context.Background()
	if v := h.ProbeSandbox(ctx).Verdict; v != dashapi.VerdictDisabledByConfig {
		t.Fatalf("before Enable the probe reads %q, want %q", v, dashapi.VerdictDisabledByConfig)
	}
	// launchGate is the gate a sandboxed bwrap launch meets in Prepare
	// (sandboxLocalFloor over the live runtime), read the way Prepare reads
	// it: after the holder's refresh.
	launchGate := func() error {
		h.refresh()
		rt := h.rt.Load()
		if rt == nil {
			return errors.New("no live sandbox runtime")
		}
		return sandboxLocalFloor(rt.cfg)
	}

	runSetupEnable(t, r, dashapi.SandboxSetupActionRun)
	if err := launchGate(); err != nil {
		t.Fatalf("after Enable a bwrap launch is refused without a restart: %v", err)
	}
	if v := h.ProbeSandbox(ctx).Verdict; v == dashapi.VerdictDisabledByConfig {
		t.Fatal("after Enable the probe still reads disabled_by_config")
	}

	runSetupEnable(t, r, dashapi.SandboxSetupActionUndo)
	err := launchGate()
	if err == nil || !strings.Contains(err.Error(), "bwrap is not in [terminal.sandbox].backends") {
		t.Fatalf("after the undo a bwrap launch = %v, want refused as not enabled", err)
	}
}

// TestSandboxSetupEnableStartsTheRelayLive (item 1): with the sandbox off at
// daemon start the capture relay listens on nothing; Enable through the
// route starts it with no restart.
func TestSandboxSetupEnableStartsTheRelayLive(t *testing.T) {
	requireComponents(t, sandboxComponent)
	if !localipc.Supported() {
		t.Skip("no local IPC here")
	}
	resetSandboxManaged(t)
	r := newSetupRig(t, "[terminal.launch]\nallow_install = true\n[terminal.sandbox]\nenabled = false\nbackends = [\"bwrap\"]\n")
	r.svc.run.applyLive = sandboxLiveApplyFor("dashboard", r.cfgPath)
	obs, err := os.MkdirTemp("/tmp", "sbl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(obs) })
	load := func() config.Config {
		c, err := config.Load(config.LoadOptions{GlobalPath: r.cfgPath})
		if err != nil {
			t.Error(err)
		}
		c.Observer.DBPath = filepath.Join(obs, "observer.db")
		selectIfInactive(t, &c, sandboxComponent)
		return c
	}
	prev := sandboxRelayConfig
	sandboxRelayConfig = func(config.Config) config.Config { return load() }
	t.Cleanup(func() { sandboxRelayConfig = prev })
	cfg := load()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	startSandboxRelay(ctx, cfg, exe, slog.New(slog.DiscardHandler), sandboxRelayDeps{})
	if sandboxRelayReachable(sandboxObserverDirFor(cfg)) {
		t.Fatal("the sandbox is off: no relay may listen")
	}
	runSetupEnable(t, r, dashapi.SandboxSetupActionRun)
	deadline := time.Now().Add(5 * time.Second)
	for !sandboxRelayReachable(sandboxObserverDirFor(cfg)) {
		if time.Now().After(deadline) {
			t.Fatal("Enable turned the sandbox on, but the relay never started")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
