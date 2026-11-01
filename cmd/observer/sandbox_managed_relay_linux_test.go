//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestSandboxRelayStartsWhenTheManagedBodyEnablesTheSandbox is SBX-P1C merge
// finding 1: with the developer's own sandbox off, a managed body that turns
// it on while the daemon runs starts the capture relay, so a CLI sandboxed
// launch passes its relay check (terminal_sandbox_cli.go) instead of being
// refused for lack of the daemon.
func TestSandboxRelayStartsWhenTheManagedBodyEnablesTheSandbox(t *testing.T) {
	if !localipc.Supported() {
		t.Skip("no local IPC here")
	}
	resetSandboxManaged(t)
	prev := sandboxRelayConfig
	sandboxRelayConfig = func(boot config.Config) config.Config { return boot }
	t.Cleanup(func() { sandboxRelayConfig = prev })
	obs, err := os.MkdirTemp("/tmp", "sbm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(obs) })
	cfg := config.Config{}
	cfg.Observer.DBPath = filepath.Join(obs, "observer.db")
	cfg.Terminal.Sandbox = config.TerminalSandboxConfig{Enabled: false, Backend: "bwrap", Egress: "internet"}
	// The sandbox module selected where this edition leaves it inactive by
	// default (developer, managed): the relay is the active module's.
	selectIfInactive(t, &cfg, sandboxComponent)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	startSandboxRelay(ctx, cfg, exe, slog.New(slog.DiscardHandler), sandboxRelayDeps{})
	if sandboxRelayReachable(sandboxObserverDirFor(cfg)) {
		t.Fatal("the sandbox is off and no body is in force: no relay may listen")
	}
	processSandboxManaged.observe(orgclient.ManagedPullOutcome{
		Rail: "sandbox", InForce: true, Version: 1, ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Body: managedBody(t, orgcontract.SandboxManagedPolicyV1{Enabled: ptr(true)}),
	})
	deadline := time.Now().Add(5 * time.Second)
	for !sandboxRelayReachable(sandboxObserverDirFor(cfg)) {
		if time.Now().After(deadline) {
			t.Fatal("the managed body turned the sandbox on, but the relay never started")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !effectiveSandboxConfig(cfg).Enabled {
		t.Fatal("the effective sandbox must be on")
	}
	// A later body that turns it off leaves the relay up, idle.
	processSandboxManaged.observe(orgclient.ManagedPullOutcome{})
	if !sandboxRelayReachable(sandboxObserverDirFor(cfg)) {
		t.Fatal("the relay must stay up for boxes launched while the sandbox was on")
	}
}

// TestSandboxManagedRootIsOneRoot is SBX-P1C merge finding 3: with a managed
// body in force, termsvc's root (the holder's), the relay's (the same value,
// attach_standalone.go) and the runtime's agree, because no body can carry a
// workspaces_dir.
func TestSandboxManagedRootIsOneRoot(t *testing.T) {
	resetSandboxManaged(t)
	obs := t.TempDir()
	cfg := config.Config{}
	cfg.Observer.DBPath = filepath.Join(obs, "observer.db")
	cfg.Terminal.Sandbox = config.TerminalSandboxConfig{Enabled: false, Backend: "bwrap", Egress: "internet"}
	processSandboxManaged.observe(orgclient.ManagedPullOutcome{
		Rail: "sandbox", InForce: true, Version: 1, ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Body: managedBody(t, orgcontract.SandboxManagedPolicyV1{Enabled: ptr(true), Egress: ptr("proxy_only")}),
	})
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	h := newSandboxHolder(cfg, "", obs, exe, nil)
	rt := h.rt.Load()
	if rt == nil {
		t.Fatalf("the managed body enables the runtime: %v", h.initErr.Load())
	}
	if rt.workspacesDir() != h.workspacesDir() || relayCloneOrigin(h.workspacesDir()) == nil {
		t.Fatalf("roots differ: runtime %s, termsvc and relay %s", rt.workspacesDir(), h.workspacesDir())
	}
	if _, err := orgcontract.DecodeSandboxManagedPolicy([]byte(`{"schema":"sbo-sandbox-managed-v1","node":{"workspaces_dir":"/srv/ws"}}`)); err == nil {
		t.Fatal("a body naming workspaces_dir must be refused")
	}
}
