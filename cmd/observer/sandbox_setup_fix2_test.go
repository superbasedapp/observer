//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/sandboxsetup"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/toolinstall"
)

// The second live-check fix round (2026-11-07 re-runs): one test per item.

// setupTwoListedConfig lists bwrap with another row, so the enable step's
// undo would change something (the default-backend rule does not decide).
const setupTwoListedConfig = "[terminal.launch]\nallow_install = true\n[terminal.sandbox]\nenabled = true\nbackends = [\"bwrap\", \"cloud-hypervisor\"]\n"

// TestSandboxSetupUndoRefusalIsExitFour (F9b): the CLI undo of Enable while a sandboxed
// run is live, or while the daemon does not answer, prints the plan's reason
// and exits 4 (refused); an undo with nothing to undo stays exit 1.
func TestSandboxSetupUndoRefusalIsExitFour(t *testing.T) {
	cases := []struct {
		name    string
		live    int
		liveErr error
		cfg     string
		exit    int
		has     string
	}{
		{"live run", 1, nil, setupTwoListedConfig, sandboxSetupExitRefused, "1 live sandboxed run(s) use this backend"},
		{"daemon does not answer", 0, errors.New("the daemon at 127.0.0.1:8081 did not answer"), setupTwoListedConfig, sandboxSetupExitRefused, "could not ask the running daemon"},
		{"nothing to undo", 0, nil, setupBaseConfig, sandboxSetupExitFailed, "there is nothing Observer can undo"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newSetupRig(t, tc.cfg)
			r.programs["bwrap"] = "/usr/bin/bwrap"
			r.live["bwrap"], r.liveErr = tc.live, tc.liveErr
			st := stepOf(t, r.plan(t, "bwrap"), sandboxsetup.PrereqEnable)
			if st.CanUndo {
				t.Fatalf("enable can_undo = true")
			}
			var out bytes.Buffer
			if got := sandboxSetupDescribeNoUndo(&out, st); got != tc.exit {
				t.Errorf("exit = %d, want %d (%q)", got, tc.exit, out.String())
			}
			if !strings.Contains(out.String(), tc.has) {
				t.Errorf("output %q lacks %q", out.String(), tc.has)
			}
			if tc.exit == sandboxSetupExitRefused && strings.Contains(out.String(), "nothing Observer can undo") {
				t.Errorf("a refusal reads as nothing to undo: %q", out.String())
			}
		})
	}
}

// TestSandboxSetupNoUndoRows is one test per sandboxSetupNoUndo row.
func TestSandboxSetupNoUndoRows(t *testing.T) {
	cases := []struct {
		row  string
		st   dashapi.SandboxSetupStep
		exit int
	}{
		{"refused", dashapi.SandboxSetupStep{Label: "x", UndoRefused: sandboxsetup.UndoRefusedKillSwitch, Reason: "off"}, sandboxSetupExitRefused},
		{"nothing_to_undo", dashapi.SandboxSetupStep{Label: "x"}, sandboxSetupExitFailed},
	}
	covered := map[string]bool{}
	for _, tc := range cases {
		for _, row := range sandboxSetupNoUndo {
			if row.match(tc.st) {
				if row.name != tc.row {
					t.Errorf("%+v matched %s, want %s", tc.st, row.name, tc.row)
				}
				covered[row.name] = true
				break
			}
		}
		if got := sandboxSetupDescribeNoUndo(&bytes.Buffer{}, tc.st); got != tc.exit {
			t.Errorf("%s exit = %d, want %d", tc.row, got, tc.exit)
		}
	}
	for _, row := range sandboxSetupNoUndo {
		if !covered[row.name] {
			t.Errorf("row %s has no case", row.name)
		}
	}
}

// TestSandboxSetupArgKeysHaveReaders (D-L5b-1): every config key a command step's last
// argument comes from is read from the local config, and the Apple
// container image key reads the configured reference.
func TestSandboxSetupArgKeysHaveReaders(t *testing.T) {
	for _, id := range sandboxsetup.IDs() {
		p, _ := sandboxsetup.Lookup(id)
		for _, rem := range p.Remedies {
			if rem.ArgKey == "" {
				continue
			}
			if _, ok := sandboxArgKeys[rem.ArgKey]; !ok {
				t.Errorf("%s: ArgKey %q has no reader in sandboxArgKeys", id, rem.ArgKey)
			}
		}
	}
	var cfg config.Config
	cfg.Terminal.Sandbox.AppleContainer.Image = "docker.io/library/alpine@sha256:" + strings.Repeat("a", 64)
	if got := sandboxSetupArgValues(cfg)["terminal.sandbox.apple_container.image"]; got != cfg.Terminal.Sandbox.AppleContainer.Image {
		t.Errorf("image value = %q", got)
	}
}

// TestToolInstallOrphanRules is one test per orphanRules row.
func TestToolInstallOrphanRules(t *testing.T) {
	yes := func() bool { return true }
	no := func() bool { return false }
	cases := []struct {
		row    string
		c      orphanCtx
		settle bool
	}{
		{"not_in_flight", orphanCtx{inFlight: false, isDaemon: true, daemonListening: no}, false},
		{"begun_here", orphanCtx{inFlight: true, begunHere: true, isDaemon: true, daemonListening: no}, false},
		{"tracked_here", orphanCtx{inFlight: true, trackedHere: true, isDaemon: true, daemonListening: no}, false},
		{"daemon_owns_it", orphanCtx{inFlight: true, isDaemon: true, daemonListening: yes}, true},
		{"daemon_listening", orphanCtx{inFlight: true, daemonListening: yes}, false},
		{"no_daemon", orphanCtx{inFlight: true, daemonListening: no}, true},
	}
	covered := map[string]bool{}
	for _, tc := range cases {
		settle, row := orphanDecision(tc.c)
		covered[row] = true
		if row != tc.row || settle != tc.settle {
			t.Errorf("%s: got row %s settle %v, want settle %v", tc.row, row, settle, tc.settle)
		}
	}
	for _, r := range orphanRules {
		if !covered[r.name] {
			t.Errorf("orphan rule %s has no case", r.name)
		}
	}
}

// TestToolInstallCLINeverSettlesALiveDaemonsRecord (F16): a CLI process reading the
// records while a daemon listens leaves the daemon's in-flight setup record
// alone; with no daemon listening it settles it as interrupted; the daemon
// itself settles a record a previous daemon left.
func TestToolInstallCLINeverSettlesALiveDaemonsRecord(t *testing.T) {
	cases := []struct {
		name      string
		listening func(context.Context) bool
		want      toolinstall.Status
	}{
		{"cli, daemon listening", func(context.Context) bool { return true }, toolinstall.StatusInstalling},
		{"cli, no daemon", func(context.Context) bool { return false }, toolinstall.StatusInstallInterrupted},
		{"daemon", nil, toolinstall.StatusInstallInterrupted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, st, _, _ := newTestLedger(t, npmCodexPlan)
			l.daemonListening = tc.listening
			ctx := context.Background()
			if _, err := st.InsertToolInstall(ctx, store.ToolInstallRow{
				SubjectKind: store.SubjectSandbox, Tool: "oci-image", Channel: string(sandboxsetup.ChOCIPull),
				Argv: []string{"/usr/bin/observer", "sandbox", "oci", "pull"}, Display: "observer sandbox oci pull",
				Status: string(toolinstall.StatusInstalling), StartedAt: l.bootAt.Add(-time.Minute),
			}); err != nil {
				t.Fatal(err)
			}
			rows, err := l.SandboxRecords(ctx)
			if err != nil || len(rows) != 1 {
				t.Fatalf("rows = %+v %v", rows, err)
			}
			if rows[0].Status != string(tc.want) {
				t.Errorf("status = %s, want %s", rows[0].Status, tc.want)
			}
		})
	}
}

// TestSandboxSetupDaemonListeningProbe: only a refused connection reads as no daemon.
func TestSandboxSetupDaemonListeningProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener: %v", err)
	}
	addr := ln.Addr().String()
	if !sandboxSetupDaemonListening(addr)(context.Background()) {
		t.Error("a listening daemon reads as gone")
	}
	_ = ln.Close()
	if sandboxSetupDaemonListening(addr)(context.Background()) {
		t.Error("a closed port reads as listening")
	}
}
