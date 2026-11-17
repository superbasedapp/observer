//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// startBoxGateRelay stands the whole launch-gate path up for a box side
// caller: the run record and the box record in a private socket dir, the
// host helper (the forwarder) on the box's relay socket, and the daemon's
// handler on the link with the PRODUCTION executor running a real observer
// binary as the relay-gate child. A request from boxLaunchGate then crosses
// the real frames on both hops, the helper's head and whole checks, the
// daemon's binding rows and the child's stdin read.
func startBoxGateRelay(t *testing.T, bin, ws string) {
	t.Helper()
	obs, sock := relayShortDir(t), relayShortDir(t)
	if err := os.Chmod(sock, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := writeRelayConfig(t, obs, "")
	run, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: "run-evid", Tool: "claude-code", ProjectRoot: ws, WorkspaceDir: ws, Roots: []string{ws}})
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteRun(obs, run); err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteBoxRecord(sock, run); err != nil {
		t.Fatal(err)
	}
	d := &sandboxrelayd.Daemon{
		ObserverDir: obs, Rules: relayRules, Peer: sandboxrelayd.PeerSameUser, Gated: relayRequestGated,
		Exec: relayExecutor(cfg, bin), LegacyRefusal: relayLegacyRefusal,
	}
	link := filepath.Join(obs, "link.sock")
	dln, err := net.Listen("unix", link)
	if err != nil {
		t.Fatal(err)
	}
	bln, err := net.Listen("unix", filepath.Join(sock, sandboxrelayd.RelaySocketName))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = d.Serve(ctx, dln) }()
	fw := &sandboxrelayd.Forwarder{Run: run, Rules: relayRules, Peer: sandboxrelayd.PeerSameUser, DialDaemon: func(ctx context.Context) (net.Conn, error) {
		var dl net.Dialer
		return dl.DialContext(ctx, "unix", link)
	}}
	go func() { _ = fw.Serve(ctx, bln) }()
	oldSock, oldRec, oldWd := boxSocketDir, boxRecordPath, boxGetwd
	boxSocketDir, boxRecordPath = sock, filepath.Join(sock, sandboxrelayd.BoxRecordName)
	boxGetwd = func() (string, error) { return ws, nil }
	t.Cleanup(func() { boxSocketDir, boxRecordPath, boxGetwd = oldSock, oldRec, oldWd })
}

// TestBoxLaunchGateCarriesATaskSizedArgument: the 2026-11-15 live run's
// defect, end to end. A sandboxed security assessment passes its whole task
// (up to 24,576 bytes plus the target) as ONE argument of the agent's
// command line, and the relay gate refused every such launch ("the launch
// evidence is refused: argument") at its 4,096 byte bound, so the run ended
// right after the box was built. The launcher's own call, boxLaunchGate,
// now carries the evidence through both relay hops and the gate child, up
// to the kernel's per-argument limit; a launch over a bound is refused with
// the bound named.
func TestBoxLaunchGateCarriesATaskSizedArgument(t *testing.T) {
	bin := probeHookTestBinary(t)
	ws := t.TempDir()
	setTestHome(t, t.TempDir())
	startBoxGateRelay(t, bin, ws)

	many := func(n int, c string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = strings.Repeat(c, 128<<10)
		}
		return out
	}
	for _, tc := range []struct {
		name string
		args []string
		// want is empty for a launch the gate lets through, else a text its
		// refusal holds.
		want string
	}{
		{"a flag", []string{"-p"}, ""},
		{"an assessment's full task and target", []string{"-p", strings.Repeat("t", 24576+512)}, ""},
		{"a task of the prompt budget's pin", []string{"--print", strings.Repeat("t", 22528)}, ""},
		{"the kernel's per-argument limit", []string{strings.Repeat("k", 128<<10)}, ""},
		{"eight arguments at the kernel's limit", many(8, "a"), ""},
		// Every byte of the task is a six byte escape in the evidence JSON
		// (an escaped < is six bytes): the widest document the bounds accept,
		// over both hops.
		{"the widest JSON the bounds accept", many(8, "<"), ""},
		{"one past the kernel's per-argument limit", []string{strings.Repeat("k", 128<<10+1)}, "over the 131072 byte bound"},
		{"a NUL in the task", []string{"-p", "task\x00more"}, "argument 1 holds a NUL byte"},
		{"nine arguments at the kernel's limit", many(9, "a"), "total bound"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err, boxed := boxLaunchGate("claude-code", budgetLaunchEvidence{Route: budgetLaunchRouteMaintenance, Arguments: tc.args})
			if !boxed {
				t.Fatal("the launch gate did not run through the relay")
			}
			if tc.want == "" {
				if err != nil {
					t.Fatalf("the relay gate refused the launch: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want a refusal naming %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "launch checks could not reach") {
				t.Fatalf("the refusal is the relay's, not the gate's: %v", err)
			}
		})
	}
}
