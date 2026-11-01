//go:build linux && !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboximage"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	"github.com/marmutapp/superbased-observer/internal/sandboxvm"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// terminal_sandbox_vm_lifecycle_linux_test.go covers milestone 6 of lane
// SBX-P4: teardown and the orphan sweep (with real processes and a reused
// pid), the destructive lifecycle cells, hostile bytes on the vsock
// transport, relay survival, the selection rules for a beta row and N13.

// vmSweepRig is one observer dir with a run dir per case.
func vmWriteRunDir(t *testing.T, obs, runID string, procs []sandboxvm.Proc) string {
	t.Helper()
	dir := vmRunStateDir(obs, runID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(sandboxvm.ProcRecord{RunID: runID, Procs: procs})
	if err := os.WriteFile(filepath.Join(dir, sandboxvm.ProcRecordName), b, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, n := range sandboxvm.LeftoverNames() {
		_ = os.WriteFile(filepath.Join(dir, n), nil, 0o600)
	}
	_ = os.WriteFile(filepath.Join(dir, "vsock.sock_1024"), nil, 0o600)
	_ = os.WriteFile(filepath.Join(dir, "fs-ws.sock.pid"), []byte("1\n"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, sandboxvm.ProcRecordName+".lock"), nil, 0o600)
	return dir
}

// startSleeper starts a real stand-in process and records it.
func startSleeper(t *testing.T) (*exec.Cmd, sandboxvm.Proc) {
	t.Helper()
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skip("no sleep")
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	f := vmProcFacts(cmd.Process.Pid)
	if !f.Alive {
		t.Fatal("no /proc facts for the sleeper")
	}
	return cmd, sandboxvm.Proc{Role: sandboxvm.RoleVMM, PID: cmd.Process.Pid, StartTicks: f.StartTicks, Exe: f.Exe}
}

// TestVMSweepAfterAHelperSIGKILL: after the helper and the daemon are gone,
// the next daemon's sweep kills the recorded VMM whose start time and
// executable match, spares a reused pid (another start time) and a live
// run, and removes the dead run's dir with every leftover socket.
func TestVMSweepAfterAHelperSIGKILL(t *testing.T) {
	obs := t.TempDir()
	vmmCmd, vmm := startSleeper(t)
	_, reused := startSleeper(t)
	reused.StartTicks++
	dead := vmWriteRunDir(t, obs, "run-dead", []sandboxvm.Proc{vmm, reused})
	live := vmWriteRunDir(t, obs, "run-live", []sandboxvm.Proc{vmm})
	heldDir := vmWriteRunDir(t, obs, "run-held", []sandboxvm.Proc{vmm})
	lock, err := os.OpenFile(filepath.Join(heldDir, sandboxvm.ProcRecordName+".lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	env := vmSweepEnv{
		facts: vmProcFacts, kill: func(pid int) error { return syscall.Kill(pid, syscall.SIGKILL) },
		relayLive: func(id string) bool { return id == "run-live" },
		held:      vmLockHeld,
	}
	res, err := vmSweepRuns(obs, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Killed) != 1 || res.Killed[0] != vmm.PID || strings.Join(res.Removed, ",") != "run-dead" {
		t.Fatalf("result %+v", res)
	}
	waited := make(chan error, 1)
	go func() { waited <- vmmCmd.Wait() }()
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("the orphaned VMM stand-in was not killed")
	}
	if _, err := os.Stat(dead); !os.IsNotExist(err) {
		t.Fatalf("the dead run's dir stays: %v", err)
	}
	for _, d := range []string{live, heldDir} {
		if _, err := os.Stat(filepath.Join(d, "api.sock")); err != nil {
			t.Fatalf("%s was touched: %v", d, err)
		}
	}
	if !strings.Contains(strings.Join(res.Spared, ";"), "start time differs") {
		t.Fatalf("the reused pid was not reported as spared: %v", res.Spared)
	}
}

// TestVMSweepRunsOnlyInTheDaemon: the sweep starts at the driver's first
// passing probe in the daemon's runtime, never in a CLI runtime.
func TestVMSweepRunsOnlyInTheDaemon(t *testing.T) {
	countVMProbe(t)
	var sweeps atomic.Int64
	prev := vmSweepFn
	vmSweepFn = func(string) { sweeps.Add(1) }
	t.Cleanup(func() { vmSweepFn = prev })
	cli := macTestRuntime(t, vmTestConfig(t, true, "cloud-hypervisor"))
	_ = cli.drivers[sandboxbackend.BackendCloudHypervisor].probe(context.Background())
	time.Sleep(50 * time.Millisecond)
	if sweeps.Load() != 0 {
		t.Fatal("a CLI runtime swept")
	}
	d := macTestRuntime(t, vmTestConfig(t, true, "cloud-hypervisor"))
	d.inDaemon = true
	_ = d.drivers[sandboxbackend.BackendCloudHypervisor].probe(context.Background())
	vmWaitFor(t, "the daemon's sweep", func() bool { return sweeps.Load() == 1 })
}

// TestVMHostileGuestBytesEndTheRunCleanly (A5 over the vsock adapter): a
// guest answering the PTY session with garbage, an oversized frame or a
// replayed preamble never crashes the helper; the run ends within its
// window and leaves nothing behind.
func TestVMHostileGuestBytesEndTheRunCleanly(t *testing.T) {
	for name, junk := range map[string][]byte{
		"garbage":   []byte("not a mux hello at all\n"),
		"oversized": append([]byte("SBM1\x01\x08run-vm-1"), make([]byte, 1<<20)...),
		"wrong run": []byte("SBM1\x01\x05other"),
	} {
		t.Run(name, func(t *testing.T) {
			r := newVMRig(t)
			r.guestOff = true
			env := r.env()
			env.bootWindow = time.Second
			r.vmmHook = func(f *fakeVM) {
				l := f.ports[vmPTYPort]
				go func() {
					for {
						select {
						case c := <-l.ch:
							go func() { _, _ = c.Write(junk); _ = c.Close() }()
						case <-l.closed:
							return
						}
					}
				}()
			}
			// A valid hello followed by junk frames passes the handshake
			// and then fails the session (exit 1, "ended without an exit
			// status"); anything else never gets a session (125).
			code := vmHostRun(r.plan, r.h, []string{"/bin/true"}, env)
			if code != sandboxHelperFailCode && code != 1 {
				t.Fatalf("exit %d", code)
			}
			if _, err := os.Stat(r.plan.VM.StateDir); !os.IsNotExist(err) {
				t.Fatalf("the state dir stays: %v", err)
			}
		})
	}
}

// TestVMRelaySurvivesACutTunnel (A6): the relay tunnel is cut and the host
// helper re-dials; a connection from the guest socket dir then reaches the
// host relay again.
func TestVMRelaySurvivesACutTunnel(t *testing.T) {
	r := newVMRig(t)
	result := make(chan string, 1)
	r.run = func(g *relaymux.Guest, _ relayStdioArgs) int {
		r.mu.Lock()
		gs := r.guestSock
		r.mu.Unlock()
		dial := func() string {
			c, err := net.Dial("unix", filepath.Join(gs, sandboxrelayd.RelaySocketName))
			if err != nil {
				return err.Error()
			}
			defer func() { _ = c.Close() }()
			_, _ = io.WriteString(c, "x\n")
			b := make([]byte, 2)
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err := io.ReadFull(c, b); err != nil {
				return err.Error()
			}
			return string(b)
		}
		if got := dial(); got != "x\n" {
			result <- "before: " + got
			return 1
		}
		// Cut every tunnel connection the fake VMM carries for port 1025.
		vm := r.fakeVMNow()
		vm.mu.Lock()
		conns := append([]net.Conn(nil), vm.conns...)
		vm.mu.Unlock()
		for i, c := range conns {
			if i >= 3 { // the PTY session's three are first
				_ = c.Close()
			}
		}
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			if got := dial(); got == "x\n" {
				result <- "ok"
				return 0
			}
			time.Sleep(100 * time.Millisecond)
		}
		result <- "never came back"
		return 1
	}
	code := r.runHost()
	if got := <-result; got != "ok" || code != 0 {
		t.Fatalf("%s, exit %d, terminal %q", got, code, r.termOut.String())
	}
}

// TestVMPTYTransportDropEndsTheRun (A7, the transport cell): a cut PTY
// session (no reattach on this row) ends the run honestly with native
// resume offered.
func TestVMPTYTransportDropEndsTheRun(t *testing.T) {
	r := newVMRig(t)
	r.run = func(g *relaymux.Guest, _ relayStdioArgs) int {
		vm := r.fakeVMNow()
		vm.mu.Lock()
		first := vm.conns[0]
		vm.mu.Unlock()
		_ = first.Close()
		<-g.Done()
		return 0
	}
	code := r.runHost()
	if code == 0 || !strings.Contains(r.termOut.String(), "Resume the agent's session") {
		t.Fatalf("exit %d, terminal %q", code, r.termOut.String())
	}
}

// TestVMRowIsNeverAnAutomaticChoice (P-062, S4c): with the microVM row and
// bubblewrap both available, auto picks bubblewrap; with only the microVM
// row it chooses nothing (beta_not_chosen); naming it picks it.
func TestVMRowIsNeverAnAutomaticChoice(t *testing.T) {
	in := sandboxselect.Input{
		Request: sandboxselect.Request{Tier: vocab.TierInternet, Interactive: true, Custody: vocab.CustodyHostBound, AcceptReducedCapture: true},
		Host:    sandboxbackend.HostLinux,
		Enabled: []string{sandboxbackend.BackendCloudHypervisor, sandboxbackend.BackendBwrap},
		Probes: map[string]sandboxselect.Probe{
			sandboxbackend.BackendCloudHypervisor: {Compiled: true, Verdict: sandboxselect.VerdictAvailable, Version: "54"},
			sandboxbackend.BackendBwrap:           {Compiled: true, Verdict: sandboxselect.VerdictAvailable, Version: "0.9.0"},
		},
		Tool: sandboxselect.Tool{Mapped: true, ProxyRouted: true, CredentialInReach: true},
	}
	if res := sandboxselect.Select(in); res.Chosen == nil || res.Chosen.Backend != sandboxbackend.BackendBwrap {
		t.Fatalf("auto chose %+v", res)
	}
	in.Enabled = []string{sandboxbackend.BackendCloudHypervisor}
	if res := sandboxselect.Select(in); res.Chosen != nil {
		t.Fatalf("auto chose the beta row: %+v", res.Chosen)
	}
	in.Request.Backend = sandboxbackend.BackendCloudHypervisor
	if res := sandboxselect.Select(in); res.Chosen == nil || res.Chosen.Backend != sandboxbackend.BackendCloudHypervisor {
		t.Fatalf("naming the row: %+v", res)
	}
}

// TestVMN13KeepsAForcedAgentSandbox: with an image set declaring user
// namespaces, a vendor-forced agent sandbox is kept inside the VM (N13);
// without, the row is like any other and the conflict text names it.
func TestVMN13KeepsAForcedAgentSandbox(t *testing.T) {
	set := vmImageSet{res: sandboximage.VMSetResult{OK: true, Descriptor: sandboximage.VMDescriptor{GuestUserns: true}}}
	n := sandboxselect.NativeSandbox{Present: true, NeedsFreshProc: true, VendorForced: true, ForcedPolicy: sandboxselect.VendorForcedNestOrRefuse}
	v := sandboxselect.NativeNesting(vmGuestRow(set), vocab.TierInternet, n)
	if v.Outcome != sandboxselect.NativeKept || v.Rule != "N13" || !v.Forced {
		t.Fatalf("with userns: %+v", v)
	}
	bw, _ := sandboxbackend.Get(sandboxbackend.BackendBwrap)
	v = sandboxselect.NativeNesting(bw, vocab.TierInternet, n)
	if v.Outcome != sandboxselect.NativeRefuse || !strings.Contains(v.Reason, sandboxbackend.BackendCloudHypervisor) {
		t.Fatalf("bwrap: %+v", v)
	}
	if row := vmGuestRow(vmImageSet{}); row.GuestUnprivUserns {
		t.Fatal("an unverified set claimed user namespaces")
	}
}

// TestVMToolRefusals (decision 8, as the first live run left it): a tool
// launch that names no binary is tool_unavailable_in_image, with the
// install cache on or off, naming the flag that lifts it; one that names a
// binary returns its path (relative to the project); a plain shell runs.
func TestVMToolRefusals(t *testing.T) {
	if bin, err := vmToolRunnable("shell", false, nil, "/home/u/p"); err != nil || bin != "" {
		t.Fatal(bin, err)
	}
	for _, cache := range []bool{false, true} {
		if _, err := vmToolRunnable("claude-code", cache, []string{"--resume"}, "/home/u/p"); err == nil || !strings.Contains(err.Error(), "tool_unavailable_in_image") || !strings.Contains(err.Error(), "--claude-path") {
			t.Fatalf("cache %v: %v", cache, err)
		}
	}
	if bin, err := vmToolRunnable("claude-code", false, []string{"--claude-path", "bin/a.sh"}, "/home/u/p"); err != nil || bin != "/home/u/p/bin/a.sh" {
		t.Fatal(bin, err)
	}
	_ = config.Default()
}

// TestVMSweepAtDaemonStartWithoutAProbe (audit finding 7): the daemon-start
// hook sweeps whenever the runs dir exists, with no driver selected and no
// probe run, and does nothing when it does not.
func TestVMSweepAtDaemonStartWithoutAProbe(t *testing.T) {
	var sweeps atomic.Int64
	prev := vmSweepFn
	vmSweepFn = func(string) { sweeps.Add(1) }
	t.Cleanup(func() { vmSweepFn = prev })
	_, reads := countVMProbe(t)
	found := false
	for _, h := range sandboxDaemonStartHooks {
		found = found || h != nil
	}
	if !found {
		t.Fatal("no daemon-start hook is registered")
	}
	obs := t.TempDir()
	start := func() {
		for _, h := range sandboxDaemonStartHooks {
			h(obs)
		}
	}
	start()
	time.Sleep(50 * time.Millisecond)
	if sweeps.Load() != 0 {
		t.Fatal("swept with no state root")
	}
	if err := os.MkdirAll(filepath.Join(vmStateRoot(obs), "runs"), 0o700); err != nil {
		t.Fatal(err)
	}
	start()
	vmWaitFor(t, "the daemon-start sweep", func() bool { return sweeps.Load() == 1 })
	if reads.Load() != 0 {
		t.Fatal("the daemon-start sweep read the probe's facts")
	}
}

// TestVMStartProcSurvivesItsCallersThread (audit finding 7): a process
// started from a goroutine that exits while locked to its OS thread (the
// runtime then ends that thread) is not killed by PR_SET_PDEATHSIG, because
// the fork happened on the starter's own locked thread.
func TestVMStartProcSurvivesItsCallersThread(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep")
	}
	got := make(chan vmProc, 1)
	go func() {
		runtime.LockOSThread()
		p, err := vmStartProc(sandboxvm.RoleVMM, []string{sleep, "30"}, nil)
		if err != nil {
			t.Error(err)
			got <- nil
			return
		}
		got <- p
		// returns locked: the runtime terminates this thread
	}()
	p := <-got
	if p == nil {
		return
	}
	defer func() { p.Kill(); <-p.Done() }()
	time.Sleep(500 * time.Millisecond)
	select {
	case <-p.Done():
		t.Fatal("the child died with the thread of the goroutine that asked for it")
	default:
	}
}
