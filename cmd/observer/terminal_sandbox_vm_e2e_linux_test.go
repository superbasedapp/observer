//go:build linux && !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
	"github.com/marmutapp/superbased-observer/internal/sandboxvm"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_vm_e2e_linux_test.go is lane SBX-P4's end-to-end test: a
// fake Cloud Hypervisor run from launch to teardown, through the real
// driver (probe, the verified image set imported under a TEST key, Create
// with a clone-local copy, Attach writing the plan) and the real host
// helper and guest serve code (boot plan, strict read-back, the PTY round
// trip over the hybrid vsock socket, the return with the scan, the
// teardown), then the daemon's sweep over a crashed run's leftovers.
// Nothing opens /dev/kvm or the network.
func TestVMEndToEndFromLaunchToTeardown(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	obs, err := os.MkdirTemp("", "vme")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(obs) })
	_ = os.Chmod(obs, 0o700)

	// The verified image set, signed with a key generated here; this
	// agent's version is the guest binary's.
	pub, priv := vmTestKey(t)
	prevKeys, prevVersion := sandboxContentVendorKeys, version
	sandboxContentVendorKeys = func() []ed25519.PublicKey { return []ed25519.PublicKey{pub} }
	version = "1.40.0"
	prevIDs := vmHostIDs
	vmHostIDs = func() (int, int) { return 1000, 1000 }
	t.Cleanup(func() { sandboxContentVendorKeys, version, vmHostIDs = prevKeys, prevVersion, prevIDs })
	if _, err := sandboxContentImport(vmContentStore(obs), []ed25519.PublicKey{pub}, writeVMTestSet(t, priv, 1, "1.0.0", "1.40.0").dir); err != nil {
		t.Fatal(err)
	}

	// The probe: a healthy KVM host, the real image set load.
	prevProbe := vmProbeEnvFn
	vmProbeEnvFn = func(r *sandboxRuntime, cfg config.TerminalSandboxVMConfig) sandboxvm.ProbeEnv {
		env := sandboxvm.ProbeEnv{
			GOOS:          "linux",
			KVM:           func() sandboxvm.KVMFacts { return sandboxvm.KVMFacts{Exists: true, CharDevice: true} },
			InVM:          func() bool { return false },
			LookVMM:       func() (string, error) { return "/usr/local/bin/cloud-hypervisor", nil },
			LookVirtiofsd: func() (string, error) { return "/usr/libexec/virtiofsd", nil },
			StatProgram: func(string) (sandboxvm.ProgramFacts, error) {
				return sandboxvm.ProgramFacts{Regular: true, OwnerOK: true, Perm: 0o755}, nil
			},
			VMMVersion: func(string) (string, error) { return "cloud-hypervisor v54.0", nil },
			ImageSet:   func() sandboxvm.ImageSetFacts { return vmImageSetFacts(r, cfg) },
		}
		return env
	}
	t.Cleanup(func() { vmProbeEnvFn = prevProbe })

	// A source repository and the runtime.
	src := filepath.Join(obs, "src")
	_ = os.MkdirAll(src, 0o700)
	git := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e", "GIT_CONFIG_NOSYSTEM=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git(src, "init", "-q")
	_ = os.WriteFile(filepath.Join(src, "a.txt"), []byte("one\n"), 0o600)
	git(src, "add", "a.txt")
	git(src, "commit", "-qm", "one")
	cfg := vmTestConfig(t, true, "cloud-hypervisor")
	cfg.Observer.DBPath = filepath.Join(obs, "observer.db")
	exe, _ := os.Executable()
	rt, err := newSandboxRuntime(cfg.Terminal.Sandbox, nil, obs, exe, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt.applyDaemonConfig(cfg)
	d, ok := rt.drivers[sandboxbackend.BackendCloudHypervisor].(*vmDriver)
	if !ok {
		t.Fatal("the driver is not active")
	}
	if p := d.probe(context.Background()); p.Verdict != sandboxvm.VerdictAvailable {
		t.Fatalf("probe %+v", p)
	}

	// Launch: Create (clone-local), Attach (the plan and the argv).
	created, err := d.Create(context.Background(), termsvc.PrepareRequest{Tool: termsvc.ShellTool, ProjectRoot: src, WorkspaceSource: string(workspace.SourceCloneLocal)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(created.Note, "backend=cloud-hypervisor (beta)") || created.Isolation.Class != "hw_vm" {
		t.Fatalf("created %+v", created)
	}
	att, err := d.Attach(context.Background(), created)
	if err != nil {
		t.Fatal(err)
	}
	if len(att.WrapArgv) < 5 || att.WrapArgv[1] != vmHostVerb || att.WrapArgv[len(att.WrapArgv)-1] != vmInnerMarker {
		t.Fatalf("wrap %v", att.WrapArgv)
	}
	planPath := att.WrapArgv[3]
	var plan vmPlanFile
	if err := readMacPlan(planPath, &plan); err != nil {
		t.Fatal(err)
	}
	if plan.VM.VerityRootHash != strings.Repeat("9", 64) || plan.Return == nil || plan.Guest.Workdir != created.Run.Dir {
		t.Fatalf("plan %+v", plan)
	}
	body, _ := sandboxvm.CreateBody(plan.VM)
	if strings.Contains(string(body), `"net"`) {
		t.Fatalf("the boot plan names a network device: %s", body)
	}

	// The run: the host helper over the fake VMM, the guest stand-in commits
	// in its copy and answers the terminal.
	r := newVMRig(t)
	r.plan = plan
	r.h.SockDir = plan.Dirs.SocketDir
	r.h.RelayRun = plan.VM.RunID
	r.h.ObserverDir = obs
	r.returnGit = runReturnGit
	scans := recordScan(t)
	var commit string
	r.run = func(g *relaymux.Guest, a relayStdioArgs) int {
		line, _ := bufio.NewReader(g.PTY()).ReadString('\n')
		_, _ = io.WriteString(g.PTY(), "box says "+line)
		_ = os.WriteFile(filepath.Join(created.Run.Dir, "b.txt"), []byte("two\n"), 0o600)
		git(created.Run.Dir, "add", "b.txt")
		git(created.Run.Dir, "commit", "-qm", "two")
		commit = git(created.Run.Dir, "rev-parse", "HEAD")
		return 0
	}
	done := make(chan int, 1)
	args := append(append([]string(nil), att.WrapArgv[2:]...), "/bin/sh")
	go func() { done <- vmHostMain(args, r.env()) }()
	_, _ = io.WriteString(r.termIn, "hello\n")
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d: %s", code, r.termOut.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("the run did not end: %s", r.termOut.String())
	}
	out := r.termOut.String()
	ref := workspace.ReturnRefPrefix + created.Run.ID
	if !strings.Contains(out, "box says hello") || !strings.Contains(out, ref) {
		t.Fatalf("terminal %q", out)
	}
	if len(*scans) != 1 || (*scans)[0].Commit != commit || git(src, "rev-parse", ref) != commit {
		t.Fatalf("scans %+v", *scans)
	}
	if _, err := os.Stat(plan.VM.StateDir); !os.IsNotExist(err) {
		t.Fatalf("the state dir stays: %v", err)
	}
	if _, err := os.Stat(planPath); !os.IsNotExist(err) {
		t.Fatalf("the plan file stays: %v", err)
	}

	// The sweep: a crashed run's leftovers go at the next daemon's sweep.
	crashed := vmWriteRunDir(t, obs, "run-crashed", nil)
	res, err := vmSweepRuns(obs, vmSweepEnv{facts: vmProcFacts, kill: func(int) error { return nil }, relayLive: func(string) bool { return false }, held: vmLockHeld})
	if err != nil || strings.Join(res.Removed, ",") != "run-crashed" {
		t.Fatalf("sweep %+v %v", res, err)
	}
	if _, err := os.Stat(crashed); !os.IsNotExist(err) {
		t.Fatalf("the crashed run's dir stays: %v", err)
	}
}
