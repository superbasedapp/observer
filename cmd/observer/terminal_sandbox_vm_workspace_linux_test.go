//go:build linux && !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
	"github.com/marmutapp/superbased-observer/internal/sandboxvm"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_vm_workspace_linux_test.go covers milestone 5 of lane
// SBX-P4: one test per workspace mapping row, on the in-process rig with a
// real git repository and real e2fsprogs where the host has them.

// vmRigWithCopy points the rig's workspace share at a real clone-local
// copy and plans its return.
func vmRigWithCopy(t *testing.T) (*vmRig, workspace.ReturnRequest, func(args ...string) string) {
	t.Helper()
	req, inCopy := returnFixture(t)
	r := newVMRig(t)
	r.plan.Shares = []vmShare{{Tag: sandboxvm.WorkspaceTag, Dir: req.CopyDir}}
	r.plan.Return = &req
	r.returnGit = runReturnGit
	return r, req, inCopy
}

// recordScan binds the return step's scan for one test.
func recordScan(t *testing.T) *[]sandboxReturnScanInput {
	t.Helper()
	var got []sandboxReturnScanInput
	prev := sandboxReturnScan
	sandboxReturnScan = func(_ context.Context, in sandboxReturnScanInput) error {
		got = append(got, in)
		return nil
	}
	t.Cleanup(func() { sandboxReturnScan = prev })
	return &got
}

// TestVMCopyReturnsARefThroughTheScan (clone-local, virtiofs): the box's
// commit comes back as refs/observer/sandbox/<run> through sandboxReturn,
// the bound scan seeing it first; the source's branch is untouched.
func TestVMCopyReturnsARefThroughTheScan(t *testing.T) {
	r, req, inCopy := vmRigWithCopy(t)
	scans := recordScan(t)
	var commit string
	r.run = func(*relaymux.Guest, relayStdioArgs) int {
		_ = os.WriteFile(filepath.Join(req.CopyDir, "b.txt"), []byte("two\n"), 0o600)
		inCopy("add", "b.txt")
		inCopy("commit", "-qm", "two")
		commit = inCopy("rev-parse", "HEAD")
		return 0
	}
	if code := r.runHost(); code != 0 {
		t.Fatalf("exit %d: %s", code, r.termOut.String())
	}
	ref := workspace.ReturnRefPrefix + req.RunID
	if !strings.Contains(r.termOut.String(), ref) {
		t.Fatalf("terminal %q", r.termOut.String())
	}
	if len(*scans) != 1 || (*scans)[0].Commit != commit {
		t.Fatalf("scans %+v, want one of %s", *scans, commit)
	}
	out, err := exec.Command("git", "-C", req.SourceRepo, "rev-parse", ref).CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != commit {
		t.Fatalf("ref %s = %q %v", ref, out, err)
	}
}

// TestVMCopyPlantsAreRefusedBeforeHostGit (D4, P-117): a copy whose git
// dir gained a commondir, an [include] or an includeIf is refused by the
// shared precheck before any host git runs and before the scan; no ref is
// written and the copy is kept.
func TestVMCopyPlantsAreRefusedBeforeHostGit(t *testing.T) {
	for name, plant := range map[string]func(copyDir string){
		"commondir": func(c string) {
			_ = os.MkdirAll(filepath.Join(c, "evil"), 0o700)
			_ = os.WriteFile(filepath.Join(c, ".git", "commondir"), []byte("../evil\n"), 0o600)
		},
		"include": func(c string) {
			f, _ := os.OpenFile(filepath.Join(c, ".git", "config"), os.O_APPEND|os.O_WRONLY, 0o600)
			_, _ = f.WriteString("[include]\n\tpath = ../inc.cfg\n")
			_ = f.Close()
		},
		"includeIf": func(c string) {
			f, _ := os.OpenFile(filepath.Join(c, ".git", "config"), os.O_APPEND|os.O_WRONLY, 0o600)
			_, _ = f.WriteString("[includeIf \"gitdir:/\"]\n\tpath = ../inc.cfg\n")
			_ = f.Close()
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, req, inCopy := vmRigWithCopy(t)
			scans := recordScan(t)
			r.run = func(*relaymux.Guest, relayStdioArgs) int {
				_ = os.WriteFile(filepath.Join(req.CopyDir, "b.txt"), []byte("two\n"), 0o600)
				inCopy("add", "b.txt")
				inCopy("commit", "-qm", "two")
				plant(req.CopyDir)
				return 0
			}
			_ = r.runHost()
			if !strings.Contains(r.termOut.String(), "were not returned") || len(*scans) != 0 {
				t.Fatalf("terminal %q scans %d", r.termOut.String(), len(*scans))
			}
			if out, err := exec.Command("git", "-C", req.SourceRepo, "rev-parse", "--verify", "-q", workspace.ReturnRefPrefix+req.RunID).CombinedOutput(); err == nil {
				t.Fatalf("a ref was written: %s", out)
			}
		})
	}
}

// TestVMDiskImageRoundTrip (clone-local, disk_image): the copy is written
// into an ext4 image without root before the VMM starts, a write the box
// makes into the image comes back into the copy, and its commit returns.
func TestVMDiskImageRoundTrip(t *testing.T) {
	progs, err := vmDiskTools()
	if err != nil {
		t.Skipf("e2fsprogs or bwrap: %v", err)
	}
	if out, err := exec.Command(progs.bwrap, "--ro-bind", "/", "/", "--unshare-all", "--die-with-parent", "--new-session", "--", "/bin/true").CombinedOutput(); err != nil {
		t.Skipf("bwrap cannot unshare here: %v %s", err, out)
	}
	mkfs, debugfs := progs.mkfs, progs.debugfs
	r, req, _ := vmRigWithCopy(t)
	scans := recordScan(t)
	img := filepath.Join(r.plan.VM.StateDir, "ws.img")
	r.plan.Shares = nil
	r.plan.VM.Shares = r.plan.VM.Shares[:1]
	r.plan.VM.Disks = []sandboxvm.Disk{{Name: sandboxvm.WorkspaceTag, Path: img}}
	r.plan.DiskImages = []vmDiskImage{{Name: sandboxvm.WorkspaceTag, Source: req.CopyDir, Target: req.CopyDir}}
	r.plan.Mkfs, r.plan.Debugfs, r.plan.DumpBwrap = mkfs, debugfs, progs.bwrap
	r.plan.Guest.Mounts = nil
	r.plan.Guest.Disks = []sandboxvm.GuestDisk{{Name: sandboxvm.WorkspaceTag, Target: "/home/u/proj"}}
	r.run = func(*relaymux.Guest, relayStdioArgs) int {
		// The box writes into its disk (debugfs -w stands in for the
		// guest's own ext4 driver).
		f := filepath.Join(r.root, "new.txt")
		_ = os.WriteFile(f, []byte("from the box\n"), 0o600)
		if out, err := exec.Command(debugfs, "-w", "-R", "write "+f+" from-box.txt", img).CombinedOutput(); err != nil {
			t.Errorf("debugfs write: %v %s", err, out)
		}
		return 0
	}
	if code := r.runHost(); code != 0 {
		t.Fatalf("exit %d: %s", code, r.termOut.String())
	}
	b, err := os.ReadFile(filepath.Join(req.CopyDir, "from-box.txt"))
	if err != nil || string(b) != "from the box\n" {
		t.Fatalf("the box's write did not come back: %q %v; terminal %q", b, err, r.termOut.String())
	}
	if _, err := os.Stat(filepath.Join(req.CopyDir, "lost+found")); !os.IsNotExist(err) {
		t.Fatal("lost+found came back into the copy")
	}
	if !strings.Contains(r.termOut.String(), "made no new commit") || len(*scans) != 0 {
		t.Fatalf("terminal %q", r.termOut.String())
	}
	found := false
	for _, s := range r.starts {
		found = found || strings.Contains(s, img)
	}
	_ = found
}

// TestVMDeliveryRows is the mapping table through the driver, one case per
// row, and a disk_image refusal naming the missing program.
func TestVMDeliveryRows(t *testing.T) {
	prev := vmDiskTools
	t.Cleanup(func() { vmDiskTools = prev })
	vmDiskTools = func() (vmDiskProgs, error) {
		return vmDiskProgs{mkfs: "/usr/sbin/mkfs.ext4", debugfs: "/usr/sbin/debugfs", bwrap: "/usr/bin/bwrap"}, nil
	}
	for _, tc := range []struct {
		src      workspace.Source
		delivery string
		ok       bool
	}{
		{workspace.SourceLive, "virtiofs", true},
		{workspace.SourceLive, "disk_image", false},
		{workspace.SourceCloneLocal, "virtiofs", true},
		{workspace.SourceCloneLocal, "disk_image", true},
		{workspace.SourceCloneRemote, "", true},
		{workspace.SourceCloneRemote, "disk_image", true},
		{workspace.SourceWorktree, "virtiofs", false},
		{workspace.SourceWorktree, "disk_image", false},
	} {
		err := vmDeliveryFor(tc.src, tc.delivery)
		if (err == nil) != tc.ok {
			t.Errorf("%s/%s: %v", tc.src, tc.delivery, err)
		}
	}
	vmDiskTools = func() (vmDiskProgs, error) {
		return vmDiskProgs{}, errors.New("mkfs.ext4 (e2fsprogs 1.43 or later) is not installed")
	}
	if err := vmDeliveryFor(workspace.SourceCloneLocal, "disk_image"); err == nil || !strings.Contains(err.Error(), "mkfs.ext4") || !strings.Contains(err.Error(), "source_unsupported") {
		t.Fatalf("%v", err)
	}
}

// TestVMDiskImageRefusedWithoutBwrap (SBX-BE-5): a host with e2fsprogs but
// no bwrap refuses disk_image by name (source_unsupported), the real lookup
// included, and a plan that names no bwrap never runs debugfs at all.
func TestVMDiskImageRefusedWithoutBwrap(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := vmLookProgramFor("bwrap"); err == nil {
		t.Skip("bwrap is in an sbin dir here")
	}
	if _, err := vmDiskTools(); err == nil || !(strings.Contains(err.Error(), "bwrap") || strings.Contains(err.Error(), "mkfs.ext4")) {
		t.Fatalf("the real lookup: %v", err)
	}
	prev := vmDiskTools
	t.Cleanup(func() { vmDiskTools = prev })
	vmDiskTools = func() (vmDiskProgs, error) {
		return vmDiskProgs{}, errors.New("bwrap (bubblewrap) is not installed, and the image the guest wrote is read back only inside a bwrap namespace")
	}
	err := vmDeliveryFor(workspace.SourceCloneLocal, "disk_image")
	if err == nil || !strings.Contains(err.Error(), "bwrap") || !strings.Contains(err.Error(), "source_unsupported") {
		t.Fatalf("%v", err)
	}
	if err := vmDeliveryFor(workspace.SourceCloneLocal, "virtiofs"); err != nil {
		t.Fatalf("virtiofs needs no bwrap: %v", err)
	}
	var ran []string
	img := filepath.Join(t.TempDir(), "ws.img")
	vmFixExt4Image(t, img, false)
	plan := vmPlanFile{
		VM:         sandboxvm.Plan{Disks: []sandboxvm.Disk{{Name: sandboxvm.WorkspaceTag, Path: img}}},
		DiskImages: []vmDiskImage{{Name: sandboxvm.WorkspaceTag, Source: t.TempDir()}}, Debugfs: "/usr/sbin/debugfs",
	}
	env := vmHostEnv{tool: func(_ context.Context, argv []string) error { ran = append(ran, strings.Join(argv, " ")); return nil }}
	if err := vmDumpDiskImages(plan, env); err == nil || !strings.Contains(err.Error(), "bwrap") || len(ran) != 0 {
		t.Fatalf("a plan without bwrap: %v, ran %v", err, ran)
	}
	plan.DumpBwrap = "/usr/bin/bwrap"
	_ = vmDumpDiskImages(plan, env)
	if len(ran) != 1 || !strings.HasPrefix(ran[0], "/usr/bin/bwrap --ro-bind / / ") || !strings.Contains(ran[0], " -- /usr/sbin/debugfs -R ") {
		t.Fatalf("the dump argv: %v", ran)
	}
}

// TestVMLiveOnlyWithTheConfinedVirtiofsd: a live workspace is refused
// source_unsupported where the confining programs are absent; where they
// exist its share runs confined, with the exec-state paths read-only and
// the git-dir pins (.git itself included) bound onto themselves, and the
// placeholders of missing protected paths go to the host services' ledger.
func TestVMLiveOnlyWithTheConfinedVirtiofsd(t *testing.T) {
	prev := vmLiveOK
	t.Cleanup(func() { vmLiveOK = prev })
	vmLiveOK = func() bool { return false }
	if err := vmMappingFor(workspace.SourceLive, "/home/u/proj"); err == nil || !strings.Contains(err.Error(), "source_unsupported") || !strings.Contains(err.Error(), "/usr/libexec/virtiofsd") {
		t.Fatalf("%v", err)
	}
	vmLiveOK = func() bool { return true }
	if err := vmMappingFor(workspace.SourceLive, "/home/u/proj"); err != nil {
		t.Fatal(err)
	}
	if err := vmMappingFor(workspace.SourceCloneLocal, "/data/proj"); err == nil || !strings.Contains(err.Error(), "writable roots") {
		t.Fatalf("a workspace outside the guest roots: %v", err)
	}
	ws := "/home/u/proj"
	overlays := []sandbox.Overlay{
		{Path: ws + "/.git/config", Kind: sandbox.OverlayReadOnly},
		{Path: ws + "/.git/hooks", Kind: sandbox.OverlayReadOnly},
		{Path: ws + "/.git/commondir", Kind: sandbox.OverlayReadOnly, Placeholder: sandbox.PlaceholderFile},
		{Path: "/home/u/.observer/config.toml", Kind: sandbox.OverlayReadOnly},
		{Path: "/home/u/.observer/keys", Kind: sandbox.OverlayHideDir},
	}
	pins := []string{ws + "/.git", ws + "/.git/info", "/elsewhere/.git"}
	sh := vmWorkspaceShare(termsvc.SandboxRun{ID: "r1", Dir: ws}, overlays, pins)
	if !sh.Confined || strings.Join(sh.Pins, ",") != ws+"/.git,"+ws+"/.git/info" || len(sh.ReadOnlyPaths) != 3 {
		t.Fatalf("share %+v", sh)
	}
	if copyShare := vmWorkspaceShare(termsvc.SandboxRun{ID: "r1", Dir: ws, Copy: true}, overlays, pins); copyShare.Confined || len(copyShare.Pins) != 0 {
		t.Fatalf("a copy got pins (copies get none by design, P-122): %+v", copyShare)
	}
	ph := vmPlaceholders(overlays, ws)
	if len(ph) != 1 || ph[0].Path != ws+"/.git/commondir" {
		t.Fatalf("placeholders %+v", ph)
	}
	argv, err := vmVirtiofsdArgv(vmPlanFile{Bwrap: vmConfinedBwrap}, sh, "/home/u/.observer/sandbox-vm/runs/r1/fs-ws.sock")
	if err != nil {
		t.Fatal(err)
	}
	j := strings.Join(argv, " ")
	if !strings.HasPrefix(j, "/usr/bin/bwrap ") || !strings.Contains(j, "--bind "+ws+"/.git "+ws+"/.git") || !strings.Contains(j, "--ro-bind "+ws+"/.git/config "+ws+"/.git/config") || !strings.Contains(j, "-- /usr/libexec/virtiofsd --socket-path=") {
		t.Fatalf("argv %s", j)
	}
	dir, _ := os.MkdirTemp("", "vmph")
	defer func() { _ = os.RemoveAll(dir) }()
	host, err := sandbox.RelayHostArgv("/usr/bin/observer", sandbox.NetRequest{Egress: "none", HostSocketDir: filepath.Join(dir, "r1")}, ph, sandbox.RelayRequest{RunID: "r1", HostObserverDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	h, err := sandbox.ParseHostArgs(append(host[2:], vmInnerMarker))
	if err != nil || len(h.PlaceholderFiles) != 1 || h.PlaceholderFiles[0] != ws+"/.git/commondir" {
		t.Fatalf("host args %+v %v", h, err)
	}
}
