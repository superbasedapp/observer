//go:build linux && !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxvm"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_vm_diskimage_linux_test.go covers D7 of the microVM
// row's first live run (2026-10-24): a disk_image run still planned the
// virtio-fs workspace share in the guest spec (no such share exists, so the
// guest mount gave EINVAL and the agent never started), and once that was
// patched the return failed: "git could not list the copy's effective
// config (... Unable to read current working directory)". The host helper
// runs with the copy dir as its working directory; the read-back renamed
// that dir aside and removed it, so every return-step git it started
// inherited a deleted cwd.

// TestVMDiskImagePlanSharesNoWorkspace (D7): a disk_image launch plans the
// workspace as the guest's disk only: no workspace share for virtiofsd and
// no virtio-fs mount in the guest spec.
func TestVMDiskImagePlanSharesNoWorkspace(t *testing.T) {
	prev := vmDiskTools
	vmDiskTools = func() (vmDiskProgs, error) {
		return vmDiskProgs{mkfs: "/usr/sbin/mkfs.ext4", debugfs: "/usr/sbin/debugfs", bwrap: "/usr/bin/bwrap"}, nil
	}
	t.Cleanup(func() { vmDiskTools = prev })
	_, d, obs := vmFixDriver(t, sandboxvm.DeliveryDiskImage)
	src := vmFixRepo(t, obs)
	ctx := context.Background()
	created, err := d.Create(ctx, termsvc.PrepareRequest{Tool: termsvc.ShellTool, ProjectRoot: src, WorkspaceSource: string(workspace.SourceCloneLocal)})
	if err != nil {
		t.Fatal(err)
	}
	att, err := d.Attach(ctx, created)
	if err != nil {
		t.Fatal(err)
	}
	var plan vmPlanFile
	if err := readMacPlan(att.WrapArgv[3], &plan); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(att.WrapArgv[3])
	if len(plan.Guest.Mounts) != 0 || len(plan.Shares) != 0 || len(plan.Guest.ReadOnly) != 0 {
		t.Fatalf("a disk_image run plans a workspace share: mounts %+v shares %+v ro %v", plan.Guest.Mounts, plan.Shares, plan.Guest.ReadOnly)
	}
	if len(plan.Guest.Disks) != 1 || plan.Guest.Disks[0].Target != created.Run.Dir || len(plan.DiskImages) != 1 {
		t.Fatalf("disks %+v images %+v", plan.Guest.Disks, plan.DiskImages)
	}
	for _, s := range plan.VM.Shares {
		if s.Tag == sandboxvm.WorkspaceTag {
			t.Fatalf("the VM plan shares %s", s.Tag)
		}
	}
	if err := plan.Guest.Validate(); err != nil {
		t.Fatal(err)
	}
}

// TestVMDiskImageReadBackKeepsTheWorkingDir (D7): the helper's working
// directory is the copy dir; after the read-back replaces that dir, the
// helper's working directory is the new copy (so the return step's git,
// which inherits it, can read it), never a removed one.
func TestVMDiskImageReadBackKeepsTheWorkingDir(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "repo")
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(filepath.Join(src, "sub"))
	vmFixExt4Image(t, filepath.Join(root, "ws.img"), false)
	plan := vmPlanFile{
		VM:         sandboxvm.Plan{Disks: []sandboxvm.Disk{{Name: sandboxvm.WorkspaceTag, Path: filepath.Join(root, "ws.img")}}},
		DiskImages: []vmDiskImage{{Name: sandboxvm.WorkspaceTag, Source: src, Target: src}},
		Debugfs:    "/usr/sbin/debugfs", DumpBwrap: "/usr/bin/bwrap",
	}
	env := vmHostEnv{tool: func(_ context.Context, argv []string) error {
		// The dump: the fresh sibling dir gets the image's tree.
		fresh := src + ".vm-return"
		if !strings.Contains(strings.Join(argv, " "), fresh) {
			t.Errorf("the dump does not name %s: %v", fresh, argv)
		}
		_ = os.MkdirAll(filepath.Join(fresh, "sub"), 0o700)
		return os.WriteFile(filepath.Join(fresh, "sub", "from-box.txt"), []byte("box\n"), 0o600)
	}}
	if err := vmDumpDiskImages(plan, env); err != nil {
		t.Fatal(err)
	}
	wd, err := os.Getwd()
	if err != nil || wd != filepath.Join(src, "sub") {
		t.Fatalf("the working dir after the read-back: %q %v", wd, err)
	}
	if _, err := os.Stat("from-box.txt"); err != nil {
		t.Fatalf("the working dir is not the new copy: %v", err)
	}
}
