package config

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// vmTestPath is an absolute path on the OS the test runs on, built from its
// parts WITHOUT cleaning them (so a ".." part stays). The rules check
// filepath.IsAbs and filepath.Clean, and a Unix path such as
// /usr/local/bin/cloud-hypervisor is not absolute on Windows, so the
// expectations are built per OS (F-023).
func vmTestPath(parts ...string) string {
	root := string(filepath.Separator)
	if runtime.GOOS == "windows" {
		root = `C:\`
	}
	return root + strings.Join(parts, string(filepath.Separator))
}

// TestTerminalSandboxVMDefaults (lane SBX-P4): the [terminal.sandbox.vm]
// defaults are the plan's (section 10.1): cloud-hypervisor, the newest
// verified set, 2 vCPUs, 4096 MiB, no install cache, programs from PATH.
func TestTerminalSandboxVMDefaults(t *testing.T) {
	got := Default().Terminal.Sandbox.VM
	want := TerminalSandboxVMConfig{VMM: "cloud-hypervisor", VCPUs: 2, MemoryMB: 4096, WorkspaceDelivery: "virtiofs"}
	if got != want {
		t.Fatalf("defaults %+v, want %+v", got, want)
	}
	if err := validateTerminalSandboxVM(got); err != nil {
		t.Fatalf("defaults refused: %v", err)
	}
}

// TestValidateTerminalSandboxVM is one case per rule.
func TestValidateTerminalSandboxVM(t *testing.T) {
	base := Default().Terminal.Sandbox.VM
	cases := []struct {
		name string
		mut  func(*TerminalSandboxVMConfig)
		want string
	}{
		{"another vmm", func(c *TerminalSandboxVMConfig) { c.VMM = "firecracker" }, "only \"cloud-hypervisor\""},
		{"image set as a path", func(c *TerminalSandboxVMConfig) { c.ImageSet = "/tmp/rootfs" }, "never a path"},
		{"image set not a version", func(c *TerminalSandboxVMConfig) { c.ImageSet = "latest" }, "never a path"},
		{"another delivery", func(c *TerminalSandboxVMConfig) { c.WorkspaceDelivery = "nfs" }, "workspace_delivery"},
		{"vcpus high", func(c *TerminalSandboxVMConfig) { c.VCPUs = 65 }, "vcpus"},
		{"memory low", func(c *TerminalSandboxVMConfig) { c.MemoryMB = 256 }, "memory_mb"},
		{"relative vmm path", func(c *TerminalSandboxVMConfig) { c.CloudHypervisorPath = "bin/cloud-hypervisor" }, "cloud_hypervisor_path"},
		{"unclean virtiofsd path", func(c *TerminalSandboxVMConfig) {
			c.VirtiofsdPath = vmTestPath("usr", "..", "usr", "libexec", "virtiofsd")
		}, "virtiofsd_path"},
		{"good", func(c *TerminalSandboxVMConfig) {
			c.ImageSet, c.VCPUs, c.MemoryMB, c.InstallCache = "1.2.3", 4, 8192, true
			c.CloudHypervisorPath = vmTestPath("usr", "local", "bin", "cloud-hypervisor")
			c.VirtiofsdPath = vmTestPath("usr", "libexec", "virtiofsd")
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mut(&c)
			err := validateTerminalSandboxVM(c)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
}

// TestTerminalSandboxVMHasASectionRow: the block is owned by its driver's
// component, so a bad block of an inactive driver is set aside.
func TestTerminalSandboxVMHasASectionRow(t *testing.T) {
	for _, s := range componentSections {
		if s.section == "terminal.sandbox.vm" {
			if s.component != "terminals.sandbox.vm" {
				t.Fatalf("owned by %s", s.component)
			}
			return
		}
	}
	t.Fatal("no component section row for terminal.sandbox.vm")
}
