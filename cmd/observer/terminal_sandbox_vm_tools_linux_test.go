//go:build linux && !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/ed25519"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxvm"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_vm_tools_linux_test.go covers D2 of the microVM row's
// first live run (2026-10-24): no path reached the row. The dashboard
// answered 400 "tool shell cannot be sandboxed" (the sandbox tool map never
// listed the plain shell), and the CLI path refused every tool
// (tool_unavailable_in_image) even when the launch names a tool binary the
// guest can run from the shared workspace.

// vmFixDriver is the real driver over a healthy stand-in KVM host with a
// verified image set imported under a test key, in an observer dir under
// /tmp (a writable guest root).
func vmFixDriver(t *testing.T, delivery string) (*sandboxRuntime, *vmDriver, string) {
	t.Helper()
	obs, err := os.MkdirTemp("", "vmfix")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(obs) })
	_ = os.Chmod(obs, 0o700)
	pub, priv := vmTestKey(t)
	prevKeys, prevVersion, prevIDs, prevProbe := sandboxContentVendorKeys, version, vmHostIDs, vmProbeEnvFn
	sandboxContentVendorKeys = func() []ed25519.PublicKey { return []ed25519.PublicKey{pub} }
	version = "1.40.0"
	vmHostIDs = func() (int, int) { return 1000, 1000 }
	t.Cleanup(func() {
		sandboxContentVendorKeys, version, vmHostIDs, vmProbeEnvFn = prevKeys, prevVersion, prevIDs, prevProbe
	})
	if _, err := sandboxContentImport(vmContentStore(obs), []ed25519.PublicKey{pub}, writeVMTestSet(t, priv, 1, "1.0.0", "1.40.0").dir); err != nil {
		t.Fatal(err)
	}
	vmProbeEnvFn = func(r *sandboxRuntime, cfg config.TerminalSandboxVMConfig) sandboxvm.ProbeEnv {
		return sandboxvm.ProbeEnv{
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
	}
	cfg := vmTestConfig(t, true, "cloud-hypervisor")
	cfg.Observer.DBPath = filepath.Join(obs, "observer.db")
	cfg.Terminal.Sandbox.VM.WorkspaceDelivery = delivery
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
	return rt, d, obs
}

// vmFixRepo is a git repository with one commit and an executable stand-in
// agent script, under dir.
func vmFixRepo(t *testing.T, dir string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}} {
		if out, err := exec.Command("git", append([]string{"-C", src}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	if err := os.WriteFile(filepath.Join(src, "agent.sh"), []byte("#!/bin/sh\necho stand-in\n"), 0o700); err != nil { //nolint:gosec // G306: an executable stand-in
		t.Fatal(err)
	}
	cmd := exec.Command("git", "-C", src, "add", "agent.sh")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v %s", err, out)
	}
	cmd = exec.Command("git", "-C", src, "commit", "-qm", "one")
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e", "GIT_CONFIG_NOSYSTEM=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v %s", err, out)
	}
	return src
}

// TestVMRowListsThePlainShellForTheDashboard (D2): with the microVM driver
// active, the sandbox tool map the dashboard validates a launch against
// lists the plain shell as available (it answered 400 "tool shell cannot be
// sandboxed" before); a runtime whose drivers host no plain shell does not
// list it.
func TestVMRowListsThePlainShellForTheDashboard(t *testing.T) {
	rt, _, _ := vmFixDriver(t, "")
	if a, ok := rt.tools()[termsvc.ShellTool]; !ok || !a.Available {
		t.Fatalf("the shell entry: %+v %v", a, ok)
	}
	if a := rt.ProbeSandbox(context.Background()).Tools[termsvc.ShellTool]; !a.Available {
		t.Fatalf("the probe's tool map: %+v", a)
	}
	plain := macTestRuntime(t, vmTestConfig(t, false, "bwrap"))
	if a, ok := plain.tools()[termsvc.ShellTool]; ok {
		t.Fatalf("a runtime with no shell-hosting driver lists the shell: %+v", a)
	}
}

// TestVMShellIsRefusedByABackendThatHostsNone (D2): a plain shell that
// resolves to a backend which runs only named tools (bwrap here) is refused
// by name before any workspace is made.
func TestVMShellIsRefusedByABackendThatHostsNone(t *testing.T) {
	rt, _, obs := vmFixDriver(t, "")
	src := vmFixRepo(t, obs)
	_, err := rt.Create(context.Background(), termsvc.PrepareRequest{
		Tool: termsvc.ShellTool, ProjectRoot: src, WorkspaceSource: string(workspace.SourceCloneLocal), Backend: sandboxbackend.BackendBwrap,
	})
	if err == nil || !strings.Contains(err.Error(), "plain shell") || !strings.Contains(err.Error(), sandboxbackend.BackendBwrap) {
		t.Fatalf("%v", err)
	}
}

// TestVMToolLaunchRunsItsBinaryFromTheSharedWorkspace (D2): the CLI's
// `observer claude --claude-path <script> --observer-sandbox
// cloud-hypervisor` reaches the row when the named binary lies inside the
// workspace the VM shares at the same path (absolute or relative to the
// project); a launch naming no binary, or one outside the share (the host's
// own tree, or the source of a copy), is refused tool_unavailable_in_image
// naming why and the flag.
func TestVMToolLaunchRunsItsBinaryFromTheSharedWorkspace(t *testing.T) {
	prev := vmLiveOK
	vmLiveOK = func() bool { return true }
	t.Cleanup(func() { vmLiveOK = prev })
	rt, d, obs := vmFixDriver(t, "")
	src := vmFixRepo(t, obs)
	ctx := context.Background()
	for name, args := range map[string][]string{
		"absolute": {"--claude-path", filepath.Join(src, "agent.sh")},
		"relative": {"--claude-path=./agent.sh", "--resume"},
	} {
		created, err := d.Create(ctx, termsvc.PrepareRequest{Tool: "claude-code", ProjectRoot: src, WorkspaceSource: string(workspace.SourceLive), ToolArgs: args})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_, _ = d.Destroy(ctx, created.Run)
	}
	for name, tc := range map[string]struct {
		source string
		args   []string
		want   string
	}{
		"no binary named":   {string(workspace.SourceLive), nil, "--claude-path"},
		"the host's binary": {string(workspace.SourceLive), []string{"--claude-path", "/usr/bin/true"}, "not inside the workspace"},
		"missing file":      {string(workspace.SourceLive), []string{"--claude-path", filepath.Join(src, "nope.sh")}, "nope.sh"},
		"a copy's source":   {string(workspace.SourceCloneLocal), []string{"--claude-path", filepath.Join(src, "agent.sh")}, "not inside the workspace"},
	} {
		_, err := d.Create(ctx, termsvc.PrepareRequest{Tool: "claude-code", ProjectRoot: src, WorkspaceSource: tc.source, ToolArgs: tc.args})
		if err == nil || !strings.Contains(err.Error(), "tool_unavailable_in_image") || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A refused copy leaves no managed workspace behind.
	if ents, _ := os.ReadDir(rt.managedRoot); len(ents) != 0 {
		t.Fatalf("a refused launch left %d workspace(s)", len(ents))
	}
	// A plain shell still runs as before.
	created, err := d.Create(ctx, termsvc.PrepareRequest{Tool: termsvc.ShellTool, ProjectRoot: src, WorkspaceSource: string(workspace.SourceLive)})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = d.Destroy(ctx, created.Run)
}
