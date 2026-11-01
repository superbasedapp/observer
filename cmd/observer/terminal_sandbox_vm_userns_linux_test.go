//go:build linux && !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxvm"
)

// terminal_sandbox_vm_userns_linux_test.go covers D5 of the microVM row's
// first live run (2026-10-24): the guest init's N13 self-test asked Go for
// the agent's uid together with CLONE_NEWUSER, and Go applies a Credential
// in the child AFTER the clone, inside the new user namespace, where no id
// is mapped yet, so setgroups and setuid fail and the start is EPERM
// ("fork/exec /run/observer-boot/observer-guest: operation not permitted")
// on every kernel. Every set declaring guest_userns was refused.

// vmUsernsAllowedHere reports whether this host lets this user clone a user
// namespace with its own ids mapped to root (unshare -Ur).
func vmUsernsAllowedHere() error {
	c := exec.Command("/bin/true")
	c.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	return c.Run()
}

// TestVMUsernsSelfTestPassesForAnUnprivilegedUser (D5): the self-test, run
// from the guest observer (this test binary standing in) for the user's own
// ids, passes where an unprivileged user may clone a user namespace.
func TestVMUsernsSelfTestPassesForAnUnprivilegedUser(t *testing.T) {
	if err := vmUsernsAllowedHere(); err != nil {
		t.Skipf("this host refuses an unprivileged user namespace: %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	boot := t.TempDir()
	if err := os.Symlink(exe, filepath.Join(boot, sandboxvm.GuestBinaryName)); err != nil {
		t.Fatal(err)
	}
	if err := vmUsernsSelfTest(boot, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("the self-test: %v", err)
	}
}

// TestVMUsernsStartsNeverCombineIDsAndAClone (D5): the drop step sets ids
// and no clone flag, and drops nothing for the ids it already runs as; the
// leaf's start clones the namespace with the ids mapped to root.
func TestVMUsernsStartsNeverCombineIDsAndAClone(t *testing.T) {
	a := vmUsernsDropAttr(os.Geteuid()+1, os.Getegid()+1)
	if a.Credential == nil || a.Cloneflags != 0 {
		t.Fatalf("the drop: %+v", a)
	}
	if a := vmUsernsDropAttr(os.Geteuid(), os.Getegid()); a.Credential != nil {
		t.Fatal("a drop to the ids it already runs as")
	}
	c := vmUsernsCloneAttr(1001, 1002)
	if c.Credential != nil || c.Cloneflags != syscall.CLONE_NEWUSER || len(c.UidMappings) != 1 || c.UidMappings[0].ContainerID != 0 || c.UidMappings[0].HostID != 1001 || c.GidMappings[0].HostID != 1002 {
		t.Fatalf("the clone: %+v", c)
	}
}
