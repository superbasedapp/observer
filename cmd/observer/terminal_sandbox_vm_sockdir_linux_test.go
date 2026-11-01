//go:build linux && !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// terminal_sandbox_vm_sockdir_linux_test.go covers D3 and D8 of the microVM
// row's first live run (2026-10-24): the host services' per-run socket dir
// (/tmp/obsbx/<run>, holding relay.sock and launch.json with the run's box
// secret) was created with a bare Mkdir under a parent nothing created
// ("create socket dir: no such file or directory", exit 125), and after a
// SIGKILL of the helper and the daemon the start sweep left that dir behind.

// strictServices stands in startHostServices' own socket-dir step (a bare
// Mkdir that refuses a missing parent or an existing path), then the rig's
// fake services.
func strictServices(r *vmRig, called *bool) func(h sandbox.HostArgs) (func(), error) {
	return func(h sandbox.HostArgs) (func(), error) {
		*called = true
		if err := os.Mkdir(h.SockDir, 0o700); err != nil {
			return func() {}, fmt.Errorf("create socket dir: %w", err)
		}
		return r.fakeServices(h)
	}
}

// TestVMHostMakesTheSocketParentOwnerOnly (D3): a missing socket parent is
// created 0700 before the host services make the run's dir in it, so the
// run starts; a parent that exists open to others, or as a link, is refused
// before any service starts.
func TestVMHostMakesTheSocketParentOwnerOnly(t *testing.T) {
	r := newVMRig(t)
	parent := filepath.Join(r.root, "obsbx")
	r.h.SockDir = filepath.Join(parent, r.plan.VM.RunID)
	r.plan.Dirs = macRunDirs{SocketParent: parent, SocketDir: r.h.SockDir}
	var called bool
	env := r.env()
	env.services = strictServices(r, &called)
	if code := vmHostRun(r.plan, r.h, []string{"/home/u/.local/bin/observer", "claude"}, env); code != 0 {
		t.Fatalf("exit %d: %s", code, r.termOut.String())
	}
	fi, err := os.Lstat(parent)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("the socket parent: %v %v", fi, err)
	}

	for name, plant := range map[string]func(string){
		"open to others": func(p string) { _ = os.Mkdir(p, 0o755); _ = os.Chmod(p, 0o755) },
		"a link":         func(p string) { _ = os.Symlink(t.TempDir(), p) },
	} {
		t.Run(name, func(t *testing.T) {
			r := newVMRig(t)
			parent := filepath.Join(r.root, "obsbx")
			plant(parent)
			r.h.SockDir = filepath.Join(parent, r.plan.VM.RunID)
			r.plan.Dirs = macRunDirs{SocketParent: parent, SocketDir: r.h.SockDir}
			var called bool
			env := r.env()
			env.services = strictServices(r, &called)
			if code := vmHostRun(r.plan, r.h, []string{"/bin/true"}, env); code == 0 || called {
				t.Fatalf("exit %d, services started %v", code, called)
			}
		})
	}
}

// TestVMHostRefusesASocketParentOfAnotherUser (D3): a parent another user
// owns (root's own home here) is refused, never used.
func TestVMHostRefusesASocketParentOfAnotherUser(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns every candidate")
	}
	fi, err := os.Lstat("/root")
	if err != nil || !fi.IsDir() || ownedByMe(fi) {
		t.Skip("no foreign directory to stand in")
	}
	r := newVMRig(t)
	r.h.SockDir = filepath.Join("/root", r.plan.VM.RunID)
	r.plan.Dirs = macRunDirs{SocketParent: "/root", SocketDir: r.h.SockDir}
	var called bool
	env := r.env()
	env.services = strictServices(r, &called)
	if code := vmHostRun(r.plan, r.h, []string{"/bin/true"}, env); code == 0 || called {
		t.Fatalf("exit %d, services started %v", code, called)
	}
}

// TestVMSweepRemovesTheRunsHostSocketDir (D8): after a SIGKILL of the helper
// and the daemon, the start sweep removes the run's whole host socket dir
// under either socket parent the row uses (relay.sock and launch.json, which
// holds the box secret), with the run's state dir; another run's socket dir
// is kept. launch.json is written 0600.
func TestVMSweepRemovesTheRunsHostSocketDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	base, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatal(err)
	}
	obs := t.TempDir()
	var gone []string
	for i, parent := range []string{filepath.Join(base, "obsbx"), filepath.Join(base, "obsbx-"+strconv.Itoa(os.Getuid()))} {
		run := "run-gone-" + strconv.Itoa(i)
		_ = vmWriteRunDir(t, obs, run, nil)
		sock := filepath.Join(parent, run)
		if err := os.MkdirAll(sock, 0o700); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(parent, 0o700)
		rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: run})
		if err != nil {
			t.Fatal(err)
		}
		if err := sandboxrelayd.WriteBoxRecord(sock, rec); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(filepath.Join(sock, sandboxrelayd.BoxRecordName))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("launch.json: %v %v", fi, err)
		}
		_ = os.WriteFile(filepath.Join(sock, sandboxrelayd.RelaySocketName), nil, 0o600)
		gone = append(gone, sock)
	}
	other := filepath.Join(base, "obsbx", "run-other")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	env := vmSweepEnv{facts: vmProcFacts, kill: func(int) error { return nil }, relayLive: func(string) bool { return false }, held: vmLockHeld}
	if _, err := vmSweepRuns(obs, env); err != nil {
		t.Fatal(err)
	}
	for _, sock := range gone {
		if _, err := os.Lstat(sock); !os.IsNotExist(err) {
			t.Errorf("%s stays: %v", sock, err)
		}
	}
	if _, err := os.Lstat(other); err != nil {
		t.Fatalf("another run's socket dir was removed: %v", err)
	}
}
