//go:build linux && !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/sandboxvm"
)

// terminal_sandbox_vm_diskclose_linux_test.go covers the disk_image return
// of the microVM row's second live run (2026-10-24): the guest committed in
// its workspace image, the host reported "the box made no new commit". The
// host tore the VMM down as soon as the session ended, before the guest's PID
// 1 synced, and the image it read back still had needs_recovery set (debugfs
// does not replay the journal), so the copy came back as it went in.

// vmFixExt4Image writes an image prefix with an ext4 superblock at path,
// needs_recovery set when dirty.
func vmFixExt4Image(t *testing.T, path string, dirty bool) {
	t.Helper()
	b := make([]byte, 4096)
	binary.LittleEndian.PutUint16(b[1024+0x38:], 0xEF53)
	incompat := uint32(0x0002 | 0x0040)
	if dirty {
		incompat |= 0x0004
	}
	binary.LittleEndian.PutUint32(b[1024+0x60:], incompat)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestVMDiskImageReadBackRefusesAnUnclosedImage: an image the guest left
// mounted is never dumped; the copy stays as it was and the error says why.
func TestVMDiskImageReadBackRefusesAnUnclosedImage(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "repo")
	if err := os.MkdirAll(src, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "README"), []byte("host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(root, "ws.img")
	vmFixExt4Image(t, img, true)
	plan := vmPlanFile{
		VM:         sandboxvm.Plan{Disks: []sandboxvm.Disk{{Name: sandboxvm.WorkspaceTag, Path: img}}},
		DiskImages: []vmDiskImage{{Name: sandboxvm.WorkspaceTag, Source: src, Target: src}},
		Debugfs:    "/usr/sbin/debugfs", DumpBwrap: "/usr/bin/bwrap",
	}
	ran := 0
	env := vmHostEnv{tool: func(_ context.Context, argv []string) error {
		ran++
		return os.MkdirAll(src+".vm-return", 0o700)
	}}
	err := vmDumpDiskImages(plan, env)
	if err == nil || !strings.Contains(err.Error(), "did not close its workspace image") || ran != 0 {
		t.Fatalf("an unclosed image: %v, dump ran %d times", err, ran)
	}
	if b, err := os.ReadFile(filepath.Join(src, "README")); err != nil || string(b) != "host\n" {
		t.Fatalf("the copy changed: %q %v", b, err)
	}
	vmFixExt4Image(t, img, false)
	if err := vmDumpDiskImages(plan, env); err != nil || ran != 1 {
		t.Fatalf("a closed image: %v, dump ran %d times", err, ran)
	}
}

// TestVMGuestClosesItsDisks: the guest kills what is left, syncs, and
// remounts each disk read-only, retrying a busy one; another error is not
// retried, and a target that stays busy fails naming it.
func TestVMGuestClosesItsDisks(t *testing.T) {
	var calls []string
	busy := map[string]int{"/w/a": 2}
	ops := vmDiskCloseOps{
		killAll: func() { calls = append(calls, "kill") },
		sync:    func() { calls = append(calls, "sync") },
		remountRO: func(target string) error {
			calls = append(calls, "ro "+target)
			if busy[target] > 0 {
				busy[target]--
				return unix.EBUSY
			}
			if target == "/w/bad" {
				return unix.EINVAL
			}
			return nil
		},
		sleep: func(time.Duration) { calls = append(calls, "sleep") },
		tries: 5,
	}
	if err := vmCloseDisks([]string{"/w/a", "/w/b"}, ops); err != nil {
		t.Fatal(err)
	}
	want := []string{"kill", "sync", "ro /w/a", "sleep", "ro /w/a", "sleep", "ro /w/a", "ro /w/b"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls %q, want %q", calls, want)
	}
	calls = nil
	if err := vmCloseDisks([]string{"/w/bad"}, ops); err == nil || !strings.Contains(err.Error(), "/w/bad") || len(calls) != 3 {
		t.Fatalf("a non-busy error: %v, calls %q", err, calls)
	}
	calls = nil
	busy["/w/stuck"] = 99
	if err := vmCloseDisks([]string{"/w/stuck"}, ops); err == nil || !errors.Is(err, unix.EBUSY) || !strings.Contains(err.Error(), "/w/stuck") {
		t.Fatalf("a target that stays busy: %v", err)
	}
}

// TestVMGuestClosesTheSpecsDisksBeforeTheExitStatus: the serve child's
// finish closes exactly the spec's disk targets (nothing when it has none),
// a failed close is reported, and the production guest env wires the close.
func TestVMGuestClosesTheSpecsDisksBeforeTheExitStatus(t *testing.T) {
	var got []string
	closeDisks := func(targets []string) error { got = append(got, targets...); return nil }
	if why := vmCloseGuestDisks(sandboxvm.GuestSpec{}, closeDisks); why != "" || got != nil {
		t.Fatalf("no disks: %q, closed %q", why, got)
	}
	spec := sandboxvm.GuestSpec{Disks: []sandboxvm.GuestDisk{{Name: "ws", Target: "/w/repo"}, {Name: "cache", Target: "/w/cache"}}}
	if why := vmCloseGuestDisks(spec, closeDisks); why != "" || !reflect.DeepEqual(got, []string{"/w/repo", "/w/cache"}) {
		t.Fatalf("disks: %q, closed %q", why, got)
	}
	if why := vmCloseGuestDisks(spec, func([]string) error { return unix.EBUSY }); !strings.Contains(why, "could not be closed") {
		t.Fatalf("a failed close: %q", why)
	}
	if vmRealGuestEnv().closeDisks == nil {
		t.Fatal("the production guest env does not close its disks")
	}
	if err := vmRealGuestEnv().closeDisks(nil); err != nil {
		t.Fatalf("closing no disks: %v", err)
	}
}
