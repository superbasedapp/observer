//go:build linux && !sbo_omit_terminals_sandbox_landlock && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/sandboxlandlock"
)

// TestLandlockAccessBitsMatchUnix: the pure package's uapi bits equal the
// ones golang.org/x/sys/unix spells.
func TestLandlockAccessBitsMatchUnix(t *testing.T) {
	pairs := [][2]uint64{
		{sandboxlandlock.AccessFSExecute, unix.LANDLOCK_ACCESS_FS_EXECUTE},
		{sandboxlandlock.AccessFSWriteFile, unix.LANDLOCK_ACCESS_FS_WRITE_FILE},
		{sandboxlandlock.AccessFSReadFile, unix.LANDLOCK_ACCESS_FS_READ_FILE},
		{sandboxlandlock.AccessFSReadDir, unix.LANDLOCK_ACCESS_FS_READ_DIR},
		{sandboxlandlock.AccessFSRemoveDir, unix.LANDLOCK_ACCESS_FS_REMOVE_DIR},
		{sandboxlandlock.AccessFSRemoveFile, unix.LANDLOCK_ACCESS_FS_REMOVE_FILE},
		{sandboxlandlock.AccessFSMakeChar, unix.LANDLOCK_ACCESS_FS_MAKE_CHAR},
		{sandboxlandlock.AccessFSMakeDir, unix.LANDLOCK_ACCESS_FS_MAKE_DIR},
		{sandboxlandlock.AccessFSMakeReg, unix.LANDLOCK_ACCESS_FS_MAKE_REG},
		{sandboxlandlock.AccessFSMakeSock, unix.LANDLOCK_ACCESS_FS_MAKE_SOCK},
		{sandboxlandlock.AccessFSMakeFifo, unix.LANDLOCK_ACCESS_FS_MAKE_FIFO},
		{sandboxlandlock.AccessFSMakeBlock, unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK},
		{sandboxlandlock.AccessFSMakeSym, unix.LANDLOCK_ACCESS_FS_MAKE_SYM},
		{sandboxlandlock.AccessFSRefer, unix.LANDLOCK_ACCESS_FS_REFER},
		{sandboxlandlock.AccessFSTruncate, unix.LANDLOCK_ACCESS_FS_TRUNCATE},
		{sandboxlandlock.AccessFSIoctlDev, unix.LANDLOCK_ACCESS_FS_IOCTL_DEV},
		{sandboxlandlock.AccessNetBindTCP, unix.LANDLOCK_ACCESS_NET_BIND_TCP},
		{sandboxlandlock.AccessNetConnectTCP, unix.LANDLOCK_ACCESS_NET_CONNECT_TCP},
		{sandboxlandlock.ScopeAbstractUnixSocket, unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET},
		{sandboxlandlock.ScopeSignal, unix.LANDLOCK_SCOPE_SIGNAL},
	}
	for _, p := range pairs {
		if ours, theirs := p[0], p[1]; ours != theirs {
			t.Errorf("bit %#x, unix says %#x", ours, theirs)
		}
	}
}

// TestLandlockApplyOnThisKernel applies a ruleset with this kernel's own ABI
// (the full row needs 9; this exercises the same applyLandlock and
// self-test code) on a locked thread that is thrown away afterwards: the
// granted directory stays usable, the denied one (standing in for the
// observer directory) is refused, and the self-test says so. Skipped where
// the kernel has no Landlock.
func TestLandlockApplyOnThisKernel(t *testing.T) {
	abi, err := landlockABI()
	if err != nil || abi < 1 {
		t.Skipf("no Landlock on this kernel (%v)", err)
	}
	allowed, denied := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(allowed, "f"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := sandboxlandlock.FeaturesFor(abi)
	rs := sandboxlandlock.Ruleset{HandledFS: f.FS, Paths: []sandboxlandlock.PathRule{
		{Path: allowed, Access: f.FS &^ sandboxlandlock.AccessFSResolveUnix},
		{Path: "/proc", Access: sandboxlandlock.AccessFSReadFile | sandboxlandlock.AccessFSReadDir, Optional: true},
	}}
	type result struct {
		readAllowed, readDenied, selfTest error
		applied                           error
	}
	done := make(chan result, 1)
	go func() {
		// The thread is restricted for good: it is never unlocked, so the
		// runtime discards it when this goroutine returns.
		runtime.LockOSThread()
		var r result
		if r.applied = applyLandlock(rs); r.applied == nil {
			_, r.readAllowed = os.ReadFile(filepath.Join(allowed, "f"))
			_, r.readDenied = os.ReadDir(denied)
			r.selfTest = landlockSelfTest(denied)
		}
		done <- r
	}()
	r := <-done
	if r.applied != nil {
		t.Fatalf("apply: %v", r.applied)
	}
	if r.readAllowed != nil {
		t.Fatalf("the granted directory was refused: %v", r.readAllowed)
	}
	if !errors.Is(r.readDenied, unix.EACCES) {
		t.Fatalf("the denied directory was readable: %v", r.readDenied)
	}
	if r.selfTest != nil {
		t.Fatalf("the self-test: %v", r.selfTest)
	}
	// This goroutine's thread was never restricted.
	if _, err := os.ReadDir(denied); err != nil {
		t.Fatalf("the test thread itself was restricted: %v", err)
	}
}
