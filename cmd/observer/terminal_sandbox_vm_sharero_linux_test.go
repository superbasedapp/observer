//go:build linux && !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// terminal_sandbox_vm_sharero_linux_test.go covers D4 of the microVM row's
// first live run (2026-10-24): the in-guest check required a guest mount
// point at every host-pinned read-only path (none exists there: the pin is
// the host's bind, read back on the host), and access(W_OK) through
// virtio-fs answers 0 although a write gets EROFS. The witness now attempts
// a write that changes nothing when refused; here it runs on a host
// filesystem, where a writable path takes the write (the witness is undone)
// and a missing or linked path never passes. (EROFS itself needs a
// read-only mount, which the guest has and the pure rows stand in:
// TestGuestCheckSharedRows.)
func TestVMShareWriteProbe(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "config")
	if err := os.WriteFile(file, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := vmShareWriteProbe(dir); err != nil {
		t.Fatalf("a writable dir: %v", err)
	}
	if err := vmShareWriteProbe(file); err != nil {
		t.Fatalf("a writable file: %v", err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("the witness left %d entries", len(ents))
	}
	if b, _ := os.ReadFile(file); string(b) != "keep\n" {
		t.Fatalf("the probe changed the file: %q", b)
	}
	if err := vmShareWriteProbe(filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a missing path: %v", err)
	}
	link := filepath.Join(dir, "link")
	_ = os.Symlink(file, link)
	if err := vmShareWriteProbe(link); err == nil {
		t.Fatal("a link passed")
	}
}
