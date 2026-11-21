//go:build !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestOpenShellWriteAtomicStaysInItsDir pins the os.Root rewrite of
// openShellWriteAtomic (fold audit H4, gosec G703, lane FX5): it writes and
// then replaces the file, owner-only, and leaves no temp file behind; a
// missing dir is an error, never a write elsewhere.
func TestOpenShellWriteAtomicStaysInItsDir(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "gateway.json")
	for _, body := range []string{"first\n", "second\n"} {
		if err := openShellWriteAtomic(p, []byte(body)); err != nil {
			t.Fatalf("write %q: %v", body, err)
		}
		got, err := os.ReadFile(p)
		if err != nil || string(got) != body {
			t.Fatalf("read back %q %v, want %q", got, err, body)
		}
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v %v, want 0600", fi.Mode().Perm(), err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "gateway.json" {
		t.Fatalf("the dir holds %v %v; want only gateway.json", entries, err)
	}
	if err := openShellWriteAtomic(filepath.Join(dir, "missing", "x.json"), []byte("x")); err == nil {
		t.Fatal("a write into a missing dir succeeded")
	}
}
