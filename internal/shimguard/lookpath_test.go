package shimguard

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// writeExec writes an executable file, creating its directory.
func writeExec(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o755); err != nil { // past the umask
		t.Fatal(err)
	}
}

// TestLookPathSkipsShims: a shim earlier on PATH is skipped for the vendor
// binary behind it, a PATH holding only a shim is not-found, and a plain
// lookup is unchanged. (Moved here from shellwrapsvc with its forwarding
// wrapper's removal; LookPath's owner is this package.)
func TestLookPathSkipsShims(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX executables")
	}
	root := t.TempDir()
	shims, real := filepath.Join(root, "shims"), filepath.Join(root, "real")
	writeExec(t, filepath.Join(shims, "sbotool"), "#!/bin/sh\n# "+ShimMarker+" v1 tool=x command=sbotool\n")
	writeExec(t, filepath.Join(real, "sbotool"), "#!/bin/sh\necho real\n")

	if !IsShimFile(filepath.Join(shims, "sbotool")) || IsShimFile(filepath.Join(real, "sbotool")) {
		t.Fatal("IsShimFile must tell the shim from the real binary")
	}
	if IsShimFile(filepath.Join(root, "missing")) {
		t.Fatal("an unreadable file is not a shim")
	}

	t.Setenv("PATH", shims+string(filepath.ListSeparator)+real)
	got, err := LookPath("sbotool")
	if err != nil || got != filepath.Join(real, "sbotool") {
		t.Fatalf("LookPath = %q, %v", got, err)
	}

	t.Setenv("PATH", shims)
	if got, err := LookPath("sbotool"); err == nil {
		t.Fatalf("only a shim on PATH must be not-found, got %q", got)
	}

	t.Setenv("PATH", real)
	if got, err := LookPath("sbotool"); err != nil || got != filepath.Join(real, "sbotool") {
		t.Fatalf("plain lookup = %q, %v", got, err)
	}
}
