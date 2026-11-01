package main

import (
	"os"
	"runtime"
	"testing"
)

// Windows test portability helpers (Windows 11 Pro live run, PT-02).

// posixModes reports whether this OS keeps POSIX permission bits. On Windows
// os.Stat reports 0666 for any writable file and these writers set no DACL,
// so a test that pins a 0600 or 0644 mode skips that one assertion there.
var posixModes = runtime.GOOS != "windows"

// setTestHome points the home directory at dir: HOME, and on Windows also
// USERPROFILE, which is what os.UserHomeDir reads there. A test that set HOME
// alone wrote into the real (or the kit's isolated) profile on Windows.
func setTestHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", dir)
	}
}

// processLifetimeDBDir is a directory for a database that a process-lifetime
// registry (the shared Guard, the shared price engine) keeps open by design.
// Windows cannot delete an open file, so t.TempDir's cleanup failed the
// test; this directory is removed best effort instead.
func processLifetimeDBDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "observer-test-db-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// skipOnWindows skips a test of a driver or path shape that does not exist
// on Windows (a Linux or macOS sandbox driver, a POSIX-only path rule).
func skipOnWindows(t *testing.T, why string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("not on Windows: " + why)
	}
}
