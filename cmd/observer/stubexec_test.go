package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// stubexec_test.go is the one helper for tests that need a POSIX shell or a
// Go toolchain (Windows 11 Pro run 3 RERUN2, PT-02: 33 cmd/observer tests
// failed there only because sh or go was not on PATH, with errors such as
// "%1 is not a valid Win32 application" for a #!/bin/sh stub). On Linux and
// macOS nothing is ever skipped: sh and go are part of the suite's host. On
// Windows a test that needs sh runs when sh is on PATH (Git for Windows)
// and is skipped with the reason "needs sh" when it is not; likewise "needs
// go".

// needSh skips the test on Windows when sh is not on PATH; it never skips
// on another OS. It returns the sh to run ("sh" off Windows).
func needSh(t testing.TB) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return "sh"
	}
	p, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("needs sh: no sh on PATH (install Git for Windows and put its usr\\bin on PATH to run it)")
	}
	return p
}

// needGo skips the test on Windows when go is not on PATH; it never skips
// on another OS.
func needGo(t testing.TB) {
	t.Helper()
	if runtime.GOOS != "windows" {
		return
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("needs go: no Go toolchain on PATH")
	}
}

// stubShPath is p as a stub's sh reads it: forward slashes on Windows (Git for
// Windows' sh reads C:/x; a backslash outside quotes is an escape there),
// unchanged elsewhere.
func stubShPath(p string) string {
	if runtime.GOOS == "windows" {
		return filepath.ToSlash(p)
	}
	return p
}

// writeShellStub writes script (a #!/bin/sh program whose paths were made
// with stubShPath) to path and returns the path a launcher should run. On Linux
// and macOS that is path itself, executable. On Windows a #! script cannot
// be started, so a path+".cmd" wrapper runs it under sh and is returned;
// without sh on PATH the test is skipped ("needs sh").
func writeShellStub(t testing.TB, path, script string) string {
	t.Helper()
	sh := needSh(t)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil { //nolint:gosec // G306: a test stub must be executable
		t.Fatalf("write stub %s: %v", path, err)
	}
	if runtime.GOOS != "windows" {
		return path
	}
	// The wrapper lives in a folder of its own whose name has no comma,
	// semicolon or other cmd.exe delimiter: a subtest's t.TempDir carries
	// the subtest's name ("no_key,_bare_launch"), and cmd.exe splits a
	// batch file's own path at a comma.
	dir, err := os.MkdirTemp("", "sbo-stub-")
	if err != nil {
		t.Fatalf("stub wrapper folder: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	wrapper := filepath.Join(dir, filepath.Base(path)+".cmd")
	body := fmt.Sprintf("@\"%s\" \"%s\" %%*\r\n@exit /b %%ERRORLEVEL%%\r\n", sh, filepath.ToSlash(path))
	if err := os.WriteFile(wrapper, []byte(body), 0o755); err != nil { //nolint:gosec // G306: a test stub must be executable
		t.Fatalf("write stub wrapper %s: %v", wrapper, err)
	}
	return wrapper
}

// TestStubHelpersNeverSkipOffWindows pins the rule: off Windows needSh and
// needGo never skip, and writeShellStub returns the script itself.
func TestStubHelpersNeverSkipOffWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the rule under test is the non-Windows one")
	}
	if needSh(t) != "sh" {
		t.Fatal("needSh off Windows")
	}
	needGo(t)
	p := filepath.Join(t.TempDir(), "stub")
	if got := writeShellStub(t, p, "#!/bin/sh\nexit 0\n"); got != p {
		t.Fatalf("writeShellStub = %q, want %q", got, p)
	}
	if stubShPath(`a\b`) != `a\b` {
		t.Fatal("stubShPath changed a path off Windows")
	}
}
