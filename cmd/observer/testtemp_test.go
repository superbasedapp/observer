package main

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"
)

// setTestTempDir points the process temp directory at dir on every OS: Go
// reads TMPDIR on Unix and TMP, then TEMP, on Windows (os.TempDir), so a
// test that set only TMPDIR wrote to the real temp folder on Windows
// (Windows 11 Pro rerun 2026-10-25, D5 group 3).
func setTestTempDir(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("TMPDIR", dir)
	t.Setenv("TMP", dir)
	t.Setenv("TEMP", dir)
}

// nativeAbs turns a POSIX absolute test path into an absolute path of this
// host: "C:\srv\x" for "/srv/x" on Windows, unchanged elsewhere. It never
// touches the filesystem (Windows 11 Pro rerun 2026-10-25, D5 group 4).
func nativeAbs(p string) string {
	if runtime.GOOS != "windows" {
		return p
	}
	return `C:` + filepath.FromSlash(p)
}

// nonSensitiveTestDir is a directory a write bind may name on this host. A
// t.TempDir() under %LOCALAPPDATA% is a sensitive location on Windows, so
// there it is a path under a drive-root folder that is never created.
func nonSensitiveTestDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return t.TempDir()
	}
	return filepath.Join(`C:\sbo-test-nonexistent`, filepath.Base(t.TempDir()))
}

// cleanRoot is a test root in the host's cleaned form ("" stays "").
func cleanRoot(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Clean(p)
}

// skipDriverOffHost skips a test of a sandbox driver that does not run on
// Windows (its row's hosts are Linux, WSL2 or macOS, so selection reports
// unsupported_platform there) and whose fixture pins that host's POSIX paths
// (Windows 11 Pro rerun 2026-10-25, D5 group 5).
func skipDriverOffHost(t *testing.T, driver string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip(driver + " does not run on Windows; the test pins its host's POSIX paths")
	}
}

// filePathInput is a tool input naming one file, JSON-encoded so a Windows
// path's backslashes are escaped (a hand-built string with a "C:\Users"
// path was not valid JSON; Windows 11 Pro rerun 2026-10-25, D5 group 1).
func filePathInput(p string) string {
	b, _ := json.Marshal(map[string]string{"file_path": p})
	return string(b)
}
