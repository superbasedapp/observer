package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestPreflightRestart pins the "never shut down into a brick" guard: a valid
// config preflights clean, a malformed one is REFUSED (the daemon keeps
// running rather than restarting into a process that won't load).
func TestPreflightRestart(t *testing.T) {
	dir := t.TempDir()

	valid := filepath.Join(dir, "ok.toml")
	if err := os.WriteFile(valid, []byte("[observer]\nlog_level = \"info\"\n"), 0o644); err != nil {
		t.Fatalf("write valid config: %v", err)
	}
	if err := preflightRestart(valid); err != nil {
		t.Fatalf("valid config should preflight clean: %v", err)
	}

	bad := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(bad, []byte("this is not = valid ]["), 0o644); err != nil {
		t.Fatalf("write bad config: %v", err)
	}
	if err := preflightRestart(bad); err == nil {
		t.Fatal("malformed config must be refused by preflightRestart")
	}
}

// TestReexecSupportedIsUnix documents the platform gate: the daemon runs under
// WSL/Linux (unix) where self re-exec works; a native-Windows build refuses.
// The answer follows the unix build constraint (reexec_unix.go vs
// reexec_other.go), whose operating systems are listed here.
func TestReexecSupportedIsUnix(t *testing.T) {
	unix := map[string]bool{
		"aix": true, "android": true, "darwin": true, "dragonfly": true,
		"freebsd": true, "hurd": true, "illumos": true, "ios": true,
		"linux": true, "netbsd": true, "openbsd": true, "solaris": true,
	}
	if got, want := reexecSupported(), unix[runtime.GOOS]; got != want {
		t.Errorf("reexecSupported() on %s = %v, want %v", runtime.GOOS, got, want)
	}
}
