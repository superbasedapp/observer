//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// TestBwrapWrapArgvSeccomp (lane N2) composes a bwrap launch with
// [terminal.sandbox].seccomp off and on, against a stand-in bwrap on PATH:
// on, the host helper names the profile and bwrap reads the program from
// sandbox.SeccompFD; off, neither flag appears and the argv is the one
// every existing install builds.
func TestBwrapWrapArgvSeccomp(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("the seccomp assembler targets amd64 and arm64")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "bwrap"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // G306: a test stand-in that must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, on := range []bool{false, true} {
		home := t.TempDir()
		setTestHome(t, home)
		if real, err := filepath.EvalSymlinks(home); err == nil {
			home = real
		}
		_ = os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
		ws := filepath.Join(home, "proj")
		_ = os.MkdirAll(ws, 0o700)
		cfg := config.Default()
		cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
		cfg.Terminal.Sandbox.Enabled = true
		cfg.Terminal.Sandbox.Seccomp = on
		exe, _ := os.Executable()
		rt, err := newSandboxRuntime(cfg.Terminal.Sandbox, nil, filepath.Join(home, ".observer"), exe, nil)
		if err != nil {
			t.Fatal(err)
		}
		rt.applyDaemonConfig(cfg)
		wrap, err := rt.buildWrapArgv("claude-code", ws, "runbwrapseccomp0001", true, "")
		if err != nil {
			t.Fatal(err)
		}
		i := slices.Index(wrap, sandbox.HostVerb)
		if i < 0 {
			t.Fatalf("seccomp %v: no host helper in %v", on, wrap)
		}
		host, err := sandbox.ParseHostArgs(wrap[i+1:])
		if err != nil {
			t.Fatal(err)
		}
		fd, found, err := sandbox.BwrapSeccompFD(host.Command)
		if err != nil {
			t.Fatal(err)
		}
		if on != (host.SeccompProfile == "observer_default") || on != found || (on && fd != sandbox.SeccompFD) {
			t.Fatalf("seccomp %v: host profile %q, bwrap --seccomp %v on fd %d", on, host.SeccompProfile, found, fd)
		}
		if _, err := newHostSeccomp(host); err != nil {
			t.Fatalf("seccomp %v: the host helper refuses the planned command: %v", on, err)
		}
	}
}
