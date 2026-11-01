package mcpregister

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestBareCommandResolvesThroughPATH pins the FU-24 follow-up: a bare
// `observer` entry is resolved through PATH, never against the working
// directory, both for existence (the stale-observer repair) and for the
// same-install rule (so init does not need --force to refresh it).
func TestBareCommandResolvesThroughPATH(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PATH search adds .exe on Windows; the bare form is POSIX-only (installshape.PathName)")
	}
	bin := t.TempDir()
	self := filepath.Join(bin, "observer")
	if err := os.WriteFile(self, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // G306: an executable test stub.
		t.Fatal(err)
	}
	// A file named observer in the working directory must not count.
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "observer"), []byte("x"), 0o755); err != nil { //nolint:gosec // G306: a decoy test stub.
		t.Fatal(err)
	}
	t.Chdir(cwd)

	t.Run("on PATH: exists and is this install", func(t *testing.T) {
		t.Setenv("PATH", bin)
		if !commandFileExists("observer") {
			t.Error("a bare name on PATH should exist")
		}
		r := &Registrar{opts: RegisterOptions{SelfBinary: self}}
		if !r.ownershipEnv().sameInstall("observer") {
			t.Error("a bare name PATH resolves to the running binary should be the same install")
		}
	})
	t.Run("not on PATH: gone, never the cwd file", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if commandFileExists("observer") {
			t.Error("a bare name PATH cannot resolve should not exist (the cwd file must not count)")
		}
		r := &Registrar{opts: RegisterOptions{SelfBinary: filepath.Join(cwd, "observer")}}
		if r.ownershipEnv().sameInstall("observer") {
			t.Error("a bare name must not resolve against the working directory")
		}
	})
	t.Run("register refreshes a bare entry of this install without --force", func(t *testing.T) {
		t.Setenv("PATH", bin)
		home := t.TempDir()
		p := filepath.Join(home, ".claude.json")
		if err := os.WriteFile(p, []byte(`{"mcpServers":{"observer":{"command":"observer","args":["serve"]}}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		r, err := NewRegistrar(RegisterOptions{BinaryPath: self, SelfBinary: self, HomeDir: home})
		if err != nil {
			t.Fatal(err)
		}
		res := r.Register("claude-code")
		if res.Error != nil || !res.Added {
			t.Fatalf("Register = %+v, want a refresh without --force", res)
		}
		if b, _ := os.ReadFile(p); !strings.Contains(string(b), self) {
			t.Fatalf("entry not refreshed: %s", b)
		}
	})
	t.Run("repair rewrites a bare entry PATH no longer resolves", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		home := t.TempDir()
		p := filepath.Join(home, ".claude.json")
		if err := os.WriteFile(p, []byte(`{"mcpServers":{"observer":{"command":"observer","args":["serve"]}}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		r, err := NewRegistrar(RegisterOptions{BinaryPath: "/new/bin/observer", HomeDir: home, RepairOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		if res := r.Register("claude-code"); res.Error != nil || !res.Added {
			t.Fatalf("Register = %+v, want the stale-observer repair", res)
		}
	})
}
