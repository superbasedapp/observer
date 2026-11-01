//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// TestWorkspaceGitExecPathsProtected proves that every git-dir execution path
// flows from the one table (sandbox.WorkspaceExecState) into the protective
// overlays every driver reads (rt.protection): an existing config and hooks
// dir are re-bound read-only, and each missing redirector under the writable
// workspace becomes a read-only placeholder the box can neither create nor
// replace, with commondir carrying the neutral "." the box's own git needs.
// This is the shared input the bwrap, Seatbelt, oci, Apple and MXC rows each
// translate into their own mechanism (verified by their own suites); ledger
// SBX-BE-21, live Mac D1.
func TestWorkspaceGitExecPathsProtected(t *testing.T) {
	home := t.TempDir()
	if real, err := filepath.EvalSymlinks(home); err == nil {
		home = real
	}
	ws := filepath.Join(home, "proj")
	gd := filepath.Join(ws, ".git")
	for _, d := range []string{"hooks", "info", "objects/info", "refs/heads"} {
		if err := os.MkdirAll(filepath.Join(gd, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(gd, "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gd, "config"), []byte("[core]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(home, ".observer"), 0o700)
	exe, _ := os.Executable()
	rt, err := newSandboxRuntime(config.TerminalSandboxConfig{Enabled: true, Egress: "none"}, nil, filepath.Join(home, ".observer"), exe, nil)
	if err != nil {
		t.Fatal(err)
	}
	overlays, _, err := rt.protection(home, ws, integration.SandboxSpec{})
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]sandbox.Overlay{}
	for _, o := range overlays {
		byPath[o.Path] = o
	}
	type want struct {
		rel string
		ph  sandbox.Placeholder
	}
	for _, w := range []want{
		{".git/config", sandbox.PlaceholderNone},
		{".git/hooks", sandbox.PlaceholderNone},
		{".git/commondir", sandbox.PlaceholderFile},
		{".git/config.worktree", sandbox.PlaceholderFile},
		{".git/info/attributes", sandbox.PlaceholderFile},
		{".git/objects/info/alternates", sandbox.PlaceholderFile},
	} {
		p := filepath.Join(ws, w.rel)
		o, ok := byPath[p]
		if !ok {
			t.Errorf("protection overlays lack %s", w.rel)
			continue
		}
		if o.Kind != sandbox.OverlayReadOnly {
			t.Errorf("%s overlay kind = %q, want read-only", w.rel, o.Kind)
		}
		if o.Placeholder != w.ph {
			t.Errorf("%s placeholder = %q, want %q", w.rel, o.Placeholder, w.ph)
		}
	}
	// The commondir placeholder content must be the neutral ".", not empty.
	if got := string(sandbox.PlaceholderContent(filepath.Join(ws, ".git/commondir"))); got != ".\n" {
		t.Errorf("commondir placeholder content = %q, want %q", got, ".\n")
	}
}
