package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHostedCloneWhereValidated (decision SBXD-5): the clone location
// defaults to auto, takes auto, box and home, and refuses anything else
// (an empty value included: an older file gets the default from the
// partial merge, never an empty one).
func TestHostedCloneWhereValidated(t *testing.T) {
	base := Default().Terminal.Sandbox.Hosted
	if base.CloneWhere != "auto" {
		t.Fatalf("default clone_where %q, want auto", base.CloneWhere)
	}
	for _, tc := range []struct {
		v  string
		ok bool
	}{{"auto", true}, {"box", true}, {"home", true}, {"", false}, {"Box", false}, {"local", false}} {
		c := base
		c.CloneWhere = tc.v
		err := validateTerminalSandboxHosted(c)
		if (err == nil) != tc.ok {
			t.Errorf("%q: %v", tc.v, err)
		}
		if err != nil && !strings.Contains(err.Error(), "hosted.clone_where") {
			t.Errorf("%q: the refusal does not name the key: %v", tc.v, err)
		}
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte("[terminal.sandbox.hosted]\nmemory_images = \"refuse\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: p, GovernanceSidecar: NoGovernanceSidecar})
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Terminal.Sandbox.Hosted.CloneWhere; got != "auto" {
		t.Errorf("a file that names no clone_where loaded %q, want auto", got)
	}
	if err := os.WriteFile(p, []byte("[terminal.sandbox.hosted]\nclone_where = \"home\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg, err = Load(LoadOptions{GlobalPath: p, GovernanceSidecar: NoGovernanceSidecar}); err != nil || cfg.Terminal.Sandbox.Hosted.CloneWhere != "home" {
		t.Errorf("clone_where = home loaded %q (%v)", cfg.Terminal.Sandbox.Hosted.CloneWhere, err)
	}
}
