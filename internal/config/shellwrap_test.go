package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestShellWrapDefaultsOffAndLoads(t *testing.T) {
	if d := Default(); d.ShellWrap.Enabled || len(d.ShellWrap.Tools) != 0 || d.ShellWrap.ShimDir != "" {
		t.Fatalf("[shell_wrap] must default off: %+v", d.ShellWrap)
	}
	p := filepath.Join(t.TempDir(), "config.toml")
	body := "[shell_wrap]\nenabled = true\nshim_dir = \"~/bin/sbo\"\n\n[shell_wrap.tools]\nclaude-code = true\ncodex = false\n\n[shell_wrap.shells]\nzsh = true\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: p})
	if err != nil {
		t.Fatal(err)
	}
	sw := cfg.ShellWrap
	if !sw.Enabled || !sw.Tools["claude-code"] || sw.Tools["codex"] || !sw.Shells["zsh"] || sw.ShimDir != "~/bin/sbo" {
		t.Fatalf("loaded %+v", sw)
	}
}
