package config

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
)

// TestSandboxOCIInstallScriptKeys (lane LEFT-SBX, ruling P-136): the
// install-script keys validate, and their shape rules agree with
// internal/sandboxoci's (config stays a leaf, so it restates them).
func TestSandboxOCIInstallScriptKeys(t *testing.T) {
	for _, v := range []string{"2.1.310", "0.164.0", "1.0.0-rc.1", "latest", "1.2", "1.2.3 --x", "^1.2.3"} {
		if sandboxInstallVersionRE.MatchString(v) != sandboxoci.ValidInstallVersion(v) {
			t.Errorf("version %q: config %v, sandboxoci %v", v, sandboxInstallVersionRE.MatchString(v), sandboxoci.ValidInstallVersion(v))
		}
	}
	for _, id := range []string{"codex", "claude-code", "Claude", "a;b", ""} {
		if sandboxToolIDRE.MatchString(id) != sandboxoci.ValidToolID(id) {
			t.Errorf("tool %q disagrees", id)
		}
	}
	integ := "sha512-" + strings.Repeat("A", 86) + "=="
	for _, pk := range []TerminalSandboxOCIPackagePin{
		{Name: "opencode-ai", Version: "1.20.0", Integrity: integ},
		{Name: "@kilocode/cli-linux-x64", Version: "7.8.18", Integrity: integ},
		{Name: "Opencode", Version: "1.20.0", Integrity: integ},
		{Name: "../x", Version: "1.20.0", Integrity: integ},
		{Name: "opencode-ai", Version: "1.20.0", Integrity: "sha256-abc"},
		{Name: "opencode-ai", Version: "1.20.0", Integrity: "sha512-short=="},
	} {
		cfg := sandboxPackageNameRE.MatchString(pk.Name) && sandboxInstallVersionRE.MatchString(pk.Version) && sandboxIntegrityRE.MatchString(pk.Integrity)
		node := sandboxoci.ValidPackagePin(sandboxoci.PackagePin{Name: pk.Name, Version: pk.Version, Integrity: pk.Integrity}) == ""
		if cfg != node {
			t.Errorf("package pin %+v: config %v, sandboxoci %v", pk, cfg, node)
		}
	}
	ok := TerminalSandboxOCIConfig{
		InstallScripts: "pinned", InstallScriptsTools: []string{"claude-code"},
		InstallScriptPins: []TerminalSandboxOCIScriptPin{{Tool: "claude-code", Version: "2.1.311", SHA256: strings.Repeat("a", 64), Added: "2026-10-24"}, {
			Tool: "opencode", Version: "1.20.0", SHA256: strings.Repeat("b", 64),
			Packages: []TerminalSandboxOCIPackagePin{{Name: "opencode-ai", Version: "1.20.0", Integrity: integ}, {Name: "opencode-linux-x64", Version: "1.20.0", Integrity: integ}},
		}},
		InstallVersions: map[string]string{"codex": "0.164.0"},
	}
	if err := validateTerminalSandboxOCI(ok); err != nil {
		t.Fatal(err)
	}
	bad := []func(c *TerminalSandboxOCIConfig){
		func(c *TerminalSandboxOCIConfig) { c.InstallScripts = "always" },
		func(c *TerminalSandboxOCIConfig) { c.InstallScriptsTools = []string{"Claude Code"} },
		func(c *TerminalSandboxOCIConfig) { c.InstallScriptPins[0].SHA256 = "abc" },
		func(c *TerminalSandboxOCIConfig) { c.InstallScriptPins[0].Version = "latest" },
		func(c *TerminalSandboxOCIConfig) { c.InstallScriptPins[0].Added = "yesterday" },
		func(c *TerminalSandboxOCIConfig) { c.InstallVersions = map[string]string{"codex": "latest"} },
		func(c *TerminalSandboxOCIConfig) { c.InstallScriptPins[1].Packages[0].Integrity = "sha512-short==" },
		func(c *TerminalSandboxOCIConfig) { c.InstallScriptPins[1].Packages[1].Name = "Opencode Linux" },
		func(c *TerminalSandboxOCIConfig) { c.InstallScriptPins[1].Packages[1].Version = "latest" },
	}
	for i, edit := range bad {
		c := ok
		c.InstallScriptPins = append([]TerminalSandboxOCIScriptPin(nil), ok.InstallScriptPins...)
		c.InstallScriptPins[1].Packages = append([]TerminalSandboxOCIPackagePin(nil), ok.InstallScriptPins[1].Packages...)
		edit(&c)
		if err := validateTerminalSandboxOCI(c); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}
