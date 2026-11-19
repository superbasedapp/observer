package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHostedGuardHooksValidated (lane HOOKS, SBXD-6): the default is auto,
// auto / on / off and "" (auto) are accepted, anything else is refused
// naming the key, and a file that sets it loads it.
func TestHostedGuardHooksValidated(t *testing.T) {
	base := Default().Terminal.Sandbox.Hosted
	if base.GuardHooks != "auto" {
		t.Fatalf("default guard_hooks = %q, want auto", base.GuardHooks)
	}
	for _, v := range []string{"", "auto", "on", "off"} {
		c := base
		c.GuardHooks = v
		if err := validateTerminalSandboxHosted(c); err != nil {
			t.Errorf("%q: %v", v, err)
		}
	}
	for _, v := range []string{"yes", "true", "ON", " auto"} {
		c := base
		c.GuardHooks = v
		err := validateTerminalSandboxHosted(c)
		if err == nil || !strings.Contains(err.Error(), "terminal.sandbox.hosted.guard_hooks") {
			t.Errorf("%q: err = %v, want a refusal naming the key", v, err)
		}
	}
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte("[terminal.sandbox.hosted]\nguard_hooks = \"off\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: p, GovernanceSidecar: NoGovernanceSidecar})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Terminal.Sandbox.Hosted.GuardHooks != "off" {
		t.Fatalf("loaded guard_hooks = %q, want off", cfg.Terminal.Sandbox.Hosted.GuardHooks)
	}
}
