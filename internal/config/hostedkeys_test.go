package config

import (
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// TestHostedKeyCustodyDefaultIsAuto (decision SBXD-1): a node that never
// set key_custody reads auto, and an explicit value keeps its meaning.
func TestHostedKeyCustodyDefaultIsAuto(t *testing.T) {
	if got := Default().Terminal.Sandbox.Hosted.KeyCustody; got != "auto" {
		t.Fatalf("default key_custody = %q, want auto", got)
	}
	for _, v := range []string{"auto", "home_relay", "in_box_api_key"} {
		c := Default()
		if _, err := toml.Decode("[terminal.sandbox.hosted]\nkey_custody = \""+v+"\"\n", &c); err != nil {
			t.Fatal(err)
		}
		if c.Terminal.Sandbox.Hosted.KeyCustody != v {
			t.Fatalf("explicit %s read %q", v, c.Terminal.Sandbox.Hosted.KeyCustody)
		}
		if err := validateTerminalSandboxHosted(c.Terminal.Sandbox.Hosted); err != nil {
			t.Fatalf("%s: %v", v, err)
		}
	}
}

// TestHostedKeySourcesValidated: one case per rule of
// validateHostedKeySources.
func TestHostedKeySourcesValidated(t *testing.T) {
	base := Default().Terminal.Sandbox.Hosted
	cases := []struct {
		name   string
		change func(*TerminalSandboxHostedConfig)
		errHas string
	}{
		{"empty is valid", func(*TerminalSandboxHostedConfig) {}, ""},
		{"a per-tool custody", func(c *TerminalSandboxHostedConfig) {
			c.KeyCustodyByTool = map[string]string{"droid": "in_box_api_key", "claude-code": "home_relay", "opencode": "auto"}
		}, ""},
		{"a per-tool custody for an unknown tool", func(c *TerminalSandboxHostedConfig) { c.KeyCustodyByTool = map[string]string{"nosuch-tool": "auto"} }, "not a tool id"},
		{"a per-tool custody outside the offered set", func(c *TerminalSandboxHostedConfig) {
			c.KeyCustodyByTool = map[string]string{"droid": "provider_injected"}
		}, "not in {auto"},
		{"saved keys of a grounded tool", func(c *TerminalSandboxHostedConfig) { c.ToolKeys = map[string]bool{"opencode": true} }, ""},
		{"saved keys of a tool with no row", func(c *TerminalSandboxHostedConfig) { c.ToolKeys = map[string]bool{"droid": true} }, "no grounded saved-keys file"},
		{"an off entry of a tool with no row is accepted", func(c *TerminalSandboxHostedConfig) { c.ToolKeys = map[string]bool{"droid": false} }, ""},
		{"a login seed of a grounded tool", func(c *TerminalSandboxHostedConfig) { c.LoginSeed = map[string]bool{"claude-code": true} }, ""},
		{"a login seed of a tool with no row", func(c *TerminalSandboxHostedConfig) { c.LoginSeed = map[string]bool{"opencode": true} }, "no grounded login file"},
		{"an unknown custody value", func(c *TerminalSandboxHostedConfig) { c.KeyCustody = "bogus" }, "not in {auto"},
	}
	for _, tc := range cases {
		c := base
		tc.change(&c)
		err := validateTerminalSandboxHosted(c)
		if tc.errHas == "" && err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if tc.errHas != "" && (err == nil || !strings.Contains(err.Error(), tc.errHas)) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.errHas)
		}
	}
}
