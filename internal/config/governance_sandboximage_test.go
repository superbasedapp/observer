package config

import (
	"strings"
	"testing"
)

// TestGovernanceSandboxImagePins walks the org image pins (lane SBX-P3B)
// through the overlay: a digest-pinned image applies, a tag is skipped and
// the node keeps its own value.
func TestGovernanceSandboxImagePins(t *testing.T) {
	good := "registry.example/team/sandbox@sha256:" + strings.Repeat("b", 64)
	own := "alpine@sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct {
		name, key string
		get       func(c *Config) string
		set       func(c *Config, v string)
	}{
		{"oci", "terminal.sandbox.oci.image", func(c *Config) string { return c.Terminal.Sandbox.OCI.Image }, func(c *Config, v string) { c.Terminal.Sandbox.OCI.Image = v }},
		{"apple", "terminal.sandbox.apple_container.image", func(c *Config) string { return c.Terminal.Sandbox.AppleContainer.Image }, func(c *Config, v string) { c.Terminal.Sandbox.AppleContainer.Image = v }},
	} {
		cfg := Default()
		tc.set(&cfg, own)
		var out GovernanceOutcome
		applyGovernancePins(&cfg, map[string]any{tc.key: good}, &out)
		if tc.get(&cfg) != good || len(out.Applied) != 1 {
			t.Errorf("%s: a digest-pinned image must apply: %q %+v", tc.name, tc.get(&cfg), out)
		}
		cfg = Default()
		tc.set(&cfg, own)
		out = GovernanceOutcome{}
		applyGovernancePins(&cfg, map[string]any{tc.key: "alpine:3"}, &out)
		if tc.get(&cfg) != own {
			t.Errorf("%s: a tag must be skipped, the node keeps its own image: %q", tc.name, tc.get(&cfg))
		}
		if _, skipped := out.Skipped[tc.key]; !skipped {
			t.Errorf("%s: the skip must be reported: %+v", tc.name, out)
		}
	}
}
