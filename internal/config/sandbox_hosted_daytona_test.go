package config

import (
	"strings"
	"testing"
)

// TestHostedDaytonaTableValidated: the daytona provider table goes through
// the same per-provider checks as the others (a region name, a template
// name, an absolute box_binary), and endpoint stays E2B only.
func TestHostedDaytonaTableValidated(t *testing.T) {
	cases := []struct {
		name string
		set  func(*TerminalSandboxHostedProviderConfig)
		want string
	}{
		{"defaults", func(*TerminalSandboxHostedProviderConfig) {}, ""},
		{"a region and a snapshot", func(p *TerminalSandboxHostedProviderConfig) { p.Region, p.Template = "eu", "daytona-small" }, ""},
		{"a bad region", func(p *TerminalSandboxHostedProviderConfig) { p.Region = "EU West" }, "daytona.region"},
		{"a bad template", func(p *TerminalSandboxHostedProviderConfig) { p.Template = "-x" }, "daytona.template"},
		{"a relative box_binary", func(p *TerminalSandboxHostedProviderConfig) { p.BoxBinary = "bin/observer" }, "daytona.box_binary"},
		{"an endpoint", func(p *TerminalSandboxHostedProviderConfig) { p.Endpoint = "https://app.daytona.io" }, "E2B only"},
	}
	for _, tc := range cases {
		h := Default().Terminal.Sandbox.Hosted
		tc.set(&h.Daytona)
		err := validateTerminalSandboxHosted(h)
		if tc.want == "" && err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}
