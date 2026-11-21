//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
)

// TestSandboxEgressHostCheckSeam: the dashboard advisor's host check is the
// gateway's own list builder, one case per list shape.
func TestSandboxEgressHostCheckSeam(t *testing.T) {
	check := sandboxEgressHostCheckSeam()
	cases := []struct {
		name string
		ts   config.TerminalSandboxConfig
		host string
		want string
	}{
		{"no list passes every host", config.TerminalSandboxConfig{}, "a.example.com", ""},
		{"listed host passes", config.TerminalSandboxConfig{EgressAllowHosts: []string{"a.example.com"}}, "a.example.com", ""},
		{"wildcard passes a name below it", config.TerminalSandboxConfig{EgressAllowHosts: []string{"*.example.com"}}, "b.example.com", ""},
		{"unlisted host is refused", config.TerminalSandboxConfig{EgressAllowHosts: []string{"a.example.com"}}, "b.example.com", sandboxnet.RuleHostNotListed},
		{"an emptied org pin refuses every host", config.TerminalSandboxConfig{PinnedNoEgressHost: "terminal.sandbox.egress_allow_hosts"}, "a.example.com", sandboxnet.RuleHostNotListed},
		{"a list that does not parse refuses", config.TerminalSandboxConfig{EgressAllowHosts: []string{"bad host"}}, "a.example.com", "host-list-invalid"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := check(c.ts, c.host); got != c.want {
				t.Fatalf("check = %q, want %q", got, c.want)
			}
		})
	}
}

// TestSandboxProviderHostSeam (audit finding N5-A1): the advisor's provider
// check is the gateway provider block's name set, the closed provider list
// plus the proxy's configured upstreams, one case per shape.
func TestSandboxProviderHostSeam(t *testing.T) {
	check := sandboxProviderHostSeam()
	withUpstream := config.Config{}
	withUpstream.Proxy.Upstreams = map[string]string{"router": "https://llm.corp.example.net/v1"}
	cases := []struct {
		name string
		cfg  config.Config
		host string
		want bool
	}{
		{"closed provider host", config.Config{}, "api.anthropic.com", true},
		{"provider host in another case", config.Config{}, "API.OpenAI.com", true},
		{"subdomain of a provider host", config.Config{}, "eu.api.anthropic.com", true},
		{"configured proxy upstream", withUpstream, "llm.corp.example.net", true},
		{"upstream not configured", config.Config{}, "llm.corp.example.net", false},
		{"ordinary host", config.Config{}, "registry.npmjs.org", false},
		{"look-alike suffix", config.Config{}, "notapi.anthropic.com.example.com", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := check(c.cfg, c.host); got != c.want {
				t.Fatalf("check(%q) = %v, want %v", c.host, got, c.want)
			}
		})
	}
}
