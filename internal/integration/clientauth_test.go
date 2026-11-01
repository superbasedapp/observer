package integration

import (
	"sort"
	"strings"
	"testing"
)

// TestClientAuthCarrierRows pins which routed tools declare the proxy client
// token carrier (OSH-R-009, docs/plans/proxy-client-auth-2026-10-30.md
// section 4). A new carrier is a grounded registry change and a design note
// row, never a guess; a row whose Suffix carries a path or whose route rides
// a lane is a carrier by the note's rule.
func TestClientAuthCarrierRows(t *testing.T) {
	t.Parallel()
	want := []string{"aider", "claude-code", "cline-cli", "codex", "copilot-cli", "crush", "grok", "hermes", "kimi-code", "opencode", "pi", "prime-agent", "qwen-code"}
	var got []string
	for _, c := range Capabilities() {
		if c.Proxy == nil {
			continue
		}
		if strings.HasPrefix(c.Proxy.Suffix, "/") || c.Proxy.Lane != nil {
			if c.Proxy.ClientAuth != ClientAuthPathToken {
				t.Errorf("%s: the route carries a path (%q) but declares no client token carrier", c.Tool, c.Proxy.Suffix)
			}
		}
		if c.Proxy.ClientAuth == ClientAuthPathToken {
			got = append(got, c.Tool)
		}
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("client token carriers = %v, want %v", got, want)
	}
}
