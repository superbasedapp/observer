package routeattest

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

func TestIsExempt(t *testing.T) {
	cases := []struct {
		name       string
		cap        integration.Capability
		wantExempt bool
	}{
		{
			name:       "native_exempt routability",
			cap:        integration.Capability{Tool: "kiro-cli", Routability: integration.RouteStatusNativeExempt},
			wantExempt: true,
		},
		{
			name:       "browser extension hook",
			cap:        integration.Capability{Tool: "claude-web", Hook: integration.HookSpec{Mechanism: integration.HookBrowserExtension}},
			wantExempt: true,
		},
		{
			name:       "routable now, nil proxy — NOT exempt (e.g. cline manual-paste)",
			cap:        integration.Capability{Tool: "cline", Proxy: nil, Routability: integration.RouteStatusRoutableNow},
			wantExempt: false,
		},
		{
			name:       "probe required — NOT exempt",
			cap:        integration.Capability{Tool: "copilot", Proxy: nil, Routability: integration.RouteStatusProbeRequired},
			wantExempt: false,
		},
		{
			name:       "routed now with live proxy — NOT exempt",
			cap:        integration.Capability{Tool: "claude-code", Proxy: &integration.ProxyRoute{Kind: integration.RouteEnvSettings}, Routability: integration.RouteStatusRoutableNow},
			wantExempt: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := IsExempt(tc.cap)
			if got != tc.wantExempt {
				t.Fatalf("IsExempt(%s) = %v (reason %q), want %v", tc.cap.Tool, got, reason, tc.wantExempt)
			}
			if got && reason == "" {
				t.Errorf("IsExempt(%s) = true with empty reason", tc.cap.Tool)
			}
		})
	}
}
