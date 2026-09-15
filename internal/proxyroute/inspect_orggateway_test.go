package proxyroute

import "testing"

// TestClassifyBaseURLWithGateways pins the §3.2 route-class addition: a
// non-loopback host that matches a published org AI Gateway endpoint is
// RouteOrgGateway (authorized), while any other non-loopback host stays
// RouteDrifted and loopback stays RouteOurs. nil gateways must restore the
// exact gateway-unaware behavior.
func TestClassifyBaseURLWithGateways(t *testing.T) {
	gws := []string{"https://gw.acme.example:8840", "https://gw2.acme.example:8840/"}
	cases := []struct {
		name     string
		raw      string
		gateways []string
		want     RouteState
	}{
		{"empty is absent", "", gws, RouteAbsent},
		{"loopback is ours even with gateways", "http://127.0.0.1:8820/v1", gws, RouteOurs},
		{"exact gateway match is org-gateway", "https://gw.acme.example:8840", gws, RouteOrgGateway},
		{"gateway match ignoring trailing path", "https://gw.acme.example:8840/v1/messages", gws, RouteOrgGateway},
		{"second gateway with trailing slash matches", "https://gw2.acme.example:8840", gws, RouteOrgGateway},
		{"non-gateway remote is drifted", "https://api.anthropic.com", gws, RouteDrifted},
		{"gateway host wrong port is drifted", "https://gw.acme.example:9999", gws, RouteDrifted},
		{"nil gateways: remote is drifted (unaware)", "https://gw.acme.example:8840", nil, RouteDrifted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyBaseURLWithGateways(tc.raw, tc.gateways); got != tc.want {
				t.Errorf("classifyBaseURLWithGateways(%q, %v) = %q, want %q", tc.raw, tc.gateways, got, tc.want)
			}
		})
	}
}

// TestIsOrgGatewayBaseURL covers the matcher edge cases directly.
func TestIsOrgGatewayBaseURL(t *testing.T) {
	gws := []string{"https://gw.acme.example:8840"}
	if IsOrgGatewayBaseURL("", gws) {
		t.Error("empty raw must not match")
	}
	if IsOrgGatewayBaseURL("https://gw.acme.example:8840", nil) {
		t.Error("nil gateways must not match")
	}
	if !IsOrgGatewayBaseURL("HTTPS://GW.ACME.EXAMPLE:8840/v1", gws) {
		t.Error("case-insensitive scheme+host match expected")
	}
}
