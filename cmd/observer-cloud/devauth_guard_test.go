package main

import "testing"

// TestRequireDevAuthLoopbackOnly is the C1 startup guard's table test (gap
// 2.3): dev-auth off is always fine regardless of origin; dev-auth on a
// loopback origin (the preserved local-dev/test path) is fine; dev-auth on
// any non-loopback origin, or dev-auth combined with the WorkOS browser leg,
// must both refuse to start.
func TestRequireDevAuthLoopbackOnly(t *testing.T) {
	cases := []struct {
		name         string
		devAuth      bool
		externalBase string
		portalBase   string
		portalWorkOS bool
		wantErr      bool
	}{
		{"dev_auth_off_public_https_is_fine", false, "https://cloud.superbased.app", "https://app.superbased.app", false, false},
		{"dev_auth_off_workos_on_is_fine", false, "https://cloud.superbased.app", "https://cloud.superbased.app", true, false},
		{"dev_auth_localhost_ok", true, "http://localhost:8090", "http://localhost:8090", false, false},
		{"dev_auth_127001_ok", true, "http://127.0.0.1:8090", "http://127.0.0.1:8090", false, false},
		{"dev_auth_ipv6_loopback_ok", true, "http://[::1]:8090", "http://[::1]:8090", false, false},
		{"dev_auth_localhost_with_port_ok", true, "http://localhost:9797", "http://localhost:9797", false, false},
		{"dev_auth_portal_base_defaults_to_external_ok", true, "http://localhost:8090", "http://localhost:8090", false, false},
		{"dev_auth_public_external_refused", true, "https://cloud.superbased.app", "http://localhost:8090", false, true},
		{"dev_auth_public_portal_refused", true, "http://localhost:8090", "https://app.superbased.app", false, true},
		{"dev_auth_both_public_refused", true, "https://cloud.superbased.app", "https://app.superbased.app", false, true},
		{"dev_auth_unparsable_base_refused", true, "not a url", "http://localhost:8090", false, true},
		{"dev_auth_plus_workos_refused_even_on_loopback", true, "http://localhost:8090", "http://localhost:8090", true, true},
		{"dev_auth_plus_workos_refused_on_public_origin_too", true, "https://cloud.superbased.app", "https://app.superbased.app", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := requireDevAuthLoopbackOnly(tc.devAuth, tc.externalBase, tc.portalBase, tc.portalWorkOS)
			if tc.wantErr && err == nil {
				t.Fatalf("requireDevAuthLoopbackOnly(%+v) = nil, want an error", tc)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("requireDevAuthLoopbackOnly(%+v) = %v, want nil", tc, err)
			}
		})
	}
}

// TestIsLoopbackOrigin pins the host classification requireDevAuthLoopbackOnly
// relies on.
func TestIsLoopbackOrigin(t *testing.T) {
	cases := []struct {
		base string
		want bool
	}{
		{"http://localhost:8090", true},
		{"http://localhost", true},
		{"http://127.0.0.1:8090", true},
		{"http://127.0.0.1", true},
		{"http://[::1]:8090", true},
		{"https://cloud.superbased.app", false},
		{"http://0.0.0.0:8090", false}, // a bind address, not a loopback visitor origin
		{"http://192.168.1.5:8090", false},
		{"not a url", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.base, func(t *testing.T) {
			if got := isLoopbackOrigin(tc.base); got != tc.want {
				t.Fatalf("isLoopbackOrigin(%q) = %v, want %v", tc.base, got, tc.want)
			}
		})
	}
}
