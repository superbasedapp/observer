package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
)

// TestManagedRouteProofRows (OSH-R-008): the one route rule a managed hard
// budget's launch coverage trusts accepts only the node's own proxy (a
// loopback spelling, the proxy's port, path "" or "/v1"). Every spelling a
// sandboxed or misconfigured run could present that does not reach that
// listener is "route unknown", so it can be refused but never admitted as
// proven.
func TestManagedRouteProofRows(t *testing.T) {
	const proxy = "http://127.0.0.1:8820"
	for _, tc := range []struct {
		got  string
		want bool
	}{
		{"http://127.0.0.1:8820", true},
		{"http://localhost:8820/v1/", true},
		{"http://[::1]:8820", true},
		// The Windows MXC box's model proxy lane: the helper's own port and
		// a per-run token path. Not the node proxy's listener, so not proof.
		{sandboxmxc.BaseURL(51234, "dG9rZW4"), false},
		{"http://127.0.0.1:8820/t/dG9rZW4", false},
		// Other ways to name a host that is not this machine's loopback.
		{"http://127.0.0.1:8820@evil.example", false},
		{"http://127.0.0.1.evil.example:8820", false},
		{"http://host.docker.internal:8820", false},
		{"http://host.openshell.internal:8820", false},
		{"http://10.0.2.2:8820", false},
		{"http://127.0.0.1:8821", false},
		{"http://127.0.0.1:8820/proxy", false},
		{"", false},
	} {
		if got := urlRoutesToProxy(tc.got, proxy); got != tc.want {
			t.Errorf("urlRoutesToProxy(%q) = %v, want %v", tc.got, got, tc.want)
		}
	}
}
