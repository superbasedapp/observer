//go:build !sbo_omit_capture_proxy

package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/proxy"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// TestRouteLanePrefixIsOneValue: proxyroute writes route lane ids and the
// proxy resolves them; the prefix must be the same string on both sides.
func TestRouteLanePrefixIsOneValue(t *testing.T) {
	if proxyroute.RouteLanePrefix != proxy.RouteLanePrefix {
		t.Fatalf("proxyroute.RouteLanePrefix %q != proxy.RouteLanePrefix %q", proxyroute.RouteLanePrefix, proxy.RouteLanePrefix)
	}
}
