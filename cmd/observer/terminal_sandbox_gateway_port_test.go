//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// TestSandboxGatewayPortFuncIsTheSandboxs pins the dashboard's injected seam to
// internal/sandbox's own answer, so the assessments' E5 rule refuses the port
// the in-box gateway really listens on, including when the proxy itself sits
// on the gateway's default port.
func TestSandboxGatewayPortFuncIsTheSandboxs(t *testing.T) {
	f := sandboxGatewayPortFunc()
	if f == nil {
		t.Fatal("no gateway-port seam in a build with the sandbox")
	}
	for _, proxyPort := range []int{8820, 3128, 3129, 1} {
		if got, want := f(proxyPort), sandbox.GatewayPort(proxyPort); got != want {
			t.Errorf("proxy port %d: seam says %d, sandbox says %d", proxyPort, got, want)
		}
	}
}
