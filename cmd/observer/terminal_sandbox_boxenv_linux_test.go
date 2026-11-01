//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox_landlock && !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox_seatbelt && !sbo_omit_terminals_sandbox_apple_container && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxlandlock"
)

// TestLinuxDriverEnvDropsTheCanary is TestDriverEnvDropsTheCanary for the
// Linux-only backends (OCI, the microVM, Landlock).
func TestLinuxDriverEnvDropsTheCanary(t *testing.T) {
	cases := map[string][]string{
		"oci":      ociContainerEnv(sandboxCanaryParent("linux")),
		"vm":       vmRunEnv(sandboxCanaryParent("linux")),
		"landlock": landlockEnv(sandboxCanaryParent("linux"), sandboxlandlock.PlanInput{TempDir: "/tmp/r", SocketDir: "/tmp/r/s"}, nil),
	}
	for name, env := range cases {
		if l := leaked(env); len(l) > 0 {
			t.Errorf("%s: %v crossed into the box", name, l)
		}
		if !hasEnv(env, "ANTHROPIC_API_KEY=provider-dummy") {
			t.Errorf("%s: the provider variable the launch named did not cross", name)
		}
	}
}
