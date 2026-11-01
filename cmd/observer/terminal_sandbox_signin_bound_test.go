//go:build !sbo_omit_terminals_sandbox_landlock && !sbo_omit_terminals_sandbox_seatbelt && !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox_apple_container && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import "testing"

// TestSandboxSignInBoundRowsAreNamed (operator ruling P-183): exactly the
// drivers that bind or grant the tool's own state implement
// sandboxStateBinder (bubblewrap is the runtime's own path; the container
// driver says it in its notices, where it knows the projection), and the
// launch names only a tool with a sign-in row.
func TestSandboxSignInBoundRowsAreNamed(t *testing.T) {
	t.Parallel()
	for name, d := range map[string]any{"landlock": &landlockDriver{}, "seatbelt": &seatbeltDriver{}, "mxc": &mxcDriver{}, "apple": &appleDriver{}} {
		if b, ok := d.(sandboxStateBinder); !ok || !b.bindsToolState() {
			t.Errorf("%s does not say it binds the tool's state", name)
		}
	}
	for name, d := range map[string]any{"oci": &ociDriver{}, "hosted": &hostedDriver{}} {
		if _, ok := d.(sandboxStateBinder); ok {
			t.Errorf("%s claims to bind the tool's state", name)
		}
	}
	if sandboxSignInSharedTool("claude-code") != "claude-code" || sandboxSignInSharedTool("gemini-cli") != "" {
		t.Fatal("the shared tool is not the sign-in row")
	}
}
