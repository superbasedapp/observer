package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestRegistrationStableMCPCommandIsOptIn pins the DEC-12 gate (FU-24): the
// bare MCP command needs the explicit [observer.mcp] stable_command opt-in
// AND a managed enrolment; a managed node without the opt-in keeps today's
// command.
func TestRegistrationStableMCPCommandIsOptIn(t *testing.T) {
	prev := launcherManagedNode
	launcherManagedNode = func(context.Context, string) bool { return true }
	t.Cleanup(func() { launcherManagedNode = prev })
	cases := []struct {
		name, body string
		want       bool
	}{
		{"default off on a managed node", "[org_client]\nenabled = true\norg_server_url = \"https://org.example\"\n", false},
		{"opt-in without the org client", "[observer.mcp]\nstable_command = true\n", false},
		{"opt-in on a managed node", "[observer.mcp]\nstable_command = true\n\n[org_client]\nenabled = true\norg_server_url = \"https://org.example\"\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := registrationStableMCPCommand(p); got != tc.want {
				t.Errorf("registrationStableMCPCommand = %v, want %v", got, tc.want)
			}
		})
	}
}
