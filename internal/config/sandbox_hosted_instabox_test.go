package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestHostedInstaBoxTableValidated: the InstaBox provider table is checked
// like the others: a template name and an absolute box_binary pass; a
// relative box_binary, a malformed region or template, and an endpoint (E2B
// only) are refused, each naming the instabox table.
func TestHostedInstaBoxTableValidated(t *testing.T) {
	base := Default().Terminal.Sandbox.Hosted
	ok := base
	ok.InstaBox = TerminalSandboxHostedProviderConfig{Template: "agent-browser@2026-10-15.4", BoxBinary: filepath.Join(t.TempDir(), "observer")}
	if err := validateTerminalSandboxHosted(ok); err != nil {
		t.Errorf("a valid table: %v", err)
	}
	for name, p := range map[string]TerminalSandboxHostedProviderConfig{
		"relative box_binary": {BoxBinary: "bin/observer"},
		"bad region":          {Region: "us west"},
		"bad template":        {Template: "a b"},
		"endpoint":            {Endpoint: "https://api.instabox.sh"},
	} {
		c := base
		c.InstaBox = p
		err := validateTerminalSandboxHosted(c)
		if err == nil || !strings.Contains(err.Error(), "hosted.instabox") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
