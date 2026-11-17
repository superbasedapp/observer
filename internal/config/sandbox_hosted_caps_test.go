package config

import (
	"strings"
	"testing"
)

// TestHostedCapsGoDownToFive (live run 2026-10-23, finding F10: a
// min_session_minutes floor of 15 kept max_run_minutes at 15 or more): a
// five-minute box is a valid config once both caps are lowered, below five
// is refused, and a session floor above the run cap names both values.
func TestHostedCapsGoDownToFive(t *testing.T) {
	base := Default().Terminal.Sandbox.Hosted
	ok := base
	ok.MinSessionMinutes, ok.MaxRunMinutes = 5, 5
	if err := validateTerminalSandboxHosted(ok); err != nil {
		t.Errorf("five-minute caps: %v", err)
	}
	low := ok
	low.MinSessionMinutes = 4
	if err := validateTerminalSandboxHosted(low); err == nil {
		t.Error("a four-minute session floor was accepted")
	}
	mixed := base
	mixed.MaxRunMinutes = 5
	err := validateTerminalSandboxHosted(mixed)
	if err == nil || !strings.Contains(err.Error(), "(30)") || !strings.Contains(err.Error(), "(5)") {
		t.Errorf("a session floor above the run cap: %v", err)
	}
}

// TestHostedDockerTableValidated (lane SBX-DOCKER): the docker table's
// region, template and box_binary go through the same shape checks as the
// other providers', an OCI image reference is a valid template, and its
// endpoint is refused (E2B only).
func TestHostedDockerTableValidated(t *testing.T) {
	base := Default().Terminal.Sandbox.Hosted
	for _, tc := range []struct {
		name string
		p    TerminalSandboxHostedProviderConfig
		ok   bool
	}{
		{"empty", TerminalSandboxHostedProviderConfig{}, true},
		{"image reference", TerminalSandboxHostedProviderConfig{Template: "ghcr.io/acme/agent:1.2"}, true},
		{"bad region", TerminalSandboxHostedProviderConfig{Region: "Not A Region"}, false},
		{"relative box binary", TerminalSandboxHostedProviderConfig{BoxBinary: "bin/observer"}, false},
		{"endpoint", TerminalSandboxHostedProviderConfig{Endpoint: "https://connect.docker.com"}, false},
	} {
		c := base
		c.Docker = tc.p
		err := validateTerminalSandboxHosted(c)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", tc.name, err)
		}
		if err != nil && !strings.Contains(err.Error(), "hosted.docker") {
			t.Errorf("%s: the refusal does not name the table: %v", tc.name, err)
		}
	}
}
