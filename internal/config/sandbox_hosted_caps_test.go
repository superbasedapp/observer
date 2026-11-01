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
