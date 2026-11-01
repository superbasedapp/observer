package config

import (
	"strings"
	"testing"
)

// TestValidateTerminalSandboxBackendsAndFloor pins the two additive keys of
// sandbox plan v2 section 10: backends is a list of id-shaped, unique
// entries, and min_isolation is one of the closed class names.
func TestValidateTerminalSandboxBackendsAndFloor(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  TerminalSandboxConfig
		want string
	}{
		{"empty is fine", TerminalSandboxConfig{}, ""},
		{"a preference list", TerminalSandboxConfig{Backends: []string{"bwrap", "oci-runc"}}, ""},
		{"a floor", TerminalSandboxConfig{MinIsolation: "container"}, ""},
		{"a bad id", TerminalSandboxConfig{Backends: []string{"Bwrap"}}, "not a backend id"},
		{"a duplicate", TerminalSandboxConfig{Backends: []string{"bwrap", "bwrap"}}, "twice"},
		{"an unknown class", TerminalSandboxConfig{MinIsolation: "vm"}, "min_isolation"},
		{"none is not a floor", TerminalSandboxConfig{MinIsolation: "none"}, "min_isolation"},
	} {
		err := validateTerminalSandbox(tc.cfg)
		if tc.want == "" && err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: err %v, want %q", tc.name, err, tc.want)
		}
	}
}
