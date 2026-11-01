//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestOCITrustConditionOnlyWhereTheDriverIsActive (N2): the full
// devcontainer row (every ignored field) is read only when the sandbox is
// on, the container driver's component is selected and an oci-* row is
// listed. Since the proposed N2 ruling (lane SBX-P3D) every install also
// reads the file for initializeCommand alone (repo/devcontainer-host).
func TestOCITrustConditionOnlyWhereTheDriverIsActive(t *testing.T) {
	cases := []struct {
		name string
		cfg  func(t *testing.T) config.Config
		want bool
	}{
		{"default install", func(*testing.T) config.Config { return config.Default() }, false},
		{"driver active, oci-runc listed", func(t *testing.T) config.Config { return ociTestConfig(t, true, "oci-runc") }, true},
		{"driver active, oci-runsc listed", func(t *testing.T) config.Config { return ociTestConfig(t, true, "oci-runsc") }, true},
		{"sandbox off", func(t *testing.T) config.Config {
			c := ociTestConfig(t, true, "oci-runc")
			c.Terminal.Sandbox.Enabled = false
			return c
		}, false},
		{"component not selected", func(t *testing.T) config.Config { return ociTestConfig(t, false, "oci-runc") }, false},
		{"no oci row listed", func(t *testing.T) config.Config { return ociTestConfig(t, true, "bwrap") }, false},
	}
	sample := []byte(`{"initializeCommand":"x","postCreateCommand":"y"}`)
	for _, tc := range cases {
		cfg := tc.cfg(t)
		snap := componentSnapshotForConfig(cfg)
		_, got := ociTrustCondition(cfg, snap)
		if got != tc.want {
			t.Errorf("%s: condition %v, want %v", tc.name, got, tc.want)
		}
		paths, parse := repoTrustConditional(cfg, snap)
		if parse == nil {
			t.Fatalf("%s: no parser for the devcontainer row", tc.name)
		}
		fields, _, err := parse(sample)
		wantFields := "initializeCommand"
		if tc.want {
			wantFields = "initializeCommand,postCreateCommand"
		}
		if err != nil || strings.Join(fields, ",") != wantFields {
			t.Errorf("%s: fields %v %v, want %s", tc.name, fields, err, wantFields)
		}
		full := false
		for _, p := range paths {
			if p.Class == agentconfig.TrustDevcontainer && slices.Contains(p.Sources, "repo/devcontainer") {
				full = true
			}
		}
		if full != tc.want {
			t.Errorf("%s: full devcontainer row %v, want %v", tc.name, full, tc.want)
		}
	}
}
