package sandboxopenshell

import (
	"strings"
	"testing"
)

// TestDriverAccepted: one case per driver row, on a tested row with and
// without a Podman launch receipt (the P6 lift, lane FU7).
func TestDriverAccepted(t *testing.T) {
	t.Parallel()
	with := TestedVersion{Version: Version{Major: 0, Minor: 1, Patch: 6}, PodmanReceipt: "receipts/o1b/x.json"}
	without := TestedVersion{Version: Version{Major: 0, Minor: 1, Patch: 6}}
	for _, tc := range []struct {
		driver string
		row    TestedVersion
		want   bool
		engine bool
	}{
		{"docker", without, true, true},
		{"docker", with, true, true},
		{"podman", with, true, false},
		{"podman", without, false, false},
		{"podman", TestedVersion{Version: with.Version, PodmanReceipt: "PENDING: the passing receipt"}, false, false},
		{"podman", TestedVersion{Version: with.Version, PodmanReceipt: "  "}, false, false},
		{"lxc", with, false, false},
		{"", with, false, false},
	} {
		if got := DriverAccepted(tc.driver, tc.row); got != tc.want {
			t.Errorf("DriverAccepted(%q, receipt=%q) = %v", tc.driver, tc.row.PodmanReceipt, got)
		}
		if got := DriverHasEngineIdentity(tc.driver); got != tc.engine {
			t.Errorf("DriverHasEngineIdentity(%q) = %v", tc.driver, got)
		}
	}
	if r := driverRefusal("podman", without.Version); !strings.Contains(r, "no live receipt measured on OpenShell 0.1.6") {
		t.Errorf("podman refusal: %s", r)
	}
	// FU7-A1: the shipped table refuses Podman on 0.1.6 until a real
	// receipt path replaces the placeholder.
	shipped, ok := testedRow(Version{Major: 0, Minor: 1, Patch: 6})
	if !ok || DriverAccepted("podman", shipped) || PodmanMeasuredVersions() != "none" {
		t.Errorf("the shipped table takes Podman: receipt %q, measured %s", shipped.PodmanReceipt, PodmanMeasuredVersions())
	}
}

// TestProbePodmanWithAReceipt drives probe rows P6 and P8e with a
// synthetic tested row that names a Podman launch receipt (the lift once
// the receipt is written in): P6 takes the Podman driver, and P8e does not
// apply to it even with no engine ID read.
func TestProbePodmanWithAReceipt(t *testing.T) {
	t.Parallel()
	row := TestedVersion{Version: Version{Major: 0, Minor: 1, Patch: 6}, PodmanReceipt: "receipts/o1b/podman-launch.json"}
	v := VersionResult{Version: row.Version, Row: row}
	f := ProbeFacts{Driver: "podman"}
	for _, r := range probeRules {
		switch r.id {
		case "P6", "P8e":
			if verdict, reason := r.verdict(f, v); verdict != ok {
				t.Errorf("row %s refused Podman with a receipt: %s %s", r.id, verdict, reason)
			}
		}
	}
	f.Driver = "docker"
	for _, r := range probeRules {
		if r.id == "P8e" {
			if verdict, _ := r.verdict(f, v); verdict != VerdictEngineUnread {
				t.Errorf("row P8e on Docker with no engine ID: %q", verdict)
			}
		}
	}
}
