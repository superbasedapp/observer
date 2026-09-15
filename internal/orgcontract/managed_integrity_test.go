package orgcontract

import "testing"

// TestManagedIntegrityReportState pins the counts→state derivation the admin
// Control Center badge renders (Arc 4 P6b, plan §9).
func TestManagedIntegrityReportState(t *testing.T) {
	cases := []struct {
		name     string
		siblings int
		drift    int
		want     string
	}{
		{"clean", 0, 0, ManagedIntegrityOK},
		{"sibling only", 2, 0, ManagedIntegritySibling},
		{"drift only", 0, 3, ManagedIntegrityRouteDrift},
		{"both", 1, 1, ManagedIntegrityBoth},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := ManagedIntegrityReport{SiblingObservers: tc.siblings, RouteDrift: tc.drift}
			if got := r.State(); got != tc.want {
				t.Fatalf("State() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestManagedIntegrityNormalizeLabelsEnforcesContentFloor(t *testing.T) {
	got := (ManagedIntegrityReport{
		CaptureCheckVersion: 99,
		SiblingDetail:       []string{"wsl-mnt/windows", "wsl-mnt:alice/windows", "/home/alice/db"},
		DriftedTools:        []string{"codex", "secret-tool"},
		CaptureRisks:        []string{CaptureRiskHookConfigChanged, "secret=/home/alice"},
		UnknownChecks:       []string{CaptureUnknownRegistryMissing, "permission denied: /home/alice"},
	}).NormalizeLabels()
	if got.CaptureCheckVersion != 0 || len(got.CaptureRisks) != 0 || len(got.UnknownChecks) != 0 {
		t.Fatalf("future capture vocabulary was certified as current: %+v", got)
	}
	if len(got.SiblingDetail) != 1 || got.SiblingDetail[0] != "wsl-mnt/windows" ||
		len(got.DriftedTools) != 1 || got.DriftedTools[0] != "codex" {
		t.Fatalf("normalized report crossed or lost the closed vocabulary: %+v", got)
	}
	current := (ManagedIntegrityReport{
		CaptureCheckVersion: ManagedCaptureCheckVersion,
		CaptureRisks:        []string{CaptureRiskHookConfigChanged, "/home/alice"},
		UnknownChecks:       []string{CaptureUnknownRegistryMissing, "raw error"},
	}).NormalizeLabels()
	if len(current.CaptureRisks) != 1 || current.CaptureRisks[0] != CaptureRiskHookConfigChanged ||
		len(current.UnknownChecks) != 1 || current.UnknownChecks[0] != CaptureUnknownRegistryMissing {
		t.Fatalf("current capture vocabulary was not normalized: %+v", current)
	}
}
