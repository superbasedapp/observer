//go:build !sbo_omit_security

package main

import (
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policyfam/securityscanning"
)

// gateTrustFloorBody sets every commit-gate and repository-trust floor key.
const gateTrustFloorBody = `{"require":{"commit_gate":"quick_scan","quick_scan_budget_s":30,"max_scan_staleness_min":30,"min_blocking_severity":"low","history_scan_on_enrol":true,"prelaunch_trust":"refuse"}}`

// TestSecurityGateTrustFloorsNotBuilt (lane SEC-GATE5 milestone 4, updated
// in lane SEC-P4 decision 9 and lane LEFT-SEC milestone 1): every
// commit-gate and repository-trust floor key is a row of the read seam's
// table now. require.commit_gate and require.prelaunch_trust apply on a
// managed node only (not_applicable: individual_node elsewhere) and write
// their floor-only fields; the four [security.scanning] axes (quick scan
// budget, scan staleness, least blocking severity, history scan at
// enrolment) apply on an individual and a managed node alike and raise
// their [security.scanning] keys.
func TestSecurityGateTrustFloorsNotBuilt(t *testing.T) {
	scanning := []string{
		securityscanning.AxisQuickScanBudget, securityscanning.AxisMaxScanStaleness,
		securityscanning.AxisMinBlockingSeverity, securityscanning.AxisHistoryScanOnEnrol,
	}
	built := append([]string{securityscanning.AxisCommitGate, securityscanning.AxisPrelaunchTrust}, scanning...)
	for _, k := range built {
		if _, ok := securityFloorNotBuilt[k]; ok {
			t.Errorf("%s is built since lane SEC-P4 and still has a not_built reason", k)
		}
		found := false
		for _, r := range securityFloorRows {
			found = found || r.Axis == k
		}
		if !found {
			t.Errorf("%s is no row of securityFloorRows", k)
		}
	}
	// Every key of the one table is a family axis with no row (contains,
	// not an exact count: later lanes add their own not_built keys).
	for k := range securityFloorNotBuilt {
		if _, ok := securityscanning.LookupAxis(k); !ok {
			t.Errorf("securityFloorNotBuilt names %s, no axis of the family", k)
		}
		for _, r := range securityFloorRows {
			if r.Axis == k {
				t.Errorf("%s is a row of securityFloorRows and has a not_built reason; keep one", k)
			}
		}
	}
	for _, managed := range []bool{false, true} {
		withSecurityScanningNode(t, managed, config.DefaultSecurityConfig(), "security.trust", "security.secrets")
		spec := compileFloor(t, gateTrustFloorBody)
		facts := secScanning.facts()
		states := map[string]securityscanning.KeyState{}
		for _, ks := range securityscanning.Evaluate(spec, facts) {
			states[ks.Key] = ks
		}
		for _, k := range built {
			ks, ok := states[k]
			if !ok {
				t.Fatalf("managed=%v: %s not reported", managed, k)
			}
			switch {
			case (k == securityscanning.AxisCommitGate || k == securityscanning.AxisPrelaunchTrust) && !managed:
				// Managed-only (the trust floor since P-125, audit SEC-P4
				// F4): an individual node never reads it.
				if ks.State != securityscanning.StateNotApplicable || ks.Reason != securityscanning.ReasonIndividualNode {
					t.Errorf("individual node: %s = %s", k, ks)
				}
			case k == securityscanning.AxisCommitGate || k == securityscanning.AxisPrelaunchTrust:
				if ks.State != securityscanning.StateApplied {
					t.Errorf("managed=%v: %s = %s, want applied", managed, k, ks)
				}
			default:
				if ks.State != securityscanning.StateApplied {
					t.Errorf("managed=%v: %s = %s, want applied", managed, k, ks)
				}
			}
		}
		installFloor(t, gateTrustFloorBody, 1, true)
		local := config.DefaultSecurityConfig()
		want := local
		want.Scanning = config.SecurityScanningConfig{QuickScanBudgetS: 30, MaxScanStalenessMin: 30, MinBlockingSeverity: "low", HistoryScanOnEnrol: true}
		if managed {
			want.CommitGateFloor, want.PrelaunchTrustFloor = "quick_scan", "refuse"
		}
		if got := securityFloorsApplied(local); !reflect.DeepEqual(got, want) {
			t.Fatalf("managed=%v: the seam returned %+v, want the floor-only fields (managed) and the [security.scanning] keys raised", managed, got)
		}
	}
}
