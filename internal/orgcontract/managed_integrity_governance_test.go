package orgcontract

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestGovernanceCaptureRiskLabels pins the lane w6-governance labels (CLI-1b,
// S-15): each is a standing condition the normalizer accepts on both sides,
// a located item keeps its tool and home-relative label, and a report
// carrying one reads at risk.
func TestGovernanceCaptureRiskLabels(t *testing.T) {
	t.Parallel()
	for _, label := range []string{CaptureRiskShellWrapMissing, CaptureRiskVendorPolicyBlocksMCP, CaptureRiskVendorPolicyPinsRoute} {
		if !validCaptureRisk(label) || !isStandingCaptureRisk(label) || captureRiskRank[label] == 0 {
			t.Errorf("%s: valid %v standing %v ranked %v", label, validCaptureRisk(label), isStandingCaptureRisk(label), captureRiskRank[label] != 0)
		}
	}
	items := NormalizeCaptureRiskItems([]CaptureRiskItem{
		{Risk: CaptureRiskVendorPolicyBlocksMCP, Tool: "droid", File: "~/.factory"},
		{Risk: CaptureRiskVendorPolicyPinsRoute, Tool: "cline", File: "~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/cache"},
	})
	if len(items) != 2 || items[0].Tool == "" || items[0].File == "" || items[1].Tool == "" || items[1].File == "" {
		t.Fatalf("located items lost their place: %+v", items)
	}
	rep := ManagedIntegrityReport{
		CaptureCheckVersion:     ManagedCaptureCheckVersion,
		RouteObservationVersion: ManagedRouteObservationVersion,
		ConfigLayerVersion:      ManagedConfigLayerVersion,
		CaptureRisks:            []string{CaptureRiskShellWrapMissing},
	}.NormalizeLabels()
	if !reflect.DeepEqual(rep.CaptureRisks, []string{CaptureRiskShellWrapMissing}) {
		t.Fatalf("normalized risks = %v", rep.CaptureRisks)
	}
	if v := rep.OverallHealth(); v.Health != ManagedHealthAtRisk || v.Reason != ManagedHealthReasonCaptureRisk {
		t.Fatalf("overall = %+v, want at_risk / capture_risk", v)
	}
}

// TestGovernanceLabelsCompat: an older node never sends the new labels, so
// its report is unchanged; a new node's report decoded by a reader that
// predates them (a frozen copy of the pre-lane label set) keeps every field
// it knows and drops only the labels it does not know.
func TestGovernanceLabelsCompat(t *testing.T) {
	t.Parallel()
	oldBody := `{"machine_identity":"m","sibling_observers":0,"route_drift":0,"capture_check_version":1,"capture_risks":["route_repaired"],"route_observation_version":1,"config_layer_version":1}`
	var fromOld ManagedIntegrityReport
	if err := json.Unmarshal([]byte(oldBody), &fromOld); err != nil {
		t.Fatal(err)
	}
	if got := fromOld.NormalizeLabels().CaptureRisks; !reflect.DeepEqual(got, []string{CaptureRiskRouteRepaired}) {
		t.Fatalf("an older node's risks = %v", got)
	}
	newRep := ManagedIntegrityReport{
		CaptureCheckVersion: ManagedCaptureCheckVersion,
		CaptureRisks:        []string{CaptureRiskRouteRepaired, CaptureRiskShellWrapMissing, CaptureRiskVendorPolicyBlocksMCP},
		CaptureRiskItems:    []CaptureRiskItem{{Risk: CaptureRiskVendorPolicyBlocksMCP, Tool: "droid", File: "~/.factory"}},
	}.NormalizeLabels()
	raw, err := json.Marshal(newRep)
	if err != nil {
		t.Fatal(err)
	}
	var older struct {
		CaptureRisks     []string          `json:"capture_risks"`
		CaptureRiskItems []CaptureRiskItem `json:"capture_risk_items"`
	}
	if err := json.Unmarshal(raw, &older); err != nil {
		t.Fatalf("an older reader cannot decode the new report: %v", err)
	}
	preLane := map[string]bool{CaptureRiskRouteRepaired: true}
	var kept []string
	for _, l := range older.CaptureRisks {
		if preLane[l] {
			kept = append(kept, l)
		}
	}
	if !reflect.DeepEqual(kept, []string{CaptureRiskRouteRepaired}) {
		t.Fatalf("an older reader keeps %v, want only the label it knows", kept)
	}
}
