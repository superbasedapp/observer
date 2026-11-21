package orgcontract

import (
	"encoding/json"
	"slices"
	"testing"
)

// sandboxgateway_posture_test.go pins the compat invariant for the sandbox
// gateway config drift posture values (OpenShell lane O4) in both
// directions: a new node's labels survive a new server's normalization; an
// unknown label (what an older server sees, and what this server sees from
// a future node) is dropped without dropping the report; an older node
// that never sends the labels is read exactly as before.

func TestSandboxGatewayPostureKeptByThisServer(t *testing.T) {
	r := ManagedIntegrityReport{
		CaptureCheckVersion: ManagedCaptureCheckVersion,
		CaptureRisks:        []string{CaptureRiskSandboxGatewayConfigDrift},
		UnknownChecks:       []string{CaptureUnknownSandboxGatewayConfig},
	}.NormalizeLabels()
	if !slices.Contains(r.CaptureRisks, CaptureRiskSandboxGatewayConfigDrift) {
		t.Fatalf("the drift label was dropped: %v", r.CaptureRisks)
	}
	if !slices.Contains(r.UnknownChecks, CaptureUnknownSandboxGatewayConfig) {
		t.Fatalf("the unknown check was dropped: %v", r.UnknownChecks)
	}
	if !isStandingCaptureRisk(CaptureRiskSandboxGatewayConfigDrift) {
		t.Fatal("the drift label is not a standing condition")
	}
}

// TestUnknownPostureValueIsIgnoredNotAnError is the older-server direction:
// a server that does not know a label drops it from the normalized report
// and keeps every label it does know. The future label stands in for this
// lane's labels as an older server sees them.
func TestUnknownPostureValueIsIgnoredNotAnError(t *testing.T) {
	raw := []byte(`{"capture_check_version":1,"capture_risks":["hook_config_changed","some_future_gateway_label"],"unknown_checks":["some_future_gateway_check"]}`)
	var r ManagedIntegrityReport
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("an unknown value made the report fail to decode: %v", err)
	}
	r = r.NormalizeLabels()
	if !slices.Equal(r.CaptureRisks, []string{CaptureRiskHookConfigChanged}) || len(r.UnknownChecks) != 0 {
		t.Fatalf("normalized = risks %v unknown %v", r.CaptureRisks, r.UnknownChecks)
	}
}

// TestOlderNodeSendsNoGatewayPosture is the older-node direction: a report
// without the labels normalizes with none of them added.
func TestOlderNodeSendsNoGatewayPosture(t *testing.T) {
	r := ManagedIntegrityReport{CaptureCheckVersion: ManagedCaptureCheckVersion, CaptureRisks: []string{CaptureRiskHookConfigChanged}}.NormalizeLabels()
	if slices.Contains(r.CaptureRisks, CaptureRiskSandboxGatewayConfigDrift) || slices.Contains(r.UnknownChecks, CaptureUnknownSandboxGatewayConfig) {
		t.Fatalf("an older node's report gained a gateway label: %+v", r)
	}
}
