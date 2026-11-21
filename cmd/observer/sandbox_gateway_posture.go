package main

import "github.com/marmutapp/superbased-observer/internal/orgcontract"

// sandbox_gateway_posture.go is the posture seam for a sandbox gateway
// Observer owns on this node (OpenShell build lane O4, revision 1 R-17):
// whether its config is still what Observer wrote. It is core (built in
// every edition) so the managed integrity report can call it
// unconditionally; a sandbox driver that owns such a gateway registers its
// read-back from init, and a build without one leaves the seam nil, which
// reports nothing. The reading is TAMPER-EVIDENT, never tamper-proof: the
// local OS user owns the config, the record of what was started and the
// daemon alike.

// sandboxGatewayDrift is one read-back's verdict.
type sandboxGatewayDrift int

// The closed sandboxGatewayDrift vocabulary.
const (
	// sandboxGatewayDriftClean: nothing to report (no gateway, or its
	// config is Observer's own).
	sandboxGatewayDriftClean sandboxGatewayDrift = iota
	// sandboxGatewayDriftChanged: the config was changed or removed outside
	// Observer.
	sandboxGatewayDriftChanged
	// sandboxGatewayDriftUnknown: the read-back could not say; never read
	// as clean.
	sandboxGatewayDriftUnknown
)

// sandboxGatewayDriftFn reads back the gateway configs Observer owns, for
// the daemon config at configPath.
type sandboxGatewayDriftFn func(configPath string) sandboxGatewayDrift

// sandboxGatewayDriftObserved is the registered read-back (nil: no driver
// in this build owns a gateway).
var sandboxGatewayDriftObserved sandboxGatewayDriftFn

// sandboxGatewayPostureRows maps a verdict onto the report, one row each.
var sandboxGatewayPostureRows = []struct {
	drift sandboxGatewayDrift
	add   func(r *orgcontract.ManagedIntegrityReport)
}{
	{sandboxGatewayDriftChanged, func(r *orgcontract.ManagedIntegrityReport) {
		r.CaptureRisks = appendLabel(r.CaptureRisks, orgcontract.CaptureRiskSandboxGatewayConfigDrift)
	}},
	{sandboxGatewayDriftUnknown, func(r *orgcontract.ManagedIntegrityReport) {
		r.UnknownChecks = appendLabel(r.UnknownChecks, orgcontract.CaptureUnknownSandboxGatewayConfig)
	}},
}

// addSandboxGatewayPosture adds the gateway config posture to a managed
// integrity report: a closed label, never a path or a value.
func addSandboxGatewayPosture(configPath string, report *orgcontract.ManagedIntegrityReport) {
	if sandboxGatewayDriftObserved == nil {
		return
	}
	d := sandboxGatewayDriftObserved(configPath)
	for _, r := range sandboxGatewayPostureRows {
		if r.drift == d {
			r.add(report)
		}
	}
}
