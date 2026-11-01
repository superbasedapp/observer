package orgcontract

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestSandboxPostureCompatBothDirections: a node without the posture sends
// no sandbox keys at all (its envelope is unchanged), an old agent's
// envelope decodes on a new server with both fields nil, and a new agent's
// envelope decodes on an old server shape that lacks the fields.
func TestSandboxPostureCompatBothDirections(t *testing.T) {
	empty, err := json.Marshal(PushEnvelope{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(empty), "sandbox_") {
		t.Fatalf("an envelope without the posture carries a sandbox key: %s", empty)
	}
	var fromOld PushEnvelope
	if err := json.Unmarshal([]byte(`{"terminal_summaries":[]}`), &fromOld); err != nil {
		t.Fatal(err)
	}
	if fromOld.SandboxPosture != nil || fromOld.SandboxCapability != nil {
		t.Fatal("an old agent's envelope decoded with posture")
	}
	newEnv := PushEnvelope{
		SandboxPosture:    []SandboxPostureRow{{Day: "2026-10-20", IsolationClass: "process", Runs: 1}},
		SandboxCapability: &SandboxCapabilityRow{Backends: []string{"bwrap"}, MaxClass: "process"},
	}
	raw, err := json.Marshal(newEnv)
	if err != nil {
		t.Fatal(err)
	}
	var oldServer struct {
		TerminalSummaries []TerminalSummaryRow `json:"terminal_summaries,omitempty"`
	}
	if err := json.Unmarshal(raw, &oldServer); err != nil {
		t.Fatalf("an old server shape refused the new keys: %v", err)
	}
	var round PushEnvelope
	if err := json.Unmarshal(raw, &round); err != nil || len(round.SandboxPosture) != 1 || round.SandboxCapability.MaxClass != "process" {
		t.Fatalf("round trip: %v %+v", err, round.SandboxCapability)
	}
}
