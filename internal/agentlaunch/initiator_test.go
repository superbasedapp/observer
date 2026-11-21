package agentlaunch

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// TestAttributeRows walks one case per attribution row, plus the orderings
// between them.
func TestAttributeRows(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		f        CallerFacts
		want     termrun.Origin
		wantRule string
	}{
		{"I1 ancestor with session", CallerFacts{Front: FrontCLI, AgentAncestor: true, AncestorSession: "s-anc"}, termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "s-anc"}, "I1-agent-ancestor"},
		{"I1 ancestor wins over a dashboard front", CallerFacts{Front: FrontDashboard, AgentAncestor: true, AncestorSession: "s-anc"}, termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "s-anc"}, "I1-agent-ancestor"},
		{"I1 ancestor without session takes the marker's", CallerFacts{Front: FrontCLI, AgentAncestor: true, AgentEnv: true, EnvSession: "s-env"}, termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "s-env"}, "I1-agent-ancestor"},
		{"I1 ancestor session wins over the marker's", CallerFacts{Front: FrontCLI, AgentAncestor: true, AncestorSession: "s-anc", AgentEnv: true, EnvSession: "s-env"}, termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "s-anc"}, "I1-agent-ancestor"},
		{"I1 ancestor with no session at all", CallerFacts{Front: FrontCLI, AgentAncestor: true}, termrun.Origin{Initiator: termrun.InitiatorAgent}, "I1-agent-ancestor"},
		{"I2 env marker only", CallerFacts{Front: FrontCLI, AgentEnv: true, EnvSession: "s-env"}, termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "s-env"}, "I2-agent-env-marker"},
		{"I3 unidentified dashboard caller", CallerFacts{Front: FrontDashboard}, termrun.Origin{Initiator: termrun.InitiatorUnknown}, "I3-unidentified"},
		{"I3 unidentified cli caller", CallerFacts{Front: FrontCLI}, termrun.Origin{Initiator: termrun.InitiatorUnknown}, "I3-unidentified"},
		{"I4 dashboard", CallerFacts{Front: FrontDashboard, Identified: true}, termrun.Origin{Initiator: termrun.InitiatorHumanDashboard}, "I4-dashboard"},
		{"I5 cli", CallerFacts{Front: FrontCLI, Identified: true}, termrun.Origin{Initiator: termrun.InitiatorHumanCLI}, "I5-cli"},
		{"I5 unknown front reads as cli", CallerFacts{Identified: true}, termrun.Origin{Initiator: termrun.InitiatorHumanCLI}, "I5-cli"},
		{"a marker session with a space is dropped", CallerFacts{AgentEnv: true, EnvSession: "a b"}, termrun.Origin{Initiator: termrun.InitiatorAgent}, "I2-agent-env-marker"},
	} {
		got := Attribute(tc.f)
		if got.Origin != tc.want || got.Rule != tc.wantRule {
			t.Errorf("%s: Attribute = %+v (%s), want %+v (%s)", tc.name, got.Origin, got.Rule, tc.want, tc.wantRule)
		}
	}
}
