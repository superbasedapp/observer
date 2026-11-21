package termrun

import (
	"strings"
	"testing"
)

// TestOriginNormalized walks one case per normalization rule: only the
// closed set is recorded, and a parent session only for an agent.
func TestOriginNormalized(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		in   Origin
		want Origin
	}{
		{"zero stays zero", Origin{}, Origin{}},
		{"unknown initiator dropped", Origin{Initiator: "robot", ParentSessionID: "s1"}, Origin{}},
		{"human dashboard keeps no parent", Origin{Initiator: InitiatorHumanDashboard, ParentSessionID: "s1"}, Origin{Initiator: InitiatorHumanDashboard}},
		{"human cli", Origin{Initiator: InitiatorHumanCLI}, Origin{Initiator: InitiatorHumanCLI}},
		{"unknown keeps no parent", Origin{Initiator: InitiatorUnknown, ParentSessionID: "s1"}, Origin{Initiator: InitiatorUnknown}},
		{"agent with parent", Origin{Initiator: InitiatorAgent, ParentSessionID: "sess-1"}, Origin{Initiator: InitiatorAgent, ParentSessionID: "sess-1"}},
		{"agent without parent", Origin{Initiator: InitiatorAgent}, Origin{Initiator: InitiatorAgent}},
		{"agent parent with a space dropped", Origin{Initiator: InitiatorAgent, ParentSessionID: "a b"}, Origin{Initiator: InitiatorAgent}},
		{"agent parent too long dropped", Origin{Initiator: InitiatorAgent, ParentSessionID: strings.Repeat("x", 257)}, Origin{Initiator: InitiatorAgent}},
	} {
		if got := tc.in.Normalized(); got != tc.want {
			t.Errorf("%s: Normalized() = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}
