package componentsvc

import (
	"strings"
	"testing"
)

// TestManualStepsCarryDashboardLink pins B-CS4: every manual teardown step
// that names a CLI verb also names the dashboard page that undoes it, so a
// preview never sends the reader only to a terminal.
func TestManualStepsCarryDashboardLink(t *testing.T) {
	prev := teardownGOOS
	t.Cleanup(func() { teardownGOOS = prev })
	teardownGOOS = "linux"
	for _, tc := range []struct {
		id       string
		wantLink string
	}{
		{"integration.statusline", "/settings?section=tools"},
		{"integration.shell-wrap", "/settings?section=terminal"},
		{"agentaccess.relay", "/security?tab=mcp"},
		{"proxy.routing", "/routing"},
		{"security.githooks", "/code-security?tab=baselines"},
		{"security.provenance", "/code-security?tab=baselines"},
		{"integration.service", "/settings?section=health"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			steps := TeardownFor(tc.id)
			if len(steps) != 1 {
				t.Fatalf("steps = %+v", steps)
			}
			st := steps[0]
			if st.Kind != StepManual || st.Command == "" {
				t.Fatalf("not a manual step with a command: %+v", st)
			}
			if st.Link != tc.wantLink {
				t.Errorf("Link = %q, want %q", st.Link, tc.wantLink)
			}
			if !strings.HasPrefix(st.Link, "/") || st.LinkLabel == "" {
				t.Errorf("link %q / label %q must be an in-app path with a label", st.Link, st.LinkLabel)
			}
		})
	}
}

// TestRunTeardownCarriesLink pins that a manual outcome keeps the step's
// dashboard link beside its command.
func TestRunTeardownCarriesLink(t *testing.T) {
	s := &Service{}
	out := s.runTeardown([]Step{{Component: "x", Kind: StepManual, Command: "observer x", Link: "/routing", LinkLabel: "Routing", What: "w"}}, true)
	if len(out) != 1 || out[0].Link != "/routing" || out[0].LinkLabel != "Routing" || out[0].Command != "observer x" {
		t.Fatalf("outcome = %+v", out)
	}
}
