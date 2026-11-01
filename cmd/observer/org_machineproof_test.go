package main

import (
	"context"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestMachineProofLines (WINNODE item 4): `observer org status` and the
// dashboard enrolment page name the daemon's machine proof, and the CLI adds
// its own process's view when only it lacks the key (an SSH session beside a
// daemon started from the developer's sign-in).
func TestMachineProofLines(t *testing.T) {
	ctx := context.Background()
	noSession := orgclient.MachineProofState{Known: true, Reason: "no Windows logon session"}
	fine := orgclient.MachineProofState{Known: true, Available: true}
	cases := []struct {
		name    string
		report  *store.OrgMachineProofReport
		own     orgclient.MachineProofState
		want    []string
		warning string
	}{
		{"no report yet", nil, fine, []string{"Machine proof: not reported yet"}, ""},
		{
			"daemon has no logon session", &store.OrgMachineProofReport{Reason: "no Windows logon session", At: "T"}, noSession,
			[]string{"Machine proof unavailable: no Windows logon session (daemon, since T)"},
			"Machine proof unavailable: no Windows logon session.",
		},
		{
			"daemon fine, this ssh session is not", &store.OrgMachineProofReport{Available: true, At: "T"}, noSession,
			[]string{"Machine proof: available (daemon, since T)", "Machine proof in this command's own process: unavailable: no Windows logon session"},
			"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, st := identTestStore(t)
			if tc.report != nil {
				if err := st.SaveOrgMachineProofReport(ctx, *tc.report); err != nil {
					t.Fatal(err)
				}
			}
			lines := machineProofLines(ctx, tc.own, st)
			if len(lines) != len(tc.want) {
				t.Fatalf("lines = %q, want %d", lines, len(tc.want))
			}
			for i, w := range tc.want {
				if !strings.HasPrefix(lines[i], w) {
					t.Fatalf("line %d = %q, want prefix %q", i, lines[i], w)
				}
			}
			got := machineProofWarning(ctx, st)
			if !strings.HasPrefix(got, tc.warning) || (tc.warning == "") != (got == "") {
				t.Fatalf("dashboard warning = %q, want %q", got, tc.warning)
			}
			// The remedy names the clean path: the developer's desktop
			// session (WINNODE merge follow-up, audit F1). What is withheld
			// is said as the server does it (audit F4): only once a machine
			// key is registered, or when the org requires proof.
			if tc.report != nil && !tc.report.Available {
				for _, s := range []string{lines[0], got} {
					if !strings.Contains(s, "withheld once a machine key is registered, or when") || !strings.Contains(s, "requires proof") {
						t.Errorf("withheld clause overstates what the server does: %q", s)
					}
					if !strings.Contains(s, "desktop sign-in") || !strings.Contains(s, "clean path") {
						t.Errorf("remedy does not name the desktop session as the clean path: %q", s)
					}
				}
			}
		})
	}
}
