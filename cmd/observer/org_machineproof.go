package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// persistMachineProof makes the daemon's org client record every change of
// its machine-proof outcome (WINNODE item 4), so `observer doctor`,
// `observer org status` and the dashboard's enrolment page report what the
// DAEMON sees. Only the daemon persists: a short-lived CLI over SSH on
// Windows has no logon session even when the daemon, started from the
// developer's sign-in, does.
func persistMachineProof(c *orgclient.Client, st *store.Store) {
	if c == nil || st == nil {
		return
	}
	c.SetMachineProofSink(func(p orgclient.MachineProofState) {
		_ = st.SaveOrgMachineProofReport(context.Background(), store.OrgMachineProofReport{
			Available: p.Available, Reason: p.Reason, At: time.Now().UTC().Format(time.RFC3339),
		})
	})
}

// printMachineProof is `observer org status`'s machine-proof line for a
// managed enrolment: the daemon's report when it has one, and this command's
// own view when it differs or no report exists yet.
func printMachineProof(ctx context.Context, out io.Writer, c *orgclient.Client, st *store.Store) {
	for _, line := range machineProofLines(ctx, c.ProbeMachineProof(), st) {
		fmt.Fprintln(out, line)
	}
}

// machineProofLines renders the lines printMachineProof prints.
func machineProofLines(ctx context.Context, own orgclient.MachineProofState, st *store.Store) []string {
	var lines []string
	report, ok, err := st.LoadOrgMachineProofReport(ctx)
	switch {
	case err != nil:
		lines = append(lines, "Machine proof: unknown - the daemon's report could not be read")
	case !ok:
		lines = append(lines, "Machine proof: not reported yet - the daemon records it at its first grant or budget fetch")
	case report.Available:
		lines = append(lines, "Machine proof: available (daemon, since "+report.At+")")
	default:
		lines = append(lines, "Machine proof unavailable: "+report.Reason+" (daemon, since "+report.At+"). Machine-scoped grants are withheld once a machine key is registered, or when the org requires proof, and the machine's budget binding once a key is registered. Run the daemon from the developer's desktop sign-in (`observer setup autostart on`) so it holds the machine key; enrolling from that session is the clean path")
	}
	if own.Known && !own.Available && (!ok || report.Available) {
		lines = append(lines, "Machine proof in this command's own process: unavailable: "+own.Reason)
	}
	return lines
}

// machineProofWarning is the dashboard enrolment page's sentence when the
// daemon's report says it signs no machine proof, "" otherwise.
func machineProofWarning(ctx context.Context, st *store.Store) string {
	report, ok, err := st.LoadOrgMachineProofReport(ctx)
	if err != nil || !ok || report.Available {
		return ""
	}
	return "Machine proof unavailable: " + report.Reason + ". Machine-scoped grants are withheld once a machine key is registered, or when your organization requires proof, and this machine's budget binding once a key is registered. Run the daemon from your desktop sign-in (observer setup autostart on) so it holds the machine key; enrolling from that session is the clean path."
}
