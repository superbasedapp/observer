package agentid_test

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentid"
	"github.com/marmutapp/superbased-observer/internal/mcpaccess"
)

// credRanksStrongestFirst walks the closed CredentialAssurance enum from
// its weakest valid member up and returns the wire names strongest first.
func credRanksStrongestFirst() []string {
	var weakestFirst []string
	for v := agentid.CredClaimed; v.Valid(); v++ {
		weakestFirst = append(weakestFirst, v.String())
	}
	return reversed(weakestFirst)
}

// attestRanksStrongestFirst does the same for ClientAttestation.
func attestRanksStrongestFirst() []string {
	var weakestFirst []string
	for v := agentid.AttestClaimed; v.Valid(); v++ {
		weakestFirst = append(weakestFirst, v.String())
	}
	return reversed(weakestFirst)
}

func reversed(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[len(in)-1-i] = s
	}
	return out
}

// TestRankOrderParityWithMCPAccess pins the rank order the MCP policy
// compiler, lint and matcher use (mcpaccess.CredAssuranceRanks and
// ClientAttestationRanks) to the agentid enums, so a rank added to an enum
// cannot leave the policy side on the old order (R8.23.i).
func TestRankOrderParityWithMCPAccess(t *testing.T) {
	if got, want := strings.Join(mcpaccess.CredAssuranceRanks, ","), strings.Join(credRanksStrongestFirst(), ","); got != want {
		t.Fatalf("mcpaccess.CredAssuranceRanks = %s, agentid enum order = %s", got, want)
	}
	if got, want := strings.Join(mcpaccess.ClientAttestationRanks, ","), strings.Join(attestRanksStrongestFirst(), ","); got != want {
		t.Fatalf("mcpaccess.ClientAttestationRanks = %s, agentid enum order = %s", got, want)
	}
	if got := mcpaccess.AcceptedAtLeast(mcpaccess.CredAssuranceRanks, agentid.CredSharedSecret.String()); strings.Join(got, ",") != "hardware_bound,node_enrolled,workload_bound,shared_secret" {
		t.Fatalf("cred expansion = %v", got)
	}
	if got := mcpaccess.AcceptedAtLeast(mcpaccess.ClientAttestationRanks, agentid.AttestIPCBound.String()); strings.Join(got, ",") != "process_attested,ipc_bound" {
		t.Fatalf("attest expansion = %v", got)
	}
}
