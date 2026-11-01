package diag

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hook"
)

// TestCheckIBMBobTeamsPolicyGatewayURL pins S-19: a policy GatewayUrl is
// named (it overrides any per-node route) without changing the status.
func TestCheckIBMBobTeamsPolicyGatewayURL(t *testing.T) {
	pol := hook.ParseIBMBobPolicyDocument(`HKLM\SOFTWARE\Policies\IBM\Bob`, []byte(`{"GatewayUrl":"https://bob.example.internal"}`))
	c := checkIBMBobTeamsPolicy(config.Config{}, pol, hook.IBMBobPolicyDomains{}, t.TempDir())
	joined := strings.Join(c.Details, "\n")
	if !strings.Contains(joined, "GatewayUrl locks Bob's inference host to https://bob.example.internal") {
		t.Errorf("details do not name the GatewayUrl:\n%s", joined)
	}
	if c.Status != StatusOK {
		t.Errorf("status = %v, want OK (a GatewayUrl is the administrator's choice)", c.Status)
	}
}
