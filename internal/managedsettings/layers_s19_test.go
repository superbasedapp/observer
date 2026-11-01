package managedsettings

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestDeepAgentsManagedLayer pins S-19: an enforced Deep Agents setting
// lands in /etc/dcode/managed_config.toml (and its macOS and Windows
// paths), tamper-evident on Windows where a user can create the folder.
func TestDeepAgentsManagedLayer(t *testing.T) {
	raw, _ := json.Marshal([]string{"claude-sonnet-4-6"})
	b, err := FromPolicy(PolicyInput{Body: orgcontract.AgentConfigPolicyBody{Directives: []orgcontract.AgentConfigDirective{
		{Setting: "deepagents-code/models.allowed", Value: raw, Mode: orgcontract.AgentConfigModeEnforced},
	}}})
	if err != nil {
		t.Fatalf("FromPolicy: %v", err)
	}
	if len(b.Unplaced) != 0 {
		t.Fatalf("unplaced: %+v", b.Unplaced)
	}
	var tb *ToolBundle
	for i := range b.Tools {
		if b.Tools[i].Tool == "deepagents-code" {
			tb = &b.Tools[i]
		}
	}
	if tb == nil || len(tb.Artifacts) == 0 {
		t.Fatalf("no deepagents-code artifact: %+v", b.Tools)
	}
	a := tb.Artifacts[0]
	if a.FileID != "deepagents-code/managed-config" || !strings.Contains(a.Content, "allowed = [") {
		t.Errorf("artifact = %s\n%s", a.FileID, a.Content)
	}
	if a.Strength["linux"] != StrengthTamperProof || a.Strength["windows"] != StrengthTamperEvident {
		t.Errorf("strength = %v, want tamper_proof on linux, tamper_evident on windows", a.Strength)
	}
}
