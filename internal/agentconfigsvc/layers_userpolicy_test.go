package agentconfigsvc

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// TestEffectiveLayersCallerRuntimeTrees (FU-105): a runtime tree the
// caller's own reader produced (an OS preferences domain, key names only)
// reaches the evaluator, a tree of a tool outside the pass is dropped, and
// the caller's map is never written.
func TestEffectiveLayersCallerRuntimeTrees(t *testing.T) {
	s := layerService(t, t.TempDir(), nil)
	userTree := map[string]any{"GatewayUrl": agentconfig.KeyPresent{}}
	trees := []agentconfig.RuntimeTree{
		{Tool: "ibm-bob", Layer: agentconfig.RuntimeUserPrefs, Tree: userTree},
		{Tool: "no-such-tool", Layer: agentconfig.RuntimeUserPrefs, Tree: map[string]any{"GatewayUrl": agentconfig.KeyPresent{}}},
	}
	rep, err := s.EffectiveLayers(context.Background(), LayerOptions{Runtime: trees})
	if err != nil {
		t.Fatal(err)
	}
	fs := findingsOf(rep, "ibm-bob/policy.GatewayUrl")
	if len(fs) != 1 || fs[0].Code != agentconfig.FindingUserPolicyOverride || fs[0].Winning.Runtime != agentconfig.RuntimeUserPrefs || rep.Path(fs[0]) != "" {
		t.Fatalf("findings = %+v, want one user_policy_override from runtime:user_prefs with no path", fs)
	}
	for _, f := range rep.Findings {
		if f.Tool == "no-such-tool" {
			t.Fatalf("a tree of a tool outside the pass was evaluated: %+v", f)
		}
	}
	if len(userTree) != 1 {
		t.Fatalf("the caller's tree was written: %v", userTree)
	}
	rep, err = s.EffectiveLayers(context.Background(), LayerOptions{Runtime: trees, Tools: []string{"claude-code"}})
	if err != nil {
		t.Fatal(err)
	}
	if fs := findingsOf(rep, "ibm-bob/policy.GatewayUrl"); len(fs) != 0 {
		t.Fatalf("a pass restricted to claude-code evaluated Bob's tree: %+v", fs)
	}
	rep, err = s.EffectiveLayers(context.Background(), LayerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Findings {
		if f.Code == agentconfig.FindingUserPolicyOverride {
			t.Fatalf("no caller tree, yet %+v", f)
		}
	}
}
