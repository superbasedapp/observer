package integration

import "testing"

// TestOrgPromptJudgeReach is one row per binding x proxy shape (lane adm-2).
func TestOrgPromptJudgeReach(t *testing.T) {
	deny := HookBinding{Cap: HookCapPromptGate, Wired: true, Decisions: []string{HookDecisionDeny}}
	warnOnly := HookBinding{Cap: HookCapPromptGate, Wired: true, Decisions: []string{"context"}}
	offered := HookBinding{Cap: HookCapPromptGate, Decisions: []string{HookDecisionDeny}}
	toolGate := HookBinding{Cap: HookCapToolGate, Wired: true, Decisions: []string{HookDecisionDeny}}
	proxy := &ProxyRoute{}
	cases := []struct {
		name string
		c    Capability
		want OrgPromptJudgeReach
	}{
		{"nothing", Capability{}, OrgPromptJudgeNone},
		{"offered, not wired", Capability{Hook: HookSpec{Bindings: []HookBinding{offered}}}, OrgPromptJudgeNone},
		{"tool gate only", Capability{Hook: HookSpec{Bindings: []HookBinding{toolGate}}}, OrgPromptJudgeNone},
		{"wired prompt gate that can deny", Capability{Hook: HookSpec{Bindings: []HookBinding{deny}}}, OrgPromptJudgeHook},
		{"wired prompt gate that cannot deny", Capability{Hook: HookSpec{Bindings: []HookBinding{warnOnly}}}, OrgPromptJudgeHookWarn},
		{"warn-only prompt seam", Capability{Hook: HookSpec{Bindings: []HookBinding{deny}, PromptWarnOnly: true}}, OrgPromptJudgeHookWarn},
		{"proxy only", Capability{Proxy: proxy}, OrgPromptJudgeProxy},
		{"hook and proxy", Capability{Hook: HookSpec{Bindings: []HookBinding{deny}}, Proxy: proxy}, OrgPromptJudgeHookAndProxy},
		{"warn-only hook and proxy", Capability{Hook: HookSpec{Bindings: []HookBinding{warnOnly}}, Proxy: proxy}, OrgPromptJudgeHookWarnAndProxy},
	}
	for _, tc := range cases {
		if got := tc.c.OrgPromptJudgeReach(); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestEveryWiredPromptGateReachesTheJudge pins the phase 2 coverage claim:
// every registry row with a wired prompt-gate binding reaches the org judge
// through its hook (P-228: all tools with a prompt gate, proxy-routable or
// not).
func TestEveryWiredPromptGateReachesTheJudge(t *testing.T) {
	for _, c := range Capabilities() {
		wired := false
		for _, b := range c.Hook.Bindings {
			if b.Cap == HookCapPromptGate && b.Wired {
				wired = true
			}
		}
		r := c.OrgPromptJudgeReach()
		if wired && (r == OrgPromptJudgeNone || r == OrgPromptJudgeProxy) {
			t.Errorf("%s: a wired prompt gate must reach the judge through its hook, got %q", c.Tool, r)
		}
	}
}
