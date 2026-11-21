package cloudsession

import (
	"strings"
	"testing"
)

// planPaths returns the changed paths of a plan.
func planPaths(p RepoPlan) map[string]FileChange {
	out := map[string]FileChange{}
	for _, c := range p.Changes {
		if c.Changed() {
			out[c.Path] = c
		}
	}
	return out
}

// TestPlanInitFeatures: --guard adds the policy file and the gate entries,
// --mcp the MCP registration and the setup script's post-install step; with
// neither, none of it is written (the golden test pins those bytes).
func TestPlanInitFeatures(t *testing.T) {
	o := guardOpts(t, "claude-code", GuardEnforce)
	o.MCP, o.CodeIntel = true, true
	repo := memRepo{".mcp.json": "{\n  \"mcpServers\": {\n    \"team\": {\n      \"command\": \"team-mcp\"\n    }\n  }\n}\n"}
	plan, err := PlanInit(o, repo.read)
	if err != nil {
		t.Fatal(err)
	}
	ch := planPaths(plan)
	if c, ok := ch[PolicyPath]; !ok || c.After != string(o.Guard.Policy) {
		t.Fatalf("policy file not written verbatim: %+v", c)
	}
	settings := ch[ClaudeSettingsPath].After
	for _, want := range []string{`"PreToolUse"`, "cloud-session gate --agent claude-code --event PreToolUse", "cloud-session gate --agent claude-code --event UserPromptSubmit"} {
		if !strings.Contains(settings, want) {
			t.Errorf("settings missing %q", want)
		}
	}
	mcp := ch[ClaudeMCPPath].After
	if !strings.Contains(mcp, `"team"`) || !strings.Contains(mcp, `"`+MCPServerName+`"`) || !strings.Contains(mcp, `exec /usr/local/bin/observer serve --config \"$HOME/`+SandboxMCPConfig) {
		t.Fatalf("mcp config:\n%s", mcp)
	}
	script := ch[SetupScriptPath].After
	if !strings.Contains(script, "post_install()") || strings.Count(script, "post_install\n") != 2 || !strings.Contains(script, "cloud-session setup --mcp --codeintel") {
		t.Fatalf("setup script lacks the post-install step:\n%s", script)
	}

	// The whole plan applied, then removed, restores the repository byte for
	// byte (the team's own MCP server stays).
	before := repo.clone()
	repo.apply(plan)
	rm, err := PlanRemove("claude-code", repo.read)
	if err != nil {
		t.Fatal(err)
	}
	repo.apply(rm)
	if len(repo) != len(before) || repo[".mcp.json"] != before[".mcp.json"] {
		t.Fatalf("remove did not restore the repository: %v", repo)
	}
}

// TestPlanInitFeatureOffConverges: re-running init without a feature takes
// back out what the feature wrote.
func TestPlanInitFeatureOffConverges(t *testing.T) {
	o := guardOpts(t, "claude-code", GuardObserve)
	o.MCP = true
	repo := memRepo{}
	plan, err := PlanInit(o, repo.read)
	if err != nil {
		t.Fatal(err)
	}
	repo.apply(plan)
	plain, err := PlanInit(testOpts("claude-code"), repo.read)
	if err != nil {
		t.Fatal(err)
	}
	repo.apply(plain)
	if _, ok := repo[PolicyPath]; ok {
		t.Error("policy file left behind")
	}
	if _, ok := repo[ClaudeMCPPath]; ok {
		t.Error(".mcp.json left behind")
	}
	if strings.Contains(repo[ClaudeSettingsPath], "cloud-session gate") || strings.Contains(repo[SetupScriptPath], "post_install") {
		t.Error("gate entries or the post-install step left behind")
	}
	fresh, _ := PlanInit(testOpts("claude-code"), memRepo{}.read)
	for _, c := range fresh.Changes {
		if repo[c.Path] != c.After {
			t.Errorf("%s differs from a fresh init without features", c.Path)
		}
	}
}

// TestPlanInitFeatureRefusals: a foreign file at the policy path or a team
// server under Observer's MCP name is refused, never overwritten.
func TestPlanInitFeatureRefusals(t *testing.T) {
	o := guardOpts(t, "claude-code", GuardEnforce)
	if _, err := PlanInit(o, memRepo{PolicyPath: "{}\n"}.read); err == nil || !strings.Contains(err.Error(), "did not write") {
		t.Fatalf("foreign policy file: err = %v", err)
	}
	o = testOpts("claude-code")
	o.MCP = true
	taken := memRepo{".mcp.json": "{\n  \"mcpServers\": {\n    \"" + MCPServerName + "\": {\n      \"command\": \"x\"\n    }\n  }\n}\n"}
	if _, err := PlanInit(o, taken.read); err == nil || !strings.Contains(err.Error(), "did not write") {
		t.Fatalf("taken MCP name: err = %v", err)
	}
}

// TestPlanInitMCPManual: an agent whose MCP config lives on a vendor page
// gets the JSON to paste, and no repository file.
func TestPlanInitMCPManual(t *testing.T) {
	o := testOpts("copilot")
	o.MCP = true
	plan, err := PlanInit(o, memRepo{}.read)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := planPaths(plan)[ClaudeMCPPath]; ok {
		t.Fatal("copilot wrote a Claude MCP file")
	}
	found := false
	for _, m := range plan.Manual {
		if strings.Contains(m, "MCP configuration") && strings.Contains(m, `"`+MCPServerName+`"`) && strings.Contains(m, `"serve"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no MCP manual step: %v", plan.Manual)
	}
}

// TestPlanInitGuardCopilot: the Copilot hooks file carries both gates.
func TestPlanInitGuardCopilot(t *testing.T) {
	plan, err := PlanInit(guardOpts(t, "copilot", GuardEnforce), memRepo{}.read)
	if err != nil {
		t.Fatal(err)
	}
	hooks := planPaths(plan)[CopilotHooksPath].After
	for _, want := range []string{`"preToolUse"`, "--event preToolUse", "--event userPromptSubmitted"} {
		if !strings.Contains(hooks, want) {
			t.Errorf("copilot hooks missing %q", want)
		}
	}
}
