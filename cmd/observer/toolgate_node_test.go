package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestLaunchAutoSandboxFollowsNodeToolGate pins the T-340 follow-up: an
// enforce-mode launch of a hook_block tool skips the sandbox only while the
// tool's tool-gate hook is registered and current on THIS node. A missing
// hook, a stale one (an older binary path), or hooks switched off by the
// vendor's own switch leave the tool with no working gate, so the launch is
// sandboxed. Claude Code is a hook_block row on the registry.
func TestLaunchAutoSandboxFollowsNodeToolGate(t *testing.T) {
	const tool = "claude-code"
	if c, _ := integration.For(tool); c.EnforcementChannel() != integration.EnforceHookBlock {
		t.Fatalf("%s is no longer hook_block on the registry; pick another hook_block row", tool)
	}
	binary := probeHookTestBinary(t)
	cases := []struct {
		name        string
		setup       func(t *testing.T, home, cfgPath string)
		wantCurrent bool
		wantReason  string
	}{
		{"registered and current: no sandbox", func(t *testing.T, home, cfgPath string) {
			probeHookRegister(t, home, binary, cfgPath, tool)
		}, true, "registered and current"},
		{"missing: sandbox", func(t *testing.T, home, _ string) {
			mustMkdir(t, filepath.Join(home, ".claude"))
		}, false, "missing or stale"},
		{"stale (registered by an older binary): sandbox", func(t *testing.T, home, cfgPath string) {
			probeHookRegister(t, home, binary+"-old", cfgPath, tool)
		}, false, "missing or stale"},
		{"switched off by disableAllHooks: sandbox", func(t *testing.T, home, cfgPath string) {
			probeHookRegister(t, home, binary, cfgPath, tool)
			setJSONKey(t, filepath.Join(home, ".claude", "settings.json"), "disableAllHooks", true)
		}, false, "switched off"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := probeHookSetupHome(t)
			cfgPath, _ := toolGateTestConfig(t, "enforce")
			tc.setup(t, home, cfgPath)
			gate := func(tl string) nodeToolGateState { return nodeToolGate(binary, cfgPath, tl) }
			st := gate(tool)
			if st.Current != tc.wantCurrent || !strings.Contains(st.Reason, tc.wantReason) {
				t.Fatalf("nodeToolGate = %+v, want current=%v reason ~ %q", st, tc.wantCurrent, tc.wantReason)
			}
			if got := launchAutoSandbox(tool, true, gate); got != !tc.wantCurrent {
				t.Errorf("launchAutoSandbox = %v, want %v", got, !tc.wantCurrent)
			}
		})
	}
	// No gate reader at all is not proof of a hook: sandbox.
	if !launchAutoSandbox(tool, true, nil) {
		t.Error("launchAutoSandbox with a nil gate reader skipped the sandbox")
	}
	// No sandbox on this platform: the honest floor, never a forced sandbox.
	if launchAutoSandbox(tool, false, nil) {
		t.Error("launchAutoSandbox forced a sandbox the platform cannot build")
	}
	// D-262: the org's no-sandbox fallback composes with this node's gate. A
	// gate that is not current, on a machine with no sandbox, reaches the
	// org's org_disallow for a proxied tool; a current gate holds whatever
	// the fallback says.
	if c, _ := integration.For(tool); c.Proxy == nil {
		t.Fatalf("%s is no longer proxied; pick a proxied hook_block row", tool)
	}
	if got := launchEnforcement(tool, false, nil, integration.EnforceOrgDisallow); got != integration.EnforceOrgDisallow {
		t.Errorf("missing gate, no sandbox, org_disallow: launchEnforcement = %q, want org_disallow", got)
	}
	current := func(string) nodeToolGateState { return nodeToolGateState{Current: true} }
	if got := launchEnforcement(tool, false, current, integration.EnforceOrgDisallow); got != integration.EnforceHookBlock {
		t.Errorf("current gate, no sandbox, org_disallow: launchEnforcement = %q, want hook_block", got)
	}
	if got := launchEnforcement(tool, false, nil, integration.EnforceRecordedAcceptance); got != integration.EnforceRecordedAcceptance {
		t.Errorf("missing gate, no sandbox, default fallback: launchEnforcement = %q, want recorded_acceptance", got)
	}
}

// TestNodeToolGateLegacyClineScript: the Cline CLI guard is the plugin
// (guard-fix lane B). A plugin rendered for another hook token (the stale
// state a script written for `observer hook cline` stood for) is not the
// plugin Observer renders today, so it never counts as a current hook. The
// test grounds a copy of the row live so the result does not depend on the
// row's grounding.
func TestNodeToolGateLegacyClineScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		// registerCline skips Windows by design (internal/hook
		// clineHooksUnsupportedOS: the SDK's .ps1 hooks are broken and the
		// plugin sandbox is untested there), so no plugin is written to
		// age into a legacy one.
		t.Skip("the Cline CLI guard plugin is registered on macOS and Linux only")
	}
	c, ok := integration.For(models.ToolClineCLI)
	if !ok {
		t.Fatal("no cline-cli row")
	}
	c.Hook.Bindings = slices.Clone(c.Hook.Bindings)
	for i, b := range c.Hook.Bindings {
		if b.Cap == integration.HookCapToolGate && b.Wired {
			c.Hook.Bindings[i].Grounding.Kind = integration.GroundingLive
		}
	}
	if c.EnforcementChannel() != integration.EnforceHookBlock {
		t.Fatalf("live-grounded cline-cli row is %q, want hook_block", c.EnforcementChannel())
	}
	binary := probeHookTestBinary(t)
	home := probeHookSetupHome(t)
	cfgPath, _ := toolGateTestConfig(t, "enforce")
	probeHookRegister(t, home, binary, cfgPath, models.ToolClineCLI)
	if st := nodeToolGateFor(c, binary, cfgPath); !st.Current {
		t.Fatalf("freshly registered cline-cli hook = %+v, want current", st)
	}
	script := filepath.Join(home, ".cline", "plugins", "superbased-observer-guard.js")
	body, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.ReplaceAll(string(body), `"tool":"cline-cli"`, `"tool":"cline"`)
	if legacy == string(body) {
		t.Fatalf("script does not name the cline-cli hook:\n%s", body)
	}
	if err := os.WriteFile(script, []byte(legacy), 0o755); err != nil {
		t.Fatal(err)
	}
	st := nodeToolGateFor(c, binary, cfgPath)
	if st.Current || !strings.Contains(st.Reason, "missing or stale") || !st.Fixable {
		t.Fatalf("legacy cline script = %+v, want not current (missing or stale) and fixable by setup", st)
	}
	if got := c.NodeEnforcement(st.Current, true); got != integration.EnforceSandbox {
		t.Errorf("legacy cline script: NodeEnforcement = %q, want sandbox_enforce", got)
	}
}

// TestToolGateEnforcementDoctorLines: `observer doctor` prints one line per
// hook_block tool. A current hook reads hook_block (OK); an installed tool
// whose hook does not hold names its fallback channel and reason (WARN, with
// the remedy); a tool that is not installed is informational (OK).
func TestToolGateEnforcementDoctorLines(t *testing.T) {
	tools := hookBlockTools()
	if len(tools) < 3 {
		t.Fatalf("hook_block tools = %v, want at least 3 for this test", tools)
	}
	states := map[string]nodeToolGateState{
		tools[0]: {Tool: tools[0], Current: true, Installed: true, Reason: "its PreToolUse hook is registered and current"},
		tools[1]: {Tool: tools[1], Installed: true, Reason: "its PreToolUse hook is missing or stale"},
		tools[2]: {Tool: tools[2], Reason: "not installed on this machine"},
	}
	checks := toolGateEnforcementChecks(true, func(tool string) nodeToolGateState {
		if st, ok := states[tool]; ok {
			return st
		}
		return nodeToolGateState{Tool: tool, Reason: "not installed on this machine"}
	})
	if len(checks) != len(tools) {
		t.Fatalf("doctor lines = %d, want one per hook_block tool (%d)", len(checks), len(tools))
	}
	c1, _ := integration.For(tools[1])
	fallback1 := string(c1.NodeEnforcement(false, true))
	byName := map[string]diag.Check{}
	for _, ck := range checks {
		byName[ck.Name] = ck
	}
	for _, tc := range []struct {
		tool   string
		status diag.Status
		want   string
	}{
		{tools[0], diag.StatusOK, tools[0] + ": hook_block on this node (its PreToolUse hook is registered and current)"},
		{tools[1], diag.StatusWarn, tools[1] + ": " + fallback1 + " on this node, not hook_block: its PreToolUse hook is missing or stale"},
		{tools[2], diag.StatusOK, "not hook_block: not installed on this machine"},
	} {
		ck, ok := byName["hooks.enforcement:"+tc.tool]
		if !ok {
			t.Errorf("no doctor line for %s", tc.tool)
			continue
		}
		if ck.Status != tc.status || !strings.Contains(ck.Message, tc.want) {
			t.Errorf("%s: %v %q, want %v ~ %q", tc.tool, ck.Status, ck.Message, tc.status, tc.want)
		}
		if tc.status == diag.StatusWarn && !strings.Contains(strings.Join(ck.Details, " "), "remedy: ") {
			t.Errorf("%s: WARN without a remedy: %v", tc.tool, ck.Details)
		}
	}
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

// setJSONKey sets one top-level key of a JSON object file.
func setJSONKey(t *testing.T, path, key string, v any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m[key] = v
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestToolGateEnforcementDoctorFollowsSandboxAvailability (live check macOS
// 2026-10-22, D2): with no sandbox on the node, a tool whose hook does not
// hold falls back to recorded acceptance, never "sandbox_enforce on this
// node".
func TestToolGateEnforcementDoctorFollowsSandboxAvailability(t *testing.T) {
	tools := hookBlockTools()
	if len(tools) == 0 {
		t.Skip("no hook_block tools")
	}
	gate := func(tool string) nodeToolGateState {
		return nodeToolGateState{Tool: tool, Installed: true, Reason: "its PreToolUse hook is missing or stale"}
	}
	c, _ := integration.For(tools[0])
	for _, available := range []bool{false, true} {
		checks := toolGateEnforcementChecks(available, gate)
		want := string(c.NodeEnforcement(false, available))
		if !strings.Contains(checks[0].Message, want+" on this node") {
			t.Fatalf("available=%v: %q, want %s", available, checks[0].Message, want)
		}
		if !available && strings.Contains(checks[0].Message, string(integration.EnforceSandbox)+" on this node") {
			t.Fatalf("no sandbox, yet the line says sandbox_enforce: %q", checks[0].Message)
		}
	}
}
