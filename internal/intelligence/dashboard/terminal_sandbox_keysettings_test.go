package dashboard

import (
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestHostedKeySettingsOnPut (decisions SBXD-1, SBXD-4): a PUT body that
// predates the per-tool key settings keeps the saved ones; a body that
// sends them replaces them (an off entry is dropped); and the GET payload
// always carries them with the registry's tool lists.
func TestHostedKeySettingsOnPut(t *testing.T) {
	saved := config.Default().Terminal.Sandbox.Hosted
	saved.KeyCustodyByTool = map[string]string{"droid": "in_box_api_key"}
	saved.ToolKeys = map[string]bool{"opencode": true}
	saved.LoginSeed = map[string]bool{"claude-code": true}

	old := &terminalSandboxHostedPayload{KeyCustody: "auto"}
	next := normalizedSandboxHostedConfig(old)
	keepHostedOnPut(&next, old, saved)
	if next.KeyCustodyByTool["droid"] != "in_box_api_key" || !next.ToolKeys["opencode"] || !next.LoginSeed["claude-code"] {
		t.Fatalf("an old client's PUT dropped the saved settings: %+v", next)
	}

	byTool := map[string]string{" codex ": " home_relay "}
	toolKeys := map[string]bool{"opencode": false}
	login := map[string]bool{"claude-code": true}
	sent := &terminalSandboxHostedPayload{KeyCustody: "auto", KeyCustodyByTool: &byTool, ToolKeys: &toolKeys, LoginSeed: &login}
	next = normalizedSandboxHostedConfig(sent)
	keepHostedOnPut(&next, sent, saved)
	if next.KeyCustodyByTool["codex"] != "home_relay" || len(next.KeyCustodyByTool) != 1 || next.ToolKeys != nil || !next.LoginSeed["claude-code"] {
		t.Fatalf("a PUT that sends them: %+v", next)
	}
	full := config.Default().Terminal.Sandbox.Hosted
	full.KeyCustodyByTool, full.ToolKeys, full.LoginSeed = next.KeyCustodyByTool, next.ToolKeys, next.LoginSeed
	if err := config.Validate(withHosted(full)); err != nil {
		t.Fatalf("the saved block does not validate: %v", err)
	}

	p := sandboxConfigPayload(config.Default().Terminal.Sandbox)
	if p.Hosted.KeyCustodyByTool == nil || p.Hosted.ToolKeys == nil || p.Hosted.LoginSeed == nil || p.Hosted.KeyTools == nil {
		t.Fatalf("GET payload %+v", p.Hosted)
	}
	if !slices.Contains(p.Hosted.KeyTools.SavedKeys, "opencode") || !slices.Contains(p.Hosted.KeyTools.LoginSeed, "claude-code") || len(p.Hosted.KeyTools.Tools) == 0 {
		t.Fatalf("key tools %+v", p.Hosted.KeyTools)
	}
}

func withHosted(h config.TerminalSandboxHostedConfig) config.Config {
	c := config.Default()
	c.Terminal.Sandbox.Hosted = h
	return c
}
