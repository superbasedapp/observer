package config

import (
	"fmt"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// hostedkeys.go validates the per-tool key settings of
// [terminal.sandbox.hosted] (decisions SBXD-1 and SBXD-4): the per-tool
// custody, and the two opt-in in-box key sources. Each key names a tool of
// the integration registry; the sources only a tool whose registry row
// grounds the file.

// hostedToolCustodies are the values a per-tool custody takes: the ones a
// hosted row offers (in_box_oauth_seed is not built, provider_injected is
// not offered).
var hostedToolCustodies = []string{"auto", "home_relay", "in_box_api_key"}

// validateHostedKeySources checks key_custody_by_tool, tool_keys and
// login_seed.
func validateHostedKeySources(c TerminalSandboxHostedConfig) error {
	for _, tool := range sortedKeys(c.KeyCustodyByTool) {
		if _, ok := integration.For(tool); !ok {
			return fmt.Errorf("config: terminal.sandbox.hosted.key_custody_by_tool names %q, which is not a tool id Observer knows", tool)
		}
		v := c.KeyCustodyByTool[tool]
		ok := false
		for _, k := range hostedToolCustodies {
			ok = ok || v == k
		}
		if !ok {
			return fmt.Errorf("config: terminal.sandbox.hosted.key_custody_by_tool.%s %q not in {auto, home_relay, in_box_api_key}", tool, v)
		}
	}
	for _, tool := range sortedBoolKeys(c.ToolKeys) {
		if _, ok := integration.SandboxSavedKeysFor(tool); !ok && c.ToolKeys[tool] {
			return fmt.Errorf("config: terminal.sandbox.hosted.tool_keys names %q, which has no grounded saved-keys file (only %v do)", tool, savedKeyTools())
		}
	}
	for _, tool := range sortedBoolKeys(c.LoginSeed) {
		if _, ok := integration.SandboxLoginSeedFor(tool); !ok && c.LoginSeed[tool] {
			return fmt.Errorf("config: terminal.sandbox.hosted.login_seed names %q, which has no grounded login file (only %v do)", tool, loginSeedTools())
		}
	}
	return nil
}

func savedKeyTools() []string {
	s, _ := integration.SandboxKeySourceTools()
	return s
}

func loginSeedTools() []string {
	_, l := integration.SandboxKeySourceTools()
	return l
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedBoolKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
