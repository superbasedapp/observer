//go:build linux && !sbo_omit_capture_proxy && !sbo_omit_terminals_sandbox_credentials && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxcred"
)

// credEnvNotModelCredential are credential-shaped variables of a tool that
// carry no model provider credential, so the box-env table leaves them to
// pass_env (each with its reason).
var credEnvNotModelCredential = map[string]string{
	"CLAUDE_CODE_CLIENT_KEY_PASSPHRASE": "the passphrase of an mTLS client key, not a model credential",
	"MCP_CLIENT_SECRET":                 "an MCP server's OAuth client secret, not a model credential",
}

// TestCredEnvCoversEveryToolCredential (audit FU3-A2): for every tool whose
// capability row maps to one injection provider, every credential variable
// the repository already names for that tool (its integration AuthEnv and
// sandbox ProviderEnv, and its settings catalog's env keys marked Secret)
// is in that provider's CredEnv, so the box-env table drops it while a
// lane is open. A non-secret name in AuthEnv (a project id, a region) is
// told apart by agentconfig.SecretKeyName.
func TestCredEnvCoversEveryToolCredential(t *testing.T) {
	checked := 0
	for _, c := range integration.Capabilities() {
		provider := credToolProvider(c.Tool)
		if provider == "" {
			continue
		}
		p, ok := sandboxcred.ProviderFor(provider)
		if !ok {
			t.Fatalf("%s: provider %q not in the table", c.Tool, provider)
		}
		names := append(append([]string(nil), c.AuthEnv...), c.Sandbox.ProviderEnv...)
		for _, r := range agentconfig.SettingsFor(c.Tool) {
			if r.Secret && len(r.Path) == 2 && r.Path[0] == "env" {
				names = append(names, r.Path[1])
			}
		}
		for _, n := range names {
			if _, exempt := credEnvNotModelCredential[n]; exempt || !agentconfig.SecretKeyName(n) {
				continue
			}
			checked++
			if !slices.Contains(p.CredEnv, n) {
				t.Errorf("%s (provider %s): credential variable %s is not in CredEnv %v", c.Tool, provider, n, p.CredEnv)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no tool credential was checked")
	}
}
