package main

import (
	"strings"
	"testing"
)

// TestEmitManagedSettings_CodexEnforceProxyProvider pins CX-3 (decision D3)
// end to end: --enforce-proxy-provider puts the enforced provider in
// requirements.toml, it is off without the flag, and it refuses
// --no-proxy-route (the enforced provider is the route).
func TestEmitManagedSettings_CodexEnforceProxyProvider(t *testing.T) {
	stdout, err := runEmitManagedSettings(t, "--provider", "codex", "--enforce-proxy-provider")
	if err != nil {
		t.Fatalf("emit: %v\n%s", err, stdout)
	}
	for _, want := range []string{
		"\nmodel_provider = \"openai-observer\"\n",
		"[model_providers.openai-observer]\n",
		"requires_openai_auth = true\n",
		"## Enforced provider",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output missing %q:\n%s", want, stdout)
		}
	}

	plain, err := runEmitManagedSettings(t, "--provider", "codex")
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if strings.Contains(plain, "[model_providers.openai-observer]") {
		t.Errorf("provider enforced without the flag:\n%s", plain)
	}

	if _, err := runEmitManagedSettings(t, "--provider", "codex", "--enforce-proxy-provider", "--no-proxy-route"); err == nil {
		t.Error("--enforce-proxy-provider with --no-proxy-route should be refused")
	}
}
