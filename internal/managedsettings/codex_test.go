package managedsettings

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestGenerateCodex_Defaults(t *testing.T) {
	arts, err := GenerateCodex(CodexOptions{
		OpenAIBaseURL:     "http://127.0.0.1:8820/v1",
		IncludeMCP:        true,
		IncludeProxyRoute: true,
	})
	if err != nil {
		t.Fatalf("GenerateCodex: %v", err)
	}

	mc := string(arts.ManagedConfigTOML)
	// Grounded defaults: proxy route, hooks, MCP pin.
	for _, want := range []string{
		`openai_base_url = "http://127.0.0.1:8820/v1"`,
		"[features]",
		"hooks = true",
		"[mcp_servers." + CodexMCPServerName + "]",
		`command = "npx"`,
		`args = ["-y", "@superbased/observer", "serve"]`,
	} {
		if !strings.Contains(mc, want) {
			t.Errorf("managed_config.toml missing %q\n---\n%s", want, mc)
		}
	}
	// No OTel block unless an endpoint is given (Rail A is deferred/gated).
	if strings.Contains(mc, "[otel]") {
		t.Errorf("managed_config.toml should not emit [otel] without an endpoint:\n%s", mc)
	}

	// Both artifacts must be valid TOML.
	assertParseableTOML(t, "managed_config.toml", arts.ManagedConfigTOML)
	assertParseableTOML(t, "requirements.toml", arts.RequirementsTOML)

	// requirements.toml is conservative: the MCP identity rule ships
	// commented (a live mcp_servers table disables every server it does not
	// name).
	rq := string(arts.RequirementsTOML)
	if !strings.Contains(rq, "# [mcp_servers."+CodexMCPServerName+".identity]") {
		t.Errorf("requirements.toml should ship the identity rule commented:\n%s", rq)
	}
	if strings.Contains(rq, "\nallow_managed_hooks_only = true") {
		t.Errorf("requirements.toml should NOT enforce managed-hooks-only by default:\n%s", rq)
	}

	if arts.Readme == "" {
		t.Error("readme empty")
	}
}

func TestGenerateCodex_OTelAndEnforce(t *testing.T) {
	arts, err := GenerateCodex(CodexOptions{
		OpenAIBaseURL:           "http://127.0.0.1:8820/v1",
		OTelEndpoint:            "http://127.0.0.1:4318",
		IncludeMCP:              true,
		IncludeProxyRoute:       true,
		EnforceManagedHooksOnly: true,
		ManagedHooks:            testCodexManagedHooks(),
	})
	if err != nil {
		t.Fatalf("GenerateCodex: %v", err)
	}
	mc := string(arts.ManagedConfigTOML)
	// The [otel] redirect ships COMMENTED (Rail A gated; nesting unconfirmed) so
	// the file stays valid TOML — an active block would be a key conflict.
	if !strings.Contains(mc, "# [otel]") || !strings.Contains(mc, `# endpoint = "http://127.0.0.1:4318"`) {
		t.Errorf("managed_config.toml missing commented [otel] redirect template:\n%s", mc)
	}
	assertParseableTOML(t, "managed_config.toml", arts.ManagedConfigTOML)

	rq := string(arts.RequirementsTOML)
	if !strings.Contains(rq, "\nallow_managed_hooks_only = true") {
		t.Errorf("requirements.toml should enforce managed-hooks-only when requested:\n%s", rq)
	}
	assertParseableTOML(t, "requirements.toml", arts.RequirementsTOML)
}

func TestGenerateCodex_MCPOnly(t *testing.T) {
	arts, err := GenerateCodex(CodexOptions{IncludeMCP: true})
	if err != nil {
		t.Fatalf("GenerateCodex: %v", err)
	}
	mc := string(arts.ManagedConfigTOML)
	if strings.Contains(mc, "openai_base_url") {
		t.Errorf("proxy route should be omitted when IncludeProxyRoute=false:\n%s", mc)
	}
	if !strings.Contains(mc, "[mcp_servers."+CodexMCPServerName+"]") {
		t.Errorf("MCP pin missing:\n%s", mc)
	}
}

func TestGenerateCodex_Errors(t *testing.T) {
	if _, err := GenerateCodex(CodexOptions{}); err == nil {
		t.Error("expected error when nothing selected")
	}
	if _, err := GenerateCodex(CodexOptions{IncludeProxyRoute: true}); err == nil {
		t.Error("expected error when proxy route requested without OpenAIBaseURL")
	}
}

func TestCodexArtifacts_RequirementsBase64(t *testing.T) {
	arts, err := GenerateCodex(CodexOptions{IncludeMCP: true})
	if err != nil {
		t.Fatalf("GenerateCodex: %v", err)
	}
	b64 := arts.RequirementsTOMLBase64()
	if b64 == "" {
		t.Fatal("expected non-empty base64")
	}
	dec, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(dec) != string(arts.RequirementsTOML) {
		t.Error("base64 does not round-trip to requirements.toml")
	}

	// Empty artifacts → empty base64.
	if (CodexArtifacts{}).RequirementsTOMLBase64() != "" {
		t.Error("empty artifacts should yield empty base64")
	}
}

func TestGenerateCodex_MCPPackageOverride(t *testing.T) {
	arts, err := GenerateCodex(CodexOptions{IncludeMCP: true, MCPPackage: "@superbased/observer@1.2.3"})
	if err != nil {
		t.Fatalf("GenerateCodex: %v", err)
	}
	if !strings.Contains(string(arts.ManagedConfigTOML), `"@superbased/observer@1.2.3"`) {
		t.Errorf("MCP package override not applied:\n%s", arts.ManagedConfigTOML)
	}
}

func assertParseableTOML(t *testing.T, name string, b []byte) {
	t.Helper()
	var v map[string]any
	if err := toml.Unmarshal(b, &v); err != nil {
		t.Fatalf("%s is not valid TOML: %v\n---\n%s", name, err, b)
	}
}
