//go:build !sbo_omit_integration_mcp_server

package main

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/mcp"
)

// runContractJSON executes `observer contract --json` and decodes it.
func runContractJSON(t *testing.T) contractDoc {
	t.Helper()
	cmd := newContractCmd()
	cmd.SetArgs([]string{"--json"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	var doc contractDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, buf.String())
	}
	return doc
}

// TestContractCmdRegistered pins `observer contract` into the root command
// set and that its constructor returns a FRESH command (the alias-group
// requirement — observerSubcommands() is called twice).
func TestContractCmdRegistered(t *testing.T) {
	t.Parallel()
	var found bool
	for _, c := range observerSubcommandsWith(defaultUsageDeps()) {
		if c.Name() == "contract" {
			found = true
		}
	}
	if !found {
		t.Error("`observer contract` is not registered in observerSubcommandsWith")
	}
	if a, b := newContractCmd(), newContractCmd(); a == b {
		t.Error("newContractCmd returned the same instance twice - constructors must return fresh commands")
	}
}

// TestContractJSONEnvelope pins the artifact's top-level shape: the version
// an integrator pins, the MCP server name, and one adapter row per registry
// capability.
func TestContractJSONEnvelope(t *testing.T) {
	t.Parallel()
	doc := runContractJSON(t)

	if doc.ContractVersion != contractVersion {
		t.Errorf("contract_version = %d, want %d", doc.ContractVersion, contractVersion)
	}
	if doc.MCP.ServerName != mcp.ServerName {
		t.Errorf("mcp.server_name = %q, want %q", doc.MCP.ServerName, mcp.ServerName)
	}
	if got, want := len(doc.MCP.Tools), len(mcp.ContractTools()); got != want {
		t.Errorf("mcp.tools = %d rows, want %d", got, want)
	}
	if got, want := len(doc.Adapters), len(integration.Capabilities()); got != want {
		t.Errorf("adapters = %d rows, want %d", got, want)
	}
}

// TestContractJSONToolsMatchTable pins that the emitter re-publishes the ONE
// contract table verbatim — the anti-drift guarantee between
// `observer contract --json` and docs/mcp-contract.md.
func TestContractJSONToolsMatchTable(t *testing.T) {
	t.Parallel()
	doc := runContractJSON(t)
	want := mcp.ContractTools()
	if len(doc.MCP.Tools) != len(want) {
		t.Fatalf("tool count = %d, want %d", len(doc.MCP.Tools), len(want))
	}
	for i, got := range doc.MCP.Tools {
		if got != want[i] {
			t.Errorf("tool[%d] = %+v, want %+v - the emitter must read internal/mcp's table, not a copy", i, got, want[i])
		}
	}
	names := make([]string, len(doc.MCP.Tools))
	for i, tl := range doc.MCP.Tools {
		names[i] = tl.Name
	}
	if !sort.StringsAreSorted(names) {
		t.Errorf("emitted tools are not alphabetical: %v", names)
	}
}

// TestPublicAdapterRow is the table-driven projection check: every field is
// derived from the capability SHAPE, and an ungrounded field stays zero
// (never fabricated).
func TestPublicAdapterRow(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   integration.Capability
		want contractAdapter
	}{
		{
			name: "zero value stays honest",
			in:   integration.Capability{Tool: "some-tool"},
			want: contractAdapter{Tool: "some-tool", NativeRails: []string{}},
		},
		{
			name: "full flagship row",
			in: integration.Capability{
				Tool:        "flagship",
				Proxy:       &integration.ProxyRoute{Kind: integration.RouteEnvSettings, EnvVar: "ANTHROPIC_BASE_URL"},
				Routability: integration.RouteStatusRoutableNow,
				Hook:        integration.HookSpec{Mechanism: integration.HookClaudeSettings, AutoWired: true},
				MCP:         &integration.MCPTarget{Format: integration.MCPServersJSON, Implemented: true},
				Native:      integration.NativeRails{A: true, B: true, C: true},
				TokenTier:   integration.TokenTier{Best: "proxy"},
			},
			want: contractAdapter{
				Tool:          "flagship",
				ProxyRoute:    "env_settings",
				Routability:   "routable_now",
				HookMechanism: "claude_settings_json",
				HookAutoWired: true,
				MCPAvailable:  true,
				MCPFormat:     "mcp_servers_json",
				TokenTier:     "proxy",
				NativeRails:   []string{"A", "B", "C"},
			},
		},
		{
			name: "hook receiver present but not auto-wired",
			in: integration.Capability{
				Tool:      "half-wired",
				Hook:      integration.HookSpec{Mechanism: integration.HookClineCLIJSONL},
				MCP:       &integration.MCPTarget{Format: integration.MCPCodexTOML},
				TokenTier: integration.TokenTier{Best: "sqlite", Gap: "no cache tier"},
				Native:    integration.NativeRails{C: true},
			},
			want: contractAdapter{
				Tool:          "half-wired",
				HookMechanism: "cline_cli_hooks_jsonl",
				HookAutoWired: false,
				MCPAvailable:  false,
				MCPFormat:     "codex_config_toml",
				TokenTier:     "sqlite",
				TokenGap:      "no cache tier",
				NativeRails:   []string{"C"},
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := publicAdapterRow(tc.in)
			gotJSON, _ := json.Marshal(got)
			wantJSON, _ := json.Marshal(tc.want)
			if string(gotJSON) != string(wantJSON) {
				t.Errorf("publicAdapterRow:\n got: %s\nwant: %s", gotJSON, wantJSON)
			}
		})
	}
}

// TestContractHumanRender pins the operator-facing summary carries the
// contract's headline facts, including the explicit out-of-contract note
// for the dashboard HTTP API.
func TestContractHumanRender(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderContract(&buf, buildContractDoc())
	out := buf.String()
	for _, want := range []string{
		"MCP server name: observer",
		"MCP TOOL",
		"config-gated",
		"always registered",
		"stable",
		"conditional",
		"experimental",
		"https://superbased.app/docs/reference/mcp-contract",
		"The dashboard HTTP API is NOT part of this contract",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("contract render missing %q\n---\n%s", want, out)
		}
	}
}
