package managedsettings

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerateClaudeCode_BothArtifacts(t *testing.T) {
	got, err := GenerateClaudeCode(ClaudeCodeOptions{
		OTelGRPCEndpoint: "http://127.0.0.1:4317",
		IncludeMCP:       true,
		IncludeTelemetry: true,
		ExclusiveMCP:     true,
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// managed-settings env block points OTel at the receiver.
	var settings struct {
		Env map[string]string `json:"env"`
	}
	if err := json.Unmarshal(got.ManagedSettingsJSON, &settings); err != nil {
		t.Fatalf("settings json: %v", err)
	}
	if settings.Env["CLAUDE_CODE_ENABLE_TELEMETRY"] != "1" ||
		settings.Env["OTEL_EXPORTER_OTLP_ENDPOINT"] != "http://127.0.0.1:4317" ||
		settings.Env["OTEL_EXPORTER_OTLP_PROTOCOL"] != "grpc" {
		t.Fatalf("env block wrong: %+v", settings.Env)
	}

	// managed-mcp pins the server with the mandatory -y npx form.
	var mcp struct {
		MCPServers map[string]struct {
			Type    string   `json:"type"`
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(got.ManagedMCPJSON, &mcp); err != nil {
		t.Fatalf("mcp json: %v", err)
	}
	srv, ok := mcp.MCPServers[MCPServerName]
	if !ok {
		t.Fatalf("mcp server %q missing: %+v", MCPServerName, mcp.MCPServers)
	}
	if srv.Command != "npx" || len(srv.Args) < 2 || srv.Args[0] != "-y" {
		t.Fatalf("mcp pin not self-bootstrapping with -y: %+v", srv)
	}

	// README must teach the MCP-vs-telemetry split.
	if !strings.Contains(got.Readme, "NOT") || !strings.Contains(strings.ToLower(got.Readme), "telemetry") {
		t.Fatalf("readme missing the MCP-vs-telemetry distinction")
	}
}

func TestGenerateClaudeCode_TelemetryRequiresEndpoint(t *testing.T) {
	_, err := GenerateClaudeCode(ClaudeCodeOptions{IncludeTelemetry: true})
	if err == nil {
		t.Fatal("expected error when telemetry requested without endpoint")
	}
}

func TestGenerateClaudeCode_NothingSelected(t *testing.T) {
	if _, err := GenerateClaudeCode(ClaudeCodeOptions{}); err == nil {
		t.Fatal("expected error when no artifact selected")
	}
}

func TestGenerateClaudeCode_MCPOnly(t *testing.T) {
	got, err := GenerateClaudeCode(ClaudeCodeOptions{IncludeMCP: true, ExclusiveMCP: true, MCPPackage: "@superbased/observer@1.8.4"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if got.ManagedSettingsJSON != nil {
		t.Fatalf("telemetry artifact should be nil when not requested")
	}
	if !strings.Contains(string(got.ManagedMCPJSON), "@superbased/observer@1.8.4") {
		t.Fatalf("pinned package not honored: %s", got.ManagedMCPJSON)
	}
}

// TestGenerateClaudeCode_ExclusiveMCPIsOptIn pins CC-6 / decision D2: by
// default the generator emits NO managed-mcp.json (which would take
// exclusive MCP control from every developer), only the allowedMcpServers
// entry for the server `observer init` registers per node.
func TestGenerateClaudeCode_ExclusiveMCPIsOptIn(t *testing.T) {
	got, err := GenerateClaudeCode(ClaudeCodeOptions{
		OTelGRPCEndpoint: "http://127.0.0.1:4317",
		IncludeMCP:       true,
		IncludeTelemetry: true,
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if got.ManagedMCPJSON != nil {
		t.Fatalf("managed-mcp.json emitted by default (exclusive MCP control):\n%s", got.ManagedMCPJSON)
	}
	var entry allowEntry
	if err := json.Unmarshal(got.AllowedMCPServerEntryJSON, &entry); err != nil {
		t.Fatalf("allowed entry json: %v\n%s", err, got.AllowedMCPServerEntryJSON)
	}
	if strings.Join(entry.ServerCommand, " ") != "observer serve" {
		t.Fatalf("serverCommand = %v, want the default user-scope command", entry.ServerCommand)
	}
	// The entry must never be a list on its own: that would block every
	// other server.
	if strings.Contains(string(got.AllowedMCPServerEntryJSON), "allowedMcpServers") || strings.Contains(string(got.ManagedSettingsJSON), "allowedMcpServers") {
		t.Fatalf("the entry was emitted as a whole allowedMcpServers list")
	}
	for _, want := range []string{"allowed-mcp-server.json", "blocks every", "claude mcp get observer"} {
		if !strings.Contains(got.Readme, want) {
			t.Errorf("README missing %q:\n%s", want, got.Readme)
		}
	}
	if strings.Contains(got.Readme, "managed-mcp.json** pins") {
		t.Errorf("README describes a managed-mcp.json that was not generated")
	}

	// The org admin turns exclusive control on; the README names the cost.
	ex, err := GenerateClaudeCode(ClaudeCodeOptions{IncludeMCP: true, ExclusiveMCP: true})
	if err != nil {
		t.Fatalf("generate exclusive: %v", err)
	}
	if ex.ManagedMCPJSON == nil || ex.AllowedMCPServerEntryJSON != nil {
		t.Fatalf("exclusive: managed-mcp=%v entry=%v, want only managed-mcp.json", ex.ManagedMCPJSON != nil, ex.AllowedMCPServerEntryJSON != nil)
	}
	if !strings.Contains(ex.Readme, "exclusive control") {
		t.Errorf("exclusive README does not name the exclusive-control cost:\n%s", ex.Readme)
	}
}

// allowEntry decodes the generated allowedMcpServers entry.
type allowEntry struct {
	ServerCommand []string `json:"serverCommand"`
}

// TestGenerateClaudeCode_MCPServerCommand pins that the entry carries the
// nodes' exact command (Claude Code matches every argument, in order).
func TestGenerateClaudeCode_MCPServerCommand(t *testing.T) {
	got, err := GenerateClaudeCode(ClaudeCodeOptions{IncludeMCP: true, MCPServerCommand: []string{`C:\Program Files\Observer\observer.exe`, "serve"}})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var entry allowEntry
	if err := json.Unmarshal(got.AllowedMCPServerEntryJSON, &entry); err != nil {
		t.Fatal(err)
	}
	if len(entry.ServerCommand) != 2 || entry.ServerCommand[0] != `C:\Program Files\Observer\observer.exe` || entry.ServerCommand[1] != "serve" {
		t.Fatalf("serverCommand = %v", entry.ServerCommand)
	}
	if _, err := GenerateClaudeCode(ClaudeCodeOptions{IncludeMCP: true, MCPServerCommand: []string{"observer", " "}}); err == nil {
		t.Fatal("an empty argument in MCPServerCommand: want an error")
	}
}
