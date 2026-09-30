package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// TestMCPRelayDefaultOffIsByteIdentical: a config with no [mcp_relay]
// section loads with the relay OFF, the encoded default section carries
// enabled=false, and an operator file that never mentions the block is
// unchanged by Load (no file written, nothing rewritten).
func TestMCPRelayDefaultOffIsByteIdentical(t *testing.T) {
	d := Default()
	if d.MCPRelay.Enabled {
		t.Fatal("mcp_relay must default OFF")
	}
	if d.MCPRelay.Mode != MCPRelayModeStdioWrapper || d.MCPRelay.AuditMode != MCPRelayAuditAsync || d.MCPRelay.PollIntervalSeconds != DefaultMCPRelayPollIntervalSeconds {
		t.Fatalf("defaults %+v", d.MCPRelay)
	}
	if d.MCPRelay.Listen != "" || d.MCPRelay.IPCPath != "" || d.MCPRelay.GatewayURL != "" {
		t.Fatalf("listen/ipc/gateway must default empty: %+v", d.MCPRelay)
	}
	if err := Validate(d); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := "[observer]\nlog_level = \"info\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: path, Env: func(string) string { return "" }, GovernanceSidecar: NoGovernanceSidecar})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MCPRelay.Enabled {
		t.Fatal("absent section must load OFF")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != body {
		t.Fatalf("Load rewrote the operator file:\n%s", after)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("Load must write no sibling file: %v", entries)
	}
}

// TestMCPRelayLoadAndExpand: a full section round-trips and ~ expands.
func TestMCPRelayLoadAndExpand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	body := `[mcp_relay]
enabled = true
mode = "ipc"
gateway_url = "https://mcp-gw.acme.example"
audit_mode = "strict"
listen = "127.0.0.1:8858"
ipc_path = "~/.observer/mcp-relay.sock"
poll_interval_seconds = 60
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: path, Env: func(string) string { return "" }, GovernanceSidecar: NoGovernanceSidecar})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	m := cfg.MCPRelay
	if !m.Enabled || m.Mode != MCPRelayModeIPC || m.AuditMode != MCPRelayAuditStrict || m.Listen != "127.0.0.1:8858" || m.PollIntervalSeconds != 60 || m.GatewayURL != "https://mcp-gw.acme.example" {
		t.Fatalf("loaded %+v", m)
	}
	if strings.HasPrefix(m.IPCPath, "~") || !strings.HasSuffix(m.IPCPath, filepath.Join(".observer", "mcp-relay.sock")) {
		t.Fatalf("ipc_path not expanded: %q", m.IPCPath)
	}
	var probe struct {
		MCPRelay MCPRelayConfig `toml:"mcp_relay"`
	}
	if _, err := toml.Decode(body, &probe); err != nil {
		t.Fatal(err)
	}
	if probe.MCPRelay.PollIntervalSeconds != 60 {
		t.Fatal("toml tags do not round-trip")
	}
}

// TestValidateMCPRelay is the validation table.
func TestValidateMCPRelay(t *testing.T) {
	cases := []struct {
		name string
		m    MCPRelayConfig
		want string // substring of the error, "" = valid
	}{
		{"zero value", MCPRelayConfig{}, ""},
		{"defaults", Default().MCPRelay, ""},
		{"loopback listen", MCPRelayConfig{Listen: "127.0.0.1:8858"}, ""},
		{"localhost listen", MCPRelayConfig{Listen: "localhost:8858"}, ""},
		{"ipv6 loopback listen", MCPRelayConfig{Listen: "[::1]:8858"}, ""},
		{"bad mode", MCPRelayConfig{Mode: "tcp"}, "mcp_relay.mode"},
		{"bad audit mode", MCPRelayConfig{AuditMode: "sync"}, "mcp_relay.audit_mode"},
		{"http gateway", MCPRelayConfig{GatewayURL: "http://gw"}, "mcp_relay.gateway_url"},
		{"non-loopback listen", MCPRelayConfig{Listen: "0.0.0.0:8858"}, "loopback"},
		{"lan listen", MCPRelayConfig{Listen: "10.0.0.5:8858"}, "loopback"},
		{"no port", MCPRelayConfig{Listen: "127.0.0.1"}, "host:port"},
		{"bad port", MCPRelayConfig{Listen: "127.0.0.1:99999"}, "port"},
		{"poll too low", MCPRelayConfig{PollIntervalSeconds: 5}, "poll_interval_seconds"},
		{"poll too high", MCPRelayConfig{PollIntervalSeconds: 3601}, "poll_interval_seconds"},
		{"enabled with bad mode still refused", MCPRelayConfig{Enabled: true, Mode: "x"}, "mcp_relay.mode"},
		{"disabled with bad mode still refused", MCPRelayConfig{Enabled: false, Mode: "x"}, "mcp_relay.mode"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateMCPRelay(c.m)
			if c.want == "" {
				if err != nil {
					t.Fatalf("unexpected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want containing %q", err, c.want)
			}
		})
	}
}

// TestAcceptFamiliesAcceptsMCPAccess: [org_client.policy].accept_families
// may name tools.mcp_access (the P4 family), and the error text lists it.
func TestAcceptFamiliesAcceptsMCPAccess(t *testing.T) {
	if err := validateOrgClientPolicy(OrgClientPolicyConfig{AcceptFamilies: []string{"tools.mcp_access"}, PreauthorizeEnforce: []string{"tools.mcp_access"}}); err != nil {
		t.Fatalf("tools.mcp_access must be accepted: %v", err)
	}
	err := validateOrgClientPolicy(OrgClientPolicyConfig{AcceptFamilies: []string{"tools.nope"}})
	if err == nil || !strings.Contains(err.Error(), "tools.mcp_access") {
		t.Fatalf("error must list tools.mcp_access: %v", err)
	}
}
