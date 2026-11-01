package managedsettings

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestGenerateCortex(t *testing.T) {
	for _, tc := range []struct {
		name, os, wantSettings, wantMCP string
	}{
		{"linux_default", "", "/etc/cortex/managed-settings.json", "/etc/cortex/mcp.json"},
		{"darwin", "darwin", "/Library/Application Support/Cortex/managed-settings.json", "/Library/Application Support/Cortex/mcp.json"},
		{"windows", "windows", `C:\ProgramData\Cortex\managed-settings.json`, `C:\ProgramData\Cortex\mcp.json`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := GenerateCortex(CortexOptions{OS: tc.os, IncludeMCP: true, Banner: "Managed by IT"})
			if err != nil {
				t.Fatal(err)
			}
			if a.ManagedSettingsPath != tc.wantSettings || a.MCPPath != tc.wantMCP {
				t.Fatalf("paths %q %q", a.ManagedSettingsPath, a.MCPPath)
			}
			var s struct {
				Version string `json:"version"`
				Files   struct {
					MCPFile string `json:"mcpFile"`
				} `json:"files"`
				UI struct {
					ShowManagedBanner bool   `json:"showManagedBanner"`
					BannerText        string `json:"bannerText"`
				} `json:"ui"`
			}
			if err := json.Unmarshal(a.ManagedSettingsJSON, &s); err != nil {
				t.Fatal(err)
			}
			if s.Version != "1.0" || s.Files.MCPFile != tc.wantMCP || !s.UI.ShowManagedBanner || s.UI.BannerText != "Managed by IT" {
				t.Fatalf("settings = %+v", s)
			}
			var m struct {
				MCPServers map[string]struct {
					Type    string   `json:"type"`
					Command string   `json:"command"`
					Args    []string `json:"args"`
				} `json:"mcpServers"`
			}
			if err := json.Unmarshal(a.MCPJSON, &m); err != nil {
				t.Fatal(err)
			}
			pin := m.MCPServers[MCPServerName]
			if pin.Type != "stdio" || pin.Command != "npx" || strings.Join(pin.Args, " ") != "-y "+DefaultMCPPackage+" serve" {
				t.Fatalf("mcp pin = %+v", pin)
			}
			// No telemetry key exists in Cortex managed settings; none is invented.
			if strings.Contains(string(a.ManagedSettingsJSON), "otel") || strings.Contains(strings.ToLower(string(a.ManagedSettingsJSON)), "telemetry") {
				t.Fatalf("an invented telemetry key: %s", a.ManagedSettingsJSON)
			}
		})
	}
	if _, err := GenerateCortex(CortexOptions{}); err == nil {
		t.Error("nothing to emit was accepted")
	}
	if _, err := GenerateCortex(CortexOptions{OS: "plan9", IncludeMCP: true}); err == nil {
		t.Error("an unknown OS was accepted")
	}
	if _, err := GenerateCortex(CortexOptions{IncludeMCP: true, MCPFilePath: "relative/mcp.json"}); err == nil {
		t.Error("a relative mcpFile was accepted")
	}
	a, err := GenerateCortex(CortexOptions{Banner: "only a banner"})
	if err != nil || a.MCPJSON != nil || strings.Contains(string(a.ManagedSettingsJSON), "mcpFile") {
		t.Fatalf("banner-only: %v %s", err, a.ManagedSettingsJSON)
	}
}

func TestGenerateBob(t *testing.T) {
	a, err := GenerateBob(BobOptions{OTLPEndpoint: "http://127.0.0.1:4318"})
	if err != nil {
		t.Fatal(err)
	}
	var policy map[string]any
	if err := json.Unmarshal(a.PolicyJSON, &policy); err != nil {
		t.Fatal(err)
	}
	if len(policy) != 1 {
		t.Fatalf("policy carries %d keys, want only OtelConfiguration: %v", len(policy), policy)
	}
	raw, ok := policy[BobPolicyName].(string)
	if !ok {
		t.Fatalf("OtelConfiguration must be a JSON STRING (Bob ignores a wrong-typed policy): %T", policy[BobPolicyName])
	}
	var otel map[string]string
	if err := json.Unmarshal([]byte(raw), &otel); err != nil {
		t.Fatal(err)
	}
	if otel["OTEL_EXPORTER_OTLP_ENDPOINT"] != "http://127.0.0.1:4318" || otel["OTEL_EXPORTER_OTLP_PROTOCOL"] != "http/json" {
		t.Fatalf("otel = %v", otel)
	}
	for k := range otel {
		if strings.HasPrefix(k, "OTEL_INCLUDE_") {
			t.Errorf("content switch %s set without IncludeContent", k)
		}
	}
	if !strings.Contains(a.Registry, `[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\IBM\Bob]`) || !strings.Contains(a.Registry, `"OtelConfiguration"="{\"OTEL_EXPORTER_OTLP_ENDPOINT\"`) {
		t.Fatalf("registry = %s", a.Registry)
	}
	if !strings.Contains(a.MobileConfig, "<string>com.ibm.bob</string>") || !strings.Contains(a.MobileConfig, "<key>OtelConfiguration</key>") {
		t.Fatalf("mobileconfig = %s", a.MobileConfig)
	}
	if strings.Contains(string(a.PolicyJSON), "EnforcedHooks") || strings.Contains(a.Registry, "EnforcedHooks") {
		t.Fatal("EnforcedHooks emitted (would double-fire Observer's own Bob hooks)")
	}

	c, err := GenerateBob(BobOptions{OTLPEndpoint: "http://127.0.0.1:4317", Protocol: "grpc", ServiceName: "IBM Bob", IncludeContent: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.OTelConfig["OTEL_INCLUDE_USER_PROMPTS"] != "1" || c.OTelConfig["OTEL_EXPORTER_OTLP_PROTOCOL"] != "grpc" || c.OTelConfig["OTEL_SERVICE_NAME"] != "IBM Bob" {
		t.Fatalf("otel = %v", c.OTelConfig)
	}
	for _, bad := range []BobOptions{{}, {OTLPEndpoint: "127.0.0.1:4318"}, {OTLPEndpoint: "http://127.0.0.1:4318", Protocol: "udp"}} {
		if _, err := GenerateBob(bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

// AP-135 decisions of 2026-10-24: EnforcedHooks rides every channel as a
// STRING (Bob ignores a wrong-typed policy), the Windows channel may name a
// different binary, and EnableTelemetry=false is refused next to the OTLP
// export Bob gates on the same setting.
func TestGenerateBobEnforcedHooksAndTelemetry(t *testing.T) {
	posix := `{"PreToolUse":[{"hooks":[{"command":"observer hook ibm-bob PreToolUse","timeout":30,"type":"command"}]}]}`
	win := `{"PreToolUse":[{"hooks":[{"command":"\"C:\\Program Files\\o\\observer.exe\" hook ibm-bob PreToolUse","timeout":30,"type":"command"}]}]}`
	a, err := GenerateBob(BobOptions{OTLPEndpoint: "http://127.0.0.1:4318", EnforcedHooks: posix, EnforcedHooksWindows: win})
	if err != nil {
		t.Fatal(err)
	}
	var policy map[string]any
	if err := json.Unmarshal(a.PolicyJSON, &policy); err != nil {
		t.Fatal(err)
	}
	if s, ok := policy[BobEnforcedHooksPolicy].(string); !ok || s != posix {
		t.Fatalf("EnforcedHooks must be the posix value as a JSON STRING: %#v", policy[BobEnforcedHooksPolicy])
	}
	if _, ok := policy[BobPolicyName].(string); !ok || len(policy) != 2 {
		t.Fatalf("policy = %v", policy)
	}
	if !strings.Contains(a.Registry, `"EnforcedHooks"="{\"PreToolUse\"`) || !strings.Contains(a.Registry, `C:\\\\Program Files`) {
		t.Fatalf("registry must carry the Windows value as REG_SZ:\n%s", a.Registry)
	}
	if !strings.Contains(a.MobileConfig, "<key>EnforcedHooks</key>") || !strings.Contains(a.MobileConfig, "<string>{&quot;PreToolUse&quot;") {
		t.Fatalf("mobileconfig = %s", a.MobileConfig)
	}
	if !strings.Contains(a.Readme, "stands down") || !strings.Contains(a.Readme, "different binary") {
		t.Fatalf("readme = %s", a.Readme)
	}

	// EnableTelemetry=false cannot ride next to OtelConfiguration.
	if _, err := GenerateBob(BobOptions{OTLPEndpoint: "http://127.0.0.1:4318", DisableVendorTelemetry: true}); !errors.Is(err, ErrBobTelemetryKillsExport) {
		t.Fatalf("telemetry off + export = %v", err)
	}
	b, err := GenerateBob(BobOptions{OmitOTel: true, DisableVendorTelemetry: true, EnforcedHooks: posix})
	if err != nil {
		t.Fatal(err)
	}
	policy = nil
	if err := json.Unmarshal(b.PolicyJSON, &policy); err != nil {
		t.Fatal(err)
	}
	if policy[BobEnableTelemetryPolicy] != false || policy[BobPolicyName] != nil || b.OTelConfig != nil {
		t.Fatalf("policy = %v", policy)
	}
	if !strings.Contains(b.Registry, `"EnableTelemetry"=dword:00000000`) || !strings.Contains(b.MobileConfig, "<key>EnableTelemetry</key>") || !strings.Contains(b.MobileConfig, "<false/>") {
		t.Fatalf("EnableTelemetry channels:\n%s\n%s", b.Registry, b.MobileConfig)
	}
	if !strings.Contains(b.Readme, "Bobalytics") {
		t.Fatalf("readme = %s", b.Readme)
	}

	for _, bad := range []BobOptions{
		{OmitOTel: true},
		{OTLPEndpoint: "http://127.0.0.1:4318", EnforcedHooks: "[1]"},
		{OTLPEndpoint: "http://127.0.0.1:4318", EnforcedHooks: "{}"},
	} {
		if _, err := GenerateBob(bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}
