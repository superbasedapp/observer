package config

import (
	"strings"
	"testing"
)

// TestValidateTerminalSandboxOpenShell: one case per accepted and refused
// shape of [terminal.sandbox.openshell] (lane O1A).
func TestValidateTerminalSandboxOpenShell(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		c    TerminalSandboxOpenShellConfig
		err  string
	}{
		{"zero value (no block)", TerminalSandboxOpenShellConfig{}, ""},
		{"external", TerminalSandboxOpenShellConfig{GatewayMode: "external"}, ""},
		{"managed", TerminalSandboxOpenShellConfig{GatewayMode: "managed"}, ""},
		{"unknown mode", TerminalSandboxOpenShellConfig{GatewayMode: "remote"}, "gateway_mode"},
		{"managed with an endpoint", TerminalSandboxOpenShellConfig{GatewayMode: "managed", Endpoint: "https://127.0.0.1:17670"}, "picks its own loopback port"},
		{"external with an endpoint", TerminalSandboxOpenShellConfig{GatewayMode: "external", Endpoint: "https://127.0.0.1:17670"}, ""},
		{"loopback endpoint", TerminalSandboxOpenShellConfig{Endpoint: "https://127.0.0.1:17670"}, ""},
		{"localhost endpoint", TerminalSandboxOpenShellConfig{Endpoint: "https://localhost:17670/"}, ""},
		{"ipv6 loopback endpoint", TerminalSandboxOpenShellConfig{Endpoint: "https://[::1]:17670"}, ""},
		{"plain http", TerminalSandboxOpenShellConfig{Endpoint: "http://127.0.0.1:17670"}, "https"},
		{"remote host", TerminalSandboxOpenShellConfig{Endpoint: "https://gateway.example.com:17670"}, "loopback"},
		{"lan address", TerminalSandboxOpenShellConfig{Endpoint: "https://192.168.1.5:17670"}, "loopback"},
		{"credentials in the url", TerminalSandboxOpenShellConfig{Endpoint: "https://user:SENTINEL@127.0.0.1:17670"}, "scheme, host and port"},
		{"a path", TerminalSandboxOpenShellConfig{Endpoint: "https://127.0.0.1:17670/api"}, "scheme, host and port"},
		{"a query", TerminalSandboxOpenShellConfig{Endpoint: "https://127.0.0.1:17670?x=1"}, "scheme, host and port"},
		{"version pin", TerminalSandboxOpenShellConfig{Version: "0.1.6"}, ""},
		{"version pin with v", TerminalSandboxOpenShellConfig{Version: "v0.1.6"}, ""},
		{"version not a version", TerminalSandboxOpenShellConfig{Version: "latest"}, "version"},
		{"version pre-release", TerminalSandboxOpenShellConfig{Version: "0.1.7-rc.1"}, "version"},
		{"absolute state dir", TerminalSandboxOpenShellConfig{StateDir: "/var/lib/observer-openshell"}, ""},
		{"relative state dir", TerminalSandboxOpenShellConfig{StateDir: "openshell"}, "state_dir"},
		{"unclean state dir", TerminalSandboxOpenShellConfig{StateDir: "/var/lib/../tmp"}, "state_dir"},
		{"windows-style state dir", TerminalSandboxOpenShellConfig{StateDir: `C:\observer\openshell`}, "state_dir"},
	}
	for _, tc := range cases {
		err := validateTerminalSandboxOpenShell(tc.c)
		switch {
		case tc.err == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
			t.Errorf("%s: err %v, want one naming %q", tc.name, err, tc.err)
		}
	}
}

// TestOpenShellBlockIsAdditive: the default config carries the zero block,
// which validates, so an existing config with no block is unchanged.
func TestOpenShellBlockIsAdditive(t *testing.T) {
	t.Parallel()
	d := Default()
	if d.Terminal.Sandbox.OpenShell != (TerminalSandboxOpenShellConfig{}) {
		t.Fatalf("default block %+v, want the zero value", d.Terminal.Sandbox.OpenShell)
	}
	if err := Validate(d); err != nil {
		t.Fatalf("default config: %v", err)
	}
}

// TestEffectiveGatewayMode is one case per row of the resolution table
// (decision D2: managed is the default; an explicit external, or an
// endpoint with no mode, keeps the user's own gateway).
func TestEffectiveGatewayMode(t *testing.T) {
	t.Parallel()
	ep := "https://127.0.0.1:17670"
	cases := []struct {
		mode, endpoint, want string
	}{
		{"external", "", "external"},
		{"external", ep, "external"},
		{"managed", "", "managed"},
		{"managed", ep, "managed"},
		{"", ep, "external"},
		{"", "", "managed"},
		{"remote", "", ""},
	}
	if len(cases)-1 != len(openShellModeRows) {
		t.Fatalf("%d rows, %d cases", len(openShellModeRows), len(cases)-1)
	}
	for _, tc := range cases {
		c := TerminalSandboxOpenShellConfig{GatewayMode: tc.mode, Endpoint: tc.endpoint}
		if got := c.EffectiveGatewayMode(); got != tc.want {
			t.Errorf("mode %q endpoint %q: %q, want %q", tc.mode, tc.endpoint, got, tc.want)
		}
	}
}
