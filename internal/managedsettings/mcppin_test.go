package managedsettings

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/BurntSushi/toml"
)

// TestMCPPinLaunch_ClientByOS pins the MCP pin each generator writes, per
// client x target OS, by decoding the artifact the client reads. POSIX is
// the plain npx form; native Windows takes the form each client's registry
// row grounds (Claude Code `cmd /c npx`, Codex `npx.cmd`).
func TestMCPPinLaunch_ClientByOS(t *testing.T) {
	const pkg = "@superbased/observer"
	plain := []string{"-y", pkg, "serve"}
	cases := []struct {
		client, goos string
		wantCmd      string
		wantArgs     []string
	}{
		{"claude-code", "", "npx", plain},
		{"claude-code", "linux", "npx", plain},
		{"claude-code", "darwin", "npx", plain},
		{"claude-code", "windows", "cmd", []string{"/c", "npx", "-y", pkg, "serve"}},
		{"codex", "", "npx", plain},
		{"codex", "linux", "npx", plain},
		{"codex", "darwin", "npx", plain},
		{"codex", "windows", "npx.cmd", plain},
	}
	for _, tc := range cases {
		t.Run(tc.client+"/"+tc.goos, func(t *testing.T) {
			var gotCmd string
			var gotArgs []string
			switch tc.client {
			case "claude-code":
				arts, err := GenerateClaudeCode(ClaudeCodeOptions{IncludeMCP: true, ExclusiveMCP: true, TargetOS: tc.goos})
				if err != nil {
					t.Fatalf("GenerateClaudeCode: %v", err)
				}
				var doc struct {
					MCPServers map[string]struct {
						Type    string   `json:"type"`
						Command string   `json:"command"`
						Args    []string `json:"args"`
					} `json:"mcpServers"`
				}
				if err := json.Unmarshal(arts.ManagedMCPJSON, &doc); err != nil {
					t.Fatalf("managed-mcp.json: %v", err)
				}
				srv := doc.MCPServers[MCPServerName]
				if srv.Type != "stdio" {
					t.Errorf("type = %q, want stdio", srv.Type)
				}
				gotCmd, gotArgs = srv.Command, srv.Args
			case "codex":
				arts, err := GenerateCodex(CodexOptions{IncludeMCP: true, TargetOS: tc.goos})
				if err != nil {
					t.Fatalf("GenerateCodex: %v", err)
				}
				var doc struct {
					MCPServers map[string]struct {
						Command string   `toml:"command"`
						Args    []string `toml:"args"`
					} `toml:"mcp_servers"`
				}
				if err := toml.Unmarshal(arts.ManagedConfigTOML, &doc); err != nil {
					t.Fatalf("managed_config.toml: %v", err)
				}
				srv := doc.MCPServers[CodexMCPServerName]
				gotCmd, gotArgs = srv.Command, srv.Args
			}
			if gotCmd != tc.wantCmd || !reflect.DeepEqual(gotArgs, tc.wantArgs) {
				t.Errorf("pin = %q %q, want %q %q", gotCmd, gotArgs, tc.wantCmd, tc.wantArgs)
			}
		})
	}
}

// TestValidatePinPackage pins that a Windows target refuses a package spec
// with a cmd.exe metacharacter in both generators, and that every other
// target accepts it as before.
func TestValidatePinPackage(t *testing.T) {
	cases := []struct {
		pkg, goos string
		wantErr   bool
	}{
		{"@superbased/observer@1.36.0", "windows", false},
		{"@superbased/observer&calc", "windows", true},
		{"@superbased/observer %PATH%", "windows", true},
		{"pkg|x", "windows", true},
		{"@superbased/observer&calc", "linux", false},
		{"@superbased/observer&calc", "", false},
	}
	for _, tc := range cases {
		_, ccErr := GenerateClaudeCode(ClaudeCodeOptions{IncludeMCP: true, ExclusiveMCP: true, MCPPackage: tc.pkg, TargetOS: tc.goos})
		_, cxErr := GenerateCodex(CodexOptions{IncludeMCP: true, MCPPackage: tc.pkg, TargetOS: tc.goos})
		if (ccErr != nil) != tc.wantErr || (cxErr != nil) != tc.wantErr {
			t.Errorf("pkg %q on %q: claude-code err=%v codex err=%v, wantErr=%v", tc.pkg, tc.goos, ccErr, cxErr, tc.wantErr)
		}
	}
	// No MCP pin requested: the package is never written, so never checked.
	if _, err := GenerateCodex(CodexOptions{IncludeProxyRoute: true, OpenAIBaseURL: DefaultCodexProxyBaseURL, MCPPackage: "x&y", TargetOS: "windows"}); err != nil {
		t.Errorf("no MCP pin: unexpected error %v", err)
	}
}

// TestTOMLString pins the TOML basic-string encoder: ordinary values match
// Go's %q byte for byte, and escapes stay inside TOML's grammar.
func TestTOMLString(t *testing.T) {
	cases := []struct{ in, want string }{
		{"npx", `"npx"`},
		{"@superbased/observer@1.2.3", `"@superbased/observer@1.2.3"`},
		{`a"b\c`, `"a\"b\\c"`},
		{"tab\there", `"tab\there"`},
		{"bell\x07", `"bell\u0007"`},
		{"café", `"café"`},
	}
	for _, tc := range cases {
		got := tomlString(tc.in)
		if got != tc.want {
			t.Errorf("tomlString(%q) = %s, want %s", tc.in, got, tc.want)
		}
		var v struct{ S string }
		if _, err := toml.Decode("S = "+got, &v); err != nil || v.S != tc.in {
			t.Errorf("tomlString(%q) does not round-trip: %v (got %q)", tc.in, err, v.S)
		}
	}
}
