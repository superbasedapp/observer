package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runEmitManagedSettings runs `org emit-managed-settings` with args against
// an empty config in a temp home and returns stdout.
func runEmitManagedSettings(t *testing.T, args ...string) (string, error) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	cmd := newOrgEmitManagedSettingsCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append([]string{"--config", filepath.Join(home, "config.toml")}, args...))
	err := cmd.Execute()
	return out.String(), err
}

// TestEmitManagedSettings_TargetOS pins --target-os per client: windows
// writes each client's grounded Windows pin, linux and darwin the plain npx
// pin, and an unknown OS is refused.
func TestEmitManagedSettings_TargetOS(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		want    string
		notWant string
	}{
		{"claude-code windows", []string{"--provider", "claude-code", "--exclusive-mcp", "--otel-endpoint", "http://127.0.0.1:4317", "--target-os", "windows"}, `"command": "cmd"`, `"command": "npx"`},
		{"claude-code linux", []string{"--provider", "claude-code", "--exclusive-mcp", "--otel-endpoint", "http://127.0.0.1:4317", "--target-os", "linux"}, `"command": "npx"`, `"command": "cmd"`},
		{"claude-code darwin", []string{"--provider", "claude-code", "--exclusive-mcp", "--otel-endpoint", "http://127.0.0.1:4317", "--target-os", "darwin"}, `"command": "npx"`, `"command": "cmd"`},
		{"codex windows", []string{"--provider", "codex", "--target-os", "windows"}, `command = "npx.cmd"`, `command = "npx"` + "\n"},
		{"codex linux", []string{"--provider", "codex", "--target-os", "linux"}, `command = "npx"` + "\n", `npx.cmd`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runEmitManagedSettings(t, tc.args...)
			if err != nil {
				t.Fatalf("emit: %v\n%s", err, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("output missing %q:\n%s", tc.want, out)
			}
			if strings.Contains(out, tc.notWant) {
				t.Errorf("output unexpectedly contains %q:\n%s", tc.notWant, out)
			}
		})
	}

	if _, err := runEmitManagedSettings(t, "--provider", "codex", "--target-os", "plan9"); err == nil {
		t.Error("--target-os plan9: want an error")
	}
}

// TestEmitManagedSettings_ClaudeExclusiveMCPIsOptIn pins CC-6 / decision
// D2 at the CLI: by default no managed-mcp.json (exclusive MCP control) is
// generated, only the allowedMcpServers entry for the per-node server;
// --exclusive-mcp is the org admin's opt-in, and --mcp-binary sets the
// entry's command.
func TestEmitManagedSettings_ClaudeExclusiveMCPIsOptIn(t *testing.T) {
	base := []string{"--provider", "claude-code", "--otel-endpoint", "http://127.0.0.1:4317", "--target-os", "linux"}
	out, err := runEmitManagedSettings(t, base...)
	if err != nil {
		t.Fatalf("emit: %v\n%s", err, out)
	}
	if strings.Contains(out, "===== managed-mcp.json =====") {
		t.Errorf("default emitted managed-mcp.json:\n%s", out)
	}
	if !strings.Contains(out, "===== allowed-mcp-server.json =====") || !strings.Contains(out, `"serverCommand": [`) {
		t.Errorf("default is missing the allowedMcpServers entry:\n%s", out)
	}

	out, err = runEmitManagedSettings(t, append(base, "--mcp-binary", "/opt/observer/bin/observer")...)
	if err != nil {
		t.Fatalf("emit --mcp-binary: %v\n%s", err, out)
	}
	if !strings.Contains(out, `"/opt/observer/bin/observer",`) {
		t.Errorf("--mcp-binary not in the entry:\n%s", out)
	}

	out, err = runEmitManagedSettings(t, append(base, "--exclusive-mcp")...)
	if err != nil {
		t.Fatalf("emit --exclusive-mcp: %v\n%s", err, out)
	}
	if !strings.Contains(out, "===== managed-mcp.json =====\n{") || strings.Contains(out, "allowed-mcp-server.json =====") {
		t.Errorf("--exclusive-mcp: want managed-mcp.json and no allowlist entry:\n%s", out)
	}

	dir := t.TempDir()
	if _, err := runEmitManagedSettings(t, append(base, "--out", dir)...); err != nil {
		t.Fatalf("emit --out: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "managed-mcp.json")); !os.IsNotExist(err) {
		t.Errorf("--out wrote managed-mcp.json by default (err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "allowed-mcp-server.json")); err != nil {
		t.Errorf("--out did not write allowed-mcp-server.json: %v", err)
	}
}

// TestDefaultEmitTargetOS pins that the default is always a valid value.
func TestDefaultEmitTargetOS(t *testing.T) {
	if got := defaultEmitTargetOS(); !validEmitTargetOS(got) {
		t.Fatalf("defaultEmitTargetOS() = %q, not a valid --target-os", got)
	}
}
