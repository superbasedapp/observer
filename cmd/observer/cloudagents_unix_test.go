//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestCloudAgentsCLI_ConnectSyncDisconnect drives the real egress package
// against a stand-in `gh` on PATH that prints the recorded fixtures.
func TestCloudAgentsCLI_ConnectSyncDisconnect(t *testing.T) {
	cfg := plansTestConfig(t)
	bin := t.TempDir()
	fix, err := filepath.Abs(filepath.Join("..", "..", "testdata", "cloudagents", "copilot-agent"))
	if err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n" +
		"case \"$1 $2\" in\n" +
		"  'api user') cat '" + filepath.Join(fix, "user.json") + "' ;;\n" +
		"  'agent-task list') cat '" + filepath.Join(fix, "list.json") + "' ;;\n" +
		"  *) echo 'unexpected' >&2; exit 2 ;;\n" +
		"esac\n"
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(script), 0o700); err != nil { //nolint:gosec // G306: test script must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+"/usr/bin"+string(os.PathListSeparator)+"/bin")

	out, err := runCloudAgents(t, "test", "copilot-agent", "--config", cfg)
	if err != nil || !strings.Contains(out, "reachable as octo-dev (5551234)") {
		t.Fatalf("test: %v %s", err, out)
	}
	out, err = runCloudAgents(t, "connect", "copilot-agent", "--config", cfg)
	if err != nil {
		t.Fatalf("connect: %v %s", err, out)
	}
	m := regexp.MustCompile(`linked as account (\d+)`).FindStringSubmatch(out)
	if m == nil || !strings.Contains(out, "3 task(s)") {
		t.Fatalf("connect output: %s", out)
	}
	out, err = runCloudAgents(t, "--config", cfg)
	if err != nil || !strings.Contains(out, "copilot-agent") || !strings.Contains(out, "Verified") {
		t.Fatalf("status: %v %s", err, out)
	}
	out, err = runCloudAgents(t, "sync", m[1], "--config", cfg)
	if err != nil || !strings.Contains(out, "0 new action(s)") {
		t.Fatalf("re-sync must be idempotent: %v %s", err, out)
	}
	out, err = runCloudAgents(t, "disconnect", m[1], "--config", cfg)
	if err != nil || !strings.Contains(out, "unlinked") {
		t.Fatalf("disconnect: %v %s", err, out)
	}

	// codex is not installed: the probe reports it and links nothing.
	out, err = runCloudAgents(t, "connect", "codex-cloud", "--config", cfg)
	if err == nil || !strings.Contains(out, "not_installed") || !strings.Contains(out, "npm i -g @openai/codex") {
		t.Fatalf("codex missing: %v %s", err, out)
	}
}
