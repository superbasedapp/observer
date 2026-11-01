package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestCopilotToolGateDenyIsStdoutOnly (WINNODE2 item 10): Copilot (the CLI
// and VS Code Copilot Chat's local agent) reports a non-zero hook exit as
// "Denied by preToolUse hook (hook errored)" and drops the reason; on
// Windows it runs the powershell field, where a native stderr line can make
// that exit non-zero. So a deny answers with the documented top-level
// permissionDecision and permissionDecisionReason on stdout, exit 0, and
// nothing at all on stderr.
func TestCopilotToolGateDenyIsStdoutOnly(t *testing.T) {
	c, ok := integration.For("copilot-cli")
	if !ok {
		t.Fatal("no copilot-cli registry row")
	}
	b, ok := c.Hook.Binding("preToolUse")
	if !ok || !toolGateServed(b) {
		t.Fatalf("copilot-cli preToolUse is not a served tool gate: %+v", b)
	}
	dir := t.TempDir()
	cp := filepath.Join(dir, "config.toml")
	writeFileT(t, cp, fmt.Sprintf("[observer]\ndb_path = %q\n[guard]\nenabled = true\nmode = \"enforce\"\n", filepath.Join(dir, "o.db")))
	body := `{"sessionId":"s1","cwd":"/home/dev/proj","toolName":"bash","toolArgs":"{\"command\":\"rm -rf /\"}"}`
	var stdout, stderr bytes.Buffer
	runToolGate("copilot-cli", "copilot-cli:preToolUse", b, []byte(body), false, cp, &stdout, &stderr)
	var reply struct {
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &reply); err != nil {
		t.Fatalf("stdout is not the Copilot reply: %q (%v)", stdout.String(), err)
	}
	if reply.PermissionDecision != "deny" || reply.PermissionDecisionReason == "" {
		t.Fatalf("reply = %+v, want a deny with its reason", reply)
	}
	if stderr.Len() != 0 {
		t.Fatalf("a Copilot hook wrote to stderr: %q", stderr.String())
	}
}
