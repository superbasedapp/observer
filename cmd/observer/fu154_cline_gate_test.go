package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
)

// TestFU154ClinePreToolUseIsServedByTheToolGate: the PreToolUse file
// Observer writes for the Cline CLI execs `observer hook cline-cli
// PreToolUse`; that invocation now resolves to the binding-driven tool gate
// (cline-pretool dialect), not the no-verdict allow, so a deny reaches Cline
// as {"cancel":true,...}.
func TestFU154ClinePreToolUseIsServedByTheToolGate(t *testing.T) {
	b, ok := standaloneToolGate("cline-cli", "PreToolUse")
	if !ok || b.Dialect != hook.ToolGateDialectCline {
		t.Fatalf("standaloneToolGate(cline-cli, PreToolUse) = %+v, %v; want the cline-pretool gate", b, ok)
	}
	setTestHome(t, t.TempDir())
	cfg := writeGuardConfig(t, "enforce")
	var out, errb bytes.Buffer
	// A payload the hook could not read in full is held under enforcement
	// whatever the rules say (SR27-D2), so the test needs no rule.
	body := []byte(`{"taskId":"t1","workspaceRoots":["/tmp/w"],"tool_call":{"name":"run_commands","input":{"commands":["ls"]}}}`)
	runToolGate("cline-cli", "cline-cli:PreToolUse", b, body, true, cfg, &out, &errb)
	var reply struct {
		Cancel       bool   `json:"cancel"`
		ErrorMessage string `json:"errorMessage"`
	}
	if err := json.Unmarshal(out.Bytes(), &reply); err != nil || !reply.Cancel || reply.ErrorMessage == "" {
		t.Fatalf("reply = %q (%v), want a cancel with a reason\nstderr: %s", out.String(), err, errb.String())
	}
}
