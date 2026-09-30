package hook

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// stubEvaluator returns a canned verdict — the hook-level tests pin
// HandleGuarded's reply/persist/ordering behavior independent of rule
// content (the guard package pins evaluation itself).
type stubEvaluator struct {
	v      guard.ActionVerdict
	worthy bool
}

func (s stubEvaluator) EvaluateHook(policy.Event) (guard.ActionVerdict, bool) {
	return s.v, s.worthy
}

// preToolBody builds a minimal Claude Code PreToolUse payload.
func preToolBody(toolName, command string) []byte {
	b, _ := json.Marshal(map[string]any{
		"session_id": "sess-1",
		"cwd":        "/home/u/proj",
		"tool_name":  toolName,
		"tool_input": map[string]any{"command": command},
	})
	return b
}

func verdictWith(d policy.Decision, ruleID string) guard.ActionVerdict {
	return guard.ActionVerdict{
		Kind:     policy.KindShellExec,
		Category: "destructive",
		Verdict: policy.Verdict{
			Decision: d, RuleID: ruleID, Severity: policy.SeverityCritical,
			Reason: "blocked thing.", Advice: "Do this instead.", Source: "builtin",
		},
	}
}

// TestHandleGuarded_DenyWritesDualShapeReply pins the §6.2 Claude
// Code decision emission: a deny verdict writes ONE object carrying
// BOTH the modern hookSpecificOutput.permissionDecision contract and
// the legacy decision/block fallback, persists immediately (after the
// reply), and returns blocked=true.
func TestHandleGuarded_DenyWritesDualShapeReply(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	var persisted []guard.ActionVerdict
	persist := func(v guard.ActionVerdict) { persisted = append(persisted, v) }

	blocked, after := HandleGuarded("claude-code:pre-tool",
		preToolBody("Bash", "rm -rf ~/x"),
		stubEvaluator{v: verdictWith(policy.DecisionDeny, "R-101"), worthy: true},
		persist, &out, &bytes.Buffer{})
	if !blocked || after != nil {
		t.Fatalf("blocked=%v after=%v, want true/nil", blocked, after != nil)
	}

	var reply struct {
		Decision           string `json:"decision"`
		Reason             string `json:"reason"`
		HookSpecificOutput struct {
			HookEventName            string `json:"hookEventName"`
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out.Bytes(), &reply); err != nil {
		t.Fatalf("reply parse: %v (raw %s)", err, out.String())
	}
	if reply.Decision != "block" {
		t.Errorf("legacy decision = %q, want block", reply.Decision)
	}
	if reply.HookSpecificOutput.HookEventName != "PreToolUse" ||
		reply.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("modern shape = %+v", reply.HookSpecificOutput)
	}
	if !strings.Contains(reply.Reason, "blocked thing.") || !strings.Contains(reply.Reason, "Do this instead.") {
		t.Errorf("reason = %q, want reason+advice composed for the agent", reply.Reason)
	}
	if reply.HookSpecificOutput.PermissionDecisionReason != reply.Reason {
		t.Error("modern and legacy reasons diverge")
	}

	if len(persisted) != 1 {
		t.Fatalf("persisted = %d rows, want 1", len(persisted))
	}
	if !persisted[0].Enforced || persisted[0].DegradedFrom != "" {
		t.Errorf("persisted enforcement fields = %+v", persisted[0])
	}
}

// TestHandleGuarded_AskEmitsAskWithLegacyBlock pins the ask emission:
// modern permissionDecision "ask", legacy "block" (the legacy
// protocol has no ask — conservative mapping).
func TestHandleGuarded_AskEmitsAskWithLegacyBlock(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	blocked, _ := HandleGuarded("claude-code:pre-tool",
		preToolBody("Bash", "git reset --hard"),
		stubEvaluator{v: verdictWith(policy.DecisionAsk, "R-104"), worthy: true},
		nil, &out, &bytes.Buffer{})
	if !blocked {
		t.Fatal("ask emission must block (defer) the call")
	}
	raw := out.String()
	if !strings.Contains(raw, `"permissionDecision":"ask"`) || !strings.Contains(raw, `"decision":"block"`) {
		t.Errorf("ask reply = %s", raw)
	}
}

// TestHandleGuarded_FlagDefersRecordUntilAfterReply pins the §6.4
// reply-first ordering on the allow path: HandleGuarded writes
// NOTHING (the caller owns the approve reply) and hands back the
// persist as recordAfterReply.
func TestHandleGuarded_FlagDefersRecordUntilAfterReply(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	var persisted int
	blocked, after := HandleGuarded("claude-code:pre-tool",
		preToolBody("Bash", "rm -rf ~/x"),
		stubEvaluator{v: verdictWith(policy.DecisionFlag, "R-101"), worthy: true},
		func(guard.ActionVerdict) { persisted++ }, &out, &bytes.Buffer{})
	if blocked {
		t.Fatal("flag emission must not block")
	}
	if out.Len() != 0 {
		t.Fatalf("HandleGuarded wrote to stdout on the allow path: %s", out.String())
	}
	if after == nil {
		t.Fatal("flag verdict must hand back a recordAfterReply")
	}
	if persisted != 0 {
		t.Fatal("persist ran BEFORE the caller's reply")
	}
	after()
	if persisted != 1 {
		t.Fatalf("persisted = %d after recordAfterReply, want 1", persisted)
	}
}

// TestHandleGuarded_FailureWrapperBothWays pins the hook-level Q2
// pair (build prompt hard rule 7): a guard_error verdict carrying
// allow (fail-open) approves silently-with-record; carrying deny
// ([guard] strict) blocks. The decision SHAPING is pinned in the
// guard package; this pins that the hook surface honors whichever
// arrives.
func TestHandleGuarded_FailureWrapperBothWays(t *testing.T) {
	t.Parallel()

	failOpen := guard.ActionVerdict{
		Kind: policy.KindShellExec, Category: "guard", GuardError: true,
		Verdict: policy.Verdict{
			Decision: policy.DecisionAllow, RuleID: guard.GuardErrorRuleID,
			Severity: policy.SeverityHigh, Reason: "guard internal error (fail-open): boom",
		},
	}
	var out bytes.Buffer
	var persisted int
	blocked, after := HandleGuarded("claude-code:pre-tool",
		preToolBody("Bash", "ls"),
		stubEvaluator{v: failOpen, worthy: true},
		func(guard.ActionVerdict) { persisted++ }, &out, &bytes.Buffer{})
	if blocked || out.Len() != 0 {
		t.Fatalf("fail-open must approve: blocked=%v out=%q", blocked, out.String())
	}
	if after == nil {
		t.Fatal("fail-open must still record a guard_error row")
	}
	after()
	if persisted != 1 {
		t.Fatal("guard_error row not persisted")
	}

	failClosed := failOpen
	failClosed.Verdict.Decision = policy.DecisionDeny
	failClosed.Verdict.Reason = "guard internal error (fail-closed, [guard] strict=true): boom"
	out.Reset()
	blocked, _ = HandleGuarded("claude-code:pre-tool",
		preToolBody("Bash", "ls"),
		stubEvaluator{v: failClosed, worthy: true},
		nil, &out, &bytes.Buffer{})
	if !blocked || !strings.Contains(out.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("fail-closed must deny: blocked=%v out=%s", blocked, out.String())
	}
}

// TestHandleGuarded_NotEvaluablePassesThrough: unknown tools and
// unparsable payloads never block and never record — unknown is not
// a violation, and the caller's normal approve path proceeds.
func TestHandleGuarded_NotEvaluablePassesThrough(t *testing.T) {
	t.Parallel()
	for _, body := range [][]byte{
		[]byte(`{"tool_name":"Glob","tool_input":{"pattern":"**/*.go"}}`),
		[]byte(`not json at all`),
		[]byte(`{}`),
	} {
		var out bytes.Buffer
		blocked, after := HandleGuarded("claude-code:pre-tool", body,
			stubEvaluator{v: verdictWith(policy.DecisionDeny, "R-101"), worthy: true},
			nil, &out, &bytes.Buffer{})
		if blocked || after != nil || out.Len() != 0 {
			t.Errorf("non-evaluable payload %q produced activity: blocked=%v", body, blocked)
		}
	}
}

// TestBuildClaudeCodeEvent pins the tool→event mapping table and the
// documented boundary approximations (empty ProjectRoot, cwd set,
// posix dialect, mcp__ classification).
func TestBuildClaudeCodeEvent(t *testing.T) {
	t.Parallel()
	mk := func(tool string, input map[string]any) []byte {
		b, _ := json.Marshal(map[string]any{
			"session_id": "s1", "cwd": "/home/u/proj",
			"tool_name": tool, "tool_input": input,
		})
		return b
	}
	cases := []struct {
		name       string
		body       []byte
		wantOK     bool
		wantKind   policy.EventKind
		wantAction string
		wantTarget string
	}{
		{
			"Bash", mk("Bash", map[string]any{"command": "rm -rf /x"}), true,
			policy.KindShellExec, "run_command", "rm -rf /x",
		},
		{
			"Write", mk("Write", map[string]any{"file_path": "/etc/x"}), true,
			policy.KindFileAccess, "write_file", "/etc/x",
		},
		{
			"Edit", mk("Edit", map[string]any{"file_path": "a.go"}), true,
			policy.KindFileAccess, "edit_file", "a.go",
		},
		{
			"Read", mk("Read", map[string]any{"file_path": "~/.ssh/id_rsa"}), true,
			policy.KindFileAccess, "read_file", "~/.ssh/id_rsa",
		},
		{
			"WebFetch", mk("WebFetch", map[string]any{"url": "https://x.example/p"}), true,
			policy.KindToolCall, "web_fetch", "https://x.example/p",
		},
		{
			"MCP tool", mk("mcp__github__create_issue", map[string]any{}), true,
			policy.KindMCPCall, "mcp_call", "mcp__github__create_issue",
		},
		{"unknown tool", mk("Glob", map[string]any{"pattern": "**"}), false, "", "", ""},
		{"missing operand", mk("Bash", map[string]any{}), false, "", "", ""},
		{"garbage", []byte("{"), false, "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev, ok := BuildClaudeCodeEvent(tc.body)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if ev.Kind != tc.wantKind || ev.ActionType != tc.wantAction || ev.Target != tc.wantTarget {
				t.Errorf("event = kind=%s action=%s target=%q", ev.Kind, ev.ActionType, ev.Target)
			}
			if ev.SessionID != "s1" || ev.Cwd != "/home/u/proj" {
				t.Errorf("session/cwd = %q/%q", ev.SessionID, ev.Cwd)
			}
			if ev.ProjectRoot != "" {
				t.Error("ProjectRoot must stay empty on the hook path (documented: cwd-as-root would FP R-150)")
			}
			if !ev.Caps.PreExecution || !ev.Caps.CanBlock || !ev.Caps.CanAsk {
				t.Errorf("caps = %+v, want full pre-execution capabilities", ev.Caps)
			}
			if ev.Dialect != "" && ev.Dialect != policy.DialectPosix {
				t.Errorf("dialect = %q, want posix default", ev.Dialect)
			}
		})
	}
}

// TestHandleGuarded_MCPToolDenyThroughExistingPath pins the Agent Access
// P4 hook deny (doc3 §12.6): an `mcp__<server>__<tool>` PreToolUse payload
// is built as a KindMCPCall event (Target = the wire tool name, so the
// guard's MCP-access seam can resolve server + tool) and an R-306/R-307
// deny verdict rides the EXISTING deny path — the same dual-shape block
// reply, stderr line and immediate persist every other deny uses; no MCP-
// specific channel exists. The watchdog fail-open contract is untouched
// (memory feedback_hook_fail_open_on_timeout): a deny is a REPLY, never a
// non-zero exit.
func TestHandleGuarded_MCPToolDenyThroughExistingPath(t *testing.T) {
	t.Parallel()
	body, _ := json.Marshal(map[string]any{
		"session_id": "sess-mcp",
		"cwd":        "/home/u/proj",
		"tool_name":  "mcp__github__create_issue",
		"tool_input": map[string]any{"title": "x"},
	})
	ev, ok := BuildClaudeCodeEvent(body)
	if !ok || ev.Kind != policy.KindMCPCall || ev.Target != "mcp__github__create_issue" || !ev.Caps.CanBlock {
		t.Fatalf("mcp event = %+v (ok=%v), want a blockable KindMCPCall on the wire tool name", ev, ok)
	}
	for _, ruleID := range []string{"R-306", "R-307"} {
		t.Run(ruleID, func(t *testing.T) {
			t.Parallel()
			v := guard.ActionVerdict{
				Kind: policy.KindMCPCall, Category: "mcp",
				Verdict: policy.Verdict{
					Decision: policy.DecisionDeny, RuleID: ruleID, Severity: policy.SeverityHigh,
					Reason: "server github (client claude-code): node table: no row matched", Advice: "Route it through the org gateway.", Source: "builtin",
				},
			}
			var stdout, stderr bytes.Buffer
			persisted := 0
			blocked, after := HandleGuarded("PreToolUse", body, stubEvaluator{v: v, worthy: true},
				func(guard.ActionVerdict) { persisted++ }, &stdout, &stderr)
			if !blocked || after != nil {
				t.Fatalf("blocked=%v deferred=%v, want blocked with no deferred record", blocked, after != nil)
			}
			var reply claudeCodeBlockReply
			if err := json.Unmarshal(stdout.Bytes(), &reply); err != nil {
				t.Fatalf("reply not JSON: %v (%s)", err, stdout.String())
			}
			if reply.Decision != "block" || reply.HookSpecificOutput.PermissionDecision != "deny" ||
				reply.HookSpecificOutput.HookEventName != "PreToolUse" ||
				!strings.Contains(reply.HookSpecificOutput.PermissionDecisionReason, "no row matched") {
				t.Errorf("reply = %+v", reply)
			}
			if !strings.Contains(stderr.String(), "guard deny ("+ruleID) {
				t.Errorf("stderr = %q", stderr.String())
			}
			if persisted != 1 {
				t.Errorf("persist calls = %d, want 1 (immediate)", persisted)
			}
		})
	}
}
