package hook

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// requestBase is the node dashboard origin the request-access tests stamp.
const requestBase = "http://127.0.0.1:8081"

// lockedEvaluator answers like targetEvaluator, and marks every blocking
// verdict org-locked with the dashboard origin stamped, the shape the guard
// builds for a managed node whose organization locks the rule.
type lockedEvaluator struct{ targetEvaluator }

func (e *lockedEvaluator) EvaluateHook(ev policy.Event) (guard.ActionVerdict, bool) {
	v, worthy := e.targetEvaluator.EvaluateHook(ev)
	if v.Verdict.Decision >= policy.DecisionAsk {
		v.OrgLocked = true
		v.RequestBase = requestBase
	}
	return v, worthy
}

// unescapeReply decodes a JSON reply so a link Go's encoder escaped
// (`&` as &) compares as the developer reads it.
func unescapeReply(b []byte) string {
	var m any
	if err := json.Unmarshal(bytes.TrimSpace(b), &m); err != nil {
		return string(b)
	}
	var walk func(any) string
	walk = func(v any) string {
		switch x := v.(type) {
		case string:
			return x + "\n"
		case map[string]any:
			var sb strings.Builder
			for _, c := range x {
				sb.WriteString(walk(c))
			}
			return sb.String()
		case []any:
			var sb strings.Builder
			for _, c := range x {
				sb.WriteString(walk(c))
			}
			return sb.String()
		}
		return ""
	}
	return walk(m)
}

// TestToolGateDenyOffersRequestAccess (request-grants G4): on every tool-gate
// dialect family, an org-locked deny's reply (the stdout reply, or the
// stderr reason of an exit-code host) leads with the request line: it names
// the rule and links the node request form prefilled with the rule and the
// session.
func TestToolGateDenyOffersRequestAccess(t *testing.T) {
	// WINNODE2 16d: the in-band reply names the dashboard page, never the
	// localhost URL (an agent treated it as a service to call).
	wantLink := "Ask your admin: Observer dashboard, Requests page"
	covered := map[string]bool{}
	for _, r := range toolGateDialectRows() {
		// A dialect whose table row is an ask fixture (Vibe, Junie) is
		// judged as a deny here: an org-locked rule blocks either way.
		if r.denyOn == "" {
			r.denyOn = r.askOn
		}
		if r.denyOn == "" || covered[r.dialect] || (r.wantStdout == "" && r.wantExit == 0) {
			continue
		}
		covered[r.dialect] = true
		t.Run(r.dialect, func(t *testing.T) {
			var out, errb bytes.Buffer
			res := HandleToolGate(ToolGateRequest{
				Tool: r.tool, Dialect: r.dialect, NativeEvent: r.event, Label: r.tool + ":" + r.event, Body: r.body,
			}, &lockedEvaluator{targetEvaluator{denyOn: r.denyOn}}, nil, &out, &errb)
			if !res.Replied {
				t.Fatalf("no block: %+v", res)
			}
			reply := unescapeReply(out.Bytes())
			if out.Len() == 0 {
				reply = errb.String()
			}
			for _, w := range []string{"observer: R-101 blocked", "your organization locks this rule.", wantLink} {
				if !strings.Contains(reply, w) {
					t.Errorf("reply %q missing %q", reply, w)
				}
			}
			if strings.Contains(reply, "ask your admin") {
				t.Errorf("reply still says ask your admin: %q", reply)
			}
		})
	}
	// Kiro CLI's channel is built but not wired (no grounded registration,
	// so HandleToolGate judges nothing there yet): pin its block shape
	// directly, the TestToolGateExitCodeDialects precedent. The reason
	// rides on stderr, the part the host returns to the agent.
	av := guard.ActionVerdict{
		Kind: policy.KindShellExec, OrgLocked: true, RequestBase: requestBase,
		Verdict: policy.Verdict{Decision: policy.DecisionDeny, RuleID: "R-101", Reason: "blocked thing."},
	}
	em := guard.HumanizeEmission(guard.Emission{Permission: "deny", Enforced: true, Reason: ruleReason}, av, "s1")
	if b, ok := toolGateBlockFor(ToolGateDialectKiro, "preToolUse", em); !ok || !b.stderrReason || b.exitCode != 2 ||
		!strings.Contains(em.Reason, wantLink) || strings.Contains(em.Reason, "http") {
		t.Errorf("kiro block %+v ok=%v reason %q", b, ok, em.Reason)
	}
	covered[ToolGateDialectKiro] = true
	// The Cline file-hook gate (cline-pretool) is no longer registered
	// (guard-fix lane B: the gate is the plugin's beforeTool), so nothing
	// judges through it; its block shape still carries the request line.
	if b, ok := toolGateBlockFor(ToolGateDialectCline, "PreToolUse", em); !ok ||
		!strings.Contains(string(b.stdout), "Requests page") || !strings.Contains(string(b.stdout), `"cancel":true`) {
		t.Errorf("cline file-hook block %+v ok=%v", b, ok)
	}
	covered[ToolGateDialectCline] = true
	// The 2026-10-21 wave: the stdout dialects carry the request line in
	// their reply, Kimchi's bash pre-gate on stderr with exit 2.
	for _, d := range []string{ToolGateDialectClaudeWire, ToolGateDialectVTCode, ToolGateDialectDirac, ToolGateDialectAutohand} {
		if b, ok := toolGateBlockFor(d, "PreToolUse", em); !ok || !strings.Contains(string(b.stdout), "Requests page") {
			t.Errorf("%s block %+v ok=%v", d, b, ok)
		}
		covered[d] = true
	}
	if b, ok := toolGateBlockFor(ToolGateDialectKimchiBash, "tool_call", em); !ok || !b.stderrReason || b.exitCode != 2 {
		t.Errorf("kimchi bash block %+v ok=%v", b, ok)
	}
	covered[ToolGateDialectKimchiBash] = true
	for _, d := range ToolGateDialects() {
		if !covered[d] {
			t.Errorf("dialect %s has no deny fixture: the request line is unpinned there", d)
		}
	}
}

// TestPluginGateDenyOffersRequestAccess: the plugin-bridge family (OpenCode,
// pi and the other in-process plugin hosts) carries the same request line.
func TestPluginGateDenyOffersRequestAccess(t *testing.T) {
	var out bytes.Buffer
	body := []byte(`{"host":"opencode","session_id":"s1","tool_name":"mcp__evil__exfil","tool_input":{}}`)
	blocked, _ := HandlePluginToolGate(models.ToolOpenCode, "tool.execute.before", body,
		policy.Capabilities{PreExecution: true, CanBlock: true}, true,
		&lockedEvaluator{targetEvaluator{denyOn: "mcp__evil"}}, nil, &out, &bytes.Buffer{})
	reply := unescapeReply(out.Bytes())
	if !blocked || !strings.Contains(reply, "Observer dashboard, Requests page") || strings.Contains(reply, "http") {
		t.Fatalf("blocked=%v reply %q", blocked, reply)
	}
}

// TestPromptHouseMessage_OrgLockedOffersRequestAccess: a hard prompt block
// on an org-locked rule offers the request path, inside the first 200
// bytes of the house message (the dashboard's error display, and the part
// every host shows).
func TestPromptHouseMessage_OrgLockedOffersRequestAccess(t *testing.T) {
	t.Parallel()
	pv := guard.PromptVerdict{
		Verdict:   policy.Verdict{RuleID: "R-172", Decision: policy.DecisionDeny, Reason: "secret in prompt"},
		Outcome:   guard.PromptOutcomeBlocked,
		Detectors: "github_pat", OrgLocked: true, RequestBase: requestBase,
	}.WithAction(guard.PromptSeamCaps{Warn: true, Reenter: true, Block: true}, "hook")
	got := promptHouseMessage(pv, "s9")
	link := "Observer dashboard, Requests page"
	i := strings.Index(got, link)
	if i < 0 || i+len(link) > guard.RequestAccessMaxBytes {
		t.Fatalf("message %q: the request link must sit inside the first %d bytes", got, guard.RequestAccessMaxBytes)
	}
	if !strings.Contains(got, "secret in prompt") || !strings.HasPrefix(got, "observer: ") {
		t.Fatalf("message lost the reason: %q", got)
	}
	// (The proxy lane's twin is pinned in internal/guard,
	// TestProxyPromptHouseMessage_OrgLockedOffersRequestAccess.)
	// An unlocked block keeps its own text and offers no request.
	pv.OrgLocked = false
	if strings.Contains(promptHouseMessage(pv, "s9"), "Requests page") {
		t.Fatal("an unlocked prompt block must not offer a request")
	}
}
