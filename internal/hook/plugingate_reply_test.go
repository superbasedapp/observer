package hook

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestBuildPluginPromptReply pins the plugin prompt reply for every outcome
// a dialect row can resolve to: a confirmable stop is ask, a hard stop deny,
// a warning an allow that carries the notice, a redact a modify.
func TestBuildPluginPromptReply(t *testing.T) {
	cases := []struct {
		name string
		out  promptReplyOutcome
		want PluginReply
	}{
		{"nothing to say", promptReplyOutcome{}, PluginReply{Decision: "allow"}},
		{"hard stop", promptReplyOutcome{Blocking: true, Reason: "r"}, PluginReply{Decision: "deny", Reason: "r"}},
		{"confirmable stop", promptReplyOutcome{Blocking: true, Confirmable: true, Reason: "r"}, PluginReply{Decision: "ask", Reason: "r"}},
		{"warning", promptReplyOutcome{Warn: true, Reason: "heads up"}, PluginReply{Decision: "allow", Message: "heads up"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := buildPluginPromptReply(c.out).(PluginReply)
			if !ok || got.Decision != c.want.Decision || got.Reason != c.want.Reason || got.Message != c.want.Message || got.Prompt != "" {
				t.Fatalf("reply = %+v, want %+v", got, c.want)
			}
		})
	}
	got, _ := buildPluginPromptRedactReply(promptReplyOutcome{Redacted: true, Masked: "m", Reason: "why"}).(PluginReply)
	if got.Decision != "modify" || got.Prompt != "m" || got.Message != "why" {
		t.Fatalf("redact reply = %+v", got)
	}
}

// TestPluginPromptDialectCaps pins what each plugin prompt dialect row
// resolves every prompt decision to (the one decision x capability table),
// and the wire decision the shim then sees.
func TestPluginPromptDialectCaps(t *testing.T) {
	cases := []struct {
		dialect  string
		decision policy.Decision
		action   guard.PromptAction
		degraded guard.PromptAction
		wire     string
	}{
		{PromptDialectPluginShim, policy.DecisionFlag, guard.PromptActionWarn, "", "allow"},
		// No native confirm on chat.message: the ask is a resend-to-confirm.
		{PromptDialectPluginShim, policy.DecisionAsk, guard.PromptActionReenter, guard.PromptActionConfirm, "ask"},
		{PromptDialectPluginShim, policy.DecisionDeny, guard.PromptActionBlock, "", "deny"},
		{PromptDialectPluginShimConfirm, policy.DecisionFlag, guard.PromptActionWarn, "", "allow"},
		{PromptDialectPluginShimConfirm, policy.DecisionAsk, guard.PromptActionConfirm, "", "ask"},
		{PromptDialectPluginShimConfirm, policy.DecisionDeny, guard.PromptActionBlock, "", "deny"},
	}
	for _, c := range cases {
		t.Run(c.dialect+"/"+c.decision.String(), func(t *testing.T) {
			d, ok := promptDialects[c.dialect]
			if !ok {
				t.Fatalf("no dialect row %q", c.dialect)
			}
			a, degraded := guard.ResolvePromptAction(c.decision, d.caps)
			if a != c.action || degraded != c.degraded {
				t.Fatalf("action = %q (degraded from %q), want %q", a, degraded, c.action)
			}
			out := promptOutcomeFor(guard.PromptVerdict{Action: a, Verdict: policy.Verdict{Decision: c.decision, Reason: "x"}}, "s1", "")
			got, _ := d.reply(out).(PluginReply)
			if got.Decision != c.wire {
				t.Fatalf("wire decision = %q, want %q", got.Decision, c.wire)
			}
			if c.wire == "allow" && got.Message == "" {
				t.Fatal("a warning must carry its notice as message")
			}
		})
	}
	if promptDialects[PromptDialectPluginShim].caps.Redact || promptDialects[PromptDialectPluginShim].redact != nil {
		t.Fatal("the chat.message seam offers no redact")
	}
	if c := promptDialects[PromptDialectPluginShimConfirm]; !c.caps.Redact || c.redact == nil {
		t.Fatal("the pi input seam rewrites with a transform")
	}
}

// TestPluginFlagMessage pins the tool-gate flag notice.
func TestPluginFlagMessage(t *testing.T) {
	cases := []struct {
		d      policy.Decision
		reason string
		want   string
	}{
		{policy.DecisionAllow, "x", ""},
		{policy.DecisionFlag, "", ""},
		{policy.DecisionFlag, " risky thing. ", "observer: flagged, not blocked: risky thing."},
		{policy.DecisionDeny, "x", "observer: flagged, not blocked: x"},
	}
	for _, c := range cases {
		if got := pluginFlagMessage(c.d, c.reason); got != c.want {
			t.Errorf("pluginFlagMessage(%v, %q) = %q, want %q", c.d, c.reason, got, c.want)
		}
	}
}

// TestHandlePluginToolGateFlagCarriesMessage: a record-worthy flag is an
// allow that carries the reason as message (the shim shows it); a clean
// allow carries none.
func TestHandlePluginToolGateFlagCarriesMessage(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"host": "opencode", "event": "tool.execute.before", "session_id": "s1", "cwd": "/w",
		"tool_name": "bash", "tool_input": map[string]any{"command": "rm -rf ./build"}, "call_id": "c1",
	})
	cases := []struct {
		name    string
		ev      stubEvaluator
		message bool
	}{
		{"flag", stubEvaluator{v: verdictWith(policy.DecisionFlag, "R-101"), worthy: true}, true},
		{"clean", stubEvaluator{v: verdictWith(policy.DecisionAllow, ""), worthy: false}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			blocked, _ := HandlePluginToolGate("opencode", "tool.execute.before", body, PluginToolGateCaps(false), true, c.ev, nil, &out, io.Discard)
			if blocked {
				t.Fatal("a flag never blocks")
			}
			var r PluginReply
			if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &r); err != nil {
				t.Fatalf("reply %q: %v", out.String(), err)
			}
			if r.Decision != "allow" {
				t.Fatalf("decision = %q", r.Decision)
			}
			if c.message != (r.Message != "") {
				t.Fatalf("message = %q, want present=%v", r.Message, c.message)
			}
			if c.message && !strings.Contains(r.Message, "blocked thing.") {
				t.Fatalf("message %q does not carry the reason", r.Message)
			}
		})
	}
}
