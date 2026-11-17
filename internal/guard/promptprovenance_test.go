package guard

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// promptprovenance_test.go: the R-172 prompt-gate false positive the 2026-11-15
// security-assessment live runs found (docs/plans/
// security-assessments-live-results-2026-11-15.md, follow-up row 12),
// pinned at the proxy prompt seam that raised it.

// fpBearer is a fake bearer credential shaped like the fixture app's.
const fpBearer = "fixtureTokenAbc123XYZ789"

// fpMainToolLoop is a main-conversation request whose newest user turn
// answers a tool call with tool output carrying the given text: the
// request in which that tool output is newest.
func fpMainToolLoop(t *testing.T, toolOutput string) []byte {
	t.Helper()
	type m = map[string]any
	body, err := json.Marshal(m{"model": "claude-opus-4-8", "messages": []any{
		m{"role": "user", "content": "run the pen test"},
		m{"role": "assistant", "content": []any{
			m{"type": "tool_use", "id": "t1", "name": "Bash", "input": m{"command": "python3 probe.py /debug"}},
		}},
		m{"role": "user", "content": []any{
			m{"type": "tool_result", "tool_use_id": "t1", "content": toolOutput},
		}},
	}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return body
}

// fpSideRequest is a side request (an agent's own safety classifier) that
// re-sends the conversation as the text of one fresh user message, the
// shape the live classifier calls had (message_count 1).
func fpSideRequest(transcript string) []byte {
	body, _ := json.Marshal(map[string]any{
		"model":    "claude-sonnet-5",
		"messages": []any{map[string]any{"role": "user", "content": "<transcript>\n" + transcript + "\n</transcript>\nIs the next action safe?"}},
	})
	return body
}

// fpChatToolLoop is the Chat Completions main request whose newest turn is
// a role:"tool" output.
func fpChatToolLoop(t *testing.T, toolOutput string) []byte {
	t.Helper()
	type m = map[string]any
	body, err := json.Marshal(m{"model": "gpt-5", "messages": []any{
		m{"role": "user", "content": "check the service"},
		m{"role": "assistant", "content": nil, "tool_calls": []any{m{"id": "c1", "type": "function", "function": m{"name": "shell", "arguments": `{"cmd":"curl /debug"}`}}}},
		m{"role": "tool", "tool_call_id": "c1", "content": toolOutput},
	}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return body
}

// fpChatSideRequest is fpSideRequest on the Chat Completions wire.
func fpChatSideRequest(transcript string) []byte {
	body, _ := json.Marshal(map[string]any{
		"model":    "gpt-5-mini",
		"messages": []any{map[string]any{"role": "user", "content": transcript}},
	})
	return body
}

// TestPromptLaneJudgesOnlyTypedText: the proxy prompt gate (R-172 on
// KindUserPrompt) judges what the developer typed, never a value the
// session's model or tools already produced, whichever request re-sends it.
func TestPromptLaneJudgesOnlyTypedText(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	type step struct {
		provider string
		session  string
		body     []byte
		// response, when set, is a model response's tool calls noted
		// through InspectProxyResponse instead of a request.
		response []ProxyToolUse
	}
	tests := []struct {
		name      string
		before    []step // requests (or responses) the session saw first
		judged    step   // the request whose prompt verdict is checked
		wantBlock bool
	}{
		{
			name:      "user-typed bearer token blocks",
			judged:    step{provider: models.ProviderAnthropic, session: "s-typed", body: anthropicUserOnlyBody("call it with Authorization: Bearer " + fpBearer)},
			wantBlock: true,
		},
		{
			name:   "tool_result bearer token, newest in its own request, is never a prompt",
			judged: step{provider: models.ProviderAnthropic, session: "s-loop", body: fpMainToolLoop(t, "HTTP 200\nAuthorization: Bearer "+fpBearer)},
		},
		{
			name: "tool output re-sent as user text by a side request does not block",
			before: []step{
				{provider: models.ProviderAnthropic, session: "s-side", body: fpMainToolLoop(t, "HTTP 200\nAuthorization: Bearer "+fpBearer)},
			},
			judged: step{provider: models.ProviderAnthropic, session: "s-side", body: fpSideRequest("tool_result: HTTP 200 Authorization: Bearer " + fpBearer)},
		},
		{
			name: "a JSON-escaped re-rendering of the tool output still matches",
			before: []step{
				{provider: models.ProviderAnthropic, session: "s-esc", body: fpMainToolLoop(t, "config dump\npassword=fixturePW12345\nmode=debug")},
			},
			judged: step{provider: models.ProviderAnthropic, session: "s-esc", body: fpSideRequest(`{"tool_result":"config dump\npassword=fixturePW12345\nmode=debug"}`)},
		},
		{
			name: "the model's own tool call re-sent before the next request does not block",
			before: []step{
				{session: "s-call", response: []ProxyToolUse{{Name: "Bash", Input: []byte(`{"command":"curl -H 'Authorization: Bearer ` + fpBearer + `' http://localhost:8080/admin"}`)}}},
			},
			judged: step{provider: models.ProviderAnthropic, session: "s-call", body: fpSideRequest("Bash: curl -H 'Authorization: Bearer " + fpBearer + "' http://localhost:8080/admin")},
		},
		{
			name: "a different token typed after a tool printed one still blocks",
			before: []step{
				{provider: models.ProviderAnthropic, session: "s-other", body: fpMainToolLoop(t, "Authorization: Bearer "+fpBearer)},
			},
			judged:    step{provider: models.ProviderAnthropic, session: "s-other", body: anthropicUserOnlyBody("use Authorization: Bearer typedByHandQwe987Rty654")},
			wantBlock: true,
		},
		{
			name: "another session's tool output exempts nothing here",
			before: []step{
				{provider: models.ProviderAnthropic, session: "s-a", body: fpMainToolLoop(t, "Authorization: Bearer "+fpBearer)},
			},
			judged:    step{provider: models.ProviderAnthropic, session: "s-b", body: fpSideRequest("Authorization: Bearer " + fpBearer)},
			wantBlock: true,
		},
		{
			name: "OpenAI role:tool output re-sent by a side request does not block",
			before: []step{
				{provider: models.ProviderOpenAI, session: "s-chat", body: fpChatToolLoop(t, "Authorization: Bearer "+fpBearer)},
			},
			judged: step{provider: models.ProviderOpenAI, session: "s-chat", body: fpChatSideRequest("tool said: Authorization: Bearer " + fpBearer)},
		},
		{
			name:      "OpenAI user-typed bearer token blocks",
			judged:    step{provider: models.ProviderOpenAI, session: "s-chat-typed", body: fpChatSideRequest("Authorization: Bearer " + fpBearer)},
			wantBlock: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := newTestGuard(t, promptProxyCfg("block", false), nil)
			for i, s := range tc.before {
				at := now.Add(time.Duration(i) * time.Second)
				if s.response != nil {
					g.InspectProxyResponse(s.session, s.response, at)
					continue
				}
				if res := g.ScanProxyPrompt(s.provider, s.body, s.session, at); res.PromptDeny {
					t.Fatalf("setup request %d was blocked: %+v", i, res)
				}
			}
			res := g.ScanProxyPrompt(tc.judged.provider, tc.judged.body, tc.judged.session, now.Add(time.Minute))
			if res.PromptDeny != tc.wantBlock {
				t.Fatalf("PromptDeny = %v, want %v (%+v)", res.PromptDeny, tc.wantBlock, res)
			}
			if tc.wantBlock && res.PromptRuleID != "R-172" {
				t.Errorf("PromptRuleID = %q, want R-172", res.PromptRuleID)
			}
		})
	}
}

// TestEgressMaskStillMasksToolOutput: the egress half of R-172 (the
// api_request row) is untouched by the prompt lane's provenance filter:
// under enforce with egress_action mask, the side request that the prompt
// gate now lets through still leaves with the tool-printed secret masked,
// and so does the main request that carried the tool output.
func TestEgressMaskStillMasksToolOutput(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		body []byte
		// wantVerdict: the mask records a verdict. The side request's
		// identical finding set is deduped per session (egressSignature,
		// unchanged), so it masks without a second row.
		wantVerdict bool
	}{
		{name: "main request carrying the tool output", body: fpMainToolLoop(t, "Authorization: Bearer "+fpBearer), wantVerdict: true},
		{name: "side request re-sending it as user text", body: fpSideRequest("Authorization: Bearer " + fpBearer)},
	}
	g := newTestGuard(t, promptProxyCfg("block", true), nil)
	// The main request first, so the side request's value is known
	// tool output (the order the live run had).
	for i, tc := range tests {
		res := g.ScanProxyRequest(models.ProviderAnthropic, tc.body, "s-mask", now.Add(time.Duration(i)*time.Second))
		if res.PromptDeny || res.Deny {
			t.Fatalf("%s: denied, want forwarded with a mask: %+v", tc.name, res)
		}
		if res.MaskedBody == nil {
			t.Fatalf("%s: no masked body, want the bearer token masked on egress", tc.name)
		}
		if strings.Contains(string(res.MaskedBody), fpBearer) || !strings.Contains(string(res.MaskedBody), "[REDACTED:bearer_token]") {
			t.Errorf("%s: masked body still carries the token or lacks the marker: %s", tc.name, res.MaskedBody)
		}
		found := false
		for _, v := range res.Verdicts {
			if v.Kind == policy.KindAPIRequest && v.Verdict.RuleID == "R-172" && v.ProxyAction == "mask" {
				found = true
			}
		}
		if found != tc.wantVerdict {
			t.Errorf("%s: R-172 api_request mask verdict = %v, want %v (verdicts %+v)", tc.name, found, tc.wantVerdict, res.Verdicts)
		}
	}
}
