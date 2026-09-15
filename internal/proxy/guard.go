package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// Guard-layer integration (guard spec §8). The proxy holds only this
// file's plain types — the Compressor/CacheSink precedent: the guard
// composition layer and the store are wired behind the GuardScanner
// interface by cmd/observer, and no guard/policy type crosses into
// this package (§17.2).
//
// Placement contract (§8.1): serve() makes ONE ScanRequest call per
// request, immediately after compression produces the final outbound
// body (the same post-compression position cachetrack hashes), and
// one InspectResponse call on the parsed response surface (stream and
// non-stream). Proxy-only, zero effect on other capture paths — the
// compression precedent.

// GuardScanner is the proxy's view of the guard layer. Implementations
// (the cmd/observer adapter) own verdict persistence and alerting;
// the proxy only acts on the returned request decision.
type GuardScanner interface {
	// ScanRequest scans the final outbound body. The proxy forwards,
	// masks, or denies per the result. Synchronous on the request
	// path — implementations hold the §17.9 ≤10ms p99 budget.
	ScanRequest(ctx context.Context, provider string, body []byte, sessionID string) GuardRequestResult
	// InspectResponse receives the response's tool_use blocks (the
	// model's intended next actions, §8.3). Called after the client
	// already has its bytes — off the latency path. Flag/alert only;
	// the proxy never rewrites responses (v1). apiTurnID is the
	// api_turn this response was captured as (0 when the turn was
	// dropped) — implementations anchor the persisted verdict to it so
	// the obs trajectory enrichment can surface the verdict on the span.
	InspectResponse(ctx context.Context, sessionID string, apiTurnID int64, tools []GuardToolUse)
}

// PromptPhaseScanner is the OPTIONAL two-phase request protocol (LIVE
// CORRECTION 2026-09-07). A scanner that implements it gets its
// prompt-submit lane run by the proxy on the ORIGINAL request body
// BEFORE conversation compression (ScanPrompt), and then the rest of
// the request scan on the final outbound body (ScanRequestAfterPrompt)
// instead of ScanRequest. Why: the compression pipeline forward-scrubs
// the outbound body, so a single post-compression ScanRequest sees
// [REDACTED] where a pasted secret was and the prompt lane can never
// ask-once/block it -- the developer gets no message and no guard event
// while the model silently receives a redacted prompt. A scanner that
// does not implement this keeps the single post-compression ScanRequest
// call exactly as before. Ordering note: for a two-phase scanner the
// prompt lane now runs BEFORE the budget check (which stays in phase 2
// on the final body), so a request that is both over budget and carries
// a pasted secret answers with the prompt-lane interrupt — the
// actionable message — rather than the budget deny.
type PromptPhaseScanner interface {
	ScanPrompt(ctx context.Context, provider string, body []byte, sessionID string) GuardRequestResult
	ScanRequestAfterPrompt(ctx context.Context, provider string, body []byte, sessionID string) GuardRequestResult
}

// GuardRequestResult is the §8.2 egress decision the proxy acts on.
type GuardRequestResult struct {
	// Action is "" or "allow" (forward unchanged), "mask" (forward
	// Body instead), "deny" (synthetic 403, §8.5), or "prompt_deny"
	// (the prompt-submit intervention PROXY LANE's own deny — contract
	// §3, docs/plans/prompt-submit-intervention-exploration-2026-09-07.md).
	// "prompt_deny" is a DISTINCT action from "deny" so the two render
	// through separate body-builders (guardDenyBody's agent-facing
	// "[observer-guard %s] request blocked by Observer policy: %s"
	// framing is wrong for a message written for the human who just
	// typed the prompt) and, via Status below, a distinct HTTP status.
	Action string
	// Body is the masked/redacted body when Action == "mask".
	Body []byte
	// RuleID / Reason feed the provider-shaped error body on "deny"
	// ("[observer-guard R-172] ...") and "prompt_deny" (Reason is
	// already the COMPLETE, house-styled developer-facing message —
	// see guardPromptDenyBody's doc comment).
	RuleID string
	Reason string
	// Status is the HTTP status to write for "deny"/"prompt_deny".
	// Zero means "unspecified" — serveGuardDeny/serveGuardPromptDeny
	// both default an unset Status to 403, so a caller that never sets
	// this field (today's cmd/observer/guardwire.go adapter) keeps the
	// EXACT status every "deny" response has always used. The
	// prompt-submit contract's own status table (§3.3) is 400 for a
	// fresh ask-once interrupt, 403 for an unconditional block. Some
	// clients retry 400 automatically, so ask-once confirmation also
	// relies on the guard's reconsider_min_delay floor; never use 429
	// (retried) or a 5xx. Status only sharpens WHICH safe value renders.
	Status int
}

// GuardToolUse is one tool_use block extracted from a response.
type GuardToolUse struct {
	// Name is the tool name as the model emitted it.
	Name string
	// Input is the JSON input object. For OpenAI shapes the
	// `arguments` JSON string is decoded to the object form first, so
	// consumers see one shape.
	Input json.RawMessage
}

// guardDenyBody renders the §8.5 provider-shaped error body: clients
// surface it as a normal API error (never connection-drop — clients
// retry-storm on those), with the rule ID and remediation inline so
// the AGENT reads it and self-corrects. status is the SAME HTTP status
// serveGuardDeny is about to write (today always 403 for this action —
// see its own doc comment) — threaded through so the Gemini row's own
// {"code",...} field never disagrees with the HTTP status line
// actually sent (a NIT the phase-3b review flagged: geminiErrorBody
// used to hardcode 400/INVALID_ARGUMENT regardless of the real status).
func guardDenyBody(provider, ruleID, reason string, status int) []byte {
	msg := fmt.Sprintf("[observer-guard %s] request blocked by Observer policy: %s", ruleID, reason)
	type errObj struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	}
	switch provider {
	case models.ProviderAnthropic:
		body, _ := json.Marshal(struct {
			Type  string `json:"type"`
			Error errObj `json:"error"`
		}{Type: "error", Error: errObj{Type: "invalid_request_error", Message: msg}})
		return body
	case models.ProviderGoogle:
		// Prompt-submit intervention contract §3.1/§3.2 flagged this as
		// a pre-existing gap: a Gemini request denied by R-172 (egress)
		// previously fell through to the OpenAI shape below, which a
		// Gemini client does not parse as an error at all.
		return geminiErrorBody(msg, status)
	default: // OpenAI Chat Completions + Responses API share one shape.
		body, _ := json.Marshal(struct {
			Error struct {
				Message string  `json:"message"`
				Type    string  `json:"type"`
				Param   *string `json:"param"`
				Code    string  `json:"code"`
			} `json:"error"`
		}{Error: struct {
			Message string  `json:"message"`
			Type    string  `json:"type"`
			Param   *string `json:"param"`
			Code    string  `json:"code"`
		}{Message: msg, Type: "invalid_request_error", Code: "observer_guard_denied"}})
		return body
	}
}

// guardPromptDenyBody renders the prompt-submit intervention PROXY
// LANE's provider-shaped error body (contract §3.2's error-body table,
// docs/plans/prompt-submit-intervention-exploration-2026-09-07.md).
// Unlike guardDenyBody — whose doc comment says the body is shaped "so
// the AGENT reads it and self-corrects" — the audience here is the
// DEVELOPER who just typed the prompt (contract §3.1): reason already
// IS the complete, house-styled message
// (guard.proxyPromptHouseMessage, e.g. "observer: <reason>. Send it
// again unchanged to confirm..."), so this function only wraps it in
// each provider's own error envelope — no extra "[observer-guard ...]
// request blocked by Observer policy:" framing on top, since this
// isn't the egress policy and the reason text already stands alone.
// status is the ACTUAL HTTP status serveGuardPromptDeny is about to
// write (400 for a fresh ask-once interrupt, 403 for an unconditional
// block, per contract §3.3 and F8's clamp) — unlike guardDenyBody's
// always-403 case, this status genuinely varies call to call, so the
// Gemini row's own {"code",...} field must vary with it too.
func guardPromptDenyBody(provider, reason string, status int) []byte {
	type errObj struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	}
	switch provider {
	case models.ProviderAnthropic:
		body, _ := json.Marshal(struct {
			Type  string `json:"type"`
			Error errObj `json:"error"`
		}{Type: "error", Error: errObj{Type: "invalid_request_error", Message: reason}})
		return body
	case models.ProviderGoogle:
		return geminiErrorBody(reason, status)
	default: // OpenAI Chat Completions + Responses API share one shape.
		body, _ := json.Marshal(struct {
			Error struct {
				Message string  `json:"message"`
				Type    string  `json:"type"`
				Param   *string `json:"param"`
				Code    string  `json:"code"`
			} `json:"error"`
		}{Error: struct {
			Message string  `json:"message"`
			Type    string  `json:"type"`
			Param   *string `json:"param"`
			Code    string  `json:"code"`
		}{Message: reason, Type: "invalid_request_error", Code: "observer_prompt_guard"}})
		return body
	}
}

// geminiErrorBody renders the Google/Gemini error envelope
// (google.aip.dev/193): {"error":{"code","message","status"}} — the
// shape contract §3.2 specifies for both guardDenyBody's Gemini row and
// guardPromptDenyBody above. code carries the REAL HTTP status through
// (a NIT the phase-3b review flagged: this previously hardcoded
// 400/INVALID_ARGUMENT unconditionally, which disagreed with the
// actual 403 HTTP status line on every plain "deny" response — the
// only action guardDenyBody ever renders), mapped to the matching
// canonical google.aip.dev/193 status string for the exact pair
// contract §3.3 allows (400/403); any other value (defensive — should
// be unreachable given serveGuardDeny's own 403 default and F8's
// clamp on the prompt-deny path) falls back to UNKNOWN rather than
// asserting a status string that doesn't match code.
func geminiErrorBody(message string, status int) []byte {
	statusStr := "UNKNOWN"
	switch status {
	case http.StatusBadRequest:
		statusStr = "INVALID_ARGUMENT"
	case http.StatusForbidden:
		statusStr = "PERMISSION_DENIED"
	}
	body, _ := json.Marshal(struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"error"`
	}{Error: struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	}{Code: status, Message: message, Status: statusStr}})
	return body
}

// extractToolUses pulls the tool_use blocks out of a response in any
// of the wire shapes the proxy serves: Anthropic JSON + SSE, OpenAI
// Chat Completions JSON + SSE deltas, Responses API JSON + SSE
// (response.completed). Tolerant — unknown shapes return nil.
func extractToolUses(provider string, body []byte, isStream bool) []GuardToolUse {
	if len(body) == 0 {
		return nil
	}
	if isStream {
		if provider == models.ProviderAnthropic {
			return extractAnthropicStreamToolUses(body)
		}
		return extractOpenAIStreamToolUses(body)
	}
	if provider == models.ProviderAnthropic {
		return extractAnthropicToolUses(body)
	}
	return extractOpenAIToolUses(body)
}

// extractAnthropicToolUses reads content[].type=="tool_use" blocks
// from a non-streaming Messages API response.
func extractAnthropicToolUses(body []byte) []GuardToolUse {
	var raw struct {
		Content []struct {
			Type  string          `json:"type"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}
	var out []GuardToolUse
	for _, c := range raw.Content {
		if c.Type == "tool_use" && c.Name != "" {
			out = append(out, GuardToolUse{Name: c.Name, Input: c.Input})
		}
	}
	return out
}

// extractAnthropicStreamToolUses assembles tool_use blocks from an
// SSE capture: content_block_start carries the name per block index;
// input_json_delta events stream the input object as partial_json
// fragments concatenated per index.
func extractAnthropicStreamToolUses(body []byte) []GuardToolUse {
	type blockAcc struct {
		name  string
		input bytes.Buffer
	}
	blocks := map[int]*blockAcc{}
	var order []int
	splitSSEEvents(body, func(lines [][]byte) {
		for _, line := range lines {
			if !bytes.HasPrefix(line, []byte("data:")) {
				continue
			}
			payload := bytes.TrimSpace(line[len("data:"):])
			if len(payload) == 0 {
				continue
			}
			var ev struct {
				Type         string `json:"type"`
				Index        int    `json:"index"`
				ContentBlock struct {
					Type  string          `json:"type"`
					Name  string          `json:"name"`
					Input json.RawMessage `json:"input"`
				} `json:"content_block"`
				Delta struct {
					Type        string `json:"type"`
					PartialJSON string `json:"partial_json"`
				} `json:"delta"`
			}
			if err := json.Unmarshal(payload, &ev); err != nil {
				continue
			}
			switch ev.Type {
			case "content_block_start":
				if ev.ContentBlock.Type != "tool_use" || ev.ContentBlock.Name == "" {
					continue
				}
				acc := &blockAcc{name: ev.ContentBlock.Name}
				// Some builds emit a (usually empty) input object on
				// the start event; keep it as the seed in case no
				// deltas follow.
				if len(ev.ContentBlock.Input) > 0 && !bytes.Equal(ev.ContentBlock.Input, []byte("{}")) {
					acc.input.Write(ev.ContentBlock.Input)
				}
				blocks[ev.Index] = acc
				order = append(order, ev.Index)
			case "content_block_delta":
				if ev.Delta.Type != "input_json_delta" {
					continue
				}
				if acc, ok := blocks[ev.Index]; ok {
					acc.input.WriteString(ev.Delta.PartialJSON)
				}
			}
		}
	})
	var out []GuardToolUse
	for _, idx := range order {
		acc := blocks[idx]
		input := acc.input.Bytes()
		if len(input) == 0 {
			input = []byte("{}")
		}
		out = append(out, GuardToolUse{Name: acc.name, Input: json.RawMessage(input)})
	}
	return out
}

// extractOpenAIToolUses reads tool calls from a non-streaming OpenAI
// body: Chat Completions choices[].message.tool_calls and Responses
// API output[].type=="function_call". Both key sets are tried.
func extractOpenAIToolUses(body []byte) []GuardToolUse {
	var raw struct {
		Choices []struct {
			Message struct {
				ToolCalls []openAIToolCall `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
		Output []struct {
			Type      string `json:"type"`
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"output"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}
	var out []GuardToolUse
	for _, ch := range raw.Choices {
		for _, tc := range ch.Message.ToolCalls {
			if tu, ok := tc.toGuardToolUse(); ok {
				out = append(out, tu)
			}
		}
	}
	for _, o := range raw.Output {
		if o.Type == "function_call" && o.Name != "" {
			out = append(out, GuardToolUse{Name: o.Name, Input: decodeArguments(o.Arguments)})
		}
	}
	return out
}

// openAIToolCall is the Chat Completions tool-call shape (full or
// delta — deltas carry an index and fragmentary arguments).
type openAIToolCall struct {
	Index    int `json:"index"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// toGuardToolUse converts a complete tool call.
func (tc *openAIToolCall) toGuardToolUse() (GuardToolUse, bool) {
	if tc.Function.Name == "" {
		return GuardToolUse{}, false
	}
	return GuardToolUse{Name: tc.Function.Name, Input: decodeArguments(tc.Function.Arguments)}, true
}

// decodeArguments normalizes OpenAI's arguments JSON STRING into the
// object form Anthropic uses, so downstream consumers see one shape.
func decodeArguments(args string) json.RawMessage {
	if args == "" {
		return json.RawMessage("{}")
	}
	if json.Valid([]byte(args)) {
		return json.RawMessage(args)
	}
	return json.RawMessage("{}")
}

// extractOpenAIStreamToolUses assembles tool calls from an OpenAI SSE
// capture. Two shapes: the Responses API's terminal response.completed
// event embeds the full output array (codex's path); Chat Completions
// streams choices[].delta.tool_calls fragments accumulated per index.
func extractOpenAIStreamToolUses(body []byte) []GuardToolUse {
	type callAcc struct {
		name string
		args bytes.Buffer
	}
	deltas := map[int]*callAcc{}
	var order []int
	var completed []GuardToolUse
	splitSSEEvents(body, func(lines [][]byte) {
		for _, line := range lines {
			if !bytes.HasPrefix(line, []byte("data:")) {
				continue
			}
			payload := bytes.TrimSpace(line[len("data:"):])
			if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
				continue
			}
			var ev struct {
				Choices []struct {
					Delta struct {
						ToolCalls []openAIToolCall `json:"tool_calls"`
					} `json:"delta"`
				} `json:"choices"`
				Response struct {
					Output []struct {
						Type      string `json:"type"`
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"output"`
				} `json:"response"`
			}
			if err := json.Unmarshal(payload, &ev); err != nil {
				continue
			}
			for _, o := range ev.Response.Output {
				if o.Type == "function_call" && o.Name != "" {
					completed = append(completed, GuardToolUse{Name: o.Name, Input: decodeArguments(o.Arguments)})
				}
			}
			for _, ch := range ev.Choices {
				for _, tc := range ch.Delta.ToolCalls {
					acc := deltas[tc.Index]
					if acc == nil {
						acc = &callAcc{}
						deltas[tc.Index] = acc
						order = append(order, tc.Index)
					}
					if tc.Function.Name != "" {
						acc.name = tc.Function.Name
					}
					acc.args.WriteString(tc.Function.Arguments)
				}
			}
		}
	})
	// response.completed output is authoritative when present (the
	// deltas would describe the same calls).
	if len(completed) > 0 {
		return completed
	}
	var out []GuardToolUse
	for _, idx := range order {
		acc := deltas[idx]
		if acc.name == "" {
			continue
		}
		out = append(out, GuardToolUse{Name: acc.name, Input: decodeArguments(acc.args.String())})
	}
	return out
}
