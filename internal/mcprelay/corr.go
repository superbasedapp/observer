package mcprelay

import (
	"encoding/json"
	"unicode"
)

// corr.go completes the relay half of P11(a) correlation (doc3 §11.12b (a),
// R10.7 / R11.8): WHERE the anchors a relay stamps into its signed
// `sbo_corr` DPoP-proof claim and its mcp_relay_record row come from.
//
//   - coding_session_id: the AI client's tree-inherited session env, read by
//     the stdio wrapper at spawn (CorrelationFromEnv; the key list is the
//     processobs.SessionTokenEnvKeys allow-list the composition root passes -
//     CLAUDE_CODE_SESSION_ID == sessions.id, verified 2026-06-17). A stream
//     transport (IPC hello, loopback headers) supplies it per stream.
//   - action_ref: PER CALL from the MCP request's `params._meta` tool-use id
//     (ToolUseMetaKeys). Claude Code puts the model's tool_use id there on
//     every tools/call (live-grounded 2026-09-25 against Claude Code 2.1.281:
//     `{..._meta, "claudecode/toolUseId": toolUseId}`); it equals
//     actions.source_event_id of that tool_use row, so the org and the node
//     can join the call to its exact action and turn.
//   - turn_ref: only when a stream transport supplies it (no client sends a
//     per-call turn id today); read-side derivation recovers the turn from
//     the matched action.
//
// Every value is bounded before it is carried: dpop refuses a proof whose
// sbo_corr member exceeds its claim bound, and a refused proof would turn a
// correlation hint into a failed call, so an unusable anchor is DROPPED.

// maxAnchorLen mirrors internal/dpop's sbo_corr member bound (maxClaimLen).
const maxAnchorLen = 256

// ToolUseMetaKeys is the table of `params._meta` keys an AI client uses to
// carry the model's tool-use id on an MCP request, in precedence order. A
// key is added here (data, never a client-name branch) only when a live
// client build is grounded to send it.
var ToolUseMetaKeys = []string{
	"claudecode/toolUseId", // Claude Code (grounded 2.1.281, 2026-09-25)
}

// CorrelationFromEnv returns the stream correlation a spawned wrapper can
// read from its own environment: the first non-empty, usable value among
// keys becomes CodingSessionID. lookup is os.Getenv in production.
func CorrelationFromEnv(lookup func(string) string, keys []string) Correlation {
	if lookup == nil {
		return Correlation{}
	}
	for _, k := range keys {
		if v := cleanAnchor(lookup(k)); v != "" {
			return Correlation{CodingSessionID: v}
		}
	}
	return Correlation{}
}

// forCall is the effective correlation of one request: the stream anchors
// (bounded) with a per-call tool-use id from params._meta taking the
// action_ref slot when present - it names THIS call, while a stream-level
// action_ref can only name the stream.
func (c Correlation) forCall(msg *Message) Correlation {
	out := Correlation{
		CodingSessionID: cleanAnchor(c.CodingSessionID),
		TurnRef:         cleanAnchor(c.TurnRef),
		ActionRef:       cleanAnchor(c.ActionRef),
	}
	if msg != nil {
		if id := toolUseIDFromMeta(msg.Params); id != "" {
			out.ActionRef = id
		}
	}
	return out
}

// toolUseIDFromMeta reads the first ToolUseMetaKeys string value from a
// request's params._meta ("" when absent, not a string, or unusable).
func toolUseIDFromMeta(params json.RawMessage) string {
	if len(params) == 0 || params[0] != '{' {
		return ""
	}
	var p struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if json.Unmarshal(params, &p) != nil || len(p.Meta) == 0 {
		return ""
	}
	for _, k := range ToolUseMetaKeys {
		raw, ok := p.Meta[k]
		if !ok {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) != nil {
			continue
		}
		if v := cleanAnchor(s); v != "" {
			return v
		}
	}
	return ""
}

// cleanAnchor returns v when it is a usable anchor: non-empty, within the
// sbo_corr bound, and free of control / space characters; otherwise "".
func cleanAnchor(v string) string {
	if v == "" || len(v) > maxAnchorLen {
		return ""
	}
	for _, r := range v {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return ""
		}
	}
	return v
}
