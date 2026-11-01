package hook

import (
	"bytes"
	"encoding/json"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// Undecodable gate payloads (FU-161, tracker R-202). Every gate reads its
// payload through a decoder; json.Valid alone (cmd/observer
// hookPayloadUnparseable) does not prove that decoder succeeds. A payload
// that is valid JSON but does not decode where the gate needs it (a
// tool_input that is not an object, a tool name or an operand of the wrong
// type, a prompt that is not a string, a top level that is not an object)
// cannot be judged, and under guard enforcement it must fail closed, never
// reach the approve-if-unevaluable answer. These predicates run the SAME
// decoders the gates run, after the same UTF-8 BOM strip, so the receiver
// that asks them and the gate that judges agree on what decodes:
//
//   - tool gates: HandleToolGate reports ToolGateResult.Undecodable itself
//     (ToolGatePayloadUndecodable is the same extractor, for a receiver
//     that must decide before its own gate runs);
//   - prompt gates: PromptPayloadUndecodable, for a handled=false answer of
//     HandlePromptSubmitGuarded;
//   - the plugin tool gate: PluginToolPayloadUndecodable;
//   - Cursor's own receiver: CursorPayloadUndecodable (cursor.go, which is
//     left out with the adapter under sbo_omit_adapter_cursor).
//
// A payload that decodes but names no tool, an unknown tool or no operand
// is NOT undecodable: it passes as before (unknown is never a violation).

// PromptPayloadUndecodable reports whether a prompt-gate dialect's
// extractor cannot decode body (after a UTF-8 BOM). False for an unknown
// dialect and for a payload the dialect reads as legitimately empty.
func PromptPayloadUndecodable(dialect string, body []byte) bool {
	d, ok := promptDialects[dialect]
	if !ok || d.extract == nil {
		return false
	}
	body = bytes.TrimPrefix(body, utf8BOM)
	if _, _, ok, _ := d.extract(body); ok {
		return false
	}
	if d.decodes != nil {
		return !d.decodes(body)
	}
	return true
}

// commandCodePromptDecodes: an object whose text member, when present, is a
// string (null counts as empty). An object with no text member is a
// transformInput call with nothing to scan, not a decode failure.
func commandCodePromptDecodes(body []byte) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		return false
	}
	raw, ok := m["text"]
	if !ok {
		return true
	}
	var text string
	return json.Unmarshal(raw, &text) == nil
}

// antigravityPreInvocationDecodes: the pre-invocation payload decodes
// (conversation id and transcript path as strings); a payload whose
// transcript is not there yet is a model call with nothing to scan.
func antigravityPreInvocationDecodes(body []byte) bool {
	var p agyPreInvocationPayload
	return json.Unmarshal(body, &p) == nil
}

// PluginToolPayloadUndecodable reports whether the plugin tool gate cannot
// decode body for tool: the envelope is not an object or a field it reads
// has the wrong type, or, for a tool the gate judges, the tool input is not
// an object or its operand field is not a string.
func PluginToolPayloadUndecodable(tool string, body []byte) bool {
	var env pluginEnvelope
	if json.Unmarshal(bytes.TrimPrefix(body, utf8BOM), &env) != nil {
		return true
	}
	if env.ToolName == "" || tooltax.IsMCPToolName(env.ToolName) {
		return false
	}
	row, ok := tooltax.Resolve(tool, env.ToolName)
	if !ok || row.Operand == tooltax.OperandNone || row.Operand == tooltax.OperandMCPName {
		return false
	}
	if _, judged := guard.ClassifyActionType(row.ActionType); !judged {
		return false
	}
	if rawNotObject(env.ToolInput) {
		return true
	}
	if pluginOperand(env.ToolInput, row.Operand) != "" {
		return false
	}
	var m map[string]any
	if json.Unmarshal(env.ToolInput, &m) != nil {
		return false
	}
	for _, k := range pluginOperandKeys[row.Operand] {
		if v, ok := m[k]; ok && v != nil {
			if _, isString := v.(string); !isString {
				return true
			}
		}
	}
	return false
}
