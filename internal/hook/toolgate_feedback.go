package hook

import (
	"bytes"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// ToolGateEvents runs the tool-gate dialect's extractor over a payload
// without evaluating it: the policy events (with their proposed edits) the
// gate would judge. The security feedback seam (cmd/observer, lane sec-h)
// uses it on a POST-tool payload, whose tool name and input have the same
// shape as the pre-tool one, to find a write's secrets in the hook when
// the daemon does not answer. ok=false for an unknown dialect or a payload
// the extractor cannot classify.
func ToolGateEvents(tool, dialect, nativeEvent string, body []byte) ([]policy.Event, bool) {
	d, ok := toolGateDialects[dialect]
	if !ok || d.extract == nil {
		return nil, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	events, _, ok, _ := d.extract(ToolGateRequest{Tool: tool, Dialect: dialect, NativeEvent: nativeEvent, Body: body})
	return events, ok
}

// ToolGatePayloadUndecodable reports whether a tool-gate dialect's
// extractor finds a payload it cannot decode where the gate reads it (not
// an object, or a field the gate reads of the wrong type; FU-161). It is
// the same extractor HandleToolGate runs, for a receiver that must decide
// before it hands the payload to a gate of its own (Cursor's internal
// preToolUse route). False for an unknown dialect.
func ToolGatePayloadUndecodable(tool, dialect, nativeEvent string, body []byte) bool {
	d, ok := toolGateDialects[dialect]
	if !ok || d.extract == nil {
		return false
	}
	_, _, ok, undecodable := d.extract(ToolGateRequest{Tool: tool, Dialect: dialect, NativeEvent: nativeEvent, Body: bytes.TrimPrefix(body, utf8BOM)})
	return !ok && undecodable
}

// ToolGatePayloadContext reads only the session id, the working directory
// and the project root a shaped tool-gate dialect's payload names, where
// that dialect reads them, without classifying the tool: a post-tool
// payload carries them as the pre-tool one does (the Cline file hook's
// taskId / sessionContext.sessionId and workspaceRoots), whatever tool ran.
// ok=false for an unknown dialect, one with no payload shape, or a payload
// that is not JSON.
func ToolGatePayloadContext(dialect string, body []byte) (sessionID, cwd, root string, ok bool) {
	d, found := toolGateDialects[dialect]
	if !found || d.extract == nil {
		return "", "", "", false
	}
	events, _, ok, _ := d.extract(ToolGateRequest{Dialect: dialect, Body: body, contextOnly: true})
	if !ok || len(events) != 1 {
		return "", "", "", false
	}
	return events[0].SessionID, events[0].Cwd, events[0].ProjectRoot, true
}
