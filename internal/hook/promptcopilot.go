package hook

import (
	"encoding/json"

	"github.com/marmutapp/superbased-observer/internal/guard"
)

// GitHub Copilot CLI's userPromptSubmitted command hook (prompt dialect
// PromptDialectCopilotCLI). Grounded live on demo node 1 (copilot 1.0.96,
// BYOK offline mode against a loopback mock model, throwaway COPILOT_HOME,
// 2026-10-15), superseding the hooks-reference page's "command hooks have
// their output dropped" (fetched 2026-10-03):
//
//   - stdin is {"sessionId","timestamp","cwd","prompt"}; sessionId is the
//     session-state directory name, so a resend in the same session keys the
//     reconsider-once flow;
//   - {"handled":true,"responseContent":"<text>"} answers the turn with ZERO
//     model requests and prints the text as the assistant message (the json
//     output records it as assistant.message), exit 0;
//   - BUT the handled prompt stays in the session history and is sent to the
//     model on the NEXT turn (a resumed session carried the withheld text
//     upstream), unless the same reply also carries modifiedPrompt: then the
//     history holds the replacement, live (handled + modifiedPrompt: zero
//     requests on the turn, the next turn carried the replacement, not the
//     prompt). So a block always sends both;
//   - {"modifiedPrompt":"<text>"} sends the replacement instead of what the
//     developer typed, and the history keeps the replacement;
//   - {"additionalContext":"<text>"} reaches the model only;
//   - exit code 2 does NOT block, and a timed-out hook fails open.
//
// responseContent is persisted as an assistant message that later turns send
// to the model, so it carries only the house message (promptHouseMessage
// never quotes the matched value), never the prompt.

// PromptDialectCopilotCLI is Copilot CLI's userPromptSubmitted shape.
const PromptDialectCopilotCLI = "copilot-cli-prompt"

// copilotWithheldPrompt replaces a blocked prompt in Copilot's session
// history (modifiedPrompt), so the next turn never carries it.
const copilotWithheldPrompt = "[SuperBased Observer withheld this message from the model]"

// promptCopilotCLICaps: a block and the resend-to-confirm message are
// developer-visible (responseContent is printed as the assistant reply),
// modifiedPrompt rewrites what the model receives, and a warning can only
// reach the MODEL (additionalContext), so a flag there still toasts
// (WarnIndirect, the Antigravity PreInvocation precedent).
var promptCopilotCLICaps = guard.PromptSeamCaps{Warn: true, WarnIndirect: true, Reenter: true, Block: true, Redact: true}

// extractCopilotCLIPrompt reads {prompt, sessionId}. A payload without a
// sessionId still parses (the engine fails an empty session closed).
func extractCopilotCLIPrompt(body []byte) (prompt, sessionID string, ok, fieldMissing bool) {
	var p struct {
		Prompt       string `json:"prompt"`
		SessionID    string `json:"sessionId"`
		SessionIDAlt string `json:"session_id"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return "", "", false, false
	}
	sid := p.SessionID
	if sid == "" {
		sid = p.SessionIDAlt
	}
	return p.Prompt, sid, true, !jsonHasAnyKey(body, "prompt")
}

// promptCopilotCLIReply is the userPromptSubmitted output object; every
// field is optional and the empty object is the allow.
type promptCopilotCLIReply struct {
	Handled           bool   `json:"handled,omitempty"`
	ResponseContent   string `json:"responseContent,omitempty"`
	ModifiedPrompt    string `json:"modifiedPrompt,omitempty"`
	AdditionalContext string `json:"additionalContext,omitempty"`
}

// buildCopilotCLIPromptReply answers a block with handled + responseContent
// (the developer reads the reason as the reply) and modifiedPrompt (the
// history keeps a marker instead of the prompt), and a warning with
// additionalContext (model-facing only).
func buildCopilotCLIPromptReply(out promptReplyOutcome) any {
	switch {
	case out.Blocking:
		return promptCopilotCLIReply{Handled: true, ResponseContent: out.Reason, ModifiedPrompt: copilotWithheldPrompt}
	case out.Warn:
		return promptCopilotCLIReply{AdditionalContext: out.Reason}
	}
	return promptCopilotCLIReply{}
}

// buildCopilotCLIPromptRedactReply sends the masked prompt in place of the
// typed one; additionalContext tells the model why a value reads as a
// redaction marker.
func buildCopilotCLIPromptRedactReply(out promptReplyOutcome) any {
	return promptCopilotCLIReply{ModifiedPrompt: out.Masked, AdditionalContext: out.Reason}
}
