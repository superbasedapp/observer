package hook

import "github.com/marmutapp/superbased-observer/internal/guard"

// The Cline CLI plugin gate (the internal/hook/pluginshim "cline" shape,
// installed as $CLINE_DIR/plugins/superbased-observer-guard.js). The plugin
// speaks the plugin transport (a normalized envelope on stdin, a PluginReply
// on stdout) to `observer hook cline-cli beforeModel|beforeTool`, and maps
// the reply onto the Cline Plugin API. Grounded live on demo node 1 (cline
// 3.0.68, throwaway HOME and CLINE_DIR, loopback mock model, 2026-10-15):
//
//   - beforeModel runs before EVERY model call with ctx.request.messages;
//     {stop:true, reason} ends the turn with zero model requests, but the
//     reason is shown nowhere (the one-shot CLI prints "[abort] aborted by
//     another client", the TUI prints nothing), so a stop cannot carry the
//     resend-to-confirm instruction: the prompt seam can block and redact,
//     never re-enter or warn the developer (a flag is recorded and toasted);
//   - {messages} rewrites only the request it is returned for, and a stopped
//     or rewritten message stays in the conversation history, so the plugin
//     re-applies every remembered withhold / redaction on every later call;
//   - beforeTool {skip:true, reason} refuses one call (the run continues and
//     the model gets the reason); {policy:{autoApprove:false}} raises Cline's
//     own y/N approval under a TTY (refused headless).

// PromptDialectClinePlugin is the Cline plugin's beforeModel prompt gate.
const PromptDialectClinePlugin = "cline-plugin-prompt"

// promptClinePluginCaps: stop the prompt (block) or rewrite it (redact);
// the developer never sees a stop reason, so no re-enter and no warning.
var promptClinePluginCaps = guard.PromptSeamCaps{Block: true, Redact: true}

// extractClinePluginPrompt reads the plugin envelope's prompt and
// session_id (the {prompt, session_id} shape extractGenericPrompt reads).
var extractClinePluginPrompt = extractGenericPrompt

// buildClinePluginPromptReply is the plugin transport's deny (the plugin
// stops the turn and withholds the message from every later call) or allow.
// A warning has no developer channel here, so it answers allow.
func buildClinePluginPromptReply(out promptReplyOutcome) any {
	if out.Blocking {
		return PluginReply{Decision: "deny", Reason: out.Reason}
	}
	return PluginReply{Decision: "allow"}
}

// buildClinePluginPromptRedactReply is the plugin transport's modify reply:
// the plugin replaces the message text with Prompt.
func buildClinePluginPromptRedactReply(out promptReplyOutcome) any {
	return PluginReply{Decision: "modify", Prompt: out.Masked, Reason: out.Reason}
}
