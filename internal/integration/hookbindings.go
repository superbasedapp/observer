package integration

import "time"

// Hook bindings for every registry row (hook-parity audit 2026-10-02,
// section 4.2; docs/plans/hook-parity-lane0-brief.md step 4). DATA ONLY.
//
// Each row lists the vendor's documented hook events (Registered and Wired
// false) and the ones Observer registers today (Registered true; Wired
// where a feature acts on it). Grounding:
//
//   - live: an in-repo live capture or recorded live test (Claude Code
//     PreToolUse and UserPromptSubmit, Codex SessionStart and
//     UserPromptSubmit per docs/codex-hook-capture.md);
//   - fixture: an in-repo recorded payload (Cursor hooks-log fixtures);
//   - doc: the vendor page fetched 2026-10-02 (audit section 4.6);
//   - inferred: prime-agent's extension API and Muse's payload schema.
//
// HostTimeout / HostOnFailure come from the vendor doc where it states
// them, else zero / unknown. Most vendor field names were read through a
// fetch summarizer: every gate binding is re-checked against a live payload
// before it flips to Wired (Lane A grounding step).

// hookDocDate is the date every doc-grounded binding below was fetched.
const hookDocDate = "2026-10-02"

// Vendor hook documentation, audit section 4.6.
const (
	hookSrcClaudeCode     = "https://code.claude.com/docs/en/hooks"
	hookSrcCodex          = "https://learn.chatgpt.com/docs/hooks"
	hookSrcCursor         = "https://cursor.com/docs/hooks"
	hookSrcGemini         = "https://geminicli.com/docs/hooks/reference/"
	hookSrcQwen           = "https://qwenlm.github.io/qwen-code-docs/en/users/features/hooks/"
	hookSrcDroid          = "https://docs.factory.com/reference/hooks-reference"
	hookSrcQoder          = "https://docs.qoder.com/en/cli/hooks"
	hookSrcPoolside       = "https://docs.poolside.ai/hooks"
	hookSrcZcode          = "https://zcode.z.ai/en/docs/hooks"
	hookSrcCommandCode    = "https://commandcode.ai/docs/hooks"
	hookSrcCommandCodeMod = "https://commandcode.ai/docs/mods"
	hookSrcDevinCLI       = "https://docs.devin.ai/cli/extensibility/hooks/lifecycle-hooks"
	hookSrcCascade        = "https://docs.devin.ai/desktop/cascade/hooks"
	hookSrcKiro           = "https://kiro.dev/docs/hooks/types/"
	hookSrcKiroCrew       = "https://kiro.dev/docs/crew/capabilities/hooks/"
	hookSrcKimi           = "https://moonshotai.github.io/kimi-code/en/customization/hooks"
	hookSrcGrok           = "https://docs.x.ai/build/features/hooks"
	hookSrcGoose          = "https://goose-docs.ai/docs/guides/context-engineering/hooks/"
	hookSrcCrush          = "https://github.com/charmbracelet/crush/blob/main/docs/hooks/README.md"
	hookSrcAntigravity    = "https://antigravity.google/docs/hooks"
	hookSrcVibe           = "https://docs.mistral.ai/vibe/code/cli/hooks"
	hookSrcMuse           = "https://dev.meta.ai/docs/muse-code/extending.md (schema: https://agenticcontrolplane.com/blog/muse-code-acp-integration, third-party)"
	hookSrcJunie          = "https://junie.jetbrains.com/docs/junie-cli-hooks.html"
	hookSrcDeepSeek       = "https://raw.githubusercontent.com/deepseek-ai/deepseek-harness/master/docs/cookbook/extension-cookbook.md"
	hookSrcOpenInterp     = "https://www.openinterpreter.com/docs/terminal/hooks"
	hookSrcCopilotCLI     = "https://docs.github.com/en/copilot/reference/hooks-reference"
	hookSrcVSCode         = "https://code.visualstudio.com/docs/copilot/customization/hooks"
	hookSrcCline          = "https://raw.githubusercontent.com/cline/cline/main/sdk/packages/core/src/hooks/hook-file-config.ts"
	hookSrcKilo           = "https://kilo.ai/docs/automate/extending/plugins"
	hookSrcOpenCode       = "https://opencode.ai/docs/plugins/"
	hookSrcPi             = "https://raw.githubusercontent.com/badlogic/pi-mono/main/packages/coding-agent/docs/extensions.md"
	hookSrcPrimeAgent     = "PrimeIntellect-ai/prime-agent #872, #2712 (pi-fork extension API, third-party PR)"
	hookSrcOpenClaw       = "https://docs.openclaw.ai/plugins/hooks/reference"
	hookSrcHermes         = "https://raw.githubusercontent.com/NousResearch/hermes-agent/main/hermes_cli/plugins.py"
	hookSrcBrowserExt     = "internal/browserhost/hostfiles/host.js (Observer's own native-messaging host)"
)

// Live grounding records.
const (
	hookLiveClaude     = "docs/plans/hook-parity-lane0-brief.md step 4 (recorded live tests: PreToolUse deny/ask; UserPromptSubmit LIVE CORRECTION 2026-09-07, internal/guard/conformance.go)"
	hookLiveClaudeDate = "2026-09-07"
	hookLiveCodex      = "docs/codex-hook-capture.md (codex 0.129.0 empirical capture)"
	hookLiveCodexDate  = "2026-05-11"
	// hookLiveCodexToolGate: codex 0.160.0 `codex exec` on demo node 1 in a
	// throwaway HOME, hooks written by `observer init`; the deny reason
	// reached the model for a shell command, an apply_patch and a degraded
	// ask (docs/guard.md "Live grounding: hook-parity Lane A").
	hookLiveCodexToolGate = "docs/guard.md \"Live grounding: hook-parity Lane A\" (codex 0.160.0, demo node 1)"
	hookLiveLaneADate     = "2026-10-03"
	// hookLiveCursorToolGate: cursor-agent 2026.10.01 (signed in) on demo
	// node 1 in a throwaway HOME: a Write to ~/.ssh/x was denied on
	// preToolUse and the agent_message reached the model.
	hookLiveCursorToolGate = "docs/guard.md \"Live grounding: hook-parity Lane A\" (cursor-agent 2026.10.01, demo node 1)"
	// hookLiveQoderToolGate: qodercli 1.1.65 on demo node 1 in a throwaway
	// HOME: a deny reached the model; an ask under --yolo was auto-approved.
	hookLiveQoderToolGate = "docs/guard.md \"Live grounding: hook-parity Lane A\" (qodercli 1.1.65, demo node 1)"
	// T-357 live grounding (2026-10-04, demo node 1): the vendor ran in the
	// operator's real HOME on its own sign-in; `observer init` (run with
	// HOME pointed at a scratch project) wrote PROJECT-scoped hooks into
	// that project, and the observer hook child ran on a scratch HOME.
	// hookLiveQwenToolGate: qwen 0.24.7 --yolo: rm -rf ~/x denied and the
	// reason reached the model ("Tool run_shell_command was not run: ...");
	// {} let ls run; an ask was not run headless (the reason was shown).
	hookLiveQwenToolGate = "docs/guard.md \"Live grounding: hook-parity Lane A\" (qwen-code 0.24.7, demo node 1, project-scoped hooks)"
	// hookLiveDroidToolGate: droid 0.233.0 `droid exec --auto high`: rm -rf
	// ~/x denied and the reason reached the model; {} let ls run; an ask
	// under --auto high ran the command, so the binding lists no ask.
	hookLiveDroidToolGate = "docs/guard.md \"Live grounding: hook-parity Lane A\" (droid 0.233.0, demo node 1, project-scoped hooks.json with events at the root)"
	hookLiveT357Date      = "2026-10-04"
	// hookLiveAgyToolGate: agy 1.2.16 on demo node 1 in a throwaway HOME
	// (hook-parity Lane A6): rm -rf ~/x and a write to ~/.ssh/x were denied
	// and the reasons reached the model; an empty stdout let ls run; an
	// empty object {} DENIED the call; force_ask under
	// --dangerously-skip-permissions ran the command.
	hookLiveAgyToolGate = "docs/guard.md \"Live grounding: hook-parity Lane A\" (agy 1.2.16, demo node 1)"
	// hookLiveAgyPreInvocation (T-476, lane LIVE-GROUND-2, 2026-10-06): agy
	// 1.3.0 `agy -p` on demo node 1 in a throwaway HOME, in its documented
	// API-key mode against a loopback mock model with a fake key (no Google
	// sign-in, no OAuth file copied), hooks written by Observer's own
	// writer. PreInvocation fires before every model call (invocationNum 0,
	// then 1 after a tool result); stdin {artifactDirectoryPath,
	// conversationId, initialNumSteps, invocationNum, modelName,
	// transcriptPath, workspacePaths}, no prompt text; transcriptPath names
	// .../brain/<id>/.system_generated/logs/transcript_full.jsonl, which
	// already holds the USER_INPUT step at invocationNum 0. A fake-token
	// prompt got an injectSteps ephemeralMessage at invocationNum 0 and the
	// notice was in the model's next agent request; later invocations of the
	// same prompt replied {}. agy also sends one tool-less side request with
	// the prompt that no hook sees. p95 40 ms. PreToolUse was re-checked on
	// 1.3.0: the deny reached the model ("tool call denied by pre-tool hook:
	// <reason>") and an empty stdout let ls run.
	hookLiveAgyPreInvocation     = "hook-parity live-ground 2026-10-06 (T-476): agy 1.3.0 on demo node 1, API-key mode, throwaway HOME, loopback mock model, hooks written by observer init"
	hookLiveAgyPreInvocationDate = "2026-10-06"
	// hookLiveAgyGuardFix (guard-enforcement fix, 2026-10-15, lead-verified):
	// agy 1.3.5 on demo node 1, isolated HOME, loopback mock, zero cost.
	// PreToolUse: deny+reason blocks (the model reads "tool call denied by
	// pre-tool hook: <reason>"); force_ask+reason raises agy's NATIVE prompt
	// with a "Reason:" line in the TUI (even for an in-workspace read),
	// auto-denies under headless -p and RUNS the tool under
	// --dangerously-skip-permissions; plain ask respects default grants;
	// allow defers to policy; auto_approve skips the developer's prompt;
	// overwrite shallow-merges args; an empty stdout falls through to agy's
	// own flow; {}, exit 1/2, invalid JSON and a timeout all DENY.
	// PreInvocation: injectSteps userMessage is shown to the developer as a
	// "> ..." user line (and becomes a user turn), ephemeralMessage /
	// systemMessage reach the model only; {"injectSteps":[{}]} aborts the
	// turn before the main model request ("unknown injected step type", -p
	// exits 3, the TUI shows a warning and the session survives) and no
	// message can accompany it; any other bad output fails OPEN. agy's
	// title-generation request carrying the prompt is sent BEFORE any hook,
	// and an aborted prompt stays in the conversation and is resent with the
	// next turn. A SessionStart event exists.
	hookLiveAgyGuardFix     = "guard-enforcement fix live probe 2026-10-15: agy 1.3.5 on demo node 1, isolated HOME, loopback mock model, zero cost"
	hookLiveAgyGuardFixDate = "2026-10-15"
	// hookLiveGrokToolGate: grok 1.0.46 on demo node 1 in a throwaway HOME
	// (hook-parity Lane A6): rm -rf ~/x was denied and the reason reached
	// the model; {"decision":"allow"} let ls run; an ask under
	// --always-approve ran the command.
	hookLiveGrokToolGate = "docs/guard.md \"Live grounding: hook-parity Lane A\" (grok 1.0.46, demo node 1)"
	hookFixtureCursor    = "testdata/cursor/hooks-log"
	// Lane C node-1 live grounding (2026-10-03): one session per vendor
	// with Observer's own writers in a throwaway HOME and
	// OBSERVER_HOOK_SHAPE_LOG; the start payload's session id equalled the
	// transcript's session id on every row marked live.
	hookLiveLaneCDate   = "2026-10-03"
	hookLiveGrokReplay  = "hook-parity Lane C node 1 capture: grok 1.0.46 `grok -p` replaying ~/.claude/settings.json (sessionId == ~/.grok/sessions/<cwd>/<sid>)"
	hookLiveQoderLC     = "hook-parity Lane C node 1 capture: qodercli 1.1.65 -p (SessionStart/Stop/SessionEnd/SubagentStart/SubagentStop; session_id == ~/.qoder/projects/<slug>/<sid>.jsonl, agent_id == subagents/agent-<id>.jsonl)"
	hookLiveCodexLC     = "hook-parity Lane C node 1 capture: codex-cli 0.160.0 exec (SessionEnd, SubagentStart/SubagentStop; session_id == rollout uuid, agent_id == child rollout uuid)"
	hookLiveClaudeLC    = "hook-parity Lane C node 1 capture: Claude Code 2.1.288 -p SessionEnd through the lifecycle spool"
	hookLiveQwenStartLC = "hook-parity Lane C node 1 capture: qwen 0.24.7 SessionStart (session_id == ~/.qwen/projects/<slug>/chats/<sid>.jsonl)"
	// hook-parity Lane D node 1 live tests (deny + allow captured per event).
	hookLivePluginShim     = "docs/guard.md \"Plugin shim gates\" live record (demo node 1: opencode 1.18.31, kilo 7.8.3, pi 1.0.0)"
	hookLivePluginShimDate = "2026-10-03"
	// Guard-enforcement research on demo node 1 (2026-10-15): the seams the
	// shim's prompt and ask mapping rely on, probed live per host.
	hookLivePluginEnforceDate = "2026-10-15"
	hookLiveOpenCodeThrow     = "guard-enforcement research, demo node 1 (opencode 1.18.31): a chat.message throw rejects the prompt before it is stored, 0 upstream requests; client.tui.showToast shows in the TUI, no-op headless; permission.ask has no trigger site"
	hookLivePiInput           = "guard-enforcement research, demo node 1 (pi 1.0.0): an input handler returning {action:\"handled\"} sends no request, {action:\"transform\"} rewrites, a throw FAILS OPEN; ctx.ui.confirm / ctx.ui.notify work when ctx.hasUI (TUI, RPC), print/json mode has no UI"
	// Vendor SOURCE read from the installed build on demo node 1 (read-only,
	// 2026-10-03, hook-parity Lanes B/E): a doc-kind grounding stronger than
	// a fetched page, still not a live capture.
	hookSrcKimiInstalled  = "kimi-code 2.1.1 bundled source (agent-core-v2 externalHooks runHook.ts, userPrompt.ts) on demo node 1"
	hookSrcQwenInstalled  = "qwen-code 0.24.7 bundled source (todoWrite chunk, hook event descriptions) on demo node 1"
	hookSrcClineInstalled = "cline 3.0.68 on demo node 1: the CLI runs its embedded Bun bundle (@cline/cli-linux-x64/bin/cline; @cline/core's hub daemon entry.js carries the same prompt_submit detached: detachAsyncHooks ?? true)"
	hookSrcLaneDate       = "2026-10-03"
	// hookLiveGooseToolGate / hookLiveClineToolGate: live-ground lane on
	// demo node 1, 2026-10-04, throwaway HOME, hooks written by `observer
	// init --all`. Goose 1.53.0 (nvidia poolside/laguna-xs-2.1): rm -rf ~/x
	// was blocked and the model got "Tool call denied by policy hook
	// `superbased-observer`: ..."; ls ran on the empty-stdout allow. Cline
	// CLI 3.0.68 (-P nvidia): the {"cancel":true,"errorMessage"} reply
	// aborted the run before rm -rf ~/x executed (the fake target
	// survived); ls ran on the empty-stdout allow.
	hookLiveGooseToolGate = "hook-parity live-ground 2026-10-04 (goose 1.53.0, demo node 1)"
	// hookLiveGeminiGates (T-363, lane LIVE-GROUND-2, 2026-10-06): gemini
	// 0.62.0 `gemini -p --yolo` on demo node 1 in a throwaway HOME against
	// a loopback mock model (gemini is not signed in there; a fake key, no
	// credential read or copied), hooks written by `observer init`.
	// BeforeTool: rm -rf ~/x was denied, the reason reached the model as the
	// functionResponse error and the fake target survived; {} let ls run; an
	// enforced ask was a deny naming `observer guard approve`. BeforeAgent:
	// a prompt carrying a fake GitHub token was blocked with ZERO model
	// requests and the developer saw "Agent execution blocked: <reason>";
	// a clean prompt replied {}. p95 BeforeTool deny 100 ms, allow 44 ms,
	// BeforeAgent allow 45 ms.
	hookLiveGeminiGates     = "hook-parity live-ground 2026-10-06 (T-363): gemini-cli 0.62.0 on demo node 1, throwaway HOME, loopback mock model, hooks written by observer init"
	hookLiveGeminiGatesDate = "2026-10-06"
	hookLiveClineToolGate   = "hook-parity live-ground 2026-10-04 (cline CLI 3.0.68 through the shared SDK hook runtime, demo node 1)"
	// LIVE-GROUND-3 (T-378): kimi-code 2.1.1 on demo node 1, throwaway HOME
	// (the operator's own ~/.kimi-code untouched), a loopback mock model
	// through the vendor's KIMI_MODEL_* env override, the [[hooks]] tables
	// written by `observer init` into a config.toml that also held a
	// provider api_key. PreToolUse: rm -rf ~/x was blocked by exit 2, the
	// stderr reason reached the model as the tool error and the fake target
	// survived; ls ran. UserPromptSubmit: a prompt carrying a fake GitHub
	// token was blocked with zero model requests and the developer saw
	// "UserPromptSubmit hook blocked" plus the reason. p95 deny 87 ms, allow
	// 36 ms, prompt allow 37 ms.
	hookLiveKimiGates     = "LIVE-GROUND-3 2026-10-07 (T-378): kimi-code 2.1.1 on demo node 1, throwaway HOME, loopback mock model, hooks written by observer init"
	hookLiveKimiGatesDate = "2026-10-07"
	// hookLiveDevinCLIToolGate is the LIVE-GROUND-3 receipt for the Devin
	// CLI PreToolUse writer (T-478): devin 3000.11.3 on demo node 1 after
	// T-574, a throwaway HOME holding only Observer's hooks key, a loopback
	// mock model. rm -rf ~/x was denied (the CLI reported "Tool rejected"
	// with the U-901 reason) and the fake target survived; ls ran. p95 deny
	// 92 ms, allow 37 ms.
	hookLiveDevinCLIToolGate     = "LIVE-GROUND-3 2026-10-07 (T-478): devin 3000.11.3 on demo node 1, throwaway HOME, loopback mock model, hook written by observer init"
	hookLiveDevinCLIToolGateDate = "2026-10-07"
	// hookLiveGuardFixB is the guard-enforcement fix lane B live run on demo
	// node 1 (2026-10-15): throwaway HOME / COPILOT_HOME / CLINE_DIR, a
	// loopback mock model, zero model cost, Observer's own receivers.
	hookLiveGuardFixBDate = "2026-10-15"
	// hookLiveCopilotCLIPrompt: copilot 1.0.96 userPromptSubmitted. A stub
	// hook proved the wire (handled+responseContent: zero requests, the text
	// printed as the reply; modifiedPrompt: the request and the history carry
	// the replacement; a handled prompt WITHOUT modifiedPrompt was sent
	// upstream on the next resumed turn, with it the history held the
	// replacement; exit 2 does not block). Then Observer's own receiver,
	// registered by `observer init`, with a fake GitHub token: block mode
	// made zero requests and printed the house message, and the next
	// resumed turn carried the withheld marker, not the token; ask-once
	// printed the resend instruction and the identical resend in the same
	// session reached the model; redact mode sent [REDACTED:github_pat] with
	// the reason as additionalContext.
	hookLiveCopilotCLIPrompt = "guard-fix lane B live run 2026-10-15: copilot 1.0.96 -p on demo node 1, BYOK offline against a loopback mock, throwaway COPILOT_HOME"
	// hookLiveClinePlugin: cline 3.0.68 Plugin API. spawn / spawnSync of an
	// executable work inside the plugin sandbox (Node); beforeModel {stop}
	// sent zero requests and showed no reason; a stopped or rewritten
	// message stayed in the history (the next turn carried it raw) unless
	// rewritten again; beforeTool {skip, reason} refused one call and the
	// model got the reason; setup ctx.session.sessionId is the session-store
	// id; the TUI kept one session across a stop and a resend. Then the
	// plugin `observer init` wrote: a fake-token prompt made zero requests
	// (block), redact mode sent [REDACTED:github_pat], and a model-issued
	// `rm -rf ~/` was skipped per call (the victim file survived, the model
	// got the R-101 reason and the run continued to its next request).
	hookLiveClinePlugin = "guard-fix lane B live run 2026-10-15: cline 3.0.68 on demo node 1, throwaway HOME and CLINE_DIR, private CLINE_HUB_PORT, loopback mock openai-compatible provider"
)

// hgSource is a binding grounded on the vendor's own source as shipped in
// an installed build (GroundingDoc: "the vendor's own documentation or
// source").
func hgSource(src string) Grounding {
	return Grounding{Kind: GroundingDoc, Source: src, Date: hookSrcLaneDate}
}

// hgSourceAt is hgSource with its own date.
func hgSourceAt(src, date string) Grounding {
	return Grounding{Kind: GroundingDoc, Source: src, Date: date}
}

// Kiro CLI vendor research (guard-enforcement fix gfiD): kiro-cli 2.28.0 on
// demo node 1 in a throwaway HOME, offline (KIRO_API_KEY=<fake> plus
// KIRO_MOCK_CHAT_RESPONSE), PROBE hooks in a custom agent JSON. It settled
// the vendor's semantics live; Observer's own writer and receiver have not
// had a live run, so the bindings carry doc-kind grounding and `observer
// start` does not write them (the live gate).
const (
	hookSrcKiroResearch  = "kiro-cli 2.28.0 vendor research on demo node 1 (probe hooks in ~/.kiro/agents/<agent>.json, offline mock model); Observer's own writer not yet live-run"
	hookKiroResearchDate = "2026-10-15"
)

// kiroResearch overrides a Kiro binding's grounding with the vendor research.
var kiroResearch hbOpt = func(b *HookBinding) { b.Grounding = hgSourceAt(hookSrcKiroResearch, hookKiroResearchDate) }

// Reply dialect ids for the bindings Observer registers. Prompt dialects
// are internal/hook's PromptDialect* keys (spelled here because this
// package imports nothing project-internal); tool-gate and lifecycle
// dialects name the receiver family that speaks them today.
const (
	hookDialectClaudePreTool  = "claude-code-pretool"
	hookDialectClaudeCode     = "claude-code"
	hookDialectCursorPerm     = "cursor-permission"
	hookDialectCursor         = "cursor"
	hookDialectCodex          = "codex"
	hookDialectTopLevelBlock  = "top-level-block"
	hookDialectGemini         = "gemini-cli"
	hookDialectQoder          = "qoder"
	hookDialectPoolside       = "poolside"
	hookDialectZcode          = "zcode"
	hookDialectCascade        = "cascade"
	hookDialectCommandCode    = "command-code"
	hookDialectAgyPreInvoke   = "antigravity-preinvocation"
	hookDialectHermesPlugin   = "hermes-plugin"
	hookDialectClineCLITail   = "cline-cli-jsonl"
	hookDialectBrowserCapture = "browser-capture"
	// hookDialectLifecycle: served by cmd/observer's ONE lifecycle handler
	// (hook-parity Lane C1, internal/hooklifecycle); the reply is the
	// neutral {} every Claude-shaped host and Codex accept.
	hookDialectLifecycle = "lifecycle"
	// Lane B prompt dialects (internal/hook promptsubmit.go).
	hookDialectKimiCode = "kimi-code"
	hookDialectDevinCLI = "devin-cli"
	// Guard-fix lane B prompt dialects (internal/hook promptcopilot.go,
	// promptclineplugin.go) and the Cline plugin tool gate
	// (toolgate_clineplugin.go).
	hookDialectCopilotPrompt     = "copilot-cli-prompt"
	hookDialectClinePluginPrompt = "cline-plugin-prompt"
	hookDialectClinePluginTool   = "cline-plugin-pretool"
	hookDialectKiroCLI           = "kiro-cli"
	// Tool-gate dialects (internal/hook toolgate.go ToolGateDialect*).
	hookDialectClaudeJSONPreTool = "claude-json-pretool"
	hookDialectGeminiBeforeTool  = "gemini-beforetool"
	hookDialectCursorPreTool     = "cursor-pretool"
	// hookDialectCursorReplay is cursor's preToolUse reached through
	// Observer's Claude Code hooks (FU-122): judges every class.
	hookDialectCursorReplay = "cursor-pretool-replay"
	// Lane A4-A6 tool-gate dialects.
	hookDialectAgyPreTool      = "antigravity-pretool"
	hookDialectGrokPreTool     = "grok-pretool"
	hookDialectCopilotPreTool  = "copilot-cli-pretool"
	hookDialectVibePreTool     = "vibe-pretool"
	hookDialectGoosePreTool    = "goose-pretool"
	hookDialectClinePreTool    = "cline-pretool"
	hookDialectPoolsidePreTool = "poolside-pretool"
	hookDialectJuniePreTool    = "junie-pretool"
	hookDialectCrushPreTool    = "crush-pretool"
	hookDialectCascadePreTool  = "cascade-pretool"
	hookDialectKiroPreTool     = "kiro-pretool"
	hookDialectKimiPreTool     = "kimi-pretool"
	// hookKimiRegisteredTimeout is the "timeout" (seconds) Observer writes
	// on its Kimi Code [[hooks]] tables (the vendor default is also 30).
	hookKimiRegisteredTimeout = 30 * time.Second
	// Host hook timeouts for the Lane A4-A6 tool gates: the value Observer
	// registers where it sets one, else the vendor's documented default.
	hookAgyToolGateTimeout      = 30 * time.Second
	hookGrokRegisteredTimeout   = 10 * time.Second
	hookCopilotCLIHostTimeout   = 30 * time.Second
	hookVibeRegisteredTimeout   = 30 * time.Second
	hookGooseHostTimeout        = 30 * time.Second
	hookClineHostTimeout        = 120 * time.Second
	hookPoolsideHostTimeout     = 60 * time.Second
	hookJunieRegisteredTimeout  = 10 * time.Second
	hookCrushHostTimeout        = 30 * time.Second
	hookZcodeRegisteredTimeout  = 30 * time.Second
	hookCommandCodeShellTimeout = 30 * time.Second
	// hookKiroHostTimeout is the timeout Observer registers on its Kiro
	// entries (timeout_ms 30000 in an agent JSON, timeout 30 in the V3
	// standalone file, whose documented default is 60 s).
	hookKiroHostTimeout = 30 * time.Second
	// hookMuseRegisteredTimeout is the "timeout" Observer registers on its
	// Muse handlers.
	hookMuseRegisteredTimeout = 30 * time.Second
	// hookDevinCLIRegisteredTimeout is the timeout Observer registers on
	// its Devin CLI handler (seconds field "timeout").
	hookDevinCLIRegisteredTimeout = 30 * time.Second
	// hookCodexHostTimeout is Codex's default command-hook timeout (600 s:
	// codex-rs/hooks/src/engine/discovery.rs normalize_command_hook, every
	// event except SessionEnd / Interrupt).
	hookCodexHostTimeout = 600 * time.Second
	// hookCursorHostTimeout is the per-hook timeout Cursor logs ("Running
	// hook 1 with timeout 60000ms").
	hookCursorHostTimeout = 60 * time.Second
	// hookGeminiHostTimeout is Gemini CLI's documented default (60000 ms).
	hookGeminiHostTimeout      = 60 * time.Second
	hookClaudeHostTimeout      = 60 * time.Second
	hookGrokHostTimeout        = 5 * time.Second
	hookAgyRegisteredTimeout   = 10 * time.Second
	hookCommandCodeModTimeoutS = 5 * time.Second
	// Plugin-host dialects (internal/hook plugingate.go): the pluginshim TS
	// shim and the Hermes Python plugin.
	hookDialectPluginShim       = "plugin-shim"
	hookDialectPluginShimPrompt = "plugin-shim-prompt"
	// hookDialectPluginShimPromptConfirm is the plugin prompt seam that
	// also has a native confirm and a rewrite (pi `input`).
	hookDialectPluginShimPromptConfirm = "plugin-shim-prompt-confirm"
)

// Post-tool feedback dialects (security pillar plan sections 4.7 and
// 5.11 (c), spike JSP-6, lane SEC-H): the reply writer internal/secfeedback
// uses to put the security feedback line into the host's post-tool reply.
// One id per reply shape, never per tool.
const (
	// hookDialectFeedbackClaude: hookSpecificOutput.additionalContext
	// beside the kept "decision":"approve" (Claude Code, Qoder).
	hookDialectFeedbackClaude = "feedback-claude"
	// hookDialectFeedbackCodex: hookSpecificOutput.additionalContext, a
	// separate developer message, after a successful tool only.
	hookDialectFeedbackCodex = "feedback-codex"
	// hookDialectFeedbackGemini: hookSpecificOutput.additionalContext
	// appended to the tool result (Gemini CLI AfterTool, Qwen Code).
	hookDialectFeedbackGemini = "feedback-gemini"
	// hookDialectFeedbackCline: a file hook's contextModification, a
	// <hook_context> user message after the tool results.
	hookDialectFeedbackCline = "feedback-cline"
	// hookDialectFeedbackPlugin: the plugin shim appends the reply's
	// context to output.output in tool.execute.after (OpenCode, Kilo).
	hookDialectFeedbackPlugin = "feedback-plugin"
	// hookDialectFeedbackCursor: additional_context on postToolUse,
	// size-capped by the host.
	hookDialectFeedbackCursor = "feedback-cursor"
)

// hookFeedbackComponent is the component whose selection registers the
// post-tool feedback events no other binding registers (RegisterWhen).
const hookFeedbackComponent = "security.feedback"

// JSP-6 grounding of the post-tool context rows.
const (
	hookJSP6LiveDate = "2026-10-20"
	hookJSP6Live     = "docs/plans/spikes/JSP-6-per-tool-grounding-2026-10.md \"Live half\" (the model quoted the probe's injected marker; evidence _spikes/jsp-6/live/)"
	hookJSP6Source   = "docs/plans/spikes/JSP-6-per-tool-grounding-2026-10.md and _spikes/jsp-6/vendor-grounding.md (vendor source at a named release; live pending)"
)

// hgSourceOpt overrides a binding's grounding with the JSP-6 vendor-source
// reading.
func hgSourceOpt(src string) hbOpt {
	return func(b *HookBinding) { b.Grounding = hgSourceAt(src, hookJSP6LiveDate) }
}

// feedbackPost marks a post-phase context_inject row: the reply dialect, a
// context-only decision, and, where no other binding registers the event,
// the component that registers it.
func feedbackPost(dialect string, optIn bool) hbOpt {
	return func(b *HookBinding) {
		b.Dialect, b.Decisions = dialect, []string{HookDecisionContext}
		if optIn {
			b.RegisterWhen = hookFeedbackComponent
		}
	}
}

// hbOpt mutates one binding under construction.
type hbOpt func(*HookBinding)

// hb builds a binding. Defaults: no process relation known, host failure
// behaviour unknown, vendor-only (not registered, not wired).
func hb(c HookCap, phase, event string, g Grounding, opts ...hbOpt) HookBinding {
	b := HookBinding{Cap: c, Phase: phase, NativeEvent: event, Grounding: g, ProcRel: ProcNone, HostOnFailure: HostFailureUnknown}
	for _, o := range opts {
		o(&b)
	}
	return b
}

func hgDoc(src string) Grounding {
	return Grounding{Kind: GroundingDoc, Source: src, Date: hookDocDate}
}

func hgInferred(src string) Grounding {
	return Grounding{Kind: GroundingInferred, Source: src, Date: hookDocDate}
}

func hgLive(src, date string) Grounding {
	return Grounding{Kind: GroundingLive, Source: src, Date: date}
}

// hookLiveGroundDate is the 2026-10-04 live-ground lane's capture date.
const hookLiveGroundDate = "2026-10-04"

// hgLiveOpt marks a binding live-grounded by the 2026-10-04 live-ground
// lane.
func hgLiveOpt(src string) hbOpt {
	return func(b *HookBinding) { b.Grounding = hgLive(src, hookLiveGroundDate) }
}

func hgFixture(src string) Grounding {
	return Grounding{Kind: GroundingFixture, Source: src, Date: hookDocDate}
}

// liveAt overrides a binding's grounding with a recorded live test (a
// plugin-host builder fixes the doc grounding for the whole host).
func liveAt(src, date string) hbOpt {
	return func(b *HookBinding) { b.Grounding = hgLive(src, date) }
}

// pluginShimLive is the Lane D node 1 live test of a shim binding.
var pluginShimLive = liveAt(hookLivePluginShim, hookLivePluginShimDate)

func dec(d ...string) hbOpt { return func(b *HookBinding) { b.Decisions = d } }

// reg marks the event as registered by Observer with the given dialect.
func reg(dialect string) hbOpt {
	return func(b *HookBinding) { b.Registered, b.Dialect = true, dialect }
}

// wired marks a feature as acting on the event today.
func wired() hbOpt { return func(b *HookBinding) { b.Wired = true } }

// dialectOnly names the dialect of a binding Observer handles but does not
// write into a vendor config (manual registration, tailer, plugin events).
func dialectOnly(dialect string) hbOpt { return func(b *HookBinding) { b.Dialect = dialect } }

func sess() hbOpt { return func(b *HookBinding) { b.SessionKey = true } }

func proc(p ProcRelation) hbOpt { return func(b *HookBinding) { b.ProcRel = p } }

func host(timeout time.Duration, f FailurePolicy) hbOpt {
	return func(b *HookBinding) { b.HostTimeout, b.HostOnFailure = timeout, f }
}

func note(s string) hbOpt { return func(b *HookBinding) { b.Note = s } }

// laneCLive overrides a binding's grounding with a hook-parity Lane C node-1
// live capture (src names the vendor build and what was confirmed).
func laneCLive(src string) hbOpt {
	return func(b *HookBinding) { b.Grounding = hgLive(src, hookLiveLaneCDate) }
}

func guardChannel(ch string) hbOpt { return func(b *HookBinding) { b.GuardChannel = ch } }

// hookWarnSystemMessage is the Claude-shaped common output field the host
// shows the developer as a warning (code.claude.com/docs/en/hooks "Warning
// message shown to the user"; Codex "surfaced as a warning in the UI";
// Gemini CLI "shown to the user in the terminal"; Qwen Code and Factory
// Droid take the Claude-compatible common field).
const hookWarnSystemMessage = "systemMessage"

// warnField declares the allow reply's developer-visible notice field
// (HookBinding.WarnField).
func warnField(f string) hbOpt { return func(b *HookBinding) { b.WarnField = f } }

// hookWarnPluginMessage is the plugin dialect's allow-reply notice field
// (internal/hook PluginReply.Message): the shim shows it to the developer
// on hosts whose plugin has a notice channel (a TUI toast, pi's notify).
const hookWarnPluginMessage = "message"

// adminCaveat sets the binding's short admin-facing coverage caveat
// (HookBinding.AdminCaveat).
func adminCaveat(s string) hbOpt { return func(b *HookBinding) { b.AdminCaveat = s } }

// all applies several options at once (a per-vendor default set).
func all(opts ...hbOpt) hbOpt {
	return func(b *HookBinding) {
		for _, o := range opts {
			o(b)
		}
	}
}

// Decision sets reused below.
var (
	decDeny          = []string{HookDecisionDeny}
	decDenyModify    = []string{HookDecisionDeny, HookDecisionModify}
	decDenyAskModify = []string{HookDecisionDeny, HookDecisionAsk, HookDecisionModify}
	decDenyAsk       = []string{HookDecisionDeny, HookDecisionAsk}
	decDenyContext   = []string{HookDecisionDeny, HookDecisionContext}
	decContext       = []string{HookDecisionContext}
	decModify        = []string{HookDecisionModify}
	decMessage       = []string{HookDecisionMessage}
)

// --- claude-code: shell commands in ~/.claude/settings.json ---------------

var claudeCodeOpts = all(sess(), proc(ProcDescendant), host(hookClaudeHostTimeout, HostProceeds))

func claudeB(c HookCap, phase, event string, opts ...hbOpt) HookBinding {
	return hb(c, phase, event, hgDoc(hookSrcClaudeCode), append([]hbOpt{claudeCodeOpts}, opts...)...)
}

// claudeTaskNote is the honest status of the Claude Code task events
// (hook-parity Lane E, 2026-10-03).
const claudeTaskNote = "capture only: `observer hook claude-code task-created|task-completed` records a task_event action and always approves (exit 0), so the vendor's exit-2 rollback is never taken. Live on demo node 1 (Claude Code 2.1.288 -p, CLAUDE_CODE_ENABLE_TASKS=true, throwaway HOME, hooks written by `observer init --claude-code`): TaskCreate fired TaskCreated and TaskUpdate(status completed) fired TaskCompleted, payload {session_id, cwd, prompt_id, task_id, task_subject, task_description}; four task_event rows landed. p95 hook latency 52 ms"

// hookLiveClaudeTasks is the T-322 live capture of the task events.
const (
	hookLiveClaudeTasksDate = "2026-10-04"
	hookLiveClaudeTasks     = "hook-parity live-ground 2026-10-04 (T-322): Claude Code 2.1.288 -p on demo node 1, TaskCreated x2 + TaskCompleted x2 captured, task_event rows in the probe DB"
)

var hookBindingsClaudeCode = []HookBinding{
	claudeB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart", reg(hookDialectClaudeCode), wired()),
	claudeB(HookCapContextInject, HookPhaseStart, "SessionStart", reg(hookDialectClaudeCode), wired(), dec(HookDecisionContext)),
	claudeB(HookCapSessionLifecycle, HookPhaseEnd, "SessionEnd", reg(hookDialectLifecycle), wired(),
		laneCLive(hookLiveClaudeLC),
		note("served by the one lifecycle handler: the session_end row is spooled DB-free (the host's SessionEnd budget is about 1.5 s) and ingested by the daemon")),
	claudeB(HookCapEnvironmentObserve, HookPhaseNone, "Setup", reg(hookDialectClaudeCode), wired()),
	hb(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", hgLive(hookLiveClaude, hookLiveClaudeDate), claudeCodeOpts,
		reg(hookDialectClaudeCode), wired(),
		dec(HookDecisionAllow, HookDecisionAsk, HookDecisionDeny, HookDecisionContext, HookDecisionMessage),
		note("process exit code 2 with NO stdout reply; stderr is the user-visible reason and the prompt is erased (LIVE CORRECTION 2026-09-07: permissionDecision is PreToolUse-only and is silently ignored on this event). Allow/warn reply with the bare hookSpecificOutput envelope (+ additionalContext on warn)")),
	claudeB(HookCapUserMessage, HookPhasePre, "UserPromptSubmit", reg(hookDialectClaudeCode), wired(), dec(HookDecisionMessage)),
	claudeB(HookCapEnvironmentObserve, HookPhaseNone, "UserPromptExpansion", reg(hookDialectClaudeCode), wired()),
	hb(HookCapToolGate, HookPhasePre, "PreToolUse", hgLive(hookLiveClaude, hookLiveClaudeDate), claudeCodeOpts,
		reg(hookDialectClaudePreTool), wired(), warnField(hookWarnSystemMessage),
		dec(HookDecisionAllow, HookDecisionAsk, HookDecisionDeny, HookDecisionModify),
		note("native ask via permissionDecision alone (the legacy decision:block is sent only beside a deny: beside an ask it turned the ask into a block, live audit 2026-10-15); a flag is shown to the developer through systemMessage on the allow; payload carries cwd but no project root, so boundary rules defer to the watcher")),
	claudeB(HookCapToolRewrite, HookPhasePre, "PreToolUse", reg(hookDialectClaudePreTool), wired(), dec(HookDecisionModify)),
	claudeB(HookCapToolObserve, HookPhasePost, "PostToolUse", reg(hookDialectClaudeCode), wired()),
	hb(HookCapContextInject, HookPhasePost, "PostToolUse", hgLive(hookJSP6Live, hookJSP6LiveDate), claudeCodeOpts,
		feedbackPost(hookDialectFeedbackClaude, false),
		note("security feedback (lane SEC-H): hookSpecificOutput.additionalContext beside the kept decision approve; live on Claude Code 2.1.304 (JSP-6 live half), also after a PowerShell call on Windows. The event is already registered for tool_observe, so nothing new is written")),
	claudeB(HookCapToolFailureObserve, HookPhasePost, "PostToolUseFailure", reg(hookDialectClaudeCode), wired()),
	claudeB(HookCapToolObserve, HookPhasePost, "PostToolBatch", reg(hookDialectClaudeCode), wired()),
	claudeB(HookCapPermissionObserve, HookPhasePre, "PermissionRequest", reg(hookDialectClaudeCode), wired()),
	claudeB(HookCapPermissionObserve, HookPhasePost, "PermissionDenied", reg(hookDialectClaudeCode), wired()),
	claudeB(HookCapTurnLifecycle, HookPhaseEnd, "Stop", reg(hookDialectClaudeCode), wired(), dec(HookDecisionDeny)),
	claudeB(HookCapTurnLifecycle, HookPhaseEnd, "StopFailure", reg(hookDialectClaudeCode), wired()),
	claudeB(HookCapCompactLifecycle, HookPhasePre, "PreCompact", reg(hookDialectClaudeCode), wired()),
	claudeB(HookCapCompactLifecycle, HookPhasePost, "PostCompact", reg(hookDialectClaudeCode), wired()),
	claudeB(HookCapSubagentLifecycle, HookPhaseStart, "SubagentStart", reg(hookDialectClaudeCode), wired()),
	claudeB(HookCapSubagentLifecycle, HookPhaseEnd, "SubagentStop", reg(hookDialectClaudeCode), wired()),
	claudeB(HookCapNotificationObserve, HookPhaseNone, "Notification", reg(hookDialectClaudeCode), wired()),
	claudeB(HookCapEnvironmentObserve, HookPhaseNone, "CwdChanged", reg(hookDialectClaudeCode), wired()),
	claudeB(HookCapEnvironmentObserve, HookPhaseNone, "InstructionsLoaded", reg(hookDialectClaudeCode), wired()),
	claudeB(HookCapEnvironmentObserve, HookPhaseNone, "ConfigChange", reg(hookDialectClaudeCode), wired()),
	claudeB(HookCapEnvironmentObserve, HookPhaseNone, "WorktreeRemove", reg(hookDialectClaudeCode), wired()),
	// Vendor-only: WorktreeCreate is blocking and opt-in
	// (docs/claude-worktree-hook.md); the task events have a capture-only
	// receiver but are not registered until live-grounded (hook-parity
	// Lane E); FileChanged needs a per-file matcher.
	claudeB(HookCapEnvironmentObserve, HookPhaseNone, "WorktreeCreate", note("opt-in only (docs/claude-worktree-hook.md): blocking, must echo the worktree path")),
	hb(HookCapTaskObserve, HookPhaseStart, "TaskCreated", hgLive(hookLiveClaudeTasks, hookLiveClaudeTasksDate), claudeCodeOpts, reg(hookDialectClaudeCode), wired(), note(claudeTaskNote)),
	hb(HookCapTaskObserve, HookPhaseEnd, "TaskCompleted", hgLive(hookLiveClaudeTasks, hookLiveClaudeTasksDate), claudeCodeOpts, reg(hookDialectClaudeCode), wired(), note(claudeTaskNote)),
	claudeB(HookCapEnvironmentObserve, HookPhaseNone, "FileChanged", note("matcher takes literal filenames, not the wildcard every registered event uses")),
}

// --- codex: shell commands in ~/.codex/hooks.json --------------------------

var codexOpts = all(sess(), proc(ProcDescendant), host(0, HostProceeds))

func codexB(c HookCap, phase, event string, opts ...hbOpt) HookBinding {
	return hb(c, phase, event, hgDoc(hookSrcCodex), append([]hbOpt{codexOpts}, opts...)...)
}

var hookBindingsCodex = []HookBinding{
	hb(HookCapSessionLifecycle, HookPhaseStart, "SessionStart", hgLive(hookLiveCodex, hookLiveCodexDate), codexOpts, reg(hookDialectCodex), wired()),
	codexB(HookCapContextInject, HookPhaseStart, "SessionStart", reg(hookDialectCodex), dec(HookDecisionContext, HookDecisionMessage)),
	hb(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", hgLive(hookLiveCodex, hookLiveCodexDate), codexOpts,
		reg(hookDialectTopLevelBlock), wired(),
		dec(HookDecisionAllow, HookDecisionAsk, HookDecisionDeny, HookDecisionContext, HookDecisionMessage),
		note("legacy {decision:block,reason} shown to the developer; prompt cannot be modified")),
	hb(HookCapToolGate, HookPhasePre, "PreToolUse", hgLive(hookLiveCodexToolGate, hookLiveLaneADate), codexOpts,
		reg(hookDialectClaudeJSONPreTool), wired(), warnField(hookWarnSystemMessage),
		host(hookCodexHostTimeout, HostProceeds),
		adminCaveat("Sub-agents started with spawn_agent bypass the gate, and some unified_exec shell calls are not intercepted."),
		dec(HookDecisionAllow, HookDecisionDeny, HookDecisionModify),
		note("hookSpecificOutput.permissionDecision deny with a reason (Codex shows the model \"Command blocked by PreToolUse hook: <reason>\"); covers Bash, apply_patch (every file in the patch) and MCP tools; no ask: Codex rejects permissionDecision:ask and fails open (openai/codex #28437), so an enforced ask is a deny that says how to confirm; unified_exec shell calls are only partly intercepted (#20204) and spawn_agent sub-agents bypass hooks (#49736)")),
	codexB(HookCapPermissionObserve, HookPhasePre, "PermissionRequest", reg(hookDialectCodex), wired()),
	codexB(HookCapToolObserve, HookPhasePost, "PostToolUse", reg(hookDialectCodex), wired()),
	hb(HookCapContextInject, HookPhasePost, "PostToolUse", hgLive(hookJSP6Live, hookJSP6LiveDate), codexOpts,
		feedbackPost(hookDialectFeedbackCodex, false),
		note("security feedback (lane SEC-H): hookSpecificOutput.additionalContext becomes a separate developer message right after the tool, and Codex runs PostToolUse only after a successful tool; live on codex 0.144.4 (JSP-6 live half). Already registered for tool_observe")),
	codexB(HookCapTurnLifecycle, HookPhaseEnd, "Stop", reg(hookDialectCodex), wired(), dec(HookDecisionDeny)),
	codexB(HookCapSessionLifecycle, HookPhaseEnd, "SessionEnd", reg(hookDialectLifecycle), wired(), laneCLive(hookLiveCodexLC)),
	codexB(HookCapSubagentLifecycle, HookPhaseStart, "SubagentStart", reg(hookDialectLifecycle), wired(), laneCLive(hookLiveCodexLC),
		note("session_id is the PARENT session; agent_id is the child rollout uuid")),
	codexB(HookCapSubagentLifecycle, HookPhaseEnd, "SubagentStop", reg(hookDialectLifecycle), wired(), laneCLive(hookLiveCodexLC)),
	codexB(HookCapCompactLifecycle, HookPhasePre, "PreCompact", dialectOnly(hookDialectCodex),
		note("routed to the one compaction recorder (hook-parity Lane E); not registered until a live Codex capture grounds it (new events also need [hooks.state] re-trust)")),
	codexB(HookCapCompactLifecycle, HookPhasePost, "PostCompact", dialectOnly(hookDialectCodex),
		note("routed to the one compaction recorder (hook-parity Lane E); not registered until a live Codex capture grounds it")),
	// The config.toml `notify` program, not a hooks.json event: listed in
	// the guard conformance matrix as an observe-only channel.
	codexB(HookCapTurnLifecycle, HookPhaseEnd, "notify", guardChannel("notify"),
		note("observe-only notification channel - no documented deny semantics (Q4); enforcement comes from the native rules dialect once G11 compiles it")),
}

// --- cursor: shell commands in ~/.cursor/hooks.json ------------------------

var cursorOpts = all(sess(), proc(ProcDescendant))

func cursorB(c HookCap, phase, event string, opts ...hbOpt) HookBinding {
	return hb(c, phase, event, hgFixture(hookFixtureCursor), append([]hbOpt{cursorOpts}, opts...)...)
}

var hookBindingsCursor = []HookBinding{
	cursorB(HookCapPromptGate, HookPhasePre, "beforeSubmitPrompt", reg(hookDialectCursor), wired(),
		dec(HookDecisionAllow, HookDecisionAsk, HookDecisionDeny, HookDecisionMessage),
		note("continue:false + user_message (NOT the permission field the shell/MCP/file channels use); prompt cannot be modified")),
	cursorB(HookCapToolGate, HookPhasePre, "beforeShellExecution", reg(hookDialectCursorPerm), wired(),
		dec(HookDecisionAllow, HookDecisionAsk, HookDecisionDeny),
		note("permission JSON allow|deny|ask; payload carries the workspace root, so boundary rules are active pre-execution")),
	cursorB(HookCapToolObserve, HookPhasePost, "afterFileEdit", reg(hookDialectCursor), wired()),
	cursorB(HookCapToolGate, HookPhasePre, "beforeMCPExecution", reg(hookDialectCursorPerm), wired(),
		dec(HookDecisionAllow, HookDecisionAsk, HookDecisionDeny), note("permission JSON allow|deny|ask")),
	cursorB(HookCapTurnLifecycle, HookPhaseEnd, "stop", reg(hookDialectCursor), wired()),
	cursorB(HookCapModelCallObserve, HookPhasePost, "stop", reg(hookDialectCursor), wired()),
	cursorB(HookCapToolGate, HookPhasePre, "beforeReadFile", reg(hookDialectCursorPerm), wired(),
		dec(HookDecisionAllow, HookDecisionAsk, HookDecisionDeny), note("permission JSON allow|deny|ask")),
	cursorB(HookCapToolFailureObserve, HookPhasePost, "postToolUseFailure", reg(hookDialectCursor), wired()),
	cursorB(HookCapSessionLifecycle, HookPhaseStart, "sessionStart", reg(hookDialectCursor), wired()),
	cursorB(HookCapContextInject, HookPhaseStart, "sessionStart", reg(hookDialectCursor), dec(HookDecisionContext)),
	cursorB(HookCapSessionLifecycle, HookPhaseEnd, "sessionEnd", reg(hookDialectCursor), wired()),
	cursorB(HookCapSubagentLifecycle, HookPhaseStart, "subagentStart", reg(hookDialectCursor), wired(), dec(HookDecisionDeny),
		note("observe only: the cursor receiver records a subagent_start row (cursor.BuildToolEvent); the deny reply is not used")),
	cursorB(HookCapSubagentLifecycle, HookPhaseEnd, "subagentStop", reg(hookDialectCursor), wired()),
	cursorB(HookCapCompactLifecycle, HookPhasePre, "preCompact", reg(hookDialectCursor), wired(),
		note("compaction_events capture (hook-parity Lane E): conversation_id + workspace_roots[0]; no post event, so the capture is never reconciled")),
	hb(HookCapToolGate, HookPhasePre, "preToolUse", hgLive(hookLiveCursorToolGate, hookLiveLaneADate), cursorOpts,
		reg(hookDialectCursorPreTool), wired(),
		host(hookCursorHostTimeout, HostFailureUnknown),
		dec(HookDecisionAllow, HookDecisionDeny, HookDecisionModify),
		note("permission allow|deny with user_message + agent_message; judges the classes the per-tool before* events do not (writes, edits, deletes, content search, web); ask is accepted but not enforced on this event (vendor docs), so an enforced ask is a deny that says how to confirm")),
	// Cursor IDE's Agents window also runs ~/.claude/settings.json hooks
	// (FU-122, Mac round 4): a fallback the claude-code receiver serves under
	// cursor only while Observer's own preToolUse registration above is
	// absent (internal/hook foreignhost.go, the copilot-cli G2 rule). While
	// it is present the replay answers neutral and the registered gate
	// judges. Listed after the registered gate so Binding("preToolUse") is
	// still that gate.
	cursorB(HookCapToolGate, HookPhasePre, "preToolUse", dialectOnly(hookDialectCursorReplay), wired(), replayedVia(replayClaudeCode), standsInFor("preToolUse"),
		host(hookCursorHostTimeout, HostFailureUnknown), dec(HookDecisionAllow, HookDecisionDeny),
		note("reached through Observer's Claude Code hooks: cursor-agent runs ~/.claude/settings.json hooks with its own preToolUse payload (cursor_version, conversation_id, hook_event_name preToolUse; Mac round 4, Cursor IDE Agents window). The claude-code receiver answers it with Cursor's neutral {} while Observer's cursor registration holds preToolUse, and otherwise gates it as cursor with the permission deny, every action class included (no before* event is replayed there). The payload is live-captured on macOS; a deny on this path is not yet live-run")),
	cursorB(HookCapToolObserve, HookPhasePost, "postToolUse", reg(hookDialectCursor), wired()),
	hb(HookCapContextInject, HookPhasePost, "postToolUse", hgSourceAt("installed cursor-agent bundle 2026.08.25 read in the JSP-6 live half (_spikes/jsp-6/live/cursor/cursor1.out.txt); no live turn", hookJSP6LiveDate), cursorOpts,
		feedbackPost(hookDialectFeedbackCursor, false),
		note("security feedback (lane SEC-H): additional_context on the postToolUse reply, size-capped by the host; installed-code grounded, live pending. Already registered for tool_observe")),
	cursorB(HookCapToolObserve, HookPhasePost, "afterShellExecution", reg(hookDialectCursor), wired()),
	cursorB(HookCapToolObserve, HookPhasePost, "afterMCPExecution", reg(hookDialectCursor), wired()),
	cursorB(HookCapModelCallObserve, HookPhasePost, "afterAgentThought", reg(hookDialectCursor), wired()),
	cursorB(HookCapModelCallObserve, HookPhasePost, "afterAgentResponse", reg(hookDialectCursor), wired()),
}

// --- gemini-cli: shell commands in ~/.gemini/settings.json -----------------

var geminiOpts = all(sess(), proc(ProcDescendant))

func geminiB(c HookCap, phase, event string, opts ...hbOpt) HookBinding {
	return hb(c, phase, event, hgDoc(hookSrcGemini), append([]hbOpt{geminiOpts}, opts...)...)
}

var hookBindingsGeminiCLI = []HookBinding{
	geminiB(HookCapPromptGate, HookPhasePre, "BeforeAgent", reg(hookDialectGemini), wired(), liveAt(hookLiveGeminiGates, hookLiveGeminiGatesDate),
		dec(HookDecisionAllow, HookDecisionAsk, HookDecisionDeny, HookDecisionContext, HookDecisionMessage),
		note("decision:deny discards the message; both reason and systemMessage are set (vendor docs call systemMessage user-visible in the terminal, and reason also renders when denying). Live (gemini 0.62.0, demo node 1): the block held with zero model requests and the developer saw \"Agent execution blocked: <reason>\"; because the reply also exits 2, gemini additionally prints \"Hook(s) failed for event BeforeAgent\" beside the block")),
	geminiB(HookCapUserMessage, HookPhasePre, "BeforeAgent", reg(hookDialectGemini), wired(), liveAt(hookLiveGeminiGates, hookLiveGeminiGatesDate), dec(HookDecisionMessage)),
	geminiB(HookCapToolGate, HookPhasePre, "BeforeTool", reg(hookDialectGeminiBeforeTool), wired(), liveAt(hookLiveGeminiGates, hookLiveGeminiGatesDate), warnField(hookWarnSystemMessage),
		host(hookGeminiHostTimeout, HostFailureUnknown),
		dec(HookDecisionAsk, HookDecisionDeny, HookDecisionModify),
		note("decision:deny with reason (sent to the agent as the tool error) and systemMessage (shown to the developer); decision:ask forces a confirmation even under YOLO (live 0.53.1, source the same at 0.64.0, JSP-6 live half), but a headless ask hangs the run (-p --yolo stalled until killed at 180 s), so the ask is offered only when the per-call probe finds the gemini process with a terminal (integration.AskHost, AskNeedsTerminal); anywhere else an ask is a deny that says how to confirm")),
	geminiB(HookCapToolObserve, HookPhasePost, "AfterTool"),
	hb(HookCapContextInject, HookPhasePost, "AfterTool", hgLive(hookJSP6Live, hookJSP6LiveDate), geminiOpts,
		feedbackPost(hookDialectFeedbackGemini, true),
		note("security feedback (lane SEC-H): hookSpecificOutput.additionalContext is escaped and appended to the tool result as <hook_context>...</hook_context>; live on gemini 0.53.1 (JSP-6 live half). AfterTool is registered only while security.feedback is selected")),
	geminiB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart", dec(HookDecisionContext, HookDecisionMessage)),
	geminiB(HookCapSessionLifecycle, HookPhaseEnd, "SessionEnd"),
	geminiB(HookCapTurnLifecycle, HookPhaseEnd, "AfterAgent", dec(HookDecisionDeny)),
	geminiB(HookCapCompactLifecycle, HookPhasePre, "PreCompress", dialectOnly(hookDialectGemini),
		note("routed to the one compaction recorder (hook-parity Lane E); the gemini-cli writer registers BeforeAgent only")),
	geminiB(HookCapModelCallObserve, HookPhasePost, "AfterModel", note("fires per streaming chunk: never bind it for token capture")),
	geminiB(HookCapNotificationObserve, HookPhaseNone, "Notification"),
}

// --- Claude-Code-shaped shell-hook clones: qwen-code, droid, qoder ---------

func cloneB(src string) func(c HookCap, phase, event string, opts ...hbOpt) HookBinding {
	return func(c HookCap, phase, event string, opts ...hbOpt) HookBinding {
		return hb(c, phase, event, hgDoc(src), append([]hbOpt{sess(), proc(ProcDescendant)}, opts...)...)
	}
}

var (
	qwenB  = cloneB(hookSrcQwen)
	droidB = cloneB(hookSrcDroid)
	qoderB = cloneB(hookSrcQoder)
)

var hookBindingsQwenCode = []HookBinding{
	qwenB(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", reg(hookDialectTopLevelBlock), wired(),
		dec(HookDecisionAllow, HookDecisionAsk, HookDecisionDeny, HookDecisionContext, HookDecisionMessage),
		note("documented decision enum is allow|deny|block|ask; observer emits \"block\" (the verb every sibling top-level-block vendor's docs confirm) rather than guessing a semantic split between deny/block/ask the docs don't draw")),
	hb(HookCapToolGate, HookPhasePre, "PreToolUse", hgLive(hookLiveQwenToolGate, hookLiveT357Date), sess(), proc(ProcDescendant),
		reg(hookDialectClaudeJSONPreTool), wired(), warnField(hookWarnSystemMessage),
		dec(decDenyAskModify...),
		note("hookSpecificOutput.permissionDecision deny|ask with permissionDecisionReason (Claude-shaped); live (qwen 0.24.7 --yolo): the deny reason reached the model, {} let the call run, and an ask was NOT run headless (qwen showed the reason); the interactive ask prompt is not probed. The payload names the native tool (run_shell_command, read_file, glob, write_file) with tool_input")),
	qwenB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart", reg(hookDialectLifecycle), wired(), dec(decContext...), laneCLive(hookLiveQwenStartLC)),
	hb(HookCapContextInject, HookPhasePost, "PostToolUse", hgSourceAt(hookJSP6Source, hookJSP6LiveDate), sess(), proc(ProcDescendant),
		feedbackPost(hookDialectFeedbackGemini, true),
		note("security feedback (lane SEC-H): hookSpecificOutput.additionalContext is appended to the function response sent to the model (qwen-code 0.25.3 source, coreToolScheduler.ts); live pending (the JSP-6 live turns stalled on HTTP 429). PostToolUse is registered only while security.feedback is selected")),
	// Owed a live run (Lane C node 1: every qwen turn 404'd on the free
	// model, so no end event fired); the lifecycle handler would serve them,
	// but they are not registered until a capture grounds them.
	qwenB(HookCapSessionLifecycle, HookPhaseEnd, "SessionEnd", dialectOnly(hookDialectLifecycle)),
	qwenB(HookCapTurnLifecycle, HookPhaseEnd, "Stop", dialectOnly(hookDialectLifecycle), dec(decDeny...)),
	qwenB(HookCapSubagentLifecycle, HookPhaseStart, "SubagentStart", dialectOnly(hookDialectLifecycle)),
	qwenB(HookCapSubagentLifecycle, HookPhaseEnd, "SubagentStop", dialectOnly(hookDialectLifecycle)),
	qwenB(HookCapCompactLifecycle, HookPhasePre, "PreCompact", dec(decDeny...), dialectOnly(hookDialectTopLevelBlock),
		note("routed to the one compaction recorder (hook-parity Lane E); exit 0 stdout is appended as custom compact instructions, so the reply is the JSON approve, never text; the qwen-code writer registers UserPromptSubmit only")),
	qwenB(HookCapCompactLifecycle, HookPhasePost, "PostCompact", dialectOnly(hookDialectTopLevelBlock),
		note("routed to the one compaction recorder (hook-parity Lane E); output ignored for control")),
	hb(HookCapTaskObserve, HookPhaseStart, "TodoCreated", hgSource(hookSrcQwenInstalled), sess(), proc(ProcDescendant),
		dialectOnly(hookDialectTopLevelBlock), dec(decDeny...),
		note("task_observe capture only (hook-parity Lane E): fires twice per todo, phase \"validation\" (exit 2 / decision block cancels the creation) then \"postWrite\"; Observer records postWrite only and never blocks. Input todo_id, todo_content, todo_status, all_todos, phase")),
	hb(HookCapTaskObserve, HookPhaseEnd, "TodoCompleted", hgSource(hookSrcQwenInstalled), sess(), proc(ProcDescendant),
		dialectOnly(hookDialectTopLevelBlock), dec(decDeny...),
		note("task_observe capture only (hook-parity Lane E): validation then postWrite like TodoCreated; input todo_id, todo_content, previous_status, all_todos, phase")),
}

var hookBindingsDroid = []HookBinding{
	droidB(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", reg(hookDialectTopLevelBlock), wired(),
		dec(HookDecisionAllow, HookDecisionAsk, HookDecisionDeny, HookDecisionContext, HookDecisionMessage),
		note("same legacy {decision:block,reason} shape as Codex; vendor docs state outright \"hook feedback goes to the user, not the agent\". Not live: on node 1 (2026-10-04) `droid exec` 0.233.0 fired PreToolUse from the same hooks.json but never UserPromptSubmit; the interactive TUI is not probed")),
	hb(HookCapToolGate, HookPhasePre, "PreToolUse", hgLive(hookLiveDroidToolGate, hookLiveT357Date), sess(), proc(ProcDescendant),
		reg(hookDialectClaudeJSONPreTool), wired(), warnField(hookWarnSystemMessage),
		dec(HookDecisionDeny, HookDecisionModify),
		note("hookSpecificOutput.permissionDecision deny with permissionDecisionReason (Claude-shaped); the deny reached the model live. Ask is NOT listed: the vendor documents permissionDecision ask, but live on droid 0.233.0 an ask under `droid exec --auto high` ran the command, so an enforced ask is a deny that says how to confirm. hooks.json keeps its events at the ROOT (a {\"hooks\":{}} wrapper is ignored by droid; Observer's writer repairs it)")),
	// Droid's lifecycle events stay vendor-only (not registered): the earlier
	// "zero hook events" on node 1 was Observer's wrapped hooks.json, fixed
	// 2026-10-04; they are owed their own live run.
	droidB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart", dec(decContext...)),
	droidB(HookCapSessionLifecycle, HookPhaseEnd, "SessionEnd"),
	droidB(HookCapTurnLifecycle, HookPhaseEnd, "Stop", dec(decDeny...)),
	droidB(HookCapSubagentLifecycle, HookPhaseEnd, "SubagentStop"),
	droidB(HookCapCompactLifecycle, HookPhasePre, "PreCompact", dialectOnly(hookDialectTopLevelBlock),
		note("routed to the one compaction recorder (hook-parity Lane E); the droid writer registers UserPromptSubmit only")),
}

var hookBindingsQoder = []HookBinding{
	qoderB(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", reg(hookDialectQoder), wired(),
		dec(HookDecisionAllow, HookDecisionAsk, HookDecisionDeny, HookDecisionMessage),
		note("Part B item 2, phase-3a - live-fetched 2026-09-07 (docs.qoder.com/en/cli/hooks): exit code 2 blocks, plain-text stderr is the developer-visible reason (no JSON reply at all); ~/.qoder/settings.json shares Claude Code's exact hooks schema, so registration reuses registerGenericSettingsHooks")),
	hb(HookCapToolGate, HookPhasePre, "PreToolUse", hgLive(hookLiveQoderToolGate, hookLiveLaneADate), sess(), proc(ProcDescendant),
		reg(hookDialectClaudeJSONPreTool), wired(),
		dec(HookDecisionDeny, HookDecisionModify, HookDecisionContext),
		note("hookSpecificOutput.permissionDecision deny with permissionDecisionReason (Claude-shaped JSON on this event, unlike the exit-code-only UserPromptSubmit); the deny reached the model live. Ask is NOT listed: the vendor documents permissionDecision ask, but live on qodercli 1.1.65 an ask under --yolo ran the command without asking, and re-grounded on 1.1.5 (JSP-6 live half, 2026-10-20) a headless ask failed closed (\"Permission confirmation required but no interactive handler is available\", also under --dangerously-skip-permissions); no interactive turn has been measured on a current build, so an enforced ask stays a deny that says how to confirm (the D-791 outcome, integration.AskHost)")),
	qoderB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart", reg(hookDialectLifecycle), wired(), dec(decContext...), laneCLive(hookLiveQoderLC)),
	hb(HookCapContextInject, HookPhasePost, "PostToolUse", hgLive(hookJSP6Live, hookJSP6LiveDate), sess(), proc(ProcDescendant),
		feedbackPost(hookDialectFeedbackClaude, true),
		note("security feedback (lane SEC-H): Claude-shaped hookSpecificOutput.additionalContext; live on qodercli 1.1.5 (JSP-6 live half: quoted for Write, Edit and Bash). PostToolUse is registered only while security.feedback is selected")),
	qoderB(HookCapSessionLifecycle, HookPhaseEnd, "SessionEnd", reg(hookDialectLifecycle), wired(), laneCLive(hookLiveQoderLC)),
	qoderB(HookCapTurnLifecycle, HookPhaseEnd, "Stop", reg(hookDialectLifecycle), wired(), dec(decDeny...), laneCLive(hookLiveQoderLC)),
	qoderB(HookCapSubagentLifecycle, HookPhaseStart, "SubagentStart", reg(hookDialectLifecycle), wired(), laneCLive(hookLiveQoderLC)),
	qoderB(HookCapSubagentLifecycle, HookPhaseEnd, "SubagentStop", reg(hookDialectLifecycle), wired(), laneCLive(hookLiveQoderLC)),
	qoderB(HookCapCompactLifecycle, HookPhasePre, "PreCompact", dec(decDeny...), dialectOnly(hookDialectQoder),
		note("routed to the one compaction recorder (hook-parity Lane E); the qoder writer registers UserPromptSubmit only")),
	qoderB(HookCapCompactLifecycle, HookPhasePost, "PostCompact", dialectOnly(hookDialectQoder),
		note("routed to the one compaction recorder (hook-parity Lane E)")),
}

// --- poolside: snake_case YAML hooks in ~/.config/poolside/settings.yaml ---

var poolsideB = cloneB(hookSrcPoolside)

// Poolside's "pool CLI only" caveat (W-5) is the ide row of hookSurfaces
// (hooksurface.go), rendered by HookSpec.SurfaceCaveat beside both gates.
var hookBindingsPoolside = []HookBinding{
	poolsideB(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", reg(hookDialectPoolside), wired(),
		dec(HookDecisionAllow, HookDecisionAsk, HookDecisionDeny, HookDecisionModify, HookDecisionContext),
		note("Part B item 2, phase-3a - live-fetched 2026-09-07 (docs.poolside.ai/hooks): JSON decision shape ({\"decision\":\"block\",\"reason\",\"hook_specific_output\":{\"updated_prompt\",\"additional_context\"}}, snake_case); registered in ~/.config/poolside/settings.yaml. REDACT wired (hook-parity Lane B, 2026-10-03): under [guard.prompt] mode redact a secret-only prompt is answered with hook_specific_output.updated_prompt (the model receives the [REDACTED:type] text, the terminal keeps the typed prompt)")),
	poolsideB(HookCapToolGate, HookPhasePre, "PreToolUse", reg(hookDialectPoolsidePreTool), wired(),
		host(hookPoolsideHostTimeout, HostProceeds), dec(decDenyModify...),
		note("hook_specific_output.permission_decision deny with permission_decision_reason (snake_case); the reason reaches the model as the tool result; the allow is an empty stdout (no allow value is documented); no ask. Runs before Poolside's own approval prompt. Fails open on timeout / bad output (60 s default). Windows: the vendor runs hooks through cmd /c; Observer writes the poolside-windows bridge too. Not installed on demo node 1 (2026-10-07): the vendor installer asks to accept the Poolside EULA on a TTY, an operator step; doc-grounded, `observer init` only")),
	poolsideB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart", dec(decContext...)),
	poolsideB(HookCapTurnLifecycle, HookPhaseEnd, "Stop"),
	poolsideB(HookCapCompactLifecycle, HookPhasePre, "PreCompact", dec(decContext...), dialectOnly(hookDialectPoolside),
		note("routed to the one compaction recorder (hook-parity Lane E); input trigger auto|forced; a block or continue decision is ignored; the poolside writer registers UserPromptSubmit only")),
}

// --- zcode: ~/.zcode/cli/config.json (receiver only, registered by hand) ---

var zcodeB = cloneB(hookSrcZcode)

var hookBindingsZcode = []HookBinding{
	zcodeB(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", reg(hookDialectZcode), wired(),
		dec(HookDecisionAllow, HookDecisionAsk, HookDecisionDeny, HookDecisionContext),
		note("Part B item 2, phase-3a - live-fetched 2026-09-07 (zcode.z.ai/en/docs/hooks): Claude-Code-shaped continue:false reply, ~/.zcode/cli/config.json registration. The dialect/receiver is built and tested; since hook-parity Lane A4 (2026-10-03) `observer init` registers it beside the PreToolUse gate, but zai-org/feedback #841 (open, v3.14.3) reports UserPromptSubmit never firing on the native agent (and #32 reported no hook firing at all), so prompt coverage there is unproven; doc-grounded, never written by `observer start`")),
	zcodeB(HookCapToolGate, HookPhasePre, "PreToolUse", reg(hookDialectClaudeJSONPreTool), wired(),
		host(hookZcodeRegisteredTimeout, HostProceeds), dec(decDenyAskModify...),
		note("hookSpecificOutput.permissionDecision deny|ask with permissionDecisionReason (Claude-shaped); registered in ~/.zcode/cli/config.json hooks.events with hooks.enabled set true (nothing runs without it). Liveness: zai-org/feedback #32 (closed) reported hooks never firing on the native agent; #841 (open, v3.14.3) reports PreToolUse firing for MAIN-session tool calls only, never for sub-agent or workflow-agent calls (main agent only). Windows: not stated by the vendor. Not installable on demo node 1: Z.ai ships no Linux CLI channel (zcode runs inside its desktop app); doc-grounded, `observer init` only")),
	zcodeB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart", dec(decContext...)),
	zcodeB(HookCapTurnLifecycle, HookPhaseEnd, "Stop", dec(decDeny...)),
}

// --- command-code: Mods SDK TS module + shell hooks ------------------------

var hookBindingsCommandCode = []HookBinding{
	hb(HookCapPromptGate, HookPhasePre, "transformInput", hgDoc(hookSrcCommandCodeMod),
		proc(ProcInProcessPID), host(hookCommandCodeModTimeoutS, HostFailureUnknown),
		reg(hookDialectCommandCode), wired(),
		dec(HookDecisionAllow, HookDecisionAsk, HookDecisionDeny, HookDecisionModify),
		note("Part B item 2, phase-3a - live-fetched 2026-09-07 (commandcode.ai/docs/mods): a Mods-SDK TypeScript module (cmd.hooks({transformInput({text}){...}})), not a shell hook - registered as ~/.commandcode/mods/observer-guard.ts (go:embed template, hermesplugin precedent) that shells out to `observer hook command-code transformInput`. The ONLY documented field is `text` - there is no session/conversation id anywhere in the signature, so an ask-once finding here fails closed to a HARD, unconditional block (no resend override) per the engine's own documented empty-session-id rule. REDACT wired (hook-parity Lane B, 2026-10-03): under [guard.prompt] mode redact a secret-only prompt is answered with {action:'transform',text} (masking needs no session key)")),
	hb(HookCapToolGate, HookPhasePre, "beforeToolCall", hgDoc(hookSrcCommandCodeMod), proc(ProcInProcessPID), dec(decDenyAskModify...),
		reg(hookDialectPluginShim), wired(),
		note("the same mod file (the one plugin shim, hook-parity Lane D): {block: true, additionalContext: <reason>} on a deny; the payload is {toolCallId, toolName, input, state}, no session id, and no ask field is documented, so an ask is a deny with a reason")),
	hb(HookCapToolGate, HookPhasePre, "PreToolUse", hgDoc(hookSrcCommandCode), proc(ProcDescendant), sess(), dec(decDenyContext...),
		dialectOnly(hookDialectClaudeJSONPreTool), host(hookCommandCodeShellTimeout, HostProceeds),
		note("the shell-hook layer (~/.commandcode/settings.json), separate from the Mods SDK: hookSpecificOutput.permissionDecision deny with permissionDecisionReason (reason reaches the model and the TUI); no ask. Never both gates: Observer's mod subscribes to the Mods beforeToolCall (the plugin shim, hook-parity Lane D), so the MOD is the gate of record and this shell entry is not written (and is removed if an earlier version wrote it; withCommandCodeShellGate). Windows: not stated by the vendor. Installed on demo node 1 (command-code 1.77.0, 2026-10-07) but not signed in (`cmd auth login`), so nothing fired: doc-grounded")),
	hb(HookCapSessionLifecycle, HookPhaseStart, "SessionStart", hgDoc(hookSrcCommandCode), proc(ProcDescendant), dec(decContext...)),
	hb(HookCapTurnLifecycle, HookPhaseEnd, "Stop", hgDoc(hookSrcCommandCode), proc(ProcDescendant), dec(decDeny...)),
	hb(HookCapModelCallObserve, HookPhasePost, "onTurnEnd", hgDoc(hookSrcCommandCodeMod), proc(ProcInProcessPID)),
}

// --- devin: Devin Desktop / Windsurf Cascade + Devin CLI -------------------

var (
	cascadeB  = cloneB(hookSrcCascade)
	devinCLIB = cloneB(hookSrcDevinCLI)
)

var hookBindingsDevin = []HookBinding{
	cascadeB(HookCapPromptGate, HookPhasePre, "pre_user_prompt", reg(hookDialectCascade), wired(),
		dec(HookDecisionAllow, HookDecisionDeny),
		note("Part B item 2, phase-3a - live-fetched 2026-09-07 (docs.devin.ai/desktop/cascade/hooks): Windsurf/Devin Desktop Cascade's pre_user_prompt, exit code 2 blocks, no JSON reply and no user-visible message channel at all (show_output does not apply to this event, so ask-once degrades to a hard block); no session_id field is documented either - trajectory_id (the conversation identifier) is used as the session-scoping key instead; registered at ~/.codeium/windsurf/hooks.json")),
	cascadeB(HookCapToolGate, HookPhasePre, "pre_run_command", reg(hookDialectCascadePreTool), wired(), host(0, HostProceeds), dec(decDeny...),
		note("Cascade: exit code 2 blocks and stderr (the reason after \"Blocked by Observer guard:\" on one first line, nothing else) is shown to the developer; no JSON reply, no ask, so an enforced ask is a deny that says how to confirm; any other exit lets the action proceed. The command is tool_info.command_line. Windows: the vendor runs `command` through PowerShell; Observer writes no Windows target for Cascade. Not installed on demo node 1: doc-grounded, `observer init` only")),
	cascadeB(HookCapToolGate, HookPhasePre, "pre_write_code", reg(hookDialectCascadePreTool), wired(), host(0, HostProceeds), dec(decDeny...),
		note("Cascade: judged as an edit of tool_info.file_path; exit 2 + stderr")),
	cascadeB(HookCapToolGate, HookPhasePre, "pre_read_code", reg(hookDialectCascadePreTool), wired(), host(0, HostProceeds), dec(decDeny...),
		note("Cascade: judged as a read of tool_info.file_path; exit 2 + stderr")),
	cascadeB(HookCapToolGate, HookPhasePre, "pre_mcp_tool_use", reg(hookDialectCascadePreTool), wired(), host(0, HostProceeds), dec(decDeny...),
		note("Cascade: judged as the MCP call mcp__<tool_info.mcp_server_name>__<tool_info.mcp_tool_name>; exit 2 + stderr")),
	devinCLIB(HookCapToolGate, HookPhasePre, "PreToolUse", reg(hookDialectClaudeJSONPreTool), wired(),
		host(hookDevinCLIRegisteredTimeout, HostProceeds), dec(decDenyModify...),
		liveAt(hookLiveDevinCLIToolGate, hookLiveDevinCLIToolGateDate),
		note("Devin CLI (T-478): Observer writes one Claude-shaped matcher group under \"hooks\" in the CLI's user config, ~/.config/devin/config.json (the devin folder under %APPDATA% on Windows), only when that directory exists (the CLI is installed); .devin/hooks.v1.json is project-only and never written. The reply is hookSpecificOutput.permissionDecision deny with permissionDecisionReason (Claude-shaped; the vendor also documents exit 2 and decision:block). The CLI can ALSO replay ~/.claude/settings.json (read_config_from.claude, default on), where Observer's Claude Code PreToolUse may be registered. Live on node 1 (devin 3000.11.3, 2026-10-07, after T-574): rm -rf ~/x was denied, the CLI reported \"Tool rejected\" with the rule reason and the fake target survived; ls ran; p95 deny 92 ms, allow 37 ms. Windows: not live-checked")),
	devinCLIB(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", dec(decContext...), dialectOnly(hookDialectDevinCLI),
		note("Devin CLI .devin/hooks.v1.json: input prompt + session_id; the only documented output is hookSpecificOutput.additionalContext (reaches the agent), no block, so the dialect warns the model and every finding toasts (hook-parity Lane B). No Observer writer yet. Node 1 (devin 3000.11.3, 2026-10-03): `devin -p` did NOT run Observer's Claude Code hooks from ~/.claude/settings.json (no hook-events rows; only post-hoc capture-lane flags)")),
	devinCLIB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart", dec(decContext...)),
	devinCLIB(HookCapSessionLifecycle, HookPhaseEnd, "SessionEnd"),
	devinCLIB(HookCapTurnLifecycle, HookPhaseEnd, "Stop", dec(decDeny...)),
	devinCLIB(HookCapCompactLifecycle, HookPhasePost, "PostCompaction"),
}

// --- kiro-cli / kiro-crew ---------------------------------------------------

var (
	kiroB     = cloneB(hookSrcKiro)
	kiroCrewB = func(c HookCap, phase, event string, opts ...hbOpt) HookBinding {
		return hb(c, phase, event, hgDoc(hookSrcKiroCrew), append([]hbOpt{proc(ProcDescendant)}, opts...)...)
	}
)

var hookBindingsKiroCLI = []HookBinding{
	kiroB(HookCapToolGate, HookPhasePre, "preToolUse", kiroResearch, reg(hookDialectKiroPreTool), wired(),
		host(hookKiroHostTimeout, HostProceeds), dec(decDeny...),
		adminCaveat("Gates only the agent in use: Observer installs its own default agent and merges into the developer's agents, but workspace agents are not covered."),
		note("exit code 2 blocks and the model gets \"PreToolHook blocked the tool execution: <stderr>\"; exit 1 runs the tool (stderr is only a TUI warning); no JSON decision, no ask, no modify, so an enforced ask is a deny that says how to confirm. Payload {hook_event_name, cwd, session_id, tool_name, tool_input}; tool names code, glob, goal, grep, introspect, knowledge, read (operations[].path), shell, subagent, todo_list, use_aws, write, and V3 MCP tools mcp_<server>_<tool>. "+
			"2.x hooks fire ONLY for the agent in use (--agent, else chat.defaultAgent in ~/.kiro/settings/cli.json, else the built-in kiro_default), so Observer writes its own agent ~/.kiro/agents/superbased-observer.json (tools [\"*\"], never allowedTools), sets chat.defaultAgent to it only when unset, merges the same entries (keyed on the command) into every other ~/.kiro/agents/*.json, and writes the V3 standalone ~/.kiro/hooks/superbased-observer.json that 2.28 does not read. Vendor semantics live-proven with probe hooks on demo node 1 (kiro-cli 2.28.0, KIRO_API_KEY=<fake> + KIRO_MOCK_CHAT_RESPONSE, offline); Observer's own writer has not had a live run, so `observer init` only. Workspace agents (<cwd>/.kiro/agents) are not merged. Windows: not stated")),
	kiroB(HookCapPromptGate, HookPhasePre, "userPromptSubmit", kiroResearch, reg(hookDialectKiroCLI), wired(), dec(decContext...),
		host(hookKiroHostTimeout, HostProceeds),
		adminCaveat("The hook cannot stop a prompt: the finding is added to the model's context and sent to the developer as a desktop notice."),
		note("WARN-ONLY (settled 2026-10-15): stdin {hook_event_name, cwd, session_id, prompt} and $USER_PROMPT; the hook CANNOT block (live: exit 1 and exit 2 both let the prompt through, matching kirodotdev/Kiro #11050 and the V3 docs), and an exit-0 stdout is added to the model's context only. The dialect replies with one plain-text line telling the model about a finding (never claiming a block) and an empty stdout otherwise; every finding is also recorded and toasted")),
	kiroB(HookCapSessionLifecycle, HookPhaseStart, "agentSpawn", dec(decContext...)),
	kiroB(HookCapTurnLifecycle, HookPhaseEnd, "stop"),
}

var hookBindingsKiroCrew = []HookBinding{
	kiroCrewB(HookCapToolGate, HookPhasePre, "PreToolUse", dec(decDeny...), note("shares .kiro/hooks/ with kiro-cli: a project hook may fire under both")),
	kiroCrewB(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", dec(decDeny...)),
	kiroCrewB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart"),
	kiroCrewB(HookCapTurnLifecycle, HookPhaseEnd, "Stop"),
}

// --- kimi-code: ~/.kimi-code/config.toml -----------------------------------

var kimiB = cloneB(hookSrcKimi)

var hookBindingsKimiCode = []HookBinding{
	kimiB(HookCapToolGate, HookPhasePre, "PreToolUse", reg(hookDialectKimiPreTool), wired(),
		host(hookKimiRegisteredTimeout, HostProceeds), dec(decDeny...), liveAt(hookLiveKimiGates, hookLiveKimiGatesDate),
		note("exit 2 blocks and its stderr is the reason the model sees; exit 0 allows and any stdout is added to the model context, so the allow is silence (the JSON hookSpecificOutput.permissionDecision deny is the vendor's other documented block). Other exit codes, a timeout or a crash allow (fail-open by the vendor). "+
			"T-378: registered as a [[hooks]] table {event, command, timeout = 30} in ~/.kimi-code/config.toml ($KIMI_CODE_HOME), a file that also holds plaintext provider keys, under the D-270 credential-file exception (only Observer's own tables are edited). No ask. Windows: implied by the vendor, shell not stated")),
	hb(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", hgSource(hookSrcKimiInstalled), sess(), proc(ProcDescendant),
		host(hookKimiRegisteredTimeout, HostProceeds), reg(hookDialectKimiCode), wired(), dec(decDenyContext...),
		liveAt(hookLiveKimiGates, hookLiveKimiGatesDate),
		note("dialect built from the installed 2.1.1 source (hook-parity Lane B) and live-captured (T-378): stdin {hook_event_name, session_id, cwd, client_type, prompt, is_steer} where prompt is the turn's content parts [{type: text, text}] (not a string); exit 2 blocks and its stderr is appended to the conversation as a <hook_result> message the developer sees; exit-0 stdout is appended to the model context, so the allow is an empty stdout; timeout or crash is an allow. "+
			"T-378: registered beside the PreToolUse gate in ~/.kimi-code/config.toml under the D-270 credential-file exception")),
	kimiB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart"),
	kimiB(HookCapSessionLifecycle, HookPhaseEnd, "SessionEnd"),
	kimiB(HookCapTurnLifecycle, HookPhaseEnd, "Stop", dec(decDeny...)),
	kimiB(HookCapSubagentLifecycle, HookPhaseStart, "SubagentStart"),
	kimiB(HookCapSubagentLifecycle, HookPhaseEnd, "SubagentStop"),
	hb(HookCapCompactLifecycle, HookPhasePre, "PreCompact", hgSource(hookSrcKimiInstalled), sess(), proc(ProcDescendant),
		dialectOnly(hookDialectKimiCode), note("routed to the one compaction recorder (hook-parity Lane E): input trigger, token_count; return value ignored")),
	hb(HookCapCompactLifecycle, HookPhasePost, "PostCompact", hgSource(hookSrcKimiInstalled), sess(), proc(ProcDescendant),
		dialectOnly(hookDialectKimiCode), note("routed to the one compaction recorder (hook-parity Lane E): input trigger, estimated_token_count; fire-and-forget")),
}

// --- grok: ~/.grok/hooks/*.json (also replays .claude / .cursor files) -----

var grokB = func(c HookCap, phase, event string, opts ...hbOpt) HookBinding {
	return hb(c, phase, event, hgDoc(hookSrcGrok), append([]hbOpt{sess(), proc(ProcDescendant), host(hookGrokHostTimeout, HostFailureUnknown)}, opts...)...)
}

// grokReplay marks a grok lifecycle binding Observer acts on WITHOUT writing
// a grok config: Grok Build runs ~/.claude/settings.json hooks, and the
// claude-code receiver dispatches a payload it identifies as Grok's
// (internal/hook foreignHostSignatures) to these bindings (Lane C3).
func grokReplay() hbOpt {
	return all(dialectOnly(hookDialectLifecycle), wired(), func(b *HookBinding) {
		laneCLive(hookLiveGrokReplay)(b)
		b.ReplayedVia = "claude-code"
		b.Note = "reached through the Claude Code settings replay (grok 1.0.46 runs ~/.claude/settings.json hooks), so only where Observer's Claude Code hooks are registered; dispatched by the claude-code receiver to the one lifecycle handler under tool grok"
	})
}

var hookBindingsGrok = []HookBinding{
	grokB(HookCapToolGate, HookPhasePre, "PreToolUse", liveAt(hookLiveGrokToolGate, hookLiveLaneADate), reg(hookDialectGrokPreTool), wired(),
		host(hookGrokRegisteredTimeout, HostProceeds), dec(decDenyModify...),
		note("top-level decision deny with reason, in ~/.grok/hooks/superbased-observer.json (always trusted); the deny reason reached the model live (grok 1.0.46, demo node 1). Ask is NOT listed: the vendor documents ask, but live an ask under --always-approve ran the command, so an enforced ask is a deny that says how to confirm. The allow {\"decision\":\"allow\"} only means not blocked (live, ls ran). Observer registers a 10 s timeout (the vendor default is 5 s); every hook failure fails open on the host side. Grok also replays ~/.claude/settings.json and ~/.cursor/hooks.json (audit section 4.4). Windows: not stated")),
	grokB(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", note("observe only: no block, no message, so no dialect row; prompt coverage is the proxy route (when routed) or the post-hoc capture lane (hook-parity Lane B)")),
	grokB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart", grokReplay()),
	grokB(HookCapSessionLifecycle, HookPhaseEnd, "SessionEnd", grokReplay()),
	grokB(HookCapTurnLifecycle, HookPhaseEnd, "Stop", grokReplay()),
	grokB(HookCapSubagentLifecycle, HookPhaseStart, "SubagentStart"),
	grokB(HookCapSubagentLifecycle, HookPhaseEnd, "SubagentStop"),
	grokB(HookCapCompactLifecycle, HookPhasePre, "PreCompact", dialectOnly(hookDialectTopLevelBlock),
		note("routed to the one compaction recorder (hook-parity Lane E); Grok reads Claude-shaped hook files, so the reply is the Claude-shaped approve (inferred). No Observer writer yet")),
	grokB(HookCapCompactLifecycle, HookPhasePost, "PostCompact", dialectOnly(hookDialectTopLevelBlock),
		note("routed to the one compaction recorder (hook-parity Lane E). No Observer writer yet")),
}

// --- goose / crush / mistral-code ------------------------------------------

var (
	gooseB = cloneB(hookSrcGoose)
	crushB = cloneB(hookSrcCrush)
	vibeB  = cloneB(hookSrcVibe)
)

var hookBindingsGoose = []HookBinding{
	gooseB(HookCapToolGate, HookPhasePre, "PreToolUse", hgLiveOpt(hookLiveGooseToolGate), reg(hookDialectGoosePreTool), wired(),
		host(hookGooseHostTimeout, HostProceeds), dec(decDeny...),
		adminCaveat("Code Mode scripts are judged as one command; the tool calls inside them bypass the gate."),
		note("{\"decision\":\"block\",\"reason\"} from Observer's Open Plugin (~/.agents/plugins/superbased-observer: plugin.json + hooks/hooks.json, no trust step); the model gets \"Tool call denied by policy hook\"; the allow is an empty stdout; no ask. The cwd is working_dir. Host default on_failure is allow (fail open), so under guard enforcement Observer writes \"on_failure\":\"block\" on its PreToolUse action (an Observer crash, timeout or unparseable reply then blocks; goose reads it on PreToolUse only). goose 1.53 resolves model-mangled names before the hook; the gate also folds developer__X / developer.X / functions.X onto X, judges Code Mode's execute_typescript script as one command (its inner tool calls bypass hooks) and reads any other <extension>__<tool> as the MCP call mcp__<extension>__<tool>. No sub-agent events. Windows: not stated (commands run through sh -c)")),
	gooseB(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", note("observe only: the vendor states hooks cannot inject, so no dialect row; prompt coverage is the proxy route (opt-in) or the post-hoc capture lane (hook-parity Lane B)")),
	gooseB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart"),
	gooseB(HookCapSessionLifecycle, HookPhaseEnd, "SessionEnd"),
	gooseB(HookCapTurnLifecycle, HookPhaseEnd, "Stop", dec(decDeny...)),
}

var hookBindingsCrush = []HookBinding{
	crushB(HookCapToolGate, HookPhasePre, "PreToolUse", reg(hookDialectCrushPreTool), wired(),
		host(hookCrushHostTimeout, HostProceeds), dec(HookDecisionDeny, HookDecisionModify, HookDecisionContext),
		adminCaveat("Main agent only: sub-agents bypass hooks by design."),
		note("the ONE crush.json hook event (global ~/.config/crush/crush.json): {\"decision\":\"deny\",\"reason\"}; the allow is an empty object because decision:allow would skip Crush's permission prompt; exit 49 halts the whole turn (never used); no ask; sub-agents bypass hooks by design (main agent only). Timeouts and other exits fail open. Windows: yes (embedded POSIX shell). Tool names include web_fetch, web_search, agentic_fetch, job_output, job_kill, and MCP tools as mcp_<server>_<tool> (one underscore), which the gate reads as mcp__<server>__<tool> (split at the first underscore after the prefix: a server name holding an underscore is ambiguous). Installed on demo node 1 (crush v0.97.1, 2026-10-07); a run needs a provider: there is no base-URL ENV knob, but a provider's base_url in crush.json (providers.<id>.base_url) routes it (a config-file proxy route Observer does not write yet). Vendor research 2026-10-15 (0.97.1 and 0.98.1): the hook loads from ~/.config/crush/crush.json, ~/.local/share/crush/crush.json and a project .crush.json; UserPromptSubmit does not exist (a configured one never fires). Observer's own writer has not had a live run: doc-grounded, `observer init` only")),
}

var hookBindingsMistralCode = []HookBinding{
	vibeB(HookCapToolGate, HookPhasePre, "pre_tool", reg(hookDialectVibePreTool), wired(),
		host(hookVibeRegisteredTimeout, HostProceeds), dec(HookDecisionDeny, HookDecisionModify, HookDecisionMessage),
		note("JSON decision only ({\"decision\":\"deny\",\"reason\"}, the reason becomes the tool error the model sees): exit 2 is NOT a block, it is a hook failure (a warning unless strict = true). Registered in ~/.vibe/hooks.toml with match \"*\", strict false and a 30 s timeout; no ask. Windows: not stated")),
	vibeB(HookCapToolObserve, HookPhasePost, "post_tool"),
	vibeB(HookCapTurnLifecycle, HookPhaseEnd, "post_agent", dec(decDeny...)),
}

// --- antigravity-cli / antigravity (agy hooks.json) ------------------------

var agyB = func(c HookCap, phase, event string, opts ...hbOpt) HookBinding {
	return hb(c, phase, event, hgDoc(hookSrcAntigravity), append([]hbOpt{sess(), proc(ProcDescendant)}, opts...)...)
}

var hookBindingsAntigravityCLI = []HookBinding{
	agyB(HookCapPromptGate, HookPhasePre, "PreInvocation", reg(hookDialectAgyPreInvoke), wired(),
		liveAt(hookLiveAgyGuardFix, hookLiveAgyGuardFixDate),
		host(hookAgyToolGateTimeout, HostProceeds),
		dec(HookDecisionAllow, HookDecisionDeny, HookDecisionContext, HookDecisionMessage),
		adminCaveat("Runs before each model call, not on send: agy's title request has already carried the prompt, and after a stop the conversation stays stopped until the developer starts a new one."),
		note("PRE-MODEL-CALL gate, not pre-send: the stdin carries no prompt text, so the receiver reads the latest USER_INPUT step from the transcriptPath file (transcript.jsonl on agy 1.2.16, transcript_full.jsonl on 1.3.x) and judges each prompt once. A flag replies injectSteps with a userMessage the developer sees in the TUI as a \"> SuperBased Observer: ...\" line (it also becomes a user turn) plus an ephemeralMessage for the model. A block (deny, and an ask: the abort is atomic, so no confirm or resend-to-confirm can ride it) replies {\"injectSteps\":[{}]}, which aborts the turn before the main model request on agy 1.3.5 through an UNDOCUMENTED error path (\"unknown injected step type\"; -p exits 3, the TUI shows a warning and the session survives); no message can accompany it, so the reason is the desktop toast. The abort is offered only when the hook's agy ancestor reports a version >= 1.3.5; otherwise the block degrades to the warning (recorded as a degrade). agy's title-generation request carrying the prompt is sent BEFORE any hook (only the proxy can stop it), and the stopped prompt stays in the conversation and is resent with every later turn, so the conversation is TAINTED: every later PreInvocation of it aborts and toasts \"start a new conversation\" (read from the first stop's guard_events row). Any bad output (exit code, invalid JSON, unknown key, timeout) fails OPEN; an empty object is the allow. On agy 1.2.16 (2026-10-03) the transcript held the prompt only after the reply, so the seam could not act; an older agy degrades to {}")),
	agyB(HookCapToolGate, HookPhasePre, "PreToolUse", liveAt(hookLiveAgyGuardFix, hookLiveAgyGuardFixDate), reg(hookDialectAgyPreTool), wired(),
		host(hookAgyToolGateTimeout, HostBlocks), dec(HookDecisionDeny, HookDecisionAsk, HookDecisionModify),
		adminCaveat("The ask reaches the developer only in an interactive agy, not in the desktop app, the IDE, a headless run or under --dangerously-skip-permissions."),
		note("top-level decision deny with reason (the model reads \"tool call denied by pre-tool hook: <reason>\"). An ask is force_ask with the reason: agy's NATIVE prompt with a \"Reason:\" line in the TUI (agy 1.3.5), sent only when the hook's ancestor is an interactive agy; under --dangerously-skip-permissions force_ask RUNS the tool and under headless -p it auto-denies silently, so there (and whenever no agy ancestor can be read: the desktop app, the IDE, an OS without /proc) an enforced ask is a deny that says how to confirm. Plain ask (respects default grants) and auto_approve (skips the developer's prompt) are never sent. The allow is an EMPTY stdout, which falls through to agy's own permission flow; decision:allow defers to policy. FAIL-CLOSED host: {}, exit 1/2, invalid JSON and a timeout all DENY (Observer registers a 30 s timeout and its own watchdog fires before it). No developer-visible warn field on the allow, so a flag is recorded and stays silent. camelCase payload: toolCall.{name,args} (args keys PascalCase, e.g. CommandLine), conversationId, workspacePaths; no cwd. The desktop app and the IDE read the same ~/.gemini/config/hooks.json; their payloads (transcriptPath under ~/.gemini/antigravity or ~/.gemini/antigravity-ide) are served and recorded under the antigravity row (surface-gap W-2c). Windows: the vendor runs hooks through cmd /c; Observer writes no Windows target")),
	agyB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart", liveAt(hookLiveAgyGuardFix, hookLiveAgyGuardFixDate),
		note("vendor event seen live on agy 1.3.5 (2026-10-15); not registered: no Observer feature acts on it yet")),
	agyB(HookCapToolObserve, HookPhasePost, "PostToolUse"),
	agyB(HookCapModelCallObserve, HookPhasePost, "PostInvocation"),
	agyB(HookCapTurnLifecycle, HookPhaseEnd, "Stop"),
}

// hookSrcAntigravityIDE is the vendor page that says the Antigravity App and
// IDE read the agy hooks.json and names each surface's app_data_dir, the
// directory every hook payload's transcriptPath lies under (surface-gap W-2c).
const (
	hookSrcAntigravityIDE     = "https://antigravity.google/docs/hooks?tab=ide"
	hookSrcAntigravityIDEDate = "2026-10-26"
	// replayAntigravityCLI is the antigravity-cli registry id (this package
	// imports nothing project-internal; replayClaudeCode's precedent).
	replayAntigravityCLI = "antigravity-cli"
)

// agyAppIDEReplay marks an antigravity gate reached through the
// antigravity-cli registration: the App and the IDE run the hooks of
// ~/.gemini/config/hooks.json, and the antigravity-cli receiver serves a
// payload whose transcriptPath lies under their app_data_dir as this row's
// call (internal/hook SurfaceTool, cmd/observer hookSurfaceBinding).
func agyAppIDEReplay() hbOpt {
	return all(wired(), replayedVia(replayAntigravityCLI), func(b *HookBinding) {
		b.Grounding = hgSourceAt(hookSrcAntigravityIDE, hookSrcAntigravityIDEDate)
	})
}

var hookBindingsAntigravity = []HookBinding{
	agyB(HookCapToolGate, HookPhasePre, "PreToolUse", dialectOnly(hookDialectAgyPreTool), agyAppIDEReplay(),
		host(hookAgyToolGateTimeout, HostBlocks), dec(HookDecisionDeny, HookDecisionAsk, HookDecisionModify),
		adminCaveat("Runs through the Antigravity CLI's hook registration, and the ask never reaches the developer here: in the App and the IDE an enforced ask is a deny that says how to confirm."),
		note("the Antigravity App and IDE read the agy ~/.gemini/config/hooks.json, so the antigravity-cli registration (`observer hook antigravity-cli PreToolUse`) gates them too. A payload whose transcriptPath lies under ~/.gemini/antigravity or ~/.gemini/antigravity-ide (the vendor's app_data_dir for the App and the IDE) is served, recorded and counted under antigravity, in the agy dialect; ~/.gemini/antigravity-cli stays the CLI's. No agy ancestor runs these hooks, so an ask is a deny. Not live-checked on either surface (pending tracker LCX-5)")),
	agyB(HookCapPromptGate, HookPhasePre, "PreInvocation", dialectOnly(hookDialectAgyPreInvoke), agyAppIDEReplay(),
		host(hookAgyToolGateTimeout, HostProceeds),
		dec(HookDecisionAllow, HookDecisionDeny, HookDecisionContext, HookDecisionMessage),
		adminCaveat("Runs through the Antigravity CLI's hook registration, before each model call; the turn abort is offered only to a proven agy build, so in the App and the IDE a stop is a warning."),
		note("reached through the antigravity-cli registration like PreToolUse and judged under antigravity from the transcript the payload names. The {\"injectSteps\":[{}]} abort is offered only when an agy ancestor reports >= 1.3.5, which the App and the IDE never are, so a stop degrades to the injected warning (recorded as a degrade). Not live-checked (pending tracker LCX-5)")),
	agyB(HookCapTurnLifecycle, HookPhaseEnd, "Stop"),
}

// --- open-interpreter (Codex-shaped, own home) ------------------------------

var oiB = cloneB(hookSrcOpenInterp)

var hookBindingsOpenInterpreter = []HookBinding{
	oiB(HookCapToolGate, HookPhasePre, "PreToolUse", reg(hookDialectClaudeJSONPreTool), wired(), host(0, HostProceeds), dec(decDenyModify...),
		note("Codex shape under its OWN home: ~/.openinterpreter/hooks.json, hookSpecificOutput.permissionDecision deny. Ask is not listed (the vendor does not state it and Codex itself rejects ask). Per-definition trust like Codex: the entry runs only after the developer reviews it with /hooks, and [features] hooks = true must be set in ~/.openinterpreter/config.toml, which Observer never reads or rewrites (it can hold plaintext provider keys). Windows: not stated. Installed on demo node 1 (open-interpreter 0.0.56, 2026-10-07) and run against a loopback mock: the hooks.json Observer wrote did not fire, even with --enable hooks, because the entry was never trusted in /hooks (a TTY step); the vendor's own exec policy refused rm -rf on its own: doc-grounded, `observer init` only")),
	oiB(HookCapPromptGate, HookPhasePre, "UserPromptSubmit",
		note("probe_required - open-interpreter is a rebadged Codex CLI Rust build (codex.NewOpenInterpreter retag); it plausibly inherits Codex's UserPromptSubmit hook under INTERPRETER_HOME, unconfirmed")),
	oiB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart", dec(decContext...)),
	oiB(HookCapTurnLifecycle, HookPhaseEnd, "Stop"),
	oiB(HookCapSubagentLifecycle, HookPhaseStart, "SubagentStart"),
	oiB(HookCapSubagentLifecycle, HookPhaseEnd, "SubagentStop"),
	oiB(HookCapCompactLifecycle, HookPhasePre, "PreCompact"),
	oiB(HookCapCompactLifecycle, HookPhasePost, "PostCompact"),
}

// --- muse (payload schema unpublished: inferred) ---------------------------

var museB = func(c HookCap, phase, event string, opts ...hbOpt) HookBinding {
	return hb(c, phase, event, hgInferred(hookSrcMuse), append([]hbOpt{proc(ProcDescendant)}, opts...)...)
}

// hookLiveMuse is the T-479 live capture (lane LIVE-GROUND-2, 2026-10-06):
// muse-bin 1.4.3 `muse exec` on demo node 1 with a throwaway HOME and XDG
// dirs, provider "meta" pointed at a loopback mock with a fake key (no Meta
// sign-in; auth.json never read). PreToolUse stdin: {cwd, hook_event_name,
// model, model_provider, permission_mode, session_id, tool_input{command,
// description, workdir}, tool_name, tool_use_id, transcript_path (null),
// turn_id}; a hookSpecificOutput.permissionDecision deny reached the model
// as "tool blocked by hook: <reason>". UserPromptSubmit stdin adds prompt;
// {"decision":"block"} and exit 2 both cancelled the run with no model
// request.
const (
	hookLiveMuse     = "hook-parity live-ground 2026-10-06 (T-479): muse-bin 1.4.3 exec on demo node 1, throwaway HOME and XDG dirs, loopback mock model, hooks written by observer init (U-901 deny reached the model, a ghp_ prompt was cancelled with no model request)"
	hookLiveMuseDate = "2026-10-06"
)

var hookBindingsMuse = []HookBinding{
	museB(HookCapToolGate, HookPhasePre, "PreToolUse", reg(hookDialectClaudeJSONPreTool), wired(), liveAt(hookLiveMuse, hookLiveMuseDate),
		host(hookMuseRegisteredTimeout, HostFailureUnknown), dec(decDenyModify...),
		note("Observer writes one Claude-shaped matcher group under \"hooks\" in ~/.config/muse/settings.json (and ensures \"schema_version\": 1); the reply is hookSpecificOutput.permissionDecision deny with permissionDecisionReason, which reached the model live as \"tool blocked by hook: <reason>\". Ask is not listed (not probed headless). Muse's own approval reviewer runs separately and can still refuse a call the hook allowed. Plugin bundles (.muse-plugin, argv commands) are the other hook source; Observer writes none. No Windows build exists")),
	museB(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", reg(hookDialectTopLevelBlock), wired(), liveAt(hookLiveMuse, hookLiveMuseDate),
		host(hookMuseRegisteredTimeout, HostFailureUnknown), dec(HookDecisionAllow, HookDecisionDeny),
		note("the top-level-block dialect (decision block with a reason): live, the run ended \"Cancelled\" before any model request (exit 2 did the same); muse exec printed no reason, so the developer-visible message is unproven and an enforced ask is a block")),
	museB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart"),
	museB(HookCapSessionLifecycle, HookPhaseEnd, "SessionEnd"),
	museB(HookCapTurnLifecycle, HookPhaseEnd, "Stop"),
	museB(HookCapSubagentLifecycle, HookPhaseStart, "SubagentStart"),
	museB(HookCapSubagentLifecycle, HookPhaseEnd, "SubagentStop"),
	museB(HookCapCompactLifecycle, HookPhasePre, "PreCompact"),
	museB(HookCapCompactLifecycle, HookPhasePost, "PostCompact"),
}

// --- junie (CLI hooks only; not in ACP/IDE mode) ---------------------------

var junieB = cloneB(hookSrcJunie)

var hookBindingsJunie = []HookBinding{
	junieB(HookCapToolGate, HookPhasePre, "PreToolUse", reg(hookDialectJuniePreTool), wired(),
		host(hookJunieRegisteredTimeout, HostProceeds), dec(HookDecisionDeny, HookDecisionAsk, HookDecisionModify, HookDecisionContext),
		// W-5: the "CLI only" caveat is the ide row of hookSurfaces
		// (hooksurface.go), rendered by HookSpec.SurfaceCaveat.
		note("CLI only: hooks do not run in ACP/IDE mode. Top-level decision deny|ask with reason in ~/.junie/config.json \"hooks\" (the reason reaches the model as an error); Observer registers a 10 s timeout because the PreToolUse default is 2 s; a timeout or crash lets the tool continue. Windows: yes (cmd /c). Installed on demo node 1 (junie 3579.5, 2026-10-07) but it needs a JetBrains account or JUNIE_API_KEY, and it refuses to start with HOME pointed at a throwaway dir: doc-grounded, `observer init` only")),
	junieB(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", dec(decDenyContext...)),
	junieB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart", dec(decMessage...)),
	junieB(HookCapSessionLifecycle, HookPhaseEnd, "SessionEnd"),
	junieB(HookCapTurnLifecycle, HookPhaseEnd, "Stop", dec(decDeny...)),
}

// --- deepseek (in-process Cordis plugins; field names inferred) -------------

var deepseekB = func(c HookCap, phase, event string, opts ...hbOpt) HookBinding {
	return hb(c, phase, event, hgDoc(hookSrcDeepSeek), append([]hbOpt{proc(ProcInProcessPID)}, opts...)...)
}

var hookBindingsDeepSeek = []HookBinding{
	deepseekB(HookCapToolGate, HookPhasePre, "tools/pre-execute", dec(decDenyAsk...), pluginShimRendered,
		note("in-process TS (Cordis) plugin; payload field names inferred. The plugin shim renders {kind: \"deny\"} / next(), but no user plugin directory is documented (profile layers, cordis.patch.yml), so Observer does not register it")),
	deepseekB(HookCapSessionLifecycle, HookPhaseStart, "agent/created"),
	deepseekB(HookCapTurnLifecycle, HookPhaseEnd, "agent/turn-stopping"),
	deepseekB(HookCapModelCallObserve, HookPhasePre, "agent/pre-step"),
	deepseekB(HookCapToolGate, HookPhasePre, "PreToolUse", deepseekClaudeReplay(), dialectOnly(hookDialectClaudeWirePreTool),
		host(0, HostFailureUnknown), dec(HookDecisionDeny, HookDecisionAsk),
		adminCaveat("Only where the experimental dsh-hooks-claude-code plugin is configured with a configPath to the Claude Code settings file that holds Observer's hooks."),
		note("reached through Observer's Claude Code hooks: DeepSeek Harness's experimental @deepseek-ai/dsh-hooks-claude-code plugin (tools/pre-execute) runs the hooks of the Claude settings file its configPath names, with session_id (the agent session header id), transcript_path always \"\" and tool_name verbatim from the harness (bash, pwsh, edit); the claude-code receiver recognises the empty transcript path and gates the call as deepseek, DeepSeek's vocabulary first. The plugin honours a deny and an ask; allow does not pre-approve. Vendor source only (0.2.1-rc.3 lib/index.js and README), not live-run (pending tracker LCX-4)")),
	deepseekB(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", deepseekClaudeReplay(), dialectOnly(hookDialectClaudeCode),
		host(0, HostFailureUnknown), dec(HookDecisionDeny, HookDecisionContext),
		adminCaveat("Only where the experimental dsh-hooks-claude-code plugin is configured with a configPath to the Claude Code settings file that holds Observer's hooks."),
		note("reached through Observer's Claude Code hooks like PreToolUse (agent/pre-step): the prompt is the text blocks of the step's messages; a deny rejects the step (the prompt is discarded) and additionalContext reaches the model; judged as deepseek. Vendor source only, not live-run (pending tracker LCX-4)")),
}

// hookSrcDeepSeekClaudeBridge is the vendor source of DeepSeek Harness's
// Claude Code hook bridge (surface-gap S-20).
const (
	hookSrcDeepSeekClaudeBridge     = "@deepseek-ai/dsh-hooks-claude-code 0.2.1-rc.3 lib/index.js and README.md (unpkg)"
	hookSrcDeepSeekClaudeBridgeDate = "2026-10-26"
)

// deepseekClaudeReplay marks a deepseek gate reached through Observer's
// Claude Code registration (the dsh-hooks-claude-code bridge spawns the hook
// command, so it is a descendant of the harness process).
func deepseekClaudeReplay() hbOpt {
	return all(wired(), replayedVia(replayClaudeCode), sess(), proc(ProcDescendant), func(b *HookBinding) {
		b.Grounding = hgSourceAt(hookSrcDeepSeekClaudeBridge, hookSrcDeepSeekClaudeBridgeDate)
	})
}

// --- copilot-cli / copilot (VS Code agent hooks) ----------------------------

var (
	copilotCLIB = cloneB(hookSrcCopilotCLI)
	vscodeB     = cloneB(hookSrcVSCode)
)

// copilot 1.0.91 live record (T-325): a deny reached the model as "Denied by
// preToolUse hook: <reason>" and the fake target survived; {} let ls run; an
// ask was refused headless as "unable to ask user for confirmation".
const (
	hookLiveCopilotCLIToolGate     = "hook-parity live-ground 2026-10-06 (T-325): copilot 1.0.91 -p on demo node 1, BYOK offline mode against a loopback mock, throwaway HOME, hooks written by observer init"
	hookLiveCopilotCLIToolGateDate = "2026-10-06"
)

var hookBindingsCopilotCLI = []HookBinding{
	copilotCLIB(HookCapToolGate, HookPhasePre, "preToolUse", reg(hookDialectCopilotPreTool), wired(),
		liveAt(hookLiveCopilotCLIToolGate, hookLiveCopilotCLIToolGateDate),
		dec(decDenyAskModify...), host(hookCopilotCLIHostTimeout, HostBlocks),
		adminCaveat("A headless run (copilot -p) refuses an ask, so the call does not run."),
		note("top-level permissionDecision deny|ask with permissionDecisionReason, in ~/.copilot/hooks/superbased-observer.json (version 1, the command in \"bash\"); toolArgs may arrive as a JSON-encoded string and is decoded. The allow is an empty object because permissionDecision:allow skips Copilot's own prompt. A crash or non-zero exit DENIES on the host side (a timeout fails open). A deny-not-blocking report exists (github/copilot-cli #3874, closed); camelCase and PascalCase event names are both accepted. Windows: Copilot runs the handler's powershell field there, so a Windows target (a native observer.exe, or the copilot-cli-windows wsl.exe bridge) also carries one. Live check 12 (2026-10-26): VS Code 1.143.1's Copilot Chat local agent IS this runtime (Copilot CLI 1.0.100-1, the session in ~/.copilot/session-state) and runs this file too, so the gate covers it; its hook environment carries COPILOT_CLI and COPILOT_HOOK_DIR and no VS Code variable, so its verdicts land under copilot-cli without an ide/vscode stamp (an agent-host.db surface enricher is a follow-up). Live 2026-10-28 (Windows demo node, managed enforce, WINNODE2 item 10): VS Code Copilot Chat agent mode's file and shell tool calls were stopped by this gate (an R-153 .env read, and every call under a B-602 budget stop); the guard reason reached the chat, the budget stop read as a pre-tool hook error. GitHub's hooks reference: exit 0 with permissionDecision/permissionDecisionReason shows the reason, exit 2 denies without it, any other non-zero exit is \"hook errored\". So this dialect writes nothing on stderr and the powershell command ends with `; if ($LASTEXITCODE -is [int]) { exit $LASTEXITCODE } else { exit 1 }` (observer's exit code, and 1 when observer.exe never ran, so a missing binary still denies); the reason reaching VS Code is owed a live check")),
	copilotCLIB(HookCapPromptGate, HookPhasePre, "userPromptSubmitted", reg(hookDialectCopilotPrompt), wired(), sess(),
		liveAt(hookLiveCopilotCLIPrompt, hookLiveGuardFixBDate),
		dec(HookDecisionAllow, HookDecisionDeny, HookDecisionAsk, HookDecisionModify, HookDecisionContext),
		host(hookCopilotCLIHostTimeout, HostProceeds),
		adminCaveat("A block's reason is printed as the assistant's reply; no request reaches the model."),
		note("live 2026-10-15 (copilot 1.0.96), superseding the hooks-reference page's \"command hooks have their output dropped\": a block is {handled:true, responseContent:<reason>, modifiedPrompt:<marker>} (zero model requests, the reason printed as the assistant reply; modifiedPrompt is required because a handled prompt otherwise stays in the session history and reaches the model on the next turn), a resend in the same session confirms an ask, a redact is modifiedPrompt (the request and the history carry the masked text), a warning is additionalContext (the model only, so a flag also toasts). Exit code 2 does not block; a timeout fails open. Registered in ~/.copilot/hooks/superbased-observer.json beside preToolUse")),
	// The Copilot CLI runtime's Claude-compatible PreToolUse (live check 12,
	// 2026-10-26) reaching Observer's Claude Code hooks: a fallback the
	// claude-code receiver serves under copilot-cli only while Observer's
	// own preToolUse registration above is absent (internal/hook
	// foreignhost.go; surface-gap Wave 5 audit finding 2, G2). While it is
	// present the replay answers neutral and the registered gate judges.
	copilotCLIB(HookCapToolGate, HookPhasePre, "PreToolUse", dialectOnly(hookDialectClaudeWirePreTool), wired(), replayedVia(replayClaudeCode), standsInFor("preToolUse"), sess(),
		host(hookCopilotCLIHostTimeout, HostFailureUnknown), dec(HookDecisionDeny, HookDecisionAsk),
		note("reached through Observer's Claude Code hooks: the Copilot CLI runtime (the standalone CLI and VS Code's local agent) runs a repository's .claude/settings(.local).json hooks (surface-gap S-8) with a Claude-compatible payload: hook_event_name PreToolUse, session_id (the Copilot CLI session id), cwd, tool_name in Claude's vocabulary (Read for view) and tool_input, NO transcript_path, and COPILOT_CLI plus COPILOT_HOOK_DIR in the hook environment (live check 12, VS Code 1.143.1, Copilot CLI 1.0.100-1). The claude-code receiver answers it neutral while Observer's copilot-cli registration holds the preToolUse entry, and otherwise gates it as copilot-cli with the Claude JSON deny, Copilot's vocabulary first. The payload is live-captured; a deny on this path is not yet live-run")),
	copilotCLIB(HookCapSessionLifecycle, HookPhaseStart, "sessionStart", dec(decContext...)),
	copilotCLIB(HookCapSessionLifecycle, HookPhaseEnd, "sessionEnd"),
	copilotCLIB(HookCapTurnLifecycle, HookPhaseEnd, "agentStop", dec(decDeny...)),
	copilotCLIB(HookCapSubagentLifecycle, HookPhaseStart, "subagentStart", dec(decContext...)),
	copilotCLIB(HookCapSubagentLifecycle, HookPhaseEnd, "subagentStop", dec(decDeny...)),
	copilotCLIB(HookCapCompactLifecycle, HookPhasePre, "preCompact"),
}

var hookBindingsCopilot = []HookBinding{
	vscodeB(HookCapToolGate, HookPhasePre, "PreToolUse", dec(decDenyAskModify...),
		note("VS Code agent hooks (Preview, chat.useHooks on by default). Live check 12 (VS Code 1.143.1, 2026-10-26): the Copilot Chat LOCAL agent is the Copilot CLI runtime, reads ~/.copilot/hooks/*.json (Observer's copilot-cli registration gates it, verdicts under copilot-cli) and fires a PascalCase entry with a Claude-compatible payload (no transcript_path) beside the camelCase one; a Claude-shaped payload from that runtime reaching Observer's Claude Code hooks is answered neutral while Observer's copilot-cli registration holds the gate, and otherwise gated as copilot-cli (internal/hook foreignhost.go). Whether VS Code also runs ~/.claude/settings.json hooks (chat.useClaudeHooks) is untested (live check 12b)")),
	vscodeB(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", dec(decContext...), note("context only; block unstated")),
	vscodeB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart", dec(decContext...)),
	vscodeB(HookCapTurnLifecycle, HookPhaseEnd, "Stop"),
	vscodeB(HookCapSubagentLifecycle, HookPhaseStart, "SubagentStart"),
	vscodeB(HookCapSubagentLifecycle, HookPhaseEnd, "SubagentStop"),
	vscodeB(HookCapCompactLifecycle, HookPhasePre, "PreCompact"),
}

// --- cline / cline-cli (shared SDK hook runtime) ---------------------------

var clineB = cloneB(hookSrcCline)

// hookNoteClineGate is the shared vendor fact about the SDK hook runtime's
// PreToolUse file, stated once for both rows that see it.
const hookNoteClineGate = "file-per-event executables: the SDK hook runtime reads ~/.cline/hooks/PreToolUse. A file-hook block is {\"cancel\":true,\"errorMessage\"}, which STOPS THE RUN (a file hook has no per-call deny); exit codes are ignored; the allow is an empty stdout; no ask from a file hook (review has no effect). Timeout 120 s, fail open. The Cline Plugin API's beforeTool does have a per-call deny and a native ask (the cline-cli row's beforeTool gate). macOS/Linux only (Windows .ps1 detached hooks broken, cline/cline #14767): Observer writes no Windows target"

var hookBindingsCline = []HookBinding{
	// T-342 (2026-10-04): the registration moved to the cline-cli row, the
	// surface live-verified to read ~/.cline/hooks. The VS Code
	// extension's scan set on cline/cline main does not include it (source,
	// 2026-10-25; a shipped build is live check 26), so this row keeps the
	// vendor surface only.
	clineB(HookCapToolGate, HookPhasePre, "PreToolUse", host(hookClineHostTimeout, HostProceeds), dec(decDenyModify...),
		note("vendor doc only: the extension shares the SDK hook runtime, but its getAllHooksDirs on cline/cline main (source, 2026-10-25) scans --hooks-dir, <Documents>/Cline/Hooks and <ws>/.clinerules/hooks, not ~/.cline/hooks (a shipped build is live check 26), so Observer registers this gate on the cline-cli row and records its verdicts under cline-cli. "+hookNoteClineGate)),
	clineB(HookCapPromptGate, HookPhasePre, "UserPromptSubmit",
		note("probe_required: the installed cline 3.0.68 SDK (demo node 1, 2026-10-03) runs prompt_submit hooks DETACHED (detached: detachAsyncHooks ?? true), with payload {hookName:\"prompt_submit\", userPromptSubmit:{prompt, attachments}}; live on Cline CLI 3.0.68 (2026-10-15) the file hook never fired for the initial prompt at all, and TaskStart is detached too. A cancel reply cannot stop the prompt there, so no dialect row (the VS Code extension's detach setting is unconfirmed). The Cline CLI's prompt gate is the Plugin API's beforeModel (the cline-cli row)")),
	clineB(HookCapSessionLifecycle, HookPhaseStart, "TaskStart"),
	clineB(HookCapSessionLifecycle, HookPhaseStart, "TaskResume"),
	clineB(HookCapSessionLifecycle, HookPhaseEnd, "SessionShutdown"),
	clineB(HookCapTurnLifecycle, HookPhaseEnd, "TaskComplete"),
	clineB(HookCapTurnLifecycle, HookPhaseEnd, "TaskError"),
	clineB(HookCapTurnLifecycle, HookPhaseEnd, "TaskCancel"),
	clineB(HookCapCompactLifecycle, HookPhasePre, "PreCompact", note("never fires")),
}

// cline-cli: Observer writes the SDK runtime's ~/.cline/hooks/PreToolUse
// (the tool gate, T-342) and TAILS its hooks.jsonl (the lifecycle and tool
// result rows below, served by the clinecli adapter, not by `observer hook`).
var clineCLITailB = func(c HookCap, phase, event string, opts ...hbOpt) HookBinding {
	return hb(c, phase, event, hgFixture("testdata/clinecli (hooks.jsonl tailer, internal/adapter/clinecli/hook.go)"),
		append([]hbOpt{sess(), dialectOnly(hookDialectClineCLITail), wired()}, opts...)...)
}

var hookBindingsClineCLI = []HookBinding{
	// T-342 / D-230: the live grounding of fix/live-ground-2026-10-04
	// (e951c73e0, 32c46db65, 0764620f2) was taken with Cline CLI 3.0.68, so it
	// sits on this row; the extension's cline row stays vendor doc.
	// Guard-fix lane B (2026-10-15): the gate moved to the Plugin API. The
	// plugin (internal/hook/pluginshim "cline" shape) is placed at
	// $CLINE_DIR/plugins/superbased-observer-guard.js (default
	// ~/.cline/plugins) and calls `observer hook cline-cli beforeModel|
	// beforeTool` with its own deadline (no timeout wraps a plugin hook).
	clineB(HookCapPromptGate, HookPhasePre, "beforeModel", reg(hookDialectClinePluginPrompt), wired(), sess(),
		liveAt(hookLiveClinePlugin, hookLiveGuardFixBDate),
		dec(HookDecisionAllow, HookDecisionDeny, HookDecisionModify),
		adminCaveat("Through Observer's Cline plugin (macOS and Linux only); Cline shows no stop reason, so the desktop notice carries it."),
		note("Cline Plugin API beforeModel, before EVERY model call; the plugin judges each user message once (setup ctx.session.sessionId keys it). A deny is {stop:true, reason} (zero model requests; the reason is shown nowhere, so an ask is a block and a flag is recorded and toasted); a redact returns {messages} with the masked text. A returned {messages} lasts one request and a stopped message stays in the history, so the plugin re-applies every withhold and redaction on every later call. macOS/Linux only (the plugin sandbox is untested on Windows)")),
	clineB(HookCapToolGate, HookPhasePre, "beforeTool", reg(hookDialectClinePluginTool), wired(), sess(),
		liveAt(hookLiveClinePlugin, hookLiveGuardFixBDate),
		dec(decDenyAsk...),
		adminCaveat("Through Observer's Cline plugin; an ask is Cline's own y/N approval in a terminal, and a headless run refuses it."),
		note("Cline Plugin API beforeTool: a deny is {skip:true, reason}, a per-call refusal the run survives (the model gets the reason, the CLI prints error: {\"error\":<reason>}); an ask is {policy:{autoApprove:false}}, Cline's own y/N approval under a TTY (refused headless: \"requires approval in a TTY session\"). Tools arrive in the CLI vocabulary (run_commands, read_files, editor, apply_patch). Input rewriting ({input}) exists in the API but Observer's tool gate issues no modify verdict here")),
	// The file gate (FU-154): Cline CLI 3.0.3 runs hook files named after
	// the event from ~/.cline/hooks (and ~/Documents/Cline/Hooks,
	// .clinerules/hooks, .cline/hooks), reads the verdict from the hook's
	// stdout and never loads plugins, so the plugin above never runs there.
	// Observer writes ~/.cline/hooks/PreToolUse as a script that execs
	// `observer hook cline-cli PreToolUse` (live PASS on MAC-6, 2026-10-30,
	// with a verdict file in this shape). On a Cline that also loads the
	// plugin a call is judged by both.
	// The runtime's fixed 120 s file-hook timeout (hookNoteClineGate) is
	// not a HostTimeout here: Observer writes no timeout into the file, and
	// the one config the cline-cli writer also writes (the plugin) carries
	// the shim's own deadlines (TestRegistrationWritersWriteTheHostTimeout).
	clineB(HookCapToolGate, HookPhasePre, "PreToolUse", hgLiveOpt(hookLiveClineToolGate), reg(hookDialectClinePreTool), wired(), sess(),
		host(0, HostProceeds), dec(decDenyModify...),
		note("the Cline CLI's file gate: ~/.cline/hooks/PreToolUse execs `observer hook cline-cli PreToolUse`, which prints {\"cancel\":true,\"errorMessage\"} to block and nothing to allow. Cline CLI 3.0.3 runs that file and no plugin (MAC-6, 2026-10-30: a {\"cancel\":true} verdict file stopped the task, \"[abort] aborted by another client\"; FU-154); the cancel aborts the whole run, not one call (live 2026-10-04 on 3.0.68). A Cline that also loads Observer's plugin judges the call twice (the plugin's beforeTool is a per-call deny). "+hookNoteClineGate)),
	clineCLITailB(HookCapSessionLifecycle, HookPhaseStart, "agent_start"),
	clineCLITailB(HookCapSessionLifecycle, HookPhaseEnd, "session_shutdown"),
	clineCLITailB(HookCapTurnLifecycle, HookPhaseEnd, "agent_end"),
	clineCLITailB(HookCapToolObserve, HookPhasePost, "tool_result"),
	hb(HookCapContextInject, HookPhasePost, "PostToolUse", hgSourceAt(hookJSP6Source, hookJSP6LiveDate), sess(), proc(ProcDescendant),
		host(hookClineHostTimeout, HostProceeds), feedbackPost(hookDialectFeedbackCline, true),
		note("security feedback (lane SEC-H): the ~/.cline/hooks/PostToolUse file hook's contextModification is queued and sent as one <hook_context source=PostToolUse> user message after the tool results (cline 4.1.25 SDK source); macOS and Linux only like the other Cline file hook; live pending. Written only while security.feedback is selected")),
}

// --- in-process TS plugin hosts: kilo-code(-cli), opencode, pi, prime-agent,
// openclaw --------------------------------------------------------------------

func pluginB(g Grounding) func(c HookCap, phase, event string, opts ...hbOpt) HookBinding {
	return func(c HookCap, phase, event string, opts ...hbOpt) HookBinding {
		return hb(c, phase, event, g, append([]hbOpt{proc(ProcInProcessPID)}, opts...)...)
	}
}

var (
	kiloB      = pluginB(hgDoc(hookSrcKilo))
	opencodeB  = pluginB(hgDoc(hookSrcOpenCode))
	piB        = pluginB(hgDoc(hookSrcPi))
	primeB     = pluginB(hgInferred(hookSrcPrimeAgent))
	openclawB  = pluginB(hgDoc(hookSrcOpenClaw))
	hermesDocB = pluginB(hgDoc(hookSrcHermes))
)

// Plugin-shim bindings (hook-parity Lane D): the internal/hook/pluginshim
// TS shim subscribes to a host's Registered bindings and speaks the plugin
// dialects (internal/hook plugingate.go). The shim passes the host's
// session id and its own pid.
var (
	// pluginShimGate: the tool gate through the shim.
	// A flagged call is allowed with the shim's notice (a TUI toast, pi's
	// notify), so the gate declares the plugin reply's message field.
	pluginShimGate = all(reg(hookDialectPluginShim), wired(), sess(), warnField(hookWarnPluginMessage))
	// pluginShimPrompt: OpenCode / Kilo chat.message. The shim throws to
	// stop the prompt (the model is never called) and toasts the reason; a
	// warning is a toast on an allow. No native confirm: an ask is a stop
	// the developer resends to confirm.
	pluginShimPrompt = all(reg(hookDialectPluginShimPrompt), wired(), sess(),
		dec(HookDecisionAllow, HookDecisionDeny, HookDecisionMessage),
		adminCaveat("Notices are toasts in the terminal UI; a headless run shows none."))
	// pluginShimPromptConfirm: pi `input`. {action:"handled"} stops the
	// prompt, ctx.ui.confirm asks (a stop to resend where there is no UI),
	// {action:"transform"} rewrites, ctx.ui.notify warns.
	pluginShimPromptConfirm = all(reg(hookDialectPluginShimPromptConfirm), wired(), sess(),
		dec(HookDecisionAllow, HookDecisionAsk, HookDecisionDeny, HookDecisionModify, HookDecisionMessage),
		adminCaveat("Without a UI (print or json mode) an ask stops the prompt and the developer resends it to confirm."))
	// pluginShimRendered: the shim renders this host's gate (dialect set)
	// but Observer does not place it: the host's plugin install location is
	// not grounded, so the binding is neither registered nor wired.
	pluginShimRendered = dialectOnly(hookDialectPluginShim)
)

const (
	notePluginChatMessage  = "plugin shim: a deny or ask THROWS, which rejects the prompt before it is stored, so the model is never called (the host itself shows only a generic server error), paired with the host's TUI toast carrying the reason (client.tui.showToast, @opencode-ai/sdk 1.18.31 / Kilo CLI 7.8.3); a warning is a toast on an allow, the prompt untouched; a headless `run` has no TUI, so no toast there (the dashboard post-hoc toast still applies to a stop). No native ask (permission.ask has no trigger site in 1.18.31): an ask is a stop the developer resends to confirm, keyed by the session id"
	notePluginOpenCodeTool = "plugin shim: throw = deny, paired with a TUI toast; no native ask (an ask is a deny with a reason); a flagged call is allowed with a warning toast; sub-agent coverage disputed (#5894); the Desktop app never dispatches plugin hooks (#38604)"
	notePiToolCall         = "plugin shim at ~/.pi/agent/extensions/: {block, reason}; a handler failure blocks the tool (pi fail-safe); an ask opens ctx.ui.confirm when ctx.hasUI (TUI, RPC) and blocks only on a no or a timeout, and is a block with the reason where there is no UI (print / json mode); a flagged call is allowed with ctx.ui.notify"
	notePiInput            = "plugin shim: a deny returns {action:\"handled\"} (no request is sent) with ctx.ui.notify (stderr where there is no UI); an ask opens ctx.ui.confirm when ctx.hasUI, else is handled and the developer resends to confirm; a redact returns {action:\"transform\"}; a warning is ctx.ui.notify on a continue. Extension-sourced input is skipped. A throw in pi's input handler FAILS OPEN, so the shim catches everything and follows its fail-closed posture rule"
)

// kiloBindings returns Kilo's plugin bindings. The CLI row gets the shim
// (wired); the legacy IDE extension row keeps the vendor surface only.
func kiloBindings(shim bool) []HookBinding {
	gate, prompt := []hbOpt{dec(decDenyModify...), note("in-process plugin: throw = deny (OpenCode contract)")}, []hbOpt{dec(decModify...), note("modify only")}
	if shim {
		gate = []hbOpt{dec(decDenyModify...), pluginShimGate, pluginShimLive, note("plugin shim at ~/.config/kilo/plugin/: throw = deny (OpenCode contract), paired with a TUI toast; no native ask; a flagged call is allowed with a warning toast")}
		prompt = []hbOpt{pluginShimPrompt, pluginShimLive, note(notePluginChatMessage)}
	}
	rows := []HookBinding{
		kiloB(HookCapToolGate, HookPhasePre, "tool.execute.before", gate...),
		kiloB(HookCapPromptGate, HookPhasePre, "chat.message", prompt...),
		kiloB(HookCapSessionLifecycle, HookPhaseStart, "session.created"),
		kiloB(HookCapTurnLifecycle, HookPhaseEnd, "session.idle"),
		kiloB(HookCapCompactLifecycle, HookPhasePre, "experimental.session.compacting"),
		kiloB(HookCapContextInject, HookPhasePre, "experimental.chat.system.transform", dec(decContext...)),
	}
	if shim {
		rows = append(rows, kiloB(HookCapContextInject, HookPhasePost, "tool.execute.after", sess(), liveAt(hookJSP6Live, hookJSP6LiveDate),
			feedbackPost(hookDialectFeedbackPlugin, true),
			note("security feedback (lane SEC-H): the plugin shim appends the reply's context to output.output in tool.execute.after, which the model reads as the tool result; live on Kilo CLI 7.3.54 (JSP-6 live half). The shim subscribes only while security.feedback is selected")))
	}
	return rows
}

var hookBindingsOpenCode = []HookBinding{
	opencodeB(HookCapToolGate, HookPhasePre, "tool.execute.before", dec(decDenyModify...), pluginShimGate, pluginShimLive,
		adminCaveat("Notices are TUI toasts; sub-agent coverage is disputed and the Desktop app never runs plugin hooks."),
		note(notePluginOpenCodeTool)),
	opencodeB(HookCapPromptGate, HookPhasePre, "chat.message", pluginShimPrompt, pluginShimLive, note(notePluginChatMessage)),
	opencodeB(HookCapSessionLifecycle, HookPhaseStart, "session.created"),
	opencodeB(HookCapSessionLifecycle, HookPhaseEnd, "session.deleted"),
	opencodeB(HookCapTurnLifecycle, HookPhaseEnd, "session.idle"),
	opencodeB(HookCapCompactLifecycle, HookPhasePre, "experimental.session.compacting"),
	opencodeB(HookCapCompactLifecycle, HookPhasePost, "session.compacted"),
	opencodeB(HookCapContextInject, HookPhasePre, "experimental.chat.system.transform", dec(decContext...)),
	opencodeB(HookCapContextInject, HookPhasePost, "tool.execute.after", sess(), hgSourceOpt(hookJSP6Source),
		feedbackPost(hookDialectFeedbackPlugin, true),
		note("security feedback (lane SEC-H): the plugin shim appends the reply's context to output.output in tool.execute.after (opencode 1.19.3 source, tools.ts; only on success); live pending (JSP-6: Kilo, its fork, is live). The shim subscribes only while security.feedback is selected")),
}

var hookBindingsPi = []HookBinding{
	piB(HookCapToolGate, HookPhasePre, "tool_call", dec(decDenyAskModify...), pluginShimGate, pluginShimLive,
		adminCaveat("Without a UI (print or json mode) an ask blocks the call."),
		note(notePiToolCall)),
	piB(HookCapPromptGate, HookPhasePre, "input", pluginShimPromptConfirm,
		liveAt(hookLivePiInput, hookLivePluginEnforceDate), note(notePiInput)),
	piB(HookCapSessionLifecycle, HookPhaseStart, "session_start"),
	piB(HookCapSessionLifecycle, HookPhaseEnd, "session_shutdown"),
	piB(HookCapTurnLifecycle, HookPhaseEnd, "turn_end"),
	piB(HookCapTurnLifecycle, HookPhaseEnd, "agent_end"),
	piB(HookCapCompactLifecycle, HookPhasePre, "session_before_compact"),
	piB(HookCapContextInject, HookPhaseStart, "before_agent_start", dec(decContext...)),
}

var hookBindingsPrimeAgent = []HookBinding{
	primeB(HookCapToolGate, HookPhasePre, "tool_call", dec(decDeny...), note("pi fork; hooks issue #872 closed not planned; the only tool is ipython")),
	primeB(HookCapPromptGate, HookPhasePre, "input"),
}

var hookBindingsOpenClaw = []HookBinding{
	openclawB(HookCapToolGate, HookPhasePre, "before_tool_call", dec(decDenyAskModify...), host(15*time.Second, HostBlocks), pluginShimRendered,
		note("runner-scoped: skips MCP under claude-cli (#155946) and Codex exec (#111254); fails closed on timeout (15 s default). The plugin shim renders {block, blockReason} / requireApproval, but OpenClaw loads a plugin only after `openclaw plugins install --link`, so Observer does not register it")),
	openclawB(HookCapPromptGate, HookPhasePre, "before_agent_run", dec(decDeny...), note("embedded / CLI runners only")),
	openclawB(HookCapSessionLifecycle, HookPhaseStart, "session_start"),
	openclawB(HookCapSessionLifecycle, HookPhaseEnd, "session_end"),
	openclawB(HookCapTurnLifecycle, HookPhaseEnd, "agent_end"),
	openclawB(HookCapSubagentLifecycle, HookPhaseStart, "subagent_spawned"),
	openclawB(HookCapSubagentLifecycle, HookPhaseEnd, "subagent_ended"),
	openclawB(HookCapCompactLifecycle, HookPhasePre, "before_compaction"),
	openclawB(HookCapCompactLifecycle, HookPhasePost, "after_compaction"),
	openclawB(HookCapContextInject, HookPhasePre, "before_prompt_build", dec(decContext...)),
}

// --- hermes: Observer's embedded Python plugin ------------------------------

var hermesPluginB = func(c HookCap, phase, event string, opts ...hbOpt) HookBinding {
	return hb(c, phase, event, hgFixture("internal/hook/hermesplugin/__init__.py + testdata/hermes"),
		append([]hbOpt{sess(), proc(ProcInProcessPID), reg(hookDialectHermesPlugin), wired()}, opts...)...)
}

var hookBindingsHermes = []HookBinding{
	hermesPluginB(HookCapSessionLifecycle, HookPhaseStart, "on_session_start"),
	hermesPluginB(HookCapSessionLifecycle, HookPhaseEnd, "on_session_end"),
	hermesPluginB(HookCapToolObserve, HookPhasePost, "post_tool_call", guardChannel("plugin"),
		note("observe-only audit-log plugin bridge - no documented deny semantics (Q4)")),
	hermesPluginB(HookCapModelCallObserve, HookPhasePost, "post_api_request"),
	hermesPluginB(HookCapSubagentLifecycle, HookPhaseEnd, "subagent_stop"),
	hermesDocB(HookCapToolGate, HookPhasePre, "pre_tool_call", dec(decDenyAskModify...), host(30*time.Second, HostBlocks),
		sess(), reg(hookDialectPluginShim), wired(),
		note("Observer's plugin subscribes (Lane A7, operator decision 2026-10-02): {\"action\": \"block\", \"message\"} denies, {\"action\": \"approve\", \"message\"} raises Hermes' own approval prompt; Hermes fails a timed-out pre_tool_call CLOSED at plugins.hook_callback_timeout (30 s default)")),
	hermesDocB(HookCapContextInject, HookPhasePre, "pre_llm_call", dec(decContext...)),
	hermesDocB(HookCapTurnLifecycle, HookPhaseEnd, "agent_loop_stopped"),
	hermesDocB(HookCapSubagentLifecycle, HookPhaseStart, "subagent_start"),
	hermesDocB(HookCapCompactLifecycle, HookPhasePost, "session:compress", note("gateway hook; `hermes serve` skips shell hooks (#102504)")),
}

// --- *-web: Observer's own MV3 extension (native messaging) ----------------

func browserBindings() []HookBinding {
	return []HookBinding{
		hb(HookCapTurnLifecycle, HookPhaseEnd, "capture", hgFixture(hookSrcBrowserExt), dialectOnly(hookDialectBrowserCapture), wired(),
			note("the extension relays each captured turn; content-script submit interception is per-site unverified")),
	}
}

// Honest-zero notes for rows with no hook surface Observer could bind.
const (
	hookNoteGrokbot = "no hook surface: Grok Bot runs tools on hosted VMs (https://docs.x.ai/grok-bot/security)"
	hookNoteZed     = "no hook surface: only static tool_permissions regex rules (https://zed.dev/docs/ai/tool-permissions), a native-compile target, not a hook"
	hookNoteAider   = "no hook surface: only post-hoc --lint-cmd / --test-cmd / --notifications-command options (https://aider.chat/docs/config/options.html)"
	hookNoteCowork  = "no hook surface: Cowork's VM never runs hooks (anthropics/claude-code #63360, #27398, #63047); Claude Code coverage does not extend to Cowork sessions"
	hookNoteFreebuf = "no hook surface: the SDK handleEvent callback is observe-only (https://www.codebuff.com/docs/advanced/sdk)"
)
