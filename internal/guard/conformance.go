package guard

import (
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Conformance matrix (guard spec §6.5): the SINGLE data table mapping
// every adapter × channel onto enforcement capabilities. This is
// where client differences live — as DATA, never as code branches
// (§3.3); boundaries look their channel up here (or hard-code the
// same values locally with a conformance test pinning agreement).
// The dashboard Security page (G7) renders this so F2 — most
// adapters can only flag post-hoc — is visible, not hidden.
//
// Q4 discipline: a channel's CanBlock/CanAsk is recorded only where
// the client DOCUMENTS deny semantics (Claude Code PreToolUse
// permissionDecision; Cursor hook permission JSON). Channels without
// documented deny semantics are observe-only here even when they are
// technically pre-execution — never assume.

// ChannelWatcher is the post-hoc transcript/DB-tail channel every
// adapter has.
const ChannelWatcher = "watcher"

// ConformanceEntry is one adapter×channel row of the §6.5 matrix.
type ConformanceEntry struct {
	// Client is the models.ToolXxx adapter name.
	Client string
	// Channel names the capture surface: "watcher", or
	// "hook:<event>" for hook receivers.
	Channel string
	// Caps are the channel's enforcement capabilities.
	Caps policy.Capabilities
	// Notes documents coverage caveats and degradation behavior —
	// rendered verbatim on status surfaces.
	Notes string
}

// watcherEntry builds the post-hoc row every adapter gets.
func watcherEntry(client string) ConformanceEntry {
	return ConformanceEntry{
		Client:  client,
		Channel: ChannelWatcher,
		Caps:    policy.Capabilities{},
		Notes:   "post-hoc flagging only; sees results (file changes, outputs) hooks structurally miss",
	}
}

// ConformanceMatrix returns the full §6.5 table. Order: hook channels
// first (the enforcement surfaces), then every adapter's watcher row.
func ConformanceMatrix() []ConformanceEntry {
	entries := []ConformanceEntry{
		{
			Client:  models.ToolClaudeCode,
			Channel: "hook:PreToolUse",
			Caps:    policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
			Notes:   "native ask via permissionDecision; payload carries cwd but no project root, so boundary rules defer to the watcher",
		},
		// --- Prompt-submit intervention hook lane (Part B,
		// docs/plans/prompt-submit-intervention-exploration-2026-09-07.md
		// §6/§10 item 12). CanAsk here means "the developer sees a
		// message they can read and act on" — the reconsider-once
		// semantics (block once, allow an identical resend) are
		// implemented entirely at the observer layer; none of these
		// wire protocols has a literal tri-state ask verb. Every row
		// below is a VERIFIED dialect (internal/hook/promptsubmit.go
		// has a builder for it) with a real conformance row here —
		// including the Part B item 2 long tail (Qoder, Poolside,
		// zcode, commandcode, Devin/Cascade), which used to sit behind
		// a since-REMOVED PromptLaneDocumented placeholder (F9,
		// phase-3a review) before their dialects/receivers were built;
		// a vendor whose wire shape is genuinely UNVERIFIED/contested
		// gets PromptLaneProbeRequired instead — never a conformance
		// row with guessed capabilities either way.
		{
			Client:  models.ToolClaudeCode,
			Channel: "hook:UserPromptSubmit",
			Caps:    policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
			Notes:   "process exit code 2 with NO stdout reply; stderr is the user-visible reason and the prompt is erased (LIVE CORRECTION 2026-09-07: permissionDecision is PreToolUse-only and is silently ignored on this event). Allow/warn reply with the bare hookSpecificOutput envelope (+ additionalContext on warn)",
		},
		{
			Client:  models.ToolCodex,
			Channel: "hook:UserPromptSubmit",
			Caps:    policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
			Notes:   "legacy {decision:block,reason} shown to the developer; prompt cannot be modified",
		},
		{
			Client:  models.ToolDroid,
			Channel: "hook:UserPromptSubmit",
			Caps:    policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
			Notes:   "same legacy {decision:block,reason} shape as Codex; vendor docs state outright \"hook feedback goes to the user, not the agent\"",
		},
		{
			Client:  models.ToolQwenCode,
			Channel: "hook:UserPromptSubmit",
			Caps:    policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
			Notes:   "documented decision enum is allow|deny|block|ask; observer emits \"block\" (the verb every sibling top-level-block vendor's docs confirm) rather than guessing a semantic split between deny/block/ask the docs don't draw",
		},
		{
			Client:  models.ToolCursor,
			Channel: "hook:beforeSubmitPrompt",
			Caps:    policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
			Notes:   "continue:false + user_message (NOT the permission field the shell/MCP/file channels use); prompt cannot be modified",
		},
		{
			Client:  models.ToolGeminiCLI,
			Channel: "hook:BeforeAgent",
			Caps:    policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
			Notes:   "decision:deny discards the message; both reason and systemMessage are set (vendor docs call systemMessage user-visible in the terminal, and reason also renders when denying)",
		},
		// --- Genuinely unverified/contested vendors (kimi-code,
		// kiro-cli, cline, open-interpreter): zero Capabilities on
		// purpose (honesty rule — degrades to observe-only until a
		// live probe confirms the wire shape), registered with a
		// PromptLane=PromptLaneProbeRequired row in internal/integration
		// instead of a guessed conformance row. Distinct from the
		// Part B item 2 long-tail rows further above (Qoder, Poolside,
		// zcode, commandcode, Devin/Cascade), whose wire shape the
		// vendor's OWN docs already fully confirm and whose
		// dialects/receivers are built and tested — PromptLaneHook,
		// not PromptLaneProbeRequired.
		{
			Client:  models.ToolKimiCode,
			Channel: "hook:UserPromptSubmit",
			Caps:    policy.Capabilities{},
			Notes:   "probe_required — the vendor's published payload sample does not confirm the prompt field is present, nor that a block reason reaches the developer; observer doctor --probe-hook decides",
		},
		{
			Client:  models.ToolKiroCLI,
			Channel: "hook:userPromptSubmit",
			Caps:    policy.Capabilities{},
			Notes:   "probe_required — a shell-action non-zero exit blocks the submission, but whether the developer ever sees the stderr (vs it going only to the agent as an error notification) is unconfirmed",
		},
		{
			Client:  models.ToolCline,
			Channel: "hook:UserPromptSubmit",
			Caps:    policy.Capabilities{},
			Notes:   "probe_required — cancel:true blocks, but the exact JSON keys for the prompt text and the block message are undocumented (macOS/Linux only, no Windows support)",
		},
		{
			Client:  models.ToolQoder,
			Channel: "hook:UserPromptSubmit",
			Caps:    policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
			Notes:   "Part B item 2, phase-3a — live-fetched 2026-09-07 (docs.qoder.com/en/cli/hooks): exit code 2 blocks, plain-text stderr is the developer-visible reason (no JSON reply at all); ~/.qoder/settings.json shares Claude Code's exact hooks schema, so registration reuses registerGenericSettingsHooks",
		},
		{
			Client:  models.ToolPoolside,
			Channel: "hook:UserPromptSubmit",
			Caps:    policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
			Notes:   "Part B item 2, phase-3a — live-fetched 2026-09-07 (docs.poolside.ai/hooks): JSON decision shape ({\"decision\":\"block\",\"reason\",\"hook_specific_output\":{\"updated_prompt\",\"additional_context\"}}, snake_case); registered in ~/.config/poolside/settings.yaml. updated_prompt (the genuine redact lane) stays unpopulated — not wired on any channel yet",
		},
		{
			Client:  models.ToolZcode,
			Channel: "hook:UserPromptSubmit",
			Caps:    policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
			Notes:   "Part B item 2, phase-3a — live-fetched 2026-09-07 (zcode.z.ai/en/docs/hooks): Claude-Code-shaped continue:false reply, ~/.zcode/cli/config.json registration. The dialect/receiver is built and tested, but registration is DELIBERATELY NOT auto-wired (HookZcodeJSON, AutoWired:false) — zai-org/feedback#32 reports configured hooks may not fire on the native agent at all; a live liveness probe (observer doctor --probe-hook) should gate turning auto-registration on",
		},
		{
			Client:  models.ToolCommandCode,
			Channel: "hook:transformInput",
			Caps:    policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
			Notes:   "Part B item 2, phase-3a — live-fetched 2026-09-07 (commandcode.ai/docs/mods): a Mods-SDK TypeScript module (cmd.hooks({transformInput({text}){...}})), not a shell hook — registered as ~/.commandcode/mods/observer-guard.ts (go:embed template, hermesplugin precedent) that shells out to `observer hook command-code transformInput`. The ONLY documented field is `text` — there is no session/conversation id anywhere in the signature, so every ask-once/redact finding here fails closed to a HARD, unconditional block (no resend override) per the engine's own documented empty-session-id rule; action:'transform' (the genuine redact lane) stays unpopulated",
		},
		{
			Client:  models.ToolDevin,
			Channel: "hook:pre_user_prompt",
			Caps:    policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: false},
			Notes:   "Part B item 2, phase-3a — live-fetched 2026-09-07 (docs.devin.ai/desktop/cascade/hooks): Windsurf/Devin Desktop Cascade's pre_user_prompt, exit code 2 blocks, no JSON reply and no user-visible message channel at all (show_output does not apply to this event, so ask-once degrades to a hard block); no session_id field is documented either — trajectory_id (the conversation identifier) is used as the session-scoping key instead; registered at ~/.codeium/windsurf/hooks.json",
		},
		{
			Client:  models.ToolOpenInterpreter,
			Channel: "hook:UserPromptSubmit",
			Caps:    policy.Capabilities{},
			Notes:   "probe_required — open-interpreter is a rebadged Codex CLI Rust build (codex.NewOpenInterpreter retag); it plausibly inherits Codex's UserPromptSubmit hook under INTERPRETER_HOME, unconfirmed",
		},
		{
			Client:  models.ToolCursor,
			Channel: "hook:" + "beforeShellExecution",
			Caps:    policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
			Notes:   "permission JSON allow|deny|ask; payload carries the workspace root, so boundary rules are active pre-execution",
		},
		{
			Client:  models.ToolCursor,
			Channel: "hook:" + "beforeMCPExecution",
			Caps:    policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
			Notes:   "permission JSON allow|deny|ask",
		},
		{
			Client:  models.ToolCursor,
			Channel: "hook:" + "beforeReadFile",
			Caps:    policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
			Notes:   "permission JSON allow|deny|ask",
		},
		{
			Client:  models.ToolCodex,
			Channel: "hook:notify",
			Caps:    policy.Capabilities{},
			Notes:   "observe-only notification channel — no documented deny semantics (Q4); enforcement comes from the native rules dialect once G11 compiles it",
		},
		{
			Client:  models.ToolHermes,
			Channel: "hook:plugin",
			Caps:    policy.Capabilities{},
			Notes:   "observe-only audit-log plugin bridge — no documented deny semantics (Q4)",
		},
	}
	// Every adapter has the watcher channel — including the
	// hook-capable ones (the hook sees declared calls; the watcher
	// sees results: the F1 mitigation).
	for _, client := range []string{
		models.ToolClaudeCode, models.ToolCodex, models.ToolCursor,
		models.ToolCline, models.ToolClineCLI, models.ToolRooCode,
		// zoo-code (2026-09-03): the ZooCode community continuation of
		// Roo Code, parsed by the same watcher-path cline adapter — same
		// shape as roo-code, so it gets the same post-hoc watcher row.
		models.ToolZooCode,
		models.ToolCopilot, models.ToolCopilotCLI, models.ToolCowork,
		models.ToolOpenCode, models.ToolOpenClaw, models.ToolPi,
		models.ToolGeminiCLI, models.ToolAntigravity, models.ToolAntigravityCLI, models.ToolHermes,
		models.ToolKiloCode, models.ToolKiloCodeCLI,
		// 2026-07 adapter wave: watcher-path adapters (SQLite/JSONL
		// tail); the store/watcher guard seam applies generically, so
		// each qualifies for the post-hoc watcher row like the other
		// watcher-only adapters (hermes, kilo-code-cli).
		models.ToolQwenCode, models.ToolKiroCLI, models.ToolCrush,
		models.ToolKimiCode, models.ToolGrok, models.ToolDevin,
		models.ToolQoder, models.ToolAider, models.ToolGoose,
		// 2026-07-29 wave: all three are watcher-path adapters (JSONL
		// tail) with no hook mechanism grounded (registry Hook is
		// HookNone for each), so the post-hoc watcher row is their ONLY
		// guard surface — exactly the F2 coverage this table makes
		// visible rather than hiding.
		models.ToolDroid, models.ToolOpenInterpreter, models.ToolCommandCode,
		// muse (2026-08-06): watcher-path adapter (event-sourced JSONL
		// tail); registry Hook is HookNone (the binary carries a hook
		// vocabulary but no receiver exists), so the post-hoc watcher
		// row is its only guard surface.
		models.ToolMuse,
		// prime-agent (2026-08-06): watcher-path adapter (JSONL tail of
		// the pi-fork session envelope); registry Hook is HookNone, so
		// the post-hoc watcher row is its only guard surface — same
		// shape as muse.
		models.ToolPrimeAgent,
		// deepseek + junie: watcher-path adapters (compressed-JSONL and
		// event-sourced-JSONL tails respectively), registry Hook HookNone
		// for both, so the post-hoc watcher row is their only guard
		// surface — same shape as muse/prime-agent.
		models.ToolDeepSeek, models.ToolJunie,
		// zcode + mistral-code + freebuff (2026-08-18 wave): watcher-path
		// adapters (SQLite/JSONL tail), registry Hook HookNone for all
		// three, so the post-hoc watcher row is their only guard
		// surface — same shape as the 2026-07 wave above.
		models.ToolZcode, models.ToolMistralCode, models.ToolFreebuff,
		// grokbot (2026-08-28): watcher-path adapter (plaintext-JSON blob
		// re-read), registry Hook HookNone, so the post-hoc watcher row is
		// its only guard surface. Note the row is post-hoc in a STRONGER
		// sense than its neighbours: Grok Bot executes tools in a REMOTE
		// sandbox, so guard could not police them even with a pre-execution
		// channel — there is no local tool execution to intercept.
		models.ToolGrokbot,
		// kiro-crew (2026-09-03): watcher-path adapter (whole-file JSONL
		// re-read), registry Hook HookNone, so the post-hoc watcher row is
		// its only guard surface. The row is thin by design — Crew drives
		// kiro-cli, and the tool calls it orchestrates are captured (and
		// guarded) under the kiro-cli row above; this adapter only emits
		// rows for a Crew chat with no kiro-cli twin.
		models.ToolKiroCrew,
		// poolside (2026-09-05): watcher-path adapter (event-sourced
		// NDJSON trajectory tail), registry Hook HookNone (no hook
		// mechanism grounded for the IDE-embedded ACP agent), so the
		// post-hoc watcher row is its only guard surface.
		models.ToolPoolside,
		// zed (2026-09-06): watcher-path adapter (whole-thread SQLite
		// re-read), registry Hook HookNone (Zed is itself the editor,
		// with no hook mechanism grounded), so the post-hoc watcher row
		// is its only guard surface.
		models.ToolZed,
	} {
		entries = append(entries, watcherEntry(client))
	}
	return entries
}

// CapabilitiesFor looks up one adapter×channel row. ok=false means
// the channel isn't in the matrix — callers treat unknown channels as
// observe-only (the zero Capabilities), never as blockable.
func CapabilitiesFor(client, channel string) (policy.Capabilities, bool) {
	for _, e := range ConformanceMatrix() {
		if e.Client == client && e.Channel == channel {
			return e.Caps, true
		}
	}
	return policy.Capabilities{}, false
}

// ClassifyActionType maps a models action-type onto the policy event
// vocabulary — the same boundary classification the ingest seam uses,
// exported so hook receivers that already produce normalized
// ToolEvents (cursor) classify identically. ok=false means the action
// is not an evaluable kind.
func ClassifyActionType(actionType string) (policy.EventKind, bool) {
	return classifyKind(actionType)
}
