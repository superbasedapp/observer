package guard

import (
	"sort"

	"github.com/marmutapp/superbased-observer/internal/integration"
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
	// AskOnceKeyless is true when Caps.CanAsk is structurally true (the
	// wire dialect DOCUMENTS an ask-capable reply verb) but the
	// operational ask-once/reconsider bookkeeping can never actually use
	// it, because the vendor's own hook payload carries no session/
	// conversation id anywhere for the guard engine to key a resend
	// override on (the engine's own documented empty-session-id rule
	// then fails every finding closed to a hard, unconditional block).
	// This is a STRUCTURAL fact about the wire shape — read from the
	// vendor's own docs, same as Caps itself — not a per-tool exception:
	// a consumer degrading CanAsk to "block only" reads THIS field
	// rather than naming the tool (2026-09-22 review finding 12;
	// CLAUDE.md #3, branch on capabilities, never on tool identity).
	// Today only ToolCommandCode sets it; see its row's Notes for the
	// grounding.
	AskOnceKeyless bool
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
//
// The hook rows are GENERATED from the internal/integration hook bindings
// (hook-parity Lane 0 step 5): no channel is hand-listed here any more, so
// registration, the receiver and this matrix read one fact. The watcher
// rows keep their explicit client list (conformanceWatcherClients): it
// includes retag identities with no registry row of their own.
func ConformanceMatrix() []ConformanceEntry {
	entries := conformanceHookRows()
	// Every adapter has the watcher channel — including the
	// hook-capable ones (the hook sees declared calls; the watcher
	// sees results: the F1 mitigation).
	for _, client := range conformanceWatcherClients {
		entries = append(entries, watcherEntry(client))
	}
	return entries
}

// conformanceRowRule is one row of the ordered table that decides whether a
// hook binding is a conformance channel and with which capabilities. Walked
// top-down; the first rule that matches wins.
type conformanceRowRule struct {
	name  string
	match func(c integration.Capability, b integration.HookBinding) bool
	caps  func(b integration.HookBinding) (policy.Capabilities, bool)
}

// zeroCaps is the observe-only / probe-required row: zero capabilities,
// never AskOnceKeyless.
func zeroCaps(integration.HookBinding) (policy.Capabilities, bool) {
	return policy.Capabilities{}, false
}

// conformanceRowRules (Q4 discipline: CanBlock / CanAsk only where the
// binding's dialect documents deny / ask):
//
//  1. a binding naming a GuardChannel is an observe-only channel row;
//  2. a WIRED tool or prompt gate whose reply can deny is an enforcement
//     row: PreExecution from its pre phase, CanAsk from an ask decision,
//     AskOnceKeyless when it can ask but its payload carries no session key
//     to key the ask-once resend on;
//  3. an unwired prompt gate on a probe_required row is the honest
//     zero-capability placeholder until `observer doctor --probe-hook`
//     verifies the wire shape.
var conformanceRowRules = []conformanceRowRule{
	{
		name:  "observe_only_channel",
		match: func(_ integration.Capability, b integration.HookBinding) bool { return b.GuardChannel != "" },
		caps:  zeroCaps,
	},
	{
		name: "wired_gate",
		match: func(_ integration.Capability, b integration.HookBinding) bool {
			return (b.Cap == integration.HookCapToolGate || b.Cap == integration.HookCapPromptGate) &&
				b.Wired && b.HasDecision(integration.HookDecisionDeny)
		},
		caps: func(b integration.HookBinding) (policy.Capabilities, bool) {
			c := policy.Capabilities{
				PreExecution: b.Phase == integration.HookPhasePre,
				CanBlock:     true,
				CanAsk:       b.HasDecision(integration.HookDecisionAsk),
			}
			return c, c.CanAsk && !b.SessionKey
		},
	},
	{
		name: "probe_required_prompt_gate",
		match: func(c integration.Capability, b integration.HookBinding) bool {
			return b.Cap == integration.HookCapPromptGate && !b.Wired && c.PromptLane == integration.PromptLaneProbeRequired
		},
		caps: zeroCaps,
	},
}

// conformanceHookRows generates the hook-channel rows from the registry
// bindings, in conformanceDisplayOrder.
func conformanceHookRows() []ConformanceEntry {
	caps := integration.Capabilities()
	sort.Slice(caps, func(i, j int) bool { return caps[i].Tool < caps[j].Tool })
	var rows []ConformanceEntry
	for _, c := range caps {
		for _, b := range c.Hook.Bindings {
			if sameChannelReplay(c, b) {
				continue
			}
			for _, r := range conformanceRowRules {
				if !r.match(c, b) {
					continue
				}
				channel := b.NativeEvent
				if b.GuardChannel != "" {
					channel = b.GuardChannel
				}
				cp, keyless := r.caps(b)
				rows = append(rows, ConformanceEntry{
					Client: c.Tool, Channel: "hook:" + channel,
					Caps: cp, AskOnceKeyless: keyless, Notes: b.Note,
				})
				break
			}
		}
	}
	rank := make(map[string]int, len(conformanceDisplayOrder))
	for i, k := range conformanceDisplayOrder {
		rank[k] = i
	}
	sort.SliceStable(rows, func(i, j int) bool {
		ri, iok := rank[rows[i].Client+" "+rows[i].Channel]
		rj, jok := rank[rows[j].Client+" "+rows[j].Channel]
		switch {
		case iok && jok:
			return ri < rj
		case iok != jok:
			return iok // a listed row sorts before an unlisted one
		default:
			return false // unlisted rows keep their generated order
		}
	})
	return rows
}

// sameChannelReplay reports a replay binding that stands in for the tool's
// own registered gate on the SAME native event (cursor's preToolUse reached
// through Observer's Claude Code hooks, FU-122): one channel, whose row is the
// registered gate's, so the fallback adds no second row of the same name. A
// replay on an event of its own (copilot-cli's Claude-shaped PreToolUse) keeps
// its row.
func sameChannelReplay(c integration.Capability, b integration.HookBinding) bool {
	return c.Hook.ReplayFallback(b) && b.NativeEvent == b.StandsInFor
}

// conformanceDisplayOrder is the order the hook rows were rendered in
// before the matrix was generated. `observer guard status`, the guard
// export and /api/guard/conformance all render the matrix in returned
// order, so the generated rows keep it; a channel added later sorts after
// these in registry order, with no edit here required.
var conformanceDisplayOrder = []string{
	models.ToolClaudeCode + " hook:PreToolUse",
	models.ToolClaudeCode + " hook:UserPromptSubmit",
	models.ToolCodex + " hook:UserPromptSubmit",
	models.ToolDroid + " hook:UserPromptSubmit",
	models.ToolQwenCode + " hook:UserPromptSubmit",
	models.ToolCursor + " hook:beforeSubmitPrompt",
	models.ToolGeminiCLI + " hook:BeforeAgent",
	models.ToolKimiCode + " hook:UserPromptSubmit",
	models.ToolCline + " hook:UserPromptSubmit",
	models.ToolQoder + " hook:UserPromptSubmit",
	models.ToolPoolside + " hook:UserPromptSubmit",
	models.ToolZcode + " hook:UserPromptSubmit",
	models.ToolCommandCode + " hook:transformInput",
	models.ToolDevin + " hook:pre_user_prompt",
	models.ToolOpenInterpreter + " hook:UserPromptSubmit",
	models.ToolCursor + " hook:beforeShellExecution",
	models.ToolCursor + " hook:beforeMCPExecution",
	models.ToolCursor + " hook:beforeReadFile",
	models.ToolCodex + " hook:notify",
	models.ToolHermes + " hook:plugin",
}

// conformanceWatcherClients is every client that gets the post-hoc watcher
// row, in display order. A named table, not derived from the registry: it
// includes retag identities (roo-code, zoo-code) that have no registry row.
var conformanceWatcherClients = []string{
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
	// The 2026-10-21 wave: every one is a watcher-path adapter, so the
	// post-hoc watcher row is the backstop beside its pre-execution hook
	// rows (generated from the registry's wired gate bindings):
	//   autohand (JSONL tail + metadata.json re-read), ibm-bob (WAL SQLite
	//   bob.db re-read by tasks.updated_at watermark), codebuddy (JSONL
	//   tail), deepagents-code (LangGraph SQLite checkpointer), dimcode
	//   (WAL SQLite re-read), dirac (op-log JSONL tail), kimchi (pi-mono v3
	//   JSONL tail; its user-level bash pre-gate and the claude-code
	//   receiver's reroute are its hook rows), vtcode (events.jsonl tail),
	//   cortex-code (JSONL tail + whole-file metadata re-read; gated
	//   through the claude-code receiver's reroute, foreignhost.go) and
	//   stakpak (WAL SQLite checkpoint delta re-read; no hooks in 0.3.88,
	//   so the watcher row is its only guard surface).
	models.ToolAutohand, models.ToolIBMBob, models.ToolCortexCode,
	models.ToolCodeBuddy, models.ToolDeepAgentsCode, models.ToolDimCode,
	models.ToolDirac, models.ToolKimchi, models.ToolStakpak, models.ToolVTCode,
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
