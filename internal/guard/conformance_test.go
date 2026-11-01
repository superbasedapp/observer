package guard

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestConformanceMatrix pins the §6.5 table's structural invariants:
// every enabled adapter has a watcher row (full coverage, no silent
// gaps — F2 is made visible, never hidden), block-capable channels
// are exactly the documented ones (Q4: never assume deny semantics),
// and lookups behave.
func TestConformanceMatrix(t *testing.T) {
	t.Parallel()
	matrix := ConformanceMatrix()

	// Every default-enabled adapter must have a watcher row. The
	// EnabledAdapters default list is the coverage contract.
	for _, client := range config.Default().Observer.Watch.EnabledAdapters {
		// Browser-extension-fed adapters have no watcher channel and no
		// local tool execution for guard to police (turns arrive via the
		// native-messaging hook, not fsnotify). Dispatch on the registry
		// capability, never the tool name.
		if cap, ok := integration.For(client); ok && cap.Hook.Mechanism == integration.HookBrowserExtension {
			continue
		}
		caps, ok := CapabilitiesFor(client, ChannelWatcher)
		if !ok {
			t.Errorf("adapter %q has no watcher row — coverage gap would be silent", client)
			continue
		}
		if caps.PreExecution || caps.CanBlock || caps.CanAsk {
			t.Errorf("adapter %q watcher row claims pre-execution capabilities: %+v", client, caps)
		}
	}

	// Block-capable channels are EXACTLY the documented set.
	var blockers []string
	for _, e := range matrix {
		if e.Caps.CanBlock {
			blockers = append(blockers, e.Client+"/"+e.Channel)
		}
	}
	want := map[string]bool{
		models.ToolClaudeCode + "/hook:PreToolUse":       true,
		models.ToolCursor + "/hook:beforeShellExecution": true,
		models.ToolCursor + "/hook:beforeMCPExecution":   true,
		models.ToolCursor + "/hook:beforeReadFile":       true,
		// Prompt-submit intervention hook lane (Part B) — every
		// VERIFIED dialect gets a block-capable row; the genuinely
		// unverified/contested long-tail (kimi-code, kiro-cli, cline,
		// open-interpreter) stays zero-Caps/probe_required and is NOT
		// in this set. devin's pre_user_prompt IS block-capable
		// (vendor-documented exit-2 block) but CanAsk:false (no
		// user-visible message channel) — commandcode's
		// hook:transformInput is likewise block-capable despite its
		// non-shell packaging (a Mods-SDK module, not a shell hook).
		models.ToolClaudeCode + "/hook:UserPromptSubmit": true,
		models.ToolCodex + "/hook:UserPromptSubmit":      true,
		models.ToolDroid + "/hook:UserPromptSubmit":      true,
		models.ToolQwenCode + "/hook:UserPromptSubmit":   true,
		models.ToolCursor + "/hook:beforeSubmitPrompt":   true,
		models.ToolGeminiCLI + "/hook:BeforeAgent":       true,
		models.ToolDevin + "/hook:pre_user_prompt":       true,
		// Part B item 2, phase-3a (2026-09-07): the documented
		// long-tail vendors, live-fetched and wired.
		models.ToolQoder + "/hook:UserPromptSubmit":     true,
		models.ToolPoolside + "/hook:UserPromptSubmit":  true,
		models.ToolZcode + "/hook:UserPromptSubmit":     true,
		models.ToolCommandCode + "/hook:transformInput": true,
		// Hook-parity Lane A (2026-10-03): the pre-tool gates whose deny
		// is documented on the vendor's own config surface (audit section
		// 4.6 sources), served by internal/hook's tool-gate table. Codex,
		// Cursor preToolUse, Gemini and Qoder are deny-only (no CanAsk;
		// Qoder's ask ran the command under --yolo, live); Qwen and Droid
		// document permissionDecision ask.
		models.ToolCodex + "/hook:PreToolUse":     true,
		models.ToolCursor + "/hook:preToolUse":    true,
		models.ToolGeminiCLI + "/hook:BeforeTool": true,
		models.ToolQwenCode + "/hook:PreToolUse":  true,
		models.ToolDroid + "/hook:PreToolUse":     true,
		models.ToolQoder + "/hook:PreToolUse":     true,
		// Hook-parity Lanes A4-A6 (2026-10-03): the remaining pre-tool gates
		// whose deny is documented on the vendor surface (or grounded on the
		// vendor binary on demo node 1).
		models.ToolAntigravityCLI + "/hook:PreToolUse": true,
		// Guard-fix lane B (2026-10-15): the Cline CLI gate moved from the
		// ~/.cline/hooks PreToolUse file (T-342; its cancel stopped the run)
		// to the Plugin API (beforeTool skip, beforeModel stop), live on
		// cline 3.0.68; Copilot CLI userPromptSubmitted blocks with handled +
		// modifiedPrompt, live on copilot 1.0.96.
		models.ToolClineCLI + "/hook:beforeTool":  true,
		models.ToolClineCLI + "/hook:beforeModel": true,
		// FU-154 (lane w12-fixes): Cline CLI 3.0.3 loads no plugin and runs
		// the ~/.cline/hooks PreToolUse file again, which now execs the tool
		// gate (dialect cline-pretool: {"cancel":true} stops the run); live
		// on MAC-6 (2026-10-30), documented in docs/guard.md and
		// docs/clinecli-adapter.md.
		models.ToolClineCLI + "/hook:PreToolUse":            true,
		models.ToolCopilotCLI + "/hook:userPromptSubmitted": true,
		// Guard-enforcement fix (2026-10-15, agy 1.3.5 live): PreInvocation's
		// {"injectSteps":[{}]} aborts the turn before the main model request
		// (an undocumented error path, gated on the agy version at run time).
		models.ToolAntigravityCLI + "/hook:PreInvocation": true,
		models.ToolCopilotCLI + "/hook:preToolUse":        true,
		models.ToolCrush + "/hook:PreToolUse":             true,
		models.ToolDevin + "/hook:pre_run_command":        true,
		models.ToolDevin + "/hook:pre_write_code":         true,
		models.ToolDevin + "/hook:pre_read_code":          true,
		models.ToolDevin + "/hook:pre_mcp_tool_use":       true,
		models.ToolGoose + "/hook:PreToolUse":             true,
		models.ToolGrok + "/hook:PreToolUse":              true,
		models.ToolJunie + "/hook:PreToolUse":             true,
		models.ToolMistralCode + "/hook:pre_tool":         true,
		models.ToolOpenInterpreter + "/hook:PreToolUse":   true,
		models.ToolPoolside + "/hook:PreToolUse":          true,
		models.ToolZcode + "/hook:PreToolUse":             true,
		// Hook-parity Lane D (2026-10-03): the in-process plugin hosts
		// through the one plugin shim (throw / {block} / Hermes' block
		// directive), and OpenCode / Kilo CLI chat.message, where the shim
		// throws so the host rejects the prompt before the model call
		// (opencode 1.18.31, live 2026-10-15). pi `input` (2026-10-15):
		// {action:"handled"} sends no request (pi 1.0.0 extensions/types.ts
		// InputEventResult, live on demo node 1).
		models.ToolOpenCode + "/hook:tool.execute.before":    true,
		models.ToolOpenCode + "/hook:chat.message":           true,
		models.ToolKiloCodeCLI + "/hook:tool.execute.before": true,
		models.ToolKiloCodeCLI + "/hook:chat.message":        true,
		models.ToolPi + "/hook:tool_call":                    true,
		models.ToolPi + "/hook:input":                        true,
		models.ToolHermes + "/hook:pre_tool_call":            true,
		models.ToolCommandCode + "/hook:beforeToolCall":      true,
		// LIVE-GROUND-2 (2026-10-06, D-363; T-581): Muse's settings.json
		// writer (T-479) is live on muse 1.4.3: a PreToolUse
		// permissionDecision deny reached the model and a UserPromptSubmit
		// {"decision":"block"} cancelled the run with no model request. The
		// prompt gate lists no ask (no developer-visible message proven), so
		// it is block-only like devin's pre_user_prompt. The Devin CLI
		// PreToolUse writer (T-478) speaks the Claude-shaped deny the vendor
		// documents (hookSpecificOutput.permissionDecision, exit 2,
		// decision:block); its firing on node 1 was not observed because the
		// node's own budget intervention stopped devin first, so the row is
		// doc-grounded, which Q4 accepts (documented deny semantics).
		models.ToolMuse + "/hook:PreToolUse":       true,
		models.ToolMuse + "/hook:UserPromptSubmit": true,
		models.ToolDevin + "/hook:PreToolUse":      true,
		// LIVE-GROUND-3 (T-378): Kimi Code's config.toml [[hooks]] writer.
		// Both gates are exit-2 blocks the vendor documents (PreToolUse:
		// stderr is the reason the model sees; UserPromptSubmit: the
		// installed 2.1.1 source appends stderr as a <hook_result>), so Q4's
		// documented deny semantics hold.
		models.ToolKimiCode + "/hook:PreToolUse": true,
		// gfiD (2026-10-15): Kiro CLI's preToolUse exit-2 block, documented
		// in the 2.x reference and observed live with probe hooks (kiro-cli
		// 2.28.0: the model got "PreToolHook blocked the tool execution").
		// Its userPromptSubmit cannot block, so it is no row here.
		models.ToolKiroCLI + "/hook:preToolUse":        true,
		models.ToolKimiCode + "/hook:UserPromptSubmit": true,
		// The 2026-10-21 wave: every gate's deny was fired live by the hook
		// probe against the shipped build (docs/guard.md "Live grounding:
		// 2026-10-21 wave"). Kimchi and Cortex Code are reached through
		// Observer's Claude Code hooks (foreignhost.go reroute).
		models.ToolIBMBob + "/hook:PreToolUse":               true,
		models.ToolIBMBob + "/hook:UserPromptSubmit":         true,
		models.ToolCodeBuddy + "/hook:PreToolUse":            true,
		models.ToolCodeBuddy + "/hook:UserPromptSubmit":      true,
		models.ToolDeepAgentsCode + "/hook:PreToolUse":       true,
		models.ToolDeepAgentsCode + "/hook:UserPromptSubmit": true,
		models.ToolDimCode + "/hook:PreToolUse":              true,
		models.ToolDimCode + "/hook:UserPromptSubmit":        true,
		models.ToolDirac + "/hook:PreToolUse":                true,
		models.ToolDirac + "/hook:UserPromptSubmit":          true,
		models.ToolAutohand + "/hook:pre-tool":               true,
		models.ToolAutohand + "/hook:pre-prompt":             true,
		models.ToolVTCode + "/hook:PreToolUse":               true,
		models.ToolVTCode + "/hook:UserPromptSubmit":         true,
		models.ToolKimchi + "/hook:tool_call":                true,
		models.ToolKimchi + "/hook:PreToolUse":               true,
		models.ToolKimchi + "/hook:UserPromptSubmit":         true,
		models.ToolCortexCode + "/hook:PreToolUse":           true,
		models.ToolCortexCode + "/hook:UserPromptSubmit":     true,
		// Surface-gap lane w5-foreign: the Antigravity App and IDE run the
		// antigravity-cli registration (the agy deny and PreInvocation
		// semantics above, antigravity.google/docs/hooks?tab=ide), and
		// DeepSeek Harness runs Observer's Claude Code hooks through its
		// dsh-hooks-claude-code bridge (deny and ask, vendor source
		// 0.2.1-rc.3); both are served by the claude-code / antigravity-cli
		// receivers under the host's own id.
		models.ToolAntigravity + "/hook:PreToolUse":    true,
		models.ToolAntigravity + "/hook:PreInvocation": true,
		models.ToolDeepSeek + "/hook:PreToolUse":       true,
		models.ToolDeepSeek + "/hook:UserPromptSubmit": true,
		// Surface-gap R-194 G2 (lane w6-tails): the Copilot CLI runtime's
		// Claude-compatible PreToolUse replay (live check 12 payload)
		// reaching Observer's Claude Code hooks is judged as copilot-cli,
		// with the Claude JSON deny, while Observer's own copilot-cli
		// registration is absent. The deny is Claude Code's documented
		// PreToolUse shape on a runtime that runs Claude settings hooks
		// (doc-grounded, which Q4 accepts); the deny on this path is not
		// yet live-run (the w6-tails report's G2 live check).
		models.ToolCopilotCLI + "/hook:PreToolUse": true,
	}
	if len(blockers) != len(want) {
		t.Errorf("block-capable channels = %v, want exactly %d documented ones", blockers, len(want))
	}
	for _, b := range blockers {
		if !want[b] {
			t.Errorf("undocumented block-capable channel %q (Q4: deny semantics must be documented before CanBlock)", b)
		}
	}

	// The LIVE-GROUND-2 prompt gate is block-only: Muse showed no reason
	// to the developer, so an enforced ask must degrade to a block.
	if caps, ok := CapabilitiesFor(models.ToolMuse, "hook:UserPromptSubmit"); !ok || !caps.PreExecution || !caps.CanBlock || caps.CanAsk {
		t.Errorf("muse hook:UserPromptSubmit = (%+v, %v), want a pre-execution block-only row", caps, ok)
	}

	// Observe-only hook channels exist for codex + hermes (they have
	// receivers but no documented deny path).
	for _, c := range []struct{ client, channel string }{
		{models.ToolCodex, "hook:notify"},
		{models.ToolHermes, "hook:plugin"},
	} {
		caps, ok := CapabilitiesFor(c.client, c.channel)
		if !ok || caps.CanBlock {
			t.Errorf("%s %s = (%+v, %v), want observe-only row", c.client, c.channel, caps, ok)
		}
	}

	// Unknown lookups: zero caps, ok=false — callers treat unknown as
	// observe-only, never blockable.
	if caps, ok := CapabilitiesFor("mystery-tool", "hook:anything"); ok || caps.CanBlock {
		t.Errorf("unknown channel lookup = (%+v, %v), want zero/false", caps, ok)
	}

	// Notes are mandatory — the dashboard renders them; an empty note
	// is a row nobody can interpret.
	for _, e := range matrix {
		if e.Notes == "" {
			t.Errorf("%s/%s has no Notes", e.Client, e.Channel)
		}
	}
}

// TestClassifyActionType pins the exported boundary classification
// against the ingest seam's vocabulary.
func TestClassifyActionType(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want policy.EventKind
		ok   bool
	}{
		{models.ActionRunCommand, policy.KindShellExec, true},
		{models.ActionReadFile, policy.KindFileAccess, true},
		{models.ActionMCPCall, policy.KindMCPCall, true},
		{models.ActionConfigChange, policy.KindConfigChange, true},
		{models.ActionWebFetch, policy.KindToolCall, true},
		{models.ActionUserPrompt, "", false},
		{models.ActionSessionEnd, "", false},
	}
	for _, tc := range cases {
		kind, ok := ClassifyActionType(tc.in)
		if kind != tc.want || ok != tc.ok {
			t.Errorf("ClassifyActionType(%s) = (%s, %v), want (%s, %v)", tc.in, kind, ok, tc.want, tc.ok)
		}
	}
}

// TestPromptSubmitConformance_RowExistsForEveryShippedChannel is the
// row-per-shipped-channel assertion contract §6.7 calls for: every
// prompt-submit channel internal/hook actually dispatches guard
// evaluation for MUST have a conformance row, or it silently degrades
// to observe-only — the single highest-risk omission the contract
// names. This list must be updated whenever a new dialect ships.
func TestPromptSubmitConformance_RowExistsForEveryShippedChannel(t *testing.T) {
	t.Parallel()
	shipped := []struct{ client, channel string }{
		{models.ToolClaudeCode, "hook:UserPromptSubmit"},
		{models.ToolCodex, "hook:UserPromptSubmit"},
		{models.ToolDroid, "hook:UserPromptSubmit"},
		{models.ToolQwenCode, "hook:UserPromptSubmit"},
		{models.ToolCursor, "hook:beforeSubmitPrompt"},
		{models.ToolGeminiCLI, "hook:BeforeAgent"},
		// Part B item 2, phase-3a (2026-09-07).
		{models.ToolQoder, "hook:UserPromptSubmit"},
		{models.ToolPoolside, "hook:UserPromptSubmit"},
		{models.ToolZcode, "hook:UserPromptSubmit"},
		{models.ToolCommandCode, "hook:transformInput"},
	}
	for _, c := range shipped {
		caps, ok := CapabilitiesFor(c.client, c.channel)
		if !ok {
			t.Errorf("%s/%s has no conformance row — a shipped dialect must never silently degrade to observe-only", c.client, c.channel)
			continue
		}
		if !caps.PreExecution || !caps.CanBlock || !caps.CanAsk {
			t.Errorf("%s/%s caps = %+v, want a full pre-execution block+ask row", c.client, c.channel, caps)
		}
	}
}

// TestPromptSubmitConformance_NoMessageChannelDegradesAskToBlock pins
// contract §10 item 12 end to end through the REAL conformance row:
// devin/hook:pre_user_prompt is CanBlock:true, CanAsk:false (Cascade
// has no user-visible message channel for this event at all), so
// ResolveEmission must degrade a fresh ask-once interrupt (Decision:
// Ask) to a hard deny with DegradedFrom="ask" — never to a silent
// allow, and never pretending the developer was asked when they
// weren't.
func TestPromptSubmitConformance_NoMessageChannelDegradesAskToBlock(t *testing.T) {
	t.Parallel()
	caps, ok := CapabilitiesFor(models.ToolDevin, "hook:pre_user_prompt")
	if !ok {
		t.Fatalf("devin/hook:pre_user_prompt has no conformance row")
	}
	if !caps.CanBlock || caps.CanAsk {
		t.Fatalf("caps = %+v, want CanBlock:true, CanAsk:false", caps)
	}
	askVerdict := policy.Verdict{Decision: policy.DecisionAsk, RuleID: "R-190", Reason: "detected credit_card×1 in the prompt text"}
	em := ResolveEmission(askVerdict, caps)
	if em.Permission != "deny" {
		t.Errorf("Permission = %q, want deny (never a silent allow on a no-message channel)", em.Permission)
	}
	if em.DegradedFrom != "ask" {
		t.Errorf("DegradedFrom = %q, want \"ask\"", em.DegradedFrom)
	}
	if !em.Enforced {
		t.Errorf("Enforced = false, want true — the prompt is genuinely blocked")
	}
}

// TestConformanceDisplayOrderHasNoStaleRows: every entry of the display
// order table names a hook row the bindings actually generate, and every
// generated row is distinct, so the order table can never silently pin a
// channel that no binding produces any more.
func TestConformanceDisplayOrderHasNoStaleRows(t *testing.T) {
	t.Parallel()
	generated := map[string]int{}
	for _, e := range conformanceHookRows() {
		generated[e.Client+" "+e.Channel]++
	}
	for k, n := range generated {
		if n != 1 {
			t.Errorf("hook row %q generated %d times", k, n)
		}
	}
	for _, k := range conformanceDisplayOrder {
		if generated[k] == 0 {
			t.Errorf("display order lists %q but no binding generates it", k)
		}
	}
}

// TestConformanceSameChannelReplayHasNoSecondRow: cursor's Claude-hook replay
// of preToolUse (FU-122) is a fallback on the channel the registered gate
// already names, so the matrix keeps one cursor hook:preToolUse row (the
// registered gate's), while copilot-cli's replay on its own PascalCase event
// keeps its row.
func TestConformanceSameChannelReplayHasNoSecondRow(t *testing.T) {
	count := map[string]int{}
	for _, e := range ConformanceMatrix() {
		count[e.Client+" "+e.Channel]++
	}
	for key, want := range map[string]int{
		"cursor hook:preToolUse":      1,
		"copilot-cli hook:PreToolUse": 1,
		"copilot-cli hook:preToolUse": 1,
	} {
		if count[key] != want {
			t.Errorf("%s: %d rows, want %d", key, count[key], want)
		}
	}
	for key, n := range count {
		if n > 1 {
			t.Errorf("%s: %d rows of one channel", key, n)
		}
	}
}
