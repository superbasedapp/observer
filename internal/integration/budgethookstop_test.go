package integration

import "testing"

// TestT519BudgetHookStopMatrix pins, for EVERY registry row, where an
// exhausted managed hard budget stops a direct-provider session through the
// tool's own hooks (T-519). A binding that becomes wired, loses its deny, or a
// new adapter row reclassifies here loudly; the per-tool coverage text in
// docs/adapter-parity.md ("Budget hook stop") is rendered from the same method.
func TestT519BudgetHookStopMatrix(t *testing.T) {
	t.Parallel()
	want := map[string]BudgetHookStop{
		// Prompt-submit AND pre-tool seams.
		"claude-code": BudgetHookStopPromptAndTool, "codex": BudgetHookStopPromptAndTool,
		"command-code": BudgetHookStopPromptAndTool, "cursor": BudgetHookStopPromptAndTool,
		"devin": BudgetHookStopPromptAndTool, "droid": BudgetHookStopPromptAndTool,
		"gemini-cli": BudgetHookStopPromptAndTool, "kilo-code-cli": BudgetHookStopPromptAndTool,
		"opencode": BudgetHookStopPromptAndTool, "poolside": BudgetHookStopPromptAndTool,
		"qoder": BudgetHookStopPromptAndTool, "qwen-code": BudgetHookStopPromptAndTool,
		"zcode": BudgetHookStopPromptAndTool, "muse": BudgetHookStopPromptAndTool,
		"kimi-code": BudgetHookStopPromptAndTool,
		// Guard-fix (2026-10-15): copilot userPromptSubmitted, the Cline plugin
		// beforeModel and agy's PreInvocation abort are prompt gates beside the
		// tool gates; a budget stop never taints an agy conversation.
		"copilot-cli": BudgetHookStopPromptAndTool, "cline-cli": BudgetHookStopPromptAndTool,
		"antigravity-cli": BudgetHookStopPromptAndTool,
		// Surface-gap lane w5-foreign: gates reached through another tool's
		// registration (the Antigravity App and IDE on antigravity-cli's
		// hooks.json; DeepSeek Harness's dsh-hooks-claude-code bridge on
		// Observer's Claude Code hooks).
		"antigravity": BudgetHookStopPromptAndTool, "deepseek": BudgetHookStopPromptAndTool,
		// Pre-tool seam only: the next tool call is denied, a prompt is not.
		"crush": BudgetHookStopTool,
		"goose": BudgetHookStopTool, "grok": BudgetHookStopTool,
		"hermes": BudgetHookStopTool, "junie": BudgetHookStopTool,
		"mistral-code": BudgetHookStopTool, "open-interpreter": BudgetHookStopTool,
		"pi": BudgetHookStopPromptAndTool, "kiro-cli": BudgetHookStopTool,
		// No wired pre-send seam: flagged after send (D-031) unless the proxy
		// or the process controller stops the session.
		"aider": BudgetHookStopNone, "chatgpt-web": BudgetHookStopNone,
		"claude-web": BudgetHookStopNone, "cline": BudgetHookStopNone, "copilot": BudgetHookStopNone,
		"copilot-web": BudgetHookStopNone, "cowork": BudgetHookStopNone,
		"freebuff": BudgetHookStopNone, "gemini-web": BudgetHookStopNone, "grokbot": BudgetHookStopNone,
		"kilo-code": BudgetHookStopNone,
		"kiro-crew": BudgetHookStopNone, "openclaw": BudgetHookStopNone,
		"perplexity-web": BudgetHookStopNone, "prime-agent": BudgetHookStopNone, "zed": BudgetHookStopNone,
		// The 2026-10-21 capture-only wave (no wired hook seam).
		"autohand": BudgetHookStopPromptAndTool, "ibm-bob": BudgetHookStopPromptAndTool, "cortex-code": BudgetHookStopPromptAndTool,
		"codebuddy": BudgetHookStopPromptAndTool, "deepagents-code": BudgetHookStopPromptAndTool, "dimcode": BudgetHookStopPromptAndTool,
		"dirac": BudgetHookStopPromptAndTool, "kimchi": BudgetHookStopPromptAndTool, "stakpak": BudgetHookStopNone, "vtcode": BudgetHookStopPromptAndTool,
	}
	for _, tool := range Tools() {
		c, ok := For(tool)
		if !ok {
			t.Fatalf("For(%q) missing", tool)
		}
		w, pinned := want[tool]
		if !pinned {
			t.Errorf("%s: no BudgetHookStop row pinned; add it (got %q)", tool, c.BudgetHookStop())
			continue
		}
		if got := c.BudgetHookStop(); got != w {
			t.Errorf("%s: BudgetHookStop = %q, want %q", tool, got, w)
		}
	}
	if len(want) != len(Tools()) {
		t.Errorf("pinned %d rows for %d registry tools", len(want), len(Tools()))
	}
}
