package integration

// OrgPromptJudgeReach says which seams bring a tool's prompts to the
// organization's coding-agent prompt judge on a managed node (P-228, lane
// adm-1 proxy lane and lane adm-2 hook lane; docs/guard.md "Org prompt
// admission judge"). Computed from the row, never stored and never a
// tool-name switch (CLAUDE.md #3).
type OrgPromptJudgeReach string

// The closed reach vocabulary.
const (
	// OrgPromptJudgeNone: no seam reaches the judge on the node.
	OrgPromptJudgeNone OrgPromptJudgeReach = "-"
	// OrgPromptJudgeHook: a wired prompt-gate hook asks the daemon and can
	// stop the prompt.
	OrgPromptJudgeHook OrgPromptJudgeReach = "hook"
	// OrgPromptJudgeHookWarn: a wired prompt-gate hook asks, but its seam
	// cannot stop the prompt, so a refusal is a warning.
	OrgPromptJudgeHookWarn OrgPromptJudgeReach = "hook (warn only)"
	// OrgPromptJudgeProxy: the proxy route Observer drives today judges the
	// prompt on the default provider lane.
	OrgPromptJudgeProxy OrgPromptJudgeReach = "proxy"
	// OrgPromptJudgeHookAndProxy: both; the hook judges first and the proxy
	// reuses its verdict for the same session and prompt.
	OrgPromptJudgeHookAndProxy OrgPromptJudgeReach = "hook+proxy"
	// OrgPromptJudgeHookWarnAndProxy: a warn-only hook plus the proxy,
	// which can still refuse.
	OrgPromptJudgeHookWarnAndProxy OrgPromptJudgeReach = "hook (warn only)+proxy"
)

// OrgPromptJudgeReach computes the row's reach: a WIRED prompt-gate binding
// is the hook lane (warn only when no wired prompt binding can deny, or the
// row's prompt seam is warn-only); a proxy route Observer drives today is the
// proxy lane.
func (c Capability) OrgPromptJudgeReach() OrgPromptJudgeReach {
	hook, canStop := false, false
	for _, b := range c.Hook.Bindings {
		if b.Cap != HookCapPromptGate || !b.Wired {
			continue
		}
		hook = true
		if b.HasDecision(HookDecisionDeny) {
			canStop = true
		}
	}
	if c.Hook.PromptWarnOnly {
		canStop = false
	}
	proxy := c.Proxy != nil
	switch {
	case hook && canStop && proxy:
		return OrgPromptJudgeHookAndProxy
	case hook && proxy:
		return OrgPromptJudgeHookWarnAndProxy
	case hook && canStop:
		return OrgPromptJudgeHook
	case hook:
		return OrgPromptJudgeHookWarn
	case proxy:
		return OrgPromptJudgeProxy
	default:
		return OrgPromptJudgeNone
	}
}
