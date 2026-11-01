package guard

import "github.com/marmutapp/superbased-observer/internal/policy"

// Prompt-rule decision semantics (operator ruling 2026-10-02, audit
// proposal P8). A prompt rule resolves to one of three DECISIONS, and
// each decision means one thing to the developer, whichever tool they
// typed the prompt into:
//
//	flag -> a visible warning; the prompt goes through.
//	ask  -> the developer confirms, or re-enters the prompt, whichever
//	        the tool's seam allows.
//	deny -> the prompt is blocked.
//
// What the developer actually SEES also depends on the seam that saw
// the prompt (a hook dialect, the proxy, a near-pre-send hook that can
// only warn, or the post-hoc capture lane). promptActionTable is the ONE
// table that maps (decision x seam capability) onto a developer action.
// Every prompt lane resolves through ResolvePromptAction; none branches
// on a tool name (CLAUDE.md rules 3 and 5). A seam that cannot do what
// the decision asks for degrades along the decision's ladder to the
// strongest action it CAN do, and the degrade is recorded on the verdict
// (PromptVerdict.ActionDegradedFrom), never silent.

// PromptAction is what the developer experiences for one prompt verdict.
type PromptAction string

const (
	// PromptActionNone: nothing to do (an allow verdict).
	PromptActionNone PromptAction = ""
	// PromptActionWarn: a visible notice, the prompt goes through.
	PromptActionWarn PromptAction = "warn"
	// PromptActionConfirm: a native confirm dialog before send.
	PromptActionConfirm PromptAction = "confirm"
	// PromptActionReenter: the prompt is stopped with a message; sending
	// it again unchanged confirms (the reconsider-once flow).
	PromptActionReenter PromptAction = "re-enter"
	// PromptActionBlock: the prompt is stopped; no resend override.
	PromptActionBlock PromptAction = "block"
	// PromptActionFlagAfter: nothing could be shown before the prompt was
	// sent; the finding is recorded (and toasted) afterwards.
	PromptActionFlagAfter PromptAction = "flag-after"
	// PromptActionRedact: the prompt goes through with every secret span
	// replaced by its [REDACTED:type] marker, so the model never sees the
	// value. Only a seam that can rewrite the prompt (PromptSeamCaps.Redact)
	// does it, and only when the lane could mask every finding (the hook
	// lane verifies the masked text rescans clean before it offers Redact).
	PromptActionRedact PromptAction = "redact"
)

// PromptSeamCaps is what one prompt seam can do, resolved at the
// boundary (the hook dialect row, the proxy lane, the capture lane).
type PromptSeamCaps struct {
	// Warn: the seam can show the developer a notice and let the
	// prompt through.
	Warn bool
	// Confirm: the seam has a native confirm dialog for this event.
	Confirm bool
	// Reenter: the seam can stop the prompt with a message that tells
	// the developer to send it again to confirm.
	Reenter bool
	// Block: the seam can stop the prompt outright.
	Block bool
	// WarnIndirect: the seam's warning reaches the MODEL, not the
	// developer (Devin CLI's additionalContext), so a warn there still
	// toasts.
	WarnIndirect bool
	// BlockSilent: the seam's block carries no developer-visible reason
	// (Antigravity CLI's PreInvocation abort is atomic: no message can
	// accompany it), so the desktop toast is the developer's only signal
	// and a block there toasts whatever [guard.alerts].min_severity says.
	BlockSilent bool
	// Redact: the seam can replace the prompt text the model receives
	// (Poolside updated_prompt, commandcode transform). A lane sets it only
	// when it can actually mask THIS prompt (every finding is a certain
	// secret and the masked text rescans clean).
	Redact bool
}

// Capability sets for the lanes that are not hook dialects. Hook
// dialects carry their own row (internal/hook promptDialect.caps).
var (
	// PromptSeamProxy: the proxy answers the client's API call with an
	// error the client renders; sending the turn again confirms. It has
	// no pass-through notice channel (a forwarded request carries no
	// message to the developer).
	PromptSeamProxy = PromptSeamCaps{Reenter: true, Block: true}
	// PromptSeamCapture: the post-hoc capture lane sees the prompt after
	// it was sent; it can only record.
	PromptSeamCapture = PromptSeamCaps{}
	// PromptSeamWarnOnly: a near-pre-send hook that can surface a notice
	// to the model but cannot stop the model call (Devin CLI
	// UserPromptSubmit).
	PromptSeamWarnOnly = PromptSeamCaps{Warn: true, WarnIndirect: true}
)

// promptActionRow is one decision's ladder, strongest wanted action
// first. The first action the seam can do wins; PromptActionFlagAfter
// (always possible) ends every ladder.
//
// Ask's ladder puts block BEFORE warn: on a seam that can stop the
// prompt but has no confirm or resend flow, an ask stays at least as
// strong as asked (F5, the same rule ResolveEmission applies to tool
// calls). Redact sits right after block on the ask and deny ladders: a
// seam that cannot stop the prompt but can rewrite it keeps the value away
// from the model, which is closer to what was asked than a warning
// (hook-parity Lane B, 2026-10-03). Flag never escalates. Deny never degrades to confirm or
// re-enter (Sol A2-11): either would let the developer approve a hard
// denial by clicking through or resending. A deny the org made
// overridable has already been softened to ask (promptDecision) before
// it reaches this table, so that is the only way a block becomes
// approvable.
type promptActionRow struct {
	decision policy.Decision
	ladder   []PromptAction
}

var promptActionTable = []promptActionRow{
	{policy.DecisionFlag, []PromptAction{PromptActionWarn, PromptActionFlagAfter}},
	{policy.DecisionAsk, []PromptAction{PromptActionConfirm, PromptActionReenter, PromptActionBlock, PromptActionRedact, PromptActionWarn, PromptActionFlagAfter}},
	{policy.DecisionDeny, []PromptAction{PromptActionBlock, PromptActionRedact, PromptActionWarn, PromptActionFlagAfter}},
}

// can reports whether caps supports action.
func (c PromptSeamCaps) can(a PromptAction) bool {
	switch a {
	case PromptActionWarn:
		return c.Warn
	case PromptActionConfirm:
		return c.Confirm
	case PromptActionReenter:
		return c.Reenter
	case PromptActionBlock:
		return c.Block
	case PromptActionRedact:
		return c.Redact
	case PromptActionFlagAfter:
		return true
	default:
		return false
	}
}

// ResolvePromptAction maps a prompt decision onto the developer action
// the seam can deliver. degradedFrom is the action the decision wanted
// when the seam could not deliver it ("" when it could). An allow
// decision returns PromptActionNone.
func ResolvePromptAction(d policy.Decision, caps PromptSeamCaps) (action, degradedFrom PromptAction) {
	for _, row := range promptActionTable {
		if row.decision != d {
			continue
		}
		for _, a := range row.ladder {
			if caps.can(a) {
				if a != row.ladder[0] {
					return a, row.ladder[0]
				}
				return a, ""
			}
		}
	}
	return PromptActionNone, ""
}

// Stops reports whether the action holds the prompt back before send.
func (a PromptAction) Stops() bool {
	return a == PromptActionConfirm || a == PromptActionReenter || a == PromptActionBlock
}

// SuppressesToast reports whether the developer already got an in-band
// message they act on (a warning, a confirm, a resend instruction), so a
// desktop toast on top would be a duplicate. A block still toasts: some
// block-only dialects render no reason at all (Devin/Cascade), and a
// flag-after toast is the only signal the developer gets. A hook-lane
// redact also toasts: neither redact-capable hook (Poolside, commandcode)
// shows the developer the rewritten prompt, so the toast is how they learn
// their prompt was masked.
func (a PromptAction) SuppressesToast() bool {
	return a == PromptActionWarn || a == PromptActionConfirm || a == PromptActionReenter
}

// stopsPrompt reports whether the seam can hold a prompt back at all.
func (c PromptSeamCaps) stopsPrompt() bool {
	return c.Confirm || c.Reenter || c.Block
}

// redactWanted reports whether a verdict on a seam with caps is answered by
// masking the prompt, before the decision ladder runs. Two cases:
//
//   - the operator asked for masking ([guard.prompt] mode "redact"): a fresh
//     interrupt or an identical resend is masked on a seam that can rewrite,
//     even where the seam could also stop it, and even when the
//     reconsider-once flow had no session to key on (commandcode's
//     transformInput carries none): masking needs no resend story;
//   - a seam that cannot stop the prompt never told the developer how to
//     confirm a resend, so a "confirmed" identical resend there is masked
//     again rather than forwarded raw (the fresh one reaches redact through
//     the decision ladder).
//
// An operator grant (Approved), a guard error and anything not
// record-worthy never redact.
func (pv PromptVerdict) redactWanted(caps PromptSeamCaps) bool {
	if !caps.Redact || pv.GuardError || !pv.RecordWorthy() {
		return false
	}
	if pv.Outcome != PromptOutcomeBlocked && pv.Outcome != PromptOutcomeConfirmed {
		return false
	}
	if pv.RequestedMode == PromptModeRedact {
		return true
	}
	return pv.Outcome == PromptOutcomeConfirmed && !caps.stopsPrompt()
}

// promptRuleIDs are the rules the prompt lanes evaluate on a developer's
// own prompt.
var promptRuleIDs = []string{"R-172", "R-190"}

// PromptRulesWarnOnly returns the prompt rules an ORG bundle body writes
// with an explicit `enforce = false` (in rule-id order): on every prompt
// lane those rules only warn (evaluatePromptDecide's org cap). The org
// server's "Effective for a developer" preview reads it so the admin sees
// the same answer the node will act on. An unparseable body returns nil.
func PromptRulesWarnOnly(bundleTOML string) []string {
	pf, err := parsePolicyFile([]byte(bundleTOML), layerOrg)
	if err != nil {
		return nil
	}
	off := map[string]bool{}
	for _, ov := range pf.overrides {
		if ov.EnforceOff {
			off[ov.RuleID] = true
		}
	}
	out := []string{}
	for _, id := range promptRuleIDs {
		if off[id] {
			out = append(out, id)
		}
	}
	return out
}
