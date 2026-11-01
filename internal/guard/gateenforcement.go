package guard

import (
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// GateEnforcement reports, per hook gate family, whether the guard would
// ENFORCE a verdict there (stop the call or the prompt) rather than only
// record or warn. It is the one answer the hook failure semantics (hook
// parity audit section 5.7, docs/guard.md "Hook failure semantics") read:
// a gate hook that fails while its family is enforced fails closed.
//
// The two families are decided independently on purpose (Sol A2-01): the
// prompt lane enforces on its own ([guard.prompt].enforce_independent,
// default true) while the global guard is in observe mode, and that must
// close the prompt gate without closing the tool gate.
type GateEnforcement struct {
	// Tool is true when tool-call verdicts can block: the global mode is
	// enforce, or at least one effective rule is per-rule enforced.
	Tool bool
	// Prompt is true when a prompt-submit hook can stop a prompt: the
	// prompt lane evaluates on hooks, some configured prompt mode is
	// stronger than warn, and prompt enforcement is active (independent
	// prompt enforcement or global enforce).
	Prompt bool
	// UserPolicyFailClosed is the organization's T-327 choice as it applies
	// on this node (Guard.OrgFallbacks): while the user guard-policy.toml
	// does not load, every ENFORCED gate family fails closed. It is a MODE,
	// not a verdict: whether the file loads is checked when a gate hook runs
	// (guard.CheckUserPolicy), so a fix takes effect at once. Only ever true
	// while some family is enforced.
	UserPolicyFailClosed bool
}

// Any reports whether some gate family is enforced.
func (e GateEnforcement) Any() bool { return e.Tool || e.Prompt }

// ConfigGateEnforcement derives GateEnforcement from configuration alone:
// the hook's fallback when no daemon posture is available. It cannot see
// org policy or per-rule enforcement (those live in policy files the
// fallback does not load), so the tool family is closed only by
// mode = "enforce"; the prompt family uses the same rule the live prompt
// lane applies.
func ConfigGateEnforcement(c config.GuardConfig) GateEnforcement {
	if !c.Enabled || c.Mode == "off" {
		return GateEnforcement{}
	}
	return GateEnforcement{
		Tool:   c.Mode == "enforce",
		Prompt: promptHookLaneCanStop(c),
	}
}

// PreliminaryGateEnforcement is the hook's interim answer while the full
// derivation (a guard built over the org bundle and the user policy, which
// can cost a database open) has not finished (T-381, D-188 / D-041 /
// D-150): ConfigGateEnforcement, except that a family a policy FILE could
// enforce counts as enforced while that file exists, because only the full
// derivation can read it. The org bundle can enforce both families (an org
// floor, or an unverifiable bundle on a managed node); the user policy can
// enforce the tool family (per-rule enforce). A node with neither file and
// no enforcing mode is not enforcing, so a slow derivation there never
// closes a gate. exists reports whether a path exists (injected I/O).
func PreliminaryGateEnforcement(c config.GuardConfig, home string, exists func(string) bool) GateEnforcement {
	e := ConfigGateEnforcement(c)
	if !c.Enabled || c.Mode == "off" || exists == nil {
		return e
	}
	if p := UserPolicyPath(c, home); p != "" && exists(p) {
		e.Tool = true
	}
	if p := OrgBundlePath(c, home); p != "" && exists(p) {
		e.Tool = true
		e.Prompt = e.Prompt || (c.Prompt.Enabled && c.Prompt.HookLane)
	}
	return e
}

// GateEnforcement is the live guard's answer: ConfigGateEnforcement plus
// what only the composed policy knows (per-rule enforcement on the tool
// family, an org cap that makes every prompt rule warn only, an org bundle
// that is present but unverifiable on a managed node). It is the ONE
// enforcement derivation behind the hook failure posture: the daemon's
// posture writer and the hook's config fallback both build a guard from
// the same inputs and call it (cmd/observer guardGateEnforcement).
func (g *Guard) GateEnforcement() GateEnforcement {
	e := ConfigGateEnforcement(g.cfg)
	if !g.cfg.Enabled || g.cfg.Mode == "off" {
		return e
	}
	es := g.set.Load()
	if !e.Tool {
		e.Tool = es.mode == policy.ModeEnforce
	}
	if !e.Tool {
		for _, r := range es.base().RuleInfos() {
			if r.Enforced {
				e.Tool = true
				break
			}
		}
	}
	if e.Prompt {
		capped := true
		for _, id := range promptRuleIDs {
			if !es.promptRuleFlagOnly(id) {
				capped = false
				break
			}
		}
		if capped {
			e.Prompt = false
		}
	}
	// An org-pinned prompt-rule decision floors the local prompt mode in the
	// live lane (promptModeFloor), so it must also close the hook's failure
	// posture: with a local "warn" and an org deny the live verdict blocks,
	// and a hook timeout or crash must not then fail open (integration
	// security review, 2026-10-15).
	if !e.Prompt && g.cfg.Prompt.Enabled && g.cfg.Prompt.HookLane && promptEnforceActiveFor(g.cfg) {
		e.Prompt = es.orgPromptFloorStops()
	}
	// A cached org bundle that exists but does not verify hides the org's
	// floor. On a managed node (or one whose tenancy is unresolved in this
	// process: the conservative reading orgLocksEveryRule already applies)
	// it counts as ENFORCING, so neither the daemon's posture nor the
	// hook's fallback reads an unknown org policy as "off". On an
	// individual node it counts as absent (Sol A2-02 follow-up).
	if g.orgBundleRejected.Load() && g.orgLocksEveryRule() {
		e.Tool = true
		e.Prompt = e.Prompt || (g.cfg.Prompt.Enabled && g.cfg.Prompt.HookLane)
	}
	// The org's invalid-user-policy MODE applies only when the bundle can be
	// attributed to this node: under the enrolment key pin, or with the
	// tenancy resolved (review M2-14). A process with neither (a hook whose
	// store cannot be opened) loaded the bundle on its own signature and
	// reads tenancy as managed; applying the org's fail_closed choice there
	// would close an individual node's gates on the org's say. The families
	// above keep the conservative reading (D-194); only the mode is withheld.
	e.UserPolicyFailClosed = e.Any() && g.orgPolicyAttributable() && g.OrgFallbacks().FailClosedOnInvalidUserPolicy()
	return e
}

// orgPolicyAttributable reports whether the loaded org bundle is tied to
// this node: verified under the enrolment key pin, or with the tenancy
// lookup wired.
func (g *Guard) orgPolicyAttributable() bool {
	return g.orgKeyPinHash != "" || g.managedTenancy.Load() != nil
}

// promptEnforceActiveFor is the prompt lane's own enforce/observe answer
// (FIX-8): independent prompt enforcement, or the global enforce mode.
// Guard.promptEnforceActive and the gate posture both read it.
func promptEnforceActiveFor(c config.GuardConfig) bool {
	return c.Prompt.EnforceIndependent || c.Mode == "enforce"
}

// promptHookLaneCanStop reports whether a prompt-submit hook can stop a
// prompt under c: the lane is on for hooks, prompt enforcement is active,
// and the global prompt mode or some per-detector mode (the mode is a
// floor; a stricter detector override wins, but nothing re-enables a
// global "off") is stronger than warn.
func promptHookLaneCanStop(c config.GuardConfig) bool {
	p := c.Prompt
	if !p.Enabled || !p.HookLane || !promptEnforceActiveFor(c) {
		return false
	}
	global, ok := parsePromptMode(p.Mode)
	if !ok || global == PromptModeOff {
		return false
	}
	if promptModeStops(global) {
		return true
	}
	for _, v := range p.Detectors {
		if m, ok := parsePromptMode(v); ok && promptModeStops(m) {
			return true
		}
	}
	return false
}

// promptModeStops reports whether a prompt mode can hold a prompt back.
func promptModeStops(m PromptMode) bool {
	return promptModeRank[m] > promptModeRank[PromptModeWarn]
}
