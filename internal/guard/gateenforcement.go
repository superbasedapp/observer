package guard

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"syscall"

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
	// enforce, or at least one effective rule is per-rule enforced (in the
	// base engine, or in any trusted per-project file or applied project
	// recipe: a node-wide answer, RC-5).
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
// floor, or an unverifiable bundle on a managed node); the user policy, its
// applied recipe and the trusted per-project directory (its files and
// applied project recipes) can enforce the tool family (per-rule enforce). A
// node with none of them and no enforcing mode is not enforcing, so a slow
// derivation there never closes a gate. exists reports whether a path exists
// (injected I/O).
func PreliminaryGateEnforcement(c config.GuardConfig, home string, exists func(string) bool) GateEnforcement {
	e := ConfigGateEnforcement(c)
	if !c.Enabled || c.Mode == "off" || exists == nil {
		return e
	}
	if p := UserPolicyPath(c, home); p != "" && exists(p) {
		e.Tool = true
	}
	// An applied global recipe can enforce per rule like the user file.
	if p := UserRecipePolicyPath(c, home); p != "" && exists(p) {
		e.Tool = true
	}
	// So can a trusted per-project file or an applied project recipe
	// (RC-5): a project held at a level by explicit enforce rows. The
	// directory existing is the file-existence analog (the dashboard and
	// the recipe service create it on their first write); only the full
	// derivation reads the files in it.
	if d := expandUserPath(c.Rules.TrustedProjectDir, home); d != "" && exists(d) {
		e.Tool = true
	}
	if p := OrgBundlePath(c, home); p != "" && exists(p) {
		e.Tool = true
		e.Prompt = e.Prompt || (c.Prompt.Enabled && c.Prompt.HookLane)
	}
	return e
}

// maxTrustedScanFiles bounds the trusted-directory scan GateEnforcement
// runs; a directory holding more files counts as enforcing without
// reading the rest.
const maxTrustedScanFiles = 1000

// trustedLayerEnforces reports whether some trusted per-project policy file
// or applied project recipe in [guard.rules] trusted_project_dir carries a
// per-rule enforced row (`enforce = true` on a [[rule]] or an [[override]]):
// a project held at a level by explicit rows (a project recipe applied while
// the machine mode is observe holds the level's enforce decisions that way,
// docs/guard-recipes.md "A level in one project"). The posture the hooks read
// is per node, not per project, so one such project closes the tool gate
// node-wide (RC-5). A file that does not parse cannot enforce (its project
// engine drops it). A directory that exists but cannot be listed counts as
// enforcing: what it holds is unknown, not absent.
func (g *Guard) trustedLayerEnforces() bool {
	dir := expandUserPath(g.cfg.Rules.TrustedProjectDir, g.home)
	if dir == "" {
		return false
	}
	entries, err := g.readDir(dir)
	if err != nil {
		// Absent is absent: a missing directory, or a path with a file where
		// a parent directory would be (ENOTDIR, which Windows reports as not
		// found), holds no policy. Anything else is unknown, so enforcing.
		return !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR)
	}
	scanned := 0
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".toml") {
			continue
		}
		if scanned++; scanned > maxTrustedScanFiles {
			return true
		}
		raw, err := g.readFile(filepath.Join(dir, ent.Name()))
		if err != nil {
			continue
		}
		pf, err := parsePolicyFile(raw, layerTrustedProject)
		if err != nil {
			continue
		}
		if policyFileEnforces(pf) {
			return true
		}
	}
	return false
}

// policyFileEnforces reports whether pf carries a per-rule enforced row.
func policyFileEnforces(pf *policyFile) bool {
	for i := range pf.rules {
		if pf.rules[i].Enforced {
			return true
		}
	}
	for _, ov := range pf.overrides {
		if ov.Enforced {
			return true
		}
	}
	return false
}

// GateEnforcement is the live guard's answer: ConfigGateEnforcement plus
// what only the composed policy knows (per-rule enforcement on the tool
// family, in the base engine or in a trusted per-project file read off disk
// now, so a project recipe applied since the guard was built counts; an org
// cap that makes every prompt rule warn only; an org bundle that is present
// but unverifiable on a managed node). It is the ONE
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
	if !e.Tool {
		e.Tool = g.trustedLayerEnforces()
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
