package guard

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// §4.6 layering & precedence: effective policy = merge(builtin, user,
// project, org bundle §14.2).
//
// Trust order (high → low): org > user > project > builtin. Strictness
// is one-way per layer: a layer may escalate any decision but may
// never relax a decision owned by a HIGHER-trust layer. Concretely:
//
//   - The org layer (G13) is a STRICTNESS FLOOR, not an owner: an org
//     override may only ESCALATE the effective decision — an org
//     override that would relax a built-in default is dropped with an
//     issue (the org server distributes minimum strictness; it cannot
//     weaken a node's posture, the same node-side-control philosophy
//     as the [org_client.share] privacy gates). Every rule the org
//     layer touches becomes FLOORED: no lower-trust layer may relax
//     below the org stance.
//   - The user layer outranks project and builtin: user overrides
//     apply unconditionally EXCEPT against the org floor (the
//     operator may relax a built-in on their own machine — the same
//     D2 philosophy that makes [guard.rules].disable a user-level
//     knob — but an enrolled agent cannot locally undercut what the
//     org floored; unenrolling removes the floor).
//   - The project layer is the LEAST trusted (the agent can edit the
//     project policy file — and R-161 flags exactly that): a project
//     override applies ONLY where it escalates the current effective
//     decision, never relaxes it, and never un-enforces. A dropped
//     project relaxation is recorded as a load issue (visible in
//     `observer guard status`), not an error — the rest of the file
//     still loads.
//   - [[rule]] definitions in any layer are additive new rules; they
//     can only ADD verdicts (a rule firing escalates, never
//     suppresses another rule), so they need no relaxation check
//     beyond the builtin-ID collision rejection in the parser. A
//     lower layer reusing an org rule ID adds a row; it cannot remove
//     the org row.

// stance is the effective per-rule decision reference the one-way
// checks compare against.
type stance struct {
	observe, enforce policy.Decision
	enforced         bool
}

// mergeState is the working state the per-layer fold functions share:
// the effective per-rule stance reference, the org floor set, and the
// accumulating engine inputs.
type mergeState struct {
	// effective is the per-rule decision reference the one-way checks
	// compare against, seeded from the built-in catalog.
	effective map[string]*stance
	// floor marks the rule IDs the org layer owns. A floored entry in
	// `effective` is the org stance (or stricter); user/project
	// overrides may never take a floored rule below it.
	floor     map[string]bool
	extra     []policy.Rule
	overrides []policy.Override
	issues    []string
	// disable accumulates the per-layer top-level `disable = [...]`
	// lists (today only the trusted-project layer contributes). The
	// caller (buildEngine) unions it into the per-project engine's
	// Config.Disabled — the merge is where the layer set is known.
	disable []string
}

// mergeLayers folds the parsed layers into the engine inputs:
// compiled extra rules (org first, then user, then project — table
// order is the final tie-break and higher trust should win full ties)
// and the effective override list, with one-way checks applied
// against the catalog reference and the org floor.
func mergeLayers(org, user, project, trusted *policyFile) (extra []policy.Rule, overrides []policy.Override, disable []string, issues []string) {
	// Multi-row IDs (R-152's write/read split) reduce to the STRICTEST
	// row per ID — for relaxation checks the conservative reference is
	// the strictest current stance (documented approximation: an
	// override on a split rule compares against its strictest row).
	m := &mergeState{effective: map[string]*stance{}, floor: map[string]bool{}}
	for _, info := range policy.Catalog() {
		s := m.effective[info.ID]
		if s == nil {
			m.effective[info.ID] = &stance{observe: info.Observe, enforce: info.Enforce}
			continue
		}
		s.observe = policy.StricterOf(s.observe, info.Observe)
		s.enforce = policy.StricterOf(s.enforce, info.Enforce)
	}
	m.applyOrg(org)
	m.applyUser(user)
	m.applyProject(project)
	// The trusted per-project layer folds LAST (guard-rule-management-ui
	// plan §3.2): applied after the in-repo project layer with
	// weaken-allowed semantics, so an operator relaxation lands over an
	// agent-writable escalation — but the org floor still hard-blocks.
	m.applyTrustedProject(trusted)
	return m.extra, m.overrides, m.disable, m.issues
}

// applyOrg folds the org layer (G13): rules join the table first
// (highest trust wins full ties) and every touched ID becomes FLOORED;
// org overrides are escalate-only against the built-in reference.
func (m *mergeState) applyOrg(org *policyFile) {
	if org == nil {
		return
	}
	m.extra = append(m.extra, org.rules...)
	for _, s := range org.rules {
		m.effective[s.ID] = &stance{observe: s.Observe, enforce: s.Enforce, enforced: s.Enforced}
		m.floor[s.ID] = true
	}
	for _, ov := range org.overrides {
		s := m.effective[ov.RuleID]
		if s == nil {
			// Unknown rule: surface at engine construction (the
			// override still goes through so policy.New errors loudly
			// with the same message lint shows).
			m.overrides = append(m.overrides, toPolicyOverride(ov))
			continue
		}
		if ov.HasDec && (ov.Decision < s.observe || ov.Decision < s.enforce) {
			m.issues = append(m.issues, fmt.Sprintf(
				"org override on %s dropped: %q would relax the effective decision (the org layer is a strictness floor; it may only escalate — spec §4.6/§14.2)",
				ov.RuleID, ov.Decision,
			))
			continue
		}
		m.apply(s, ov)
		m.floor[ov.RuleID] = true
	}
}

// applyUser folds the user layer: overrides apply unconditionally
// EXCEPT against the org floor.
func (m *mergeState) applyUser(user *policyFile) {
	if user == nil {
		return
	}
	m.extra = append(m.extra, user.rules...)
	for _, s := range user.rules {
		if m.floor[s.ID] {
			// A user rule reusing an org rule ID adds a row but cannot
			// lower the recorded floor stance — keep the stricter
			// reference for later override checks.
			f := m.effective[s.ID]
			f.observe = policy.StricterOf(f.observe, s.Observe)
			f.enforce = policy.StricterOf(f.enforce, s.Enforce)
			f.enforced = f.enforced || s.Enforced
			continue
		}
		m.effective[s.ID] = &stance{observe: s.Observe, enforce: s.Enforce, enforced: s.Enforced}
	}
	for _, ov := range user.overrides {
		m.noteUngrantableOverridable(ov)
		s := m.effective[ov.RuleID]
		if s == nil {
			m.overrides = append(m.overrides, toPolicyOverride(ov))
			continue
		}
		if m.floor[ov.RuleID] && ov.HasDec && (ov.Decision < s.observe || ov.Decision < s.enforce) {
			m.issues = append(m.issues, fmt.Sprintf(
				"user override on %s dropped: %q would relax the org policy floor (org > user — spec §4.6)",
				ov.RuleID, ov.Decision,
			))
			continue
		}
		// R-160/R-161 are the guard's own integrity rules: no below-org
		// layer may weaken them (treated like a floored rule REGARDLESS of
		// m.floor). Escalation still passes — a stricter decision is not
		// < the effective stance. policy.New is the hard backstop even if
		// this drop is somehow missed; recording the issue here is what
		// makes `observer guard status` surface WHY the edit did nothing
		// instead of it being a silent no-op.
		if policy.IsIntegrityRuleID(ov.RuleID) && ov.HasDec && (ov.Decision < s.observe || ov.Decision < s.enforce) {
			m.issues = append(m.issues, fmt.Sprintf(
				"user override on %s dropped: %s is an integrity rule and cannot be relaxed below the org (guard-rule-management-ui plan §3.4 / §2)",
				ov.RuleID, ov.RuleID,
			))
			continue
		}
		// User outranks builtin + project: apply unconditionally (the
		// org floor, when present, was checked above).
		m.apply(s, ov)
	}
}

// applyProject folds the project layer: escalate-only against the
// effective reference (which already carries the org floor — org
// applied first).
func (m *mergeState) applyProject(project *policyFile) {
	if project == nil {
		return
	}
	m.extra = append(m.extra, project.rules...)
	for _, ov := range project.overrides {
		m.noteUngrantableOverridable(ov)
		s := m.effective[ov.RuleID]
		if s == nil {
			m.overrides = append(m.overrides, toPolicyOverride(ov))
			continue
		}
		if ov.HasDec && (ov.Decision < s.observe || ov.Decision < s.enforce) {
			m.issues = append(m.issues, fmt.Sprintf(
				"project override on %s dropped: %q would relax the effective decision (project layer may only escalate — spec §4.6)",
				ov.RuleID, ov.Decision,
			))
			continue
		}
		m.apply(s, ov)
	}
}

// noteUngrantableOverridable records the load issue for an
// `overridable = true` key on a layer that cannot grant it. ONLY the
// org layer grants overridability (the org bundle is the authority
// that withheld or allowed the block in the first place); a user or
// project file asking for it is a policy-authoring mistake, reported
// the same way a dropped relaxation is — loudly, without failing the
// rest of the file. `observer guard lint` surfaces the identical
// string.
func (m *mergeState) noteUngrantableOverridable(ov rawOverride) {
	if !ov.Overridable {
		return
	}
	m.issues = append(m.issues, fmt.Sprintf(
		"%s override on %s: `overridable` ignored — only the org policy bundle grants a per-rule override (spec §4.6/§14.2)",
		ov.Layer, ov.RuleID,
	))
}

// applyTrustedProject folds the dashboard-authored, daemon-local trusted
// per-project layer (guard-rule-management-ui plan §3.2). It mirrors
// applyUser (NOT applyProject): overrides apply UNCONDITIONALLY except
// against the org floor — this layer sits under ~/.observer, inside
// R-160's deny surface, so the agent cannot write it, and the operator
// may relax/disable a rule for a specific project. An org-floored rule
// can NEVER be relaxed here (the floor map, populated by applyOrg, still
// hard-blocks). Its top-level `disable` list is threaded onto
// mergeState.disable for buildEngine to union into Config.Disabled.
//
// Because it folds AFTER applyProject and its overrides append last,
// policy.New (which applies overrides in order, last-wins) lets a trusted
// relaxation override both the built-in default and any in-repo project
// escalation of the same rule — the operator layer outranks the
// agent-writable one, while both stay below the org floor.
func (m *mergeState) applyTrustedProject(trusted *policyFile) {
	if trusted == nil {
		return
	}
	// A trusted `disable` is subject to the SAME org floor as a trusted
	// override: disabling an org-floored rule would remove it entirely
	// (policy.New's disable path only exempts protected BUDGET rows), so
	// it would silently defeat the org floor for non-budget floored rules
	// (e.g. R-160/R-161 if the org floored them). Drop those IDs with a
	// recorded issue; a non-floored built-in stays disable-able (the
	// operator's per-project (c)/(d) power — the ONLY hard limit is the
	// org floor).
	for _, id := range trusted.disable {
		if m.floor[id] {
			m.issues = append(m.issues, fmt.Sprintf(
				"trusted project disable of %s dropped: an org-floored rule cannot be disabled (org > trusted project — spec §4.6)", id))
			continue
		}
		// R-160/R-161 are the guard's own integrity rules — never
		// disable-able below the org, treated like a floored ID REGARDLESS
		// of m.floor. Dropping R-160 here would let an agent write
		// ~/.observer/** (including the trusted layer itself) freely.
		// policy.New's disable filter is the hard backstop; this recorded
		// issue makes the drop visible in `observer guard status` and the
		// LintTrustedProject save-gate instead of a silent no-op.
		if policy.IsIntegrityRuleID(id) {
			m.issues = append(m.issues, fmt.Sprintf(
				"trusted project disable of %s dropped: %s is an integrity rule and cannot be disabled below the org (guard-rule-management-ui plan §3.4 / §2)", id, id))
			continue
		}
		m.disable = append(m.disable, id)
	}
	m.extra = append(m.extra, trusted.rules...)
	for _, s := range trusted.rules {
		if m.floor[s.ID] {
			// A trusted rule reusing an org rule ID adds a row but cannot
			// lower the recorded floor stance (same as applyUser).
			f := m.effective[s.ID]
			f.observe = policy.StricterOf(f.observe, s.Observe)
			f.enforce = policy.StricterOf(f.enforce, s.Enforce)
			f.enforced = f.enforced || s.Enforced
			continue
		}
		m.effective[s.ID] = &stance{observe: s.Observe, enforce: s.Enforce, enforced: s.Enforced}
	}
	for _, ov := range trusted.overrides {
		m.noteUngrantableOverridable(ov)
		s := m.effective[ov.RuleID]
		if s == nil {
			m.overrides = append(m.overrides, toPolicyOverride(ov))
			continue
		}
		// For a floored rule this drops a trusted relaxation whenever it
		// falls below the CURRENT effective stance (s), which may already
		// sit ABOVE the org floor because a user / in-repo layer escalated
		// it. That is deliberately conservative: it can never take a rule
		// below the org floor (the whole point), and refusing to relax
		// below a stricter local stance too is a safe v1 simplification,
		// not a behavior we need to loosen.
		if m.floor[ov.RuleID] && ov.HasDec && (ov.Decision < s.observe || ov.Decision < s.enforce) {
			m.issues = append(m.issues, fmt.Sprintf(
				"trusted project override on %s dropped: %q would relax the org policy floor (org > trusted project — spec §4.6)",
				ov.RuleID, ov.Decision,
			))
			continue
		}
		// R-160/R-161 are the guard's own integrity rules: no below-org
		// layer may weaken them (treated like a floored rule REGARDLESS of
		// m.floor). Escalation still passes. policy.New is the hard
		// backstop; the recorded issue surfaces the drop in the
		// LintTrustedProject save-gate and `observer guard status`.
		if policy.IsIntegrityRuleID(ov.RuleID) && ov.HasDec && (ov.Decision < s.observe || ov.Decision < s.enforce) {
			m.issues = append(m.issues, fmt.Sprintf(
				"trusted project override on %s dropped: %s is an integrity rule and cannot be relaxed below the org (guard-rule-management-ui plan §3.4 / §2)",
				ov.RuleID, ov.RuleID,
			))
			continue
		}
		// Trusted project outranks built-in + in-repo project: apply
		// unconditionally (the org floor, when present, was checked above).
		m.apply(s, ov)
	}
}

// apply commits an accepted override to the stance reference and the
// engine input list.
func (m *mergeState) apply(s *stance, ov rawOverride) {
	if ov.HasDec {
		s.observe, s.enforce = ov.Decision, ov.Decision
	}
	s.enforced = s.enforced || ov.Enforced
	m.overrides = append(m.overrides, toPolicyOverride(ov))
}

// toPolicyOverride converts a parsed override into the engine's
// mechanical form.
func toPolicyOverride(ov rawOverride) policy.Override {
	out := policy.Override{
		RuleID:   ov.RuleID,
		Enforced: ov.Enforced,
		Source:   ov.Layer,
		// Structural gate, not a caller courtesy: overridability is
		// carried ONLY off the org layer, so no other call path can
		// grant it even by mistake.
		Overridable: ov.Overridable && ov.Layer == layerOrg,
	}
	if ov.HasDec {
		d := ov.Decision
		out.Decision = &d
	}
	return out
}
