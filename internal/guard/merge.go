package guard

import (
	"fmt"
	"strings"

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
//     beyond the builtin-ID collision rejection in the parser. An id
//     belongs to the most trusted layer that defines it (ruleIDOwners,
//     RC-1/RC-2): a lower layer's row reusing it is dropped ALONE with a
//     load issue. Before that rule a reused id added a row, and a row
//     that disagreed on category or severity failed engine construction,
//     which the fallback ladders answered by dropping a whole layer (the
//     org floor, or the trusted project layer and its recipe).
//   - An override on a rule a disable removes (the config's
//     [guard.rules] disable, or the trusted project layer's own list) is
//     dropped alone with a load issue (RC-4): there is no row to tune, and
//     policy.New refuses such an override, which used to cost the whole
//     layer it came from.

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
	// cfgOff and layerOff are the ids the engine's disable filter will be
	// asked to remove: the config-level [guard.rules] disable list and the
	// trusted project layer's own list. removedBy reads them.
	cfgOff, layerOff map[string]bool
	// managed is the managed-node lock (managedlock.go): on a managed node,
	// with or without an org layer in force, every built-in and rule-pack
	// rule counts as floored for the below-org layers, so no local layer may
	// relax or disable it. nil on every other node, where only the rules the
	// org layer names are floored.
	managed *managedRuleLock
	// track asks the folds to record an outcome per below-org change
	// (outcomes). Only the local-change report (localchanges.go) sets it,
	// so the report reads what the merge DID rather than re-deriving it.
	track    bool
	outcomes []mergeOutcome
}

// mergeOutcome is what the merge did with one below-org change: a [[rule]]
// row, an [[override]] row or a trusted-project disable of one layer.
// loosens is judged by relaxes against the reference the merge's own checks
// use at that point of the fold; applied is whether the change reached the
// engine inputs (a row claimRuleIDs kept, an override appended, a disable
// kept).
type mergeOutcome struct {
	layer    string
	kind     string // mergeKindRule, mergeKindOverride or mergeKindDisable
	ruleID   string
	rule     *policy.Rule
	override *rawOverride
	loosens  bool
	applied  bool
}

// The mergeOutcome kinds (the wire's orgcontract.LocalRuleKind* values).
const (
	mergeKindRule     = "rule"
	mergeKindOverride = "override"
	mergeKindDisable  = "disable"
)

// note records one outcome when the merge is tracked.
func (m *mergeState) note(o mergeOutcome) {
	if m.track {
		m.outcomes = append(m.outcomes, o)
	}
}

// decisionRelaxes reports whether ov's decision sits below the stance s on
// either seam. It is the ONE comparison every one-way check of the merge and
// the local-change report make (review finding 2, 2026-11-12). A nil stance
// (a rule the layer set does not load) is never relaxed by a decision.
func decisionRelaxes(s *stance, ov rawOverride) bool {
	return s != nil && ov.HasDec && (ov.Decision < s.observe || ov.Decision < s.enforce)
}

// relaxes reports whether ov loosens its rule against the merge's current
// reference (the stance after the org layer and every layer folded before
// ov's): a decision below it, or an explicit `enforce = false`, which caps
// the rule at flag.
func (m *mergeState) relaxes(ov rawOverride) bool {
	return ov.EnforceOff || decisionRelaxes(m.effective[ov.RuleID], ov)
}

// foldTracked folds one override of layer through fold and, on a tracked
// merge, records whether it loosens (judged before the fold moves the
// reference) and whether fold kept it.
func (m *mergeState) foldTracked(layer string, ov rawOverride, fold func(rawOverride)) {
	loosens := m.relaxes(ov)
	n := len(m.overrides)
	fold(ov)
	if m.track {
		cp := ov
		m.note(mergeOutcome{
			layer: layer, kind: mergeKindOverride, ruleID: ov.RuleID, override: &cp,
			loosens: loosens, applied: len(m.overrides) > n,
		})
	}
}

// floored reports whether no below-org layer may relax or disable id: the
// org layer names it, or the managed-node lock covers it.
func (m *mergeState) floored(id string) bool {
	return m.floor[id] || m.managed.locks(id)
}

// floorWords names why a floored id may not be relaxed, for a load issue:
// the org layer's own floor, or the managed-node lock.
func (m *mergeState) floorWords(id string) string {
	if m.floor[id] {
		return "the org policy floor"
	}
	return managedLockWords
}

// floorRuleWords is floorWords for a sentence that names the rule itself
// ("cannot be disabled", "at flag").
func (m *mergeState) floorRuleWords(id string) string {
	if m.floor[id] {
		return "an org-floored rule"
	}
	return managedLockWords
}

// ruleIDOwners is the [[rule]] id ownership order (RC-1, RC-2), most
// trusted first, after the built-in catalog and the module's rule pack: an
// id belongs to the first layer here that defines it, and a later layer's
// row reusing it is dropped alone with a load issue. Within one layer (the
// own file folded with its applied recipe, or the repository files of
// several checkouts) the rows stand as the layer folded them. This is the
// TRUST order, not the fold order mergeLayersWithDisable applies the
// layers in (org, user, project, trusted).
var ruleIDOwners = []struct {
	layer string
	label string
}{
	{layerOrg, "the organization's policy"},
	{layerUser, "the user policy (or its applied recipe)"},
	{layerTrustedProject, "the trusted project policy (or its applied recipe)"},
	{layerProject, "the repository's project policy file"},
}

// claimRuleIDs applies ruleIDOwners to one layer set and returns the user,
// project and trusted layers without the rows whose id a more trusted
// source already defines (the built-in catalog, the rule pack, or a layer
// above in ruleIDOwners), each drop recorded as an issue. The org layer's
// own rows are never dropped here. Inputs are not modified; a layer with
// nothing to drop is returned as is.
func (m *mergeState) claimRuleIDs(pack []policy.Rule, org, user, project, trusted *policyFile) (u, p, t *policyFile) {
	// The built-in catalog owns its ids too; the parser already refuses a
	// built-in id in every layer, so only the pack and the layers are
	// listed here.
	owner := map[string]string{}
	for i := range pack {
		if _, ok := owner[pack[i].ID]; !ok {
			owner[pack[i].ID] = "the code security rule pack"
		}
	}
	files := map[string]*policyFile{layerOrg: org, layerUser: user, layerProject: project, layerTrustedProject: trusted}
	for _, o := range ruleIDOwners {
		pf := files[o.layer]
		if pf == nil {
			continue
		}
		if o.layer != layerOrg {
			pf = m.dropReusedRuleIDs(pf, o.layer, owner)
			files[o.layer] = pf
		}
		// The layer's own ids are claimed only after the whole layer was
		// checked, so a layer's folded rows never drop each other.
		for i := range pf.rules {
			if _, ok := owner[pf.rules[i].ID]; !ok {
				owner[pf.rules[i].ID] = o.label
			}
		}
	}
	return files[layerUser], files[layerProject], files[layerTrustedProject]
}

// dropReusedRuleIDs returns pf without the [[rule]] rows whose id owner
// already names, one issue per drop (the withOrgProjectLayers wording).
func (m *mergeState) dropReusedRuleIDs(pf *policyFile, layer string, owner map[string]string) *policyFile {
	var kept []policy.Rule
	dropped := false
	for i := range pf.rules {
		by, ok := owner[pf.rules[i].ID]
		if !ok && policy.IsBuiltinRuleID(pf.rules[i].ID) {
			by, ok = "a built-in rule", true
		}
		m.note(mergeOutcome{layer: layer, kind: mergeKindRule, ruleID: pf.rules[i].ID, rule: &pf.rules[i], applied: !ok})
		if ok {
			m.issues = append(m.issues, fmt.Sprintf(
				"%s rule %s dropped: the id is already defined by %s (give the rule its own id; use [[override]] to tune the existing rule)",
				ruleLayerLabel(layer), pf.rules[i].ID, by,
			))
			dropped = true
			continue
		}
		kept = append(kept, pf.rules[i])
	}
	if !dropped {
		return pf
	}
	out := *pf
	out.rules = kept
	return &out
}

// ruleLayerLabel names the layer a dropped row came from, in the merge's
// "<layer> override on ..." voice.
func ruleLayerLabel(layer string) string {
	switch layer {
	case layerProject:
		return "project (repository file)"
	case layerTrustedProject:
		return "trusted project"
	case "":
		return "policy"
	}
	return layer
}

// removedBy reports whether the engine will hold no row for id because a
// disable removes it, and which list does: [guard.rules] disable or the
// trusted project layer's own `disable`. An org-floored rule and an
// integrity rule survive every below-org disable (policy.New keeps them),
// so neither is removed. A budget row only the org's budget protection
// keeps reads as removed: that drops at most one tuning of a row the org
// already holds at deny, and never fails the build. Valid once applyOrg
// has filled the floor.
func (m *mergeState) removedBy(id string) (string, bool) {
	if m.floored(id) || policy.IsIntegrityRuleID(id) {
		return "", false
	}
	switch {
	case m.cfgOff[id]:
		return "[guard.rules] disable", true
	case m.layerOff[id]:
		return "the trusted project policy's disable list", true
	}
	return "", false
}

// dropRemovedTarget drops (with a recorded issue) an override whose rule a
// disable removes (RC-4). It reports whether ov was dropped.
func (m *mergeState) dropRemovedTarget(ov rawOverride) bool {
	by, ok := m.removedBy(ov.RuleID)
	if !ok {
		return false
	}
	m.issues = append(m.issues, fmt.Sprintf(
		"%s override on %s dropped: %s is disabled by %s, so there is no row to tune",
		ruleLayerLabel(ov.Layer), ov.RuleID, ov.RuleID, by,
	))
	return true
}

// mergeLayers folds the parsed layers into the engine inputs:
// compiled extra rules (org first, then user, then project — table
// order is the final tie-break and higher trust should win full ties)
// and the effective override list, with one-way checks applied
// against the catalog reference and the org floor.
func mergeLayers(org, user, project, trusted *policyFile) (extra []policy.Rule, overrides []policy.Override, disable []string, issues []string) {
	return mergeLayersWithPack(nil, org, user, project, trusted)
}

// mergeLayersWithPack is mergeLayers with a module's rule pack composed in
// (security pillar plan section 4.7 item 1): pack rows join the table
// before every layer's rules and seed the effective reference like
// built-ins, so a user override and the org floor may tune them and the
// project layer may only escalate them. An override naming a pillar rule
// id (S-7xx) whose pack is not loaded is dropped with a load issue instead
// of failing engine construction, because a skipped module must not break
// guard.
func mergeLayersWithPack(pack []policy.Rule, org, user, project, trusted *policyFile) (extra []policy.Rule, overrides []policy.Override, disable []string, issues []string) {
	return mergeLayersWithDisable(pack, nil, org, user, project, trusted)
}

// mergeLayersWithDisable is mergeLayersWithPack with the config-level
// [guard.rules] disable list the engine will apply (cfgDisable), so an
// override on a rule that list removes is dropped alone instead of failing
// engine construction (RC-4). The engine build funnel and the status checks
// that must agree with it pass the config list; the authoring lints pass
// nil (they have no config).
func mergeLayersWithDisable(pack []policy.Rule, cfgDisable []string, org, user, project, trusted *policyFile) (extra []policy.Rule, overrides []policy.Override, disable []string, issues []string) {
	return mergeLayersLocked(pack, cfgDisable, nil, org, user, project, trusted)
}

// mergeLayersLocked is mergeLayersWithDisable under an optional managed-node
// lock (managedlock.go; nil = none): the engine build funnel passes the lock
// a managed node resolves (with or without an org layer in force), so every
// built-in and rule-pack rule is floored for the user and trusted project
// layers too. The authoring lints pass nil.
func mergeLayersLocked(pack []policy.Rule, cfgDisable []string, lock *managedRuleLock, org, user, project, trusted *policyFile) (extra []policy.Rule, overrides []policy.Override, disable []string, issues []string) {
	m := &mergeState{effective: map[string]*stance{}, floor: map[string]bool{}, cfgOff: setOfIDs(cfgDisable), managed: lock}
	m.fold(pack, org, user, project, trusted)
	return m.extra, m.overrides, m.disable, m.issues
}

// mergeOutcomes runs the same merge as mergeLayersLocked and returns what it
// did with every below-org change (mergeOutcome), in fold order. The
// local-change report reads it, so the report and the engine cannot judge a
// change differently.
func mergeOutcomes(pack []policy.Rule, cfgDisable []string, lock *managedRuleLock, org, user, project, trusted *policyFile) []mergeOutcome {
	m := &mergeState{effective: map[string]*stance{}, floor: map[string]bool{}, cfgOff: setOfIDs(cfgDisable), managed: lock, track: true}
	m.fold(pack, org, user, project, trusted)
	return m.outcomes
}

// fold is the merge body mergeLayersLocked and mergeOutcomes share.
func (m *mergeState) fold(pack []policy.Rule, org, user, project, trusted *policyFile) {
	// Multi-row IDs (R-152's write/read split) reduce to the STRICTEST
	// row per ID — for relaxation checks the conservative reference is
	// the strictest current stance (documented approximation: an
	// override on a split rule compares against its strictest row).
	if trusted != nil {
		m.layerOff = setOfIDs(trusted.disable)
	}
	// Id ownership first, on the layers as given, so every fold below sees
	// only rows whose id is theirs (RC-1, RC-2).
	user, project, trusted = m.claimRuleIDs(pack, org, user, project, trusted)
	// The trusted layer folds after the repository file but outranks it:
	// its rules' stances join the reference BEFORE the repository file is
	// folded, so a repository override on a trusted-layer rule (a project
	// recipe's RC-* row, say) is escalate-only like an override on any
	// other rule. Before this, such an override found no reference, skipped
	// the one-way checks and could set the rule to allow or cap it at flag
	// (RC-1, the override half).
	if trusted != nil {
		for _, s := range trusted.rules {
			m.effective[s.ID] = &stance{observe: s.Observe, enforce: s.Enforce, enforced: s.Enforced}
		}
	}
	for _, info := range policy.Catalog() {
		s := m.effective[info.ID]
		if s == nil {
			m.effective[info.ID] = &stance{observe: info.Observe, enforce: info.Enforce}
			continue
		}
		s.observe = policy.StricterOf(s.observe, info.Observe)
		s.enforce = policy.StricterOf(s.enforce, info.Enforce)
	}
	for _, r := range pack {
		if s := m.effective[r.ID]; s != nil {
			s.observe = policy.StricterOf(s.observe, r.Observe)
			s.enforce = policy.StricterOf(s.enforce, r.Enforce)
			continue
		}
		m.effective[r.ID] = &stance{observe: r.Observe, enforce: r.Enforce, enforced: r.Enforced}
	}
	m.extra = append(m.extra, pack...)
	m.applyOrg(org)
	m.applyUser(user)
	m.applyProject(project)
	// The trusted per-project layer folds LAST (guard-rule-management-ui
	// plan §3.2): applied after the in-repo project layer with
	// weaken-allowed semantics, so an operator relaxation lands over an
	// agent-writable escalation — but the org floor still hard-blocks.
	m.applyTrustedProject(trusted)
}

// setOfIDs is a membership set of ids (nil for an empty list).
func setOfIDs(ids []string) map[string]bool {
	if len(ids) == 0 {
		return nil
	}
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}

// configDisableOrgFloorIssues reports each config-level [guard.rules]
// disable entry that names a rule the org layer defines or tunes
// (OSH-R-014). That list never passes through the merge (it goes straight
// to policy.Config.Disabled), and policy.New keeps the row as the hard
// backstop; this note is what makes `observer guard status` say why the
// disable did nothing instead of it being a silent no-op.
func configDisableOrgFloorIssues(org *policyFile, disable []string) []string {
	floor := orgLayerIDs(org)
	if len(floor) == 0 || len(disable) == 0 {
		return nil
	}
	var issues []string
	for _, id := range disable {
		if floor[id] {
			issues = append(issues, fmt.Sprintf(
				"[guard.rules] disable of %s ignored: your organization's policy sets this rule, and a local config may not remove it (org > config - spec §4.6, OSH-R-014)", id,
			))
		}
	}
	return issues
}

// orgLayerIDs is the set of rule ids the org layer defines or tunes, the
// floor policy.New keeps against every below-org disable (OSH-R-014).
func orgLayerIDs(org *policyFile) map[string]bool {
	if org == nil {
		return nil
	}
	floor := map[string]bool{}
	for _, r := range org.rules {
		floor[r.ID] = true
	}
	for _, ov := range org.overrides {
		floor[ov.RuleID] = true
	}
	return floor
}

// effectiveConfigDisable is the config-level disable list as the engine
// applies it: without the org-floored ids policy.New keeps anyway, so the
// guard's own "which rows are loaded" reasoning agrees with the engine.
func effectiveConfigDisable(org *policyFile, disable []string) []string {
	floor := orgLayerIDs(org)
	if len(floor) == 0 {
		return disable
	}
	out := make([]string, 0, len(disable))
	for _, id := range disable {
		if !floor[id] {
			out = append(out, id)
		}
	}
	return out
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
			if m.dropUnloadedPackOverride("org", ov) {
				continue
			}
			// Unknown rule: surface at engine construction (the
			// override still goes through so policy.New errors loudly
			// with the same message lint shows).
			m.overrides = append(m.overrides, toPolicyOverride(ov))
			continue
		}
		if decisionRelaxes(s, ov) {
			m.issues = append(m.issues, fmt.Sprintf(
				"org override on %s dropped: %q would relax the effective decision (the org layer is a strictness floor; it may only escalate - spec §4.6/§14.2)",
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
	// claimRuleIDs dropped every user row whose id a more trusted source
	// defines, so each id here is the user layer's own.
	for _, s := range user.rules {
		m.effective[s.ID] = &stance{observe: s.Observe, enforce: s.Enforce, enforced: s.Enforced}
	}
	for _, ov := range user.overrides {
		m.foldTracked(layerUser, ov, m.foldUserOverride)
	}
}

// foldUserOverride folds one user-layer override (applyUser).
func (m *mergeState) foldUserOverride(ov rawOverride) {
	m.noteUngrantableOverridable(ov)
	if m.dropRemovedTarget(ov) {
		return
	}
	s := m.effective[ov.RuleID]
	if s == nil {
		if m.dropUnloadedPackOverride(ov.Layer, ov) {
			return
		}
		m.overrides = append(m.overrides, toPolicyOverride(ov))
		return
	}
	if m.floored(ov.RuleID) && decisionRelaxes(s, ov) {
		m.issues = append(m.issues, fmt.Sprintf(
			"user override on %s dropped: %q would relax %s (org > user - spec §4.6)",
			ov.RuleID, ov.Decision, m.floorWords(ov.RuleID),
		))
		return
	}
	if m.dropBelowOrgEnforceOff("user", ov) {
		return
	}
	// The integrity rules (policy.IsIntegrityRuleID) are the guard's
	// own: no below-org layer may weaken them (treated like a floored
	// rule REGARDLESS of m.floor). Escalation still passes: a
	// stricter decision is not < the effective stance. policy.New is
	// the hard backstop even if this drop is somehow missed; recording
	// the issue here is what makes `observer guard status` surface WHY
	// the edit did nothing instead of it being a silent no-op.
	if policy.IsIntegrityRuleID(ov.RuleID) && decisionRelaxes(s, ov) {
		m.issues = append(m.issues, fmt.Sprintf(
			"user override on %s dropped: %s is an integrity rule and cannot be relaxed below the org (guard-rule-management-ui plan §3.4 / §2)",
			ov.RuleID, ov.RuleID,
		))
		return
	}
	// User outranks builtin + project: apply unconditionally (the
	// org floor, when present, was checked above).
	m.apply(s, ov)
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
		m.foldTracked(layerProject, ov, m.foldProjectOverride)
	}
}

// foldProjectOverride folds one repository-file override (applyProject).
func (m *mergeState) foldProjectOverride(ov rawOverride) {
	m.noteUngrantableOverridable(ov)
	if m.dropRemovedTarget(ov) {
		return
	}
	s := m.effective[ov.RuleID]
	if s == nil {
		if m.dropUnloadedPackOverride(ov.Layer, ov) {
			return
		}
		m.overrides = append(m.overrides, toPolicyOverride(ov))
		return
	}
	if decisionRelaxes(s, ov) {
		m.issues = append(m.issues, fmt.Sprintf(
			"project override on %s dropped: %q would relax the effective decision (project layer may only escalate - spec §4.6)",
			ov.RuleID, ov.Decision,
		))
		return
	}
	if ov.EnforceOff {
		m.issues = append(m.issues, fmt.Sprintf(
			"project override on %s dropped: `enforce = false` would cap the rule at flag (project layer may only escalate - spec §4.6)",
			ov.RuleID,
		))
		return
	}
	m.apply(s, ov)
}

// dropUnloadedPackOverride drops an override on a pillar rule id (S-7xx)
// that no loaded row carries: the module that owns the rule is not active
// (or not in this build). It records the load issue the plan words
// (section 4.7 item 1) and reports true; any other unknown id is left for
// policy.New to reject loudly, as before.
func (m *mergeState) dropUnloadedPackOverride(layer string, ov rawOverride) bool {
	if !strings.HasPrefix(ov.RuleID, policy.SecurityRuleIDPrefix) {
		return false
	}
	if layer == "" {
		layer = "policy"
	}
	m.issues = append(m.issues, unloadedPackIssue(layer, ov.RuleID))
	return true
}

// unloadedPackIssue is the load issue for an override on a pillar rule that
// no loaded row carries. It is built in one place so lint can recognise it.
func unloadedPackIssue(layer, ruleID string) string {
	return fmt.Sprintf("%s override on %s dropped: rule %s is not loaded: Code security is not active", layer, ruleID, ruleID)
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
		"%s override on %s: `overridable` ignored - only the org policy bundle grants a per-rule override (spec §4.6/§14.2)",
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
		kept := m.foldTrustedDisable(id)
		m.note(mergeOutcome{layer: layerTrustedProject, kind: mergeKindDisable, ruleID: id, loosens: true, applied: kept})
	}
	m.extra = append(m.extra, trusted.rules...)
	// claimRuleIDs dropped every trusted row whose id a more trusted source
	// defines (same as applyUser), and mergeLayersWithDisable seeded these
	// stances before the repository file folded; a repository escalation
	// accepted since is kept in them.
	for _, s := range trusted.rules {
		if m.effective[s.ID] == nil {
			m.effective[s.ID] = &stance{observe: s.Observe, enforce: s.Enforce, enforced: s.Enforced}
		}
	}
	for _, ov := range trusted.overrides {
		m.foldTracked(layerTrustedProject, ov, m.foldTrustedOverride)
	}
}

// foldTrustedDisable folds one id of the trusted layer's `disable` list and
// reports whether the merge kept it.
func (m *mergeState) foldTrustedDisable(id string) bool {
	if m.floored(id) {
		m.issues = append(m.issues, fmt.Sprintf(
			"trusted project disable of %s dropped: %s cannot be disabled (org > trusted project - spec §4.6)", id, m.floorRuleWords(id),
		))
		return false
	}
	// The integrity rules (policy.IsIntegrityRuleID) are the guard's
	// own, never disable-able below the org, treated like a floored ID
	// REGARDLESS of m.floor. Dropping R-160 here would let an agent
	// write ~/.observer/** (including the trusted layer itself) freely.
	// policy.New's disable filter is the hard backstop; this recorded
	// issue makes the drop visible in `observer guard status` and the
	// LintTrustedProject save-gate instead of a silent no-op.
	if policy.IsIntegrityRuleID(id) {
		m.issues = append(m.issues, fmt.Sprintf(
			"trusted project disable of %s dropped: %s is an integrity rule and cannot be disabled below the org (guard-rule-management-ui plan §3.4 / §2)", id, id,
		))
		return false
	}
	m.disable = append(m.disable, id)
	return true
}

// foldTrustedOverride folds one trusted-project override
// (applyTrustedProject).
func (m *mergeState) foldTrustedOverride(ov rawOverride) {
	m.noteUngrantableOverridable(ov)
	if m.dropRemovedTarget(ov) {
		return
	}
	s := m.effective[ov.RuleID]
	if s == nil {
		if m.dropUnloadedPackOverride(ov.Layer, ov) {
			return
		}
		m.overrides = append(m.overrides, toPolicyOverride(ov))
		return
	}
	// For a floored rule this drops a trusted relaxation whenever it
	// falls below the CURRENT effective stance (s), which may already
	// sit ABOVE the org floor because a user / in-repo layer escalated
	// it. That is deliberately conservative: it can never take a rule
	// below the org floor (the whole point), and refusing to relax
	// below a stricter local stance too is a safe v1 simplification,
	// not a behavior we need to loosen.
	if m.floored(ov.RuleID) && decisionRelaxes(s, ov) {
		m.issues = append(m.issues, fmt.Sprintf(
			"trusted project override on %s dropped: %q would relax %s (org > trusted project - spec §4.6)",
			ov.RuleID, ov.Decision, m.floorWords(ov.RuleID),
		))
		return
	}
	if m.dropBelowOrgEnforceOff("trusted project", ov) {
		return
	}
	// The integrity rules (policy.IsIntegrityRuleID) are the guard's
	// own: no below-org layer may weaken them (treated like a floored
	// rule REGARDLESS of m.floor). Escalation still passes. policy.New
	// is the hard backstop; the recorded issue surfaces the drop in the
	// LintTrustedProject save-gate and `observer guard status`.
	if policy.IsIntegrityRuleID(ov.RuleID) && decisionRelaxes(s, ov) {
		m.issues = append(m.issues, fmt.Sprintf(
			"trusted project override on %s dropped: %s is an integrity rule and cannot be relaxed below the org (guard-rule-management-ui plan §3.4 / §2)",
			ov.RuleID, ov.RuleID,
		))
		return
	}
	// Trusted project outranks built-in + in-repo project: apply
	// unconditionally (the org floor, when present, was checked above).
	m.apply(s, ov)
}

// dropBelowOrgEnforceOff drops (with a recorded issue) an explicit
// `enforce = false` from a below-org layer that may otherwise relax
// (user, trusted project) when the rule is org-floored or one of the
// guard's integrity rules: capping it at flag would weaken what that
// layer may not weaken (Sol A2-06). It reports whether ov was dropped.
func (m *mergeState) dropBelowOrgEnforceOff(layer string, ov rawOverride) bool {
	if !ov.EnforceOff {
		return false
	}
	switch {
	case m.floored(ov.RuleID):
		m.issues = append(m.issues, fmt.Sprintf(
			"%s override on %s dropped: `enforce = false` would cap %s at flag (org > %s - spec §4.6)",
			layer, ov.RuleID, m.floorRuleWords(ov.RuleID), layer,
		))
		return true
	case policy.IsIntegrityRuleID(ov.RuleID):
		m.issues = append(m.issues, fmt.Sprintf(
			"%s override on %s dropped: %s is an integrity rule and cannot be capped at flag below the org (guard-rule-management-ui plan §3.4 / §2)",
			layer, ov.RuleID, ov.RuleID,
		))
		return true
	}
	return false
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
		RuleID:     ov.RuleID,
		Enforced:   ov.Enforced,
		EnforceOff: ov.EnforceOff,
		Source:     ov.Layer,
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
