package guard

import (
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Org-composed budget application
// (docs/plans/org-budget-enforcement-and-token-display-plan-2026-09-07.md
// §3.3c, wave W3b).
//
// The guard does NOT compose. It never sees an org body, never learns whether
// a number was lowered or replaced, and never branches on tenancy or on an
// authority token: the boundary (cmd/observer's guard wiring, over the pure
// internal/orgbudget) resolves all of that into ONE plain
// config.GuardBudgetConfig and hands it in. That is the same discipline
// SetBudgetLookup follows for spend and SetApprovalLookup for grants — one
// seam per integration point, no type leakage past it (CLAUDE.md #2/#3).

// budgetConfig returns the EFFECTIVE budget numbers: whatever ApplyOrgBudget
// last published, else the config this Guard was constructed with. Lock-free;
// safe on the hot rebuild path.
func (g *Guard) budgetConfig() config.GuardBudgetConfig {
	if b := g.effBudget.Load(); b != nil {
		return *b
	}
	return g.cfg.Budget
}

func (g *Guard) budgetProtection() policy.BudgetProtection {
	if p := g.effBudgetProtection.Load(); p != nil {
		return *p
	}
	return policy.BudgetProtection{}
}

func (g *Guard) budgetBinding() string {
	if binding := g.effBudgetBinding.Load(); binding != nil {
		return *binding
	}
	return ""
}

func (g *Guard) budgetCalendars() BudgetCalendars {
	if calendars := g.effBudgetCalendars.Load(); calendars != nil {
		return *calendars
	}
	return normalizedBudgetCalendars(nil)
}

// EffectiveBudget returns the budget numbers currently in force. It is the
// read side of ApplyOrgBudget for status surfaces (`observer guard`) and for
// the posture composer, so neither has to guess whether an org body has landed.
func (g *Guard) EffectiveBudget() config.GuardBudgetConfig {
	if g == nil {
		return config.GuardBudgetConfig{}
	}
	return g.budgetConfig()
}

// ApplyOrgBudget publishes an already-composed effective budget and REBUILDS
// the live engine set so the next Evaluate compares against it — the
// ReloadOrgLayer discipline, applied to numbers instead of to rules.
//
// Two properties make this correct rather than merely convenient:
//
//   - The rebuild goes through buildEngine, which reads budgetConfig(), so
//     EVERY later rebuild (a project layer loading lazily, an org bundle
//     reloading) keeps these numbers. A version that stashed them only into
//     the base engine would pass a first test and silently revert on the next
//     project-scoped evaluation.
//   - It is FAIL-SAFE: a build failure returns the error and leaves the
//     running engine untouched, exactly like ReloadOrgLayer. A budget that
//     could not be applied must never take the guard down with it.
//
// softWindows is the set of budget WINDOWS whose breach must stay a flag even
// though [guard.budget].hard is on for this node — the per-window half of the
// org's enforcement, resolved at the boundary by internal/orgbudget and passed
// in as plain window names (review fix round 2, MEDIUM-3).
//
// The org authors enforcement per PERIOD and the gateway honours it per cap;
// a node that folded the strictest mode across periods denied a daily cap the
// admin wrote as `soft` while the gateway merely warned on it. Empty (the
// overwhelmingly common case: one uniform posture) reproduces the previous
// behaviour byte for byte.

// budgetWindowRules maps a window name onto the budget rule rows that measure
// it — the $ row and its TOKEN sibling, which are two units of ONE window and
// must always agree about whether that window denies. Table, not a switch, so
// a new window is a row (CLAUDE.md #5).
var budgetWindowRules = []struct {
	window  string
	ruleIDs []string
}{
	{window: "session", ruleIDs: []string{"B-601", "B-621"}},
	{window: "daily", ruleIDs: []string{"B-602", "B-622"}},
	{window: "monthly", ruleIDs: []string{"B-603", "B-623"}},
	{window: "weekly", ruleIDs: []string{"B-604", "B-624"}},
}

// budgetSoftOverrides renders the published soft-window set as policy
// overrides that hold enabled rows at flag. Rows the operator disabled are
// skipped because soft ceilings carry no native-intervention protection and
// policy.New rejects overrides on absent rows. Hard organization ceilings in
// other windows remain protected independently.
func (g *Guard) budgetSoftOverrides() []policy.Override {
	windows := g.effBudgetSoft.Load()
	if windows == nil || len(*windows) == 0 {
		return nil
	}
	off := map[string]bool{}
	for _, id := range g.cfg.Rules.Disable {
		off[strings.TrimSpace(id)] = true
	}
	flag := policy.DecisionFlag
	var out []policy.Override
	for _, name := range *windows {
		for _, row := range budgetWindowRules {
			if row.window != name {
				continue
			}
			for _, id := range row.ruleIDs {
				if off[id] && !g.budgetProtection().ProtectsRule(id) {
					continue
				}
				out = append(out, policy.Override{
					RuleID: id, Decision: &flag, Source: policy.SourceOrgBudget,
				})
			}
		}
	}
	return out
}

// required is the FAIL-CLOSED posture (org-budget ruling R2): true when the
// boundary resolved that this managed node may not run without the
// organization's budget and none has ever verified here. It arms B-625, which
// denies every proxied request in enforce mode. It travels as its own argument
// for the same reason softWindows does — it is not a [guard.budget] key an
// operator can author, and config.GuardBudgetConfig must stay exactly the
// operator's own block.
//
// protection carries managed enforce.budget provenance for the exact hard
// units and windows the organization authored. Preserved local ceilings stay
// unprotected. It is a no-op when the numbers, soft-window set, fail-closed
// posture, provenance, and enrollment binding are unchanged, so the push
// cycle can call it every time without churning the project-engine cache.
func (g *Guard) ApplyOrgBudget(effective config.GuardBudgetConfig, softWindows []string, required bool, protection policy.BudgetProtection, binding string, calendars ...BudgetCalendars) error {
	return g.applyOrgBudget(effective, softWindows, required, protection, binding, BudgetDocumentWitness{}, calendars...)
}

// ApplyOrgBudgetWithWitness publishes an org-composed budget together with the
// exact durable document state that produced it. Native intervention requires
// this form; ApplyOrgBudget remains for local/advisory callers.
func (g *Guard) ApplyOrgBudgetWithWitness(effective config.GuardBudgetConfig, softWindows []string, required bool, protection policy.BudgetProtection, binding string, witness BudgetDocumentWitness, calendars ...BudgetCalendars) error {
	return g.applyOrgBudget(effective, softWindows, required, protection, binding, witness, calendars...)
}

func (g *Guard) applyOrgBudget(effective config.GuardBudgetConfig, softWindows []string, required bool, protection policy.BudgetProtection, binding string, witness BudgetDocumentWitness, calendars ...BudgetCalendars) error {
	if g == nil {
		return nil
	}
	g.reloadMu.Lock()
	defer g.reloadMu.Unlock()
	windowCalendars := normalizedBudgetCalendars(calendars)
	windowCalendars.documentWitness = witness

	if g.numbersUnchanged(effective, softWindows, required, protection, binding, windowCalendars) {
		return nil
	}
	restore := g.publishNumbers(effective, softWindows, required, protection, binding, windowCalendars)
	if err := g.rebuildLocked(binding, windowCalendars); err != nil {
		// Roll the published numbers back: leaving them stored while the live
		// engine still enforces the old ones would make budgetConfig() lie to
		// every status surface and to the posture report.
		restore()
		return fmt.Errorf("guard.ApplyOrgBudget: build engine: %w", err)
	}
	return nil
}

// numbersUnchanged is the numeric half of the no-op check.
func (g *Guard) numbersUnchanged(effective config.GuardBudgetConfig, softWindows []string, required bool,
	protection policy.BudgetProtection, binding string, calendars BudgetCalendars,
) bool {
	return g.budgetConfig() == effective && sameWindows(g.effBudgetSoft.Load(), softWindows) &&
		g.effBudgetRequired.Load() == required && g.budgetProtection() == protection &&
		g.budgetBinding() == binding && g.budgetCalendars() == calendars
}

// publishNumbers stores the numeric half and returns the undo.
func (g *Guard) publishNumbers(effective config.GuardBudgetConfig, softWindows []string, required bool,
	protection policy.BudgetProtection, binding string, calendars BudgetCalendars,
) func() {
	prev := g.effBudget.Load()
	prevSoft := g.effBudgetSoft.Load()
	prevRequired := g.effBudgetRequired.Load()
	prevProtection := g.effBudgetProtection.Load()
	prevBinding := g.effBudgetBinding.Load()
	prevCalendars := g.effBudgetCalendars.Load()
	effectiveCopy := effective
	g.effBudget.Store(&effectiveCopy)
	soft := append([]string(nil), softWindows...)
	g.effBudgetSoft.Store(&soft)
	g.effBudgetRequired.Store(required)
	protectionCopy := protection
	g.effBudgetProtection.Store(&protectionCopy)
	bindingCopy := binding
	g.effBudgetBinding.Store(&bindingCopy)
	calendarsCopy := calendars
	g.effBudgetCalendars.Store(&calendarsCopy)
	return func() {
		g.effBudget.Store(prev)
		g.effBudgetSoft.Store(prevSoft)
		g.effBudgetRequired.Store(prevRequired)
		g.effBudgetProtection.Store(prevProtection)
		g.effBudgetBinding.Store(prevBinding)
		g.effBudgetCalendars.Store(prevCalendars)
	}
}

// appendOverrides concatenates two override lists into a FRESH slice. A plain
// append would share mergeLayers' backing array, so a later build could
// overwrite the caller's tail — the aliasing bug this one-liner exists to make
// impossible.
func appendOverrides(layers, extra []policy.Override) []policy.Override {
	if len(extra) == 0 {
		return layers
	}
	out := make([]policy.Override, 0, len(layers)+len(extra))
	out = append(out, layers...)
	out = append(out, extra...)
	return out
}

// sameWindows compares a published soft-window set against a candidate one.
// Order is significant and deliberately so: orgbudget emits the set in a fixed
// window order, so a differing order is a differing composition, not noise.
func sameWindows(cur *[]string, next []string) bool {
	var have []string
	if cur != nil {
		have = *cur
	}
	if len(have) != len(next) {
		return false
	}
	for i := range have {
		if have[i] != next[i] {
			return false
		}
	}
	return true
}

// PER-SUBJECT ORG CAPS + THE CROSS-MACHINE BASELINE (bundle BUD-N).
//
// The same discipline as ApplyOrgBudget: the guard does not compose. The
// boundary resolves the organization's body into plain numbers — a list of
// already-windowed per-tool / per-model ceilings and one set of per-window
// baseline amounts — and publishes them here.

// budgetSubjectCaps returns the published per-subject caps, or nil.
func (g *Guard) budgetSubjectCaps() []policy.BudgetSubjectCap {
	if caps := g.effBudgetSubjects.Load(); caps != nil {
		return *caps
	}
	return nil
}

// budgetBaseline returns the published cross-machine baseline. The zero value
// (every window 0) is the ordinary state and is what every individual node
// stamps — it changes no comparison.
func (g *Guard) budgetBaseline() policy.BudgetWindowAmounts {
	if b := g.effBudgetBaseline.Load(); b != nil {
		return *b
	}
	return policy.BudgetWindowAmounts{}
}

// budgetBaselineFlagOnly reports whether the published baseline may only WARN.
// See Guard.effBudgetBaselineFlagOnly and
// orgcontract.BudgetBaselineAppliedFlagOnly.
func (g *Guard) budgetBaselineFlagOnly() bool {
	if g == nil {
		return false
	}
	return g.effBudgetBaselineFlagOnly.Load()
}

// EffectiveBudgetSubjects returns the per-subject caps currently in force. The
// read side of ApplyOrgBudgetSubjects for status surfaces, mirroring
// EffectiveBudget.
func (g *Guard) EffectiveBudgetSubjects() []policy.BudgetSubjectCap {
	if g == nil {
		return nil
	}
	return g.budgetSubjectCaps()
}

// ApplyOrgBudgetSubjects publishes the organization's per-tool / per-model caps
// and the cross-machine spend baseline, and rebuilds the live engine so the
// next Evaluate compares against them.
//
// It is a SECOND entry point rather than two more parameters on ApplyOrgBudget,
// for two reasons that both come down to one owner per piece of state:
//
//   - ApplyOrgBudget's signature is the NUMERIC budget plus the per-window
//     posture that goes with it, and every caller of it — including callers
//     that have no organization body at all — would have to learn a subject
//     vocabulary it never uses.
//   - The baseline is not a ceiling. It is an addend applied to measured spend
//     before a ceiling is consulted, which is why it is stamped onto the event
//     rather than folded into config.GuardBudgetConfig, where it would look
//     like a number an operator authored.
//
// It is a NO-OP when neither the caps nor the baseline changed, so the push
// cycle may call it every cycle; on a cycle that changes both this and the
// numeric budget there are two rebuilds, which is bounded by the push cadence
// and is the same cost ApplyOrgBudget already pays on any change.
//
// FAIL-SAFE, exactly like ApplyOrgBudget: a failed build returns the error and
// leaves the running engine — and the previously published values — untouched.
//
// PREFER ApplyOrgComposedBudget when the caller has both halves of one
// composition: publishing the caps and then the numbers is two rebuilds, and
// the engine in between holds NEW caps against OLD protection.
func (g *Guard) ApplyOrgBudgetSubjects(baseline policy.BudgetWindowAmounts, baselineFlagOnly bool, subjects []policy.BudgetSubjectCap) error {
	if g == nil {
		return nil
	}
	g.reloadMu.Lock()
	defer g.reloadMu.Unlock()
	if g.subjectsUnchanged(baseline, baselineFlagOnly, subjects) {
		return nil
	}
	cur := g.set.Load()
	restore := g.publishSubjects(baseline, baselineFlagOnly, subjects)
	if err := g.rebuildLocked(cur.budgetBinding, cur.budgetCalendars); err != nil {
		restore()
		return fmt.Errorf("guard.ApplyOrgBudgetSubjects: build engine: %w", err)
	}
	return nil
}

// ApplyOrgComposedBudget publishes ONE composition — the per-subject caps and
// the cross-machine baseline together with the numeric ceilings, the per-window
// soft set, the fail-closed posture, the authority provenance and the calendars
// — and rebuilds the live engine ONCE.
//
// WHY IT EXISTS (adversarial review of BUD-N, P2-6). The boundary used to call
// ApplyOrgBudgetSubjects and then ApplyOrgBudget, and each rebuilds. Between
// the two rebuilds the LIVE engine held the new cap table against the previous
// BudgetProtection and the previous fail-closed posture, which is a snapshot no
// composition ever produced: a request arriving in that window could be judged
// against a cap the org had just authored under authority it had just revoked,
// or the reverse. They come from ONE signed body and one Compose call, so they
// become one atomic publication.
//
// It is the same no-op check and the same fail-safe rollback as its two halves,
// applied across both: nothing is published unless something changed, and a
// failed build restores every previously published value before returning.
func (g *Guard) ApplyOrgComposedBudget(
	effective config.GuardBudgetConfig,
	softWindows []string,
	required bool,
	protection policy.BudgetProtection,
	binding string,
	witness BudgetDocumentWitness,
	baseline policy.BudgetWindowAmounts,
	baselineFlagOnly bool,
	subjects []policy.BudgetSubjectCap,
	calendars ...BudgetCalendars,
) error {
	if g == nil {
		return nil
	}
	g.reloadMu.Lock()
	defer g.reloadMu.Unlock()
	windowCalendars := normalizedBudgetCalendars(calendars)
	windowCalendars.documentWitness = witness
	if g.subjectsUnchanged(baseline, baselineFlagOnly, subjects) &&
		g.numbersUnchanged(effective, softWindows, required, protection, binding, windowCalendars) {
		return nil
	}
	restoreSubjects := g.publishSubjects(baseline, baselineFlagOnly, subjects)
	restoreNumbers := g.publishNumbers(effective, softWindows, required, protection, binding, windowCalendars)
	if err := g.rebuildLocked(binding, windowCalendars); err != nil {
		restoreNumbers()
		restoreSubjects()
		return fmt.Errorf("guard.ApplyOrgComposedBudget: build engine: %w", err)
	}
	return nil
}

// subjectsUnchanged is the per-subject half of the no-op check.
func (g *Guard) subjectsUnchanged(baseline policy.BudgetWindowAmounts, baselineFlagOnly bool, subjects []policy.BudgetSubjectCap) bool {
	return sameSubjectCaps(g.effBudgetSubjects.Load(), subjects) &&
		g.budgetBaseline() == baseline && g.budgetBaselineFlagOnly() == baselineFlagOnly
}

// publishSubjects stores the per-subject half and returns the undo.
func (g *Guard) publishSubjects(baseline policy.BudgetWindowAmounts, baselineFlagOnly bool, subjects []policy.BudgetSubjectCap) func() {
	prevSubjects := g.effBudgetSubjects.Load()
	prevBaseline := g.effBudgetBaseline.Load()
	prevFlagOnly := g.effBudgetBaselineFlagOnly.Load()
	next := append([]policy.BudgetSubjectCap(nil), subjects...)
	g.effBudgetSubjects.Store(&next)
	baselineCopy := baseline
	g.effBudgetBaseline.Store(&baselineCopy)
	g.effBudgetBaselineFlagOnly.Store(baselineFlagOnly)
	return func() {
		g.effBudgetSubjects.Store(prevSubjects)
		g.effBudgetBaseline.Store(prevBaseline)
		g.effBudgetBaselineFlagOnly.Store(prevFlagOnly)
	}
}

// rebuildLocked rebuilds the live engine set from the currently published
// state, sealing binding and calendars into the new snapshot. Called with
// reloadMu held; a caller that changes neither passes the current pair.
func (g *Guard) rebuildLocked(binding string, calendars BudgetCalendars) error {
	cur := g.set.Load()
	base, err := g.buildEngine(cur.base.Mode(), cur.orgLayer, cur.userLayer, nil, nil)
	if err != nil {
		return err
	}
	g.set.Store(newEngineSet(base, cur.orgLayer, cur.userLayer, cur.states,
		buildRuleCategories(cur.orgLayer, cur.userLayer), binding, calendars))
	return nil
}

// sameSubjectCaps compares a published cap list against a candidate one. Order
// is significant, as it is for sameWindows: the composer emits caps in the
// organization body's own order, so a differing order is a differing body.
func sameSubjectCaps(cur *[]policy.BudgetSubjectCap, next []policy.BudgetSubjectCap) bool {
	var have []policy.BudgetSubjectCap
	if cur != nil {
		have = *cur
	}
	if len(have) != len(next) {
		return false
	}
	for i := range have {
		if have[i] != next[i] {
			return false
		}
	}
	return true
}
