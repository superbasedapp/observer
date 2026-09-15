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

	if cur := g.budgetConfig(); cur == effective && sameWindows(g.effBudgetSoft.Load(), softWindows) &&
		g.effBudgetRequired.Load() == required && g.budgetProtection() == protection &&
		g.budgetBinding() == binding && g.budgetCalendars() == windowCalendars {
		return nil
	}
	prev := g.effBudget.Load()
	prevSoft := g.effBudgetSoft.Load()
	prevRequired := g.effBudgetRequired.Load()
	prevProtection := g.effBudgetProtection.Load()
	prevBinding := g.effBudgetBinding.Load()
	prevCalendars := g.effBudgetCalendars.Load()
	g.effBudget.Store(&effective)
	soft := append([]string(nil), softWindows...)
	g.effBudgetSoft.Store(&soft)
	g.effBudgetRequired.Store(required)
	protectionCopy := protection
	g.effBudgetProtection.Store(&protectionCopy)
	bindingCopy := binding
	g.effBudgetBinding.Store(&bindingCopy)
	g.effBudgetCalendars.Store(&windowCalendars)

	cur := g.set.Load()
	base, err := g.buildEngine(cur.base.Mode(), cur.orgLayer, cur.userLayer, nil)
	if err != nil {
		// Roll the published numbers back: leaving them stored while the live
		// engine still enforces the old ones would make budgetConfig() lie to
		// every status surface and to the posture report.
		g.effBudget.Store(prev)
		g.effBudgetSoft.Store(prevSoft)
		g.effBudgetRequired.Store(prevRequired)
		g.effBudgetProtection.Store(prevProtection)
		g.effBudgetBinding.Store(prevBinding)
		g.effBudgetCalendars.Store(prevCalendars)
		return fmt.Errorf("guard.ApplyOrgBudget: build engine: %w", err)
	}
	g.set.Store(newEngineSet(base, cur.orgLayer, cur.userLayer, cur.states,
		buildRuleCategories(cur.orgLayer, cur.userLayer), binding, windowCalendars))
	return nil
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
