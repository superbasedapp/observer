package guard

import (
	"fmt"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// The managed-node lock on local rule changes (2026-11-12 operator ruling:
// "Enterprise has absolute visibility" and stale entries of an older build
// do not persist).
//
// On a managed node the organization is authoritative over the whole
// catalog (override.go: "managed | no | - | org-locked"). Before this lock
// the merge floored only the rules the org bundle NAMES, so a local
// `[guard.rules] disable` entry, a user policy file relaxation or a trusted
// per-project relaxation of a rule the bundle does not name still took the
// rule down; the dashboard refused a NEW such edit (guardOrgLockedEdits), but
// an entry already in the file kept working and the organization was not
// told. Now, on a node whose tenancy is resolved as managed, every built-in
// and rule-pack rule is floored for every below-org layer: a disable of it is
// ignored and a relaxation of it is dropped, each with a load issue. A local
// change that only makes a rule stricter, and a rule a local layer defines
// for itself, stand as before. Individual nodes are unchanged: their lock
// reaches only the rules the bundle names, which the merge's floor already
// covered.
//
// The lock exists whenever the tenancy is managed, with or without an org
// guard bundle in force (review finding 1, 2026-11-12): a managed node whose
// organization has published no guard policy yet, or whose first fetch has
// not landed, runs the catalog as shipped, never the developer's local
// relaxations of it.
//
// The bundle has no construct that lets a developer disable or relax a rule
// locally: `overridable` grants a scoped, audited approval past a deny
// (override.go), and a rule the bundle names is floored whatever it says
// (OSH-R-014). A future "allow a local change" grant becomes the one
// exception in managedRuleLock.locks.

// managedLockWords names the managed-node lock in a load issue.
const managedLockWords = "a rule your organization manages on this machine (on a managed node only the organization changes a built-in rule)"

// managedRuleLock is the per-build answer to "which rules may no local layer
// relax or disable here". nil means no managed lock (an individual node, a
// process whose tenancy is unresolved, or an authoring lint).
type managedRuleLock struct {
	// lockable is the set of rule ids the organization holds: the built-in
	// catalog and the loaded rule pack. A rule a local layer defines for
	// itself is not in it.
	lockable map[string]bool
}

// locks reports whether the lock floors id. nil-safe.
func (l *managedRuleLock) locks(id string) bool {
	return l != nil && l.lockable[id]
}

// newManagedLock builds the lock over the built-in catalog and pack.
func newManagedLock(pack []policy.Rule) *managedRuleLock {
	l := &managedRuleLock{lockable: map[string]bool{}}
	for _, info := range policy.Catalog() {
		l.lockable[info.ID] = true
	}
	for i := range pack {
		l.lockable[pack[i].ID] = true
	}
	return l
}

// managedLock resolves the lock an engine build runs under: the lock over
// the catalog and the pack when this node's tenancy is RESOLVED as managed,
// nil otherwise. It does not depend on an org bundle being in force. Unlike
// the approvals lock (orgLocksEveryRule), an unresolved tenancy does not arm
// it: every guard a managed node builds resolves its tenancy (the daemon
// wires it, and every other process reads it off the daemon's org lock,
// applyOrgLock), so an unresolved reading is a process with no daemon record
// at all, and treating that as managed would change an individual node's
// rules. The daemon also strips the stale entries from the config file
// (cmd/observer guard_managed_disables.go).
func (g *Guard) managedLock() *managedRuleLock {
	if !g.managedTenancyResolved() {
		return nil
	}
	return newManagedLock(g.packRules)
}

// managedTenancyResolved reports a tenancy that is resolved AND managed.
func (g *Guard) managedTenancyResolved() bool {
	fn := g.managedTenancy.Load()
	return fn != nil && (*fn)()
}

// splitConfigDisable splits a config-level `[guard.rules] disable` list
// under lock into the ids the engine applies (kept) and the ids the lock
// ignores (ignored, sorted, deduplicated). With no lock everything is kept.
func splitConfigDisable(lock *managedRuleLock, disable []string) (kept, ignored []string) {
	if lock == nil {
		return disable, nil
	}
	seen := map[string]bool{}
	kept = make([]string, 0, len(disable))
	for _, raw := range disable {
		id := strings.TrimSpace(raw)
		if lock.locks(id) {
			if !seen[id] {
				seen[id] = true
				ignored = append(ignored, id)
			}
			continue
		}
		kept = append(kept, raw)
	}
	sort.Strings(ignored)
	return kept, ignored
}

// configDisable is the `[guard.rules] disable` list an engine build applies:
// the configured list without the ids the managed-node lock ignores. It is
// the ONE place the guard reads the config list for an engine build, so
// every build, its fallback checks and the in-repo override targets agree on
// which rows are loaded.
func (g *Guard) configDisable() []string {
	kept, _ := splitConfigDisable(g.managedLock(), g.cfg.Rules.Disable)
	return kept
}

// managedDisableIssues is the load issue for each config-level disable the
// managed-node lock ignored, so `observer guard status` says why the entry
// does nothing.
func managedDisableIssues(ignored []string) []string {
	out := make([]string, 0, len(ignored))
	for _, id := range ignored {
		out = append(out, fmt.Sprintf(
			"[guard.rules] disable of %s ignored: %s",
			id, managedLockWords))
	}
	return out
}

// configDisableNotes is every load note the config-level disable list earns
// on an engine over org's layer set: the org-floor notes (OSH-R-014) and the
// managed-node lock notes.
func (g *Guard) configDisableNotes(org *policyFile) []string {
	_, ignored := splitConfigDisable(g.managedLock(), g.cfg.Rules.Disable)
	notes := configDisableOrgFloorIssues(org, g.cfg.Rules.Disable)
	return append(notes, managedDisableIssues(ignored)...)
}

// ManagedIgnoredConfigDisables returns, sorted, the `[guard.rules] disable`
// ids configured in disable that the managed-node lock of the live guard
// ignores: the stale local disables the daemon strips from a managed node's
// config file (cmd/observer guard_managed_disables.go). Empty on an
// individual node and in a process whose tenancy is unresolved; on a managed
// node it does not wait for an org bundle (the lock does not either).
func (g *Guard) ManagedIgnoredConfigDisables(disable []string) []string {
	_, ignored := splitConfigDisable(g.managedLock(), disable)
	return ignored
}
