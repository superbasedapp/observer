package orgpricing

import "github.com/marmutapp/superbased-observer/internal/config"

// Mode resolves whether this node applies the org's price document and
// whether it does so authoritatively.
//
// fromOrg is the node's opt-in: false means the rail is not consulted at all,
// no document is fetched, and the persisted cache — if an earlier, opted-in
// run left one — is INERT rather than deleted. That last part is deliberate:
// turning the switch off is a statement about what this node applies, not an
// instruction to destroy a document the org signed, and a node that flipped
// the switch back on would otherwise have to wait a full poll cycle pricing at
// list rates.
//
// authoritative can only be true when fromOrg is: a node that has not opted
// into the org's prices cannot be applying them above its own. Returning the
// pair from one function rather than exposing two predicates is what keeps
// that invariant from having to be re-checked at each of the three call sites.
func Mode(cfg config.GuardBudgetConfig, grantsBudgetEnforcement bool) (fromOrg, authoritative bool) {
	fromOrg = cfg.FromOrg
	return fromOrg, fromOrg && grantsBudgetEnforcement
}
