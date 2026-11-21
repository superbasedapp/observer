package govern

// Managed policy tiers (2026-11-12 operator ruling: "Enterprise has
// absolute visibility, so any changes that are happening, especially on the
// policy front, have to be available to the org").
//
// A share tier that carries policy or enforcement state is ON for every
// managed node, whatever the node's own [org_client.share] value says and
// whatever the grant's extraction tokens are: the share switch gates these
// tiers only on an individual node. There is no compatibility switch; a
// managed node cannot opt out (no live customers depended on one).
//
// The tiers:
//
//   - policy_state: the policy-ack rail (every family's effective state, the
//     guard row's local guard posture and rule changes).
//   - routing_summary: the routing decision aggregate (which policy decided
//     how many turns).
//   - terminal_detail: the sandbox posture and capability rows (backends,
//     isolation class, managed refusals) and the terminal and remote audit
//     counts.
var managedPolicyTiers = map[string]bool{
	"policy_state":    true,
	"routing_summary": true,
	"terminal_detail": true,
}

// ManagedPolicyTierKeys lists the managed policy tiers in a stable order.
func ManagedPolicyTierKeys() []string {
	return []string{"policy_state", "routing_summary", "terminal_detail"}
}

// ManagedPolicyTier reports whether key is on by force here: a managed
// node and a policy tier.
func (e Effective) ManagedPolicyTier(key string) bool {
	return e.Managed && managedPolicyTiers[key]
}
