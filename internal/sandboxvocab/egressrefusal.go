package sandboxvocab

import "time"

// egressrefusal.go holds the minute bucket of the sandbox egress refusal
// audit (lane N1, audit N1-A10): the one definition both the refusal flood
// bound (internal/sandboxnet.RefusalLimiter) and the store's unique key on
// sandbox_egress_refusals use, so the two can never disagree.

// EgressRefusalMinute is the minute bucket of at (Unix minutes, UTC).
func EgressRefusalMinute(at time.Time) int64 { return at.Unix() / 60 }

// EgressRefusalRule is the closed rule name a recorded egress refusal
// carries (internal/sandboxnet.RefusalRule, the frozen N1 contract), spelled
// here so core readers can check it without importing the egress gateway,
// which is component code (audit CG-15: the org-wire refusal counts clamp
// on it on the node and again at org ingest). A sandboxnet test pins the
// two lists equal, in order.
type EgressRefusalRule string

// egressRefusalRules is the vocabulary in sandboxnet.RefusalRules' order.
var egressRefusalRules = []EgressRefusalRule{
	"allow-list-miss", "private-range", "provider-host", "host-local",
	"tier-none", "ssrf-floor", "literal-ip", "port-not-allowed", "tls-server-name",
}

// EgressRefusalRules returns the closed vocabulary in its one fixed order.
func EgressRefusalRules() []EgressRefusalRule {
	return append([]EgressRefusalRule(nil), egressRefusalRules...)
}

// Valid reports whether r is in the closed vocabulary.
func (r EgressRefusalRule) Valid() bool {
	for _, v := range egressRefusalRules {
		if v == r {
			return true
		}
	}
	return false
}
