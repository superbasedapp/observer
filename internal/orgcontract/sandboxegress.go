package orgcontract

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// SandboxEgressRefusalDayRow is one row of the sandbox egress refusal counts
// (audit finding CG-15, decision D-11): how many egress attempts of the
// node's sandboxed runs were refused per UTC day, by the run's egress tier
// and the closed rule that refused them. Only a MANAGED node sends it (the
// org's signed sandbox body can decide the tier and the allowed ranges
// there, so the org sees whether its policy is refusing); an individual
// node never does.
//
// Every field is a closed enum or a count. It never carries a host, an
// address, a port, a path, a project, a run id, a session id or the
// deciding config key (pinned by tests/invariant/privacy_test.go); the
// per-refusal rows stay in the node-local sandbox_egress_refusals table.
// An empty Tier or Rule means "not recorded" (a run with no stored tier, a
// value outside the vocabulary, or dropped refusals whose rule is unknown).
// Optional both directions: an old agent omits it, an old server ignores
// the unknown key.
type SandboxEgressRefusalDayRow struct {
	// OrgID / UserEmail are the agent-stamped attribution; the server
	// overwrites both with the authenticated pusher's.
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// Day is the UTC date (YYYY-MM-DD) of the refusals.
	Day string `json:"day"`
	// Tier is the run's egress tier (sandboxvocab.Tier).
	Tier string `json:"tier"`
	// Rule is the closed refusal rule (sandboxvocab.EgressRefusalRule).
	Rule string `json:"rule"`
	// Refusals is how many recorded refusals fell into the bucket.
	Refusals int64 `json:"refusals"`
	// Dropped is how many refusals happened but are missing from the
	// recorded counts: dropped before they were written, or removed to keep
	// a run under the node's per-run bound. Their rule is unknown, so they
	// land on Rule "" (by the day their run's count last grew).
	Dropped int64 `json:"dropped,omitempty"`
}

// ClampSandboxEgressRefusalDay clamps one row to the closed contract: a tier
// or rule outside its vocabulary lands as "" (not recorded); a row whose day
// is not a date, whose counts are negative, or that counts nothing is
// dropped (ok=false). The node applies it before sending and the org again
// on ingest, so nothing else is ever stored, whatever a node sends.
func ClampSandboxEgressRefusalDay(r SandboxEgressRefusalDayRow) (SandboxEgressRefusalDayRow, bool) {
	if _, err := time.Parse("2006-01-02", r.Day); err != nil || r.Refusals < 0 || r.Dropped < 0 || r.Refusals+r.Dropped == 0 {
		return r, false
	}
	if !sandboxvocab.Tier(r.Tier).Valid() {
		r.Tier = ""
	}
	if !sandboxvocab.EgressRefusalRule(r.Rule).Valid() {
		r.Rule = ""
	}
	return r, true
}
