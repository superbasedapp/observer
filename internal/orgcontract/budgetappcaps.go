package orgcontract

import "strings"

// APP budget caps on the per-caller budget rail (GET /api/agent/budget; org
// server migration 338, Plane A W4-1, ruling D9). Beside the developer's own
// caps, the org's budgets on its Plane A app's END USERS and SERVICES reach the
// machine, where its admission check (internal/obs/admission) applies them:
// as the admission budget itself on a managed machine holding the org budget,
// and lowering-only on an individual machine.
//
// What travels is governance, not data: caps, periods, the end user as the
// org-bound hash (HashObsIdentity, never the raw id) and normalised service
// names. A machine hashes the end user it sees with AppOrgID and compares.

// BudgetAppCapability is the ?policy_caps token a machine sends to say it
// understands BudgetPolicyBody.AppCaps / AppOrgID. The server populates them
// only for a request that carried it (the BudgetGrantCapability rule): a
// populated field an old machine does not know fails its signature check.
const BudgetAppCapability = "app_budgets.v1"

// The app cap scopes (the org `budgets.scope` values of migration 338).
const (
	BudgetAppScopeEndUser        = "end_user"
	BudgetAppScopeService        = "service"
	BudgetAppScopeEndUserService = "end_user_service"
)

// BudgetAppDefault is the "every end user / every service" key of a default
// cap.
const BudgetAppDefault = "*"

// BudgetAppCap is one app budget as the machine applies it.
type BudgetAppCap struct {
	// Scope is one of the BudgetAppScope* constants; an unknown scope is
	// ignored by the machine, never widened.
	Scope string `json:"scope"`
	// EndUserKey is the org-bound end-user hash, or BudgetAppDefault; "" on a
	// service cap.
	EndUserKey string `json:"end_user_key,omitempty"`
	// Service is the normalised service (trim + lower case), or
	// BudgetAppDefault; "" on an end-user cap.
	Service string `json:"service,omitempty"`
	// Period / Timezone / CapTokens / CapUSD / Enforcement mean what they mean
	// on BudgetPolicyCap. Soft and hard caps travel as caps; an explicit
	// report budget travels only as an exemption marker
	// (BudgetAppExemptEnforcement, no cap), and only where a default cap
	// would otherwise cover its subject.
	Period      string  `json:"period"`
	Timezone    string  `json:"timezone,omitempty"`
	CapTokens   int64   `json:"cap_tokens,omitempty"`
	CapUSD      float64 `json:"cap_usd,omitempty"`
	Enforcement string  `json:"enforcement"`
	// BudgetID names the authored budget row, for the machine's status page.
	BudgetID string `json:"budget_id,omitempty"`
}

// BudgetAppExemptEnforcement is the enforcement of an EXEMPTION marker: an
// explicit report-only budget, or an explicit cap the rail's bound left out,
// sent with no cap so the subject is not cut to its default cap (ruling D29,
// findings E-20 and E-46). An explicit row is an exception to the default,
// never a second cap; a machine's applicability rule (an exact cap overrides
// the default) honours a marker as it is, an old machine included.
const BudgetAppExemptEnforcement = "report"

// Exempt reports whether c is an exemption marker: no cap in either unit.
// A soft or hard cap always sets one (the resolver drops a capless one).
func (c BudgetAppCap) Exempt() bool {
	return c.CapUSD <= 0 && c.CapTokens <= 0
}

// BudgetAppEndUserKey is the key a machine compares an end user under: the
// org-bound hash of the trimmed id. "" for an empty id.
func BudgetAppEndUserKey(orgID, endUser string) string {
	return HashObsIdentity(ObsIdentityEndUser, orgID, strings.TrimSpace(endUser))
}

// BudgetAppCapLimit is one app cap's binding as MergeBudgetAppCapLimits reads
// it: its enforcement rank (BudgetAppEnforcementRank) and its two units, a
// zero meaning that unit is not capped.
type BudgetAppCapLimit struct {
	Rank      int
	CapUSD    float64
	CapTokens int64
}

// BudgetAppEnforcementRank orders enforcement for the merge: hard binds
// harder than soft, soft than anything else.
func BudgetAppEnforcementRank(enforcement string) int {
	switch enforcement {
	case "hard":
		return 2
	case "soft":
		return 1
	}
	return 0
}

// MergeBudgetAppCapLimits is THE rule for two app caps that compete for one
// slot (review finding E-48): the org projector (two authored rows meeting on
// one gateway key) and the machine's admission check (two caps for one
// scope, service and period) both apply it, so a dollar-only cap and a
// token-only cap on one scope bind the same way in both places.
//
// A cap of a higher enforcement rank wins outright. At equal rank the two
// MERGE unit by unit: each unit is the lower of the caps that set it, so a $5
// cap and a 1,000-token cap become one cap of $5 AND 1,000 tokens.
//
// primary names the cap the result is attributed to (its budget id): -1 for
// a, +1 for b, 0 when nothing tells them apart (the caller breaks the tie,
// by the lower budget id). The higher rank is primary; at equal rank, the
// lower dollar cap (a set cap beats none), then the lower token cap. The
// result does not depend on argument order.
func MergeBudgetAppCapLimits(a, b BudgetAppCapLimit) (merged BudgetAppCapLimit, primary int) {
	switch {
	case a.Rank > b.Rank:
		return a, -1
	case b.Rank > a.Rank:
		return b, 1
	}
	merged = BudgetAppCapLimit{
		Rank:      a.Rank,
		CapUSD:    lowerSetCap(a.CapUSD, b.CapUSD),
		CapTokens: int64(lowerSetCap(float64(a.CapTokens), float64(b.CapTokens))),
	}
	switch {
	case a.CapUSD != b.CapUSD:
		primary = sideOf(lowerSetCap(a.CapUSD, b.CapUSD) == a.CapUSD)
	case a.CapTokens != b.CapTokens:
		primary = sideOf(lowerSetCap(float64(a.CapTokens), float64(b.CapTokens)) == float64(a.CapTokens))
	}
	return merged, primary
}

// sideOf is -1 for a, +1 for b.
func sideOf(isA bool) int {
	if isA {
		return -1
	}
	return 1
}

// lowerSetCap is the lower of two caps where 0 means "not set".
func lowerSetCap(a, b float64) float64 {
	switch {
	case a <= 0:
		return b
	case b <= 0:
		return a
	case a < b:
		return a
	}
	return b
}
