package aigateway

// Usage is the token accounting for one inference turn, observed from the
// provider response. Per Sol S12 token usage is AUTHORITATIVE; the dollar
// figures derived from it (see RateCard) are estimates.
type Usage struct {
	InputTokens      int
	OutputTokens     int
	CacheReadTokens  int
	CacheWriteTokens int
}

// TotalTokens is the sum across all four buckets, used for coarse metadata
// and the load-test DB-write budget accounting.
func (u Usage) TotalTokens() int {
	return u.InputTokens + u.OutputTokens + u.CacheReadTokens + u.CacheWriteTokens
}

// EconomicOwner is the spend-ledger category dimension carried from day one
// (design §2.6b) so a developer's coding spend, the org's own intelligence
// jobs, and judge/eval calls never conflate in budgets or rollups.
type EconomicOwner string

const (
	// OwnerDeveloper is coding-agent traffic, attributed to the member.
	OwnerDeveloper EconomicOwner = "developer"
	// OwnerOrgIntelligence is the parity-arc enrichment/review/report jobs,
	// attributed to the org/feature rather than a member.
	OwnerOrgIntelligence EconomicOwner = "org_intelligence"
	// OwnerJudge is judge/eval inference (admission judges, eval judges).
	OwnerJudge EconomicOwner = "judge"
)

// economicOwners is the closed vocabulary. Validation refuses anything else
// so a caller cannot silently persist an unbounded category.
var economicOwners = map[EconomicOwner]struct{}{
	OwnerDeveloper:       {},
	OwnerOrgIntelligence: {},
	OwnerJudge:           {},
}

// ValidEconomicOwner reports whether o is one of the closed categories.
func ValidEconomicOwner(o EconomicOwner) bool {
	_, ok := economicOwners[o]
	return ok
}

// DataControl annotates what an upstream route actually guarantees about the
// customer's data (design §2.6b). The org variant explicitly cannot inherit
// the personal plane's ZDR promise, so the annotation is how an admin sees
// the real posture of a configured route. It is a LABEL surfaced in the
// dashboard, never a security control the gateway enforces.
type DataControl string

const (
	// DataControlSelfHosted — a `local` upstream the org operates itself.
	DataControlSelfHosted DataControl = "self_hosted"
	// DataControlContract — a contract provider (e.g. Azure with a DPA).
	DataControlContract DataControl = "contract"
	// DataControlZDR — a zero-data-retention route the admin has arranged.
	DataControlZDR DataControl = "zdr"
	// DataControlUnspecified — the honest default when nothing is asserted.
	DataControlUnspecified DataControl = "unspecified"
)

// dataControls is the closed annotation vocabulary.
var dataControls = map[DataControl]struct{}{
	DataControlSelfHosted:  {},
	DataControlContract:    {},
	DataControlZDR:         {},
	DataControlUnspecified: {},
}

// NormalizeDataControl coerces an empty or unknown value to Unspecified — an
// unrecognized label must never read as a stronger guarantee than it is.
func NormalizeDataControl(d DataControl) DataControl {
	if _, ok := dataControls[d]; !ok {
		return DataControlUnspecified
	}
	return d
}

// CredentialMode selects how the gateway authenticates to an upstream on a
// member's behalf, per the ToS research (docs/general_info/
// gateway-vendor-tos-research-2026-08-29.md): a single org-held credential
// (the blessed default), or a per-developer provider-scoped key mapping
// (OpenAI Projects / Anthropic Workspaces) so literal shared-secret fan-out
// is avoided where the provider's own primitive supports per-member keys.
type CredentialMode string

const (
	// CredentialSingleOrg uses one org credential for every member (default).
	CredentialSingleOrg CredentialMode = "single_org"
	// CredentialPerDeveloper maps the virtual key to a provider-scoped key.
	CredentialPerDeveloper CredentialMode = "per_developer"
)

// NormalizeCredentialMode defaults an empty/unknown value to the blessed
// single-org credential.
func NormalizeCredentialMode(m CredentialMode) CredentialMode {
	if m == CredentialPerDeveloper {
		return CredentialPerDeveloper
	}
	return CredentialSingleOrg
}
