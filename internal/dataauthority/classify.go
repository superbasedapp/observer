package dataauthority

// Version is the schema version of this package's exported classification
// contract. Design §5.3 item 7 requires the classifier be "a stable,
// versioned local API, not an internal flag" — a future caller (starting
// with the personal client) reads Version alongside Authority so a later
// incompatible reshape of Classification is detectable rather than
// silently misread. Bump this only on a breaking change to Classification
// or the exported functions' semantics; additive fields do not require a
// bump.
const Version = 1

// Authority names which plane owns a unit of node data.
type Authority string

const (
	// AuthorityPersonal marks data captured on a node that has never been
	// org-enrolled (or, for a unit classified before any enrolment,
	// captured before that enrolment happened). The personal cloud plane
	// may consider it for enrichment/cohorts/leaderboards, subject to
	// that plane's own developer-consent gate — dataauthority answers
	// "whose data is this," not "did the developer opt in."
	AuthorityPersonal Authority = "personal"

	// AuthorityOrg marks data captured while the node was org-enrolled,
	// under EITHER product posture (teams or enterprise) — the posture
	// split governs how much content the org itself receives
	// (internal/store.ShareOptions.shipsRawContent's teams-vs-enterprise
	// disjunct), not whether the org owns the data. The personal cloud
	// plane MUST refuse AuthorityOrg data for personal
	// enrichment/cohorts/leaderboards regardless of the developer's own
	// personal consent (design §5.3 item 7) — Eligible reports this
	// refusal directly so a caller never has to re-derive it.
	AuthorityOrg Authority = "org"
)

// EnrolmentState is the one fact this package needs from the caller: is
// the node, right now, enrolled with an org. Callers assemble this from
// their own state (e.g. internal/orgclient's config-resolved enrolment) —
// dataauthority does not read config, TOML, or any store itself.
type EnrolmentState struct {
	// Enrolled is true when the node is currently registered with an org
	// server under either product posture. Which posture is irrelevant to
	// authority classification (see AuthorityOrg's doc comment) so it is
	// deliberately not a field here — keeping the input to the one fact
	// that changes the answer is what design §5.3 item 7 means by "small."
	Enrolled bool
}

// Classification is the exported result: which plane owns a unit of data,
// carried with the contract Version it was computed under.
type Classification struct {
	// Authority is the classification itself.
	Authority Authority
	// Version is the Version this Classification was computed under. A
	// caller persisting a Classification should persist Version alongside
	// it, so a later contract change is a known migration, not silent
	// data drift.
	Version int
}

// EligibleForPersonalEnrichment reports whether c may be considered for
// personal-cloud-plane enrichment, cohorts, or leaderboards. Only
// AuthorityPersonal data is eligible; AuthorityOrg data is refused
// unconditionally, "regardless of the developer's personal consent"
// (design §5.3 item 7) — consent is a separate, later gate that only ever
// narrows eligibility further, never widens past what this reports.
func (c Classification) EligibleForPersonalEnrichment() bool {
	return c.Authority == AuthorityPersonal
}

// EligibleForOrgEnrichment reports whether c may be considered for the
// ORG-served intelligence rail (the enrolled-node plane). Only AuthorityOrg
// data is eligible; AuthorityPersonal data is refused (it belongs to the
// personal plane) and an unknown authority (NULL / pre-096 row / fail-closed
// enrolment read) is refused too.
//
// This is the exact disjoint counterpart of EligibleForPersonalEnrichment:
// the two predicates are mutually exclusive and neither one covers the unknown
// authority, which is how INV-1 ("org data to the org rail only, personal to
// the personal plane only, unknown to neither") holds by construction. Like
// its sibling, this answers "whose data is this," not "did anyone opt in" —
// consent is a separate, later gate that only ever narrows further.
func (c Classification) EligibleForOrgEnrichment() bool {
	return c.Authority == AuthorityOrg
}

// ClassifyAtCapture computes the Classification for a unit of data being
// captured right now, given the node's current enrolment state. It has no
// notion of prior state — call Combine instead when a unit of data
// already carries an earlier Classification (e.g. re-classifying an
// existing session on each check) so stickiness is honored.
func ClassifyAtCapture(state EnrolmentState) Classification {
	if state.Enrolled {
		return Classification{Authority: AuthorityOrg, Version: Version}
	}
	return Classification{Authority: AuthorityPersonal, Version: Version}
}

// Combine applies the sticky-classification rule (design §5.3 item 7(b)):
// a unit of data that has ever been classified AuthorityOrg stays
// AuthorityOrg, including after the node later de-enrols — the safer
// default. prior is the unit's last-known Classification, or nil if it
// has never been classified before (e.g. first capture). state is the
// node's CURRENT enrolment state.
//
// The returned Classification always carries the current Version: a prior
// Classification computed under an older Version is upgraded (its
// Authority is preserved — stickiness applies to Authority, not to the
// Version it happened to be recorded under) rather than left stale.
func Combine(prior *Classification, state EnrolmentState) Classification {
	if prior != nil && prior.Authority == AuthorityOrg {
		return Classification{Authority: AuthorityOrg, Version: Version}
	}
	return ClassifyAtCapture(state)
}
