package projectroi

// OwnershipRuleVersion is the version of the commit-ownership rule in
// ownership.go (the eligibility gates O1-O3, the ranking table O4-O7 and the
// share basis). It rides the org wire on every CommitOwnershipRow
// (internal/orgcontract/commitowner.go) so the org server keeps the answer a
// NEWER rule produced over a straggler push from an older one. Bump it in the
// same change that alters ownershipGates, ownershipRanks or assignShares.
//
// History: 1 - the original O1-O7 rule (lane F-PROJ). 2 - the O2b
// foreign_author gate (review 2026-09-29 finding 8): a commit by another
// author carries nothing and has no owner.
const OwnershipRuleVersion = 2
