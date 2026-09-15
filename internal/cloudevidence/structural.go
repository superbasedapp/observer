package cloudevidence

import (
	"fmt"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// structural.go is the PURE builder for the structural-insights rail
// (divergence-remediation plan rev 4.1 §3 W2 "Node half"). It composes a
// cloudcontract.StructuralSnapshot from a bounded DTO and returns
// (canonical bytes, digest) — it PERSISTS NOTHING. The store inserts those
// exact bytes; a retry resends them and never re-aggregates.
//
// Purity is unchanged from the rest of the package: cloudcontract and stdlib
// only, pinned by imports_test.go.

// Snapshot-rule versions this builder implements. They are constants, not
// caller input, because they identify the RULE the bytes were produced under —
// a caller that could pass its own would be able to mislabel a snapshot.
const (
	// StructuralPeriodRuleV1 is the activity→period mapping this build
	// implements: a session belongs to the period its START falls in, and all
	// of that session's actions and token rows belong with it. Late data
	// re-snapshots the same window at a higher revision rather than moving
	// between windows. Changing this rule means shipping version 2, never
	// silently re-bucketing history.
	StructuralPeriodRuleV1 = 1
	// StructuralTimezoneRuleV1 is the timezone rule: the period's UTC
	// boundaries are resolved from the account's DECLARED IANA zone (never
	// from the machine's local zone), by the caller, before aggregation. A
	// device that travels does not re-bucket its history.
	StructuralTimezoneRuleV1 = 1
)

// Coverage-band thresholds (v1). Ratio = numerator / SessionCount.
//
//	ratio == 0                     -> none
//	0 < ratio < lowCeiling         -> low
//	lowCeiling <= r < mediumCeiling-> medium
//	ratio >= mediumCeiling         -> high
//
// Even thirds, deliberately: the bands make no claim finer than "hardly any /
// a minority / a majority / nearly all", and an even split is the one choice
// that needs no justification story. They are constants here rather than in
// the contract because they are a BUILD rule — a consumer can always re-band
// from the raw numerators the snapshot carries.
const (
	structuralBandLowCeiling    = 1.0 / 3.0
	structuralBandMediumCeiling = 2.0 / 3.0
)

// StructuralUnclassifiedKey is the bucket a mix key falls into when it cannot
// be expressed as a valid category key (invalid UTF-8, a control character, a
// path separator, or over-long). Merging into a named bucket rather than
// dropping the count keeps the mix's counts summing to the session count; and
// rather than failing the whole window, because one malformed local tool
// string should not cost a developer their day's insights.
const StructuralUnclassifiedKey = "unclassified"

// StructuralMixInput is one raw categorical count from the store DTO. Key is a
// raw local value; the builder normalizes, merges, and sorts.
type StructuralMixInput struct {
	Key   string
	Count int
}

// StructuralDayInput is the bounded, content-free window DTO the caller
// assembles from store rows (internal/store.StructuralDayFacts) and hands to
// BuildStructuralSnapshot. It carries no paths, no excerpts, and no session
// identity — there is no field in which any of those could be expressed.
type StructuralDayInput struct {
	// Period is the "YYYY-MM-DD" calendar day in the account's declared zone.
	Period string
	// Revision is the 1-based revision the store allocated for this window.
	Revision int
	// SourceWatermark is the RFC3339 maximum local event time included, or ""
	// when the window carried no activity.
	SourceWatermark string

	// SessionCount / ActionCount are the window's counts.
	SessionCount int
	ActionCount  int
	// ToolMix / ModelFamilyMix are raw categorical counts, in any order, with
	// duplicate keys permitted (the builder merges them).
	ToolMix        []StructuralMixInput
	ModelFamilyMix []StructuralMixInput
	// TokensIn / TokensOut / CacheReadTokens / CostUSD are the window's sums.
	TokensIn        int
	TokensOut       int
	CacheReadTokens int
	CostUSD         float64
	// SessionsWithOutcomes / SessionsWithVerification are the coverage
	// numerators the bands are derived from. Their definitions are the store
	// seam's (internal/store/structuralinsights.go's COVERAGE-NUMERATOR
	// DEFINITIONS block); the builder only bands them.
	SessionsWithOutcomes     int
	SessionsWithVerification int
}

// StructuralBuildOptions carries the account-level facts the DTO does not.
//
// There is deliberately NO clock here. A snapshot carries no build timestamp:
// two builds of the same window must produce byte-identical output, or the
// digest stops identifying the window's CONTENT and idempotent replay-ack
// stops working. Every time value in the snapshot comes from the data (the
// period, the watermark), never from when the build happened.
type StructuralBuildOptions struct {
	// DeclaredTimezone is the account's declared IANA zone name. Required — it
	// is what gives Period its meaning, and guessing it would silently
	// re-bucket a traveling developer's history.
	DeclaredTimezone string
}

// BuildStructuralSnapshot composes a validated StructuralSnapshot from a window
// DTO. It normalizes, merges, and sorts both categorical mixes; derives the two
// coverage bands; derives the Active flag; stamps the rule versions; and
// validates the result before returning it, so an invalid snapshot can never
// escape the builder.
func BuildStructuralSnapshot(in StructuralDayInput, opts StructuralBuildOptions) (cloudcontract.StructuralSnapshot, error) {
	const pfx = "cloudevidence.BuildStructuralSnapshot"
	if opts.DeclaredTimezone == "" {
		return cloudcontract.StructuralSnapshot{}, fmt.Errorf("%s: declared timezone is required", pfx)
	}
	if in.SessionCount < 0 {
		return cloudcontract.StructuralSnapshot{}, fmt.Errorf("%s: session_count %d is negative", pfx, in.SessionCount)
	}
	// A DTO claiming activity with no sessions is internally inconsistent —
	// zeroing it silently would discard real counts, so refuse instead.
	if in.SessionCount == 0 {
		if in.ActionCount != 0 || in.TokensIn != 0 || in.TokensOut != 0 || in.CacheReadTokens != 0 ||
			in.CostUSD != 0 || len(in.ToolMix) != 0 || len(in.ModelFamilyMix) != 0 ||
			in.SessionsWithOutcomes != 0 || in.SessionsWithVerification != 0 {
			return cloudcontract.StructuralSnapshot{}, fmt.Errorf("%s: session_count is 0 but the window carries aggregates", pfx)
		}
	}

	toolMix, err := normalizeMix("tool_mix", in.ToolMix)
	if err != nil {
		return cloudcontract.StructuralSnapshot{}, fmt.Errorf("%s: %w", pfx, err)
	}
	familyMix, err := normalizeMix("model_family_mix", in.ModelFamilyMix)
	if err != nil {
		return cloudcontract.StructuralSnapshot{}, fmt.Errorf("%s: %w", pfx, err)
	}

	snap := cloudcontract.StructuralSnapshot{
		SchemaVersion:            cloudcontract.StructuralSnapshotSchemaVersion,
		Period:                   in.Period,
		PeriodRuleVersion:        StructuralPeriodRuleV1,
		TimezoneRuleVersion:      StructuralTimezoneRuleV1,
		DeclaredTimezone:         opts.DeclaredTimezone,
		Revision:                 in.Revision,
		SourceWatermark:          in.SourceWatermark,
		Active:                   in.SessionCount > 0,
		SessionCount:             in.SessionCount,
		ActionCount:              in.ActionCount,
		ToolMix:                  toolMix,
		ModelFamilyMix:           familyMix,
		TokensIn:                 in.TokensIn,
		TokensOut:                in.TokensOut,
		CacheReadTokens:          in.CacheReadTokens,
		CostUSD:                  in.CostUSD,
		VerificationCoverageBand: CoverageBandFor(in.SessionsWithVerification, in.SessionCount),
		OutcomeEvidenceBand:      CoverageBandFor(in.SessionsWithOutcomes, in.SessionCount),
		CoverageDenominators: cloudcontract.StructuralCoverageDenominators{
			SessionsWithOutcomes:     in.SessionsWithOutcomes,
			SessionsWithVerification: in.SessionsWithVerification,
		},
	}
	if err := snap.Validate(); err != nil {
		return cloudcontract.StructuralSnapshot{}, fmt.Errorf("%s: %w", pfx, err)
	}
	return snap, nil
}

// CoverageBandFor maps a numerator/denominator pair to a coverage band. A
// zero (or negative) denominator is "none": there is nothing to have covered.
func CoverageBandFor(numerator, denominator int) cloudcontract.CoverageBand {
	if denominator <= 0 || numerator <= 0 {
		return cloudcontract.CoverageBandNone
	}
	ratio := float64(numerator) / float64(denominator)
	switch {
	case ratio < structuralBandLowCeiling:
		return cloudcontract.CoverageBandLow
	case ratio < structuralBandMediumCeiling:
		return cloudcontract.CoverageBandMedium
	default:
		return cloudcontract.CoverageBandHigh
	}
}

// normalizeMix turns raw categorical counts into the contract's canonical mix:
// every key normalized (an unrepresentable key folds into
// StructuralUnclassifiedKey), duplicate keys merged by summing, non-positive
// counts dropped, and the result sorted by key ascending.
//
// Merging + sorting here is what makes the digest independent of the ORDER the
// store happened to return rows in — two aggregations of the same window
// produce identical bytes even if SQLite grouped them differently.
func normalizeMix(field string, in []StructuralMixInput) ([]cloudcontract.StructuralMixEntry, error) {
	if len(in) == 0 {
		return nil, nil
	}
	merged := make(map[string]int, len(in))
	for i, e := range in {
		if e.Count <= 0 {
			continue
		}
		key, err := cloudcontract.NormalizeMixKey(fmt.Sprintf("%s[%d].key", field, i), e.Key)
		if err != nil {
			key = StructuralUnclassifiedKey
		}
		merged[key] += e.Count
	}
	if len(merged) == 0 {
		return nil, nil
	}
	if len(merged) > cloudcontract.MaxStructuralMixEntries {
		return nil, fmt.Errorf("%s has %d distinct keys, exceeds max %d",
			field, len(merged), cloudcontract.MaxStructuralMixEntries)
	}
	out := make([]cloudcontract.StructuralMixEntry, 0, len(merged))
	for k, n := range merged {
		out = append(out, cloudcontract.StructuralMixEntry{Key: k, Count: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// SerializeStructural is THE ONE function that produces the structural
// snapshot's bytes — the peer of Serialize for the session envelope, and the
// same guarantee: what is previewed, what is digested, and what is uploaded are
// one byte-string, because there is no second serializer.
//
// It works on a copy of s (the caller's snapshot is never mutated), validates,
// computes the NON-SELF-REFERENTIAL digest over the canonical preimage (the
// snapshot with the digest field absent), stamps it, and returns the final
// bytes with the digest embedded — so the server can RECOMPUTE the digest from
// exactly the bytes it received instead of trusting a client-declared value.
func SerializeStructural(s cloudcontract.StructuralSnapshot) ([]byte, string, error) {
	const pfx = "cloudevidence.SerializeStructural"
	s.Digest = "" // belt-and-braces: never digest over a previously-stamped value
	if err := s.Validate(); err != nil {
		return nil, "", fmt.Errorf("%s: %w", pfx, err)
	}
	digest, err := cloudcontract.StructuralDigest(s)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", pfx, err)
	}
	s.Digest = digest
	final, err := cloudcontract.StructuralUploadBytes(s)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", pfx, err)
	}
	return final, digest, nil
}
