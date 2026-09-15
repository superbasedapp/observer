package cloudevidence

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// community.go is the PURE builder for the W5 cohort-benchmarking
// contribution upload (divergence-remediation plan §3 W5 "contribution-upload
// path"). It composes a cloudcontract.CommunityContribution from a single
// caller-supplied metric value and returns (canonical bytes, digest) — it
// PERSISTS NOTHING and NEVER COMPUTES the value itself. The value arrives
// already derived (by whichever store-side aggregation owns the metric); the
// builder's only job is to stamp the fixed registry identifiers, digest the
// result, and validate it before it can leave the machine.
//
// Purity is unchanged from the rest of the package: cloudcontract and stdlib
// only, pinned by imports_test.go.

// CommunityInput is the bounded, content-free DTO the caller assembles for
// one contribution and hands to BuildCommunityContribution. It carries no
// paths, no excerpts, and no session identity — only the four fixed registry
// identifiers and the account's own derived value.
type CommunityInput struct {
	// CohortKey is the fixed versioned cohort identifier ("global", "lang:go").
	CohortKey string
	// MetricID / MetricVersion name the fixed registry metric.
	MetricID      string
	MetricVersion int
	// WindowID is the "YYYY-MM" UTC-month window this value belongs to.
	WindowID string
	// Value is the account's own derived metric value for the window.
	Value float64
}

// BuildCommunityContribution composes a validated CommunityContribution from
// in: it stamps the schema version, validates, and only then digests the
// result, so an invalid contribution can never escape the builder.
//
// Validation runs BEFORE digesting rather than after: CommunityDigest
// marshals the contribution to JSON, and a NaN/Inf value fails that marshal
// with an opaque encoding error before Validate's own "must be finite" check
// ever gets a chance to run. Validating first guarantees the caller always
// sees Validate's message, never a json-encoding one, for the same class of
// bad input.
func BuildCommunityContribution(in CommunityInput) (cloudcontract.CommunityContribution, error) {
	const pfx = "cloudevidence.BuildCommunityContribution"
	c := cloudcontract.CommunityContribution{
		SchemaVersion: cloudcontract.CommunityContributionSchemaVersion,
		CohortKey:     in.CohortKey,
		MetricID:      in.MetricID,
		MetricVersion: in.MetricVersion,
		WindowID:      in.WindowID,
		Value:         in.Value,
	}
	if err := c.Validate(); err != nil {
		return cloudcontract.CommunityContribution{}, fmt.Errorf("%s: %w", pfx, err)
	}
	digest, err := cloudcontract.CommunityDigest(c)
	if err != nil {
		return cloudcontract.CommunityContribution{}, fmt.Errorf("%s: %w", pfx, err)
	}
	c.Digest = digest
	return c, nil
}

// SerializeCommunity is THE ONE function that produces a community
// contribution's bytes — the peer of SerializeStructural, and the same
// guarantee: what is previewed, what is digested, and what is uploaded are
// one byte-string, because there is no second serializer.
//
// It works on a copy of c (the caller's contribution is never mutated),
// validates, computes the NON-SELF-REFERENTIAL digest over the canonical
// preimage (the contribution with the digest field absent), stamps it, and
// returns the final bytes with the digest embedded — so the server can
// RECOMPUTE the digest from exactly the bytes it received instead of trusting
// a client-declared value.
func SerializeCommunity(c cloudcontract.CommunityContribution) ([]byte, string, error) {
	const pfx = "cloudevidence.SerializeCommunity"
	c.Digest = "" // belt-and-braces: never digest over a previously-stamped value
	if err := c.Validate(); err != nil {
		return nil, "", fmt.Errorf("%s: %w", pfx, err)
	}
	digest, err := cloudcontract.CommunityDigest(c)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", pfx, err)
	}
	c.Digest = digest
	final, err := cloudcontract.CommunityUploadBytes(c)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", pfx, err)
	}
	return final, digest, nil
}
