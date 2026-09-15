package cloudcontract

import (
	"fmt"
	"strings"
)

// community.go is the WIRE CONTRACT for the W5 cohort-benchmarking contribution
// upload (divergence-remediation plan §3 W5 "contribution-upload path"). A node
// that holds a live community_cohort_benchmarking grant computes ONE derived
// scalar for a (cohort, metric, version, window) and uploads it; the hosted read
// surface + delayed-band materialization (already built, migrations 0022/0023)
// turn a floored, k-suppressed cohort of such scalars into a private band + the
// contributor's own placement.
//
// The digest discipline mirrors StructuralSnapshot exactly and for the same
// reason: the node digests the canonical bytes, stores/sends them VERBATIM, and
// the server RECOMPUTES the digest from what arrived (a client-declared digest
// is evidence of nothing). Unlike an evidence envelope, a contribution carries
// no excerpts, no paths, and no per-session identifiers — only the four fixed
// registry identifiers and one number.

// CommunityContributionSchemaVersion is the schema the contribution bytes are
// built against. A `-candidate` suffix marks it pre-launch (mirrors structural).
const CommunityContributionSchemaVersion = "community_contribution.v1-candidate"

const (
	// MaxCohortKeyBytes bounds a cohort identifier. Cohort keys are fixed
	// registry values ("global", "lang:go"); 64 bytes is generous headroom and a
	// hard wall the server also enforces.
	MaxCohortKeyBytes = 64
	// MaxMetricIDBytes bounds a metric identifier, same discipline.
	MaxMetricIDBytes = 64
	// MaxContributionValue is a data-independent absolute ceiling on a single
	// contribution value — a sanity wall against a NaN/Inf/absurd upload, NOT a
	// metric-specific range (that belongs to the registry/builder). A month of
	// per-active-day rates or a 0..100 percentage sit far below it.
	MaxContributionValue = 1e9
)

// CommunityWindowLayout is the documented window format, published in the data
// dictionary so a developer previews exactly what a window id means.
const CommunityWindowLayout = "YYYY-MM (UTC calendar month)"

// CommunitySourceWindowRule is the versioned identifier of WHICH activity a
// STANDING cohort-benchmarking grant covers — the community counterpart to the
// structural rail's source-window rule, and the value the node records on the
// receipt, prints on the binding screen, and declares on the wire beside every
// contribution.
//
// v1, "in_progress_utc_month_after_grant": the contribution for a UTC calendar
// month is the developer's own running value for the CURRENT, IN-PROGRESS
// month. It is recomputed and re-sent on every sync until that month closes;
// the server then freezes it (its finalized-window rule) and the last value it
// received before close is what the cohort aggregation uses. The month the
// grant is created in is NEVER contributed: the first eligible month is the
// first one that starts after the grant, so no activity from before consent
// existed is ever folded into a scalar.
//
// The rule was previously named "completed_utc_months_after_grant" and its
// disclosure said "per completed calendar month" — which is not what egress
// did (Sol re-review N1). It is part of the community data dictionary below,
// so renaming it changed the dictionary digest every community receipt binds:
// a receipt recorded under the old rule no longer matches the dictionary this
// package serves, the node refuses to send under it, and the server refuses a
// contribution declaring it (data_dictionary_mismatch). Reconfirmation is the
// only way forward, by design.
const CommunitySourceWindowRule = "in_progress_utc_month_after_grant"

// CommunityDeclaredTimezone is the ONLY timezone a cohort-benchmarking grant
// may declare. Community windows are UTC calendar months everywhere — in the
// eligibility rule, in the metric computation, on the wire, and in the hosted
// finalization — so a declared zone that changed none of those would be a
// binding term that binds nothing (Sol re-review N5). It is part of the data
// dictionary for the same reason the source-window rule is.
const CommunityDeclaredTimezone = "UTC"

// validCommunityWindow reports whether s is a 'YYYY-MM' UTC-month id with a
// month in 01..12 — the same shape the leaderboard_contributions.window_id CHECK
// constraint enforces. Hand-rolled rather than via regexp: this package's closed
// import allowlist excludes regexp, and the grammar is trivial.
func validCommunityWindow(s string) bool {
	if len(s) != 7 || s[4] != '-' {
		return false
	}
	for i := 0; i < 4; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	if s[5] < '0' || s[5] > '9' || s[6] < '0' || s[6] > '9' {
		return false
	}
	month := int(s[5]-'0')*10 + int(s[6]-'0')
	return month >= 1 && month <= 12
}

// CommunityContribution is ONE immutable per-account contribution for one
// window. The four identifiers are fixed registry values (the server rejects an
// unregistered cohort/metric); Value is the account's own derived metric value.
type CommunityContribution struct {
	// SchemaVersion is the contribution schema these bytes were built against.
	SchemaVersion string `json:"schema_version"`
	// CohortKey is the fixed versioned cohort identifier ("global", "lang:go").
	CohortKey string `json:"cohort_key"`
	// MetricID / MetricVersion name the fixed registry metric.
	MetricID      string `json:"metric_id"`
	MetricVersion int    `json:"metric_version"`
	// WindowID is the 'YYYY-MM' UTC-month window this value belongs to.
	WindowID string `json:"window_id"`
	// Value is the account's own derived metric value for the window. Finite and
	// non-negative; the cross-tenant read never projects it raw (banded + floored
	// + k-suppressed), and the owning account reads it back only under RLS.
	Value float64 `json:"value"`
	// Digest is the NON-SELF-REFERENTIAL "sha256:<hex>" over the preimage (this
	// struct with Digest absent). Omitempty so the preimage never contains it.
	Digest string `json:"digest,omitempty"`
}

// Validate enforces every structural bound the wire type promises. It is the
// same check the node runs before digesting and the server runs after parsing,
// so a body that validates on one side validates on the other.
func (c CommunityContribution) Validate() error {
	const pfx = "cloudcontract.CommunityContribution.Validate"
	if c.SchemaVersion != CommunityContributionSchemaVersion {
		return fmt.Errorf("%s: unsupported schema_version %q", pfx, c.SchemaVersion)
	}
	if c.CohortKey == "" {
		return fmt.Errorf("%s: cohort_key is required", pfx)
	}
	if len(c.CohortKey) > MaxCohortKeyBytes {
		return fmt.Errorf("%s: cohort_key exceeds %d bytes", pfx, MaxCohortKeyBytes)
	}
	if c.MetricID == "" {
		return fmt.Errorf("%s: metric_id is required", pfx)
	}
	if len(c.MetricID) > MaxMetricIDBytes {
		return fmt.Errorf("%s: metric_id exceeds %d bytes", pfx, MaxMetricIDBytes)
	}
	if c.MetricVersion <= 0 {
		return fmt.Errorf("%s: metric_version must be positive", pfx)
	}
	if !validCommunityWindow(c.WindowID) {
		return fmt.Errorf("%s: window_id %q is not 'YYYY-MM'", pfx, c.WindowID)
	}
	// Finiteness without importing math (not in this package's allowlist):
	// (v - v) is exactly 0 for every finite v, and NaN for NaN and for ±Inf, so
	// this single test rejects every non-finite value with the honest message
	// before the range checks below (which would otherwise mislabel +Inf as
	// merely "over the ceiling").
	if c.Value-c.Value != 0 {
		return fmt.Errorf("%s: value must be finite", pfx)
	}
	if c.Value < 0 {
		return fmt.Errorf("%s: value must be non-negative", pfx)
	}
	if c.Value > MaxContributionValue {
		return fmt.Errorf("%s: value exceeds the %g sanity ceiling", pfx, MaxContributionValue)
	}
	return nil
}

// CommunityPreimage returns the canonical preimage the digest is computed over:
// c marshaled with Digest absent. It never covers itself.
func CommunityPreimage(c CommunityContribution) ([]byte, error) {
	c.Digest = ""
	b, err := marshalCanonical(c)
	if err != nil {
		return nil, fmt.Errorf("cloudcontract.CommunityPreimage: %w", err)
	}
	return b, nil
}

// CommunityDigest returns the "sha256:<hex>" digest over CommunityPreimage(c).
// The server recomputes this same value from the bytes it received — a
// client-declared digest is never trusted as proof of byte equality.
func CommunityDigest(c CommunityContribution) (string, error) {
	pre, err := CommunityPreimage(c)
	if err != nil {
		return "", fmt.Errorf("cloudcontract.CommunityDigest: %w", err)
	}
	return digest(pre), nil
}

// CommunityUploadBytes returns the final exact serialized bytes for c: the
// canonical serialization WITH Digest as currently set. These are the bytes the
// node sends verbatim — there is no second serialization anywhere, so what was
// digested and what is sent cannot diverge.
func CommunityUploadBytes(c CommunityContribution) ([]byte, error) {
	b, err := marshalCanonical(c)
	if err != nil {
		return nil, fmt.Errorf("cloudcontract.CommunityUploadBytes: %w", err)
	}
	return b, nil
}

// communityDataDictionary enumerates EXACTLY the contribution shape a standing
// cohort-benchmarking grant binds — every wire field (by its JSON name, because
// that is what appears in the bytes a developer previews) plus every bound and
// the schema/window layout. It deliberately does NOT enumerate the specific
// registry cohort/metric ids: which cohorts and metrics are contributable is
// enforced by the server-side registry at write time and evolves independently,
// whereas this digest must stay stable for a standing grant across such
// additions. Kept sorted (TestCommunityDataDictionaryIsSorted).
var communityDataDictionary = []string{
	"field:community_contribution.cohort_key:string",
	"field:community_contribution.digest:string_omitempty",
	"field:community_contribution.metric_id:string",
	"field:community_contribution.metric_version:int",
	"field:community_contribution.schema_version:string",
	"field:community_contribution.value:float64",
	"field:community_contribution.window_id:string",

	"grant:declared_timezone:" + CommunityDeclaredTimezone,

	"limit:max_cohort_key_bytes:64",
	"limit:max_contribution_value:1000000000",
	"limit:max_metric_id_bytes:64",

	"schema_version:" + CommunityContributionSchemaVersion,
	"source_window_rule:" + CommunitySourceWindowRule,
	"window_layout:" + CommunityWindowLayout,
}

// CommunityDataDictionaryPreimage returns the exact bytes the community data-
// dictionary digest is computed over: the canonical enumeration joined with
// "\n". Exported so a consent surface can show a developer precisely what the
// digest on their standing grant covers.
func CommunityDataDictionaryPreimage() []byte {
	return []byte(strings.Join(communityDataDictionary, "\n"))
}

// CommunityDataDictionaryDigest returns the "sha256:<hex>" digest over
// CommunityDataDictionaryPreimage(). A STANDING cohort-benchmarking grant binds
// this value; an upload declares the value it was built under, and the server
// refuses one that is not the dictionary it currently serves.
func CommunityDataDictionaryDigest() string {
	return digest(CommunityDataDictionaryPreimage())
}
