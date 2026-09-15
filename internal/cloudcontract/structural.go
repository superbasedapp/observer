package cloudcontract

import (
	"fmt"
	"strings"
	"time"
)

// structural.go is the "structural_insights.v1-candidate" schema: the
// immutable per-device per-window snapshot the structural-insights rail
// uploads under a STANDING consent grant (divergence-remediation plan rev 4.1
// §2 R1 + §3 W2 "Contract").
//
// What makes this schema different from the session Envelope:
//
//   - It is a WINDOW, not a session. One row per (period, period-rule version,
//     schema version, revision) — no session identity of any kind.
//   - It carries DETERMINISTIC AGGREGATES ONLY. There are no paths, no
//     excerpts, no repo identity, no free text, and no per-session rows — the
//     TYPE makes them inexpressible, not merely "validated away". The only
//     string-valued data are the period, the declared IANA timezone, the two
//     closed-vocabulary coverage bands, and the tool / model-family mix KEYS
//     (bounded, separator-free, control-free — see NormalizeMixKey).
//   - It carries ONE digest, not two. The session Envelope needs two because it
//     is REBUILT at send time (a content digest stable across framing, plus a
//     digest over the final bytes). A structural snapshot is serialized ONCE
//     and its exact bytes are stored and resent verbatim, so a second framing
//     digest would add nothing. The single digest is NON-SELF-REFERENTIAL,
//     computed over the canonical bytes with the digest field absent — the same
//     discipline as EvidenceContentDigest in digest.go — and it is EMBEDDED in
//     the upload bytes so the server can recompute it from what it received
//     rather than trust a client-declared value.
//
// Field declaration order IS the canonical serialization order (marshalCanonical
// in digest.go relies on struct-order marshaling, and the type contains no Go
// maps). Reordering fields changes every digest: do not reorder.

// StructuralSnapshotSchemaVersion identifies the structural-insights snapshot
// schema. ".v1-candidate" pre-launch (plan §4(a)) — versioned and mutable until
// the A0-exit freeze.
const StructuralSnapshotSchemaVersion = "structural_insights.v1-candidate"

// CoverageBand is a closed-vocabulary honesty qualifier: how much of a window's
// session set carried the evidence a band names. It is deliberately a BAND, not
// a ratio — the raw numerator/denominator ride along in
// StructuralCoverageDenominators, so a consumer that wants the ratio computes
// it, and a consumer that wants a headline reads the band.
type CoverageBand string

const (
	// CoverageBandNone means no session in the window carried the evidence.
	CoverageBandNone CoverageBand = "none"
	// CoverageBandLow means some but under a third of sessions carried it.
	CoverageBandLow CoverageBand = "low"
	// CoverageBandMedium means between a third and two thirds carried it.
	CoverageBandMedium CoverageBand = "medium"
	// CoverageBandHigh means two thirds or more carried it.
	CoverageBandHigh CoverageBand = "high"
)

// allCoverageBands is the canonical ordered vocabulary (ascending coverage).
var allCoverageBands = []CoverageBand{
	CoverageBandNone,
	CoverageBandLow,
	CoverageBandMedium,
	CoverageBandHigh,
}

// AllCoverageBands returns a copy of the coverage-band vocabulary in ascending
// order.
func AllCoverageBands() []CoverageBand {
	out := make([]CoverageBand, len(allCoverageBands))
	copy(out, allCoverageBands)
	return out
}

// Valid reports whether b is one of the four known coverage bands.
func (b CoverageBand) Valid() bool {
	for _, known := range allCoverageBands {
		if b == known {
			return true
		}
	}
	return false
}

// StructuralMixEntry is one entry of a categorical mix. It is a SORTED SLICE
// entry rather than a map value on purpose: canonical serialization requires
// deterministic ordering, and Go map iteration is randomized. The builder sorts
// by Key ascending and merges duplicates; Validate re-checks both.
type StructuralMixEntry struct {
	// Key is the bounded, separator-free category key (a tool identifier or a
	// coarse model family). Never a path, never free text.
	Key string `json:"key"`
	// Count is the number of sessions in the window attributed to Key.
	Count int `json:"count"`
}

// StructuralCoverageDenominators carries the RAW numerators behind the two
// coverage bands, so the bands are auditable rather than opaque. Both are
// counts of SESSIONS within the window (the denominator is SessionCount).
type StructuralCoverageDenominators struct {
	// SessionsWithOutcomes is how many of the window's sessions carried
	// recorded evidence of HOW the work went. See the node-side definition in
	// internal/store/structuralinsights.go — it is a deliberately narrow,
	// honest definition, and the band exists precisely so a low number reads
	// as "this aggregate is thinly evidenced" rather than being hidden.
	SessionsWithOutcomes int `json:"sessions_with_outcomes"`
	// SessionsWithVerification is how many of the window's sessions submitted
	// work to an external checker (an executed command whose exit status the
	// harness recorded). It is an UPPER BOUND on "the work was verified".
	SessionsWithVerification int `json:"sessions_with_verification"`
}

// StructuralSnapshot is the "structural_insights.v1-candidate" schema. It is
// constructed only by internal/cloudevidence.BuildStructuralSnapshot and
// serialized only by internal/cloudevidence.SerializeStructural.
//
// The canonical bytes cover EVERYTHING the server-side idempotency key covers
// (period, period-rule version, schema version, revision — plus the timezone
// rule and declared timezone that give the period its meaning), so a replay-ack
// comparison on (key, digest) is a comparison of the whole snapshot.
type StructuralSnapshot struct {
	// SchemaVersion is always StructuralSnapshotSchemaVersion.
	SchemaVersion string `json:"schema_version"`
	// Period is the window: a "YYYY-MM-DD" calendar day in the account's
	// DECLARED timezone (DeclaredTimezone), not in UTC and not in whatever
	// zone the machine happens to sit in. A device that moves does not
	// re-bucket history.
	Period string `json:"period"`
	// PeriodRuleVersion versions the rule that maps activity to a period
	// (currently: a session belongs to the period its start falls in). A rule
	// change is a NEW version, never a silent re-bucketing — the server keys
	// on it, so old and new windows coexist rather than colliding.
	PeriodRuleVersion int `json:"period_rule_version"`
	// TimezoneRuleVersion versions the rule that resolves DeclaredTimezone to
	// the period's UTC boundaries. Versioned separately from the period rule
	// so a timezone-handling change does not have to invalidate period rules.
	TimezoneRuleVersion int `json:"timezone_rule_version"`
	// DeclaredTimezone is the IANA zone name the account declared (e.g.
	// "Europe/Berlin"). It is declared, not sniffed.
	DeclaredTimezone string `json:"declared_timezone"`
	// Revision is the 1-based snapshot revision for this window. Late or
	// backfilled data re-snapshots the SAME window as revision N+1; a window
	// is never overwritten. Currency is decided by revision number, not
	// arrival order.
	Revision int `json:"revision"`
	// SourceWatermark is the RFC3339 maximum LOCAL event time included in this
	// snapshot. It may fall outside the period (a session that started inside
	// the window and ran past its end), which is correct: it states what was
	// included, not what the window spans. Empty only for an inactive window.
	SourceWatermark string `json:"source_watermark"`
	// Active reports whether the window carried any activity at all. It is
	// derived (SessionCount > 0) and validated as such, so an "inactive" claim
	// can never coexist with non-zero aggregates.
	Active bool `json:"active"`
	// SessionCount is the number of eligible sessions in the window.
	SessionCount int `json:"session_count"`
	// ActionCount is the number of actions across those sessions.
	ActionCount int `json:"action_count"`
	// ToolMix is sessions-per-tool, sorted by key ascending, keys unique.
	ToolMix []StructuralMixEntry `json:"tool_mix"`
	// ModelFamilyMix is sessions-per-coarse-model-family, same shape as
	// ToolMix. The family is a closed vocabulary — never a raw model string.
	ModelFamilyMix []StructuralMixEntry `json:"model_family_mix"`
	// TokensIn is the summed net input tokens.
	TokensIn int `json:"tokens_in"`
	// TokensOut is the summed output tokens.
	TokensOut int `json:"tokens_out"`
	// CacheReadTokens is the summed cache-read tokens.
	CacheReadTokens int `json:"cache_read_tokens"`
	// CostUSD is the summed estimated cost in USD.
	CostUSD float64 `json:"cost_usd"`
	// VerificationCoverageBand bands SessionsWithVerification / SessionCount.
	VerificationCoverageBand CoverageBand `json:"verification_coverage_band"`
	// OutcomeEvidenceBand bands SessionsWithOutcomes / SessionCount.
	OutcomeEvidenceBand CoverageBand `json:"outcome_evidence_band"`
	// CoverageDenominators carries the raw numerators behind both bands.
	CoverageDenominators StructuralCoverageDenominators `json:"coverage_denominators"`
	// Digest is set by the serializer and omitted from its own preimage (the
	// `omitempty` tag drops it when cleared) — the same non-self-reference
	// discipline as Envelope.EvidenceContentDigest. See StructuralPreimage.
	Digest string `json:"digest,omitempty"`
}

// StructuralPeriodLayout is the period's exact format: a calendar day. (The
// size/count bounds live in limits.go with every other schema bound.)
const StructuralPeriodLayout = "2006-01-02"

// NormalizeMixKey is the ONE validator/normalizer every categorical mix key is
// run through, exported so the pure builder (internal/cloudevidence) and
// Validate apply exactly the same rule. It rejects invalid UTF-8, C0/C1/DEL
// controls, and bidi controls; NFC-normalizes; bounds the result; and then
// requires the whole key to be drawn from a small CATEGORY-SLUG charset:
// ASCII letters, digits, and the four joiners '.', '_', '-', '+'.
//
// The charset whitelist is what makes "a path leaked into a mix key"
// structurally impossible rather than merely unlikely. No '/', no '\\', no ':',
// no whitespace, no quote, and no non-ASCII text can appear in a key, so no
// filesystem path, URL, Windows drive reference, prose fragment, or
// human-language string can be spelled as one. It is deliberately stricter
// than "not obviously a path": mix keys are machine-generated slugs (an
// adapter's tool identifier, a coarse model family from a closed vocabulary),
// so the narrow set costs nothing real, and the builder folds anything outside
// it into an "unclassified" bucket rather than failing a whole window.
func NormalizeMixKey(field, key string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("cloudcontract.NormalizeMixKey: %s is empty", field)
	}
	normalized, err := normalizeString("NormalizeMixKey: "+field, key)
	if err != nil {
		return "", err
	}
	if len(normalized) > MaxStructuralMixKeyBytes {
		return "", fmt.Errorf("cloudcontract.NormalizeMixKey: %s is %d bytes after normalization, exceeds max %d",
			field, len(normalized), MaxStructuralMixKeyBytes)
	}
	if i := strings.IndexFunc(normalized, func(r rune) bool { return !isMixKeyRune(r) }); i >= 0 {
		return "", fmt.Errorf("cloudcontract.NormalizeMixKey: %s has a character outside the category-slug charset at byte %d — a mix key is a slug, never a path or free text",
			field, i)
	}
	return normalized, nil
}

// isMixKeyRune reports whether r may appear in a categorical mix key: ASCII
// letters, ASCII digits, and the joiners '.', '_', '-', '+'.
func isMixKeyRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	case r == '.' || r == '_' || r == '-' || r == '+':
		return true
	}
	return false
}

// Validate enforces every schema bound and every internal-consistency rule that
// makes the snapshot's claims checkable: the period parses as a calendar day,
// the versions and revision are positive, both bands are in the closed
// vocabulary, both mixes are bounded / normalized / strictly key-ascending
// (which is sorted AND unique in one check), every count is non-negative, the
// coverage numerators cannot exceed the session denominator, and Active agrees
// with SessionCount.
func (s StructuralSnapshot) Validate() error {
	const pfx = "cloudcontract.StructuralSnapshot.Validate"
	if err := s.validateHeader(pfx); err != nil {
		return err
	}
	if err := s.validateAggregates(pfx); err != nil {
		return err
	}
	return s.validateConsistency(pfx)
}

// validateHeader checks the window identity: schema version, period, rule
// versions, declared timezone, revision, and the source watermark.
func (s StructuralSnapshot) validateHeader(pfx string) error {
	if s.SchemaVersion != StructuralSnapshotSchemaVersion {
		return fmt.Errorf("%s: schema_version %q, want %q", pfx, s.SchemaVersion, StructuralSnapshotSchemaVersion)
	}
	if s.Period == "" {
		return fmt.Errorf("%s: period is empty", pfx)
	}
	if _, err := time.Parse(StructuralPeriodLayout, s.Period); err != nil {
		return fmt.Errorf("%s: period %q is not %q: %w", pfx, s.Period, StructuralPeriodLayout, err)
	}
	if s.PeriodRuleVersion < 1 {
		return fmt.Errorf("%s: period_rule_version %d is not positive", pfx, s.PeriodRuleVersion)
	}
	if s.TimezoneRuleVersion < 1 {
		return fmt.Errorf("%s: timezone_rule_version %d is not positive", pfx, s.TimezoneRuleVersion)
	}
	if s.DeclaredTimezone == "" {
		return fmt.Errorf("%s: declared_timezone is empty", pfx)
	}
	if len(s.DeclaredTimezone) > MaxDeclaredTimezoneBytes {
		return fmt.Errorf("%s: declared_timezone is %d bytes, exceeds max %d", pfx, len(s.DeclaredTimezone), MaxDeclaredTimezoneBytes)
	}
	if s.Revision < 1 {
		return fmt.Errorf("%s: revision %d is not positive", pfx, s.Revision)
	}
	if s.SourceWatermark != "" {
		if _, err := time.Parse(time.RFC3339, s.SourceWatermark); err != nil {
			return fmt.Errorf("%s: source_watermark %q not RFC3339: %w", pfx, s.SourceWatermark, err)
		}
	} else if s.Active {
		return fmt.Errorf("%s: an active window must carry a source_watermark", pfx)
	}
	return nil
}

// validateAggregates checks the per-window aggregates in isolation: counts,
// tokens, cost, both mixes, and both bands.
func (s StructuralSnapshot) validateAggregates(pfx string) error {
	if s.SessionCount < 0 || s.ActionCount < 0 {
		return fmt.Errorf("%s: negative session/action count", pfx)
	}
	if s.TokensIn < 0 || s.TokensOut < 0 || s.CacheReadTokens < 0 {
		return fmt.Errorf("%s: negative token count", pfx)
	}
	if err := validateFiniteNonNegative(pfx, "cost_usd", s.CostUSD); err != nil {
		return err
	}
	if err := validateMix(pfx, "tool_mix", s.ToolMix); err != nil {
		return err
	}
	if err := validateMix(pfx, "model_family_mix", s.ModelFamilyMix); err != nil {
		return err
	}
	if !s.VerificationCoverageBand.Valid() {
		return fmt.Errorf("%s: unknown verification_coverage_band %q", pfx, s.VerificationCoverageBand)
	}
	if !s.OutcomeEvidenceBand.Valid() {
		return fmt.Errorf("%s: unknown outcome_evidence_band %q", pfx, s.OutcomeEvidenceBand)
	}
	return nil
}

// validateConsistency checks the cross-field rules: coverage numerators
// bounded by the session denominator, Active derived from SessionCount, an
// inactive window carrying no aggregates, and the digest prefix.
func (s StructuralSnapshot) validateConsistency(pfx string) error {
	d := s.CoverageDenominators
	if d.SessionsWithOutcomes < 0 || d.SessionsWithVerification < 0 {
		return fmt.Errorf("%s: negative coverage denominator", pfx)
	}
	if d.SessionsWithOutcomes > s.SessionCount {
		return fmt.Errorf("%s: sessions_with_outcomes %d exceeds session_count %d", pfx, d.SessionsWithOutcomes, s.SessionCount)
	}
	if d.SessionsWithVerification > s.SessionCount {
		return fmt.Errorf("%s: sessions_with_verification %d exceeds session_count %d", pfx, d.SessionsWithVerification, s.SessionCount)
	}
	if s.Active != (s.SessionCount > 0) {
		return fmt.Errorf("%s: active=%v contradicts session_count=%d — active is derived, never asserted", pfx, s.Active, s.SessionCount)
	}
	if !s.Active {
		if s.ActionCount != 0 || s.TokensIn != 0 || s.TokensOut != 0 || s.CacheReadTokens != 0 || s.CostUSD != 0 ||
			len(s.ToolMix) != 0 || len(s.ModelFamilyMix) != 0 ||
			d.SessionsWithOutcomes != 0 || d.SessionsWithVerification != 0 {
			return fmt.Errorf("%s: an inactive window must carry no aggregates", pfx)
		}
	}
	if s.Digest != "" && !hasDigestPrefix(s.Digest) {
		return fmt.Errorf("%s: digest %q missing %q prefix", pfx, s.Digest, digestPrefix)
	}
	return nil
}

// validateMix checks a categorical mix: bounded length, normalized keys,
// strictly ascending key order (sorted AND unique in one pass), and positive
// counts (a zero-count entry is noise the builder drops, never wire content).
func validateMix(pfx, field string, mix []StructuralMixEntry) error {
	if len(mix) > MaxStructuralMixEntries {
		return fmt.Errorf("%s: %d %s entries exceeds max %d", pfx, len(mix), field, MaxStructuralMixEntries)
	}
	prev := ""
	for i, e := range mix {
		name := fmt.Sprintf("%s[%d].key", field, i)
		norm, err := NormalizeMixKey(name, e.Key)
		if err != nil {
			return fmt.Errorf("%s: %w", pfx, err)
		}
		if norm != e.Key {
			return fmt.Errorf("%s: %s %q is not in normalized form (want %q)", pfx, name, e.Key, norm)
		}
		if i > 0 && e.Key <= prev {
			return fmt.Errorf("%s: %s must be strictly key-ascending: %q follows %q", pfx, field, e.Key, prev)
		}
		prev = e.Key
		if e.Count <= 0 {
			return fmt.Errorf("%s: %s[%d].count %d is not positive", pfx, field, i, e.Count)
		}
	}
	return nil
}

// validateFiniteNonNegative rejects NaN, ±Inf, and negatives. NaN/Inf matter
// beyond tidiness: encoding/json refuses them, so an unchecked one would fail
// serialization far from its origin rather than at validation.
func validateFiniteNonNegative(pfx, field string, v float64) error {
	if v != v { // NaN is the only value not equal to itself
		return fmt.Errorf("%s: %s is NaN", pfx, field)
	}
	if v > maxFiniteFloat64 || v < -maxFiniteFloat64 {
		return fmt.Errorf("%s: %s is not finite", pfx, field)
	}
	if v < 0 {
		return fmt.Errorf("%s: %s %v is negative", pfx, field, v)
	}
	return nil
}

// maxFiniteFloat64 is the largest finite float64; anything strictly beyond it
// is ±Inf. Spelled out rather than imported so cloudcontract's exact stdlib
// allowlist (imports_test.go) does not have to grow a "math" entry for one
// constant.
const maxFiniteFloat64 = 1.7976931348623157e308

// StructuralPreimage returns the canonical preimage the snapshot's digest is
// computed over: s marshaled with the Digest field absent (forced empty so its
// `omitempty` tag drops it). s is taken by value, so clearing the digest here
// never mutates the caller's snapshot. The preimage is a public, testable
// definition — a test can assert it contains no digest field.
func StructuralPreimage(s StructuralSnapshot) ([]byte, error) {
	s.Digest = ""
	b, err := marshalCanonical(s)
	if err != nil {
		return nil, fmt.Errorf("cloudcontract.StructuralPreimage: %w", err)
	}
	return b, nil
}

// StructuralDigest returns the "sha256:<hex>" digest over StructuralPreimage(s).
// It never covers itself. The server recomputes this same value from the bytes
// it received — a client-declared digest is never trusted as proof of byte
// equality.
func StructuralDigest(s StructuralSnapshot) (string, error) {
	pre, err := StructuralPreimage(s)
	if err != nil {
		return "", fmt.Errorf("cloudcontract.StructuralDigest: %w", err)
	}
	return digest(pre), nil
}

// StructuralUploadBytes returns the final exact serialized bytes for s: the
// canonical serialization WITH Digest as currently set. These are the bytes the
// node stores in the outbox and uploads verbatim — there is no second
// serialization anywhere, so what was digested and what is sent cannot diverge.
func StructuralUploadBytes(s StructuralSnapshot) ([]byte, error) {
	b, err := marshalCanonical(s)
	if err != nil {
		return nil, fmt.Errorf("cloudcontract.StructuralUploadBytes: %w", err)
	}
	return b, nil
}
