package pricingfeed

import (
	"errors"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// SupportedSchemaVersion is the only feed schema_version this build understands.
// A feed carrying any other value is refused ([ErrUnsupportedSchema]) rather
// than half-parsed: the envelope is all-or-nothing (§E). A later optional field
// (e.g. the D4 min-cacheable column) would bump this.
const SupportedSchemaVersion = 1

// FeedSigningDomain domain-separates the pricing-FEED signature from every
// other Ed25519 use in the protocol — in particular from the org PRICING
// POLICY rail's sbo-pricing-policy-v1 (orgcontract), whose body has the same
// row vocabulary. A signature minted on one rail must never verify on another
// (docs/security.md ROUTING-SIG-1); the plan names this tag in §A.
const FeedSigningDomain = "sbo-pricing-feed-v1"

// Row is ONE model's feed entry: the platform's canonical rate vocabulary
// (orgcontract.PricingPolicyRow, embedded VERBATIM so no consumer translates
// rates) plus the Tokenomics quality Grade.
//
// The embedded row's rate fields are POINTERS, preserving the nil-vs-quoted-
// zero distinction node migration 135 needs end to end: a nil rate is "not
// quoted" (the node falls through to its seed) and a &0.0 is "quoted FREE"
// (state='known_free' in Tokenomics). The embedding flattens in JSON, so a Row
// marshals as { ...the policy-row fields... , "grade": "..." } — exactly the
// §A envelope shape.
type Row struct {
	orgcontract.PricingPolicyRow
	// Grade is the Tokenomics source grade (e.g. "verified", "observed") the
	// export carried for this row. It is OUT OF BAND of the rate vocabulary:
	// the org importer reads it to decide auto-apply vs park (§C.1), and it
	// never reaches the node engine (which speaks only orgcontract rates).
	Grade string `json:"grade,omitempty"`

	// Economics is OPTIONAL per-model economics beyond the bare rates
	// (operator directive 2026-09-11): cache systems differ (Anthropic's
	// EXPLICIT cache writes vs OpenAI/Gemini-style IMPLICIT caching) and
	// thinking-vs-non-thinking billing differs, and a price alone cannot say
	// which regime a model is in. It is a POINTER so its absence is honestly
	// "unknown" rather than a struct full of fabricated zero-value defaults;
	// every field inside it is likewise optional. It stays inside this same
	// canonical body (no map, fixed field order) so the digest and signature
	// cover it, and it is additive under SchemaVersion 1.
	Economics *Economics `json:"economics,omitempty"`
}

// Economics carries per-model economic shape the bare rate vocabulary cannot
// express. EVERY field is optional: a nil pointer or an empty string means
// UNKNOWN, never a default — a consumer that reads "unknown" keeps whatever it
// already believed (its code-level registry), and a consumer must never invent
// a value the feed did not state. The enum-valued strings have CLOSED
// vocabularies validated by Verify when Economics is present; an unrecognised
// value fails the whole envelope (all-or-nothing, §E), so a typo in the
// publisher can never be half-applied.
type Economics struct {
	// CacheMode is the caching regime: "explicit" (Anthropic — the caller
	// marks cache-write points and pays a write rate), "implicit" (OpenAI/
	// Gemini — the provider caches transparently, no explicit write), or
	// "none". Empty = unknown.
	CacheMode string `json:"cache_mode,omitempty"`
	// CacheWriteBilling is how a cache WRITE is billed: "per_write" (a distinct
	// write rate applies), "included" (writes are folded into the input rate),
	// or "none". Empty = unknown.
	CacheWriteBilling string `json:"cache_write_billing,omitempty"`
	// CacheTTLSeconds is the default cache entry lifetime in seconds.
	CacheTTLSeconds *int64 `json:"cache_ttl_seconds,omitempty"`
	// CacheTTL1HAvailable reports whether a 1-hour cache tier is offered.
	CacheTTL1HAvailable *bool `json:"cache_ttl_1h_available,omitempty"`
	// MinCacheableTokens is the smallest prefix length that can be cached (the
	// cachetrack min-cacheable fact, carried here as DATA rather than code when
	// the publisher knows it).
	MinCacheableTokens *int64 `json:"min_cacheable_tokens,omitempty"`
	// ReasoningSupported reports whether the model has a thinking/reasoning
	// mode at all.
	ReasoningSupported *bool `json:"reasoning_supported,omitempty"`
	// ReasoningBilling is how reasoning/thinking tokens are billed:
	// "output_rate" (at the output rate, the Anthropic convention),
	// "separate_rate" (a distinct reasoning rate — then ReasoningPerMTok),
	// "included", or "none". Empty = unknown.
	ReasoningBilling string `json:"reasoning_billing,omitempty"`
	// ReasoningPerMTok is the distinct reasoning rate in USD per 1M tokens,
	// meaningful when ReasoningBilling is "separate_rate".
	ReasoningPerMTok *float64 `json:"reasoning_per_mtok,omitempty"`
	// ContextWindowTokens is the model's maximum context window.
	ContextWindowTokens *int64 `json:"context_window_tokens,omitempty"`
	// FastMultiplier is the latency-premium multiplier (cost.Pricing's
	// seed-only FastMultiplier, carried here as DATA when known). It is a
	// premium, not a negotiated rate, which is why it rides in Economics rather
	// than in the embedded rate row.
	FastMultiplier *float64 `json:"fast_multiplier,omitempty"`
	// Notes is free-form provenance, SafeText-constrained: Verify rejects any
	// control character, bidi-formatting code point or ANSI escape, so a note
	// can never smuggle a terminal-control sequence onto an operator surface.
	Notes string `json:"notes,omitempty"`
}

// Cache mode vocabulary (Economics.CacheMode).
const (
	CacheModeExplicit = "explicit"
	CacheModeImplicit = "implicit"
	CacheModeNone     = "none"
)

// Cache-write billing vocabulary (Economics.CacheWriteBilling).
const (
	CacheWriteBillingPerWrite = "per_write"
	CacheWriteBillingIncluded = "included"
	CacheWriteBillingNone     = "none"
)

// Reasoning billing vocabulary (Economics.ReasoningBilling).
const (
	ReasoningBillingOutputRate   = "output_rate"
	ReasoningBillingSeparateRate = "separate_rate"
	ReasoningBillingIncluded     = "included"
	ReasoningBillingNone         = "none"
)

// Envelope is the signed feed document served at the publish endpoint (§A) and
// verified offline by every consumer.
type Envelope struct {
	// SchemaVersion is the feed wire version; only SupportedSchemaVersion is
	// accepted by this build.
	SchemaVersion int `json:"schema_version"`
	// FeedVersion is the publisher's monotonic content version, bumped on
	// every content change. It is bound INTO the signature (alongside the
	// canonical rows) so a replayed lower version can be refused; a consumer
	// also checks FeedVersion > 0.
	FeedVersion int64 `json:"feed_version"`
	// GeneratedAt is the RFC3339 instant the publisher materialized the
	// export. Provenance only — it is NOT in the signing message, so a
	// re-publish of identical rows at a new clock does not invalidate a cached
	// body (the Digest is the change detector).
	GeneratedAt string `json:"generated_at"`
	// Rows are the feed rows, one per model. CanonicalRows sorts them by model
	// before signing/digesting so the bytes are stable regardless of the order
	// the publisher emitted them.
	Rows []Row `json:"rows"`
	// Digest is the sha256 hex of CanonicalRows(Rows). It is the ETag
	// substrate (a corrected-in-place rate without a version bump still
	// re-applies) and is re-checked on verify.
	Digest string `json:"digest"`
	// Signature is base64 (std) of the raw 64-byte Ed25519 signature over
	// [SigningMessage]. An empty Signature is [ErrUnsigned] — never applied.
	Signature string `json:"signature"`
	// KeyID names which compiled vendor key signed this body, so a rotation
	// can ship an overlap window (the vendorkey.go slot pattern). Verify looks
	// the key up by this id and refuses an unknown one ([ErrUnknownKey]).
	KeyID string `json:"key_id"`
}

// Typed verification errors. Verify is all-or-nothing: it returns the FIRST of
// these that applies and never partially applies a body (§E). Callers map every
// one of them to "refuse the body, keep the previously applied prices".
var (
	// ErrUnsigned — the envelope carries no signature. A build that produced
	// it lacked the signing secret (§B.4); consumers fail closed.
	ErrUnsigned = errors.New("pricingfeed: envelope is unsigned")
	// ErrBadSignature — a signature is present but does not verify under the
	// named key.
	ErrBadSignature = errors.New("pricingfeed: signature does not verify")
	// ErrDigestMismatch — the envelope's Digest does not equal the recomputed
	// digest of its rows (tampering, or a publisher bug).
	ErrDigestMismatch = errors.New("pricingfeed: digest does not match rows")
	// ErrUnsupportedSchema — SchemaVersion is not SupportedSchemaVersion.
	ErrUnsupportedSchema = errors.New("pricingfeed: unsupported schema_version")
	// ErrUnknownKey — KeyID names no key this build accepts.
	ErrUnknownKey = errors.New("pricingfeed: envelope signed by an unknown key_id")
	// ErrInvalidRows — a row is malformed (e.g. an empty model id) or
	// FeedVersion is not positive. The whole set is rejected.
	ErrInvalidRows = errors.New("pricingfeed: envelope rows are invalid")
)
