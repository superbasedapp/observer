package orgcontract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"
)

// The FLEET-WIDE org PRICING policy body served by GET /api/agent/pricing
// (docs/plans/enterprise-pricing-and-admin-assistant-plan-2026-09-08.md §3.3,
// wave W2).
//
// WHY THIS LIVES HERE, and not in internal/orgserver or internal/orgclient: it
// is a node<->server contract and BOTH ends must derive the same signing
// bytes. orgcontract is the package that already owns every such shape (zero
// internal dependencies), which is what lets the pure server-side authoring
// package (internal/orgserver/pricing) and the node-side fetch both reach it
// without either importing the other.
//
// WHAT IT CARRIES: model ids and rates. Nothing else — no member, no team, no
// project, no spend, no content. Distributing it is a GOVERNANCE act of the
// same class as the sibling budget document: it names no content-bearing
// column, it travels on the agent POLICY rail rather than on PushEnvelope, and
// it is refused unless the org's signing key matches the node's TOFU pin.
//
// HOW IT DIFFERS FROM THE BUDGET RAIL, and why that difference is in the
// signing message rather than in a comment: a budget body is resolved PER
// CALLER, so its signature binds a SUBJECT — a genuinely signed body handed to
// a different member would otherwise grant them somebody else's cap. A price
// list is the same for every node in the org, so there is no subject to bind
// and binding one would be a lie about what the document is. The org id and
// the version are bound instead.
//
// WHY THE ROWS ARE ALREADY FLATTENED, and yet still carry EffectiveFrom: the
// server resolves the dated timeline at generation time (pricing.FlattenAt) so
// the fleet and the gateway can never disagree about which of two dated rows
// was in force. EffectiveFrom rides along anyway so a node that has not
// re-fetched across a rate boundary can see WHEN the rate it is applying
// started, and so a future node-side re-flatten needs no wire change.

// COMPAT over the nullable-rate change, stated honestly (review finding P1-1).
//
// FORWARD (a node built AFTER 135 reading an OLD document) is benign: it reads
// the same `"rate": 0` it always did, into a SET pointer, where that document
// meant "not set". The cost is one release in which such a rate reads as free
// rather than as inherited, bounded by the server bumping the pricing version
// on its next mutation. Not a parse failure.
//
// BACKWARD (a node built BEFORE 135 reading a NEW document) is NOT benign, and
// an earlier version of this comment claimed it was. Decoding is indeed fine -
// an omitted rate lands as the zero value that build already meant by "not
// negotiated" - but decoding is not where such a node stops. It VERIFIES by
// RE-MARSHALING the struct it just decoded (VerifyPricingPolicy ->
// PricingPolicySigningMessage -> json.Marshal(body)), and a pre-135 build's
// `float64,omitempty` DROPS a quoted 0. So any document carrying a negotiated
// free rate re-marshals to different bytes on that node, the signature does not
// verify, and the node lands in `unverified`: it keeps its persisted table and
// stops taking price updates altogether.
//
// NO BUILD IS AFFECTED. This rail and migration 135 landed the same morning, on
// a held branch: no released tag and no deployed node carries the pre-135
// spelling of this struct, so there is no fleet in that state to break. That is
// why P1-1 was a comment fix and not a code change.
//
// THE STANDING CONSEQUENCE, and why the FIRST of the two exits is now TAKEN on
// this rail (docs/plans/peak-off-peak-pricing-plan-2026-09-20.md §R / §3.4,
// "Phase 0"): historically verification re-derived the bytes from THIS BUILD'S
// struct rather than checking the signature against the bytes actually
// received, so ANY future field-shape change to this document - a field added,
// removed, renamed, reordered, or retyped between value and pointer - was a
// fleet-freezing change for every node still on the older struct. A row-level
// field ADDED by a future server (e.g. a nested "peak" object) is the case that
// motivated the fix: an already-deployed node would drop the unknown field on
// decode, re-marshal without it, and refuse a perfectly genuine document as
// `unverified`.
//
// [PricingPolicyDoc.UnmarshalJSON] now captures the RAW RECEIVED bytes of the
// body's `rows` field, and [VerifyPricingPolicy] signs over THOSE bytes (via
// [canonicalPricingBodyRaw]) whenever the document was decoded from JSON. An
// unknown row field therefore rides through into the signing message untouched,
// so a future-field document VERIFIES on an old node instead of freezing it —
// while the node's typed logic still runs against only the fields it knows.
//
// The fix carries a HARD byte-compatibility property, pinned by
// TestPricingPolicyByteCompatNoUnknownFields: for a document with NO unknown
// fields, canonicalPricingBodyRaw produces bytes IDENTICAL to
// canonicalPricingBody(typed body). This holds because the server signs over
// json.Marshal(typed body) and serves those exact compact rows bytes, so the
// raw path recovers precisely the bytes that were signed. Every currently
// deployed org server's signed document therefore still verifies on an upgraded
// node — the whole point of the change.
//
// The SIGNER ([SignPricingPolicy]) keeps using the typed path: it builds
// documents programmatically with no unknown fields, and by the byte-compat
// property that path is identical to the raw one. The SECOND exit (versioning
// the document so an old node can refuse it knowingly) is unneeded for additive
// row fields now that the raw path exists.
//
// TestPricingPolicyCanonicalBytesArePinned remains the tripwire for a change to
// the fields THIS build already knows — a rename/reorder/retype of an existing
// field still changes the typed signer's bytes and must be versioned, because it
// changes what the SERVER signs.

// RateSet mirrors internal/intelligence/cost.RateSet and
// internal/orgserver/pricing.RateSet EXACTLY (identical json tags): a
// complete token-rate set, base rates plus an optional long-context sub-tier.
// This is the SIGNED WIRE shape of a peak rate variant; peak_json (the org
// store's column, internal/orgserver/pricing.RateSet) and this wire type
// share the shape by construction, so the store<->wire translation at each
// boundary is a plain field copy with no arithmetic (Phase 2, plan §R2/P2-B).
type RateSet struct {
	Input           float64 `json:"input"`
	Output          float64 `json:"output"`
	CacheRead       float64 `json:"cache_read"`
	CacheCreation   float64 `json:"cache_creation"`
	CacheCreation1h float64 `json:"cache_creation_1h"`

	LongContextThreshold       int64   `json:"long_context_threshold,omitempty"`
	LongContextInput           float64 `json:"long_context_input,omitempty"`
	LongContextOutput          float64 `json:"long_context_output,omitempty"`
	LongContextCacheRead       float64 `json:"long_context_cache_read,omitempty"`
	LongContextCacheCreation   float64 `json:"long_context_cache_creation,omitempty"`
	LongContextCacheCreation1h float64 `json:"long_context_cache_creation_1h,omitempty"`
}

// PeakWindow mirrors cost.PeakWindow / pricing.PeakWindow: one recurring UTC
// time window on the given weekdays. Days is []time.Weekday (plan §R4), the
// same element kind cost and pricing already use, so the three mirrors stay
// wire-identical (a time.Weekday marshals as a plain int either way, but one
// convention is picked rather than left to coincide).
type PeakWindow struct {
	Days     []time.Weekday `json:"days"`
	StartUTC string         `json:"start_utc"`
	EndUTC   string         `json:"end_utc"`
}

// PeakSchedule mirrors cost.PeakSchedule / pricing.PeakSchedule: an ordered
// set of windows.
type PeakSchedule struct {
	Windows []PeakWindow `json:"windows"`
}

// PeakRates mirrors cost.PeakRates / pricing.PeakRates: the peak rate set
// plus the schedule that selects it. Nil on a [PricingPolicyRow] ⇒ the org
// has authored no peak variant for that model; the node prices flat around
// the clock.
type PeakRates struct {
	RateSet
	Schedule PeakSchedule `json:"schedule"`
}

// PricingPolicyRow is ONE model's authored rate set, in the vocabulary of
// internal/intelligence/cost.Pricing (the node's own price table) so the node
// composes a row into its engine with no translation.
//
// It is internal/orgserver/pricing.Row minus the columns that are the SERVER's
// bookkeeping and not a price: id, org_id, note and the authorship stamps. The
// note is deliberately absent — it is free text an admin wrote for other
// admins ("MSA amendment 3"), it is not a rate, and shipping free text to
// every node in the fleet is a disclosure the rail has no reason to make.
type PricingPolicyRow struct {
	// Model is the model id the rate applies to, already normalized
	// (lower-cased, trimmed) by the server.
	Model string `json:"model"`

	// The eleven rate fields are POINTERS (server migration 135). A nil rate
	// is the org quoting NOTHING for that field, and the node falls through
	// to the next precedence level for it; a rate set to 0 is a rate the org
	// negotiated FREE. Before 135 they were bare float64 with omitempty, so
	// the wire could not say "not set" - zero and absent were the same bytes,
	// and a free rate was inexpressible end to end.
	//
	// omitempty on a POINTER omits nil only, so the two spellings stay
	// distinct AND deterministic in the signing bytes: an unquoted rate is
	// absent from the JSON, a free one appears as `0`.
	InputPerMTok        *float64 `json:"input_per_mtok,omitempty"`
	OutputPerMTok       *float64 `json:"output_per_mtok,omitempty"`
	CacheReadPerMTok    *float64 `json:"cache_read_per_mtok,omitempty"`
	CacheWritePerMTok   *float64 `json:"cache_write_per_mtok,omitempty"`
	CacheWrite1hPerMTok *float64 `json:"cache_write_1h_per_mtok,omitempty"`

	// LongContextThreshold is a POINTER since server migration 175 so the org
	// store's three states (NULL = not quoted, 0 = quoted flat, N = a tier)
	// can be carried, but ON THIS (ORG) RAIL its absence keeps the LEGACY
	// meaning. A server built before 175 wrote its NOT NULL DEFAULT 0 as an
	// OMITTED field, and every node built before 175 overlaid that 0
	// unconditionally - an org row turned the seed's long-context tier OFF.
	// So an absent threshold still means "quoted flat" here, and the NEW
	// state, "not quoted, keep the seed's tier", is spelled with the additive
	// [PricingPolicyRow.LongContextThresholdUnquoted] marker. Read it through
	// [PricingPolicyRow.OrgThreshold]; write it through
	// [PricingPolicyRow.SetOrgThreshold], which emits a quoted flat 0 as the
	// legacy omitted field so an old node gets byte-identical rows.
	//
	// The PUBLIC FEED (internal/pricingfeed, which embeds this row) is a
	// different rail with the opposite absence rule - there an omitted
	// threshold was always "the feed does not know the tier" - and never sets
	// the marker; its projection reads the pointer directly.
	LongContextThreshold           *int64   `json:"long_context_threshold,omitempty"`
	LongContextInputPerMTok        *float64 `json:"long_context_input_per_mtok,omitempty"`
	LongContextOutputPerMTok       *float64 `json:"long_context_output_per_mtok,omitempty"`
	LongContextCacheReadPerMTok    *float64 `json:"long_context_cache_read_per_mtok,omitempty"`
	LongContextCacheWritePerMTok   *float64 `json:"long_context_cache_write_per_mtok,omitempty"`
	LongContextCacheWrite1hPerMTok *float64 `json:"long_context_cache_write_1h_per_mtok,omitempty"`

	WebSearchPerRequest *float64 `json:"web_search_per_request,omitempty"`

	// EffectiveFrom is the RFC3339 timestamp or YYYY-MM-DD date the rate
	// started, "" meaning "since forever". The server has already resolved
	// the timeline; this is provenance, not a second resolution axis.
	EffectiveFrom string `json:"effective_from,omitempty"`
	// Source is the row's provenance vocabulary (negotiated|list|imported),
	// carried so a node surface can say "org (negotiated)" rather than
	// merely "org".
	Source string `json:"source,omitempty"`

	// Peak is the org-authored peak (time-of-day) rate variant, mirroring
	// internal/orgserver/pricing.Row.Peak (the peak_json org-store payload)
	// field for field (Phase 2, plan §R2/P2-B). Presence is the contract (the
	// migration-135 rule, applied to the structural fields): nil = the org
	// quoted no peak for this model and the node KEEPS the seed's peak
	// schedule; a present Peak is quoted and replaces it, and a present peak
	// with an empty schedule means "negotiated flat" and clears it (plan §R2
	// R1/N2, kept for the explicit case; rework 2026-09-23). omitempty keeps
	// an absent peak byte-identical to a pre-Phase-2 document, so a document
	// with no peak rows still verifies unchanged on a node built before this
	// field existed; omitempty on a POINTER omits nil only, so an explicitly
	// empty peak survives the wire as a quoted "flat".
	//
	// ON THIS (ORG) RAIL an ABSENT peak keeps its LEGACY meaning too: every
	// node built before the presence rule REPLACED the seed's peak with the
	// org row's nil, so absence = "quoted flat". "Not quoted, keep the seed's
	// peak" is spelled with [PricingPolicyRow.PeakUnquoted]; read through
	// [PricingPolicyRow.OrgPeak], write through [PricingPolicyRow.SetOrgPeak].
	Peak *PeakRates `json:"peak,omitempty"`

	// LongContextThresholdUnquoted and PeakUnquoted are the org rail's
	// PRESENCE DISCRIMINATORS (review finding F1, 2026-09-26). They are true
	// only for a row whose org store column is NULL - "this org quotes no
	// threshold / no peak for this model, keep the node's own" - which is a
	// state no server before migration 175 could produce. Absent (false) is
	// every legacy row, so an old server's document keeps meaning exactly
	// what it meant to the node it shipped with.
	//
	// WHY PER ROW AND NOT A BODY-LEVEL SCHEMA FIELD: a node verifies over the
	// RAW received `rows` bytes but re-frames the body from only version,
	// generated_at and rows ([canonicalPricingBodyRaw]); a new body-level
	// field would be dropped from that frame and fail verification on EVERY
	// deployed node. A new ROW field rides through the raw rows untouched.
	// No new signing domain is needed for the same reason: the framing is
	// unchanged, and a new domain tag would itself freeze the fleet.
	//
	// Declared LAST and omitempty, so a row that sets neither marshals to the
	// same bytes as before these fields existed.
	LongContextThresholdUnquoted bool `json:"long_context_threshold_unquoted,omitempty"`
	PeakUnquoted                 bool `json:"peak_unquoted,omitempty"`

	// The EXTENDED rate dimensions (server migration 190 / pg 0056, the
	// 2026-09-30 pricing-chain contract). Every one follows the migration-135
	// presence rule on BOTH rails: nil = not quoted (the node keeps its seed's
	// value), a set value wins, a set 0 = quoted free. They are new, so unlike
	// the threshold and the peak there is no legacy absence meaning to keep.
	// Declared after the presence markers and omitempty, so a row that sets
	// none marshals byte-identically to a document from before they existed,
	// and a node verifies them through the raw received rows untouched.
	//
	// ReasoningPerMTok is USD per 1M reasoning tokens (absent = billed at the
	// output rate). RequestFeeUSD is USD per API request.
	// CacheWriteOtherPerMTok is USD per 1M cache-write tokens of a TTL other
	// than the 5-minute and 1-hour ones. ImageInputPerMTok / AudioInputPerMTok
	// / AudioOutputPerMTok are USD per 1M tokens of that modality;
	// ImageOutputPerImage is USD per generated image.
	ReasoningPerMTok       *float64 `json:"reasoning_per_mtok,omitempty"`
	RequestFeeUSD          *float64 `json:"request_fee_usd,omitempty"`
	CacheWriteOtherPerMTok *float64 `json:"cache_write_other_per_mtok,omitempty"`
	ImageInputPerMTok      *float64 `json:"image_input_per_mtok,omitempty"`
	ImageOutputPerImage    *float64 `json:"image_output_per_image,omitempty"`
	AudioInputPerMTok      *float64 `json:"audio_input_per_mtok,omitempty"`
	AudioOutputPerMTok     *float64 `json:"audio_output_per_mtok,omitempty"`
	// FastMultiplier is the provider's latency-tier premium (dimensionless,
	// e.g. 2.0), carried as DATA from the Tokenomics feed so an enrolled node
	// takes its fast-mode premium from the org rail rather than from its
	// built-in table. nil = not stated (the seed's stays), 0 = no fast tier.
	FastMultiplier *float64 `json:"fast_multiplier,omitempty"`
	// Grade is the Tokenomics source grade an imported row carried
	// ("verified", "observed", ...), provenance only: no node arithmetic reads
	// it. "" = not graded (an org-authored row). On the public feed the feed
	// Row's own top-level Grade shadows this field (encoding/json picks the
	// shallower one), so the feed's bytes are unchanged by it.
	Grade string `json:"grade,omitempty"`

	// History is this model's WHOLE dated timeline in the org's price book
	// (lane R2-PRICING-2): every org_model_prices row for the model, ascending
	// by effective_from, each projected exactly as a top-level row is (the
	// SetOrgThreshold / SetOrgPeak encodings included) and with no History of
	// its own. The top-level fields above remain the row in force at
	// GeneratedAt (the F13 flattening is unchanged), so a node that ignores
	// History prices exactly as before; a node that reads it can price an OLD
	// session at the org rate in force at the session's own timestamp, instead
	// of re-pricing all of history at today's rate.
	//
	// The server emits it only for a model with MORE than one row, so an org
	// with a flat price book signs byte-identical documents. It is a ROW field,
	// declared last and omitempty, for the reason the presence markers above
	// are: a node verifies over the raw received `rows` bytes, so an unknown
	// row key rides through its signature check (a node older than that fix
	// re-marshals and refuses - the named peak cutover residual).
	History []PricingPolicyRow `json:"history,omitempty"`
}

// OrgThreshold reads this row's long-context threshold under the ORG rail's
// rule: the [PricingPolicyRow.LongContextThresholdUnquoted] marker means "not
// quoted" (quoted=false, the node keeps its own tier); otherwise the row
// quotes a threshold, and an ABSENT one is the legacy spelling of 0 - "no
// long-context tier" - which is what every pre-175 node did with it.
func (r PricingPolicyRow) OrgThreshold() (value int64, quoted bool) {
	if r.LongContextThresholdUnquoted {
		return 0, false
	}
	if r.LongContextThreshold == nil {
		return 0, true
	}
	return *r.LongContextThreshold, true
}

// SetOrgThreshold writes a stored threshold (nil = NULL, not quoted) onto the
// row in the org rail's encoding: NULL becomes the unquoted marker; a quoted
// 0 becomes the legacy OMITTED field (byte-identical to a pre-175 server's
// row, which is what keeps a pre-175 node verifying and billing flat); a
// positive threshold is written as itself.
func (r *PricingPolicyRow) SetOrgThreshold(stored *int64) {
	r.LongContextThreshold, r.LongContextThresholdUnquoted = nil, false
	switch {
	case stored == nil:
		r.LongContextThresholdUnquoted = true
	case *stored != 0:
		v := *stored
		r.LongContextThreshold = &v
	}
}

// OrgPeak reads this row's peak under the ORG rail's rule: the
// [PricingPolicyRow.PeakUnquoted] marker means "not quoted" (the node keeps
// its seed's peak); otherwise the row quotes its peak, and an ABSENT one is
// the legacy spelling of "flat, no time-of-day premium".
func (r PricingPolicyRow) OrgPeak() (peak *PeakRates, quoted bool) {
	if r.PeakUnquoted {
		return nil, false
	}
	return r.Peak, true
}

// SetOrgPeak writes a stored peak (nil = NULL, not quoted) onto the row in the
// org rail's encoding: NULL becomes the unquoted marker; the EMPTY peak - no
// schedule window and every rate zero, which is the org store's "quoted
// flat" spelling ('{}', what migration 175 turns every legacy NULL peak into)
// - becomes the legacy OMITTED field; every other peak, INCLUDING a
// window-less one that carries rates, is written as itself, exactly as a
// pre-175 server wrote it.
//
// The one state this cannot keep byte-identical (review round 2, finding 3):
// a pre-175 row that STORED an explicit all-zero, window-less peak object.
// The org store decodes it to the same value as the cut-over's '{}', so the
// two cannot be told apart here; a pre-175 server shipped the object and
// this ships nothing. Every node bills both as flat (a window-less peak can
// never select its rates), and a node too old to know the `peak` field
// verifies the omitted spelling where it refused the object. Named in
// docs/pricing.md.
func (r *PricingPolicyRow) SetOrgPeak(stored *PeakRates) {
	r.Peak, r.PeakUnquoted = nil, false
	switch {
	case stored == nil:
		r.PeakUnquoted = true
	case len(stored.Schedule.Windows) == 0 && stored.RateSet == (RateSet{}):
		// quoted flat, spelled by omission as every pre-175 server did
	default:
		r.Peak = stored
	}
}

// Rate boxes a quoted rate so a caller can state one inline. &0.0 is not
// expressible in a Go composite literal, and every builder of a policy row
// needs to be able to say "this rate IS set, to zero" - a negotiated free
// model - as distinct from leaving it nil.
func Rate(v float64) *float64 { return &v }

// Threshold boxes a quoted long-context threshold, [Rate]'s token-count
// sibling (server migration 175): a builder must be able to say "this
// threshold IS set, to zero" - quoted flat - as distinct from nil.
func Threshold(v int64) *int64 { return &v }

// PricePrecision is the price-precision quantum every float decode boundary
// on the pricing chain rounds to (the 2026-09-30 contract): Tokenomics stores
// NUMERIC(20,10), so a rate that crossed a float64 wire is snapped back onto
// that grid and two decoders of the same number never disagree in the 17th
// significant digit.
const PricePrecision = 1e-10

// RoundPrice rounds v to [PricePrecision]. Non-finite values pass through
// unchanged (validation, not rounding, is what refuses them).
func RoundPrice(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return v
	}
	// Scale by the EXACT power of ten (1e10 is representable in float64) and
	// divide back, so a value already on the grid (3, 0.3, 1.25e-7) survives
	// bit-identically; multiplying by the inexact 1e-10 would not.
	return math.Round(v*1e10) / 1e10
}

// roundPtr rounds a quoted rate in place of a copy; nil stays nil.
func roundPtr(p *float64) *float64 {
	if p == nil {
		return nil
	}
	v := RoundPrice(*p)
	return &v
}

// RoundedRates returns a copy of r with every quoted rate, the fast
// multiplier, the peak variant's rates and every history period rounded to
// [PricePrecision]. It is the ONE rounding step the decode boundaries call
// (node feed and org-rail projection, org import); presence is preserved (a
// nil stays nil, a quoted 0 stays a quoted 0). It never touches the signed
// bytes: callers round AFTER verification.
func (r PricingPolicyRow) RoundedRates() PricingPolicyRow {
	out := r
	for _, p := range []**float64{
		&out.InputPerMTok, &out.OutputPerMTok, &out.CacheReadPerMTok,
		&out.CacheWritePerMTok, &out.CacheWrite1hPerMTok,
		&out.LongContextInputPerMTok, &out.LongContextOutputPerMTok,
		&out.LongContextCacheReadPerMTok, &out.LongContextCacheWritePerMTok,
		&out.LongContextCacheWrite1hPerMTok, &out.WebSearchPerRequest,
		&out.ReasoningPerMTok, &out.RequestFeeUSD, &out.CacheWriteOtherPerMTok,
		&out.ImageInputPerMTok, &out.ImageOutputPerImage,
		&out.AudioInputPerMTok, &out.AudioOutputPerMTok, &out.FastMultiplier,
	} {
		*p = roundPtr(*p)
	}
	if r.Peak != nil {
		pk := *r.Peak
		for _, f := range []*float64{
			&pk.Input, &pk.Output, &pk.CacheRead, &pk.CacheCreation, &pk.CacheCreation1h,
			&pk.LongContextInput, &pk.LongContextOutput, &pk.LongContextCacheRead,
			&pk.LongContextCacheCreation, &pk.LongContextCacheCreation1h,
		} {
			*f = RoundPrice(*f)
		}
		out.Peak = &pk
	}
	if r.History != nil {
		out.History = make([]PricingPolicyRow, len(r.History))
		for i, h := range r.History {
			out.History[i] = h.RoundedRates()
		}
	}
	return out
}

// PricingPolicyBody is the signed body.
//
// An EMPTY Rows slice is MEANINGFUL, not a degenerate case: it is the org
// saying "we have negotiated nothing, price at the seed table". It is the only
// thing that may ever empty a node's org price table, which is why it must
// arrive signed like any other body (plan §3.3 / N1) — an unsigned signal that
// could clear the table would be a one-header lever to drop a whole fleet back
// to list prices.
type PricingPolicyBody struct {
	// Version is org_pricing_version.version — bumped by every pricing
	// mutation. Unlike the budget rail's version this one is sufficient on
	// its own to detect change (a price list has no per-caller resolution
	// that could move without it), but the ETag still digests the whole
	// document so the two can never disagree.
	Version int64 `json:"version"`
	// GeneratedAt is the RFC3339 instant the server FLATTENED the dated rows
	// at. It is what makes a stale document diagnosable: a node applying a
	// document generated three weeks ago has missed a rate boundary.
	//
	// It is TRUNCATED TO THE MINUTE by the server, because it sits inside the
	// signed bytes the ETag digests: a per-second stamp moved the validator
	// every second and re-downloaded an unchanged price list across the whole
	// fleet. Nothing may read it as a monotonic signal or at second precision —
	// [PricingPolicyBody.Version] is what orders two documents.
	GeneratedAt string `json:"generated_at"`
	// Rows are the effective rows at GeneratedAt, one per model, sorted by
	// model id so the bytes are stable for a digest and a golden test.
	Rows []PricingPolicyRow `json:"rows"`
}

// PricingPolicyDoc is the wire document: the body's fields inline (the
// embedded struct flattens in JSON) plus the org's Ed25519 signature.
type PricingPolicyDoc struct {
	PricingPolicyBody
	// Signature is base64 (std encoding, matching every other org rail) over
	// [PricingPolicySigningMessage].
	Signature string `json:"signature"`

	// ContextWindows is the org's model context-window table (tokens), from
	// the org's pricing-feed economics (org_pricing_feed_state
	// .economics_json, economics.context_window_tokens - the one source the
	// org's own session drawer gauge reads), sorted by model. It lets an
	// ENROLLED node, which prices from this document and ignores the public
	// feed (orgpricing.FeedApplies), size its session context gauge from the
	// same number the org uses (internal/sessiongauge.DocWindows).
	//
	// UNSIGNED DISPLAY DATA, deliberately OUTSIDE [PricingPolicyBody]. It is
	// never a rate and the cost engine never reads it; its integrity is the
	// TLS + enrolment-bearer channel it arrives on. It sits beside the
	// signature rather than inside the signed body because every node
	// verifies over version, generated_at and rows only: a v1.33.0 .. rc.7
	// node re-marshals the typed body it decoded, and an rc.8+ node re-frames
	// the raw received `rows` bytes, and BOTH ignore an unknown top-level key,
	// so a document carrying windows verifies on every deployed node. The
	// earlier design (lane G-WIRE2, never released) stamped a
	// context_window_tokens field onto each signed ROW, which a re-marshal
	// verifier drops on decode - every pre-rc.8 node refused the document and
	// froze its price updates, automatically for any org with feed economics
	// (review finding, 2026-09-29).
	//
	// The ETag ([PricingPolicyDigest]) hashes the whole document, so a window
	// change moves the validator and a node re-fetches. It names EVERY model
	// the org's economics carries a positive window for, not only the price
	// book's rows. Absent or empty = the org states no windows; each model
	// then reads as unknown on the node, never 0.
	ContextWindows []ModelContextWindow `json:"context_windows,omitempty"`

	// rawRows holds the RAW RECEIVED bytes of the body's `rows` field,
	// populated by [PricingPolicyDoc.UnmarshalJSON] and read only by
	// [VerifyPricingPolicy] so it can sign over what was ACTUALLY RECEIVED
	// rather than a re-marshal of this build's typed rows (which silently drops
	// any row field this build does not know — the fleet-freeze residual, now
	// closed; see the P1-1 block above and the feed rail's precedent
	// internal/pricingfeed.Envelope.rawRows).
	//
	// It is UNEXPORTED and carries no json tag, so encoding/json never marshals
	// it: json.Marshal(doc), [PricingPolicyDigest] and the wire bytes are
	// unchanged. It is nil for a document built programmatically (e.g. by
	// [SignPricingPolicy] or a test literal); Verify then falls back to the
	// typed path, which the byte-compat property makes identical.
	rawRows []byte
}

// ModelContextWindow is one model's context window in tokens, the element of
// [PricingPolicyDoc.ContextWindows]. Model is normalized (trimmed,
// lower-cased) by the server; Tokens is always positive.
type ModelContextWindow struct {
	Model  string `json:"model"`
	Tokens int64  `json:"context_window_tokens"`
}

// pricingPolicyDocAlias is PricingPolicyDoc's field set without its methods,
// used by UnmarshalJSON to decode the ordinary fields without recursing back
// into UnmarshalJSON itself.
type pricingPolicyDocAlias PricingPolicyDoc

// UnmarshalJSON decodes b into d exactly as the default struct decoding would
// (every field of the embedded body plus the signature, unknown JSON keys
// ignored, same as before this method existed), and ADDITIONALLY captures the
// raw bytes of the body's "rows" array into the unexported rawRows field for
// [VerifyPricingPolicy] to sign over.
//
// This is the ONLY behavioural change on the type. json.Marshal(d) still
// produces exactly the same bytes as before (rawRows is unexported so it never
// marshals), so [PricingPolicyDigest], [SignPricingPolicy] and every existing
// consumer and golden test are unaffected. rawRows is left nil when the
// document carries no "rows" field, in which case Verify falls back to the
// typed canonicalisation.
func (d *PricingPolicyDoc) UnmarshalJSON(b []byte) error {
	if err := json.Unmarshal(b, (*pricingPolicyDocAlias)(d)); err != nil {
		return err
	}
	var rowsHolder struct {
		Rows json.RawMessage `json:"rows"`
	}
	if err := json.Unmarshal(b, &rowsHolder); err != nil {
		return err
	}
	if len(rowsHolder.Rows) == 0 {
		d.rawRows = nil
		return nil
	}
	d.rawRows = rowsHolder.Rows
	return nil
}

// pricingPolicySigningDomain domain-separates pricing-policy signatures from
// every other Ed25519 use in the protocol. One org key signs several rails
// (routing policy, announcement, policy resource, budget, now pricing), so a
// signature minted on one must never verify on another — docs/security.md
// ROUTING-SIG-1. The sibling constant is budgetPolicySigningDomain; the two
// are pinned apart by TestPricingAndBudgetDomainsNeverVerifyEachOther.
const pricingPolicySigningDomain = "sbo-pricing-policy-v1"

// canonicalPricingBody renders the body's signing bytes.
//
// encoding/json's rendering IS the canonical form here, and that is a property
// of the SHAPE rather than a hope: field order is the struct's declaration
// order, there is no map anywhere in PricingPolicyBody or PricingPolicyRow,
// and the slice preserves the order the server built it in. A map field would
// break this (Go randomises map iteration but json sorts keys — deterministic
// but only by accident of the encoder), so a future field that needs one must
// bring a real canonicaliser with it.
//
// The NULLABLE rates (server migration 135) keep this property: a *float64
// with omitempty renders as nothing when nil and as `0` when it points at
// zero, both deterministically, so an unquoted rate and a negotiated free rate
// sign as different documents - which is exactly what they are.
func canonicalPricingBody(body PricingPolicyBody) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("orgcontract.canonicalPricingBody: %w", err)
	}
	return raw, nil
}

// canonicalPricingBodyRaw renders the body's signing bytes from the RAW
// RECEIVED bytes of the `rows` field, so a row field this build does not know
// (a future nested "peak" object, say) rides through into the signature
// untouched instead of being dropped by a typed re-marshal. This is the
// fleet-no-freeze path (see the P1-1 block).
//
// It returns (nil, nil) when rawRows is empty, signalling "no raw bytes were
// captured; the caller must fall back to the typed [canonicalPricingBody]".
//
// BYTE-COMPATIBILITY (the hard requirement). For a document with NO unknown
// fields this MUST produce bytes identical to canonicalPricingBody(typed body),
// or a currently-deployed org server's signed document would stop verifying on
// an upgraded node. It does, because:
//
//   - The wrapper marshals the SAME three fields in the SAME order as
//     PricingPolicyBody — version, then generated_at, then rows — with the same
//     json tags and types, so the framing bytes match exactly.
//   - The server signs over json.Marshal(typed body) and serves those exact
//     compact rows bytes (json.NewEncoder(w).Encode, escapeHTML on). rawRows is
//     therefore already the byte-for-byte output of json.Marshal on the typed
//     rows; json.Compact removes only insignificant whitespace (of which there
//     is none) and the wrapper re-emits the RawMessage verbatim, so the rows
//     portion is unchanged.
//
// The UNLIKE part from the sibling feed rail: this does NOT sort the rows. The
// org server pre-sorts by model id at authoring time, and canonicalPricingBody
// never sorted, so re-ordering here would produce DIFFERENT bytes from the
// signer and break the property above. Received order is preserved.
//
// json.Compact is defensive: were a document ever re-serialised with
// insignificant whitespace between the signer and this verifier, compacting
// restores the canonical form. It cannot change the escaping of the values the
// server produced (its input never contains a literal <, > or &), so it does
// not perturb byte-compatibility.
func canonicalPricingBodyRaw(version int64, generatedAt string, rawRows []byte) ([]byte, error) {
	if len(rawRows) == 0 {
		return nil, nil
	}
	var compacted bytes.Buffer
	if err := json.Compact(&compacted, rawRows); err != nil {
		return nil, fmt.Errorf("orgcontract.canonicalPricingBodyRaw: %w", err)
	}
	raw, err := json.Marshal(struct {
		Version     int64           `json:"version"`
		GeneratedAt string          `json:"generated_at"`
		Rows        json.RawMessage `json:"rows"`
	}{version, generatedAt, json.RawMessage(compacted.Bytes())})
	if err != nil {
		return nil, fmt.Errorf("orgcontract.canonicalPricingBodyRaw: %w", err)
	}
	return raw, nil
}

// PricingPolicySigningMessage returns the canonical bytes signed over a
// pricing policy body:
//
//	SHA-256( domain || 0x00 || orgID || 0x00 || decimal(version) || 0x00 || bodyJSON )
//
// The ORG is bound because a control plane can serve several tenants with one
// signing key in a future deployment, and a genuinely signed price list handed
// to the wrong tenant would be a valid document quoting somebody else's
// negotiated rates. The VERSION is bound EXPLICITLY as well as inside bodyJSON:
// the redundancy costs nothing and it means a reader that ever compares
// versions before parsing the body is comparing a value the signature already
// covered.
//
// There is deliberately NO subject. The document is fleet-wide; binding a
// subject would make every node's copy different, force a per-caller signature
// on a body that is identical for everyone, and misdescribe what the rail is.
func PricingPolicySigningMessage(orgID string, body PricingPolicyBody) ([]byte, error) {
	raw, err := canonicalPricingBody(body)
	if err != nil {
		return nil, err
	}
	return pricingSigningHash(orgID, body.Version, raw), nil
}

// pricingSigningHash frames the domain, org, version and body bytes into the
// SHA-256 signing message. It is the ONE place the framing lives, so the typed
// path ([PricingPolicySigningMessage]) and the raw verification path
// ([pricingVerifyMessage]) can never drift in how they bind the header.
func pricingSigningHash(orgID string, version int64, bodyJSON []byte) []byte {
	h := sha256.New()
	h.Write([]byte(pricingPolicySigningDomain))
	h.Write([]byte{0})
	h.Write([]byte(orgID))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(version, 10)))
	h.Write([]byte{0})
	h.Write(bodyJSON)
	return h.Sum(nil)
}

// pricingVerifyMessage returns the signing message a VERIFIER must reproduce
// for doc. When doc carries the raw received `rows` bytes (i.e. it was decoded
// from JSON, so [PricingPolicyDoc.UnmarshalJSON] populated rawRows) it signs
// over those bytes via [canonicalPricingBodyRaw], so an unknown future row
// field verifies instead of freezing the node. Otherwise — a document built
// programmatically, with no unknowns — it falls back to the typed path, which
// the byte-compat property makes identical.
func pricingVerifyMessage(orgID string, doc PricingPolicyDoc) ([]byte, error) {
	if len(doc.rawRows) > 0 {
		raw, err := canonicalPricingBodyRaw(doc.Version, doc.GeneratedAt, doc.rawRows)
		if err != nil {
			return nil, err
		}
		if raw != nil {
			return pricingSigningHash(orgID, doc.Version, raw), nil
		}
	}
	return PricingPolicySigningMessage(orgID, doc.PricingPolicyBody)
}

// SignPricingPolicy returns the wire document for one org.
func SignPricingPolicy(priv ed25519.PrivateKey, orgID string, body PricingPolicyBody) (PricingPolicyDoc, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return PricingPolicyDoc{}, errors.New("orgcontract.SignPricingPolicy: bad private key size")
	}
	msg, err := PricingPolicySigningMessage(orgID, body)
	if err != nil {
		return PricingPolicyDoc{}, err
	}
	return PricingPolicyDoc{
		PricingPolicyBody: body,
		Signature:         base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)),
	}, nil
}

// ErrPricingPolicySignature is returned by [VerifyPricingPolicy] when the
// document does not verify under pub for this orgID. The node maps it to
// "refuse the body and keep the persisted one", never to "apply an unsigned
// price" — a mis-priced captured turn is permanent (ruling R8).
var ErrPricingPolicySignature = errors.New("orgcontract: pricing policy signature does not verify")

// VerifyPricingPolicy checks doc's signature against pub for the org it was
// minted for. pub is the org's policy signing key, which the node accepts only
// when PublicKeyPinHash(pub) equals its TOFU pin — this function deliberately
// does NOT re-check that pin, so the pin stays owned by the one place that
// established it (internal/orgclient's loadRailPins).
//
// When doc was decoded from JSON it verifies over the RAW RECEIVED `rows` bytes
// ([pricingVerifyMessage] → [canonicalPricingBodyRaw]), so a row field this
// build does not yet know rides through into the signing message untouched and
// a future-field document VERIFIES instead of freezing the node (P1-1). A
// document with no unknown fields signs to identical bytes either way, so every
// currently deployed server's document still verifies.
func VerifyPricingPolicy(pub ed25519.PublicKey, orgID string, doc PricingPolicyDoc) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("orgcontract.VerifyPricingPolicy: bad public key size")
	}
	sig, err := base64.StdEncoding.DecodeString(doc.Signature)
	if err != nil {
		return fmt.Errorf("orgcontract.VerifyPricingPolicy: %w", err)
	}
	msg, err := pricingVerifyMessage(orgID, doc)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return ErrPricingPolicySignature
	}
	return nil
}

// PricingPolicyDigest is the ETag substrate for GET /api/agent/pricing: the
// sha256 hex of the whole signed document.
//
// It hashes the DOCUMENT rather than merely Version for the same reason the
// budget rail does, arrived at from the other side: a version bump is
// SUFFICIENT here but not NECESSARY. A rate corrected in place under one
// version, or a dated row crossing its effective_from boundary between two
// generations, both change what the fleet should apply with no mutation to
// count. Digesting the document means the node re-fetches exactly when the
// bytes it would apply have moved.
func PricingPolicyDigest(doc PricingPolicyDoc) (string, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("orgcontract.PricingPolicyDigest: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// Pricing rail FETCH-STATE vocabulary — the total, closed classification of
// one GET /api/agent/pricing cycle as the node observed it. It lives here
// beside the document because BOTH ends read it: the node stores it in
// org_pricing_cache.state and reports a projection of it on the budget posture
// row, and the server's coverage note renders that projection back.
//
// Every value except Verified means "this node is NOT running the org's
// prices right now, and here is why" — there is no state that means "probably
// fine".
const (
	// PricingFetchDisabled — [guard.budget].from_org is off, so the node
	// never asked. Ruling R2: pricing rides the budget opt-in, because a
	// node enforcing an org cap against non-org prices is the exact failure
	// this arc exists to remove.
	PricingFetchDisabled = "disabled"
	// PricingFetchNotEnrolled — no org enrolment on this node.
	PricingFetchNotEnrolled = "not_enrolled"
	// PricingFetchVerified — a signed body verified and was applied.
	PricingFetchVerified = "verified"
	// PricingFetchNoPricing — a VERIFIED body carrying no rows: the org has
	// authored nothing. The node's org table is cleared and it prices from
	// the seed. This is the ONLY state that may empty the table.
	PricingFetchNoPricing = "no_pricing"
	// PricingFetchNotSupported — 404: the org server predates this rail. The
	// cache is left EXACTLY as it was; see the ladder in
	// internal/orgclient/pricingpolicy.go for why 404 must never clear.
	PricingFetchNotSupported = "not_supported"
	// PricingFetchAuthFailed — 401/403: the server answered, our credential
	// was refused.
	PricingFetchAuthFailed = "auth_failed"
	// PricingFetchChannelOff — 409: the org has published no signing key, so
	// the rail cannot serve a body this node could trust.
	PricingFetchChannelOff = "channel_off"
	// PricingFetchUnreachable — transport error / timeout / 5xx.
	PricingFetchUnreachable = "unreachable"
	// PricingFetchUnverified — a body arrived but this node could not verify
	// it (no pinned org key, a key mismatch, a bad signature, or a replayed
	// lower version). It is REFUSED, never applied.
	PricingFetchUnverified = "unverified"
)
