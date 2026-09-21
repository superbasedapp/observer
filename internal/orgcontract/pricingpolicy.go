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

	// LongContextThreshold is NOT nullable: 0 already means "no long-context
	// tier" unambiguously, so a NULL would say nothing new.
	LongContextThreshold           int64    `json:"long_context_threshold,omitempty"`
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
	// field for field (Phase 2, plan §R2/P2-B). Nil ⇒ the org has authored no
	// peak variant for this model — and that nil-ness is itself the signal:
	// composing it onto the node's seed table REPLACES the seed's peak
	// wholesale rather than leaving it, so a negotiated flat-rate model is
	// never rebilled at the seed's peak multiplier (see cost.OrgPrice's
	// overlay). omitempty keeps an absent peak byte-identical to a
	// pre-Phase-2 document, so a document with no peak rows still verifies
	// unchanged on a node built before this field existed.
	Peak *PeakRates `json:"peak,omitempty"`
}

// Rate boxes a quoted rate so a caller can state one inline. &0.0 is not
// expressible in a Go composite literal, and every builder of a policy row
// needs to be able to say "this rate IS set, to zero" - a negotiated free
// model - as distinct from leaving it nil.
func Rate(v float64) *float64 { return &v }

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
