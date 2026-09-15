package orgcontract

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
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
// THE STANDING CONSEQUENCE, which is the part worth carrying forward: because
// verification re-derives the bytes from THIS BUILD'S struct rather than
// checking the signature against the bytes actually received, ANY future
// field-shape change to this document - a field added, removed, renamed,
// reordered, or retyped between value and pointer - is a fleet-freezing change
// for every node still on the older struct. It is a DESIGN RESIDUAL of
// verify-by-re-marshal, not a property of the nullable-rate change. Two exits
// exist and neither is taken here: verify over the received canonical bytes, or
// version the document so an old node can refuse it knowingly. Until one is,
// TestPricingPolicyCanonicalBytesArePinned is the tripwire - a shape change
// fails there, at authoring time, instead of on a fleet.

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
	h := sha256.New()
	h.Write([]byte(pricingPolicySigningDomain))
	h.Write([]byte{0})
	h.Write([]byte(orgID))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(body.Version, 10)))
	h.Write([]byte{0})
	h.Write(raw)
	return h.Sum(nil), nil
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
func VerifyPricingPolicy(pub ed25519.PublicKey, orgID string, doc PricingPolicyDoc) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("orgcontract.VerifyPricingPolicy: bad public key size")
	}
	sig, err := base64.StdEncoding.DecodeString(doc.Signature)
	if err != nil {
		return fmt.Errorf("orgcontract.VerifyPricingPolicy: %w", err)
	}
	msg, err := PricingPolicySigningMessage(orgID, doc.PricingPolicyBody)
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
