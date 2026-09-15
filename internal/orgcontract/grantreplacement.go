package orgcontract

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// Grant replacement (Plane B dual-mode gateway/RBAC/IA design,
// docs/plans/plane-b-dual-mode-gateway-rbac-ia-design-2026-08-29.md §5.3
// item 5, Sol S4). A grant replacement is an OUT-OF-BAND authority change:
// the org server can push a freshly-signed message that supersedes an
// already-enrolled node's stored EnrolmentGrant WITHOUT the node going
// through re-enrolment. It reuses EnrolmentGrant's signing pattern exactly
// (same Ed25519 policy key, same TOFU key-pin check, same
// CanonicalAuthority canonicalization) under its own domain tag, so a
// signature minted for one purpose can never verify for the other.
//
// GrantReplacement carries its own Generation field, which orders
// REPLACEMENTS against each other — it is NOT the Plane-A P0-5
// enrolment-identity generation (internal/store.EnrolmentGeneration) and
// must never be compared against or confused with it. See migration 094's
// header comment for why the two are kept structurally separate.

// grantReplacementSigningDomain domain-separates replacement signatures from
// EnrolmentGrant's own signatures and every other Ed25519 use in the
// protocol: a signature minted for one purpose can never verify for
// another.
const grantReplacementSigningDomain = "sbo-grant-replacement-v1"

// GrantReplacement is the org server's out-of-band replacement message. It
// mirrors EnrolmentGrant's field shape (same identity-binding fields, same
// consent-evidence fields) plus Generation, the strictly-monotonic ordering
// counter the node's accept path enforces so a replayed or out-of-order
// replacement is rejected rather than applied.
type GrantReplacement struct {
	// OrgID / OrgServerURL bind the replacement to the identity it targets;
	// the node checks both against the enrolment it is already governed by.
	OrgID        string `json:"org_id"`
	OrgServerURL string `json:"org_server_url"`
	// KeyPinSHA256 is the hex sha256 of the org policy signing key this
	// replacement is bound to. The node refuses a replacement whose pin does
	// not match the key pinned at enrolment.
	KeyPinSHA256 string `json:"key_pin_sha256"`
	// Generation orders replacements against EACH OTHER, strictly increasing
	// with every accepted replacement for the same identity. It starts
	// comparison at 0 (no replacement ever accepted), so the first
	// replacement (Generation >= 1) always applies. It is NOT the enrolment-
	// identity generation and the accept path must never write it there.
	Generation int64 `json:"generation"`
	// PublicKey is the base64url Ed25519 public half of the signing key,
	// carried INLINE like PolicyBundle.PublicKey (NOT like EnrolmentGrant,
	// which instead trusts a separately-delivered EnrollResponse field).
	// This is deliberate: EnrolmentGrant is verified during the SAME
	// request/response round trip as enrolment, so the envelope's own
	// OrgPolicyPublicKey field is trustworthy right then. A replacement
	// arrives later, out-of-band, with no fresh envelope to source a key
	// from — the node's only durable record of the org policy key is a
	// SHA256 PIN (guard_policy_state), not the raw bytes. So, like a policy
	// bundle fetch, the message must be self-contained: VerifyGrantReplacement
	// extracts PublicKey and checks the signature under it; the accept path
	// then separately hashes it and compares against the EXISTING pin
	// recorded at enrolment (never TOFU-pins from a replacement — unlike a
	// first policy-bundle fetch, this is not the node's first contact with
	// the org, so an unpinned key here is refused, not trusted).
	PublicKey string `json:"public_key"`
	// Authority is the closed-vocabulary token list (see internal/govern)
	// this replacement grants, in full — like EnrolmentGrant, a replacement
	// REPLACES the stored authority set, it does not merge into it.
	Authority []string `json:"authority"`
	// GrantedAt / ExpiresAt are RFC3339.
	GrantedAt string `json:"granted_at"`
	ExpiresAt string `json:"expires_at"`
	// ConsentMode / ConsentActor are the ACP-P6c consent EVIDENCE, carried
	// through unchanged from EnrolmentGrant's convention: empty for every
	// token-rail-originated grant, populated for an idp-approved one.
	ConsentMode  string `json:"consent_mode,omitempty"`
	ConsentActor string `json:"consent_actor,omitempty"`
	// Signature is base64url(Ed25519) over GrantReplacementSigningMessage.
	Signature string `json:"signature"`
}

// GrantReplacementSigningMessage returns the canonical bytes signed over a
// replacement: a fixed domain prefix plus every semantic field, NUL-
// separated so no field can shift a boundary into another, mirroring
// EnrolmentGrantSigningMessage's construction with Generation bound in
// (encoded as its base-10 string form, itself NUL-terminated like every
// other field) between the identity fields and the authority list.
func GrantReplacementSigningMessage(g GrantReplacement) []byte {
	h := sha256.New()
	write := func(s string) {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	write(grantReplacementSigningDomain)
	write(g.OrgID)
	write(g.OrgServerURL)
	write(g.KeyPinSHA256)
	write("generation")
	write(fmt.Sprintf("%d", g.Generation))
	for _, a := range CanonicalAuthority(g.Authority) {
		write("authority")
		write(a)
	}
	write(g.GrantedAt)
	write(g.ExpiresAt)
	if g.ConsentMode != "" {
		write("consent_mode")
		write(g.ConsentMode)
		write("consent_actor")
		write(g.ConsentActor)
	}
	return h.Sum(nil)
}

// SignGrantReplacement signs the canonical replacement message and returns
// the base64url signature the wire carries. The org server's replacement
// endpoint is the only caller.
func SignGrantReplacement(priv ed25519.PrivateKey, g GrantReplacement) string {
	sig := ed25519.Sign(priv, GrantReplacementSigningMessage(g))
	return base64.RawURLEncoding.EncodeToString(sig)
}

// VerifyGrantReplacement checks a replacement's signature against its OWN
// embedded PublicKey (self-contained, mirroring VerifyPolicyBundle — see
// GrantReplacement.PublicKey's doc comment for why this differs from
// VerifyEnrolmentGrant's caller-supplies-the-key shape) and, on success,
// returns the decoded key so the accept path can separately hash it and
// compare against the pin recorded at enrolment. It returns a NAMED error
// for every failure so the accept path can log exactly why a replacement
// was refused rather than silently keeping (or worse, silently dropping)
// the last-good grant.
func VerifyGrantReplacement(g GrantReplacement) (ed25519.PublicKey, error) {
	if g.PublicKey == "" {
		return nil, errors.New("orgcontract.VerifyGrantReplacement: replacement carries no public key")
	}
	pub, err := base64.RawURLEncoding.DecodeString(g.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("orgcontract.VerifyGrantReplacement: decode public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("orgcontract.VerifyGrantReplacement: public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	if g.Signature == "" {
		return nil, errors.New("orgcontract.VerifyGrantReplacement: replacement carries no signature")
	}
	sig, err := base64.RawURLEncoding.DecodeString(g.Signature)
	if err != nil {
		return nil, fmt.Errorf("orgcontract.VerifyGrantReplacement: decode signature: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), GrantReplacementSigningMessage(g), sig) {
		return nil, errors.New("orgcontract.VerifyGrantReplacement: signature verification failed")
	}
	return ed25519.PublicKey(pub), nil
}

// GrantReplacementReceiptHash is the node's own content address for an
// accepted replacement, mirroring EnrolmentGrantReceiptHash.
func GrantReplacementReceiptHash(g GrantReplacement) string {
	sum := sha256.Sum256(append(GrantReplacementSigningMessage(g), []byte(g.Signature)...))
	return hex.EncodeToString(sum[:])
}
