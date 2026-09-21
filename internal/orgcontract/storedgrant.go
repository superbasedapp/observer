package orgcontract

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
)

// storedgrant.go — RUNTIME re-verification of the grant document a node has
// on disk (Track C item 1,
// docs/plans/org-guardrail-control-wave-2026-09-21.md).
//
// Until this file, a grant's signature was verified exactly ONCE, at the
// moment the org offered it (orgclient.evaluateGrantOffer), and thereafter
// treated as evidence rather than as a check: internal/govern.Resolve never
// looked at Grant.Signature again. That left one cheap evasion open — edit
// the stored row (authority_json is a plain JSON array in a node-local
// SQLite file) and the resolver would honour the rewritten authority set for
// the life of the grant, because every OTHER gate it applies (org id, server
// URL, key pin, generation, TTL) is a field of that same rewritten row.
//
// Re-verification closes it: the stored fields are re-canonicalized into the
// document the organization actually signed and checked against the org
// distribution key the node recorded at enrolment. A rewritten authority
// list no longer verifies, and the resolver reports a loud state instead of
// obeying it.
//
// HONESTY ABOUT WHAT THIS BUYS (the same posture as grant.go's own note).
// This is DETECTION on a machine the developer owns, not prevention. Someone
// who can edit the grant row can also delete the key-material row, which
// yields "unchecked" rather than "invalid" — loud in `observer org status`
// and `observer doctor`, and visible to the org as a governance lapse (the
// fleethealth `governance_lapsed` finding), but not a lock. The lock is
// OS-level ownership / MDM; see docs/teams-operations.md.

// StoredGrantDocument is the node-local shape of a stored grant, flattened
// to exactly the fields the signature covers.
//
// It exists so the node's store row (internal/store.EnrolmentGrant) never
// has to be shaped like a wire type, and so the two document shapes a stored
// grant can have — the enrolment grant and an out-of-band grant REPLACEMENT,
// which is signed over a different domain with the replacement generation
// bound in — are chosen by a DATA property of the row
// (ReplacementGeneration > 0), never by a caller-side branch.
type StoredGrantDocument struct {
	OrgID        string
	OrgServerURL string
	KeyPinSHA256 string
	Authority    []string
	// GrantedAt / ExpiresAt are RFC3339 as the signer wrote them. ExpiresAt
	// MUST be the SIGNED expiry (store.EnrolmentGrant.SignedExpiresAt), not
	// the working clock: RenewEnrolmentGrant moves the working expiry
	// forward inside the signed window and deliberately leaves the signature
	// and the signed window untouched, precisely so the row keeps verifying.
	GrantedAt string
	ExpiresAt string

	ConsentMode  string
	ConsentActor string

	// Signature is the base64url Ed25519 signature stored with the row.
	Signature string

	// ReplacementGeneration is 0 for an enrolment grant and > 0 for a grant
	// this node accepted through the out-of-band replacement rail. It both
	// SELECTS the document shape and is BOUND INTO the replacement's signing
	// message, so it cannot be flipped to dodge the check: flipping it makes
	// the other document shape's message, which does not verify either.
	ReplacementGeneration int64
}

// ErrStoredGrantUncheckable reports that no verification could be performed
// because the node holds no org distribution key material. It is NOT a
// tamper signal: a pre-2026-09-13 enrolment, or an org server that delivered
// no policy key, legitimately produces it. Callers map it to "unchecked" and
// keep today's behaviour.
var ErrStoredGrantUncheckable = errors.New("orgcontract: no org distribution key material to re-verify the stored grant against")

// VerifyStoredGrant re-verifies a stored grant document under pub.
//
// It returns nil when the document verifies, ErrStoredGrantUncheckable when
// pub is absent/malformed (the honest "we could not check" answer), and a
// named error when the document did NOT verify — which is the tamper signal.
func VerifyStoredGrant(d StoredGrantDocument, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrStoredGrantUncheckable
	}
	if d.Signature == "" {
		return errors.New("orgcontract.VerifyStoredGrant: the stored grant carries no signature")
	}
	sig, err := base64.RawURLEncoding.DecodeString(d.Signature)
	if err != nil {
		return fmt.Errorf("orgcontract.VerifyStoredGrant: decode signature: %w", err)
	}
	if !ed25519.Verify(pub, StoredGrantSigningMessage(d), sig) {
		return errors.New("orgcontract.VerifyStoredGrant: the stored grant does not verify under this organisation's signing key")
	}
	return nil
}

// StoredGrantSigningMessage rebuilds the canonical signing message for a
// stored document by re-projecting it onto whichever wire type actually
// signed it. There is deliberately no third algorithm here: both branches
// call the SAME functions the signer and the enrol-time verifier call, so a
// future change to either signing message can never silently desynchronize
// the runtime check.
func StoredGrantSigningMessage(d StoredGrantDocument) []byte {
	if d.ReplacementGeneration > 0 {
		return GrantReplacementSigningMessage(GrantReplacement{
			OrgID:        d.OrgID,
			OrgServerURL: d.OrgServerURL,
			KeyPinSHA256: d.KeyPinSHA256,
			Generation:   d.ReplacementGeneration,
			Authority:    d.Authority,
			GrantedAt:    d.GrantedAt,
			ExpiresAt:    d.ExpiresAt,
			ConsentMode:  d.ConsentMode,
			ConsentActor: d.ConsentActor,
		})
	}
	return EnrolmentGrantSigningMessage(EnrolmentGrant{
		OrgID:        d.OrgID,
		OrgServerURL: d.OrgServerURL,
		KeyPinSHA256: d.KeyPinSHA256,
		Authority:    d.Authority,
		GrantedAt:    d.GrantedAt,
		ExpiresAt:    d.ExpiresAt,
		ConsentMode:  d.ConsentMode,
		ConsentActor: d.ConsentActor,
	})
}
