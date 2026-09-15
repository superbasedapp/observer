package orgcontract

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// Break-glass credential leases (Plane B dual-mode gateway/RBAC/IA design,
// docs/plans/plane-b-dual-mode-gateway-rbac-ia-design-2026-08-29.md §4.2 rung 3,
// operator ruling Q5, P6). Break-glass is fallback-ladder rung 3: when the org
// AI Gateway is unreachable, an admin may REQUEST short-TTL direct provider
// credentials for named nodes; the SINGLE super admin is the sole approver
// (§6.2.2 (d) — no two-person rule); on approval the server mints a per-machine,
// individually-revocable, short-TTL secret lease delivered on the enrolment
// rail. Custody is temporarily, deliberately, visibly suspended — never
// silently.
//
// The design is explicit that break-glass credentials NEVER ride the broadcast
// policy body: "the signed body carries only the permission for break-glass;
// the credentials themselves are per-machine encrypted, individually revocable
// secret leases delivered on the enrolment rail". This file is the wire
// contract for that lease. It mirrors GrantReplacement's signing shape (own
// domain tag, self-contained embedded PublicKey verified against the pinned
// key, NUL-separated signing message, named-error verify helper) so a lease
// signature can never verify as a grant replacement (or anything else), and
// adds two lease-specific facts on top of authenticity:
//
//   - SealedCredential is the provider credential SEALED to the target
//     machine's own key (confidentiality: the broadcast-vs-per-machine
//     distinction the design draws). The signature gives authenticity; the seal
//     gives confidentiality. The org server never distributes a plaintext
//     provider key on any path — the seal is opaque here and OPENED node-side
//     (a separate lane: the enrolment-rail keychain slots). This contract keeps
//     the seal an opaque base64 blob + a SealScheme tag so the node lane knows
//     how to open it without this package taking a crypto dependency.
//   - ExpiresAt bounds the lease: the node stops honoring it at TTL and the
//     server auto-revokes it, in addition to the explicit revoke rail.
//
// The lease is delivered server->node on the push response (the same
// already-authenticated node->server round trip GrantReplacement rides), as an
// omitempty slice so a pre-P6 server never emits it and a pre-P6 node ignores
// it. A node may have more than one pending lease (one per provider upstream),
// hence a slice rather than the single pointer GrantReplacement uses.

// breakGlassLeaseSigningDomain domain-separates break-glass lease signatures
// from every other Ed25519 use in the protocol.
const breakGlassLeaseSigningDomain = "sbo-break-glass-lease-v1"

// HeaderBreakGlassAck is the request header a node sets on its next push to
// report which break-glass lease ids it has adopted/redeemed (comma-separated
// lease ids). Like HeaderGrantReplacementAck it is advisory bookkeeping over an
// already-authenticated push — it can only report the node's OWN adoption and
// never widens access. Redemption processing is the node/enrolment lane's; the
// server's TTL auto-revoke is authoritative regardless of whether this arrives.
const HeaderBreakGlassAck = "X-SBO-Break-Glass-Ack"

// BreakGlassLease is one approved, minted, per-machine break-glass credential
// lease. It targets exactly one node (UserID == the enrolment bearer subject)
// and one provider upstream. Its field shape mirrors GrantReplacement's
// identity-binding + signing fields plus the lease-specific SealedCredential /
// SealScheme / ExpiresAt / Rung / ApprovedBy.
type BreakGlassLease struct {
	// LeaseID is the server-assigned unique id (the revoke rail's key).
	LeaseID string `json:"lease_id"`
	// RequestID links the lease back to the admin break-glass request it was
	// minted under (audit trail; one request fans out to many per-machine
	// leases).
	RequestID string `json:"request_id"`
	// OrgID / OrgServerURL bind the lease to the identity it targets; the node
	// checks both against the enrolment it is already governed by.
	OrgID        string `json:"org_id"`
	OrgServerURL string `json:"org_server_url"`
	// KeyPinSHA256 is the hex sha256 of the org policy signing key this lease is
	// bound to. The node refuses a lease whose pin does not match the key pinned
	// at enrolment.
	KeyPinSHA256 string `json:"key_pin_sha256"`
	// UserID is the target node/machine (the enrolment bearer subject). A lease
	// is per-machine: the server mints and seals one per named target node.
	UserID string `json:"user_id"`
	// UpstreamID names which provider upstream credential this lease unlocks so
	// the node can attach it to direct calls for that provider only.
	UpstreamID string `json:"upstream_id"`
	// Rung is the fallback-ladder rung this lease serves (always
	// "break_glass" today; carried so a future ladder rung can reuse the rail).
	Rung string `json:"rung"`
	// SealScheme names how SealedCredential was sealed to the target machine
	// (opaque to this package; the node lane dispatches on it). Empty is not a
	// valid minted lease.
	SealScheme string `json:"seal_scheme"`
	// SealedCredential is the provider credential sealed to the target machine,
	// base64 (std) opaque bytes. This package never decodes it.
	SealedCredential string `json:"sealed_credential"`
	// PublicKey is the base64url Ed25519 public half of the signing key, carried
	// INLINE like GrantReplacement (the lease arrives out-of-band with no fresh
	// enrolment envelope to source a key from). Verify extracts it and the
	// accept path compares its hash against the pin recorded at enrolment.
	PublicKey string `json:"public_key"`
	// ApprovedBy is the super-admin user id that approved the request this lease
	// was minted under (the single-approver evidence, §6.2.2 (d)).
	ApprovedBy string `json:"approved_by"`
	// GrantedAt / ExpiresAt are RFC3339. ExpiresAt is the short TTL bound.
	GrantedAt string `json:"granted_at"`
	ExpiresAt string `json:"expires_at"`
	// Signature is base64url(Ed25519) over BreakGlassLeaseSigningMessage.
	Signature string `json:"signature"`
}

// BreakGlassLeaseSigningMessage returns the canonical bytes signed over a lease:
// a fixed domain prefix plus every semantic field, NUL-separated so no field can
// shift a boundary into another, mirroring GrantReplacementSigningMessage. The
// sealed credential and its scheme are bound in so a lease cannot be re-pointed
// at a different sealed blob under the same signature.
func BreakGlassLeaseSigningMessage(l BreakGlassLease) []byte {
	h := sha256.New()
	write := func(s string) {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	write(breakGlassLeaseSigningDomain)
	write(l.LeaseID)
	write(l.RequestID)
	write(l.OrgID)
	write(l.OrgServerURL)
	write(l.KeyPinSHA256)
	write(l.UserID)
	write(l.UpstreamID)
	write(l.Rung)
	write(l.SealScheme)
	write(l.SealedCredential)
	write(l.ApprovedBy)
	write(l.GrantedAt)
	write(l.ExpiresAt)
	return h.Sum(nil)
}

// SignBreakGlassLease signs the canonical lease message and returns the
// base64url signature the wire carries. The org server's break-glass mint path
// is the only caller.
func SignBreakGlassLease(priv ed25519.PrivateKey, l BreakGlassLease) string {
	sig := ed25519.Sign(priv, BreakGlassLeaseSigningMessage(l))
	return base64.RawURLEncoding.EncodeToString(sig)
}

// VerifyBreakGlassLease checks a lease's signature against its OWN embedded
// PublicKey (self-contained, mirroring VerifyGrantReplacement) and, on success,
// returns the decoded key so the accept path can separately hash it and compare
// against the pin recorded at enrolment (a lease is never TOFU-pinned — an
// unpinned key here is refused). It returns a NAMED error for every failure so
// the accept path can log exactly why a lease was refused.
func VerifyBreakGlassLease(l BreakGlassLease) (ed25519.PublicKey, error) {
	if l.PublicKey == "" {
		return nil, errors.New("orgcontract.VerifyBreakGlassLease: lease carries no public key")
	}
	pub, err := base64.RawURLEncoding.DecodeString(l.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("orgcontract.VerifyBreakGlassLease: decode public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("orgcontract.VerifyBreakGlassLease: public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	if l.Signature == "" {
		return nil, errors.New("orgcontract.VerifyBreakGlassLease: lease carries no signature")
	}
	sig, err := base64.RawURLEncoding.DecodeString(l.Signature)
	if err != nil {
		return nil, fmt.Errorf("orgcontract.VerifyBreakGlassLease: decode signature: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), BreakGlassLeaseSigningMessage(l), sig) {
		return nil, errors.New("orgcontract.VerifyBreakGlassLease: signature verification failed")
	}
	return ed25519.PublicKey(pub), nil
}

// BreakGlassLeaseReceiptHash is the node's own content address for an accepted
// lease, mirroring GrantReplacementReceiptHash.
func BreakGlassLeaseReceiptHash(l BreakGlassLease) string {
	sum := sha256.Sum256(append(BreakGlassLeaseSigningMessage(l), []byte(l.Signature)...))
	return hex.EncodeToString(sum[:])
}
