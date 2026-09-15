package update

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// The VENDOR artifact-signature key material.
//
// Two independent signatures protect an apply (§2.2):
//
//  1. the ORG's Ed25519 manifest signature, TOFU-pinned per org — the
//     same distribution identity the announcement and routing rails
//     already pin. verify.go checks it.
//  2. the VENDOR's per-artifact signature over the ARCHIVE BYTES,
//     verified against a key compiled into this binary, so a compromised
//     org server alone cannot serve a binary we did not build.
//
// Verification of (2) is OFFLINE by design: no Rekor lookup, because
// that would be a second outbound host on a node whose only permitted
// egress is the org server it is enrolled with (ruling R8).
//
// STATUS: the producer of (2) EXISTS as of W6 (2026-09-07). The release
// pipeline signs each agent archive with the private half of
// VendorPublicKeyV1 and attaches a sibling `<archive>.sig` holding the
// RAW 64-byte Ed25519 signature over the archive bytes — the exact shape
// cmd/observer/update_vendorsig.go verifies, so producer and verifier
// cannot drift into a container format one side does not implement.
// A release built without the OBSERVER_VENDOR_SIGNING_KEY secret still
// ships, but carries no `.sig` files, and a node fails closed on the
// resulting unsigned artifact (verify rule 9,
// blocked{unsigned_artifact}) rather than applying it.
const (
	// VendorPublicKeyV1 is the CURRENT vendor verification key, base64
	// of the 32 raw Ed25519 public-key bytes. Its private half lives
	// only in the OBSERVER_VENDOR_SIGNING_KEY secret on the private
	// origin repo; it is never in this tree.
	//
	// Generated 2026-09-07 (W6). key_id (the first 16 bytes of
	// sha256(pubkey), hex) = 7595a73e343e517a07c8d944ba75be91.
	VendorPublicKeyV1 = "npbhJUUL/Zy088BDnuqYRDqjjQtlyF9/eVcWFOCzj2g="

	// VendorPublicKeyV0Previous is the ROTATION SLOT: the key retained
	// for ONE release after a rotation, so an agent released during the
	// overlap accepts both the old and the new key and a rotation
	// cannot strand a fleet mid-flight (§2.2).
	//
	// It is EMPTY between rotations, and an empty slot contributes no
	// key — the zero value must never mean "accept anything". The
	// rotation procedure is four steps and step 3 is the one that is
	// easy to skip and impossible to recover from without re-enrolling
	// every node:
	//
	//  1. generate a new keypair (`go run ./scripts/vendorsign keygen`);
	//  2. move VendorPublicKeyV1's value HERE and put the new key in
	//     VendorPublicKeyV1;
	//  3. SHIP A RELEASE with both accepted, and wait for the fleet to
	//     reach it — agents verify against a compiled-in key set, so a
	//     key they never received is a key they will never accept;
	//  4. swap the OBSERVER_VENDOR_SIGNING_KEY secret, then clear this
	//     slot one release later.
	VendorPublicKeyV0Previous = ""

	// vendorPlaceholderKey is the pre-W6 placeholder: 32 zero bytes,
	// base64. It is kept as a REFUSED sentinel rather than deleted,
	// because the reason it was never accepted outlives it: an all-zero
	// Ed25519 public key VERIFIES an all-zero signature (the identity
	// point satisfies the verification equation trivially), so a build
	// that accepted it could be passed with 64 zero bytes. Anything
	// that puts those bytes back into the accepted set — a bad merge, a
	// half-finished rotation that blanks V1 — must fail closed, and
	// vendorkey_test.go pins that.
	vendorPlaceholderKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)

// vendorPublicKeysB64 is the ACCEPTED set, newest first.
//
// It is a SLICE, not a single value, because §2.2 requires a key
// rotation to ship an overlap window: an agent release that accepts
// both the old and the new key, so rotating cannot strand a fleet
// mid-flight. Adding a key is one line here plus one release.
var vendorPublicKeysB64 = []string{VendorPublicKeyV1, VendorPublicKeyV0Previous}

// VendorPublicKeys returns the vendor verification keys this binary
// ACCEPTS, in preference order.
//
// Empty entries (the unused rotation slot), malformed entries and the
// placeholder are all dropped rather than panicked on (no panic in
// library code). A build whose key material is missing or unparseable
// therefore returns an EMPTY slice, which the caller must treat as
// "this build can verify no artifact signature" and fail closed on —
// never as "no key needed".
func VendorPublicKeys() []ed25519.PublicKey {
	out := make([]ed25519.PublicKey, 0, len(vendorPublicKeysB64))
	for _, s := range vendorPublicKeysB64 {
		if s == "" || s == vendorPlaceholderKey {
			continue
		}
		raw, err := ParseVendorKey(s)
		if err != nil {
			continue
		}
		out = append(out, raw)
	}
	return out
}

// ParseVendorKey decodes one base64 Ed25519 public key. It is exported
// so the key material can be checked (by a test, and by the release
// pipeline's signer) independently of whether this build accepts it.
func ParseVendorKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("update.ParseVendorKey: not base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("update.ParseVendorKey: key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// VendorKeyIsPlaceholder reports whether this build carries NO usable
// vendor key — every slot is empty or still the pre-W6 placeholder.
//
// It exists so a surface can say "no vendor key is compiled into this
// build" instead of reporting every artifact as a signature FAILURE —
// two different facts that would otherwise be indistinguishable to an
// operator. It changes no gate: rule 9 already refuses an artifact
// without a signature, and an apply against no key can never verify one.
//
// Since W6 it is false for a normally-built binary. It stays in the
// codebase because a rotation that blanks the current key, or a build
// from a branch that predates the key, must still be describable.
func VendorKeyIsPlaceholder() bool {
	for _, s := range vendorPublicKeysB64 {
		if s != "" && s != vendorPlaceholderKey {
			return false
		}
	}
	return true
}
