// Package passkey is the staff console's WebAuthn verifier (managed-SaaS
// plan 07 M6.8; operator ruling A2 of 2026-11-13): the production
// implementation of staffauth.Verifier, over github.com/go-webauthn/webauthn
// (protocol package, v0.18.2).
//
// It is the ONLY package that imports the library (imports_test.go pins that
// for the cloud service), and the library's types stop here: the exported
// surface is New, which returns a staffauth.Verifier, and the ErrVerification
// sentinel. A response goes in as bytes and comes out as staffauth's own
// NewCredential or VerifiedAssertion.
//
// What it enforces, on top of the library's ceremony checks (type,
// challenge, exact origin, rpIdHash, user presence, signature, attested
// credential id):
//
//   - user verification on every ceremony (ruling A2);
//   - no cross-origin and no top-level-origin embedding;
//   - the relying-party id is exactly the origin's host, never a parent
//     domain (ruling A3), and the origin is https unless it is loopback;
//   - the credential's algorithm is one staffauth.CredentialAlgorithms
//     offers;
//   - an assertion names the stored credential and carries the stored user
//     handle (every staff ceremony is discoverable);
//   - the backup-state flag is never set without backup eligibility.
//
// Attestation: any format the library verifies is accepted ("none" is what
// the options request), with no metadata service and no trust anchors, so a
// hardware security key cannot be told from a synced platform passkey. The
// signature counter is reported, not judged: the caller applies
// staffauth.CheckSignCount against the stored value.
//
// passkeytest holds a software authenticator for tests (real CBOR and COSE,
// ES256 and EdDSA keys); it is not imported by production code.
package passkey
