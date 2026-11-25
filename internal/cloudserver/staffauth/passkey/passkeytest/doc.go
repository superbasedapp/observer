// Package passkeytest is a software WebAuthn authenticator for tests of the
// staff console: it builds the exact bytes a browser hands a relying party
// (clientDataJSON, a CBOR attestation object with attestation "none" and a
// COSE credential key, authenticator data, an assertion signature) with a
// real ES256 or EdDSA key, so the production verifier (package passkey) is
// exercised end to end with no network and no fake verification.
//
// Every knob on Ceremony defaults to the honest value; a test sets one to
// produce the response a misbehaving or hostile client would send. It is
// test support only: no production package imports it.
package passkeytest
