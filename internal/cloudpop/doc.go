// Package cloudpop implements the DPoP-style per-request proof-of-possession
// format that binds a SuperBased personal-cloud API token to the caller's
// Ed25519 device key (arc 2, CI-P2 — docs/plans/cloud-intelligence-azure-
// foundry-plan-of-record-2026-08-30.md §6 "CI-P2", Sol SC2; amendment §3.3).
//
// Both sides of the wire import this package: the node client (internal/
// cloudclient) mints a fresh proof on every device API request, and the
// hosted server verifies it. A stolen short-lived API token is useless without
// the device private key, because every request must carry a proof signed by
// that key and bound to (a) the exact request method and canonical URL,
// (b) a hash of the presented access token, (c) the request body on write
// methods, and (d) a fresh timestamp and unique jti.
//
// # Encoding
//
// The proof is a JWS-compact structure (RFC 7515 §7.1) using EdDSA over
// Ed25519 (RFC 8037): base64url(protected-header) "." base64url(payload) "."
// base64url(signature), where the signature is Ed25519 over the ASCII bytes of
// "base64url(protected-header).base64url(payload)". All base64url uses the
// URL alphabet with NO padding (RFC 7515 §2). This was chosen over a custom
// canonical-JSON scheme so the hosted server can verify with any conformant
// JWS/EdDSA library while the node stays stdlib-only.
//
//   - Protected header: {"typ":"sbo-pop+jws","alg":"EdDSA","jwk":{...}}. The
//     device public key is embedded as an RFC 8037 OKP JWK so the verifier can
//     both check the signature and recompute the RFC 7638 thumbprint that binds
//     the proof to the registered device.
//   - Payload claims: jti (unique), htm (method), htu (canonical URL), iat
//     (unix seconds), ath (base64url SHA-256 of the presented access token),
//     and bdh (the "sha256:<hex>" body digest — REQUIRED on write methods,
//     absent otherwise).
//
// # Replay
//
// jti uniqueness (replay defence) is the CALLER's store-side job: Verify
// returns the jti so the server can consult its own single-use cache within
// the clock window. This package holds no state and does not detect replay.
//
// # Purity
//
// stdlib-only (pinned by imports_test.go): the package never touches
// filesystem, network, database, or config surfaces.
package cloudpop
