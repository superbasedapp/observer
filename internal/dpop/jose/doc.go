// Package jose is the strict, stdlib-only JOSE core shared by the Agent Access
// crypto packages: RFC 7515 JWS compact serialisation over an OPAQUE
// crypto.Signer, RFC 7517 public JWKs, RFC 7638 thumbprints and the closed
// asymmetric algorithm allowlist {EdDSA, ES256, RS256} (R8.23.m / R8.26.m).
//
// It lives under internal/dpop so that BOTH internal/dpop (RFC 9449 proofs)
// and internal/agentid (RFC 9068 access tokens, sbo-actor+jwt assertions) can
// share one implementation without an agentid<->dpop import cycle: doc3 §2.1
// lets agentid import internal/dpop/..., and forbids dpop from importing
// agentid.
//
// Design rules:
//
//   - Signing goes through crypto.Signer only, so a KMS-backed non-exportable
//     key (Azure Key Vault, LocalSealed) and an in-memory key are the same
//     thing to the caller. ECDSA signers follow the Go convention of returning
//     an ASN.1 DER signature; Sign converts it to the JWS fixed-width R||S form.
//   - alg "none" and every symmetric (HS*) algorithm are unrepresentable: the
//     allowlist is a closed set of asymmetric algorithms, and an algorithm is
//     only accepted when it matches the key type of the JWK it is verified
//     against (no RSA-key-as-HMAC-secret confusion is possible).
//   - Headers that point at remote or unsupported key material (jku, x5u, x5c,
//     crit, b64) are rejected; this package never fetches anything.
//   - Parsing is bounded (caller-supplied byte cap) and fails closed.
//
// Purity: stdlib only (pinned by imports_test.go) - no database/sql, net/http,
// fsnotify, os, or any other package of this module.
package jose
