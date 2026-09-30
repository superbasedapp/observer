// Package dpop is a fresh RFC 9449 (OAuth 2.0 Demonstrating Proof of
// Possession) implementation for Agent Access (doc3 §4.4). It is NOT a
// rename of internal/cloudpop, whose `sbo-pop+jws` profile requires a body
// digest and delegates replay to its caller.
//
// Proofs are `typ=dpop+jwt` JWS with an embedded public `jwk` and the claims
// {jti, htm, htu, iat, ath?, nonce?}. The node relay may add the extra claim
// `sbo_corr` (R11.8): signed per call, bound to the token's cnf.jkt key.
//
// Two verifier profiles (R8.23.j):
//
//   - ProfileTokenEndpoint - the STS /oauth2/token request: htm/htu/iat/jti
//     (+nonce); there is no access token yet, so ath is not evaluated.
//   - ProfileResource - every data-plane request: additionally requires ath =
//     base64url(SHA-256(access token)) and (optionally) the token's cnf.jkt.
//
// Replay defence is a SHARED store (ReplayStore: the `dpop_replay` CONTROL
// table or NATS-KV, atomic insert-if-absent) - a per-process cache is not
// sufficient across STS/data-plane replicas (finding-8). Verify fails CLOSED
// when the store is absent or errors.
//
// htu is compared in canonical form (CanonicalHTU); CanonicalRequestHTU
// reconstructs the request URI honouring X-Forwarded-* ONLY from a configured
// trusted-proxy CIDR (§14.3). Server nonces (`DPoP-Nonce`) are stateless
// HMAC time buckets (NonceIssuer) so every replica sharing the key agrees.
//
// Body binding (`bdh`) is not part of this profile.
//
// Purity: stdlib + internal/dpop/jose only; takes a bare crypto.Signer + alg
// and never imports internal/agentid (no agentid<->dpop cycle). Pinned by
// imports_test.go.
package dpop
