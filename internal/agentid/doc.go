// Package agentid is the PURE Agent Access identity core (doc3 §2.1/§2.4/§4,
// wave P1 W1a/W1c): the principal and claim schema, RFC 9068 `at+jwt`
// mint/verify with an algorithm-agile key ring, the context-free RFC 9068
// profile check our own ext_authz / A2 front runs (agentgateway does not check
// typ, iat, jti, client_id or our typed claims, and tolerates ~60 s past exp -
// ADR-0007 §3.2), the token-exchange decision table, the key-ring rotation
// state machine, the bounded unknown-kid JWKS refetch, and the node
// `sbo-actor+jwt` actor-assertion profile.
//
// Invariants:
//
//   - Algorithm agility (R8.23.m / R8.26.m): signing goes through the opaque
//     Signer (a crypto.Signer plus an alg-tagged public JWK), selected by kid
//     from a configured asymmetric allowlist {EdDSA, ES256, RS256}. EdDSA is
//     the default, never a pinned literal; alg none and HMAC are
//     unrepresentable (internal/dpop/jose).
//   - Server-token signing (ServerTokenSigner, the org key ring) and node
//     proof signing (NodeProofSigner, the per-device agent-access key) are
//     SEPARATE interfaces, so one can never be passed where the other is
//     expected (R8.13 / B8).
//   - The JOSE `typ` lives in the protected header (R8.13): `at+jwt` for
//     access tokens, `sbo-actor+jwt` for actor assertions. A token of one type
//     is never accepted as the other.
//   - Bearer is the DEFAULT sender constraint (R9.1): `cnf` is emitted only
//     when the caller binds the token (DPoP jkt or mTLS x5t#S256). sbo_sender
//     is INFORMATIONAL; VerifyProfile is context-free crypto/profile
//     validation and never an admission decision (R8.24.m).
//   - MFA claims (amr/acr/auth_time) are copied only from a Principal whose
//     caller populated them from a FRESH user assertion - never from the
//     enrolment bearer (R6).
//   - Token size (§4.7): an access token over the 4 KiB target switches its
//     authorization_details to a single sbo_mcp_grant reference digest.
//
// Purity: no database/sql, net/http, fsnotify or internal/orgserver import
// (pinned by imports_test.go). Stores, clocks and randomness are injected.
package agentid
