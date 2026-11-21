// Package oidcissuer is the pure core of the control plane's platform OIDC
// issuer (managed-SaaS plan 07 M6.2; design
// docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md sections
// 3.3 and 4.4, lead decision L-9 Q5).
//
// The issuer signs a member of an org in to that org's tenant: the tenant's
// OIDC rail (internal/orgserver/auth, preset "platform" from M6.7) is the
// relying party, the control plane is the identity provider. Every org has
// one PUBLIC client, client_id "org:<org_id>", with exactly one registered
// redirect URI (https://<slug>.<tenant domain>/auth/oidc/callback), PKCE S256
// required and no client secret. id_tokens are RS256 (the tenant rail
// verifies RSA only) and live at most five minutes.
//
// What lives here (no I/O, pinned by imports_test.go):
//
//   - the rule tables walked top-down for the authorize request, the client
//     and redirect URI, the caller's membership, the token request and the
//     code's binding (rules.go), one test case per row;
//   - PKCE S256 verification (plain is refused), the exact redirect URI match,
//     and code single-use semantics expressed through the Store seam
//     (ConsumeCode is one conditional UPDATE, so authorize and token may run
//     on different replicas: codes live in the database, never in memory);
//   - the claim set, its builder and the validation the SIGNER applies before
//     it signs anything (claims.go): fixed iss, aud equal to the org's client
//     id, exp at most five minutes after iat, iat fresh, jti present;
//   - compact JWS assembly and verification, RSA JWKs and their RFC 7638
//     thumbprints (the kid), the JWKS and discovery documents (jwt.go);
//   - LocalSigner, the in-process Signer used by tests and by the signer
//     process itself (internal/cloudserver/oidcissuer/signerd serves it over a
//     unix socket with a peer-uid check);
//   - Issuer, the service the HTTP layer calls: it holds no state between
//     requests and reaches the database only through Store and the private key
//     only through Signer.
//
// Ordering rules the Issuer enforces, because they are the security of the
// flow:
//
//   - authorize validates the client and the exact redirect URI BEFORE it
//     asks the caller to sign in or redirects anywhere (an unknown client or a
//     mismatched redirect URI is answered in place, never redirected, RFC 6749
//     4.1.2.1);
//   - token consumes the code FIRST (one conditional UPDATE), then checks the
//     client, the redirect URI and the PKCE verifier, so a wrong verifier burns
//     the code and a code can be redeemed at most once;
//   - token re-checks the caller's membership and the org's state, so a
//     member removed (or an org suspended) between authorize and token gets
//     no token;
//   - the token is signed, verified against the PUBLISHED public key for its
//     kid, and recorded (oidc_issued plus the oidc_audit_mirror outbox row, one
//     transaction) BEFORE it is returned. A failed record fails the sign-in
//     (audit before act); a signer outage is 503 and never an unsigned token.
//
// Keys: each app VM's signer holds its own RSA key, so the JWKS lists one kid
// per VM. A key the signer reports is registered "staged" (not published);
// an operator promotes it to "active" with a not_before at least the
// publication lead time ahead, so the kid is in the JWKS before its first use;
// "retiring" keys stay published (old tokens and the tenants' one-hour JWKS
// cache) but sign nothing; "retired" keys are gone.
package oidcissuer
