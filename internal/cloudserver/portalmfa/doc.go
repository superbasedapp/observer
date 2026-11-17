// Package portalmfa is the pure core of the portal's passkey second factor
// (managed-SaaS plan 07 tracker row "C2 portal WebAuthn second factor";
// lead decision L-92: C2 before GA; wave 17 lane portal-guardrails;
// docs/security.md PLATRAIL-3).
//
// A SuperBased account signs in to the portal with its primary method
// (WorkOS AuthKit, or the dev-auth stub). An account that has registered a
// passkey must then prove it on every new portal session before the session
// can do anything but finish that proof; the platform OIDC issuer signs the
// proof into the tenant's id_token as `amr` (RFC 8176), and an org can
// require it of every member at its sign-in.
//
// This package holds the decisions, as data tables walked top down, and the
// library-independent pieces:
//
//   - the WebAuthn user handle of an account and the relying-party name;
//   - the recovery codes: minting, normalising, hashing;
//   - the amr a portal session can truthfully carry (amrRules);
//   - which portal routes a session with a pending second factor may reach
//     (pendingRoutes);
//   - whether a session may enrol a passkey, manage passkeys and recovery
//     codes, or change an org's second-factor requirement (actionRules);
//   - whether the platform issuer may issue for an org (IssueRule).
//
// WebAuthn verification itself is staffauth.Verifier (the staff console's
// passkey code, L-92), reused unchanged. No SQL, HTTP or file I/O here
// (pinned by imports_test.go): the store and api packages do the I/O.
package portalmfa
