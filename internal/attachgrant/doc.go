// Package attachgrant is the one-step attach grant of the Getting started v2
// connect flow (docs/plans/onboarding-v2-connect-flow.md section 11; ledger
// docs/security.md ONB-8 to ONB-10).
//
// When a signed-in person clicks Connect for a dashboard, the SuperBased
// cloud answers the machine's approved poll with an attach grant: a short,
// domain-separated Ed25519 token that names the dashboard (org id, slug,
// kind), the account (id, identity-provider subject, verified email), the
// device key the connect request was made with (its RFC 7638 thumbprint), the
// request, the share level, and a ten-minute lifetime. The machine presents
// it to that dashboard's own server at POST /api/agent/enroll together with a
// proof signed by the same device key, and is enrolled with no second browser
// step.
//
// The package is PURE: the token format, the verification rules (a table
// walked top-down), the proof message and the RFC 7638 thumbprint. No SQL, no
// HTTP, no clock (the caller passes now), no file reads. The cloud mints with
// Mint; the org server verifies with Verify and VerifyProof; the node signs
// its proof with SignProof. Single use (the grant's jti) and membership are
// the org server's decisions over its own store, not this package's.
//
// Token format:
//
//	sbag1.<base64url(payload JSON)>.<base64url(Ed25519 signature)>
//
// The signature is over SigningDomain || 0x00 || payload bytes, so a grant
// signature never verifies as any other document, envelope or JWS the
// platform signs (each carries its own tag, and a JWS signing input is
// base64url text with no NUL byte).
package attachgrant
