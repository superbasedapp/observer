// Package sdkkeygrant is the SDK key grant of the AI Apps SDK quickstart
// (docs/plans/sdk-quickstart-one-command-plan-2026-11-25.md section 3.6;
// contract docs/plans/onboarding-v2-connect-flow.md section 13; ledger
// SDKQS-2).
//
// When a signed-in person approves an `sdk_key` connect request (the device
// sign-in `npx @superbased/sdk setup` and `uvx superbased-sdk setup` start),
// the SuperBased cloud answers the SDK's approved poll with a key grant: a
// short, domain-separated Ed25519 token that names the dashboard (org id,
// slug, kind), the approving account (id, identity-provider subject), the
// connect request, the SHA-256 of the redeem secret only the SDK holds, and a
// ten-minute lifetime. The SDK presents it, with the redeem secret, to that
// dashboard's own host at POST /api/agent/sdk-credential/grant, which mints
// the member's own SDK key through the member key rail.
//
// The package is PURE: the token format, Sign, and Verify with a typed reason
// for every check that belongs to the grant itself (shape, version, the key,
// the signature, the domain, clock skew, lifetime and expiry; a table walked
// top-down). No SQL, no HTTP, no clock (the caller passes now), no file
// reads. The organization, the redeem secret, single use (the jti) and the
// member are the tenant host's decisions over its own store, not this
// package's; RedeemHash and RedeemSecretValid are the shared helpers for the
// redeem check so the SDKs and the host hash the same bytes.
//
// Token format:
//
//	sbsk1.<base64url(payload JSON)>.<base64url(Ed25519 signature)>
//
// The signature is over SigningDomain || 0x00 || payload bytes. The attach
// grant (internal/attachgrant, "sbo-attach-grant-v1", prefix sbag1.) uses
// another tag, another prefix and another claim set, so an attach grant never
// verifies as a key grant nor a key grant as an attach grant, even when one
// platform key signs both (ruling R13's cheaper option); a test pins it both
// ways.
package sdkkeygrant
