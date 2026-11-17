// Package staffauth is the pure core of the cloud staff console (managed-SaaS
// plan 07 M6.8; design docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md
// 3.5, 3.6, 4.9; operator rulings A2 and A3 of 2026-11-13).
//
// It holds the decisions the staff console makes, as data tables walked top
// down, and the types its I/O layers share:
//
//   - the staff roles (support, ops, admin) and the authorization table that
//     says which role may perform which staff action and whether the action
//     needs a fresh WebAuthn assertion (Authorize);
//   - the WebAuthn verifier seam (Verifier) and its ceremony types, which are
//     this package's own: no WebAuthn library type crosses it. The
//     production implementation is the passkey subpackage, over
//     github.com/go-webauthn/webauthn; Unavailable is the verifier of a
//     process that has none wired, and its routes answer not_available;
//   - the library-independent halves of a ceremony: the challenge, the
//     creation and request options a browser passes to
//     navigator.credentials, the credential id read from a browser's
//     response, and the signature-counter rule;
//   - the closed vocabularies of the staff action log and of the
//     availability-input sections, with their validators.
//
// Staff passkey policy (ruling A2):
//
//   - The passkey is the factor Observer verifies itself; there is no
//     WorkOS-only staff sign-in. A staff session is minted only by a
//     verified assertion with user verification.
//   - Every credential is discoverable (residentKey required) and every
//     assertion is discoverable (no allowCredentials), so the user handle in
//     the assertion names the staff member.
//   - Attestation "none" is requested and accepted, so the console cannot
//     tell a hardware security key from a synced platform passkey: hardware
//     keys are NOT enforced. The AAGUID is recorded when the authenticator
//     reports one, for the operator's own audit only.
//   - A staff member may hold several active passkeys (at least two are
//     expected: a primary and a backup), at most MaxActivePasskeys (five,
//     ruling Staff 2): a further registration is refused and logged, and
//     passkeys registered before the cap are kept. Each one is registered
//     with its own single-use code from `observer-cloud staff enrol
//     --staff-id`.
//   - The first credential, every later one, and every recovery come from
//     the operator CLI only: no web route mints an enrolment code. A lost
//     passkey is revoked with `observer-cloud staff revoke-credential`, which
//     ends every session it signed in, and replaced through a fresh code.
//
// No SQL, no HTTP, no file system: the store seam is
// internal/cloudserver/store (staff.go) and the HTTP routes are
// internal/cloudserver/api (staff*.go). imports_test.go pins it.
package staffauth
