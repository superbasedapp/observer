// Package cloudcred is the hardened credential backend for the personal
// cloud-intelligence client (arc 2, CI-P2 — docs/plans/cloud-intelligence-
// azure-foundry-plan-of-record-2026-08-30.md §6 "CI-P2", Sol SC8; amendment
// §3.3). It stores exactly three secrets under the service name
// "sbo-cloud-credential-v1":
//
//   - the WorkOS refresh material (WorkOS is the sole refresh authority);
//   - the device Ed25519 private key that proves possession on every request;
//   - the current short-lived SuperBased API token.
//
// # Per-host scoping
//
// A node can be configured against more than one cloud estate over its
// lifetime (staging then production, or vice versa). OpenForHost scopes the
// API token and WorkOS refresh material to the bare, lower-cased host of the
// cloud base URL currently in use — two estates never share a sign-in — but
// keeps the device signing key SHARED across every host: it is one device
// identity, registered with each estate on exchange, not a per-estate
// secret. Open is a thin wrapper over OpenForHost with host = "", the legacy
// single-slot shape every pre-scoping install already has on disk.
//
// A legacy unscoped API token or WorkOS refresh record is adopted ONCE, by
// whichever host reads it first (in practice the operator's production
// estate, since that is where the legacy sign-in happened): the read returns
// the legacy value and migrates it to the scoped name, then deletes the
// unscoped record, so no other host can adopt it afterwards.
//
// # Backends
//
// The OS keychain (github.com/zalando/go-keyring, the same library the org
// bearer store uses) is the primary backend and provides OS-backed at-rest
// encryption (Keychain / libsecret / Credential Manager). When the keychain is
// unavailable — headless Linux with no Secret Service, a CIFS-mounted HOME —
// the store falls back to a hardened 0600 file backend.
//
// The file fallback is deliberately NOT a clone of orgclient's fileStore
// (which the plan explicitly forbids). It adds, on every read and write:
//
//   - private-directory validation (0700, owner, not a symlink);
//   - Lstat + O_NOFOLLOW symlink refusal, with a re-check of the open handle to
//     close the TOCTOU window;
//   - POSIX ownership verification (unix) on every read and write.
//
// fileFallbackSecure (cred_unix.go / cred_other.go) gates whether Open ever
// selects that file store at all: it is true only on unix, where the
// protections above are real. On every other platform build (Windows today)
// openNoFollow is 0 and the ownership checks are no-ops — there is no
// verified current-user SID/DACL check and no reparse-point refusal — so
// Open fails closed instead (selectFallbackStore returns failClosedStore,
// cred.go): every Save/Load call returns ErrInsecureFallbackUnavailable
// rather than silently writing the WorkOS refresh material, API bearer
// token, or Ed25519 device signing key to an unverified plaintext file. See
// FF2, docs/audits/cloud-intelligence-shipped-code-sol-review-2026-08-31.md.
//
// # Degraded security
//
// Where the file fallback IS selected (unix), it stores plaintext bytes in a
// 0600 file. It cannot provide OS-backed encryption without a platform key
// store (that IS the keychain), so SecurityDiagnostic returns a non-empty,
// CLI-surfaceable message whenever the active backend is the file fallback —
// and a distinct fail-closed message when failClosedStore is active instead.
// A future enhancement could add passphrase-derived (scrypt+AES-GCM) or
// DPAPI/Keychain-item encryption, at which point fileFallbackSecure could be
// flipped to true on that platform; this arc ships the honest diagnostic (or
// the honest refusal) instead of a false sense of protection.
//
// # Purity
//
// stdlib plus github.com/zalando/go-keyring only (pinned by imports_test.go).
// No other internal package, no database/sql, net/http, or fsnotify.
package cloudcred
