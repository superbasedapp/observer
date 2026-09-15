// Command vendorsign is the RELEASE-SIDE producer of the vendor
// artifact signature and the signed release manifest that wave W6 of
// docs/plans/enterprise-update-management-plan-2026-09-07.md specifies.
//
// It is the counterpart of two things already in the tree:
//
//   - cmd/observer/update_vendorsig.go, which verifies an artifact
//     signature on a node against a key compiled into the agent
//     (internal/update/vendorkey.go). This tool produces exactly the
//     bytes that verifier consumes: the RAW 64-byte Ed25519 signature
//     over the whole archive, written to a sibling `<archive>.sig`.
//     A container format (minisign, a cosign bundle) would be a
//     producer/verifier mismatch, because nothing unwraps one — which
//     is why neither is spellable in a manifest any more: the sig-type
//     vocabulary is exactly the set of schemes something verifies.
//   - internal/update.Verify, whose nine ordered rules judge a signed
//     manifest envelope. This tool emits an envelope of exactly that
//     shape, so `update-manifest-<channel>.json` is a first-class
//     object an org server can consume instead of scraping asset names.
//
// It lives under scripts/ because it runs in
// .github/workflows/npm-release.yml and nowhere else: no shipped binary
// imports it, and it must not import internal/orgserver (which is
// stripped from the public tree, so a scripts/ tool that depended on it
// would not build there).
//
// Verbs:
//
//	vendorsign keygen  -out DIR
//	vendorsign sign    -key FILE ARCHIVE...
//	vendorsign manifest -key FILE -dir DIR -version vX.Y.Z -channel stable -out FILE
//
// The private key is a base64 32-byte Ed25519 seed on one line, held in
// the OBSERVER_VENDOR_SIGNING_KEY repository secret on the private
// origin. It is never in this tree, and every verb that needs it fails
// loudly rather than signing with anything improvised.
package main
