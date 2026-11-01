// Package sandboxremote is the pure core of the hosted sandbox rows (sandbox
// plan v2 section 13 P7, sections 5.5, 5.7, 7.1 and 7.2; lane SBX-P7): the
// decisions every remote driver shares, so the E2B, Modal and Vercel Sandbox
// drivers differ only in their wire client.
//
// It holds:
//
//   - the per-vendor table (vendors.go): endpoints, credential names, the
//     egress tiers each vendor can express and how, region model, lifetime
//     caps, memory-image policy, the PTY and relay paths, and a dated price
//     table used only for labelled estimates;
//   - the upload manifest (manifest.go): what leaves the machine, never the
//     home directory, never outside the workspace root, credential-shaped
//     files excluded and listed;
//   - the consent record (consent.go) and its invalidation;
//   - the spend ledger (ledger.go): box-minutes per provider per day and the
//     vendor timeout every create sets;
//   - the teardown state machine (teardown.go), including a create whose
//     response was lost, and the leftover-box view;
//   - credential binding to an endpoint identity (credential.go,
//     SBX-GOV-4) and redaction;
//   - the checkpoint transcript pull plan (pullplan.go).
//
// The package is pure: no network, no SQL, no process, no file I/O
// (imports_test.go pins it). The wire clients live in the subpackages e2b,
// modal and vercel (the only packages that talk to a vendor); the cmd layer
// composes them.
package sandboxremote
