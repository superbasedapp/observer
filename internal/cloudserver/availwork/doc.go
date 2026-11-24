// Package availwork is the worker side of the platform availability envelope
// (managed-SaaS plan 07 M6.3; design
// docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 4.5; ledger
// STAFF-8; lane fix/sr-17-staff-control). Two loops, both run by
// `observer-cloud worker` when its host-API client is on and the document
// signer publishes an availability key:
//
//   - the [Issuer] carries out a staff issue request (cloud 0154, written by
//     the staff console's "Issue" step): it reads the availability inputs,
//     refuses the request as stale when they are no longer the inputs the
//     staff member previewed (availcompose.Digest) or when another envelope
//     was issued since (base_version), composes the body
//     (availcompose.Compose), has the document signer sign it at the next
//     version (max(stored, floor) + 1, and never below the current Unix
//     second, as entitlementwork does), verifies the signed envelope as a
//     host will (platformcontract.VerifyAvailability under the keys hosts
//     verify under: the compiled-in keys when the build has any, else the
//     signer's published availability keys; the body's rules and the
//     catalog's), and stores it with the request's outcome in one
//     transaction;
//   - the [Deliverer] pushes the newest envelope to every host of the hosts
//     file (hostapi.AvailabilityPush over the host-API sender) until the
//     host answers, verified, that it holds that version or a newer one, and
//     records each host's state (availability_deliveries). That answer
//     stands for six hours ([DefaultConfirmAfter]); then the envelope is
//     sent again, so a host restored from a backup or rebuilt under the same
//     id gets it back (a host that still holds it answers Applied=false and
//     nothing changes). A host that refuses a version is not sent that
//     version again for an hour; a newer envelope is sent at once.
//
// Explicit issue, not auto-issue: an envelope reaches every org on every
// host, so a person reviews its diff, gives a reason and verifies a passkey
// before it is signed; the request records who and why.
//
// No SQL, HTTP or key here: the store, the signer, the transport and the
// clock are injected (imports_test.go pins it).
package availwork
