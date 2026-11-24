// Package availcompose is the control plane's availability envelope composer
// (managed-SaaS plan 07 M6.3; design
// docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 4.5;
// ledger STAFF-8). It turns the staff-authored availability inputs
// (cloud table availability_inputs: one row per section and key) into the
// signed body of the platform availability envelope,
// platformcontract.AvailabilityBody (sbo-availability-v1), and says what
// changes against the envelope last issued.
//
// It is the ONE owner of the input rules:
//
//   - [ValidateInput] is what the staff API runs at PUT (and the store again
//     before it writes): the value decodes into its section's shape with no
//     unknown field, the section's key rules hold (an org_controls key is an
//     org UUID or "platform", and the value's org equals it, "*" for
//     platform; org ids in a named list are canonical UUIDs), and the row,
//     put alone into a body, passes the body's own rules
//     (AvailabilityBody.Validate) and the catalog's
//     (components.CheckEnvelope). An input the composer cannot carry is
//     refused before it is stored.
//   - [Compose] builds the next body from every input, sorted, with each
//     row's reason and author, and validates the whole body the way the
//     document signer and every host will. An input that no longer composes
//     (a row stored before validation existed, or a component this build
//     no longer knows) is a [Problem], and no body is produced.
//   - [Digest] binds an issue request to the exact inputs a staff member
//     previewed; [Diff] is the preview's change list.
//   - [OrgComponents], [Offered] and [Toggle] are the per-org component
//     control (lane SR-17, first row org.security): whether a body offers a
//     component to one org (the host's own components.EvaluateAvailability)
//     and the components input that turns it on or off for that org. Every
//     decision is a rule table walked top down.
//
// Purity: no SQL, HTTP, signer or clock of its own (imports_test.go): the
// store reads the inputs, the worker signs, the caller passes the time.
package availcompose
