// Package openshellorg is the node's wire client for the org-hosted
// OpenShell gateway (tracker F-019, docs/plans/openshell/build/g1-design.md
// section 11.4, lane G4). It speaks the tagged OpenShell Go module's public
// generated openshellv1 service (rule W9: no vendored or regenerated code)
// to the organization's validating front, never to the gateway itself, and
// implements sandboxremote.Client so the shared hosted core drives it like
// the three vendor rows.
//
// It is the ONLY node package that imports the OpenShell SDK
// (tests/invariant/openshell_boundary_test.go, sandbox_remote_egress_test.go).
// The facts it holds:
//
//   - every call carries a short-lived run token from a
//     sandboxremote.CredentialSource (the org server mints it; this package
//     never sees a grant handle or an agent key), sent only over TLS to the
//     org-published front URL, with the front's certificate pinned when the
//     org publishes a pin;
//   - every mutating RPC carries an RFC 4122 version 4 request id minted by
//     the core's one helper (openshellorg.RandomRequestUUID): the 0.1.6
//     gateway refuses any other shape (OB-079). The front replaces a
//     create's id with its own deterministic one, so a retried create is at
//     most once without a node-side seeded id (lane RC1);
//   - a create carries no driver config and no template content: the front
//     creates the spec the org compiled at mint, and the 0.1.6 gateway ignores
//     a caller's driver config anyway (OB-077);
//   - an interactive stream with the TTY off is flow-controlled: the gateway's
//     supervisor ends an exec whose client outruns its bounded stdin buffer
//     ("process stdin buffer is full; terminating exec", exit 74), so stdin is
//     sent in bounded frames, never more than a window ahead of the credit the
//     box reports (the in-box paced-stdin wrapper's acknowledgement lines);
//   - one-shot stdin (ExecSandbox) is bounded by MaxOneShotStdin, and its
//     credit is the exec's own exit: one part in flight at a time;
//   - exit codes come back exact; a cut stream ends the in-box process, so
//     nothing here assumes a process survives a dropped stream.
package openshellorg
