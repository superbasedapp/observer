// Package modal is the Modal wire client of the hosted sandbox rows (sandbox
// plan v2 section 13 P7 R3, lane SBX-P7). Modal declares its gRPC API
// non-public, so the client speaks it only through Modal's own Go SDK
// (github.com/modal-labs/modal-client/go v0.11.1, Apache-2.0), behind the
// sbo_omit_terminals_sandbox_modal build tag. It is one of the three
// packages that talk to a vendor (an egress lane row in
// tests/invariant/egress_lanes_test.go) and is imported only by
// cmd/observer (tests/invariant/sandbox_remote_egress_test.go). The call
// table is in docs/sandboxed-terminals.md ("Hosted sandboxes", Modal).
//
// It implements sandboxremote.Client and nothing more: no SDK type leaves
// the package (sdk.go is the only file that names one). A token is held only
// in memory for the client's life and never appears in an error.
//
// What Modal does not document, the client does not pretend: a process has
// no reattach and no terminal resize (the guest helper owns the PTY), the
// SDK has no per-process kill (Kill closes stdin; the box's terminate ends
// the rest), and a box's region is the one asked for, not one read back.
package modal
