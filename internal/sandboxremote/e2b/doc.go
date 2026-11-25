// Package e2b is the E2B wire client of the hosted sandbox rows (sandbox
// plan v2 section 13 P7 R2, lane SBX-P7): E2B's REST control plane and
// envd's Connect-RPC process service and files endpoint, spoken from Go with
// net/http (no SDK). It is one of the three packages that talk to a vendor
// (an egress lane row in tests/invariant/egress_lanes_test.go) and is
// imported only by cmd/observer (tests/invariant/sandbox_remote_egress_
// test.go). Every call is grounded in E2B's public spec; the table is in
// docs/sandboxed-terminals.md ("Hosted sandboxes", E2B).
//
// It implements sandboxremote.Client and nothing more: no vendor type leaves
// the package. A credential is held only in memory for the client's life and
// never appears in an error (errors carry the vendor's status and a
// redacted body).
package e2b
