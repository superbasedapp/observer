// Package lkgsidecar is the node-local last-known-good materialization of the
// node.features tools.disallow list (P7 gateway-arc / tracker P5b→P6 item 5).
//
// The daemon holds the live node.features policy in memory
// (cmd/observer's nodeFeaturesHandle), but a BARE CLI launcher
// (`observer claude`, `observer codex`, `observer gemini`, …) and
// `observer adapters` run as SHORT-LIVED processes that never touch that
// in-memory handle. This file is how they see the live disallow state: the
// daemon writes the resolved disallow list here beside the DB, and the
// short-lived reader loads it with a fail-open failure table.
//
// It mirrors internal/govern/sidecar (the governance posture materialization)
// deliberately — same closed-decoder, same MaxBytes latency guard, same
// never-error/never-stderr Read contract, same grant-expiry offboarding
// guarantee — but is a SEPARATE package so internal/policyfam/nodefeatures
// stays a pure compiler/decision package (no os/file I/O; imports_test-pinned).
package lkgsidecar
