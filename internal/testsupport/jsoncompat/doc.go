// Package jsoncompat is the shared harness behind the Go 1.27 JSON
// differential tests of the AI tool hook decode paths (lane GO127, joint
// roadmap piece F0-1; security pillar plan section 8.4, risk T17).
//
// Go 1.27 backs encoding/json with the v2 implementation. The v1 API is
// meant to keep v1 behaviour, but a hook payload that suddenly decoded
// differently would change what the guard sees, and one that failed to
// decode would fail closed under enforcement. The harness pins every hook
// decode entry point against the decoder Go 1.26 shipped:
//
//   - Payloads loads the real payloads kept under testdata/ (the guard
//     conformance fixtures, the Cursor hooks-log INPUT blocks and the Cline
//     CLI hooks.jsonl sample).
//   - Variants rewrites one payload at the byte level into the shapes the
//     v2 defaults treat differently: unknown members, field-name case and
//     Unicode case folding, duplicate names, null versus missing, type
//     mismatches, number edge cases, invalid UTF-8, lone surrogates,
//     escaped names, a byte-order mark, truncation and trailing data.
//   - Dump renders whatever a decoder returned as deterministic text.
//   - Check hashes the dumps per decoder and payload and compares them with
//     a golden file that was written by a build using the v1 decoder
//     (GOEXPERIMENT=nojsonv2). A mismatch under the default build is a
//     behaviour change of the toolchain: make the decode path tolerant,
//     never regenerate the golden file from the new decoder.
//
// TEST SUPPORT ONLY: no production command or package may import it
// (tests/invariant/vendormock_boundary_test.go).
package jsoncompat
