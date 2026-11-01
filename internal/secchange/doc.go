// Package secchange is the pure core of the signed AI change record per
// commit (security pillar plan section 7.10, ruling Q8; component
// security.provenance; lane SEC-F2A).
//
// A change record is a statement a node makes about one commit: which
// sessions, agents, models and tool versions its attribution ties to the
// commit, the AI, human and unknown line split, the guard, taint, scanner
// and finding summary, and the exceptions in force. It is labelled
// everywhere as node-reported attribution: a signed claim by a device that
// a same-user or privileged developer could fabricate, never proof of
// authorship or of causation. Prompt text never enters it.
//
// What this package owns, all over data:
//
//   - Record, the v1 payload, and Canonical, its canonical JSON (sorted
//     keys, no insignificant whitespace, no HTML escaping). A payload that
//     is not byte-identical to its own canonical form is refused, so a
//     record has exactly one encoding.
//   - The DSSE envelope with payload type PayloadType, signed over DSSE's
//     pre-authentication encoding (PAE). The domain string Domain is a
//     required field of the payload, so the signature is domain-separated
//     while the envelope stays standard DSSE.
//   - Ed25519 signing and verification; KeyID is the first 16 bytes of the
//     SHA-256 of the public key, in hex.
//   - The binding: commit, tree, patch fingerprint
//     (internal/commitlog.PatchFingerprint), org, org project, machine
//     identity, project hash and policy version, and CheckBinding, the
//     ordered table that says whether a record speaks for a presented
//     commit exactly, through its patch (a rebase), or not at all.
//   - The replay, amend, rebase and squash rule tables, the 90-day and
//     re-enrolment rotation schedule, and the key certificate and
//     revocation checks of a TrustSet (a keys file named by the verifier,
//     never read from the repository under test).
//
// No I/O: the package imports no os, os/exec, net, database/sql or
// fsnotify (imports_test.go). The cmd layer generates and stores keys
// (internal/keystore), builds records from node attribution and writes
// them (internal/store/secchange.go, internal/secsvc).
package secchange
