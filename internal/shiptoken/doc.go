// Package shiptoken holds the pure rules of the cloud-session ship token
// (cloud-agents arc, lane CA-B3, decision CA-D8; ledger CLOUDSESS-3).
//
// A ship token is the ONE credential a vendor cloud sandbox (Rail S) holds to
// deliver its captured rows to a destination: the member's org server
// (POST /ingest/cloud-session/v1/batch) or the individual's own node
// (POST /api/cloud-session/ingest). It is opaque, random, short-lived,
// revocable and ingest-only. It is NOT an Ed25519 node bearer and is never
// accepted where one is: the enrolment, push, policy and dashboard surfaces
// all parse their own credential shapes, none of which a ship token matches.
//
// This package owns, with no I/O of its own:
//
//   - the token format (Generate / Parse / Hash): a fixed prefix plus 32
//     random bytes, stored only as a sha256 hex digest;
//   - the lifetime table (ClampLifetime);
//   - the label rule (ValidLabel);
//   - the status rule (StatusAt): active, expired or revoked;
//   - the envelope admission table (Admit): which push-envelope families a
//     ship-token batch may land and which it drops, plus the per-session
//     execution-location rule;
//   - the error codes both destinations answer with.
//
// Both destinations import it, so the org server and the node agree on every
// rule. It imports no database/sql, net/http or os (pinned by
// imports_test.go); the randomness source is injected.
package shiptoken
