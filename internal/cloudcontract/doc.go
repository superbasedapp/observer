// Package cloudcontract holds the versioned, plane-neutral wire and result
// schemas for the Signed-in Free cloud-intelligence spine (arc 2, CI-P1 —
// docs/plans/cloud-intelligence-azure-foundry-plan-of-record-2026-08-30.md
// §6, and the telemetry plan §6 / amendment §4.1+§5.4). It defines:
//
//   - the session-evidence envelope ("session-evidence.v1-candidate") that a
//     node builds locally and uploads for a single enrichment job;
//   - the enrichment result ("session_enrichment.v2-candidate") a Luna call
//     returns and the node stores;
//   - the seven consent purposes (amendment §4.1) and the preview field-class
//     labels (§5.2) as a typed vocabulary;
//   - the size/count limits every bounded field is validated against;
//   - the two-digest protocol (Sol SC1): a non-self-referential
//     evidence-content digest over a defined canonical preimage, and an
//     upload digest over the final exact serialized bytes.
//
// Purity discipline (Sol SB7, CLAUDE.md §1): this package is stdlib-only,
// PLUS internal/dataauthority (itself pure) for the authority classification
// type carried on the envelope. NO database/sql, net/http, os, io/fs,
// fsnotify, or any store/config/server package — pinned by imports_test.go.
// It owns schema shape, validation, and the digest DEFINITIONS; the pure
// builder (internal/cloudevidence) owns the one serializer that produces both
// the literal preview and the upload bytes.
//
// The schemas are ".v#-candidate": versioned and MUTABLE pre-launch (plan
// §4(a)); they FREEZE at A0-exit before any beta account sees the wire. Types
// are written plane-neutral (no personal-only field names) so a later shared
// kernel can adopt them (plan §4(f)).
package cloudcontract
