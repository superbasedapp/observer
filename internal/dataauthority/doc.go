// Package dataauthority is the pure-logic core of the P2a-2 gateway-arc
// data-authority classifier (design §5.3 item 7 —
// docs/plans/plane-b-dual-mode-gateway-rbac-ia-design-2026-08-29.md,
// "Data-authority classification export (coherence hook for the personal
// plane)"; tracker docs/plans/plane-b-gateway-implementation-tracker-2026-08-29.md).
//
// It answers one question, for one unit of node data (today: a session):
// "which plane owns this — the individual's personal cloud plane, or the
// org?" An org-enrolled node marks its data org-authority REGARDLESS of
// product posture (teams or enterprise) — the posture split governs how
// MUCH content an org receives (internal/store.ShareOptions), not whether
// the data belongs to the org at all. The personal-cloud-intelligence
// plane's own §4.2 eligibility gate is required to cite this package as
// its signal source rather than asserting a classifier of its own.
//
// Two contract properties, both load-bearing (design §5.3 item 7):
//
//   - Stable, versioned local API, not an internal flag. Schema carries a
//     Version so a future caller (the personal client, not yet built) can
//     detect a contract change instead of silently misreading a reshaped
//     result. The classification is computed synchronously, locally — the
//     node already knows its own enrolment state; no server round-trip.
//   - Sticky. Once a unit of data is classified AuthorityOrg it stays
//     AuthorityOrg forever, including after the node later de-enrols. This
//     is the safer default (data captured under an org's roof does not
//     un-become the org's because the node walked away later) and is
//     stated as a ruling, not left to be discovered by a future caller.
//     Combine (the sticky merge) is the only path that may change an
//     existing classification's Authority value; ClassifyAtCapture alone
//     never does (it has no prior state to be sticky against).
//
// Discipline mirrors internal/predict and internal/routing: NO
// database/sql, NO net/http, NO fsnotify (pinned by imports_test.go).
// Every input is a plain value the caller assembles from its own state
// (today: whether the node is currently org-enrolled) — this package owns
// only the classification and stickiness math. Nothing in the repo calls
// this package yet: the org purge path and the personal plane are later
// phases (design §5.3 item 7's own callers); this phase ships the
// contract standalone so those callers have a stable target to build
// against.
package dataauthority
