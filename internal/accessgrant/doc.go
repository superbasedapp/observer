// Package accessgrant is the PURE core of developer requests and time-bound
// access grants (docs/plans/request-grants-design-2026-10-03.md §4.2, operator
// decisions D-080..D-095).
//
// A developer asks (a typed request); an admin approves; the approval mints a
// signed, effective-dated grant bound to the developer (member) or one of
// their machines; the node honours it until it expires, is used up, is
// revoked, or the node has been unable to re-verify it for too long.
//
// This package owns the RULES of that lifecycle so the org (the approver
// preview, the sweeper, the summary) and the node (the cache, the lookup)
// cannot drift apart - the internal/sessionmsg one-owner lesson:
//
//   - RequestTypes: the closed request-type table (approver key, where the
//     grant lands, maximum duration). Adding a type is adding a row.
//   - Validate: a developer's request.
//   - Decide: an approver's grant, returning the required approval tier
//     (key / super-admin), refusals, warnings and the widened flag.
//   - Match: which cached grant (if any) covers a guard query.
//   - Status / Honoured: the server's and the node's view of whether a grant
//     is in force at an instant.
//   - BudgetOverlay: a budget increase folded into a cap. The node's offline
//     revert at expiry (§3.3) is orgcontract.BudgetPolicyCap.RevertExpiredGrant,
//     which also clears the grant id and the base caps.
//   - ShapeContext: the one place the request context block's content keys
//     are kept or stripped.
//
// No I/O: no SQL, no HTTP, no fsnotify, no clock (every function takes now),
// no config. Pinned by imports_test.go. Wire shapes live in internal/
// orgcontract (accessgrant.go), which this package may import because it is
// itself dependency-free.
package accessgrant
