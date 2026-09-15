// Package orgbudget is the PURE composition layer between a node's own
// [guard.budget] thresholds and the ORGANIZATION's per-caller budget body
// (docs/plans/org-budget-enforcement-and-token-display-plan-2026-09-07.md
// §3.3c, wave W3b).
//
// It answers exactly one question and returns two plain values:
//
//	Compose(local, orgBody, caps) -> (effective Thresholds, Posture)
//
// Discipline (CLAUDE.md #1 / spec §24.1): NO SQL, NO HTTP, NO fsnotify, NO
// os/exec, and no import of internal/store, internal/guard, internal/policy or
// internal/config. Everything arrives as values; imports_test.go pins that.
// The only observer packages it may import are internal/orgcontract (the wire
// shape both ends already share) and internal/govern (the numeric
// lowering primitives LowerFloat / LowerInt, which own the "0 means unset"
// algebra so it is not re-derived here).
//
// CAPABILITY-BRANCHED, NEVER SOURCE-BRANCHED (CLAUDE.md #3). Compose never
// asks "did this come from an org?" — it asks whether the caller resolved two
// capabilities at the boundary:
//
//   - FromOrg: the node opted in ([guard.budget].from_org, itself pinnable
//     through node governance). Off is the default and is byte-identical to a
//     build without this feature.
//   - OrgAuthoritative: the node is MANAGED and its grant carries
//     govern.AuthorityEnforceBudget (govern.Effective.GrantsBudgetEnforcement).
//     With it the org's numbers and enforcement mode REPLACE the local ones;
//     without it they may only LOWER them.
//
// PERIOD MAPPING IS A TABLE, NOT A LADDER (CLAUDE.md #5). The org authors caps
// per PERIOD (rolling_30d / calendar_day / calendar_month); the node enforces
// per WINDOW (session / daily / weekly / monthly). The mapping lives in one
// ordered table with one row per period, INCLUDING the periods that map to no
// window — present with the reason, never silently absent:
//
//	calendar_day   -> daily
//	calendar_month -> monthly
//	rolling_30d    -> (none: the node has no 30-day window, and ruling R7
//	                   makes rolling_30d report-only anyway)
//
// The node's session and weekly windows are never org-sourced: the org's
// vocabulary has no period that means either one, and inventing a mapping
// would enforce a cap the org did not author.
package orgbudget
