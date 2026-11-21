// Package promptreg is the one owner of the prompt registry's rules (Plane A
// build-out W3-3, lane B8; contract
// docs/plans/plane-a-sdk-buildout/contracts/prompts.md; ruling D10: a
// registry with labels, fetch/cache and a span stamp, no playground).
//
// It is PURE: no database/sql, no net/http, no fsnotify, no internal/obs
// (imports_test.go). The registry has two store seams that both call it:
//
//   - the org store, internal/orgserver/promptstore, behind the SDK control
//     API's GET /v1/sdk/prompts/{name} and the admin routes
//     /api/org/obs/prompts/*;
//   - the machine store, internal/obs/store/prompts.go, behind the node
//     dashboard's /api/obs/prompts/* and the local SDK fetch
//     /api/obs/sdk/prompts/*.
//
// What lives here, once:
//
//   - the vocabulary: names (ValidName), the two labels (Labels), the two
//     prompt types;
//   - a create request's validation and canonical form (ParseDraft,
//     NewVersion): a version is immutable once built;
//   - label moves and rollback (PlanMove, PlanRollback) over the label's
//     history, so a rollback is a recorded relabel;
//   - resolution by label or version (ParseSelector, Resolve);
//   - variables and compile ({{name}} placeholders, Variables, Compile);
//   - the exact fetch and list response bytes, the content digest and the
//     ETag (Fetch, List, ETagMatches), so the org and the machine answer
//     byte for byte the same shape;
//   - the error vocabulary and its HTTP status and code (ErrorStatus);
//   - W5-3 (lane C8, contract section 9): staged rollout (PlanRollout,
//     ResolveServed, the cohort key and salt; the split itself is
//     rolloutcore's engine, injected as a CohortFunc because this package
//     imports nothing from the repository), the version diff (Diff,
//     DiffText) and production approval (NeedsApproval's rule table,
//     NewProposal, PlanApprove, PlanReject).
//
// A store loads the state it needs, calls a plan function, and writes what
// the plan returns.
package promptreg
