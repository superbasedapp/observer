// Package mcpaccess is the PURE Agent Access grant model and its four policy
// compilers (docs/plans/agent-access-implementation-plan-2026-09-23.md §11.4
// W2b; rulings R6, R8.1, R8.23.c/i, R8.30.g, R14.11 in
// docs/plans/agent-access-research/ARCH-BRIEF-ADDENDUM-R1.md).
//
// One input - a Spec (the mcp_grant rows plus the registry view they name) -
// compiles to four targets that MUST return the same verdict on every
// conformance-corpus row:
//
//   - CompileCEL: the agentgateway mcpAuthorization rule list. Every rule is a
//     TYPED {require}/{allow}/{deny} object, never a bare string (a bare string
//     deserializes as an ALLOW, crates/agentgateway/src/http/authorization.rs
//     RuleSerde::PlainString). The list is a positive allowlist + require
//     invariants over MINTED claims + a deny-all sentinel `{allow: 'false'}`,
//     because agentgateway's RBAC (authorization.rs:254-274) treats an empty
//     rule set AND a deny-only rule set as ALLOW-ALL - the sentinel makes an
//     empty/invalid/stale policy default-DENY. Deny grants are POSITIVE
//     predicates in the deny list, never a negated allow.
//   - CompileNodeTable: the ordered decision table the P4 node relay walks
//     top-down, first match wins (rows are ordered by effect precedence deny >
//     ask > allow, then hierarchy level, then ord).
//   - CompileAuthZEN: an AuthZEN-shaped evaluation function (subject / resource /
//     action / context -> decision) that collects EVERY matching grant and then
//     resolves by precedence.
//   - CompileFastPath: the PDP index keyed (vserver, action, name) with a
//     per-subject-class filter, for the ext_mcp hot path.
//
// The three PDP-side targets are deliberately different evaluation strategies
// over the same normalized grants; the CEL target is evaluated with cel-go
// (cel.dev/cel-go) over the SAME corpus so a rendering mistake is caught
// before the real-binary golden (internal/mcpgw/agwadapter/compiler_boot_test.go)
// runs against the pinned agentgateway.
//
// v1 REJECTS what it cannot enforce (R8.1, doc2-B11): the `judge` effect, a
// `taint` condition, `requires_mfa` AND a grant on any of the three task
// actions are typed feature_unavailable lint ERRORS, never silently
// dropped. The task refusal is grounded in the pinned agentgateway v1.5.0:
// its mcpAuthorization CEL context carries mcp.task{target,name} and no
// request method (rbac.rs McpAuthorizationSet::validate builds
// MCPInfo::from(&ResourceType) with method_name None; session.rs routes
// tasks/get, tasks/update and tasks/cancel through ONE
// authorize_task_request), so a tasks/get-only grant would compile to a
// rule that also allows tasks/cancel - a silent widening. The three task
// actions stay in the vocabulary (a request naming them default-denies on
// every target; the A2 front dispatches them natively) until agentgateway
// exposes the method. The action set is enumerated with NO wildcard
// (R8.30.g). Product-scoped grants are honoured only at client_attestation
// process_attested / ipc_bound (R2); at configured/claimed the caller is
// node-wide and a product predicate does not match.
//
// Approved-snapshot membership (R9.8, plan §11.4 W2a drift): the registry
// view carries each member server's ACTIVE approved snapshot (Server.
// Snapshot: id + the approved exposed tool names). A snapshot-scoped grant
// (tools/call) matches a name only when the member serving it approves that
// name - in the three PDP targets through the ONE shared matcher
// (snapshotApproves) and in CEL as an explicit per-member
// `mcp.tool.target == T && mcp.tool.name in [...]` allowlist conjunct (never
// a negation). Under ALERT drift the active snapshot is unchanged, so
// previously approved KNOWN tools keep flowing while a NEWLY-named tool
// default-denies on all four targets until an admin adopts a snapshot that
// lists it; tools/list visibility follows the same set. A member with no
// active snapshot is unpinned (nothing to enforce yet). The pin is live
// registry input, not signed policy: the family's canonical body strips it,
// so adoption is picked up by the next policy reload, never by a republish.
//
// Project / team ABAC (P11(e), R10.9): two CONTEXT-GATED subject kinds.
// team matches the server-side roster claim jwt.sbo_team_ids; project
// matches the relay-attested jwt.sbo_project_hash or - for a caller with no
// attested project (a direct OAuth / API-key client) - the vserver's
// DECLARED project scope (VServer.Projects), and nothing else. When the
// trusted context is absent (no roster claim; no attested project and no
// declared scope) a team / project grant is FAIL-CLOSED on every target: an
// allow never matches, a deny or an ask always does, so withholding the
// context can never slip past a deny. The CEL target renders the same rule
// with explicit has() guards (contextGatedExpr) and the cel-go activation
// materializes the two claims only when present, exactly like a minted
// token. A token carrying jwt.sbo_team_overflow (a roster over the claim
// bound, minted without sbo_team_ids; P11 fold PF2) makes every team
// subject untrusted on all four targets - the PDP presence rule folds the
// marker in and the CEL guard adds has(jwt.sbo_team_overflow).
//
// Pure package: no database/sql, net/http or fsnotify (imports_test.go).
package mcpaccess
