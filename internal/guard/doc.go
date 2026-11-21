// Package guard is the guard layer's composition root (guard spec
// §3.1): it owns the policy.Engine instances, loads and merges the
// policy sources (built-ins + user TOML + project TOML; the org
// bundle joins in G13), owns the per-session TaintState tracker, and
// wraps evaluation in the Q2 fail-open/fail-closed contract.
//
// Guard is Plane B (docs/deployment-models.md): it governs the developer's
// own AI coding agents (their tool calls, prompts and spend). The input
// admission of the AI apps a developer builds is Plane A and lives in
// internal/obs/admission; the two are separate subsystems.
//
// Boundaries (CLAUDE.md Module rules, guard spec §17):
//
//   - internal/policy stays PURE; all I/O (reading policy files,
//     expanding the home dir) happens here, with results passed into
//     policy as plain data.
//   - This package does NOT import internal/store. Persistence flows
//     the cachetrack way: hot paths (store.Ingest, the hook handler)
//     hold a *Guard, call its evaluation seam, and persist the plain
//     results through the store's own one-owner guard.go helpers.
//   - TaintState has ONE owner: the Guard's tracker (§17.4). Policy
//     rules only ever read the snapshot stamped onto each Event.
//   - No tool-identity branching: client differences arrive as
//     policy.Capabilities resolved at each boundary; this package
//     never inspects Event.Tool (grep-pinned in internal/policy's
//     §17.3 invariant; the same discipline applies here by review).
//
// Failure posture (Q2, default fail-open): a panic inside evaluation
// is recovered at the Evaluate seam and surfaces as an allow verdict
// carrying the synthetic rule ID "guard_error", so callers both stay
// safe AND get a loud audit row. [guard] strict = true inverts the
// decision to deny for pre-execution channels that can block. A
// malformed user/project policy file degrades the same way: the
// affected layer is dropped, the issue is recorded on the Guard
// (LoadIssues) and surfaced as a guard_error event by the caller —
// the daemon never refuses to start over a policy typo.
package guard
