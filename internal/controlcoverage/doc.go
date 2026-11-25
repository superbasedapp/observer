// Package controlcoverage joins Observer's two independent, deliberately
// separate control-plane classifiers into ONE per-tool row:
//
//   - internal/integration's EnforcementChannel() ladder — can a dangerous
//     TOOL CALL be stopped? — and its sibling BudgetAdmissionChannel() —
//     can an Observer-managed spend cap be enforced pre-request?
//   - internal/guard's ConformanceMatrix() — can the developer's PROMPT be
//     blocked/asked-about before it ever reaches the model?
//
// internal/integration imports neither internal/guard nor internal/policy;
// internal/guard reads the registry's hook bindings to GENERATE its
// conformance matrix (hook-parity Lane 0 step 5) but keeps its own
// enforcement vocabulary. This package is the one place that joins the two
// classifiers' answers, so each stays independently pure while still
// answering the combined question an operator or org admin
// actually asks: "what, if anything, controls this developer's use of this
// tool?"
//
// Pure join: no SQL/HTTP/fsnotify (both source packages are pure data
// packages themselves — see their own package docs). See
// docs/plans/adapter-coverage-parity-plan-2026-06-26.md §16 and the
// 2026-09-22 control-coverage investigation
// (~/sbo-scratch/s8/items/controls/ISSUE.md + PLAN.md) for the grounding.
package controlcoverage
