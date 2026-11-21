// Package proccapture is the pure CAPTURE BUDGET of the process observability
// feature (docs/process-observability.md §11 "Capture budget", plan of record
// docs/plans/process-capture-budget-plan-2026-11-04.md).
//
// It decides, per observed process run, whether the run is stored as its own
// row, folded into its parent, tracked as part of a service the agent started,
// rolled up into a counted group, or dropped. The decision is ONE ordered rule
// table (rules.go, R1-R11) walked top-down, first match wins, one test case
// per row (CLAUDE.md rule 5). Findings and side effects (R1), failures (R2)
// and tool-call links (R3) are evaluated before any budget, so a run that
// matters can never hide inside a rollup.
//
// What lives here:
//
//   - RunFacts / Decision / BudgetState: the plain inputs and output of
//     Policy.Classify (and the package-level Classify convenience).
//   - The built-in service and fold tables (tables.go), extended by config.
//   - Lineage / Policy.Derive: the tree-derived facts (service root, seed
//     root, tool-call root and key, nearest kept ancestor) one owner computes
//     for both the live Observer and a replay of stored runs.
//   - Ledger: the per-tool-call, per-session, per-session-per-minute and
//     per-service exemplar counters the caller owns.
//   - Template / TemplateHash: argv templating (numbers, hex ids, UUIDs,
//     temp paths become placeholders) so 32,802 identical polls are one group.
//   - Accumulator / Delta: rollup groups with exact counts, failures,
//     durations, CPU and peak RSS, plus per-session capture stats and fold
//     counts, flushed with the run batch.
//   - Replay / Estimate: replay stored runs through the same rules under two
//     configs, for the Settings data-volume card and `observer process stats`.
//
// The package is PURE: no database/sql, net/http, os/exec, fsnotify, and no
// store (pinned by imports_test.go). It imports only the standard library,
// so the store, the dashboard and the capture runtime can all use it.
package proccapture
