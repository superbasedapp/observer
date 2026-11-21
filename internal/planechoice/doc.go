// Package planechoice is the ONE owner of the first-run product choice
// (docs/plans/first-run-plane-choice-flow-plan-2026-11-20.md, revision 2,
// sections 2.2, 3.5 and 3.8): which getting-started track a machine shows
// (AI coding agents, AI apps and agents you build, or both), whether AI Apps
// can be offered here at all, the one consent sentence for turning AI Apps
// on, and how the outcome of turning it on reads.
//
// Every decision is a data table walked top-down, one test per row
// (CLAUDE.md #5):
//
//   - availabilityRules: the obs component's state -> apps_available and its
//     reason. The rule never reads an edition name and never reads
//     "enrolled" (review P-02); a managed edition has no AI Apps because the
//     component is absent, not because it is managed.
//   - codingRules / appsRules: the two facts, each computed from its own
//     inputs (review P-01). No row refers to another row.
//   - Rules: the four-row table mapping (coding, apps) to a track.
//   - consentRules: the two-row consent sentence builder (review P-05).
//   - enableRules: the outcome of one enable attempt, with its fix line.
//
// The package is pure: no database, no HTTP, no filesystem (imports_test).
// The daemon (cmd/observer) gathers the facts, the dashboard serves the
// result on /api/firstrun; no app keeps its own copy of the rule.
package planechoice
