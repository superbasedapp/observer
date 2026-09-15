// Package taskreport is the Phase-2 cost+metrics layer for session-level
// task/todo/plan checklist tracking (docs/task-tracking.md "Phase 2").
//
// It is a standalone leaf package — deliberately NOT
// internal/intelligence/dashboard, and NOT internal/taskflow (which
// internal/taskflow/imports_test.go pins free of the cost engine
// import) — so both the dashboard HTTP handlers AND the MCP
// get_session_tasks tool can import it without an import cycle
// (internal/intelligence/dashboard already imports internal/diag,
// which imports internal/mcp; internal/mcp cannot import dashboard
// back).
//
// This is the one place that prices a task's attributed tokens through
// cost.Engine.LookupAt/cost.Compute, mirroring internal/intelligence/
// dashboard/live.go's "recorded cost wins, else price at the row's own
// timestamp" rule. It never sums estimated_cost_usd directly — that
// flows through store.TaskTokenRow.RecordedCostUSD, still priced/summed
// per-row here.
//
// It reads through internal/store (internal/store/taskflow.go owns the
// task_items/task_transitions SQL) and internal/taskflow (pure decode/
// diff/attribution logic) — no SQL of its own, no HTTP, no file
// watching (pinned by imports_test.go, which allows the
// intelligence/cost import this package is built around, unlike
// internal/predict/internal/cachetrack's stricter cost-free pins).
package taskreport
