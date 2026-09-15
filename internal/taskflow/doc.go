// Package taskflow decodes per-session task/todo/plan checklist calls
// (claude-code TaskCreate/TaskUpdate/TodoWrite, codex update_plan,
// opencode/kilo-code-cli/zcode todowrite, gemini-cli write_todos,
// copilot manage_todo_list, freebuff write_todos, poolside todo_action,
// kiro-cli todo_list, droid TodoWrite, hermes todo, …) into a normalized
// item/transition model, and attributes token/action activity to the
// task that was open at the time.
//
// Scope and provenance: this package is the Phase-1 build against
// docs/audits/task-tracking-capture-audit-2026-09-07.md (round-2
// reviewed). It is pure logic — no database/sql, net/http, or
// fsnotify (pinned by imports_test.go) — mirroring internal/predict
// and internal/cachetrack: I/O is injected at the store seam
// (internal/store/taskflow.go).
//
// Three shape families (the decoder table's Kind discriminator, per
// CLAUDE.md §3 "branch on capabilities, never on source identity"):
//
//   - Snapshot: the WHOLE list is rewritten every call (TodoWrite,
//     update_plan, opencode/kilo/zcode's todowrite, gemini write_todos,
//     freebuff write_todos, copilot manage_todo_list, droid TodoWrite).
//     Items with no vendor id are keyed by a content hash — exact-string
//     matching (Trim only, no fuzzy match) is the v1 identity rule
//     (§R2.3.4). Items WITH a vendor id (copilot, freebuff) are a rare
//     "keyed snapshot" — the same vanish/appear bookkeeping applies, but
//     no content hashing is needed.
//   - Delta: one call changes ONE (or a few) items, addressed by a
//     stable key (claude-code/cowork TaskCreate/TaskUpdate's taskId,
//     kiro-cli's index-keyed todo_list, hermes' defensive probe) or by
//     exact content text (poolside todo_action, which has no id at
//     all).
//
// A tool call whose (tool, raw_tool_name) is not registered in the
// decoder table produces no TaskEvent — an unknown shape is a silent
// no-op, never a guess (grok, deepseek, kimi-code, qoder, qwen-code,
// command-code, muse, mistral-code, and cline's task_progress parameter
// shape are all deliberately unregistered; see docs/task-tracking.md).
//
// Attribution (§R2.3.2): for each token/action row, count the tasks
// whose normalized status is in_progress at that row's timestamp.
// Exactly one → attribute to it. Zero → a per-session between_tasks
// bucket. Two or more → a per-session shared bucket (never split,
// never picked). This package computes the bucket assignment and the
// raw token/action bundles per task; converting a bundle to a dollar
// figure is the CALLER's job via the existing cost.Engine ladder
// (internal/intelligence/cost), priced at each row's own timestamp —
// this package must never import that engine (CLAUDE.md module
// boundary #1) and never sums a pre-computed estimated_cost_usd
// column, which is NULL on every claude-code/codex/cowork row.
package taskflow
