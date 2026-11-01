# testdata/dimcode — DimCode fixtures

**Captured**: 2026-10-21, dimcode 0.5.21, one real session each on WSL Ubuntu
(`sess_1792562933471_0gxgbenesl7a`, `poolside/laguna-s-2.1:free` via OpenRouter)
and Windows 11 (`sess_1792562920436_15k4s9hq3ynj`,
`dots-studio/dots-3-note-preview:free` via OpenRouter). Both ran the same
prompt: create a hello-world Python file, run it, edit it, run it, delete it,
check the folder.

Operator reference: [`docs/dimcode-adapter.md`](../../docs/dimcode-adapter.md).

| File | What it is | Use in tests |
|---|---|---|
| `schema.sql` | Genuine `CREATE TABLE` DDL (zero data) of the six tables the adapter reads: `sessions`, `session_states`, `session_relations`, `messages`, `usage_ledger`, `usage_run_stats`. | Loaded first into a temp SQLite. |
| `fixture-wsl.sql` | Real rows from the WSL store, anonymized. | `TestLiveWSLCapture` |
| `fixture-win.sql` | Real rows from the Windows store, anonymized. | `TestLiveWindowsCapture` |
| `fixture-probe-wsl.sql` | Real rows from the 2026-10-21 hook-probe sessions (WSL), anonymized: a LIVE sub-agent pair (parent `sess_...` + its own `subagent_...` session, `session_relations` row, `__subagentOrigin` settings), a `run_terminal` provider 404, a hook-blocked prompt (`SESSION_RUN_ABORTED`), a `runtime_continuation` recovery row, a `background_task_notification` row. Provider response bodies / debug details / account ids were dropped; paths and the project folder neutralized. | `TestHarnessRowsAreNotUserPrompts`, `TestSubagentSession`, `TestPermissionModeAndBranch`, `TestReadTranscript` |
| `fixture-probe-win.sql` | Real rows from the Windows hook-probe sessions: a multi-step exec run with a `runtime_continuation` row, and a hook-blocked prompt. | `TestLiveWindowsProbe` |
| `fixture-synthetic.sql` | **Hand-written** rows; every id/path/prompt invented. Shapes from the live captures and the vendor code. | Parallel tool calls, failure/exit-code results, pending calls, `agent` spawn, sub-agent + branch `session_relations`, cache-write netting, `exact` cost quality, orphan ledger mirror, `reasoningEffort`. |

Built into a temp SQLite per test run; no `.sqlite` binary is tracked (the
tree-wide `*.db`-style ignore is deliberate and the fixtures stay reviewable as
SQL).

## Anonymization

Real fixtures: `/home/marmu` → `/home/user`, `C:\Users\marmu` →
`C:\Users\user`, the project folder names → `project`, the owner column of the
`ls -la` tool output → `user`. Nothing else was altered; message text is the
benign hello-world transcript. Session/run/message ids and the OpenRouter model
ids are kept (they carry no personal data and the tests pin them).

Never present in any fixture (grep-proved when the fixtures were cut: `marmu`,
`santosh`, `Bearer`, `sk-` followed by a key body, `api_key`/`api-key`,
`password`, `secret`, e-mail `@` addresses, URLs): the `providers` table,
`providers.json`, `auth.json`, any credential, any process environment or
env-var name list.

## Live facts the fixtures pin

* The usage JSON keys are `promptTokens`, `completionTokens`, `totalTokens`,
  `cacheReadTokens` (+ optional `cacheWriteTokens`), with a nested `lastCall` on
  the run mirror. `totalTokens` = prompt + completion (cache is NOT added), so
  the prompt is GROSS: WSL run 147551 − 41504 cached = 106047 net input;
  Windows run 55911 − 35840 = 20071.
* A `plugin_ledger_<uuid>` ledger row (session-title generation, 138/100 and
  129/100 tokens live) is a separate billable call that `usage_run_stats` does
  not include.
* `tool_result` messages carry `runId` in `toolMetadata`, not `metadata`.
* `exec` results carry `structuredContent.{exitCode,wallTimeMs}`; a tool call
  can sit unanswered for the whole human-approval wait.
