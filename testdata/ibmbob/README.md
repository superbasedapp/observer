# testdata/ibmbob — IBM Bob Shell fixtures

**Grounded**: 2026-10-21 against bobshell 2.0.6 on two live installs (WSL
Ubuntu `~/.bob/db/bob.db` and Windows `%USERPROFILE%\.bob\db\bob.db`), one
real operator session each.

**Anonymisation**: `real.sql` holds REAL rows from the 2026-10-21 hook-probe
sessions with ids re-minted (sha256), workspace and user names replaced and the
15 KB system prompt / long vendor mode text elided; `fixture.sql` is hand-written
synthetic (shapes only) for what no live session has produced.

| File | Purpose |
|------|---------|
| `schema.sql` | The genuine `.schema` DDL for the two tables the adapter reads (`tasks`, `messages`), zero data. |
| `real.sql` | Five real tasks (WSL: a write/edit/run/todo session and a `/compact` session; Windows: a write/edit/run/todo session and two hook-blocked-prompt tasks with `last_error` and no messages). Covers `approval_config`, `env.modeId`, `_meta.spend`/`changes`/`todos`/`pid`, `stop`, the compaction summary and `UserPromptHookError`. Built into its own store by the tests (`schema.sql` + `real.sql`). |
| `logs/shell/bob-shell-*.log` | Two shell logs in the live NDJSON shape: the Windows sign-in sequence (`Logged out`, SSO flow, `Login successful` with the e-mail replaced by `user@example.com`, then a restored session) and a later restore-only launch. Paths anonymized, gateway lines kept for shape. `account_test.go` copies them beside a store built from `real.sql`. |
| `fixture.sql` | Hand-written synthetic rows whose SHAPES (env keys, message data keys, `toolCalls` / `toolUsage` envelopes, `_meta` fields, epoch-ms timestamps, the shared per-turn `messages.created_at`, the empty launch placeholder task) match the live captures. Every id, path, prompt and output is invented. |

`internal/adapter/ibmbob/adapter_test.go` builds a temp SQLite store from
`schema.sql` then `fixture.sql` (no `.db` binary is tracked).

## What the fixture covers

| Feature | Rows |
|---|---|
| Launch placeholder task with no messages (emits nothing) | task `f000...0001` |
| system prompt (not emitted) | `1000...0001` |
| user prompt with `envContext` + `availableTools` | `1000...0002` |
| `update_todo_list` call + result with `_meta.todos` | `1000...0003/4` |
| `write_file` call + result | `1000...0005/6` |
| `execute_command` failing via `_meta.exitCode: 1` | `1000...0007/8` |
| `search_and_replace` failing via `signature.isError: true` | `1000...0009/10` |
| assistant text + two tool calls in one message (`spawn_subagent`, `mcp__docs__lookup`); spawn result carries `_meta.subagentId` | `1000...0011/12/13` |
| final assistant text with `stop: true` | `1000...0014` |
| `_meta.notAi` harness notice (becomes `notification`) | `1000...0015` |
| subagent child task (`task_type subagent`, `parent_id`) with `read_file` | task `c0ffee...01` |
| Windows-shaped task: `C:\` workspace, `env.model` as a bare string, a `_meta.hide` replay user message (skipped), array-form user content with an image part | task `b7e1...8e9f` |

Live-only (not in the fixture): `_meta.spend` values are copied in shape
only; the real per-call `contextTokens` / Bobcoin `cost` numbers are in
`docs/ibmbob-adapter.md`.

## Synthetic rows that remain, and why

Shapes no live session has produced stay synthetic in `fixture.sql`: a failing
`execute_command` (exit code 1) and `isError` result, `spawn_subagent` +
`mcp__` calls, the `_meta.subagentId` result, the subagent child task, the
`_meta.hide` replay, a bare-string `env.model`, an array-form image part and
a non-compaction `notAi` notice. Reasoning, message-level `images`,
`tasks.version`, `tasks.git_branch` and non-hook `last_error` are exercised by
in-test inserts (`features_test.go`).
