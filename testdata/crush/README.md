# testdata/crush

Live-capture reference for the Charm **Crush** adapter
(`internal/adapter/crush`). Crush stores each project's sessions in a
per-project SQLite DB at `<project>/.crush/crush.db` — there is no central
session directory — so these fixtures are anonymized JSON dumps of real
`crush.db` stores rather than committed `.db` files.

The adapter's own tests build tiny synthetic `crush.db` files in-process via
the `newCrushDB` helper in `adapter_test.go` (mirroring the kilocode /
opencode approach); this directory is the human-readable ground-truth
reference those fixtures were modelled on.

## Files

| File | Contents |
|------|----------|
| `_capture.json` | Three anonymized live captures (2026-07-09, WSL Ubuntu 24.04 + Windows 11). Absolute paths and free-text scrubbed; **token/cost numbers preserved verbatim**. |

### `_capture.json` sections

- **`wsl_oneshot`** — a WSL one-shot "create hello.txt then run a command"
  session. Assistant `gpt-5.4` (`openai`). Exercises `ls` / `write` /
  `bash` tool_call parts + paired `tool_result` messages.
- **`windows_oneshot`** — the Windows-side equivalent
  (`gpt-5.4-mini`/`openai`), tokens `8975/5`, cost `0.08627345`. Includes a
  `reasoning` part with real chain-of-thought text and a
  `bash → "dir: command not found" → retry` failure/recovery shape.
- **`windows_failover`** — a multi-provider **failover** session: the first
  assistant message is `us.anthropic.claude-sonnet-4-6` (`bedrock`), the
  second is `gpt-5.4-mini` (`openai`). Pins the "newest assistant message
  wins" model/provider resolution for the session-level token event.

## Schema (live, 2026-07-09)

```
sessions(id, parent_session_id, title, message_count,
         prompt_tokens, completion_tokens, cost REAL,
         updated_at, created_at, summary_message_id, todos)
messages(id, session_id, role, parts TEXT,        -- JSON array
         model, created_at, updated_at, finished_at,
         provider, is_summary_message)
files(...)  read_files(...)  goose_db_version(...)
```

### Gotchas encoded in these fixtures

1. **Timestamps are Unix SECONDS**, not milliseconds — the column comments
   say milliseconds, but the `update_*_updated_at` triggers write
   `strftime('%s','now')` (seconds), and every captured value is ~`1.78e9`.
2. **Cost is session-CUMULATIVE; the token counters are NOT.** Both live
   on the `sessions` row, not per message. Crush is the only wave tool
   that persists its own pre-computed dollar `cost` (`Cost += cost` every
   step), but `prompt_tokens` / `completion_tokens` are OVERWRITTEN each
   step with that step's (input + cache-read) and output - the TUI's
   context-window figure. The adapter reports them only for a one-step
   session (corrected 2026-09-27 against crush v0.83.0 + v0.96.1 source;
   the `windows_failover` capture is a two-step session whose counters are the second
   step alone).
3. **`tool_call` and `tool_result` live in separate messages** — the
   `tool_call` in an `assistant` message, the `tool_result` in a following
   `role="tool"` message, paired by the tool-call `id`.
4. **`parts` block types:** `text`, `reasoning` (`data.thinking`),
   `tool_call` (`data.{id,name,input}` where `input` is a JSON *string*),
   `tool_result` (`data.{tool_call_id,content,is_error,metadata}`),
   `finish` (`data.{reason,time}`).
