# Kimchi adapter fixtures

Fixtures for `internal/adapter/kimchi/`. Kimchi (Cast AI, `kimchi` 1.17.0)
writes one append-only pi-mono v3 JSONL transcript per session at
`~/.config/kimchi/harness/sessions/--<cwd-slug>--/<ISO-ts>_<uuid>.jsonl` on
Linux, macOS and native Windows alike. Operator reference + Phase-0
findings: `docs/kimchi-adapter.md`.

## Inventory

| File | Lines | Origin | What it exercises |
|---|---|---|---|
| `session-wsl.jsonl` | 70 | LIVE, WSL2 Ubuntu, 2026-10-21 (`kimchi --session 01a15d30-…`) | Three exhausted-credit `kimchi-dev` turns (`stopReason:"error"`, all-zero usage → `api_error`, no token row), then a `openai-codex/gpt-5.6-luna` run with `reasoning` in every usage envelope; `thinking_level_change` `off`; tools create_todos / write / bash / mark_todo / read / edit. |
| `session-windows.jsonl` | 74 | LIVE, Windows 11, 2026-10-21 (`kimchi --session 01a15d31-…`) | `C:\…` cwd; thinking level `medium`; bash failures (exit 49 twice, exit 127 → `isError:true`); `powershell` and `clear_todos`; 12 usage-bearing calls. |
| `session-agent-parent-wsl.jsonl` | 20 | LIVE, WSL2 Ubuntu, 2026-10-21 (hook probe) | The parent of a real sub-agent run: `Agent` tool call + toolResult `details` (`agentId`, `sessionFile`), `custom:subagents:record`, `permission_mode`, a `resume_subagent` call (unmapped), `prompt-summary`. |
| `session-agent-child-wsl.jsonl` | 8 | LIVE, same run | The spawned agent's own file: header `parentSession` + `custom:kimchi:subagent-session {type:"General-Purpose"}`; its two turns are provider errors (`minimal` thinking unsupported on the model) so no usage rows. |

The live files are the operator's own sessions with only these edits (the two agent fixtures additionally keep `custom:subagents:record`, drop `context_assembly`, `work_identity`, `trace_ids` and the other telemetry kinds):

- the operator's username → `user` everywhere (paths, slugs, tool output); one Windows
  `where python` line's third-party venv path shortened.
- Dropped: every `thinkingSignature` (carries an `encrypted_content`
  reasoning blob) and the `traceId` / `requestId` / `handle` keys.
- Dropped whole entries: `custom` kinds `context_assembly`,
  `behaviour_loaded`, `behaviour_session_summary`, `work_identity`,
  `trace_ids`, `request_diagnostics`, `kimchi_error_classification`,
  `pr-cost-reporting-notice`, `multi_model_enabled`,
  `auto-update-notice`, and `custom_message:todo-state`. Kept on purpose: `custom:permission_mode` (restored 2026-10-21 from the
  live originals, one before the first user prompt), `custom:llm_response_debug` (repeats each call's usage — the parser must
  ignore it), `custom:cache_summary` (the vendor's running cumulative —
  the tests assert the parsed rows reproduce its final value exactly),
  `custom:turn_duration`, `custom:agent_end`, `session_info`, and one
  `custom_message:behaviour`.
- Every string longer than 400 characters truncated with `...`.

Every `message` entry is otherwise byte-for-byte what kimchi wrote, so
token counts, ids and timestamps are live values.

Both files use LF line endings; the CRLF case is synthesised in
`crlf_test.go`.

## Never copy into this directory

`~/.config/kimchi/config.json` (Kimchi `apiKey`, `deviceId`),
`harness/auth.json`, `harness/models.json` (per-provider `apiKey` beside
the `baseUrl`), `org-policy.json`, `harness/work-attribution/**` and any
`image-cache/` content.
