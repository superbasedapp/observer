# VT Code fixtures

Anonymized, trimmed copies of real VT Code 0.180.2 sessions the operator ran
on 2026-10-21 (OpenRouter provider). Used by `internal/adapter/vtcode`.

| Path | Source | Trimming |
|---|---|---|
| `wsl/demo-wsl/.vtcode/sessions/session-demo-wsl-20261021T090440Z_077281-179245/events.jsonl` | WSL Ubuntu, `~/teams-observer-test` | first three turns (two user turns + one harness `continuation` turn) + `thread.completed`; `item.updated` tool_output, permission and latency lines dropped |
| `wsl/demo-wsl/.vtcode/sessions/session-demo-wsl-20261021T071719Z_868051-135688/events.jsonl` | WSL, an earlier session whose only turn aborted (no usage) | complete |
| `wsl/demo-wsl/.vtcode/logs/trajectory.jsonl` | WSL workspace telemetry log | model-bearing records (`prompt_cache_metrics`, `history_projection_metrics`) + one of each other kind |
| `wsl/demo-wsl/.vtcode/logs/trajectory-20261021T090440Z.jsonl` | the ROTATED log holding the earlier session (`xiaomi/mimo-v2.6-pro`, request failed) | complete; `last_error` redacted |
| `win/demo-win/.vtcode/sessions/session-demo-win-20261021T090636Z_370151-33628/events.jsonl` | Windows 11, `C:\Users\<u>\sbo-stepin` | first 70 lines + `turn.failed` + `thread.completed` (policy-blocked `exec_command` calls, two `code_search` calls) |
| `win/demo-win/.vtcode/logs/trajectory.jsonl` | Windows workspace telemetry log | as above |
| `*/state/sessions/<id>.json` | the global archive (`~/.local/state/vtcode/sessions`, `%APPDATA%\vinhnx\vtcode\state\sessions`) | `metadata` + timestamps only; `messages` / `transcript` emptied |
| `*/manifest.json` | session manifests | complete |
| `wsl/demo-exec/.vtcode/sessions/session-demo-exec-20261021T121537Z_320744-339386/events.jsonl` | WSL hook-probe `vtcode exec --json` run (2026-10-21): the ThreadEvent stream VT Code printed to stdout, each line re-wrapped in the store envelope `{"schema_version":"0.18.0","event":...}` (the workspace, and so its own events.jsonl, was deleted after the probe) | complete; strings > 1500 chars cut. Carries the live `apply_patch` `{"input":"*** Begin Patch..."}` shape and 9 exec-mode phantom headers (`call_function_*`, failed/error, no output) |
| `wsl/state/sessions/session-demo-exec-20261021T121537Z_320744-339386.json` | that run's real global archive | `metadata`, `started_at`/`ended_at`, `messages` (with model `reasoning`); `transcript` emptied; strings > 1500 chars cut. Its workspace does not exist, so the archive trigger exercises the archive-only parse |
| `win/state/sessions/session-demo-probe-20261021T124710Z_055429-24236.json` | Windows hook-probe TUI session archive (workspace deleted) | as above; prompts marked `source: user_input`, PreToolUse-hook denials as string `error` |
| `win/demo-win/.../events.jsonl` permission lines | the 5 `permission.requested`/`permission.resolved` pairs from the same live lines (1-70), re-inserted after their original predecessors | verbatim (tool name, decision, wait_ms only) |
| `last_update_check` | WSL `~/.cache/vtcode/last_update_check` | `release_notes` cut to its first lines |

Strings longer than 160 characters (120 in trajectory) are cut with `…`.

## Anonymization

Hook-probe fixtures: `marmu` -> `user`, workspace `sbo-hookprobe-vtcode` ->
`demo-exec` (WSL) / `demo-probe` (Windows), applied to ids, paths,
`thread_id` and `actor_id` alike. Grep proof (2026-10-21, all fixtures):
`marmu`, `santosh`, `bearer`, emails: 0 hits (the only `marmu` is this
README's mapping note); `@` only in `@@` diff hunks; `sk-` only inside
`task-<uuid>`; `api_key_env` only in VT Code's own config-error advice text,
no value.

Original fixtures:

`marmu` -> `user`, workspace names `teams-observer-test` -> `demo-wsl` and
`sbo-stepin` -> `demo-win` (applied consistently to session ids, directory
names, `thread_id` and `actor_id`, so ids still agree), provider error text
redacted. Grep proof at creation (all zero meaningful hits): `marmu`,
`santosh`, `@`, `Bearer`, `key` (0); `sk-` hits are only the substring of
`task-<uuid>`; `token` hits are only usage field names.

## Never copied

The VT Code config dirs (`~/.config/vtcode/`, `%APPDATA%\vinhnx\vtcode\config\`
incl. `auth/` and `config.toml`), any `vtcode.toml`, `.vtcode/checkpoints/`,
`.vtcode/context/`, `.vtcode/history/`, `.vtcode/tasks/`, `.vtcode/terminals/`,
`tool-policy.json`, and the archive's message history.
