# Cortex Code fixtures

Anonymized copies of real Cortex Code v1.2.18 sessions captured
2026-10-21 and 2026-10-22 (operator step-ins and the hook probe). Each OS directory mirrors
a data home: `<data home>/conversations/<session-uuid>.{history.jsonl,json}`
plus a derived `<data home>/logs/coco.log`.

| Path | Source | What it exercises |
|---|---|---|
| `wsl/conversations/0f1e2d3c-…` | WSL Ubuntu session | write, bash, edit, bash tool calls each paired with its result; per-tool `metrics`; `git_branch` set |
| `wsl/conversations/5c4b3a29-…` | WSL hook-probe session (lines 0-11 and 18-23 of the original) | two hook-blocked `bash` calls with tool_result `status:"error"` and null metrics; an internalOnly hook-injected context block beside a typed prompt; a hook-rewritten command; `metrics.bash.exit_code`; thinking blocks |
| `windows/conversations/9a8b7c6d-…` | Windows 11 session | user records re-appended as growing snapshots; a second typed prompt nested inside an earlier record's snapshot; `[Request interrupted by user]` and hook-output internal blocks; thinking blocks; PowerShell `bash` commands; `git_root`/`git_branch` null |
| `windows/conversations/7e6d5c4b-…` | Windows 11 tool probe (2026-10-22, whole session) | write, read, edit, two PowerShell-run `bash` calls (`echo hi`, `dir`), glob, grep, each paired with its result; Windows drive-letter `file_path`s; per-tool `metrics` (`write`, `edit`, `bash`, `search`); the failed-PreToolUse-hook internalOnly block beside every tool result; assistant records holding only a tool_use; net input 32 |
| `wsl/logs/coco.log`, `windows/logs/coco.log` | the real vendor logs, reduced | run boundaries, `coco.utils.bundle` install-dir version lines, `Desktop sidecar mode`, exit cleanup, the session-id switch lines, the onboarding run's hook-only session id, a `-p` run with no session, pre-JSON plain-text lines (Windows) |

Anonymization applied (scripts kept outside the repo):

* session ids replaced by fixed fake UUIDs (the hook-only and probe ids in
  the logs by `00000000-0000-4000-8000-00000000000N`); tool_use ids by
  `toolu_fixture_NN`
* home paths: `/home/<user>/<project>` → `/home/user/project`,
  `C:\Users\<user>\...` → `C:\Users\user\...` (the 7e6d5c4b probe's
  working directory → `C:\Users\user\project`)
* harness `internalOnly` system reminders and hook-output blocks replaced by
  a one-line placeholder (kept as blocks so the skip logic is exercised)
* the Observer `observer run` wrapper prefix and its stderr notices removed
  from the WSL bash results (the probe fixture drops the records that
  carried them)
* thinking `signature` → `FIXTURE_SIGNATURE`
* metadata: `connection_name` → `EXAMPLE_CONN`, `session_accounts` →
  `["EXAMPLE_ACCOUNT"]`, `thread` → fake id and `example.snowflakecomputing.com`,
  `last_request_id` → fake UUID, `permission_cache` emptied
* logs: only the lines the reader keys on are kept (plus the first line of
  each session-id switch); every other `msg` is `[fixture: message removed]`,
  `request_id` is null, pids are the real (meaningless) numbers

Token numbers (`token_usage`) are the real values.

Never copy into this directory: `~/.snowflake/connections.toml` /
`config.toml`, `cortex/cache/credential_cache/`, `cortex/connection_cache.json`,
`cortex/history`, `cortex/settings.json`, `cortex/permissions.json`,
`cortex/stats/usage.json`, or an unreduced `logs/` file (its `msg` text
carries prompt excerpts).

Synthetic cases (subagent `parent_session_id`, `forked_from`, a live
unexited log run, ACP / vscode / desktop launcher sources, torn metadata
reads, secrets) are built inline in the tests and labelled SYNTHETIC there;
no synthetic file lives here.
