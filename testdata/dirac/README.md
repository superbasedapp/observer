# testdata/dirac

Anonymized live captures from Dirac CLI (`dirac-cli` 0.5.22), captured
read-only on 2026-10-21 (the first task per OS, then the hook-probe runs the
same day). Consumed by
`internal/adapter/dirac/adapter_test.go` (`TestParseLiveFixtures` and
friends), which copies each `<layout>/data` tree into a temp dir shaped like
a real Dirac home (`<tmp>/.dirac/data/...`).

| Layout | Task id | Model / provider | Content |
|---|---|---|---|
| `linux/data` | `1792563515376` | `gpt-5.6-luna` / `openai-codex` | WSL Ubuntu: write_to_file x2, execute_command x3, respond.complete; 6 token rows, reasoning on 4 |
| `windows/data` | `1792563501436` | `gpt-6-luna` / `openai-codex` | Windows 11: one multi-step execute_command, respond.complete; 2 token rows |
| `windows/data` | `1792584662340` | `gpt-6-luna` / `openai-codex` | Windows probe run: read_file, execute_command, **edit_file** (anchor edit, `insert_after`), respond.complete; 4 token rows; ui cards with start/end times |
| `windows/data` | `1792584820846` | none | Windows: task cancelled by a prompt hook: op log is ONE empty `reset`, NO `task_metadata.json` (surface/version come from the log) |
| `linux/data` | `1792585271550` | `gpt-5.6-luna` / `openai-codex` | WSL: read_file, execute_command, edit_file, respond.complete, then a real `-T` RESUME whose ui log carries two `reset` ops; 4 token rows |

Files per layout (the real layout, trimmed to what the adapter reads):

- `data/tasks/<id>/api_conversation_history.jsonl`: the op log (the claimed file)
- `data/tasks/<id>/ui_messages.jsonl`: presentation op log (api_status token split)
- `data/tasks/<id>/task_metadata.json`: model_usage + environment_history
- `data/state/taskHistory.json`: the task index (cwd per task)
- `data/logs/dirac-cli.log`: the vendor log TRIMMED to the `[Task <id>]` lines of
  the fixture tasks plus their process's `DistinctId` / `Extension dir` startup
  lines (pid, hashed install id, package dir, channel)

## Anonymization

- The username became `user`; the project directories became `project`
  (`/home/user/project`, `C:\Users\user\project`).
- Every `redacted_thinking.data` value (an opaque, provider-encrypted
  reasoning blob) became `REDACTED-OPAQUE-PROVIDER-BLOB`.
- The probe tasks' hook-script paths (`...\hooks\windows\<Event>.ps1`) became
  `C:\Users\user\hooks\<Event>.ps1`; the probe workspace became `project`;
  the machine hostname in the log became `host`; the log's `DistinctId` (a
  real hashed device id) became a synthetic 64-hex value (`aaaaaaaa0123...` on
  Windows, `bbbbbbbbfedc...` on Linux); the Linux `Extension dir` became
  `/usr/lib/node_modules/dirac-cli`.
- Nothing else was edited, so every token count still sums to the task's
  own `taskHistory.json` totals (the tests pin that arithmetic).

Grep-proven clean: the operator's username and real name, `@`, `sk-`,
`Bearer` and the encrypted-reasoning prefix have no hits; `key`/`token` hit
only JSON field names (`tokensIn`, `reasoningTokens`, `inputTokens`,
`"tokens"`).

## Never copy

`data/secrets.json` (provider keys, ChatGPT OAuth tokens),
`data/globalState.json` (provider settings), the UNTRIMMED `data/logs/dirac-cli.log`
(hostname, prompts, commands), any `tool_context*.jsonl`, and the home's `Agents/Hooks/Rules/Workflows`
directories. Strip process environment lists from any future capture.

## Wanted next (not yet captured)

- A `--subagents` run (`subagents/<runId>/`), a `condense` / shrinking `reset`,
  a metered provider with non-zero `cost`.
- A task long enough to rotate (`.archive.<n>` + `.baseline.jsonl`); covered
  today by a synthetic test only.
- An Anthropic-provider task (non-zero `cacheWrites`), a Gemini task
  (disjoint reasoning), a `--subagents` run (`subagents/<runId>/`), a
  `respond` question/answer round trip, an `--images` turn, and an ACP-mode
  task (`host_name` "Dirac ACP Agent").
