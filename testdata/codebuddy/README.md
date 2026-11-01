# testdata/codebuddy

Fixtures for `internal/adapter/codebuddy` (Tencent CodeBuddy Code,
`@tencent-ai/codebuddy-code` 2.171.0). Operator reference:
`docs/codebuddy-adapter.md`.

| File | Kind | Source |
|---|---|---|
| `wsl-auth-error-session.jsonl` | REAL, anonymized | WSL Ubuntu, `~/.codebuddy/projects/home-<user>-<proj>/01a15cae-7d33-7739-8d55-8b6a3940d798.jsonl`, operator session, 2026-10-21 |
| `windows-auth-error-session.jsonl` | REAL, anonymized | Windows 11, `%USERPROFILE%\.codebuddy\projects\c-Users-<user>-<proj>\01a15cad-f2df-7ac8-a141-61794a419f5b.jsonl`, operator session, 2026-10-21 |
| `windows-tool-session.jsonl` | REAL, anonymized, mock-model | hook probe, headless `codebuddy -p -y`: Read, Bash, Edit all complete (session `01a15e5d-65aa-…`) |
| `windows-permission-denied-session.jsonl` | REAL, anonymized, mock-model | hook probe, headless `-p` without `-y`: Read runs, Bash and Edit are denied (`status:"incomplete"`, `toolResult.error`) (session `01a15e5d-0eef-…`) |
| `windows-hook-blocked-session.jsonl` | REAL, anonymized | hook probe, a UserPromptSubmit hook exiting 2: the ONLY record is the assistant-role block message (`hookStatus:"blocked"`) (session `01a15e5b-cd73-…`) |
| `windows-interrupted-session.jsonl` | REAL, anonymized, mock-model | hook probe, run killed mid-Bash: a Read pair and an unanswered Bash call (session `01a15e67-88b2-…`) |
| `wsl-tool-session.jsonl` | REAL, anonymized, mock-model | same Read / Bash / Edit sequence on WSL (POSIX `cwd`) (session `01a15e64-be14-…`) |
| `synthetic-unobserved-shapes.jsonl` | **SYNTHETIC** | Hand-built from the vendor's @openai/agents-core 0.5.2 item schema and the 2.171.0 bundle. NOT a capture. Covers ONLY shapes no live capture has produced (below) |

## What "mock-model" means

The operator could not log in. For the 2026-10-21 hook probe a loopback
mock OpenAI-chat-completions server scripted Read -> Bash -> Edit tool
calls (`CODEBUDDY_BASE_URL=http://127.0.0.1:<port>`, a dummy key), and the
real CLI executed them and wrote its normal transcripts. So:

- PROVEN by these fixtures: every record shape and field position the
  adapter parses (`function_call`, `function_call_result`, usage envelopes
  on every item of a generation, `model` / `requestModelId`, `messageId` /
  `stepSeq`, the hook-block message, the permission-denial result, the
  interrupted run, the headless run with no `session-meta`).
- NOT proven (mock values): the token numbers (constant 10 in / 5 out per
  generation), any non-zero cache or reasoning count, that a real provider
  echoes the executed model, the `call_probe_N` ids, non-zero Bash exit
  codes, cost.

The two operator auth-error sessions never reached a model: only the
opening `session-meta`, local slash-command bookkeeping
(`providerData.skipRun:true`), the prompt `hi`, an assistant record whose
`providerData.error` is "Authentication required…", `file-history-snapshot`
and `summary` lines.

## What the synthetic fixture exercises (UNVERIFIED paths only)

A `reasoning` item, an `input_image` user attachment, an `mcp__` tool, an
unmapped built-in (`ImageGen`), a `_fromSubAgent:true` forwarded sub-agent
line, `rawUsage` cache read / write fields, a Bash result whose
`toolResult.rawResponse.exitCode` is non-zero, and the two compaction
shapes (a `summary` with `providerData.source:"pre-compact"` and the
provider's opaque `compaction` item). Everything a live capture now shows is
tested on the real fixtures instead.

## Anonymization

The username became `user`, the probe project directory `project`, and the
hook command (which named a local scratch path) became
`node "C:/Users/user/hooks/capture.cjs" …`. Session ids, line ids, turn ids,
message ids and W3C trace ids are kept verbatim: they are random
identifiers, not personal data. Grep-checked for the username, the
developer's first name, `programsx`, `scratchpad`, `sk-`, `bearer`,
`api_key` (zero hits; `TestLiveFixturesAreAnonymized` pins it). The only `@`
is the `<hash>@v1` backup file name inside `file-history-snapshot` lines
(not an e-mail). `token` appears only as the `inputTokens` / `outputTokens`
usage field names.

## Replace the synthetic fixture after a logged-in step-in

Capture, in this order, from a logged-in session that runs at least one
`Read`, one `Bash`, one `Edit` and one `Agent` (sub-agent) call, plus a
`/compact`:

1. `~/.codebuddy/projects/<slug>/<session-id>.jsonl` (the main transcript).
2. `~/.codebuddy/projects/<slug>/<session-id>/subagents/agent-*.jsonl`
   and its `.meta.json` (to settle the sub-agent double-count question).

Never copy: `~/.codebuddy/settings.json`, `~/.codebuddy.json`,
`~/.codebuddy/mcp.json` / `.mcp.json`, `models.json`, `local_storage/`,
`history.jsonl`, `traces/`, `logs/` (it can hold prompt text and auth
notes), or any file the CLI writes after `/login` to hold credentials.
Strip usernames, paths, host names, e-mail addresses and any pasted secret
before committing.
