# testdata/deepagents - Deep Agents Code (`dcode`) fixtures

Back `internal/adapter/deepagents` ([`docs/deepagents-adapter.md`](../../docs/deepagents-adapter.md)).

**Captured**: 2026-10-21, `deepagents-code 0.1.87`, provider OpenRouter
(`minimax/minimax-m3.1-flash:free`): a native WSL Ubuntu install
(`~/.deepagents/.state/sessions.db`) and, after the 2026-10-21 hook probe
populated it, the Windows install on the same host
(`%USERPROFILE%\.deepagents\.state\sessions.db`, previously 0 bytes).

## Files

| File | Purpose |
|---|---|
| `fixture.sql` | Loaded by the package tests into `<tmp>/.deepagents/.state/sessions.db`. The real `checkpoints`, `writes`, `dcode_thread_workspaces`, `dcode_thread_names` and `dcode_btw_costs` DDL (copied from the live store) followed by `INSERT`s. Every `writes.value` / `checkpoints.checkpoint` is a hex (`X'...'`) msgpack blob in LangGraph's JsonPlus format - binary, so it cannot be read by eye; use the companion file. |
| `fixture.decoded.json` | The decoded content of every `messages` write in `fixture.sql` (extension types rendered as `{"__ext": <code>, "v": [...]}`), so a reviewer can audit exactly what is in the blobs without a msgpack tool. |

## What is in it

Five threads (`thread_id` values are synthetic UUIDv7s):

| Thread | Source | Shape |
|---|---|---|
| `...a001` | **The real WSL session, anonymized** (re-encoded) | 24 `messages` writes = 19 distinct messages (five AI messages written twice by the after-model middleware), 9 model calls (input 14473-15037 gross, cache_read 185-14978, no reasoning), tool calls `ls` x2, `write_file`, `execute` x2, `edit_file`, `delete`, three prompts (the first `hi` was interrupted, no reply), two `finish_reason: stop` replies, `approval_mode: manual`. Naming spend row in `dcode_btw_costs` (297 / 91 / 184 / 87). One decoy `_quickjs_snapshot_payload` write that must never be read |
| `...b002` | **Synthetic** | Anthropic-style content blocks (`thinking` + `text`), `cache_creation` + `ephemeral_1h_input_tokens` + reasoning tokens, a failed `execute` (`artifact.exit_code` 1, status `success`), `task` (sub-agent), an OpenRouter call with a dollar `cost`, an unresolved `write_file` (-> `OutcomePending`), a `[SYSTEM]` human message, an image attachment, a `RemoveMessage`, `approval_mode: auto`, a `dcode_btw_costs` row with a cost |
| `...c003` | **Synthetic** | Windows cwd (`C:\Users\user\win-project`), an OpenAI call with reasoning tokens (implicit-cache overlay), a `null` `dcode_btw_costs` tombstone. Kept: no live session carries those shapes |
| `...d004` | **Real Windows headless (`dcode -n`) hook-probe session, anonymized** | Every checkpoint (51, with `parent_checkpoint_id`), the 10 `messages` writes, the 4 `_last_model_request_at` writes (GenMs), 12 `__interrupt__`/`__resume__` writes that are all dcode hook-protocol invocations (no approval rows), native `C:\Users\user1\...` cwd, a BOM-prefixed PowerShell prompt, a hook-blocked `execute` (`status: error`), a failed `glob` (Windows path), `git_branch: main`, `interactive: false` |
| `...e005` | **Real WSL headless session with a sub-agent, anonymized** | Every checkpoint of the root AND the child namespace `tools:08038a3d-...` (74), 16 `messages` writes (7 root, 9 child; the child's first write re-states the parent prompt under the same id), 2 `_last_model_request_at`, 20 `__interrupt__`/`__resume__` writes (two HITL approvals - `task` in the root, `execute` in the child - among hook-protocol invocations, incl. a resume list longer than its interrupt list), and the child's `_session_cost_transfers` (never read; its numbers pin the no-double-count test), `interactive: false` |

## Anonymisation

### Threads D and E (added 2026-10-21, round 2)

Copied from the live stores with **byte-level, same-length** substitutions so
the msgpack length prefixes stay valid without re-encoding: the account name
-> `user1` (in `/home/...` and `C:\Users\...`), the real thread id -> the
fixture id, and every OpenRouter generation token (`gen-<epoch>-<20 chars>`)
-> `fixture<tag>nNN000...`. Writes are limited to the channels the adapter
reads plus the one `_session_cost_transfers` decoy; the `checkpoints.metadata`
JSON is rebuilt from a whitelist (`cwd`, `git_branch`, `approval_mode`,
`agent_name`, `ls_integration_version`, `lc_versions`, `turn_id`,
`turn_number`, `ls_agent_type`, `lc_agent_name`) and stored as plain JSON
text; workspace ids / fingerprints are replaced (`ws-<tag>`, `rk`, `cf`) and
`workspace_config_json` is the real (path-free) config. The interrupt blobs
carry hook-protocol ids (`invocation_id`, `snapshot_id`, `run_id`), which are
random and identify nothing. The decoded content is appended to
`fixture.decoded.json` (`namespace` / `channel` / `value` per write). The
only `@` in either file is the `@@ lines 1-1 of 1 @@` read_file hunk header.

Thread A's `workspace_config_json` and checkpoint metadata were also refreshed
from the live store (real `interactive: true`, `turn_id`, `turn_number`; the
earlier rebuilt metadata carried a per-checkpoint counter in `turn_number`).

### Threads A-C

Thread A is the operator's real conversation re-encoded after replacing: the
home path -> `/home/user`, the project directory name -> `demo-project`, the
operator's first name in the model's greeting -> `there`, and every OpenRouter
generation id (`gen-<epoch>-<token>`) -> `gen-fixture-NN`. Checkpoint ids are
kept (they are random UUIDv6s; their clock is the 2026-10-21 capture time and
the tests rely on it). The `checkpoints.metadata` JSON is **rebuilt from
scratch** (cwd, branch, approval mode, version only) - none of the live
metadata (run ids, request ids, ports, thread-owner hashes, terminal program,
etc.) is carried over, and `checkpoints.checkpoint` blobs are a stub
`{"v": 4, "id": ...}`. No process env, env-var names, API keys, tokens, emails
or hostnames are present: the grep set (the operator's account names, `@`, `sk-`,
`Bearer`, `api_key`, `secret`, `password`, `credential`, a non-`/home/user`
home path) is empty over both files. (The words "token(s)" and "key" appear only
as LangChain field names such as `input_tokens` and SQL `PRIMARY KEY`.)

The fixture was generated by a throwaway script that read the live store,
rewrote the strings, and re-packed with `ormsgpack`; the script is not kept
(it embeds the strings it replaces).

## Live-grounding numbers the tests pin

* `input_tokens 14510 = 151 net + 14359 cache_read`, so cache reads are a SUBSET
  of LangChain's `input_tokens`.
* The 9 graph calls sum to the vendor's own `_session_cost_breakdown`
  (`input 132451`, `cache_read 117683`, `output 430`); plus the naming spend
  (297) the whole store totals `132748` gross input.
* `dcode_thread_message_counts.message_count = 19` = distinct message ids.
* Thread E: the three sub-agent calls sum to dcode's own transfer record
  (`input_tokens 35723`, `cache_read 26316`, `reasoning 131`); the two root
  calls' GenMs are 3663 ms and 1372 ms (request start -> step checkpoint).

## Opt-in live run

```
DEEPAGENTS_REAL_DB=~/.deepagents/.state/sessions.db \
  go test -run TestRealStore -v ./internal/adapter/deepagents/
```
