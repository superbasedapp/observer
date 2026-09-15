# testdata/devin — Devin CLI fixtures

Fixtures backing the `internal/adapter/devin` table-driven tests
(`adapter_test.go`, `transcript_test.go`).

Two fixture families live here: the **synthesized** CLI fixture
(`fixtureSQL`, described first) and the **live-derived** Devin Desktop
fixture (`desktop/sessions.sql`, described under
"The `desktop/` fixture").

**Source shape**: Modeled on a live capture 2026-07-09 from Cognition's
Devin CLI build **3000.1.27** on WSL2 + Windows — the SQLite store at
`~/.local/share/devin/cli/sessions.db` (Windows
`%APPDATA%\devin\cli\sessions.db`). See
`docs/plans/new-adapters-live-capture-2026-07-09.md`.

**Anonymisation**: These fixtures are **synthesized**, not a copy of the
operator's live DB. They reproduce the real schema and JSON shapes
(`message_nodes` tree, `chat_message` JSON with
`metadata.metrics.{input_tokens,output_tokens,cache_read_tokens,`
`cache_creation_tokens,ttft_ms}`, tool-role
`metadata.extensions["chisel/tool_result_meta"].success`, adjective-noun
session ids, `main_chain_id` leaf pointer) with generic prompts
(`"hi"`, `"Create a file hello.txt …"`) and paths (`/home/user/project`,
`C:\Users\dev\project`). No real usernames, prompts, or file bodies.

## File inventory

| File | Purpose | Use in tests |
|------|---------|--------------|
| (in-test `sessions.db`) | Synthesized SQLite store with 3 sessions: `cobalt-fruit` (native linux cwd, a **dead regeneration branch** off `main_chain_id`, write+exec tool calls with success results, per-node token metrics), `bird-brick` (raw `C:\…` Windows `working_directory` for the crossmount path), `malformed-test` (a `main_chain_id` leaf whose `chat_message` is invalid JSON). **NOT a tracked file** — the repo tracks no `.db` binaries (tree-wide `*.db` gitignore, SQLite fixtures are synthesized in-test by convention); `TestMain` builds the DB once per test binary from the embedded SQL dump in `internal/adapter/devin/fixture_test.go`. | All parser + transcript tests. Exercises: active-chain walk / regeneration dedup, token capture, tool→action mapping, ContentBytes, foreign-Windows project-root translation, malformed-node skip-don't-crash, watermark idempotency, `ReadTranscript`. |
| `cobalt-fruit.json` | Trimmed, anonymized **ATIF-v1.7** rendered transcript export (as Devin writes to `cli/transcripts/<id>.json`). | Reference only — **not loaded by tests**. The adapter reads the always-present `message_nodes` store, not this convenience export. |

| `desktop/sessions.sql` | **Derived from a LIVE Devin Desktop 2.3.15 capture** (Windows, 2026-09-03) — anonymized, see below. Materialized into a `cli/sessions.db` per test run by `desktop_test.go::desktopStore`. | `desktop_test.go` — the desktop store's schema parity, action/token shape, `ide`/`devin-desktop` surface stamp, `hidden = 1` summary-agent lineage stamp, watermark idempotency. |

## The `desktop/` fixture — derivation

Unlike the synthesized fixture above, `desktop/sessions.sql` is
**derived from the operator's real store** (`%APPDATA%\Devin\cli\
sessions.db`, copied read-only after a signed-in five-turn prompt-kit run
in Devin Desktop 2.3.15 on 2026-09-03). It is a `.sql` text dump rather
than a `.db` because the repo tracks no SQLite binaries (tree-wide `*.db`
gitignore).

**Kept verbatim** (this is the point of the fixture):

- Every `CREATE TABLE` exactly as the live store emits it, plus all 16
  `refinery_schema_history` rows (version 16 = `add_session_json_metadata`)
  — the evidence that the desktop-bundled CLI store schema *is* the CLI
  store schema.
- The full 85-row `message_nodes` tree of both sessions: forked/regenerated
  branches, dead branches, `parent_node_id` pointers, `main_chain_id`
  leaves, node `metadata` (`num_tokens_preceding`, `is_system_prefix`,
  `compact/prior_node_ids`).
- Every `metadata.metrics` bundle **unchanged** (`input_tokens`,
  `output_tokens`, `cache_read_tokens`, `ttft_ms`, `tpot_ms`, …) and
  every `generation_model` / `finish_reason`.
- The `chisel/*` extension shapes (`tool_result_meta`, `terminal_output`
  with its `exit_code`, `tool_call_timing`, `tool_call_content`) and the
  `client_meta` / `response_dimensions` session metadata shape.
- `hidden`, `backend_type`, `agent_mode`, `workspace_dirs`.

**Rewritten / elided**:

| What | How |
|---|---|
| Session ids | (real names withheld) → `amber-lantern` (user), `tidy-marmot` (summary agent) |
| Paths | the operator's workspace and home → `C:\Users\dev\workspace\demo`, `C:\Users\dev` |
| Project nouns | the real project name → `demo` / `Demo (scratch workspace)` |
| Message / request / tool-call ids | remapped deterministically (sha256-derived UUIDs, `call_<24 hex>`), terminal id → `a1b2c3` |
| Requesting tab id | → `new-1700000000000-tab0000000` (shape preserved; presence is what the surface rule keys on) |
| User prompt text | replaced with an equivalent generic five-step prompt |
| The summary agent's prompt (the whole parent conversation pasted in) | elided to a marker |
| Vendor system-prompt bodies (`role: "system"`, > 400 chars — incl. the 19.6 KB system prefix) | elided to a length placeholder; the node, its position in the tree and its metadata are kept |
| `cogs_json` | → `[]` (a large session-policy blob the adapter never reads) |
| `refinery_schema_history.applied_on` / `checksum` | neutralized |
| `tool_call_state` rows | dropped (the adapter never reads that table; its `CREATE` is kept) |

The scrub is verified by grep: no operator username, home path, project
name or real session id survives in the file.

## Regenerating the fixture DB

Edit the `fixtureSQL` dump embedded in
`internal/adapter/devin/fixture_test.go`; the tests assert on the
specific ids
(`u-1`, `a-live1`, `a-final`, `call_write1`, `call_exec1`, `a-dead`,
`call_dead`) so keep them stable.
