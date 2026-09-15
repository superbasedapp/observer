# testdata/kirocli

Anonymized fixtures for the Kiro CLI adapter (`internal/adapter/kirocli`,
`models.ToolKiroCLI = "kiro-cli"`). All captured live 2026-07-09 on WSL
Ubuntu + Windows 11 and scrubbed before landing here (cwd → `/home/dev/
project`, ids replaced with stable placeholders, one injected secret to
exercise the scrubber).

Kiro CLI has a **mode-dependent dual store**: interactive runs write the
flat-file bundle; `--no-interactive` runs write the SQLite
`conversations_v2` table. The adapter parses both; these fixtures cover
each layout plus the two `.json` state shapes.

## Flat-bundle fixtures (Layout 1 — `~/.kiro/sessions/cli/`)

| File | Shape it exercises |
|---|---|
| `flat-with-metadata.json` | The FINISHED `.json` state — `session_state.conversation_metadata.user_turn_metadatas[]` populated with `input/output_token_count` (0), `context_usage_percentage`, `metering_usage` credits, `end_timestamp`. Drives the per-turn token event. |
| `flat-with-metadata.jsonl` | The append-only message stream: `{"kind":"Prompt"|"AssistantMessage","data":{message_id,content:[{kind:"text",data}],meta:{timestamp}}}`. The Prompt carries an injected `sk-…` secret so the scrub test can assert redaction. |
| `flat-with-metadata.history` | Raw input lines — the adapter never reads `.history`; kept only to mirror the real bundle. |
| `flat-live-shape.json` | The LIVE/killed `.json` shape — `conversation_metadata` present but `user_turn_metadatas` ABSENT. Proves the adapter tolerates a bundle with no turn accounting (emits messages, no token events). |
| `flat-live-shape.jsonl` | Stream paired with the bare state. |
| `flat-malformed.jsonl` | Two valid stream lines around one broken JSON line — asserts the parser warns + advances rather than crashing. Has no `.json` sibling. |

## SQLite fixture (Layout 2 — `conversations_v2`)

| File | Shape it exercises |
|---|---|
| `conversations_v2-value.json` | The `value` column of ONE `conversations_v2` row — the live one-shot `--no-interactive --trust-tools` run that did `fs_write` (create hello.txt) then `execute_bash` (`ls`) then a text Response. `history[]` carries the `user`/`assistant`/`request_metadata` turn shape, `env_context.env_state.current_working_directory`, tool_use + tool_use_result records, and the all-null token fields real captures exhibit. |

The SQLite tests (`statedb_test.go`) build a `data.sqlite3` in-process
(`sql.Open` + `CREATE TABLE conversations_v2` + `INSERT`) and load this
`value` JSON — the same in-test-DB approach clinecli / kilocode use, so
no binary `.db` is committed. Tests also seed the `auth_kv` + `state`
tables with sentinel secrets to prove the adapter NEVER reads them, and
vary the row `key` to a `C:\…` string to exercise Windows-key
crossmount translation.

## Reality-check finds (Phase 0, live 2026-07-09)

1. Even a FINISHED `.json` reports `input_token_count: 0` /
   `output_token_count: 0` — Kiro's local counts are structurally zero
   (accounting is server-side on SigV4 endpoints). Emitted honestly,
   tagged `unreliable`.
2. The SQLite `request_metadata` token fields
   (`total_tokens`/`uncached_input_tokens`/`output_tokens`/
   `cache_read_input_tokens`/`cache_write_input_tokens`) were ALL null
   in every capture → no token event from the SQLite path.
3. `metering_usage` values are Kiro **credits**, not tokens and not USD
   — deliberately NOT stored.
4. A tool_use result content block is `{"Text":"…"}` OR `{"Json":{…}}`
   (execute_bash returns the latter with `exit_status`/`stdout`/
   `stderr`).
5. `model_id` is `"auto"` for auto-mode sessions (no pricing entry →
   cost engine `unknown`, documented gap).
6. The Windows SQLite row `key` is a raw `C:\tmp\sbo-capture\kiro`
   string — the KEY itself needs `crossmount.TranslateForeignPath`.
7. The sqlite `conversations` (v1) + `history` tables are legacy
   shell-history — never chat; `auth_kv` (`kirocli:social:token`) +
   `state` (`telemetry-cognito-credentials`, …) are credential/telemetry
   rows the adapter must never read.

---

## Kiro IDE fixtures (Layout 3 — `~/.kiro/sessions/<bucket>/<sid>/`)

There are **two** IDE fixtures, and the difference matters.

### 1. `ide/9f3c1d0b7a4e2856/sess_0a1b2c3d-…/` — REAL, anonymized (primary)

An **anonymized derivation of a real Kiro IDE 1.0.411 session** the
operator ran **2026-09-03** (signed in with **Google** — no AWS Builder
ID needed, correcting the earlier note): a five-step prompt kit
(summarise the project; create + run `hello.py`; edit it to "Hello
Universe" + run; delete it; list the directory to verify). 67 records.

**Derivation rules** — structure-preserving, values-only rewrite. Every
record, payload key, `toolName`, `kind`, `actionType`, `status` and
nesting level is carried through verbatim; only identifying values are
replaced, deterministically:

| Real | Fixture |
|---|---|
| session id (real value withheld — a `sess_<uuid>` id) | `sess_0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d` |
| workspace-hash bucket (real 16-hex value withheld) | `9f3c1d0b7a4e2856` |
| workspace path `c:\Users\<user>\<dir>\<proj>` | `c:\Users\dev\workspace\demo` (incl. its percent-double-encoded and doubled-backslash escapings inside `snapshotUri` and JSON-in-a-JSON-string bodies) |
| every UUID (`executionId`, message ids, `requestIds`, `traceparent`, `userMessageTag`) | sequential `%08d-0000-4000-8000-%012d` placeholders, one per distinct source value |
| every `tooluse_<rand>` / `turn_approval_<ms>_<ms>_<rand>` id | sequential placeholders keeping the same prefix shape |
| timestamps | shifted to a `2026-09-03T12:00:00.000Z` base, **relative deltas preserved** |
| `reasoningSignature` (encrypted blob) | `REDACTED-REASONING-SIGNATURE` |
| the user prompt | rewritten to an equivalent generic prompt **plus an injected `sk-ant-api03-…` secret**, so the scrub assertion runs against the real-derived fixture |
| model/README prose naming the operator's project | generic equivalents |
| `session_start.content` (~18 KB Kiro system prompt) | a one-line elision note — the record and its `agentType` / `forcedRole` / `messageId` keys are kept |

Everything else — the tool argument shapes, the `todo_list` task
payloads, the PowerShell echo noise in `execute_pwsh` results, the
`{}` bodies `delete_file` and `list_directory` return, the
`contextUsage` percentages, the `usage_summary` credit float — is the
vendor's own output, unmodified apart from the substitutions above.

### 2. `ide/a1b2c3d4e5f60718/sess-ide-shapes-0001/` — BUNDLE-DERIVED (shape variants)

> **⚠️ SYNTHESISED, NOT LIVE.** Built from the Kiro agent extension's
> own source (`kiro.kiro-agent` **1.0.776**, 12.9 MB bundle read
> verbatim **2026-09-02**): the `session.json` zod schema `hV`, the
> `messages.jsonl` payload union, the record-id spellings and the
> `sha256(normalize(workspaceFolders)).hex[:16]` bucket formula. Field
> PRESENCE and SHAPES are grounded in the bundle; per-field VALUES are
> invented.

It is kept — rather than deleted when the real capture landed — because
it carries payload shapes the five-turn live run never produced, and
deleting it would delete real regression coverage:
`tombstone`, `sub_agent_start`, `source:"steer"`, ARRAY-shaped
`content`, an UNMAPPED tool name (`open_cli_terminal`), the SYNTHETIC
interrupted `tool_result` (`<toolCallId>-result-synthetic`,
`success:false`), `operationType` `Print` / `Summary`, and a
`session.json` that carries `effortLevel` (the live 1.0.411 one does
not).

### What the real capture proved

1. The IDE ships an **entirely different tool vocabulary from the CLI**
   — `read_file`, `fs_write` (body in `text`, no `command` sub-arg),
   `str_replace`, `execute_pwsh`, `delete_file`, `list_directory`,
   `todo_list`. Before this fixture landed, ten of the session's rows
   were `unknown` on the live daemon.
2. `create` / `complete` are the **`todo_list` sub-command**, not tool
   names — they surfaced as targets only because the generic arg probe
   reads the `command` key on an unmapped tool.
3. Three payload types the bundle read missed —
   `pending_interaction`, `interaction_resolved`, `usage_summary` —
   warned nine times on one five-turn session.
4. `session_start` is written **LAST**, and its `content` is the Kiro
   system prompt, not the user's first message.
5. `assistant` `operationType:"Reasoning"` records carry an encrypted
   `reasoningSignature` and a literal `"..."` body — Kiro elides the
   reasoning text.
6. `modelId` is `"auto"`; `effortLevel` is **absent**.
7. `delete_file` names its operand `targetFile`, a key the probe table
   did not know — the one live row with a blank target.

The remaining IDE cases are built in-test rather than committed:
a session dir with **no** `session.json` (missing-sibling tolerance), a
**CRLF** copy of the stream, a **split-window** parse (tool_call in one
window, its `tool_result` in the next → `ParseResult.OutcomeUpdates`),
an unmapped tool with no recognisable operand, and the `classifyLayout`
path matrix (`cli` bucket vs hash bucket vs `snapshots/**` vs
`sub-executions/*.jsonl` vs `session.json`).

**No token fixture exists for this layout, by construction:** Kiro IDE
persists no token counts anywhere. `session_metadata`'s
`contextUsage.usagePercentage` is a context-window fraction, and
`usage_summary`'s `promptTurnSummaries[].usage` is a Kiro **credit**
float (`"unit":"credit"`) — neither is a token count nor convertible
into one, so `parseIDESession` emits ZERO `TokenEvent`s.

### Sidecars observed but NOT copied here

`~/.kiro/session-index/<bucket>.jsonl` (session roster),
`~/.kiro/sessions/<bucket>/<sid>/publish.cursor` (Kiro's own
`<byteOffset>:<recordIndex>` tail watermark),
`~/.kiro/workspace-roots/<bucket>/permissions.yaml` (per-workspace tool
policy) and `~/.kiro/logs/<ts>/kiro.log`. None is wired; the reasoning
is tabulated in `docs/kiro-cli-adapter.md`, "Sidecar files under
`~/.kiro`".
