# testdata/qoder — Qoder fixtures (CLI · IDE · Qoder Work)

> Layout: the root holds the original **Qoder CLI** fixtures;
> `ide/` holds the **Qoder IDE** transcript and `work/` the **Qoder Work**
> desktop-store fixture, both added 2026-09-03. See
> [`docs/qoder-adapter.md`](../../docs/qoder-adapter.md) for what each
> surface is and why all three share one tool id.

**Captured**: 2026-07-09 from a live `qoder` v1.0.40 session on WSL Ubuntu
(`~/.qoder/projects/-tmp-sbo-capture-qoder/` + the run log under
`~/.qoder/logs/sessions/<slug>/<sid>/segments/`). Ground truth documented
in
[`docs/plans/new-adapters-live-capture-2026-07-09.md`](../../docs/plans/new-adapters-live-capture-2026-07-09.md)
(qoder rows, Phase A/C + Windows addendum).

**Anonymisation**: every fixture is REGENERATED from the live shapes, not
copied verbatim. Real prompts kept only as the neutral capture prompt
("Create a file hello.txt … then run ls"); real cwd replaced with
`/home/dev/proj` (a non-git dir so `git.Resolve` returns it unchanged);
UUIDs replaced with readable synthetic ids (`…-000000000001`); upstream
`chatcmpl-…` ids replaced with `chatcmpl-AAA/BBB`; tool-call ids replaced
with `call_write01` / `call_bash01`; segment `request_id`s replaced with
`req-0000-0001/0002`. The machine-id fingerprint, `.auth/user` token
blob, `settings.json`, and the encrypted `state.json` blobs are NOT
copied here — the `state.json` fixture is a structure-only STUB with the
nonce + encrypted `p` blob replaced by `STUB_…_TRUNCATED`.

## What the live capture established (verdicts the fixtures pin)

- **No local tokens.** The transcript (`projects/<slug>/<uuid>.jsonl`)
  carries NO token fields at all. The run-log segments DO carry
  Anthropic-NET token names (`input_tokens` / `output_tokens` /
  `cache_read_input_tokens` / `cache_creation_input_tokens` on
  `model.response.completed`), but every value was **ZERO** in live
  capture — usage is resolved server-side and never written locally. The
  adapter parses the segment tokens with a zero-usage guard so real
  future counts would flow while today nothing lands.
- **No local model string.** `message.model`, `runtime-config.model`,
  and every segment `model` field were EMPTY. The adapter leaves `Model`
  empty rather than fabricating one.
- **Anthropic content-block shape.** `message.content` is a bare STRING
  for a human prompt and an ARRAY of `text` / `tool_use` / `tool_result`
  blocks otherwise (like Claude Code). Tool names are the Claude-Code
  vocabulary verbatim (`Write` / `Bash` / `Read` / …).

## File inventory

| File | Purpose | Use in tests |
|------|---------|--------------|
| `tool-call-session.jsonl` | Full one-shot turn: `runtime-config` → user prompt (bare-string content) → `file-history-snapshot` → assistant text + two `tool_use` blocks (`Write` + `Bash`) → two user `tool_result` records → assistant end-turn text → `last-prompt`. Model empty throughout; `chatcmpl-AAA/BBB` message ids. | `TestParseToolCallSession` (taxonomy, result stamping, ContentBytes, MessageID, empty-model honesty), `TestCursorResumption` |
| `segments-zero.jsonl` | A real-shape run-log segment: `session.config.loaded` (project_root) → `turn.started` → `model.request.started` → two `model.response.completed` (all-zero tokens) → `turn.finished` (zero). | `TestSegmentTokensZeroGuarded` (zero-usage guard → 0 token events) |
| `segments-tokens.jsonl` | Same shape but with SYNTHETIC non-zero token counts on the two `model.response.completed` records (and an aggregate `turn.finished` that must NOT be double-counted). | `TestSegmentTokensNonZeroFlow` (future-proof token flow; session id from path; project root from config.loaded) |
| `malformed-session.jsonl` | 4 physical lines: good user record, a non-JSON garbage line, an empty line, good assistant record. | `TestMalformedToleranceAndOffset` (skip-with-warning + cursor reaches EOF) |
| `state.json` | Structure-only STUB of the encrypted per-session store (`items.<id>.{n,p}` nonce + ciphertext replaced with `STUB_…`). | Reference only — the adapter NEVER reads it (off-limits: encrypted). |

## `ide/` — Qoder IDE transcript (added 2026-09-03)

**Captured**: 2026-09-03 from two live in-editor agent tasks on Windows 11
(`~/.qoder/projects/c-Users-<u>-<proj>/transcript/task-<20 hex>.session.execution.jsonl`).

**Anonymisation**: derived from the real transcript, not copied — cwd
`c:\Users\dev\proj`, session id `task-1111222233334444aaaa.session.execution`,
record uuids `00000000-0000-4000-8000-00000000e0NN`, tool-call ids
`call_0000…`, and neutral prompt/response text.

| File | Purpose | Use in tests |
|------|---------|--------------|
| `ide/transcript/task-1111222233334444aaaa.session.execution.jsonl` | A full IDE task: `progress` (SessionStart hook) → `session_meta` → user prompt → assistant text → `Read` + result → `Write` (note `file_content`, the IDE's spelling) + result → `progress` (PostToolUse hook) → `SearchReplace` + result → `Bash` + result → closing assistant text. | `TestParseIDETranscript` (shared parser, `ide`/`qoder` surface stamp, `file_content` authored bytes, `SearchReplace` → `unknown`) |

What it pins:

- The IDE record shape is **identical** to the CLI transcript, so the same
  parser handles both; only the surface stamp differs.
- Two extra record types appear (`session_meta`, `progress`) and are
  skipped like `runtime-config`.
- The IDE emits tool names the CLI never did (`SearchReplace`,
  `DeleteFile`); `internal/tooltax` has no rows for them yet, so they land
  as `unknown` with the raw name preserved.
- `Write` spells its body `file_content`, not `content`.

## `work/` — Qoder Work desktop store (added 2026-09-03)

**Captured**: 2026-09-03 from a live Windows install,
`%APPDATA%\com.qoder.app.stable\main.sqlite` (6 `chat_sessions`, 18
`chat_session_messages`).

**Form**: checked in as **SQL, not a binary** — diffable, and provably
free of anything but what is written in it. `buildWorkDB` in
`internal/adapter/qoder/work_test.go` renders it into a temp
`main.sqlite`.

**Anonymisation**: the DDL is copied verbatim from the live
`sqlite_master` for the three tables the adapter touches; every ROW value
is synthetic (session ids `sess-with-twin` / `sess-no-twin` /
`sess-fresh`, uuids `00000000-0000-4000-8000-0000…`, cwd
`C:\Users\dev\proj`). No credential, account or BYOK table is present in
the fixture at all, so a test cannot accidentally query one.

| File | Purpose | Use in tests |
|------|---------|--------------|
| `work/main-sqlite-fixture.sql` | `chat_sessions` + `chat_session_messages` + `chat_session_context_usage`, with the three live message shapes (host-projection user turn, sdk-projection assistant with a complete `tools[]` record, hook-activity system row) and a failed assistant carrying `failureReason`. | `TestWorkDB*` (hosted surface stamp, twin rule both branches, freshness gate both branches, watermark idempotence, tool projection, no tokens/model, missing-table tolerance) |

What it pins:

- **The id spaces are shared with the CLI store** — a user message's `id`
  is the transcript record's `uuid`, and `tools[].id` is the transcript's
  `tool_use` id. This is the evidence for the §2.1 "one tool, two
  surfaces" call.
- **No tokens.** `chat_session_context_usage.snapshot_json` is
  `tokenCountsAvailable:false` with every count 0 — a context-window
  occupancy gauge, not usage.
- **No model.** `chat_sessions.model` is `byok:<profile-uuid>` or the tier
  alias `auto`.
- **Ownership.** A Work session WITH a `<sid>.jsonl` twin contributes only
  the hosted `desktop`/`qoder-work` stamp; a twin-less one (the aborted-run
  shape) is emitted in full.

## Off-limits files (never read by the adapter)

- `projects/<slug>/<uuid>/state.json` and
  `projects/<slug>/<uuid>/compression-v2/state.json` — encrypted blobs.
- `~/.qoder/settings.json` — provider config.
- `~/.qoder/.auth/user` — auth token blob.
- `~/.qoder/.auth/machine_id` — telemetry fingerprint.
- Qoder Work `main.sqlite` tables `byok_model_credentials`,
  `mcp_oauth_credentials` (encrypted) and `account_profiles` (identity),
  plus its `sessionMigration.sqlite` / `qoder-data.v1.json` siblings.
- The Qoder IDE's `state.vscdb` and
  `SharedClientCache/cache/db/local.db` (the latter's `vec0` virtual
  tables are unreadable by `modernc.org/sqlite`, and its plain
  `chat_*` tables were all 0 rows live).
